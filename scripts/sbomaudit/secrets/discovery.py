"""GitHub owner discovery (`gh repo list`) and bare clones under `<out>/.cache/repos/`.

The bare clones are the plugin's own copies; no audited working tree is touched. The only network calls
are `gh repo list` and `git clone` / `git fetch` to the listed remotes.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .. import config, gitio
from ..errors import ToolError

GH_FIELDS = "nameWithOwner,isArchived,isFork,isPrivate,sshUrl,url"
CLONE_URL_KEYS = {"ssh": "sshUrl", "https": "url"}   # the `gh repo list` field each protocol clones from
FETCH_REFSPEC = "+refs/heads/*:refs/heads/*"


@dataclass
class Repo:
    name: str
    path: Path
    github: str | None
    source: str  # "project" | "ignored" | "discovered" | "github"


def _first_line(text: str | None) -> str:
    return next((line.strip() for line in (text or "").splitlines() if line.strip()), "")


def _scrub(text: str) -> str:
    """Drop `user:pass@` from any URL quoted in an error line."""
    return gitio.scrub_credentials(text)


def _run(git, cmd: list[str], env: dict[str, str] | None = None) -> str | None:
    """Run one git command; the credential-free first error line, or None on success."""
    kwargs: dict = {"capture_output": True, "text": True, "errors": "replace", "timeout": 600}
    if env is not None:
        kwargs["env"] = env
    try:
        proc = git(cmd, **kwargs)
    except subprocess.TimeoutExpired:
        return "timed out"
    except OSError as exc:
        return _scrub(str(exc))
    if proc.returncode != 0:
        return _scrub(_first_line(proc.stderr)) or f"git exited {proc.returncode}"
    return None


def _is_bare(git, dest: Path) -> bool:
    try:
        proc = git(["git", "-C", str(dest), "rev-parse", "--is-bare-repository"],
                   capture_output=True, text=True, errors="replace", timeout=600)
    except (subprocess.TimeoutExpired, OSError):
        return False
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def list_repos(owner: str, include_forks: bool, gh=subprocess.run) -> list[dict]:
    """Every repository of `owner`; forks only with `include_forks`, archived ones kept."""
    cmd = ["gh", "repo", "list", owner, "--limit", "1000", "--json", GH_FIELDS]
    try:
        proc = gh(cmd, capture_output=True, text=True, errors="replace", timeout=120)
    except FileNotFoundError:
        raise ToolError("gh", None, "gh not installed") from None
    except subprocess.TimeoutExpired:
        raise ToolError("gh", None, "timed out") from None
    except OSError as exc:
        raise ToolError("gh", None, _scrub(str(exc))) from None
    if proc.returncode != 0:
        raise ToolError("gh", proc.returncode, _scrub(_first_line(proc.stderr)) or "gh repo list failed")
    try:
        data = json.loads(proc.stdout or "")
    except json.JSONDecodeError:
        data = None
    if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
        raise ToolError("gh", proc.returncode, "gh returned invalid JSON")
    return [item for item in data if include_forks or not item.get("isFork")]


def sync(out: Path, repos: list[dict], git=subprocess.run,
         log: Callable[[str], None] | None = None, protocol: str = "ssh",
         fetch: bool = True) -> tuple[list[Repo], list[dict]]:
    """Bare-clone new repositories over `protocol` (`sshUrl` or `url` of each entry) and prune-fetch
    existing clones (kept as they are with `fetch=False`); failures are returned, never raised.
    Network commands run with `gitio.net_env`, so an unattended run never waits for a prompt."""
    url_key = CLONE_URL_KEYS.get(protocol, "sshUrl")
    net = gitio.net_env()
    synced: list[Repo] = []
    failures: list[dict] = []
    for item in repos:
        slug = item.get("nameWithOwner") or ""
        try:
            dest = config.bare_clone_path(out, slug)
        except ValueError as exc:
            failures.append({"repo": slug, "error": str(exc)})
            continue
        url = item.get(url_key)
        if not url:
            failures.append({"repo": slug, "error": "no clone url"})
            continue
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            action = "cloned"
            if dest.exists():
                if _is_bare(git, dest):
                    action = "fetched"
                else:  # left behind by a killed run: start over
                    shutil.rmtree(dest, ignore_errors=True)
                    action = "recloned"
        except OSError as exc:
            failures.append({"repo": slug, "error": _scrub(str(exc))})
            continue
        if action == "fetched" and not fetch:
            action, error = "kept", None
        elif action == "fetched":
            error = _run(git, ["git", "-C", str(dest), "fetch", "--prune", "--quiet", "origin", FETCH_REFSPEC],
                         env=net)
        else:
            error = (_run(git, ["git", "clone", "--bare", "--quiet", "--", url, str(dest)], env=net)
                     or _run(git, ["git", "-C", str(dest), "config", "remote.origin.fetch", FETCH_REFSPEC]))
            if error is not None:
                shutil.rmtree(dest, ignore_errors=True)
        if error is not None:
            failures.append({"repo": slug, "error": error})
            continue
        if log is not None:
            log(f"{action} {slug}")
        synced.append(Repo(name=slug, path=dest, github=slug, source="discovered"))
    return synced, failures
