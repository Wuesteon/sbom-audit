"""Which repositories the secrets scan covers.

Every local git repository under the portfolio root (including `ignore_projects`, which only the SBOM
audit skips), every repository of `[discovery] github_owner` as a bare clone, and every configured
`[projects."<name>"] github = "owner/repo"` that has no local folder. Deduplicated by GitHub slug,
case-insensitively: local > configured github > discovered.
"""
from __future__ import annotations

import fnmatch
import subprocess
from collections.abc import Callable
from pathlib import Path

from .. import config, gitio
from ..errors import ToolError
from . import discovery
from .discovery import Repo

__all__ = ["Repo", "local_repos", "all_repos"]


def _default_clone_url(slug: str, protocol: str = "ssh") -> str:
    """GitHub clone URL for a configured slug that `gh repo list` did not return."""
    if protocol == "https":
        return f"https://github.com/{slug}.git"
    return f"git@github.com:{slug}.git"


def _common_dir(child: Path) -> Path:
    """The shared `.git` directory: identical for a main repository and each of its linked worktrees."""
    try:
        return Path(gitio.git(child, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()).resolve()
    except gitio.GitError:
        pass
    try:  # git < 2.31 has no --path-format
        return (child / gitio.git(child, "rev-parse", "--git-common-dir").strip()).resolve()
    except gitio.GitError:
        return (child / ".git").resolve()


def local_repos(cfg: config.Config) -> list[Repo]:
    if cfg.mode == "single":
        return [Repo(name=cfg.root.name, path=cfg.root,
                     github=config.github_slug(config.remote_url(cfg.root)), source="project")]
    found: list[Repo] = []
    seen: set[Path] = set()
    out = cfg.out.resolve()
    for child in sorted(cfg.root.iterdir(), key=lambda p: p.name.lower()):
        if not child.is_dir() or not (child / ".git").exists():
            continue
        if child.resolve() == out:
            continue
        if any(fnmatch.fnmatch(child.name, pat) for pat in config.SKIP_PROJECT_PATTERNS):
            continue
        common = _common_dir(child)
        if common in seen:
            continue
        seen.add(common)
        source = "ignored" if child.name in cfg.ignore_projects else "project"
        found.append(Repo(name=child.name, path=child,
                          github=config.github_slug(config.remote_url(child)), source=source))
    return found


def all_repos(cfg: config.Config, out: Path, *, gh=subprocess.run, git=subprocess.run,
              log: Callable[[str], None] | None = None,
              clone_url: Callable[[str], str] | None = None) -> tuple[list[Repo], list[dict]]:
    """Local repos, configured GitHub-only projects and discovered repos, plus the failure list.

    Clones follow `cfg.discovery.protocol`; existing clones are fetched only when `cfg.fetch` is true."""
    protocol = cfg.discovery.protocol
    url_key = discovery.CLONE_URL_KEYS.get(protocol, "sshUrl")
    clone_url = clone_url or (lambda slug: _default_clone_url(slug, protocol))
    repos = local_repos(cfg)
    failures: list[dict] = []
    seen = {r.github.lower() for r in repos if r.github}

    listed: list[dict] = []
    owner = cfg.discovery.github_owner
    if owner:
        try:
            listed = discovery.list_repos(owner, cfg.discovery.include_forks, gh=gh)
        except ToolError as exc:
            failures.append({"repo": f"{owner}/*", "error": exc.detail})
    listed_urls = {str(item.get("nameWithOwner") or "").lower(): {"sshUrl": item.get("sshUrl"), "url": item.get("url")}
                   for item in listed}

    for name, slug in config.github_only_projects(cfg):
        slug = str(slug)
        if slug.lower() in seen:
            continue
        seen.add(slug.lower())
        entry = {"nameWithOwner": slug, **(listed_urls.get(slug.lower()) or {})}
        if not entry.get(url_key):
            entry[url_key] = clone_url(slug)
        synced, failed = discovery.sync(out, [entry], git=git, log=log, protocol=protocol, fetch=cfg.fetch)
        failures.extend(failed)
        repos.extend(Repo(name=name, path=r.path, github=slug, source="github") for r in synced)

    pending: list[dict] = []
    for item in listed:
        key = str(item.get("nameWithOwner") or "").lower()
        if key in seen:
            continue
        seen.add(key)
        pending.append(item)
    synced, failed = discovery.sync(out, pending, git=git, log=log, protocol=protocol, fetch=cfg.fetch)
    repos.extend(synced)
    failures.extend(failed)
    return repos, failures
