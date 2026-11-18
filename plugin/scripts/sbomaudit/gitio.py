"""Read-only git access: branch selection, origin comparison, tree export.

Nothing here checks anything out. The only write to an audited repo is
`git fetch --prune origin`, which touches remote-tracking refs only.
"""
from __future__ import annotations

import fnmatch
import os
import re
import subprocess
from collections.abc import Mapping
from pathlib import Path

_CREDENTIALS_RE = re.compile(r"//[^/@\s]+@")


class GitError(RuntimeError):
    pass


def scrub_credentials(text: str) -> str:
    """Drop `user:pass@` from every URL quoted in a git message."""
    return _CREDENTIALS_RE.sub("//***@", text)


def net_env(env: Mapping[str, str] = os.environ) -> dict[str, str]:
    """Environment for a git command that talks to a remote: it never waits for a password or passphrase.

    `GIT_TERMINAL_PROMPT=0` stops credential prompts; `GIT_SSH_COMMAND=ssh -oBatchMode=yes` stops ssh prompts
    unless the caller already chose an ssh command (`GIT_SSH_COMMAND` or `GIT_SSH`), which is kept verbatim.
    Host key checking is unchanged: an unknown host fails instead of asking."""
    result = dict(env)
    result["GIT_TERMINAL_PROMPT"] = "0"
    if "GIT_SSH_COMMAND" not in result and "GIT_SSH" not in result:
        result["GIT_SSH_COMMAND"] = "ssh -oBatchMode=yes"
    return result


def git(repo: Path, *args: str, env: Mapping[str, str] | None = None) -> str:
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, env=env)
    if proc.returncode != 0:
        raise GitError(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc.stdout


def git_bytes(repo: Path, *args: str) -> bytes:
    """Like `git`, but returns raw stdout bytes (for file content that may not be UTF-8)."""
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True)
    if proc.returncode != 0:
        stderr = proc.stderr.decode(errors="replace").strip()
        raise GitError(stderr or f"git {' '.join(args)} failed")
    return proc.stdout


def remote_url(repo: Path) -> str | None:
    try:
        url = git(repo, "remote", "get-url", "origin").strip()
    except GitError:
        return None
    return url or None


def fetch_origin(repo: Path) -> str | None:
    """Fetch remote-tracking refs without prompting. Returns the credential-free first error line, or None."""
    try:
        git(repo, "fetch", "--quiet", "--prune", "origin", env=net_env())
        return None
    except GitError as exc:
        text = scrub_credentials(str(exc))
        return text.splitlines()[0] if text else "fetch failed"


def _local_branches(repo: Path) -> set[str]:
    return set(git(repo, "branch", "--format=%(refname:short)").split())


def _remote_branches(repo: Path) -> set[str]:
    out = git(repo, "branch", "-r", "--format=%(refname:short)").split()
    return {b[len("origin/"):] for b in out if b.startswith("origin/") and b != "origin/HEAD"}


def pick_branches(repo: Path, requested: list[str]) -> list[str]:
    """Requested branches that exist locally or as origin/<branch>, in requested order."""
    available = _local_branches(repo) | _remote_branches(repo)
    chosen: list[str] = []
    for branch in requested:
        if branch in available and branch not in chosen:
            chosen.append(branch)
    return chosen


def branch_ref(repo: Path, branch: str) -> tuple[str, str, int]:
    """Decide which ref to read for `branch`.

    Returns (ref, full commit sha, commits the local branch is behind origin).
    origin/<branch> wins when the local branch is strictly behind or does not
    exist locally; a diverged branch is read locally and reported as behind N.
    """
    local = branch in _local_branches(repo)
    has_remote = branch in _remote_branches(repo)
    ref, behind = branch, 0
    if not local and has_remote:
        ref = f"origin/{branch}"
    elif local and has_remote:
        counts = git(repo, "rev-list", "--left-right", "--count",
                     f"{branch}...origin/{branch}").split()
        ahead, behind = int(counts[0]), int(counts[1])
        if behind > 0 and ahead == 0:
            ref = f"origin/{branch}"
    sha = git(repo, "rev-parse", ref).strip()
    return ref, sha, behind


def last_change(repo: Path, commit: str, path: str) -> str | None:
    """Full sha of the last commit reachable from `commit` that changed the file `path` (a literal path),
    or None. Read from git objects only; repository config cannot make it prompt or run anything (no
    fsmonitor, hooks, external diff or textconv)."""
    if not commit or commit.startswith("-"):
        return None
    try:
        out = git(repo, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "diff.external=",
                  "--literal-pathspecs", "log", "-1", "--no-ext-diff", "--no-textconv", "--format=%H",
                  commit, "--", path, env=net_env()).strip()
    except (GitError, OSError):
        return None
    return out if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", out) else None


def list_tags(repo: Path, pattern: str) -> list[dict]:
    """Local tags whose name matches the glob `pattern` and that point (peeled) at a commit.

    Each entry: `{"tag", "ref" ("refs/tags/<tag>"), "commit" (full sha), "date"}` where `date` is the
    annotated tag's tagger date, else the commit's committer date (git's `creatordate`), ISO 8601.
    Reads refs only; nothing is fetched or checked out."""
    fmt = "%(refname)%00%(objecttype)%00%(objectname)%00%(*objecttype)%00%(*objectname)%00%(creatordate:iso-strict)"
    tags = []
    for line in git(repo, "for-each-ref", f"--format={fmt}", "refs/tags").splitlines():
        parts = line.split("\0")
        if len(parts) != 6:
            continue
        ref, otype, oid, ptype, pid, date = parts
        name = ref[len("refs/tags/"):]
        if not fnmatch.fnmatchcase(name, pattern):
            continue
        if otype == "commit":
            commit = oid
        elif otype == "tag" and ptype == "commit":
            commit = pid
        else:                                   # a tag of a tree or blob, or a tag of a tag: not a release
            continue
        tags.append({"tag": name, "ref": ref, "commit": commit, "date": date})
    return tags


def export_ref(repo: Path, ref: str, dest: Path) -> None:
    """Write the tree at `ref` into `dest`, leaving out `security/`."""
    dest.mkdir(parents=True, exist_ok=True)
    archive = subprocess.Popen(
        ["git", "-C", str(repo), "archive", "--format=tar", ref, "--", ".", ":!security"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    untar = subprocess.run(["tar", "-x", "-C", str(dest)], stdin=archive.stdout,
                           capture_output=True)
    archive.stdout.close()
    _, archive_err = archive.communicate()
    if archive.returncode != 0:
        raise GitError(archive_err.decode(errors="replace").strip() or f"git archive {ref} failed")
    if untar.returncode != 0:
        raise GitError(untar.stderr.decode(errors="replace").strip() or "tar extraction failed")
