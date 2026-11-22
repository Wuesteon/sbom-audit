"""Read-only git access: branch selection, origin comparison, tree export.

Nothing here checks anything out. The only write to an audited repo is
`git fetch --prune origin`, which touches remote-tracking refs only.

An audited repository is hostile input, its committed files and its local `.git/config` alike. Every git
process this package starts (directly or through gitleaks) gets `git_env`: command-line-scope config that
turns off fsmonitor, hooks, the external diff command and signature checks in `git log`, and forbids the
`ext::` transport. `export_ref` also neutralises every filter driver (smudge, clean, process) that the
repository's config defines, and readers of history pass `--no-textconv --no-ext-diff`. What still comes
from the repository's config: the transport settings of `git fetch` (`core.sshCommand`, credential
helpers, `core.askPass`, proxies), which a fetch needs to work.
"""
from __future__ import annotations
import atexit

import fnmatch
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path

_CREDENTIALS_RE = re.compile(r"//[^/@\s]+@")
GIT_TIMEOUT = 600      # seconds, any one git command (a fetch included)
EXPORT_TIMEOUT = 1800  # seconds, `git archive | tar` of one branch


class GitError(RuntimeError):
    pass


def scrub_credentials(text: str) -> str:
    """Drop `user:pass@` from every URL quoted in a git message."""
    return _CREDENTIALS_RE.sub("//***@", text)


# Command-line-scope config for every git process: repository config cannot make a read run a program.
HARDENING = (
    ("core.fsmonitor", "false"),
    ("core.hooksPath", "/dev/null"),
    ("diff.external", ""),
    ("log.showSignature", "false"),
    ("protocol.ext.allow", "never"),
)
_FILTER_KEYS = ("smudge", "clean", "process")


APPLE_GIT_SHIM = "/usr/bin/git"
_XCODE_SELECT_LINK = "/var/db/xcode_select_link"
_COMMAND_LINE_TOOLS = "/Library/Developer/CommandLineTools"


def _first_git(path: str | None) -> str | None:
    """The first executable `git` on `path` (default: this process's PATH)."""
    for directory in (os.environ.get("PATH", "") if path is None else path).split(os.pathsep):
        candidate = os.path.join(directory or ".", "git")
        if os.access(candidate, os.X_OK) and not os.path.isdir(candidate):
            return candidate
    return None


def real_git(path: str | None = None, platform: str = sys.platform) -> str | None:
    """On macOS, when `git` on `path` is Apple's shim: the git binary the shim would start (in the selected
    developer directory, else the Command Line Tools), or None. The shim asks `xcrun`, which writes a cache
    file under the per-user temp directory; a sandbox that forbids that write (Claude Code's sandbox, an eval
    sandbox) makes every git call fail before git starts. The real binary needs no cache. Only these system
    locations are considered, never anything a repository can influence."""
    if platform != "darwin" or _first_git(path) != APPLE_GIT_SHIM:
        return None
    candidates = []
    developer = os.environ.get("DEVELOPER_DIR")
    if developer:
        candidates.append(developer)
    try:
        candidates.append(os.path.realpath(_XCODE_SELECT_LINK, strict=True))
    except OSError:
        pass
    candidates.append(_COMMAND_LINE_TOOLS)
    for base in candidates:
        binary = os.path.join(base, "usr", "bin", "git")
        if os.access(binary, os.X_OK):      # not isfile(): a sandbox can refuse stat() and still let it run
            return binary
    return None


def use_real_git() -> str | None:
    """Put the real git before Apple's shim on this process's PATH (see `real_git`), so every child process,
    gitleaks and syft included, finds it. Only git: the entry is a private temporary folder holding one
    symlink, because the developer folder itself also holds an old python3 and a hundred other tools that
    must not shadow the user's. The folder is removed at exit. Returns the folder, or None when nothing was
    changed (not macOS, git is not the shim, no real binary, or no writable temp folder)."""
    binary = real_git()
    if not binary:
        return None
    try:
        folder = tempfile.mkdtemp(prefix="sbom-audit-git-")
        os.symlink(binary, os.path.join(folder, "git"))
    except OSError:
        return None
    atexit.register(shutil.rmtree, folder, True)
    os.environ["PATH"] = folder + os.pathsep + os.environ.get("PATH", "")
    return folder


def git_env(env: Mapping[str, str] | None = None,
            extra: tuple[tuple[str, str], ...] = ()) -> dict[str, str]:
    """`env` (default `os.environ`) plus `HARDENING` and `extra` as `GIT_CONFIG_COUNT`/`KEY_n`/`VALUE_n`,
    appended after any config the caller already passes that way. Inherited by every git child process,
    including the `git log` gitleaks starts."""
    result = dict(os.environ if env is None else env)
    try:
        start = max(int(result.get("GIT_CONFIG_COUNT") or 0), 0)
    except ValueError:
        start = 0
    pairs = (*HARDENING, *extra)
    for i, (key, value) in enumerate(pairs, start):
        result[f"GIT_CONFIG_KEY_{i}"] = key
        result[f"GIT_CONFIG_VALUE_{i}"] = value
    result["GIT_CONFIG_COUNT"] = str(start + len(pairs))
    return result


def _filter_overrides(repo: Path) -> tuple[tuple[str, str], ...]:
    """Empty every filter driver any config scope defines (an empty command passes content through)."""
    proc = subprocess.run(["git", "-C", str(repo), "config", "--name-only", "--get-regexp",
                           r"^filter\..+\.(smudge|clean|process|required)$"],
                          capture_output=True, text=True, errors="replace", env=git_env(), timeout=GIT_TIMEOUT)
    drivers = {line.rsplit(".", 1)[0] for line in proc.stdout.splitlines() if line.startswith("filter.")}
    pairs: list[tuple[str, str]] = []
    for driver in sorted(drivers):
        pairs += [(f"{driver}.{key}", "") for key in _FILTER_KEYS] + [(f"{driver}.required", "false")]
    return tuple(pairs)


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


def git(repo: Path, *args: str, env: Mapping[str, str] | None = None, harden: bool = True) -> str:
    """stdout of `git -C repo <args>`; GitError on failure. `harden=False` only for reading the
    repository's own config as it is (the pre-commit guard)."""
    try:
        proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                              env=git_env(env) if harden else env, timeout=GIT_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise GitError(f"git {args[0] if args else ''} timed out after {GIT_TIMEOUT}s") from None
    if proc.returncode != 0:
        raise GitError(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc.stdout


def git_bytes(repo: Path, *args: str) -> bytes:
    """Like `git`, but returns raw stdout bytes (for file content that may not be UTF-8)."""
    try:
        proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, env=git_env(),
                              timeout=GIT_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise GitError(f"git {args[0] if args else ''} timed out after {GIT_TIMEOUT}s") from None
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


LOCAL = "refs/heads/"
REMOTE = "refs/remotes/origin/"


def _refs_under(repo: Path, prefix: str) -> set[str]:
    """Names below `prefix`, read as full refnames: `%(refname:short)` turns `refs/heads/main` into
    `heads/main` when a tag `main` exists, and a bare name would resolve to the tag."""
    out = git(repo, "for-each-ref", "--format=%(refname)", prefix.rstrip("/")).splitlines()
    return {r[len(prefix):] for r in out if r.startswith(prefix)}


def _local_branches(repo: Path) -> set[str]:
    return _refs_under(repo, LOCAL)


def _remote_branches(repo: Path) -> set[str]:
    return _refs_under(repo, REMOTE) - {"HEAD"}


def short_ref(ref: str) -> str:
    """`refs/heads/main` -> `main`, `refs/remotes/origin/main` -> `origin/main` (for display only)."""
    if ref.startswith(LOCAL):
        return ref[len(LOCAL):]
    if ref.startswith("refs/remotes/"):
        return ref[len("refs/remotes/"):]
    return ref


def tag_shadows_branch(repo: Path, branch: str) -> bool:
    """True when a tag has the same name as `branch`: a bare `branch` would name the tag, not the branch.
    The scan reads full refs (`refs/heads/...`), so it is not misled; this is only reported."""
    return bool(git(repo, "for-each-ref", "--format=%(refname)", f"refs/tags/{branch}").strip())


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

    Returns (full ref, full commit sha, commits the local branch is behind origin). The ref is always
    `refs/heads/<branch>` or `refs/remotes/origin/<branch>`, never a bare name a tag could shadow.
    origin/<branch> wins when the local branch is strictly behind or does not
    exist locally; a diverged branch is read locally and reported as behind N.
    """
    local, remote = f"{LOCAL}{branch}", f"{REMOTE}{branch}"
    is_local = branch in _local_branches(repo)
    has_remote = branch in _remote_branches(repo)
    ref, behind = local, 0
    if not is_local and has_remote:
        ref = remote
    elif is_local and has_remote:
        counts = git(repo, "rev-list", "--left-right", "--count", f"{local}...{remote}", "--").split()
        ahead, behind = int(counts[0]), int(counts[1])
        if behind > 0 and ahead == 0:
            ref = remote
    sha = git(repo, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}").strip()
    return ref, sha, behind


def last_change(repo: Path, commit: str, path: str) -> str | None:
    """Full sha of the last commit reachable from `commit` that changed the file `path` (a literal path),
    or None. Read from git objects only, without a prompt, with fsmonitor, hooks, the external diff
    command and textconv switched off (`git_env` plus the flags below); no diff is generated."""
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


def _tar_argv(dest: Path) -> list[str]:
    return ["tar", "-x", "-C", str(dest)]


def export_ref(repo: Path, ref: str, dest: Path) -> None:
    """Write the tree at `ref` into `dest`, leaving out `security/`. Filter drivers from the repository's
    config do not run (`git archive` would otherwise apply smudge and process filters)."""
    dest.mkdir(parents=True, exist_ok=True)
    archive = subprocess.Popen(
        ["git", "-C", str(repo), "archive", "--format=tar", ref, "--", ".", ":!security"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=git_env(extra=_filter_overrides(repo)),
    )
    try:
        untar = subprocess.run(_tar_argv(dest), stdin=archive.stdout, capture_output=True,
                               timeout=EXPORT_TIMEOUT)
        archive.stdout.close()
        _, archive_err = archive.communicate(timeout=EXPORT_TIMEOUT)
    except subprocess.TimeoutExpired:
        archive.kill()
        archive.communicate()
        raise GitError(f"git archive {ref} timed out after {EXPORT_TIMEOUT}s") from None
    finally:
        if archive.stdout and not archive.stdout.closed:
            archive.stdout.close()
    if archive.returncode != 0:
        raise GitError(archive_err.decode(errors="replace").strip() or f"git archive {ref} failed")
    if untar.returncode != 0:
        raise GitError(untar.stderr.decode(errors="replace").strip() or "tar extraction failed")
