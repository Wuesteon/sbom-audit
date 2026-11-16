"""Evidence folder housekeeping: own docs, stale sbom dirs, run commit, guarded push, remote visibility."""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import gitio

TEMPLATE_DIR = Path(__file__).resolve().parents[2] / "templates" / "evidence"
FOLDER_DOCS = ("CLAUDE.md", "README.md")
_MARKER_RE = re.compile(r"^<!--\s*sbom-audit-template\s+v(\d+)\s*-->\s*$")
_GITHUB_URL_RES = (
    re.compile(r"^https://github\.com/(?P<o>[\w.-]+)/(?P<r>[\w.-]+?)(?:\.git)?/?$"),
    re.compile(r"^git@github\.com:(?P<o>[\w.-]+)/(?P<r>[\w.-]+?)(?:\.git)?$"),
    re.compile(r"^ssh://git@github\.com/(?P<o>[\w.-]+)/(?P<r>[\w.-]+?)(?:\.git)?/?$"),
)
VISIBILITIES = ("public", "private", "internal")
PUBLIC_REFUSAL = "remote is public; keep the evidence repository private"
SBOM_SUFFIX = ".cdx.json"
_URLISH_RE = re.compile(r"\S+://\S+|\S+@\S+:\S+")


# --- folder docs ------------------------------------------------------------

def _marker_version(text: str) -> int | None:
    first = text.split("\n", 1)[0].strip()
    m = _MARKER_RE.match(first)
    return int(m.group(1)) if m else None


def write_folder_docs(out: Path) -> list[Path]:
    """Copy CLAUDE.md / README.md templates into `out` when missing or carrying an older marker.

    Returns every doc the plugin owns (first line is a template marker), rewritten or not, so a
    run's commit covers them; a target without the marker is hand-written, left alone, not returned.
    """
    out = Path(out).resolve()
    written: list[Path] = []
    for name in FOLDER_DOCS:
        text = (TEMPLATE_DIR / name).read_text(encoding="utf-8")
        template_version = _marker_version(text)
        target = out / name
        if target.exists():
            current = _marker_version(target.read_text(encoding="utf-8", errors="replace"))
            if current is None:
                continue
            if template_version is None or current >= template_version:
                written.append(target)
                continue
        out.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        written.append(target)
    return written


def holds_only_sboms(folder: Path) -> bool:
    """True when `folder` contains nothing but `*.cdx.json` regular files (no subfolders, no links)."""
    try:
        return all(child.is_file() and not child.is_symlink() and child.name.endswith(SBOM_SUFFIX)
                   for child in Path(folder).iterdir())
    except OSError:
        return False


def prune_sbom_dirs(out: Path, keep: set[str]) -> list[str]:
    """Remove `out/sbom/<project>/` directories whose project is not in `keep`; return the names.

    A directory holding anything but `*.cdx.json` files is never removed (a hand-placed file).
    """
    out = Path(out).resolve()
    root = out / "sbom"
    if root.is_symlink() or not root.is_dir():
        return []
    removed = []
    for child in sorted(root.iterdir()):
        if child.name in keep:
            continue
        if child.is_symlink():
            child.unlink()
        elif child.is_dir():
            if not holds_only_sboms(child):
                continue
            shutil.rmtree(child)
        else:
            continue
        removed.append(child.name)
    return removed


# --- git helpers ------------------------------------------------------------

def _git(git, out: Path, *args: str, **kwargs):
    """Every git call of this module: `--literal-pathspecs` so a `*` or `:` in a file name is never a pattern."""
    return git(["git", "--literal-pathspecs", "-C", str(out), *args], capture_output=True, text=True, **kwargs)


def _first_line(proc, cap: int | None = 200) -> str:
    for line in ((proc.stderr or "") + "\n" + (proc.stdout or "")).splitlines():
        if line.strip():
            return line.strip()[:cap]
    return f"exit {proc.returncode}"


def _is_work_tree(git, out: Path) -> bool:
    if not out.is_dir():
        return False
    try:
        proc = _git(git, out, "rev-parse", "--is-inside-work-tree")
    except OSError:
        return False
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def is_own_repo(out: Path, git=subprocess.run) -> bool:
    """True when `out` is the top level of its own git work tree (not a folder inside another repo)."""
    out = Path(out).resolve()
    if not out.is_dir():
        return False
    try:
        proc = _git(git, out, "rev-parse", "--show-toplevel")
    except OSError:
        return False
    if proc.returncode != 0 or not proc.stdout.strip():
        return False
    return Path(proc.stdout.strip()).resolve() == out


def _rel(out: Path, path: Path) -> str:
    path = Path(path)
    if path.is_absolute():
        try:
            path = path.resolve().relative_to(out.resolve())
        except ValueError:
            path = Path(path)
    return path.as_posix()


def pending_hand_edits(out: Path, written: set[Path], git=subprocess.run) -> list[str]:
    """Paths `git status` shows as changed that the run did not write (sorted, relative to `out`)."""
    out = Path(out).resolve()
    if not _is_work_tree(git, out):
        return []
    ours = {_rel(out, p) for p in written}
    prefix = _git(git, out, "rev-parse", "--show-prefix").stdout.strip()
    proc = _git(git, out, "status", "--porcelain", "-z", "-uall", "--", ".")
    if proc.returncode != 0:
        return []
    pending = []
    records = proc.stdout.split("\0")
    i = 0
    while i < len(records):
        rec = records[i]
        i += 1
        if len(rec) < 4:
            continue
        code, path = rec[:2], rec[3:]
        if "R" in code or "C" in code:
            i += 1                                   # skip the original-path record
        if prefix and path.startswith(prefix):
            path = path[len(prefix):]
        if path not in ours:
            pending.append(path)
    return sorted(pending)


# --- commit -----------------------------------------------------------------

@dataclass
class CommitResult:
    status: str          # committed | nothing | skipped | failed
    sha: str | None
    detail: str


def subject_line(status: dict) -> str:
    counts = status.get("counts") or {}
    secrets = counts.get("secrets")
    day = str(status.get("generated_at") or "")[:10]
    tail = f"{secrets.get('A', 0)} class A secrets" if isinstance(secrets, dict) else "secrets skipped"
    return f"audit {day}: {counts.get('vulnerable', 0)} vulnerable, {counts.get('kev', 0)} KEV, {tail}"


def body_line(status: dict) -> str:
    code = status.get("exit_code")
    return (f"sbom-audit {status.get('plugin_version', '?')}, exit {'none' if code is None else code}, "
            f"run host {status.get('run_host', '?')}")


def commit_run(out: Path, written: list[Path], subject: str, body: str,
               git=subprocess.run) -> CommitResult:
    """Commit exactly the files this run wrote; anything else in the tree stays untouched.

    `written` paths may be absolute or relative to `out`.
    """
    out = Path(out).resolve()
    if not _is_work_tree(git, out):
        return CommitResult("skipped", None, "not a git repository")
    rels = []
    for rel in sorted({_rel(out, p) for p in written}):
        # a pruned path stays when git tracks it (its deletion gets staged); an untracked ghost is dropped
        if (out / rel).exists() or (out / rel).is_symlink():
            rels.append(rel)
        elif _git(git, out, "ls-files", "-z", "--", rel).stdout.strip("\0"):
            rels.append(rel)
    if not rels:
        return CommitResult("nothing", None, "no files written")
    proc = _git(git, out, "add", "-A", "--", *rels)
    if proc.returncode != 0:
        return CommitResult("failed", None, _first_line(proc))
    if _git(git, out, "diff", "--cached", "--quiet", "--", *rels).returncode == 0:
        return CommitResult("nothing", None, "no changes")
    proc = _git(git, out, "commit", "-q", "-m", subject, "-m", body, "--", *rels)
    if proc.returncode != 0:
        return CommitResult("failed", None, _first_line(proc))
    sha = _git(git, out, "rev-parse", "--short", "HEAD").stdout.strip()
    return CommitResult("committed", sha or None, sha)


# --- visibility and push ----------------------------------------------------

_NET_TIMEOUT = 120


def _upstream(git, out: Path) -> tuple[str, str] | None:
    """(remote, merge ref) of the current branch's upstream, or None. Never returns a URL."""
    branch = _git(git, out, "symbolic-ref", "--short", "-q", "HEAD")
    name = branch.stdout.strip() if branch.returncode == 0 else ""
    if not name:
        return None
    remote = _git(git, out, "config", f"branch.{name}.remote")
    merge = _git(git, out, "config", f"branch.{name}.merge")
    if remote.returncode != 0 or merge.returncode != 0:
        return None
    remote_name, merge_ref = remote.stdout.strip(), merge.stdout.strip()
    if not remote_name or remote_name == "." or not merge_ref:
        return None
    return remote_name, merge_ref


def has_upstream(out: Path, git=subprocess.run) -> bool:
    """True when `out` is a work tree whose current branch has an upstream a push would go to."""
    out = Path(out).resolve()
    return _is_work_tree(git, out) and _upstream(git, out) is not None


def remote_visibility(out: Path, gh=subprocess.run, which=shutil.which,
                      remote: str | None = None, git=subprocess.run) -> str:
    """`public | private | internal` for the GitHub remote a push would go to, else `unknown`.

    `remote=None` resolves the current branch's upstream remote and falls back to `origin`, so
    visibility can be read before a first push. The URL is the push URL and never leaves this function.
    """
    out = Path(out).resolve()
    if not which("gh"):
        return "unknown"
    try:
        if remote is None:
            up = _upstream(git, out)
            remote = up[0] if up else "origin"
        proc = _git(git, out, "remote", "get-url", "--push", "--", remote)
    except OSError:
        return "unknown"
    if proc.returncode != 0:
        return "unknown"
    url = proc.stdout.strip()
    slug = None
    for rx in _GITHUB_URL_RES:
        m = rx.match(url)
        if m:
            slug = f"{m['o']}/{m['r']}"
            break
    if not slug:
        return "unknown"
    try:
        res = gh(["gh", "api", f"repos/{slug}", "--jq", ".visibility"],
                 capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if res.returncode != 0:
        return "unknown"
    value = (res.stdout or "").strip()
    return value if value in VISIBILITIES else "unknown"


def _remote_parts(git, out: Path, remote: str) -> list[str]:
    """Host, path and userinfo pieces of the remote's URLs, to scrub from git's own messages."""
    parts: set[str] = set()
    for args in (("remote", "get-url", "--all", "--", remote), ("remote", "get-url", "--push", "--all", "--", remote)):
        try:
            proc = _git(git, out, *args)
        except OSError:
            continue
        for url in (proc.stdout or "").split():
            m = re.match(r"^(?:[\w+.-]+://)?(?:(?P<user>[^@/]+)@)?(?P<host>[^/:]+)[:/]?(?P<path>.*)$", url)
            if not m:
                continue
            parts.update([m["host"], m["path"].strip("/")])
            if "://" in url and m["user"] and m["user"] != "git":   # https userinfo: user and token; not ssh's `git@`
                parts.update([m["user"], *m["user"].split(":")])
    return sorted((p for p in parts if len(p) >= 3), key=len, reverse=True)


def _scrub(text: str, parts: list[str] = ()) -> str:
    """Replace every URL-like token and every known piece of the remote URL with `<remote>`; cap 200."""
    text = _URLISH_RE.sub("<remote>", text)
    for part in parts:
        text = text.replace(part, "<remote>")
    return text[:200]


def push_run(out: Path, visibility: str, git=subprocess.run) -> dict:
    """Fast-forward onto the upstream, then push there. Never forces; never pushes to a public remote."""
    if str(visibility or "").strip().lower() == "public":
        return {"status": "refused_public", "detail": PUBLIC_REFUSAL}
    out = Path(out).resolve()
    if not _is_work_tree(git, out):
        return {"status": "skipped", "detail": "not a git repository"}
    up = _upstream(git, out)
    if up is None:
        return {"status": "skipped", "detail": "no upstream"}
    remote, merge_ref = up
    parts = _remote_parts(git, out, remote)
    net = {"env": gitio.net_env(), "timeout": _NET_TIMEOUT}
    try:
        proc = _git(git, out, "fetch", remote, **net)
        if proc.returncode != 0:
            return {"status": "failed", "detail": _scrub(_first_line(proc, cap=None), parts)}
        proc = _git(git, out, "merge", "--ff-only", "@{u}")
        if proc.returncode != 0:
            return {"status": "conflict",
                    "detail": "remote has diverged; local commit kept, merge by hand then push"}
        proc = _git(git, out, "push", remote, f"HEAD:{merge_ref}", **net)
        if proc.returncode != 0:
            return {"status": "failed", "detail": _scrub(_first_line(proc, cap=None), parts)}
    except subprocess.TimeoutExpired:
        return {"status": "failed", "detail": "timed out"}
    sha = _git(git, out, "rev-parse", "--short", "HEAD").stdout.strip()
    return {"status": "pushed", "detail": sha}
