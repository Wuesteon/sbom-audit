"""Read-only access to an audited project's committed code: `code grep`, `code show`, `code files`.

A verifier checks a claim against the code on the audited branch, never the working tree. These subcommands
give it that without a general shell: only projects from the config, only branches that exist, only git
plumbing that reads objects (`grep` on a tree, `cat-file`, `ls-tree`). Nothing is checked out, nothing runs
from the repository (no textconv, no filters, no hooks), and nothing is written. Output is capped.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import PurePosixPath

from . import config
from .gitio import GitError, branch_ref, git, git_bytes, pick_branches

MAX_LINES = 400
MAX_LINE_CHARS = 400
MAX_SHOW_BYTES = 512 * 1024
# Repository config cannot make these reads run anything: no fsmonitor, no hooks, no textconv drivers.
SAFE = ("-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "diff.external=")


class CodeError(ValueError):
    pass


def _project(cfg, name: str):
    projects = {p.name: p for p in config.discover(cfg)}
    if name not in projects:
        known = ", ".join(sorted(projects)) or "(none)"
        raise CodeError(f"unknown project {name!r}; projects: {known}")
    return projects[name]


def _ref(project, branch: str) -> str:
    if not pick_branches(project.path, [branch]):
        raise CodeError(f"{project.name}: no branch {branch!r} (locally or on origin)")
    return branch_ref(project.path, branch)[0]


def _path(path: str) -> str:
    """A repository-relative path without `..`, pathspec magic or the evidence cache."""
    p = PurePosixPath(path.strip())
    if not path.strip() or p.is_absolute() or ".." in p.parts or path.startswith(":"):
        raise CodeError(f"not a repository-relative path: {path!r}")
    if p.parts[:2] == ("security", ".cache"):
        raise CodeError("security/.cache is never read")
    return p.as_posix()


def _cap(lines: list[str], what: str) -> list[str]:
    out = [line if len(line) <= MAX_LINE_CHARS else line[:MAX_LINE_CHARS - 1] + "…" for line in lines[:MAX_LINES]]
    if len(lines) > MAX_LINES:
        out.append(f"… {len(lines) - MAX_LINES} more {what}; narrow the pattern or the path")
    return out


def grep(project, ref: str, pattern: str, paths: list[str], ignore_case: bool = False) -> list[str]:
    args = [*SAFE, "grep", "-n", "-I", "--no-textconv", "--no-color", "--full-name"]
    if ignore_case:
        args.append("-i")
    args += ["-E", "-e", pattern, ref, "--", *([_path(p) for p in paths] or ["."]), ":!security/.cache"]
    proc = subprocess.run(["git", "-C", str(project.path), *args], capture_output=True, text=True,
                          errors="replace")
    if proc.returncode == 1 and not proc.stderr.strip():      # no match
        return []
    if proc.returncode != 0:
        raise GitError(proc.stderr.strip() or "git grep failed")
    out = proc.stdout
    prefix = ref + ":"
    return _cap([line[len(prefix):] if line.startswith(prefix) else line for line in out.splitlines()], "matches")


def show(project, ref: str, path: str, start: int = 1, end: int | None = None) -> list[str]:
    spec = f"{ref}:{_path(path)}"
    try:
        kind = git(project.path, *SAFE, "cat-file", "-t", spec).strip()
    except GitError:
        raise CodeError(f"{project.name}: no file {path!r} on {ref}") from None
    if kind != "blob":
        raise CodeError(f"{path!r} is a {kind}, not a file; use `code files`")
    data = git_bytes(project.path, *SAFE, "cat-file", "blob", spec)
    if b"\0" in data[:8192]:
        raise CodeError(f"{path!r} is binary")
    if len(data) > MAX_SHOW_BYTES:
        data = data[:MAX_SHOW_BYTES]
    lines = data.decode("utf-8", errors="replace").splitlines()
    end = len(lines) if end is None else min(end, len(lines))
    numbered = [f"{n}: {lines[n - 1]}" for n in range(max(start, 1), end + 1)]
    return _cap(numbered, "lines")


def files(project, ref: str, path: str | None) -> list[str]:
    args = [*SAFE, "ls-tree", "-r", "--name-only", "--full-tree", ref]
    if path:
        args += ["--", _path(path)]
    return _cap(git(project.path, *args).splitlines(), "files")


def _parse_lines(text: str | None) -> tuple[int, int | None]:
    if not text:
        return 1, None
    first, _, last = text.partition("-")
    try:
        return int(first), (int(last) if last else int(first))
    except ValueError:
        raise CodeError(f"--lines takes N or N-M, not {text!r}") from None


def cli(args) -> int:
    try:
        cfg = config.load(args.out)
        project = _project(cfg, args.project)
        ref = _ref(project, args.branch)
        if args.code_command == "grep":
            lines = grep(project, ref, args.pattern, args.path, args.ignore_case)
            if not lines:
                print(f"no match in {project.name}@{args.branch}")
                return 1
        elif args.code_command == "show":
            lines = show(project, ref, args.path, *_parse_lines(args.lines))
        else:
            lines = files(project, ref, args.path)
    except (CodeError, GitError) as exc:
        print(f"code: {exc}", file=sys.stderr)
        return 2
    print("\n".join(lines))
    return 0
