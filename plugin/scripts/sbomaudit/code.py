"""Read-only access to an audited project's committed code: `code grep`, `code show`, `code files`.

A verifier checks a claim against the code on the audited branch, never the working tree. These subcommands
give it that without a general shell: only projects from the config, only branches that exist, only git
plumbing that reads objects (`grep` on a tree, `cat-file`, `ls-tree`). Nothing is checked out, nothing runs
from the repository (no textconv, no filters, no hooks), and nothing is written. Output is capped.

Three outcomes a caller must not confuse, each with its own exit code: a match (0) or no match (1); a request
refused, or a repository or ref that could not be read (2); and git itself could not run (4: not found, not
executable, or failing before it reads any repository, as the macOS `xcrun` shim does in a sandbox). Only the
first says anything about the code.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import PurePosixPath

from . import config
from .gitio import GitError, branch_ref, git, git_bytes, git_env, pick_branches

MAX_LINES = 400
MAX_LINE_CHARS = 400
MAX_SHOW_BYTES = 512 * 1024
# Repository config cannot make these reads run anything: no fsmonitor, no hooks, no textconv drivers.
SAFE = ("-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "diff.external=")


EXIT_NO_MATCH = 1
EXIT_UNREADABLE = 2
EXIT_GIT_UNUSABLE = 4
GIT_HINT = "git not usable (macOS xcrun shim or sandbox?)"
PROBE_TIMEOUT = 30


class CodeError(ValueError):
    pass


class GitUnusable(RuntimeError):
    """git could not run at all, so nothing about the code is known: neither a match nor no match."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"git could not run: {reason}; hint: {GIT_HINT}. Nothing was read; this is not "
                         "\"no match\"")


def _first_line(text: str) -> str:
    return next((line.strip() for line in (text or "").splitlines() if line.strip()), "")


def git_unusable_reason() -> str | None:
    """None when `git --version` runs and answers like git; else why not (the first line of its stderr, or the
    OS error). The probe reads no repository, so its failure is git itself, never the code or the ref."""
    try:
        proc = subprocess.run(["git", "--version"], capture_output=True, text=True, errors="replace",
                              timeout=PROBE_TIMEOUT)
    except FileNotFoundError:
        return "git not found on PATH"
    except PermissionError:
        return "git is not executable"
    except OSError as exc:
        return f"git could not start ({exc.strerror or type(exc).__name__})"
    except subprocess.TimeoutExpired:
        return f"`git --version` did not answer within {PROBE_TIMEOUT}s"
    if proc.returncode != 0 or not proc.stdout.startswith("git version"):
        return _first_line(proc.stderr) or f"`git --version` exited {proc.returncode}"
    return None


def _classify(exc: BaseException) -> BaseException:
    """A failed git call: GitUnusable when git itself does not run, else the error unchanged."""
    reason = git_unusable_reason()
    return GitUnusable(reason) if reason else exc


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
    try:
        proc = subprocess.run(["git", "-C", str(project.path), *args], capture_output=True, text=True,
                              errors="replace", env=git_env())
    except OSError as exc:
        raise _classify(exc) from exc
    if proc.returncode == 1 and not proc.stderr.strip():      # no match
        return []
    if proc.returncode != 0:
        raise _classify(GitError(proc.stderr.strip() or "git grep failed"))
    out = proc.stdout
    prefix = ref + ":"
    return _cap([line[len(prefix):] if line.startswith(prefix) else line for line in out.splitlines()], "matches")


def show(project, ref: str, path: str, start: int = 1, end: int | None = None) -> list[str]:
    spec = f"{ref}:{_path(path)}"
    try:
        kind = git(project.path, *SAFE, "cat-file", "-t", spec).strip()
    except (GitError, OSError) as exc:
        if isinstance(failure := _classify(exc), GitUnusable):
            raise failure from None
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
    """0 output (for `grep`: a match), 1 no match, 2 refused or repository/ref unreadable, 4 git could not run."""
    where = args.project
    try:
        cfg = config.load(args.out)
        project = _project(cfg, args.project)
        where = f"{project.name}@{args.branch}"
        ref = _ref(project, args.branch)
        if args.code_command == "grep":
            lines = grep(project, ref, args.pattern, args.path, args.ignore_case)
            if not lines:
                print(f"no match in {where}")
                return EXIT_NO_MATCH
        elif args.code_command == "show":
            lines = show(project, ref, args.path, *_parse_lines(args.lines))
        else:
            lines = files(project, ref, args.path)
    except GitUnusable as exc:
        print(f"code: {exc}", file=sys.stderr)
        return EXIT_GIT_UNUSABLE
    except (GitError, OSError) as exc:
        failure = _classify(exc)
        if isinstance(failure, GitUnusable):
            print(f"code: {failure}", file=sys.stderr)
            return EXIT_GIT_UNUSABLE
        reason = _first_line(str(exc)) or type(exc).__name__
        print(f"code: repository or ref unreadable: {where}: {reason}", file=sys.stderr)
        return EXIT_UNREADABLE
    except CodeError as exc:
        print(f"code: {exc}", file=sys.stderr)
        return EXIT_UNREADABLE
    print("\n".join(lines))
    return 0
