"""Read-only access to an audited project's committed code: `code grep`, `code show`, `code files`.

A verifier checks a claim against the code on the audited branch, never the working tree. These subcommands
give it that without a general shell: only projects from the config, only branches that exist, only git
plumbing that reads objects (`grep` on a tree, `cat-file`, `ls-tree`), with user paths taken literally (no
pathspec magic). Nothing is checked out and nothing is written. What is guaranteed against the repository's
own config: no textconv driver, no external diff, no fsmonitor and no hooks run (command-line config and
`--no-textconv`, as every git call of the plugin gets). Not guaranteed: the git binary itself parses the
repository; a bug in it is outside what this module can rule out. See "Hostile repositories" in
docs/reference.md. Every git call has a timeout (`gitio.GIT_TIMEOUT`); a timeout is "unreadable", never "no
match". Output is capped.

Secret-bearing paths (`sensitive.py`, the same list the headless assessment denies to its own tools) are never
searched, shown or listed, nor is `security/.cache`; a line where `secrets.json` records a finding is masked
in `show` and not searched by `grep`. The output says how many files or lines were withheld, never which
content.

Three outcomes a caller must not confuse, each with its own exit code: a match (0) or no match (1); a request
refused, or a repository or ref that could not be read (2); and git itself could not run (4: not found, not
executable, or failing before it reads any repository, as the macOS `xcrun` shim does in a sandbox). Only the
first says anything about the code.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path, PurePosixPath

from . import config, sensitive
from .gitio import GIT_TIMEOUT, GitError, branch_ref, git, git_bytes, git_env, pick_branches

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
CACHE = "security/.cache"
CACHE_PARTS = ("security", ".cache")
SECRETS_JSON = "secrets.json"


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
    text = path.strip()
    p = PurePosixPath(text)
    if not text or p.is_absolute() or ".." in p.parts or text.startswith(":"):
        raise CodeError(f"not a repository-relative path: {path!r}")
    if _in_cache(p.as_posix()):
        raise CodeError("security/.cache is never read")
    return p.as_posix()


def _in_cache(name: str) -> bool:
    return PurePosixPath(name).parts[:2] == CACHE_PARTS


def _cap(lines: list[str], what: str) -> list[str]:
    out = [line if len(line) <= MAX_LINE_CHARS else line[:MAX_LINE_CHARS - 1] + "…" for line in lines[:MAX_LINES]]
    if len(lines) > MAX_LINES:
        out.append(f"… {len(lines) - MAX_LINES} more {what}; narrow the pattern or the path")
    return out


def _count(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


class Withheld:
    """What `code` keeps back in one project on one ref: secret-bearing paths (sensitive.py), security/.cache,
    and lines where the secrets scan recorded a finding (from `secrets.json`, which holds no secret value: a
    finding is a file, a line and the commit it was found in). A finding's line is masked where the file at
    `ref` is the blob the finding was recorded in; where the file changed since and the value is still live
    in a branch tip, the line may have moved, so the whole file is withheld."""

    def __init__(self, project, ref: str, out: Path | None):
        self.lines: dict[str, set[int]] = {}
        self.files: set[str] = set()
        for f in _findings(out, project.name):
            path, line, commit = f["file"], f["line"], f["commit"]
            here = _blob(project.path, ref, path)
            if here is None:
                continue
            if here == _blob(project.path, commit, path) or not f.get("live_in_tree", True):
                self.lines.setdefault(path, set()).add(line)
            else:
                self.files.add(path)

    def path(self, name: str) -> bool:
        return sensitive.is_sensitive(name) or _in_cache(name) or name in self.files

    def line(self, name: str, number: int) -> bool:
        return number in self.lines.get(name, ())


def _findings(out: Path | None, project: str) -> list[dict]:
    """The project's findings from `secrets.json` as (file, line, commit); [] when there is none."""
    try:
        doc = json.loads((Path(out) / SECRETS_JSON).read_text())
    except (OSError, ValueError, TypeError):
        return []
    found = []
    for f in (doc.get("findings") if isinstance(doc, dict) else None) or []:
        if (isinstance(f, dict) and f.get("repo") == project and isinstance(f.get("file"), str)
                and isinstance(f.get("line"), int) and isinstance(f.get("commit"), str)):
            found.append(f)
    return found


def _blob(repo: Path, rev: str, path: str) -> str | None:
    try:
        return git(repo, *SAFE, "rev-parse", "--verify", "-q", f"{rev}:{path}").strip() or None
    except (GitError, OSError):
        return None


def _note(files_n: int, lines_n: int, verb: str) -> list[str]:
    parts = [_count(files_n, "file")] if files_n else []
    parts += [_count(lines_n, "line")] if lines_n else []
    if not parts:
        return []
    return [f"… withheld{verb}: {', '.join(parts)} ({sensitive.DESCRIPTION}, lines with a recorded "
            "secrets finding); content not shown"]


def _tree(project, ref: str, paths: list[str]) -> list[str]:
    args = ["--literal-pathspecs", *SAFE, "ls-tree", "-r", "-z", "--name-only", "--full-tree", ref]
    if paths:
        args += ["--", *paths]
    return [name for name in git(project.path, *args).split("\0") if name]


def grep(project, ref: str, pattern: str, paths: list[str], ignore_case: bool = False,
         out: Path | None = None) -> list[str]:
    """Matches as `path:line:text`. Withheld files and lines are not searched (excluded or dropped before
    anything is printed), so neither the output nor the exit code says whether they match; a last line says
    how many were withheld."""
    held = Withheld(project, ref, out)
    paths = [_path(p) for p in paths]
    in_scope = [name for name in _tree(project, ref, paths) if held.path(name) and not _in_cache(name)]
    lines_held = sum(1 for name, numbers in held.lines.items() for _ in numbers
                     if not held.path(name) and _under(name, paths))
    args = [*SAFE, "grep", "-n", "-z", "-I", "--no-textconv", "--no-color", "--full-name"]
    if ignore_case:
        args.append("-i")
    args += ["-E", "-e", pattern, ref, "--", *[f":(literal){p}" for p in paths], *_excludes(in_scope)]
    try:
        proc = subprocess.run(["git", "-C", str(project.path), *args], capture_output=True, text=True,
                              errors="replace", env=git_env(), timeout=GIT_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise GitError(f"git grep timed out after {GIT_TIMEOUT}s") from None
    except OSError as exc:
        raise _classify(exc) from exc
    note = _note(len(in_scope), lines_held, ", not searched")
    if proc.returncode == 1 and not proc.stderr.strip():      # no match
        return [], note
    if proc.returncode != 0:
        raise _classify(GitError(proc.stderr.strip() or "git grep failed"))
    prefix = ref + ":"
    matches = []
    for row in proc.stdout.splitlines():
        name, _, rest = row.partition("\0")
        number, _, text = rest.partition("\0")
        name = name[len(prefix):] if name.startswith(prefix) else name
        if held.path(name) or (number.isdigit() and held.line(name, int(number))):
            continue
        matches.append(f"{name}:{number}:{text}")
    return _cap(matches, "matches"), note


def _under(name: str, paths: list[str]) -> bool:
    return not paths or any(name == p or name.startswith(p.rstrip("/") + "/") or p == "." for p in paths)


def _excludes(names: list[str]) -> list[str]:
    """Exclude pathspecs: the cache, the secret-bearing patterns, and each withheld file by name. The patterns
    cover what a later commit may add; the names cover what `held.files` adds beyond the patterns."""
    return [f":(exclude,literal){CACHE}", *sensitive.git_excludes(),
            *[f":(exclude,literal){name}" for name in names if not sensitive.is_sensitive(name)
              and not _in_cache(name)]]


def show(project, ref: str, path: str, start: int = 1, end: int | None = None,
         out: Path | None = None) -> list[str]:
    path = _path(path)
    if sensitive.is_sensitive(path):
        raise CodeError(f"{path!r} is withheld: {sensitive.DESCRIPTION} are never shown")
    spec = f"{ref}:{path}"
    try:
        kind = git(project.path, *SAFE, "cat-file", "-t", spec).strip()
    except (GitError, OSError) as exc:
        if isinstance(failure := _classify(exc), GitUnusable):
            raise failure from None
        raise CodeError(f"{project.name}: no file {path!r} on {ref}") from None
    if kind != "blob":
        raise CodeError(f"{path!r} is a {kind}, not a file; use `code files`")
    held = Withheld(project, ref, out)
    if held.path(path):
        raise CodeError(f"{path!r} is withheld: the secrets scan recorded a finding in it that is still live, "
                        "and the file changed since, so the line cannot be masked; see SECRETS.md")
    data = git_bytes(project.path, *SAFE, "cat-file", "blob", spec)
    if b"\0" in data[:8192]:
        raise CodeError(f"{path!r} is binary")
    if len(data) > MAX_SHOW_BYTES:
        data = data[:MAX_SHOW_BYTES]
    lines = data.decode("utf-8", errors="replace").splitlines()
    end = len(lines) if end is None else min(end, len(lines))
    numbered, masked = [], 0
    for n in range(max(start, 1), end + 1):
        if held.line(path, n):
            numbered.append(f"{n}: [withheld: a secrets finding is recorded on this line]")
            masked += 1
        else:
            numbered.append(f"{n}: {lines[n - 1]}")
    return _cap(numbered, "lines") + (_note(0, masked, "") if masked else [])


def files(project, ref: str, path: str | None) -> list[str]:
    names = _tree(project, ref, [_path(path)] if path else [])
    names = [name for name in names if not _in_cache(name)]          # never read, never counted
    shown = [name for name in names if not sensitive.is_sensitive(name)]
    held = len(names) - len(shown)
    note = [f"… withheld: {_count(held, 'name')} ({sensitive.DESCRIPTION})"] if held else []
    return _cap(shown, "files") + note


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
            lines, note = grep(project, ref, args.pattern, args.path, args.ignore_case, cfg.out)
            if not lines:
                print("\n".join([f"no match in {where}", *note]))
                return EXIT_NO_MATCH
            lines += note
        elif args.code_command == "show":
            lines = show(project, ref, args.path, *_parse_lines(args.lines), out=cfg.out)
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
