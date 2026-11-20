"""Pre-commit guard installer: copy the guard into the config dir, detect a repo's hook setup, install.

The guard itself is `templates/guard/guard.py` (self-contained, stdlib only, python3 >= 3.8). It is copied with
`gitleaks.toml` and `classes.toml` into the sbom-audit config dir; each copy carries a `# sbom-audit <version>`
header line and is replaced when that version differs from the plugin's.

The working tree of an audited repository is only written for its hook: the untracked `.git/hooks/pre-commit`
(or a `core.hooksPath` inside the git dir) always, a tracked or shared hook file (`.husky/pre-commit`,
`lefthook.yml`, `.pre-commit-config.yaml`, a `core.hooksPath` outside the git dir) only with `tracked_ok`.
A tracked file gets `TRACKED_LINE`: portable (no machine path), and it allows the commit with one notice line on
a machine where the guard is not installed. A `core.hooksPath` from global or system git config is never edited.
Nothing here touches the index.
"""
from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import sbomaudit
from sbomaudit import gitio, scheduler
from sbomaudit.secrets import store


def _git(repo: Path, *args: str) -> str:
    """The guard reads and edits the repository's own hook setup (`core.hooksPath`, `--git-path hooks`), so
    it runs git without `gitio.git_env`'s hardening, which would report `core.hooksPath=/dev/null`."""
    return gitio.git(repo, *args, harden=False)

MARKER = "# sbom-audit-guard v1"
GUARD_ID = "sbom-audit-guard"
GUARD_NAME = "guard.py"
LOCAL_HOOK = "pre-commit.local"
PLACEHOLDER = "@GUARD@"
SOURCES = (("secrets/gitleaks.toml", "gitleaks.toml"), ("secrets/classes.toml", "classes.toml"),
           ("templates/guard/guard.py", GUARD_NAME))
HOOK_TEMPLATE = Path("templates") / "guard" / "pre-commit.sh"
HEADER = re.compile(r"^# sbom-audit (\d\S*)\s*$")
GUARD_REF = re.compile(r"sbom-audit[/\\]guard\.py|" + GUARD_ID)
HOOK_MODE = 0o755
_TOP_LEVEL = re.compile(r"^[^\s#]")
_EXIT = re.compile(r"^\s*(exit|exec)\b")
TRACKED_LINE = ('G="${XDG_CONFIG_HOME:-$HOME/.config}/sbom-audit/guard.py"; if [ -f "$G" ]; then '
                'if command -v python3 >/dev/null 2>&1; then python3 "$G" || exit 1; '
                'else echo "sbom-audit guard: python3 not found; commit allowed"; fi; '
                'else echo "sbom-audit guard: not installed on this machine (run: sbom-audit setup --install-guard); '
                'commit allowed"; fi')
HUSKY_INACTIVE = "husky is not active here (core.hooksPath unset; run husky's install to activate it)"


@dataclass(frozen=True)
class Detection:
    kind: str        # plain | hookspath | husky | lefthook | pre-commit-framework
    hook_path: Path  # the file the guard goes into
    tracked: bool    # outside the git dir (tracked or shared): written only with --tracked-ok
    origin: str = ""  # where core.hooksPath came from: local | global (global or system config) | "" (unset)
    hooks_path: str = ""  # the raw core.hooksPath value


# --- config dir -------------------------------------------------------------------------------------------

def _header_version(path: Path) -> str | None:
    try:
        head = path.read_text(encoding="utf-8", errors="replace").splitlines()[:2]
    except OSError:
        return None
    return next((m.group(1) for m in map(HEADER.match, head) if m), None)


def _with_header(text: str, version: str) -> str:
    header = f"# sbom-audit {version}\n"
    if text.startswith("#!"):
        first, _, rest = text.partition("\n")
        return f"{first}\n{header}{rest}"
    return header + text


def sync_config_dir(cfg_dir: Path, plugin_root: Path) -> list[Path]:
    """Copy the rules, classes and guard into `cfg_dir`; return the files (re)written (header version differs)."""
    version = sbomaudit.__version__
    written = []
    for source, name in SOURCES:
        dest = Path(cfg_dir) / name
        if _header_version(dest) == version:
            continue
        text = (Path(plugin_root) / source).read_text(encoding="utf-8")
        written.append(store.atomic_write(dest, _with_header(text, version)))
    return written


def refresh_installed(cfg_dir: Path, plugin_root: Path) -> list[Path]:
    """`sync_config_dir` when a guard was installed into `cfg_dir` before; never creates the config dir."""
    if not (Path(cfg_dir) / GUARD_NAME).is_file():
        return []
    return sync_config_dir(cfg_dir, plugin_root)


# --- detection --------------------------------------------------------------------------------------------

def _resolve(repo: Path, value: str) -> Path:
    path = Path(os.path.expanduser(value))
    return (path if path.is_absolute() else repo / path).resolve()


def _inside(path: Path, folder: Path) -> bool:
    return path == folder or folder in path.parents


def _config(repo: Path, git, *args: str) -> str:
    try:
        return git(repo, "config", *args[:-1], "--get", args[-1]).strip()
    except gitio.GitError:  # exit 1: unset
        return ""


def detect(repo: Path, git=_git) -> Detection:
    repo = Path(repo).resolve()
    git_dir = _resolve(repo, git(repo, "rev-parse", "--git-common-dir").strip())
    local_value, hooks_path = (_config(repo, git, *scope, "core.hooksPath") for scope in (("--local",), ()))
    if hooks_path:
        folder = _resolve(repo, hooks_path)
        if local_value != hooks_path:  # set in global or system config: shared by every repo, never edited here
            return Detection("hookspath", folder / "pre-commit", tracked=True, origin="global", hooks_path=hooks_path)
        if _inside(folder, git_dir):
            return Detection("hookspath", folder / "pre-commit", tracked=False, origin="local", hooks_path=hooks_path)
        if _inside(folder, repo / ".husky"):
            return Detection("husky", repo / ".husky" / "pre-commit", tracked=True, origin="local",
                             hooks_path=hooks_path)
        return Detection("hookspath", folder / "pre-commit", tracked=True, origin="local", hooks_path=hooks_path)
    if (repo / ".husky" / "pre-commit").exists():
        return Detection("husky", repo / ".husky" / "pre-commit", tracked=True)
    for name in ("lefthook.yml", ".lefthook.yml"):
        if (repo / name).exists():
            return Detection("lefthook", repo / name, tracked=True)
    if (repo / ".pre-commit-config.yaml").exists():
        return Detection("pre-commit-framework", repo / ".pre-commit-config.yaml", tracked=True)
    hook = _resolve(repo, git(repo, "rev-parse", "--git-path", "hooks/pre-commit").strip())
    return Detection("plain", hook, tracked=False)


# --- install ----------------------------------------------------------------------------------------------

def _sh_escape(text: str) -> str:
    """For use inside a double-quoted sh string."""
    return re.sub(r'([\\"$`])', r"\\\1", text)


def _guard_ref(guard_py: Path) -> str:
    """`$HOME/.config/sbom-audit/guard.py` when under the home dir (portable in tracked files), else absolute."""
    try:
        return "$HOME/" + _sh_escape(guard_py.relative_to(Path.home()).as_posix())
    except ValueError:
        return _sh_escape(str(guard_py))


def render_hook(guard_py: Path, plugin_root: Path) -> str:
    """The untracked hook; it names this machine's guard (`$HOME/...` when under the home dir)."""
    template = (Path(plugin_root) / HOOK_TEMPLATE).read_text(encoding="utf-8")
    return template.replace(PLACEHOLDER, _guard_ref(Path(guard_py)))


def _rel(repo: Path, path: Path) -> str:
    try:
        return path.relative_to(repo).as_posix()
    except ValueError:
        return str(path)


def _write(path: Path, text: str, mode: int) -> None:
    store.atomic_write(path, text)
    path.chmod(mode)


def _install_hook(repo: Path, hook: Path, guard_py: Path, plugin_root: Path) -> str:
    rendered = render_hook(guard_py, plugin_root)
    local = hook.with_name(LOCAL_HOOK)
    rel = _rel(repo, hook)
    note = ""
    if hook.is_symlink() or hook.exists():
        current = hook.read_text(encoding="utf-8", errors="replace") if hook.is_file() else ""
        if MARKER in current:
            if current == rendered and hook.stat().st_mode & 0o777 == HOOK_MODE:
                return f"unchanged ({rel})"
            _write(hook, rendered, HOOK_MODE)
            return f"updated ({rel})"
        if local.is_symlink() or local.exists():
            return f"not installed: {rel} and {LOCAL_HOOK} both exist (merge them by hand, then rerun)"
        os.replace(hook, local)
        note = f", existing hook kept as {LOCAL_HOOK} and run after the guard"
    hook.parent.mkdir(parents=True, exist_ok=True)
    _write(hook, rendered, HOOK_MODE)
    return f"installed ({rel}){note}"


def _lines(text: str) -> list[str]:
    lines = text.splitlines(keepends=True)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    return lines


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _block(lines: list[str], key: str) -> tuple[int, int] | None:
    """(start, end) of the top-level `key:` block mapping; None when absent; -1 start when not block style."""
    for i, line in enumerate(lines):
        if re.match(rf"^{re.escape(key)}\s*:", line):
            if not re.match(rf"^{re.escape(key)}\s*:\s*(#.*)?$", line):
                return -1, -1
            end = next((j for j in range(i + 1, len(lines)) if _TOP_LEVEL.match(lines[j])), len(lines))
            return i, end
    return None


def _content(lines: list[str], start: int, end: int) -> list[int]:
    return [j for j in range(start, end) if lines[j].strip() and not lines[j].lstrip().startswith("#")]


def _yaml_sq(text: str) -> str:
    """A YAML single-quoted scalar (the guard line contains `: `, which a plain scalar cannot)."""
    return "'" + text.replace("'", "''") + "'"


def _lefthook_block(cmd: str) -> list[str]:
    return ["pre-commit:\n", "  commands:\n", f"    {GUARD_ID}:\n", f"      run: {cmd}\n"]


def _lefthook_insert(text: str, cmd: str) -> str | None:
    lines = _lines(text)
    block = _block(lines, "pre-commit")
    if block is None:
        return "".join(lines + _lefthook_block(cmd))
    start, end = block
    if start < 0:
        return None
    body = _content(lines, start + 1, end)
    step = _indent(lines[body[0]]) if body else 2
    if step == 0:
        return None
    commands = [j for j in body if _indent(lines[j]) == step and lines[j].lstrip().startswith("commands")]
    if not commands:
        lines[start + 1:start + 1] = [f"{' ' * step}commands:\n", f"{' ' * 2 * step}{GUARD_ID}:\n",
                                      f"{' ' * 3 * step}run: {cmd}\n"]
        return "".join(lines)
    at = commands[0]
    if not re.match(r"^\s*commands\s*:\s*(#.*)?$", lines[at]):
        return None
    child = next((_indent(lines[j]) for j in body if j > at), 0)
    child = child if child > step else 2 * step
    lines[at + 1:at + 1] = [f"{' ' * child}{GUARD_ID}:\n", f"{' ' * (child + step)}run: {cmd}\n"]
    return "".join(lines)


def _pre_commit_entry(indent: int, cmd: str) -> list[str]:
    pad = " " * indent
    return [f"{pad}- repo: local\n", f"{pad}  hooks:\n", f"{pad}  - id: {GUARD_ID}\n",
            f"{pad}    name: sbom-audit secrets guard\n", f"{pad}    entry: {cmd}\n",
            f"{pad}    language: system\n", f"{pad}    pass_filenames: false\n", f"{pad}    always_run: true\n",
            f"{pad}    stages: [pre-commit]\n"]


def _pre_commit_insert(text: str, cmd: str) -> str | None:
    lines = _lines(text)
    block = _block(lines, "repos")
    if block is None:
        return "".join(lines + ["repos:\n"] + _pre_commit_entry(0, cmd))
    start, end = block
    if start < 0:
        return None
    body = _content(lines, start + 1, end)
    items = [j for j in body if lines[j].lstrip().startswith("- ")]
    indent = _indent(lines[items[0]]) if items else 0
    at = (body[-1] if body else start) + 1
    lines[at:at] = _pre_commit_entry(indent, cmd)
    return "".join(lines)


def _sh_insert(text: str) -> str | None:
    """Append the line, or put it before a trailing top-level `exit`/`exec`; None when another `exit`/`exec`
    could end the script before the line (nested, or not last)."""
    if not text:
        return f"#!/bin/sh\n{TRACKED_LINE}\n"
    lines = _lines(text)
    body = _content(lines, 0, len(lines))
    at = len(lines)
    if body and re.match(r"^(exit|exec)\b", lines[body[-1]]):
        at = body[-1]
    if any(_EXIT.match(lines[j]) for j in body if j != at):
        return None
    lines[at:at] = [TRACKED_LINE + "\n"]
    return "".join(lines)


def _framework(det: Detection) -> tuple[str, Callable[[str], str | None]]:
    """(the exact addition — one line, or a `\n`-joined YAML block — and an editor `text -> new text | None`)."""
    if det.kind == "lefthook":
        cmd = _yaml_sq(TRACKED_LINE)
        return "".join(_lefthook_block(cmd)).rstrip("\n"), lambda text: _lefthook_insert(text, cmd)
    if det.kind == "pre-commit-framework":
        cmd = _yaml_sq(f"sh -c '{TRACKED_LINE}'")
        return "".join(_pre_commit_entry(0, cmd)).rstrip("\n"), lambda text: _pre_commit_insert(text, cmd)
    return TRACKED_LINE, _sh_insert


def _add(addition: str, where: str) -> str:
    """`add  <line>  <where>`, or `add this block <where>:` followed by the block's lines."""
    if "\n" in addition:
        return f"add this block {where}:\n{addition}"
    return f"add  {addition}  {where}"


def install(repo: Path, cfg_dir: Path, tracked_ok: bool, git=_git, plugin_root: Path | None = None) -> str:
    """Install the guard in `repo`; a summary (its first line is the status; a YAML block may follow).
    Tracked hook files only with `tracked_ok`; a global or system `core.hooksPath` never."""
    repo = Path(repo).resolve()
    guard_py = Path(cfg_dir) / GUARD_NAME
    det = detect(repo, git)
    if det.origin == "global":
        return f"global core.hooksPath {det.hooks_path}: install by hand"
    if not det.tracked:
        root = scheduler.plugin_root() if plugin_root is None else plugin_root
        return _install_hook(repo, det.hook_path, guard_py, root)
    addition, edit = _framework(det)
    rel = _rel(repo, det.hook_path)
    where = f"to {rel}" + (" under repos" if det.kind == "pre-commit-framework" else "")
    note = f"; {HUSKY_INACTIVE}" if det.kind == "husky" and not det.origin else ""
    if not tracked_ok:
        return _with_note(f"needs confirmation ({det.kind}): " + _add(addition, where), note)
    exists = det.hook_path.is_file()
    text = det.hook_path.read_text(encoding="utf-8", errors="replace") if exists else ""
    if GUARD_REF.search(text):
        return _with_note(f"unchanged (guard line already in {rel})", note)
    if "\ufffd" in text:
        return f"not changed: {rel} is not valid UTF-8; " + _add(addition, "by hand")
    new = edit(text)
    if new is None:
        return f"not changed: {rel} has a layout this installer does not edit; " + _add(addition, "by hand")
    mode = det.hook_path.stat().st_mode & 0o777 if exists else HOOK_MODE
    det.hook_path.parent.mkdir(parents=True, exist_ok=True)
    _write(det.hook_path, new, mode)
    return _with_note(f"guard line added to {rel}", note)


def _with_note(summary: str, note: str) -> str:
    """The note goes on the status (first) line, before any YAML block."""
    first, sep, rest = summary.partition("\n")
    return first + note + sep + rest


def uninstall(repo: Path, git=_git) -> str:
    """Remove a guard hook from the git dir and restore `pre-commit.local`; tracked files are left to the user."""
    repo = Path(repo).resolve()
    det = detect(repo, git)
    rel = _rel(repo, det.hook_path)
    if det.origin == "global":
        return f"global core.hooksPath {det.hooks_path}: not managed here (remove the guard there by hand)"
    if det.tracked:
        text = det.hook_path.read_text(encoding="utf-8", errors="replace") if det.hook_path.is_file() else ""
        if not GUARD_REF.search(text):
            return "not installed"
        return f"not removed ({det.kind}): delete the {GUARD_ID} line from {rel} by hand"
    hook = det.hook_path
    if not hook.is_file() or MARKER not in hook.read_text(encoding="utf-8", errors="replace"):
        return "not installed"
    hook.unlink()
    local = hook.with_name(LOCAL_HOOK)
    if local.is_symlink() or local.exists():
        os.replace(local, hook)
        return f"removed ({rel}), {LOCAL_HOOK} restored"
    return f"removed ({rel})"
