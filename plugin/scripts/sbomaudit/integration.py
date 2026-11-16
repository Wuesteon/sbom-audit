"""Opt-in Claude Code integration: autonomous mode and the session status hook (`settings` subcommand).

The plugin ships without hooks, and its skills pre-approve only Read, Grep and Glob, so by default Claude
Code asks before every command. Two opt-ins change that, both written into the user's own
`~/.claude/settings.json` and both reversible:

- autonomous mode: allow rules for exactly this plugin's CLI (the installed path, quoted and unquoted) and
  only for subcommands that read, or write to the local evidence folder, plus WebSearch and WebFetch for
  the advisory domains. `setup` (Dependabot on GitHub) and `hosts patch|bootstrap|unbootstrap` (changes on
  servers) are never covered and always ask.
- session hook: copies the stdlib status script to `~/.claude/sbom-audit/session-start.py` and registers it
  as a SessionStart hook. It reads `security/status.json`, makes no network call and exits 0.

What was added is recorded in `~/.claude/sbom-audit/integration.json`, so `off` removes exactly that and
nothing the user wrote. A backup of settings.json is kept before the first change. After a plugin update
the CLI path changes; `refresh` rewrites the recorded rules to the new path (no new rules).
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

from .assess import FETCH_DOMAINS

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
CLI = PLUGIN_ROOT / "scripts" / "sbom_audit_cli.py"
HOOK_TEMPLATE = PLUGIN_ROOT / "templates" / "session-hook" / "session-start.py"
# Subcommands autonomous mode allows: they read, or write only to the local security/ folder. `hosts check`
# logs in with the forced-command audit key, which can only print the package list.
AUTONOMOUS_SUBCOMMANDS = ("status", "lookup", "incident", "code", "issues", "run", "scan", "audit",
                          "vex add", "secrets", "hosts check", "hosts accept")
NEVER_AUTONOMOUS = ("setup", "hosts patch", "hosts bootstrap", "hosts unbootstrap", "settings")
HOOK_MATCHER = "startup|resume|clear"
HOOK_TIMEOUT = 5


class SettingsError(RuntimeError):
    pass


def _paths(home: Path) -> dict[str, Path]:
    base = home / ".claude"
    return {"settings": base / "settings.json", "dir": base / "sbom-audit",
            "state": base / "sbom-audit" / "integration.json", "hook": base / "sbom-audit" / "session-start.py",
            "backup": base / "settings.json.sbom-audit.bak"}


def plugin_version() -> str:
    try:
        return json.loads((PLUGIN_ROOT / ".claude-plugin" / "plugin.json").read_text())["version"]
    except (OSError, ValueError, KeyError):
        from . import __version__
        return __version__


def autonomy_rules(cli: Path = CLI) -> list[str]:
    path = Path(cli).as_posix()
    bash = [f"Bash(python3 {p} {sub} *)" for sub in AUTONOMOUS_SUBCOMMANDS for p in (f'"{path}"', path)]
    return [*bash, "WebSearch", *(f"WebFetch(domain:{d})" for d in FETCH_DOMAINS)]


def hook_command(home: Path) -> str:
    return f'python3 "{_paths(home)["hook"].as_posix()}"'


def _load(path: Path, default):
    if not path.exists():
        return default
    try:
        data = json.loads(path.read_text(encoding="utf-8") or "{}")
    except ValueError as exc:
        raise SettingsError(f"{path}: not valid JSON ({exc}); fix it by hand, nothing changed") from None
    if not isinstance(data, dict):
        raise SettingsError(f"{path}: not a JSON object; nothing changed")
    return data


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _save_settings(p: dict[str, Path], settings: dict) -> None:
    if p["settings"].exists() and not p["backup"].exists():
        shutil.copy2(p["settings"], p["backup"])
    _write(p["settings"], settings)


def _allow(settings: dict) -> list:
    perms = settings.setdefault("permissions", {})
    if not isinstance(perms, dict):
        raise SettingsError("settings.json: `permissions` is not an object; nothing changed")
    allow = perms.setdefault("allow", [])
    if not isinstance(allow, list):
        raise SettingsError("settings.json: `permissions.allow` is not a list; nothing changed")
    return allow


def _session_hooks(settings: dict) -> list:
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise SettingsError("settings.json: `hooks` is not an object; nothing changed")
    entries = hooks.setdefault("SessionStart", [])
    if not isinstance(entries, list):
        raise SettingsError("settings.json: `hooks.SessionStart` is not a list; nothing changed")
    return entries


def _is_our_hook(entry, command: str) -> bool:
    return isinstance(entry, dict) and any(isinstance(h, dict) and h.get("command") == command
                                           for h in entry.get("hooks") or [])


def _prune_empty(settings: dict) -> None:
    hooks = settings.get("hooks")
    if isinstance(hooks, dict):
        if hooks.get("SessionStart") == []:
            del hooks["SessionStart"]
        if not hooks:
            del settings["hooks"]
    perms = settings.get("permissions")
    if isinstance(perms, dict):
        if perms.get("allow") == []:
            del perms["allow"]
        if not perms:
            del settings["permissions"]


def set_autonomy(on: bool, home: Path, cli: Path = CLI) -> list[str]:
    p = _paths(home)
    settings, state = _load(p["settings"], {}), _load(p["state"], {})
    allow = _allow(settings)
    ours = list(state.get("rules") or [])
    if on:
        wanted = autonomy_rules(cli)
        stale = [r for r in ours if r not in wanted]
        allow[:] = [r for r in allow if r not in stale]
        added = [r for r in wanted if r not in allow]
        allow.extend(added)
        state["rules"] = [r for r in ours if r in wanted] + added
        state["cli"] = Path(cli).as_posix()
        lines = [f"autonomous mode on: {len(added)} allow rule(s) added to {p['settings']}"
                 + (f", {len(stale)} stale removed" if stale else ""),
                 "  allowed without asking: " + ", ".join(AUTONOMOUS_SUBCOMMANDS) + "; WebSearch; WebFetch on "
                 + ", ".join(FETCH_DOMAINS),
                 "  still asks every time: " + ", ".join(NEVER_AUTONOMOUS) + ", gh, git and any other command"]
    else:
        allow[:] = [r for r in allow if r not in ours]
        lines = [f"autonomous mode off: {len(ours)} rule(s) removed from {p['settings']}" if ours
                 else "autonomous mode was not on; nothing changed"]
        state.pop("rules", None)
        state.pop("cli", None)
    _prune_empty(settings)
    _save_settings(p, settings)
    _write(p["state"], state)
    return lines


def _install_hook_file(p: dict[str, Path]) -> None:
    text = HOOK_TEMPLATE.read_text(encoding="utf-8")
    text = text.replace("\nVERSION = None\n", f"\nVERSION = {plugin_version()!r}\n", 1)
    p["dir"].mkdir(parents=True, exist_ok=True)
    tmp = p["hook"].with_name(p["hook"].name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, p["hook"])


def set_session_hook(on: bool, home: Path) -> list[str]:
    p = _paths(home)
    settings, state = _load(p["settings"], {}), _load(p["state"], {})
    entries = _session_hooks(settings)
    command = hook_command(home)
    present = any(_is_our_hook(e, command) for e in entries)
    if on:
        _install_hook_file(p)
        if not present:
            entries.append({"matcher": HOOK_MATCHER,
                            "hooks": [{"type": "command", "command": command, "timeout": HOOK_TIMEOUT}]})
        state["hook"] = True
        lines = [f"session hook on: {p['hook']} registered in {p['settings']} (SessionStart, {HOOK_MATCHER})"
                 if not present else f"session hook already on; script refreshed at {p['hook']}"]
    else:
        entries[:] = [e for e in entries if not _is_our_hook(e, command)]
        if p["hook"].exists():
            p["hook"].unlink()
        state.pop("hook", None)
        lines = ["session hook off: entry and script removed" if present else "session hook was not on; nothing changed"]
    _prune_empty(settings)
    _save_settings(p, settings)
    _write(p["state"], state)
    return lines


def status_lines(home: Path, cli: Path = CLI) -> list[str]:
    p = _paths(home)
    state = _load(p["state"], {})
    rules = state.get("rules") or []
    if not rules:
        auto = "off (Claude Code asks before each command)"
    elif state.get("cli") != Path(cli).as_posix():
        auto = f"on, but for an older plugin path ({state.get('cli')}); run `settings --autonomy on` to refresh"
    else:
        auto = f"on ({len(rules)} rules in {p['settings']})"
    hook = "on" if state.get("hook") and p["hook"].exists() else "off"
    return [f"autonomous mode: {auto}", f"session hook: {hook}"]


def refresh(home: Path, cli: Path = CLI) -> list[str]:
    """After a plugin update: point recorded rules at the current CLI path and refresh the hook script.

    Adds nothing the user did not opt into; does nothing when neither opt-in is on or all is current."""
    p = _paths(home)
    if not p["state"].exists():
        return []
    state = _load(p["state"], {})
    lines = []
    if state.get("rules") and state.get("cli") != Path(cli).as_posix():
        lines += set_autonomy(True, home, cli)[:1]
    if state.get("hook") and p["hook"].exists():
        current = p["hook"].read_text(encoding="utf-8")
        if f"\nVERSION = {plugin_version()!r}\n" not in current:
            _install_hook_file(p)
            lines.append(f"session hook script refreshed for {plugin_version()}")
    return lines


def cli(args) -> int:
    home = Path(os.environ.get("SBOM_AUDIT_HOME") or Path.home())
    try:
        lines: list[str] = []
        if args.autonomy:
            lines += set_autonomy(args.autonomy == "on", home)
        if args.session_hook:
            lines += set_session_hook(args.session_hook == "on", home)
        lines += status_lines(home)
    except (SettingsError, OSError) as exc:
        print(f"settings: {exc}", file=sys.stderr)
        return 2
    print("\n".join(lines))
    return 0
