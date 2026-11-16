"""Weekly run by a per-user timer: launchd (macOS) or a systemd user timer (Linux).

The timer executes a small wrapper script that resolves the plugin's install path when it runs, so a
plugin update does not break the timer. `.cache/scheduler.json` records what the scheduler did; the status
screen and the SessionStart hook read it to say when the timer did not fire.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import plistlib
import re
import socket
import subprocess
from pathlib import Path

from . import status
from .cache import atomic_write

STATE_FILE = ".cache/scheduler.json"
LABEL_PREFIX = "dev.waiser.sbom-audit."
UNIT_PREFIX = "sbom-audit-"
ACTIONS_TEMPLATE = "templates/github-actions/sbom-audit.yml"
FIRE_WEEKDAY, FIRE_HOUR = 5, 3            # Saturday 03:00 local (launchd counts Sunday as 0, so Saturday is 6)
_CACHE_LAYOUT = re.compile(r"plugins/cache/([^/]+)/([^/]+)/[^/]+/?$")


def _stamp(when: dt.datetime) -> str:
    return when.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def config_dir(env=os.environ, home: Path | None = None) -> Path:
    xdg = env.get("XDG_CONFIG_HOME")
    return (Path(xdg) if xdg else (home or Path.home()) / ".config") / "sbom-audit"


def portfolio_id(out: Path) -> str:
    return hashlib.sha256(str(Path(out).resolve()).encode("utf-8")).hexdigest()[:8]


def label(out: Path) -> str:
    return LABEL_PREFIX + portfolio_id(out)


def unit_name(out: Path) -> str:
    return UNIT_PREFIX + portfolio_id(out)


def plugin_root(env=os.environ) -> Path:
    """This plugin's root: `$CLAUDE_PLUGIN_ROOT`, else the checkout this module lives in."""
    root = env.get("CLAUDE_PLUGIN_ROOT")
    return Path(root) if root else Path(__file__).resolve().parents[2]


def plugin_id_from_root(root: Path) -> str | None:
    """`…/plugins/cache/<marketplace>/<name>/<version>` -> `<name>@<marketplace>`; None for a dev checkout."""
    match = _CACHE_LAYOUT.search(Path(root).as_posix())
    return f"{match.group(2)}@{match.group(1)}" if match else None


def resolve_install_path(installed_json: Path, plugin_id: str) -> Path | None:
    """`installPath` of the entry with the newest `lastUpdated` in Claude Code's installed_plugins.json."""
    try:
        data = json.loads(Path(installed_json).read_text(encoding="utf-8"))
        entries = [e for e in data["plugins"][plugin_id] if isinstance(e, dict) and e.get("installPath")]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not entries:
        return None
    return Path(max(entries, key=lambda e: str(e.get("lastUpdated") or ""))["installPath"])


def next_fire(now: dt.datetime) -> str:
    """The coming Saturday 03:00 in local time (today when it is Saturday before 03:00)."""
    now = now.astimezone()
    days = (FIRE_WEEKDAY - now.weekday()) % 7
    fire = (now + dt.timedelta(days=days)).replace(hour=FIRE_HOUR, minute=0, second=0, microsecond=0)
    if fire <= now:
        fire += dt.timedelta(days=7)
    return fire.isoformat()


# --------------------------------------------------------------------------- state

def read_state(out: Path) -> dict | None:
    try:
        data = json.loads((Path(out) / STATE_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def write_state(out: Path, state: dict) -> Path:
    return atomic_write(Path(out) / STATE_FILE, json.dumps(state, indent=1) + "\n")


def missed_fire(state: dict | None, now: dt.datetime) -> str | None:
    """The ISO date to report when an installed timer has not fired for more than 8 days (counted from
    `installed_at` while it never fired); the same rule as `status` and the SessionStart hook."""
    if not state or not state.get("installed"):
        return None
    since = state.get("last_fired") or state.get("installed_at")
    when = status._parse(since)
    if when is None or status._elapsed(when, now) > dt.timedelta(days=status.SCHEDULER_MISSED_DAYS):
        return (since or "install")[:10]
    return None


# --------------------------------------------------------------------------- wrapper

# Runs under launchd/systemd with a minimal PATH and possibly the system python3, so it is plain
# Python 3.6+ syntax, extends PATH with the usual tool locations and looks for python >= 3.11 itself.
_WRAPPER = '''#!/usr/bin/env python3
"""sbom-audit weekly run (written by `sbom-audit setup --schedule weekly`; do not edit)."""
import datetime, json, os, shutil, subprocess, sys

OUT = {out!r}
PLUGIN_ID = {plugin_id!r}
FALLBACK_ROOT = {fallback_root!r}
STATE = os.path.join(OUT, ".cache", "scheduler.json")
CLI = os.path.join("scripts", "sbom_audit_cli.py")
TOOL_DIRS = ["/opt/homebrew/bin", "/usr/local/bin", "/home/linuxbrew/.linuxbrew/bin",
             os.path.expanduser("~/.local/bin")]


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def update_state(**fields):
    try:
        with open(STATE, encoding="utf-8") as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        state = {{}}
    state.update(fields)
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + ".%d.tmp" % os.getpid()
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=1)
            fh.write("\\n")
        os.replace(tmp, STATE)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def install_path():
    if PLUGIN_ID:
        try:
            with open(os.path.expanduser("~/.claude/plugins/installed_plugins.json"), encoding="utf-8") as fh:
                entries = json.load(fh)["plugins"][PLUGIN_ID]
            entries = [e for e in entries if isinstance(e, dict) and e.get("installPath")]
            path = max(entries, key=lambda e: str(e.get("lastUpdated") or ""))["installPath"]
            if os.path.isfile(os.path.join(path, CLI)):
                return path
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            pass
    return FALLBACK_ROOT if os.path.isfile(os.path.join(FALLBACK_ROOT, CLI)) else None


def python(env):
    if sys.version_info >= (3, 11):
        return sys.executable
    for name in ["python3.%d" % minor for minor in range(15, 10, -1)] + ["python3"]:
        found = shutil.which(name, path=env["PATH"])
        if not found:
            continue
        try:
            if subprocess.call([found, "-c", "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"]) == 0:
                return found
        except OSError:
            continue
    return None


def run_once():
    runs = os.path.join(OUT, ".cache", "runs")
    os.makedirs(runs, exist_ok=True)
    log_path = os.path.join(runs, datetime.date.today().isoformat() + ".log")
    update_state(last_fired=stamp(), last_exit=None, last_error=None)
    env = dict(os.environ)
    env["PATH"] = os.pathsep.join([d for d in TOOL_DIRS if os.path.isdir(d)] + [env.get("PATH", "")])
    env["SBOM_AUDIT_SCHEDULED"] = "1"    # the CLI refuses `hosts ... --confirm` under this marker
    install = install_path()
    py = python(env)
    with open(log_path, "a", encoding="utf-8") as log:
        log.write("== sbom-audit weekly run " + stamp() + " ==\\n")
        error = None
        if install is None:
            error = "plugin install path not found (plugin id %s, fallback %s)" % (PLUGIN_ID, FALLBACK_ROOT)
        elif py is None:
            error = "python 3.11 or newer not found on PATH"
        if error:
            log.write(error + "\\n")
            update_state(last_exit=127, last_error=error)
            return 127
        log.write("plugin install: " + install + "\\n")
        log.flush()
        code = subprocess.call([py, os.path.join(install, CLI), "run", "--out", OUT],
                               stdout=log, stderr=subprocess.STDOUT, cwd=OUT, env=env)
        log.write("== exit " + str(code) + " ==\\n")
    update_state(last_exit=code, last_error=None)
    return code


def main():
    try:
        return run_once()
    except Exception as exc:    # every exit path records last_exit and last_error
        error = "wrapper failed: %s: %s" % (type(exc).__name__, exc)
        try:
            with open(os.path.join(OUT, ".cache", "runs", datetime.date.today().isoformat() + ".log"), "a",
                      encoding="utf-8") as log:
                log.write(error + "\\n")
        except OSError:
            pass
        try:
            update_state(last_exit=1, last_error=error)
        except Exception:    # the state file itself is what failed; stderr is all that is left
            print(error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
'''


def write_wrapper(out: Path, plugin_id: str | None, fallback_root: Path, cfg_dir: Path) -> Path:
    """`<cfg_dir>/run-weekly-<id>.py`: resolves the install path at run time, logs to `.cache/runs/<date>.log`."""
    out = Path(out).resolve()
    path = Path(cfg_dir) / f"run-weekly-{portfolio_id(out)}.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_WRAPPER.format(out=str(out), plugin_id=plugin_id, fallback_root=str(fallback_root)),
                    encoding="utf-8")
    path.chmod(0o755)
    return path


# --------------------------------------------------------------------------- launchd / systemd

def launchd_plist(label: str, wrapper: Path, log_dir: Path) -> bytes:
    log = str(Path(log_dir) / "launchd.log")
    return plistlib.dumps({
        "Label": label,
        "ProgramArguments": ["/usr/bin/env", "python3", str(wrapper)],
        "StartCalendarInterval": {"Weekday": 6, "Hour": FIRE_HOUR, "Minute": 0},
        "RunAtLoad": False,
        "StandardOutPath": log,
        "StandardErrorPath": log,
    })


def _exec_arg(path: Path) -> str:
    text = str(path)
    return '"' + text.replace('"', '\\"') + '"' if re.search(r"\s", text) else text


def systemd_units(name: str, wrapper: Path) -> tuple[str, str]:
    """(`.service`, `.timer`) texts."""
    service = ("[Unit]\nDescription=sbom-audit weekly run\n\n"
               "[Service]\nType=oneshot\n"
               f"ExecStart=/usr/bin/env python3 {_exec_arg(wrapper)}\n")
    timer = (f"[Unit]\nDescription=sbom-audit weekly timer ({name})\n\n"
             "[Timer]\nOnCalendar=Sat 03:00\nPersistent=true\n\n"
             "[Install]\nWantedBy=timers.target\n")
    return service, timer


def _paths(out: Path, home: Path, platform: str) -> list[Path]:
    if platform == "darwin":
        return [home / "Library" / "LaunchAgents" / f"{label(out)}.plist"]
    unit_dir = home / ".config" / "systemd" / "user"
    return [unit_dir / f"{unit_name(out)}.service", unit_dir / f"{unit_name(out)}.timer"]


def _supported(platform: str) -> str | None:
    if platform == "darwin":
        return "darwin"
    return "linux" if platform.startswith("linux") else None


def _unsupported(platform: str) -> str:
    return f"scheduling not supported on {platform}; use {ACTIONS_TEMPLATE}"


def _failure(what: str, proc) -> str:
    detail = ((getattr(proc, "stderr", "") or getattr(proc, "stdout", "") or "").strip().splitlines() or [""])[0]
    return f"scheduler install failed: {what} exit {proc.returncode}" + (f" ({detail})" if detail else "")


def _call(run, cmd: list[str]):
    """(CompletedProcess, None) or (None, reason) when the tool itself cannot be started (not installed)."""
    try:
        return run(cmd, text=True, capture_output=True), None
    except OSError as exc:
        return None, f"{cmd[0]} could not be run ({exc.strerror or type(exc).__name__})"


def install_weekly(out: Path, plugin_root: Path, home: Path, platform: str, run=subprocess.run,
                   now: dt.datetime | None = None, cfg_dir: Path | None = None) -> list[str]:
    """Write the wrapper, the timer files and the state, load the timer; returns the lines to print."""
    kind = _supported(platform)
    if kind is None:
        return [_unsupported(platform)]
    out, home = Path(out).resolve(), Path(home)
    now = now or dt.datetime.now().astimezone()
    cfg_dir = Path(cfg_dir) if cfg_dir else config_dir(home=home)
    plugin_id = plugin_id_from_root(plugin_root)
    wrapper = write_wrapper(out, plugin_id, plugin_root, cfg_dir)
    lines = [f"wrapper: {wrapper} (resolves {plugin_id or plugin_root} when it runs)"]
    files = _paths(out, home, kind)
    for path in files:
        path.parent.mkdir(parents=True, exist_ok=True)
    uid = os.getuid()
    if kind == "darwin":
        files[0].write_bytes(launchd_plist(label(out), wrapper, out / ".cache" / "runs"))
        _call(run, ["launchctl", "bootout", f"gui/{uid}/{label(out)}"])        # reinstall: unload first
        loads = [["launchctl", "bootstrap", f"gui/{uid}", str(files[0])]]
    else:
        service, timer = systemd_units(unit_name(out), wrapper)
        files[0].write_text(service, encoding="utf-8")
        files[1].write_text(timer, encoding="utf-8")
        loads = [["systemctl", "--user", "daemon-reload"],
                 ["systemctl", "--user", "enable", "--now", f"{unit_name(out)}.timer"]]
    installed, failure = True, None
    for cmd in loads:
        proc, reason = _call(run, cmd)
        if proc is None:
            installed, failure = False, f"scheduler install failed: {reason}"
        elif proc.returncode != 0:
            installed, failure = False, _failure(cmd[0] if cmd[0] == "launchctl" else " ".join(cmd[:3]), proc)
        if failure:
            for path in files:      # never leave a timer file that the platform would load while state says "not installed"
                path.unlink(missing_ok=True)
            break
    previous = read_state(out) or {}
    write_state(out, {"installed": installed, "schedule": "weekly", "installed_at": _stamp(now),
                      "last_fired": previous.get("last_fired") if installed else None,
                      "last_exit": previous.get("last_exit") if installed else None,
                      "next_fire": next_fire(now) if installed else None, "plugin_id": plugin_id,
                      "wrapper": str(wrapper), "platform": kind, "label": label(out)})
    if failure:
        return lines + [failure]
    lines += [f"timer: {p}" for p in files]
    lines.append(f"scheduler: installed, weekly Saturday 03:00 local, next fire {next_fire(now)}")
    doc = status.read(out)
    host = socket.gethostname()
    if doc and doc.get("run_host") and doc["run_host"] != host:
        lines.append(f"warning: the last run happened on {doc['run_host']}, this timer runs on {host}; "
                     "install it on the machine that should audit")
    return lines


def remove(out: Path, home: Path, platform: str, run=subprocess.run, cfg_dir: Path | None = None) -> list[str]:
    """Unload the timer, delete its files and the wrapper, mark the state `installed = false`."""
    kind = _supported(platform)
    if kind is None:
        return [_unsupported(platform)]
    out, home = Path(out).resolve(), Path(home)
    state = read_state(out) or {}
    wrapper_name = f"run-weekly-{portfolio_id(out)}.py"
    wrapper = Path(state["wrapper"]) if state.get("wrapper") else (
        (Path(cfg_dir) if cfg_dir else config_dir(home=home)) / wrapper_name)
    files = _paths(out, home, kind)
    if wrapper.name == wrapper_name:                    # only a file this module wrote
        files.append(wrapper)
    if not state.get("installed") and not any(p.exists() for p in files):
        return ["scheduler: not installed"]
    unload = (["launchctl", "bootout", f"gui/{os.getuid()}/{label(out)}"] if kind == "darwin"
              else ["systemctl", "--user", "disable", "--now", f"{unit_name(out)}.timer"])
    _, reason = _call(run, unload)       # a non-zero exit is normal when the timer was never loaded
    if reason:
        return [f"scheduler remove failed: {reason}"]
    for path in files:
        path.unlink(missing_ok=True)
    if kind == "linux":
        _call(run, ["systemctl", "--user", "daemon-reload"])
    write_state(out, {**state, "installed": False, "next_fire": None})
    return ["scheduler: removed"]
