"""Run the secrets engine (gitleaks 8, or betterleaks 1.x) over one repository's history.

gitleaks' own stdout/stderr are captured and never re-printed. Its raw report holds secret values, so it
lives only in a 0600 file under `raw_dir` and is unlinked in a `finally`.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from sbomaudit import gitio, preflight
from sbomaudit.errors import EngineError

RULES_PATH = Path(__file__).resolve().parents[3] / "secrets" / "gitleaks.toml"   # parents[3] = plugin root
BETTERLEAKS_ENV = {"BETTERLEAKS_VALIDATE": "false", "BETTERLEAKS_ANALYZE": "false"}
CANDIDATES = (("gitleaks", "8."), ("betterleaks", "1."), ("betterleaks-v1", "1."))
VERSION_TIMEOUT = 30
SCAN_TIMEOUT = 600
# always in front of the caller's log options: no textconv or external diff driver from the repository
SAFE_LOG_OPTS = "--no-textconv --no-ext-diff"
ANSI = re.compile(r"\x1b\[[0-9;]*m")
# zerolog console timestamps: "10:08PM " or RFC 3339 "2026-11-07T10:08:00Z "
TIMESTAMP = re.compile(r"^(?:\d{1,2}:\d{2}(?::\d{2})?\s?[AP]M|\d{4}-\d{2}-\d{2}T\S+)\s+")


@dataclass
class Engine:
    binary: str
    name: str
    version: str
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class EngineProblem:
    reason: str       # "missing" or "unsupported (<name> <version>)"
    detail: str = ""  # the install line for "missing"


def _version(binary: str, run) -> str | None:
    try:
        proc = run([binary, "version"], capture_output=True, text=True, errors="replace",
                   timeout=VERSION_TIMEOUT)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return (proc.stdout or "").strip().removeprefix("v") or None


def find_engine(which=shutil.which, run=subprocess.run) -> Engine | EngineProblem:
    """gitleaks 8.x first, then betterleaks 1.x (validation and analysis off); 2.x is unsupported."""
    unsupported: EngineProblem | None = None
    for name, major in CANDIDATES:
        binary = which(name)
        if not binary:
            continue
        version = _version(binary, run)
        if version is None:
            continue
        if version.startswith(major):
            env = {} if name == "gitleaks" else dict(BETTERLEAKS_ENV)
            return Engine(binary, name, version, env)
        unsupported = unsupported or EngineProblem(f"unsupported ({name} {version})")
    return unsupported or EngineProblem("missing", preflight.SECRETS_INSTALL)


def log_opts_full() -> str:
    return "--all"


def log_opts_since(tips: list[str]) -> str:
    """Every commit reachable from any ref but not from the tips scanned last time."""
    return " ".join(["--all", *("^" + tip for tip in tips)])


def _stderr_lines(stderr: str | None) -> list[str]:
    """gitleaks' log lines without colour codes and timestamps, empty lines dropped."""
    lines = (TIMESTAMP.sub("", ANSI.sub("", line)).strip() for line in (stderr or "").splitlines())
    return [line for line in lines if line]


def _error_line(stderr: str | None) -> str | None:
    """The first ERR/FTL line (or a swallowed `git log` failure); these name paths and shas, never values."""
    for line in _stderr_lines(stderr):
        if line.startswith(("ERR ", "FTL ")) or "[git] fatal" in line:
            return line
    return None


def _read_rows(path: Path) -> list[dict] | None:
    try:
        rows = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        return None
    return rows


def scan_repo(engine: Engine, repo: Path, *, log_opts: str, ignore_file: Path | None, raw_dir: Path,
              run=subprocess.run) -> list[dict]:
    """Scan `repo`'s git history; return gitleaks' report rows (raw `Secret` included, in memory only)."""
    # gitleaks runs under cwd=raw_dir: every path it sees must be absolute
    repo, raw_dir = Path(repo).resolve(), Path(raw_dir).resolve()
    ignore_file = Path(ignore_file).resolve() if ignore_file is not None else None
    raw_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    raw_dir.chmod(0o700)
    with tempfile.NamedTemporaryFile(dir=raw_dir, delete=False, suffix=".json") as handle:
        raw = Path(handle.name).resolve()
    try:
        os.chmod(raw, 0o600)
        argv = [engine.binary, "git", "--no-banner", "--no-color", "-c", str(RULES_PATH),
                "-f", "json", "-r", str(raw), "--exit-code", "1", "--log-opts", f"{SAFE_LOG_OPTS} {log_opts}"]
        if ignore_file is not None:
            argv += ["-i", str(ignore_file)]
        argv.append(str(repo))
        # gitleaks' own `git log` inherits the hardening config (no fsmonitor, hooks, external diff)
        env = gitio.git_env({**os.environ, **engine.env})
        try:
            # cwd=raw_dir: gitleaks' `-i` default "." must never resolve to an audited repo's ignore file.
            # umask 077: gitleaks replaces the report file, which would otherwise come out 0644.
            proc = run(argv, capture_output=True, text=True, errors="replace", cwd=raw_dir, env=env,
                       umask=0o077, timeout=SCAN_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise EngineError("timed out") from None
        except OSError as exc:
            raise EngineError(f"{engine.name} could not start: {exc.strerror or type(exc).__name__}") from None
        if raw.exists():
            os.chmod(raw, 0o600)
        if proc.returncode == 0:
            # gitleaks swallows `git log` failures (a vanished tip, a missing repo) and exits 0
            error = _error_line(proc.stderr)
            if error is not None:
                raise EngineError(error)
            return []
        if proc.returncode == 1:
            rows = _read_rows(raw)
            if rows is None:
                raise EngineError(f"{engine.name} exit 1 without a parsable report")
            return rows
        first = _error_line(proc.stderr) or next(iter(_stderr_lines(proc.stderr)), "")
        detail = f"{engine.name} exit {proc.returncode}"
        raise EngineError(f"{detail}: {first}" if first else detail)
    finally:
        raw.unlink(missing_ok=True)
