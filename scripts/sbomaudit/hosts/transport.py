"""Host mode transport: one read-only `ssh … collect` per host, with the host key pinned under an alias.

The audit key logs in as `sbom-audit`, whose forced command runs the collector; the remote command word
`collect` is all the client ever sends. Host keys are checked strictly against `<out>/hosts/known_hosts`
under the alias `sbom-audit-<host>` (so an IP or a `~/.ssh/config` alias both work, and the user's own
known_hosts never counts). Nothing here writes on the host.

`collect` retries once, after `retry_after_s`, when the connection failed (ssh exit 255), the call timed out
or the output was not JSON (a reboot window, a dropped connection). A changed host key is never retried: it
is the one transport failure that is a finding (`host_key_changed`). Every other failure (sudo asking for a
password, the forced command failing) is a failed source on the first attempt.

The admin side (`hosts bootstrap` / `unbootstrap`) logs in with the user's own ssh setup (their config, keys
and known_hosts) as the configured `admin` login. `AdminSession` holds one ControlMaster connection open for
the whole change, so a broken sshd edit can still be rolled back through it; `fresh_login` deliberately
bypasses that master (`ControlPath=none`) to prove a brand-new admin login still works.
"""
from __future__ import annotations

import json
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .store import ALIAS_PREFIX, KNOWN_HOSTS

USER = "sbom-audit"
COMMAND = "collect"
CHANGED = "REMOTE HOST IDENTIFICATION HAS CHANGED"
VERIFY_FAILED = "Host key verification failed"
NOT_KNOWN = "host key is known for"
MAX_ERROR = 300
PERSIST = "2h"                                  # a kept admin master closes after 2 idle hours


@dataclass(frozen=True)
class CollectResult:
    doc: dict | None
    error: str | None
    host_key_changed: bool = False


def _option_path(path: Path) -> str:
    text = str(path)
    return f'"{text}"' if any(c.isspace() for c in text) else text


def ssh_argv(opts, host: str, h, out: Path) -> list[str]:
    address = h.address
    if not isinstance(address, str) or not address or address.startswith("-") \
            or any(c.isspace() for c in address):
        raise ValueError(f"host {host}: invalid address {address!r}")
    known = _option_path(Path(out) / KNOWN_HOSTS)
    return ["ssh", "-i", str(opts.key), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known}",
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", f"HostKeyAlias={ALIAS_PREFIX}{host}",
            "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=4",
            "-o", "ControlPath=none", "-l", USER, address, COMMAND]


def _text(data) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)


def _first_line(text: str) -> str:
    line = next((ln.strip() for ln in text.splitlines() if ln.strip() and not set(ln.strip()) <= {"@"}), "")
    return line[:MAX_ERROR]


def _attempt(argv: list[str], timeout_s: int, run, pinned: bool) -> tuple[CollectResult, bool]:
    """One ssh call: (result, retryable). `pinned`: the alias already has lines in known_hosts, so "no host
    key is known" means the host now offers only a key type that was never pinned: a changed key."""
    try:
        proc = run(argv, capture_output=True, timeout=timeout_s, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return CollectResult(None, f"ssh timed out after {timeout_s} s"), True
    except OSError as exc:
        return CollectResult(None, f"ssh could not be started: {type(exc).__name__}: {exc}"), False
    stderr = _text(proc.stderr)
    if CHANGED in stderr:
        return CollectResult(None, "host key changed: REMOTE HOST IDENTIFICATION HAS CHANGED", True), False
    if VERIFY_FAILED in stderr:
        if NOT_KNOWN in stderr and not pinned:
            return CollectResult(None, "no pinned host key: run `hosts bootstrap` for this host first"), False
        return CollectResult(None, f"host key verification failed: {_first_line(stderr)}", True), False
    if proc.returncode == 255:
        return CollectResult(None, f"ssh failed (exit 255): {_first_line(stderr) or 'no error output'}"), True
    if proc.returncode != 0:
        # stderr only: stdout is the collector's document and may carry host data
        detail = _first_line(stderr) or "no stderr"
        return CollectResult(None, f"collector failed (exit {proc.returncode}): {detail}"), False
    try:
        doc = json.loads(_text(proc.stdout))
    except ValueError:
        return CollectResult(None, "collector output is not JSON (truncated or garbled)"), True
    if not isinstance(doc, dict):
        return CollectResult(None, "collector output is not a JSON object"), False
    return CollectResult(doc, None), False


def collect(argv: list[str], timeout_s: int, run=subprocess.run, sleep=time.sleep,
            retry_after_s: int = 300, pinned: bool = False) -> CollectResult:
    result, retryable = _attempt(argv, timeout_s, run, pinned)
    if not retryable:
        return result
    sleep(retry_after_s)
    second, _ = _attempt(argv, timeout_s, run, pinned)
    if second.doc is None and not second.host_key_changed:
        first = "" if second.error == result.error else f"; first attempt: {result.error}"
        return CollectResult(None, f"{second.error} (after one retry{first})")
    return second


def audit_fingerprint(key: Path, run=subprocess.run) -> str:
    """The SHA256 fingerprint of the audit key (`ssh-keygen -lf <key>.pub`); ValueError when there is none."""
    proc = run(["ssh-keygen", "-lf", f"{key}.pub"], capture_output=True, timeout=30, stdin=subprocess.DEVNULL)
    for field in _text(proc.stdout).split():
        if field.startswith("SHA256:"):
            return field
    raise ValueError("ssh-keygen gave no SHA256 fingerprint for the audit key")


def collect_once(argv: list[str], timeout_s: int, run=subprocess.run, pinned: bool = False) -> CollectResult:
    """One `collect` attempt, no retry (bootstrap's "is it already set up?" probe)."""
    return _attempt(argv, timeout_s, run, pinned)[0]


# --------------------------------------------------------------------------- admin login

@dataclass(frozen=True)
class Proc:
    rc: int
    out: str
    err: str


class AdminError(Exception):
    """The admin login could not be opened or used."""


def admin_argv(target) -> list[str]:
    """`ssh` options for the admin login `target` (`user@host` or a `~/.ssh/config` alias); ValueError when it
    could be read as an option or carries whitespace or control characters."""
    if not isinstance(target, str) or not target or target.startswith("-") \
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in target):
        raise ValueError("invalid admin login")
    # UpdateHostKeys=no: an admin login never rewrites the user's known_hosts behind their back
    return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20", "-o", "UpdateHostKeys=no", target]


def fresh_login(target_argv: list[str], run=subprocess.run, sleep=time.sleep, retry_after_s: float = 3) -> bool:
    """True when a brand-new login (no ControlMaster reuse) with `target_argv` runs `true`. A failure is tried once
    more after `retry_after_s`: a reload or a busy sshd (MaxStartups) must not read as "locked out"."""
    argv = [target_argv[0], "-o", "ControlPath=none", "-o", "ControlMaster=no", "-o", "UpdateHostKeys=no",
            *target_argv[1:], "true"]
    for attempt in range(2):
        if attempt:
            sleep(retry_after_s)
        try:
            proc = run(argv, capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            return True
    return False


_UNSET = object()


class AdminSession:
    """One ControlMaster connection as the admin login, held open while a change runs.

    `sh(script, args)` runs `sh -s -- <args>` as root (prefixed with `sudo -n` when the login is not root),
    the script text and `stdin_extra` on stdin. `privilege()` is "root", "sudo" (passwordless) or None.
    `keep_open()` leaves the master running after the `with` block (a failed rollback: the user still has a
    way in) and returns its control path."""

    def __init__(self, target, control_dir, run=subprocess.run):
        self.argv = admin_argv(target)
        self.target = target
        self.dir = Path(control_dir)
        self.ctl = str(self.dir / "m")
        self.run = run
        self._privilege = _UNSET
        self._kept = False

    def __enter__(self):
        argv = ["ssh", "-M", "-N", "-f", "-o", f"ControlPersist={PERSIST}", "-o", "ServerAliveInterval=30",
                "-o", "ServerAliveCountMax=4", "-S", self.ctl, *self.argv[1:]]
        err_path = self.dir / "master.err"
        try:
            # `-f` leaves a background ssh holding stderr: a file, never a pipe, or this call would never return
            with open(err_path, "wb") as err:
                proc = self.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err, timeout=90)
        except subprocess.TimeoutExpired:
            raise AdminError("admin login timed out") from None
        except OSError as exc:
            raise AdminError(f"ssh could not be started ({type(exc).__name__})") from None
        if proc.returncode != 0:
            try:
                detail = _first_line(err_path.read_text(errors="replace"))
            except OSError:
                detail = ""
            raise AdminError(f"admin login failed (exit {proc.returncode}){': ' + detail if detail else ''}")
        return self

    def __exit__(self, *exc):
        if not self._kept:
            try:
                self.run(["ssh", "-S", self.ctl, "-O", "exit", self.target], capture_output=True, timeout=30,
                         stdin=subprocess.DEVNULL)
            except (OSError, subprocess.TimeoutExpired):
                pass
        return False

    def keep_open(self) -> str:
        self._kept = True
        return self.ctl

    @property
    def kept(self) -> bool:
        return self._kept

    def command(self, remote: str, as_root: bool = False, timeout: int = 60) -> Proc:
        if as_root and not self.is_root:
            if self.privilege() is None:
                raise AdminError("the admin login has no passwordless sudo")
            remote = "sudo -n " + remote
        return self._call(remote, b"", timeout)

    def _call(self, remote: str, data: bytes, timeout: int) -> Proc:
        argv = ["ssh", "-S", self.ctl, "-o", "ControlMaster=no", *self.argv[1:], remote]
        try:
            proc = self.run(argv, input=data, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            # keep what arrived: a marker printed before the timeout (ALLOWUSERS_EDITED) still matters
            err = _text(exc.stderr)
            return Proc(124, _text(exc.stdout), (err + "\n" if err else "") + f"timed out after {timeout} s")
        return Proc(proc.returncode, _text(proc.stdout), _text(proc.stderr))

    def privilege(self):
        if self._privilege is _UNSET:
            uid = self._call("id -u", b"", 60)
            if uid.rc != 0:
                raise AdminError(f"id -u failed on the admin login (exit {uid.rc})")
            if uid.out.strip() == "0":
                self._privilege = "root"
            else:
                self._privilege = "sudo" if self._call("sudo -n true", b"", 60).rc == 0 else None
        return self._privilege

    @property
    def is_root(self) -> bool:
        return self.privilege() == "root"

    def sh(self, script: str, args, stdin_extra: str | None = None, timeout: int = 900) -> Proc:
        privilege = self.privilege()
        if privilege is None:
            raise AdminError("the admin login has no passwordless sudo")
        prefix = "" if privilege == "root" else "sudo -n "
        remote = prefix + "sh -s -- " + " ".join(shlex.quote(a) for a in args)
        return self._call(remote, (script + (stdin_extra or "")).encode(), timeout)
