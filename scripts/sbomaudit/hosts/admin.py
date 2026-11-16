"""`hosts bootstrap`, `hosts unbootstrap` and `hosts patch`: set up and remove the read-only audit login on one
server, and run its own unattended-upgrades once (the last section: `patch`, `DOCKER_PACKAGES`, `parse_dry_run`).

Without `--confirm <host>` both only show the plan and write nothing (no local file, no key, nothing on the
host). With it:

bootstrap
  1. pins the host keys (`host_keys`: `ssh -G` for the real hostname and port, `ssh-keyscan`, cross-checked
     against the user's own known_hosts; a mismatch aborts before anything is written) through
     `store.pin_host_keys`, so a re-pin also clears a `hostkey:changed` finding;
  2. creates the audit key `[hosts] key` (ed25519, no passphrase) when it is missing;
  3. stops early when the audit login already returns a document from the shipped collector;
  4. opens one ControlMaster admin session (`transport.AdminSession`) and runs `templates/hosts/bootstrap.sh`
     as root in it. An admin login without root or passwordless sudo is never escalated another way: the
     commands to run by hand are printed instead;
  5. when the script appended sbom-audit to an AllowUsers line (`ALLOWUSERS_EDITED`, also when it shows up in
     the partial output of a timed-out or dropped run), the edited file is recorded in
     `<out>/hosts/bootstrap/<host>.json` for unbootstrap and the lockout guard proves a fresh admin login
     (`ControlPath=none`) and an audit collect that returns a collector document; if the record cannot be
     written or either check fails the backup is restored through the still-open session (`ROLLBACK_SCRIPT`).
     A failed restore is loud and leaves the session open; a restore whose reload fails is reported as such.
  6. a run that ends without the script saying how far it got (timeout, dropped ssh, an interrupt) is never a
     success: "state unknown" names what to check and keeps the admin session open.

unbootstrap runs `templates/hosts/unbootstrap.sh` (user, sudoers drop-in, collector files, the AllowUsers token
in the recorded file; lynis stays), then removes the pinned keys and the record.

Every confirmed outcome is a log.md line (`report.append_log_admin`). Nothing here prints, logs or records key
material: the audit key appears only as its SHA256 fingerprint.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import tempfile
import time
from pathlib import Path

from ..cache import atomic_write
from . import parse, report, store, transport

TEMPLATES = Path(__file__).resolve().parents[3] / "templates" / "hosts"
KEY_PREFIX = 'restrict,command="sudo -n /usr/local/lib/sbom-audit/collect" '
PRF_MARKER = "@@SBOM_AUDIT_LYNIS_PRF@@"
PAYLOAD_END = "SBOM_AUDIT_PAYLOAD_END"
BOOTSTRAP_DIR = Path("hosts/bootstrap")
BACKUP_SUFFIX = ".sbom-audit.bak"
SSHD_FILE = re.compile(r"/etc/ssh/sshd_config|/etc/ssh/sshd_config\.d/[A-Za-z0-9._-]+\.conf")
KEY_TYPES = frozenset({"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
                       "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"})
# Restores the bootstrap backup of the AllowUsers file ($1) and reloads sshd, only when the restored file passes
# `sshd -t`. Grouped so a failed cp or sshd -t never reaches a reload. Exit 0 = restored and reloaded; 9 = the
# file is restored (equal to the backup, passes sshd -t) but no reload went through; 8 = not restored.
ROLLBACK_SCRIPT = ("PATH=/usr/sbin:/usr/bin:/sbin:/bin\n"
                   'cp "$1.sbom-audit.bak" "$1" && sshd -t && { systemctl reload ssh || systemctl reload sshd; } '
                   "&& exit 0\n"
                   'cmp -s "$1.sbom-audit.bak" "$1" && sshd -t && exit 9\n'
                   "exit 8\n")
EXIT_OK, EXIT_FAILED = 0, 2
EXIT_FINDINGS = 1
# bootstrap.sh can wait 3 x 300 s for the dpkg lock, then download lynis: far beyond that, never a guess
BOOTSTRAP_TIMEOUT, UNBOOTSTRAP_TIMEOUT, ROLLBACK_TIMEOUT = 2400, 600, 180
# The scripts' own exit codes, each printed right after its marker as the last stdout line. A code counts only
# with its marker: under `set -e` a failing command exits with its own status (usermod/userdel exit 8 when the
# user is busy). Anything else (124 timeout, 255 dropped ssh, a signal, a bare failure) is "state unknown".
BOOTSTRAP_EXITS = {3: "UNSUPPORTED", 4: "ALLOWUSERS_MANUAL", 5: "ALLOWUSERS_FAILED", 6: "NEEDS_SUDO",
                   7: "PAYLOAD_CORRUPT", 8: "ALLOWUSERS_RESTORE_FAILED", 9: "ALLOWUSERS_RELOAD_FAILED"}
UNBOOTSTRAP_EXITS = {5: "ALLOWUSERS_FAILED", 8: "ALLOWUSERS_RESTORE_FAILED", 9: "ALLOWUSERS_RELOAD_FAILED"}
BOOTSTRAP_STATE = ("/etc/ssh/sshd_config, /etc/ssh/sshd_config.d/*.conf (and any *.sbom-audit.bak next to them), "
                   "/etc/sudoers.d/sbom-audit, the user sbom-audit and `dpkg --audit`")


def _unbootstrap_state(recorded: str | None) -> str:
    # no "restore the .bak" here: a backup left by an earlier run may predate later sshd changes
    where = recorded or "/etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*.conf"
    return (f"the AllowUsers line in {where} by hand (do not copy an old *.sbom-audit.bak over it), "
            "/etc/sudoers.d/sbom-audit and the user sbom-audit")
MAX_DETAIL = 300


# --------------------------------------------------------------------------- texts

def script_text(name: str) -> str:
    return (TEMPLATES / name).read_text(encoding="utf-8")


def authorized_keys_line(pub: str) -> str:
    """The audit user's one authorized_keys line: forced collector, `restrict`. ValueError unless `pub` is a single
    OpenSSH public key line (type, base64 blob, optional comment)."""
    text = pub.strip() if isinstance(pub, str) else ""
    parts = text.split()
    if len(parts) < 2 or parts[0] not in KEY_TYPES or not re.fullmatch(r"[A-Za-z0-9+/]+={0,3}", parts[1]) \
            or any(ord(c) < 32 or ord(c) == 127 or c in '"\\' for c in text):
        raise ValueError("not a single OpenSSH public key line")
    return KEY_PREFIX + text


def sudoers_text() -> str:
    return 'sbom-audit ALL=(root) NOPASSWD: /usr/local/lib/sbom-audit/collect ""\n'


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def bootstrap_payload() -> str:
    """What follows bootstrap.sh on stdin: collect.sh, the marker line, lynis.prf, the here-document end."""
    collect, prf = script_text("collect.sh"), script_text("lynis.prf")
    for name, text in (("collect.sh", collect), ("lynis.prf", prf)):
        if not text.endswith("\n") or {PRF_MARKER, PAYLOAD_END} & set(text.splitlines()):
            raise ValueError(f"{name} cannot be sent as bootstrap payload")
    return f"{collect}{PRF_MARKER}\n{prf}{PAYLOAD_END}\n"


def bootstrap_args(pub: str) -> list[str]:
    return [authorized_keys_line(pub), _sha256(script_text("collect.sh")), _sha256(script_text("lynis.prf"))]


def record_path(out: Path, host: str) -> Path:
    return Path(out) / BOOTSTRAP_DIR / f"{store.check_host(host)}.json"


def _read_record(out: Path, host: str) -> str | None:
    try:
        doc = json.loads(record_path(out, host).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    value = doc.get("allowusers_file") if isinstance(doc, dict) else None
    return value if isinstance(value, str) and SSHD_FILE.fullmatch(value) else None


# --------------------------------------------------------------------------- host keys

def _text(data) -> str:
    return transport._text(data)


def _blob_fingerprint(key_type: str, blob_b64: str) -> str:
    try:
        blob = base64.b64decode(blob_b64, validate=True)
    except ValueError:
        raise ValueError("host key is not base64") from None
    if len(blob) < 4:
        raise ValueError("host key blob too short")
    (n,) = struct.unpack(">I", blob[:4])
    if blob[4:4 + n] != key_type.encode():
        raise ValueError("host key blob does not match its key type")
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def fingerprint(line: str) -> str:
    """OpenSSH's SHA256 fingerprint of a known_hosts / keyscan line (`<hosts> <type> <base64>`)."""
    parts = line.split()
    if len(parts) < 3 or parts[1] not in KEY_TYPES:
        raise ValueError("not a host key line")
    return _blob_fingerprint(parts[1], parts[2])


def _check_name(value: str, what: str) -> str:
    if not value or value.startswith("-") or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError(f"invalid {what}")
    return value


def _ssh_g(address: str, run) -> dict[str, str]:
    proc = run(["ssh", "-G", _check_name(address, "host address")], capture_output=True, timeout=30,
               stdin=subprocess.DEVNULL)
    if proc.returncode != 0:
        raise ValueError("ssh -G failed for the host address")
    opts: dict[str, str] = {}
    for line in _text(proc.stdout).splitlines():
        key, _, value = line.strip().partition(" ")
        opts.setdefault(key.lower(), value.strip())
    return opts


def _known_entries(name: str, files: list[str], run) -> list[tuple[str, str, str]]:
    """(marker, type, blob) for `name` in the user's known_hosts files (`ssh-keygen -F`)."""
    entries = []
    for file in files:
        path = os.path.expanduser(file)
        if not path or path == "/dev/null" or not os.path.isfile(path):
            continue
        proc = run(["ssh-keygen", "-F", name, "-f", path], capture_output=True, timeout=30, stdin=subprocess.DEVNULL)
        if proc.returncode != 0:
            continue
        for line in _text(proc.stdout).splitlines():
            parts = line.split()
            if not parts or parts[0].startswith("#"):
                continue
            marker = ""
            if parts[0].startswith("@"):
                marker, parts = parts[0], parts[1:]
            if len(parts) >= 3:
                entries.append((marker, parts[1], parts[2]))
    return entries


def host_keys(h, run=subprocess.run) -> list[tuple[str, str]]:
    return _host_keys(h, run)[0]


def _host_keys(h, run) -> tuple[list[tuple[str, str]], bool]:
    """The host keys to pin, as (keyscan line, SHA256 fingerprint), and whether the user's known_hosts vouched
    for them (False: trust on first use).

    `ssh -G <address>` resolves the real hostname and port (an alias from the user's ssh config works), then
    `ssh-keyscan -p <port> <hostname>`. When the user's own known_hosts knows the host, a scanned key of a known
    type must equal a known key (else ValueError: nothing is pinned), and only the vouched-for types are kept.
    With no known entry the keys are trusted on first use: the plan prints the fingerprints to compare."""
    opts = _ssh_g(h.address, run)
    hostname = _check_name(opts.get("hostname") or h.address, "hostname")
    port = opts.get("port") or "22"
    if not port.isdigit():
        raise ValueError("invalid port from ssh -G")
    proc = run(["ssh-keyscan", "-p", port, hostname], capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
    scanned: dict[str, tuple[str, str]] = {}
    for line in _text(proc.stdout).splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[0].startswith("#") or parts[1] not in KEY_TYPES or parts[1] in scanned:
            continue
        scanned[parts[1]] = (" ".join(parts[:3]), fingerprint(line))
    if not scanned:
        raise ValueError(f"no host keys from ssh-keyscan -p {port} {hostname}")
    name = opts.get("hostkeyalias") or (hostname if port == "22" else f"[{hostname}]:{port}")
    files = (opts.get("userknownhostsfile", "") + " " + opts.get("globalknownhostsfile", "")).split()
    known = _known_entries(name, files, run)
    blobs = {t: line.split()[2] for t, (line, _) in scanned.items()}
    if any(marker == "@revoked" and blob in blobs.values() for marker, _, blob in known):
        raise ValueError("a scanned host key is marked @revoked in your known_hosts")
    plain: dict[str, set[str]] = {}
    for marker, key_type, blob in known:
        if not marker:
            plain.setdefault(key_type, set()).add(blob)
    if not plain:
        return list(scanned.values()), False
    common = [t for t in scanned if t in plain]
    if not common:
        raise ValueError(f"the host key does not match your known_hosts: it knows {name} with other key types only")
    bad = [t for t in common if blobs[t] not in plain[t]]
    if bad:
        raise ValueError(f"the {', '.join(bad)} host key does not match your known_hosts entry for {name}")
    return [scanned[t] for t in common], True


# --------------------------------------------------------------------------- audit key

def _audit_public_key(key: Path, run, say) -> str:
    """The audit key's public line, creating the key pair first when it is missing."""
    pub = Path(f"{key}.pub")
    if not key.exists():
        if pub.exists():
            raise ValueError(f"{pub.name} exists without its private key: remove it or restore the key")
        key.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        proc = run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "sbom-audit", "-f", str(key)],
                   capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
        if proc.returncode != 0 or not pub.exists():
            raise ValueError("ssh-keygen could not create the audit key")
        say(f"created the audit key {key} (ed25519, no passphrase)")
    if pub.exists():
        return pub.read_text(encoding="utf-8")
    proc = run(["ssh-keygen", "-y", "-f", str(key)], capture_output=True, timeout=30, stdin=subprocess.DEVNULL)
    if proc.returncode != 0:
        raise ValueError("could not derive the audit public key (ssh-keygen -y)")
    return _text(proc.stdout)


def _key_fingerprint(pub: str) -> str:
    parts = pub.split()
    return _blob_fingerprint(parts[0], parts[1])


# --------------------------------------------------------------------------- shared helpers

def _detail(text: str) -> str:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return lines[-1][:MAX_DETAIL] if lines else ""


def _markers(out: str, name: str) -> list[str]:
    return [ln[len(name) + 1:].strip() for ln in out.splitlines() if ln.startswith(name + " ")]


def _collect_doc(cfg, host: str, h, run, *, once: bool) -> dict | None:
    """The audit login's collector document, or None (an error, or output that is not a collector document)."""
    argv = transport.ssh_argv(cfg.hosts, host, h, cfg.out)
    timeout = max(60, int(cfg.hosts.timeout_minutes) * 60)
    if once:
        result = transport.collect_once(argv, timeout, run, pinned=True)
    else:
        result = transport.collect(argv, timeout, run, sleep=lambda s: None, retry_after_s=0, pinned=True)
    if result.doc is None:
        return None
    try:
        parse.parse(result.doc)
    except Exception:                               # noqa: BLE001 - anything unparsable is "not a document"
        return None
    return result.doc


def _control_dir() -> Path:
    # short: a ControlPath must fit a unix socket path (about 100 bytes)
    base = "/tmp" if os.path.isdir("/tmp") else None
    return Path(tempfile.mkdtemp(prefix="sbom-audit-", dir=base))


def _cleanup(ctl: Path, opened: list) -> None:
    """Remove the control directory unless a session in it was kept open (its socket is the way back in)."""
    if not any(getattr(s, "kept", False) for s in opened):
        shutil.rmtree(ctl, ignore_errors=True)


def _log(cfg, action: str, host: str, outcome: str) -> None:
    report.append_log_admin(cfg.out, action, host, outcome)


def _rerun(action: str, host: str) -> str:
    return f"hosts {action} {host} --confirm {host}"


def _manual_steps(admin: str, files: list[tuple[str, str]], run_cmd: str) -> list[str]:
    """Upload each (remote name, local shell expression producing it) with the admin login, then run `run_cmd`
    under `ssh -t` so sudo can ask for a password."""
    q = shlex.quote
    lines = [f"  {local} | ssh {q(admin)} {q('umask 077; cat > ' + name)}" for name, local in files]
    lines.append(f"  ssh -t {q(admin)} {q(run_cmd)}")
    return lines


def _keep_session(s, h, say, message: str) -> None:
    ctl = s.keep_open()
    say(message)
    say(f"the admin session stays open; use it with: ssh -S {shlex.quote(ctl)} {shlex.quote(h.admin)}")
    say(f"close it afterwards with: ssh -S {shlex.quote(ctl)} -O exit {shlex.quote(h.admin)}")
    say(f"it closes by itself after {transport.PERSIST.removesuffix('h')} h of idle time "
        f"(ControlPersist={transport.PERSIST}): check the host before then")


def _sshd_file(markers: list[str], fallback: str | None = None) -> str | None:
    """The first marker path when it is an sshd config path, else `fallback`: host output is never echoed
    unchecked."""
    return markers[0] if markers and SSHD_FILE.fullmatch(markers[0]) else fallback


def _state_unknown(s, h, run, say, state: str, sleep, check_login: bool = True) -> None:
    """Loud, and the admin session is kept: the script did not report how far it got."""
    ctl = s.keep_open()
    _keep_session(s, h, say, f"state unknown: check {state} on the host, the admin session is kept at "
                             f"{shlex.quote(ctl)}")
    if not check_login:
        return
    if transport.fresh_login(transport.admin_argv(h.admin), run, sleep=sleep):
        say("a fresh admin login works right now")
    else:
        say("a fresh admin login FAILS right now: do not close the admin session before sshd is fixed")


def _in_flight(s, h, run, say, state: str, sleep, call):
    """Runs a host-side change; an interrupt or crash while it runs keeps the session (the state is unknown)."""
    try:
        return call()
    except BaseException:
        try:
            _state_unknown(s, h, run, say, state, sleep, check_login=False)   # no new logins after an interrupt
        except BaseException:                       # noqa: BLE001 - the original error is the one to raise
            pass
        raise


def _rollback_failed_message(file: str | None) -> str:
    if file is None:
        return ("ROLLBACK FAILED: the admin session is still open; restore the edited sshd config file from its "
                f"{BACKUP_SUFFIX} copy by hand before closing it")
    return (f"ROLLBACK FAILED: the admin session is still open; restore {file} from {file}{BACKUP_SUFFIX} "
            "by hand before closing it")


def _reload_failed_message(file: str | None) -> str:
    return (f"restored {file or 'the sshd config file'}; sshd reload failed — the running sshd still has the old "
            "config, nothing to undo (check `systemctl status ssh` on the host)")


# --------------------------------------------------------------------------- bootstrap

def _allowusers_plan(s) -> str:
    """The plan's AllowUsers line, from `sshd -T` (global settings only: Match blocks show at run time)."""
    if s.privilege() is None:
        return "AllowUsers: not checked (the admin login has no passwordless sudo)"
    proc = s.command("sshd -T", as_root=True)
    if proc.rc != 0:
        return "AllowUsers: not checked (sshd -T failed)"
    values: dict[str, list[str]] = {"allowusers": [], "allowgroups": []}
    for line in proc.out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in values:
            values[parts[0]].extend(parts[1:])

    def admits(patterns: list[str], name: str) -> bool:
        return any(fnmatch.fnmatchcase(name, p) for p in patterns if "@" not in p and not p.startswith("!"))
    if values["allowgroups"] and not admits(values["allowgroups"], transport.USER):
        return ("AllowUsers: AllowGroups is set and does not admit sbom-audit: that needs a change by hand "
                "(bootstrap stops before changing anything)")
    if values["allowusers"] and not admits(values["allowusers"], transport.USER):
        return ("AllowUsers: set without sbom-audit; bootstrap will add sbom-audit to the AllowUsers line "
                "(backup, sshd -t, reload; restored unless a fresh admin login and an audit collect still work). "
                "Several AllowUsers lines or one inside a Match block are left to you (nothing is changed)")
    return "AllowUsers: no change needed"


def _plan(cfg, host: str, h, keys, run, say, session) -> int:
    say(f"hosts bootstrap {host}: plan (nothing is changed without --confirm {host})")
    say(f"  admin login: {h.admin}")
    say("  host keys to pin (compare with `ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub` on the host):")
    for line, fp in keys:
        say(f"    {line.split()[1]} {fp}")
    key = Path(cfg.hosts.key)
    say(f"  audit key: {key} ({'exists' if key.exists() else 'will be created: ed25519, no passphrase'})")
    ctl = _control_dir()
    try:
        with session(h.admin, ctl, run=run) as s:
            privilege = s.privilege()
            say(f"  privilege on the host: {privilege or 'none (no root, no passwordless sudo): commands to run by hand are printed'}")
            say(f"  {_allowusers_plan(s)}")
    except (transport.AdminError, ValueError) as exc:
        say(f"  admin login: {exc}")
    finally:
        shutil.rmtree(ctl, ignore_errors=True)
    say("  on the host (as root): user sbom-audit (no password, home /var/lib/sbom-audit, root-owned), its one")
    say("    authorized key with the forced collector, /usr/local/lib/sbom-audit/{collect,lynis.prf},")
    say("    /etc/sudoers.d/sbom-audit (the collector only, checked with visudo), apt-get install lynis;")
    say("    sshd is only ever reloaded, never restarted; nothing is rebooted")
    say(f"run `{_rerun('bootstrap', host)}` to apply")
    return EXIT_OK


def _bootstrap_manual(cfg, host: str, h, pub: str, say) -> int:
    q = shlex.quote
    _, sha_collect, sha_prf = bootstrap_args(pub)
    bundle = (f"{{ cat {q(str(TEMPLATES / 'bootstrap.sh'))} {q(str(TEMPLATES / 'collect.sh'))}; "
              f"echo {q(PRF_MARKER)}; cat {q(str(TEMPLATES / 'lynis.prf'))}; echo {q(PAYLOAD_END)}; }}")
    key_arg = '"' + KEY_PREFIX.replace('"', '\\"') + '$(cat sbom-audit-bootstrap.pub)"'
    run_cmd = (f"sudo sh -s -- {key_arg} {sha_collect} {sha_prf} < sbom-audit-bootstrap.sh; "
               "rm -f sbom-audit-bootstrap.sh sbom-audit-bootstrap.pub")
    say(f"hosts bootstrap {host}: the admin login {h.admin} has no root and no passwordless sudo.")
    say("nothing was changed on the host. Run these yourself (sudo may ask for your password):")
    for line in _manual_steps(h.admin, [("sbom-audit-bootstrap.sh", bundle),
                                        ("sbom-audit-bootstrap.pub", f"cat {q(str(cfg.hosts.key) + '.pub')}")],
                              run_cmd):
        say(line)
    say("keep a second admin session open while it runs, and test a fresh admin login before closing it")
    say(f"then run `{_rerun('bootstrap', host)}` again: it pins the keys and verifies the audit login")
    return EXIT_FAILED


def _guard(cfg, host: str, h, run, sleep) -> bool:
    """The lockout guard: a brand-new admin login, then an audit collect that returns a collector document."""
    if not transport.fresh_login(transport.admin_argv(h.admin), run, sleep=sleep):
        return False
    return _collect_doc(cfg, host, h, run, once=False) is not None


def _after_edit(cfg, host: str, h, s, file: str, run, say, sleep) -> tuple[int, str]:
    """The AllowUsers edit is live: record it and prove it, or restore the backup. Nothing returns with an
    unrecorded or unproven edit still in place."""
    why = "the lockout guard failed"
    try:
        try:
            atomic_write(record_path(cfg.out, host), json.dumps({"allowusers_file": file}) + "\n")
        except OSError as exc:
            why, ok = f"the bootstrap record could not be written ({type(exc).__name__})", False
        else:
            ok = _guard(cfg, host, h, run, sleep)
    except Exception:                               # noqa: BLE001 - any failure of the guard means "not proven"
        ok = False
    except BaseException:
        _rollback(cfg, host, h, s, file, run, say, sleep)   # an interrupt must not leave an unproven edit behind
        raise
    if ok:
        say(f"AllowUsers in {file} now admits sbom-audit; a fresh admin login and an audit collect both work")
        return EXIT_OK, "ok"
    say(f"{why} after editing {file}: restoring the backup")
    return EXIT_FAILED, _rollback(cfg, host, h, s, file, run, say, sleep)


def _rollback(cfg, host: str, h, s, file: str, run, say, sleep) -> str:
    proc = _in_flight(s, h, run, say, file, sleep, lambda: s.sh(ROLLBACK_SCRIPT, [file], timeout=ROLLBACK_TIMEOUT))
    if proc.rc == 9:
        record_path(cfg.out, host).unlink(missing_ok=True)
        _keep_session(s, h, say, f"restored {file} on disk, but sshd did not reload: the running sshd still has "
                                  "the edited config until its next reload (check `systemctl status ssh`)")
        return "rollback reload failed"
    if proc.rc != 0:
        _keep_session(s, h, say, _rollback_failed_message(file))
        return "rollback failed"
    record_path(cfg.out, host).unlink(missing_ok=True)
    if transport.fresh_login(transport.admin_argv(h.admin), run, sleep=sleep):
        say(f"rolled back: {file} restored and sshd reloaded; a fresh admin login works")
    else:
        _keep_session(s, h, say, f"rolled back {file}, but a fresh admin login still fails: check sshd by hand")
    return "rolled back"


def _stopped_itself(proc) -> bool:
    """The script ended through `die` (exit 1 with an ERROR line): it reported where it stopped."""
    return proc.rc == 1 and any(ln.startswith("ERROR ") for ln in proc.err.splitlines())


def _last_line(out: str) -> str:
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return lines[-1] if lines else ""


def _reported(proc, exits: dict[int, str]) -> int | None:
    """The script's own exit code, only when its marker is the last stdout line; else None (unknown)."""
    marker, last = exits.get(proc.rc), _last_line(proc.out)
    return proc.rc if marker and (last == marker or last.startswith(marker + " ")) else None


def _finished(proc) -> bool:
    return proc.rc == 0 and _last_line(proc.out) == "DONE"


def _run_bootstrap(cfg, host: str, h, s, pub: str, run, say, sleep) -> tuple[int, str]:
    proc = _in_flight(s, h, run, say, BOOTSTRAP_STATE, sleep,
                      lambda: s.sh(script_text("bootstrap.sh"), bootstrap_args(pub), stdin_extra=bootstrap_payload(),
                                   timeout=BOOTSTRAP_TIMEOUT))
    detail = _detail(proc.err)
    code = _reported(proc, BOOTSTRAP_EXITS)
    if code == 3:
        say(f"unsupported OS ({' '.join(_markers(proc.out, 'UNSUPPORTED')) or 'unknown'}): only Debian and Ubuntu")
        return EXIT_FAILED, "unsupported os"
    if code == 4:
        files = " ".join(_markers(proc.out, "ALLOWUSERS_MANUAL"))
        say(f"AllowUsers needs a change by hand: {detail}")
        say(f"  add sbom-audit where it is admitted in: {files}; nothing was changed on the host")
        say(f"  then run `{_rerun('bootstrap', host)}` again")
        return EXIT_FAILED, "allowusers manual"
    if code == 5:
        say(f"the sshd config edit was rejected and restored: {' '.join(_markers(proc.out, 'ALLOWUSERS_FAILED'))}")
        return EXIT_FAILED, "allowusers restored"
    if code == 6:
        say("sudo or visudo is missing on the host: install sudo first")
        return EXIT_FAILED, "needs sudo"
    if code == 7:
        say("the collector payload arrived corrupt (checksum mismatch): nothing was installed")
        return EXIT_FAILED, "payload corrupt"
    if code == 8:
        _keep_session(s, h, say, _rollback_failed_message(_sshd_file(_markers(proc.out, "ALLOWUSERS_RESTORE_FAILED"))))
        return EXIT_FAILED, "rollback failed"
    if code == 9:
        say(_reload_failed_message(_sshd_file(_markers(proc.out, "ALLOWUSERS_RELOAD_FAILED"))))
        return EXIT_FAILED, "reload failed"
    finished = _finished(proc)
    unknown = not finished and code is None and not _stopped_itself(proc)
    if unknown:
        say(f"bootstrap did not finish on the host (exit {proc.rc}): {detail or 'no error output'}")
    edited = _markers(proc.out, "ALLOWUSERS_EDITED")
    if edited:
        # the edit is live whatever happened afterwards: prove it or restore it before anything else
        file = edited[0]
        if not SSHD_FILE.fullmatch(file):
            _keep_session(s, h, say, f"the host reported an unexpected edited file {file!r}: check its sshd "
                                      "config by hand")
            return EXIT_FAILED, "unexpected allowusers file"
        rc, outcome = _after_edit(cfg, host, h, s, file, run, say, sleep)
        if finished or outcome in ("rollback failed", "rollback reload failed"):
            return rc, outcome
        if not unknown:
            say(f"bootstrap stopped on the host: {detail}")
            return EXIT_FAILED, "failed"
        _state_unknown(s, h, run, say, BOOTSTRAP_STATE, sleep)
        return EXIT_FAILED, "state unknown"
    if unknown:
        _state_unknown(s, h, run, say, BOOTSTRAP_STATE, sleep)
        return EXIT_FAILED, "state unknown"
    if proc.rc != 0:
        say(f"bootstrap failed on the host (exit {proc.rc}): {detail or 'no error output'}")
        return EXIT_FAILED, "failed"
    if _collect_doc(cfg, host, h, run, once=False) is None:
        say("bootstrap ran, but the audit login does not return a collector document: check the host by hand")
        return EXIT_FAILED, "verify failed"
    say("the audit login returns a collector document")
    return EXIT_OK, "ok"


def _refused(action: str, host: str, confirm: str | None, env, say) -> bool:
    """True (after saying why) when `hosts.cli.refuse_confirm` refuses this `--confirm`: checked here as well as in
    the CLI, so no other caller can reach a host-changing step past the gate."""
    from . import cli
    refusal = cli.refuse_confirm(argparse.Namespace(confirm=confirm, host=host), env)
    if refusal:
        say(f"hosts {action} {host}: {refusal}")
    return refusal is not None


def bootstrap(cfg, host: str, confirm: str | None, *, run=subprocess.run, say=print,
              session=transport.AdminSession, sleep=time.sleep, env=os.environ) -> int:
    store.check_host(host)
    if _refused("bootstrap", host, confirm, env, say):
        return EXIT_FAILED
    h = cfg.hosts.servers[host]
    if not h.admin:
        say(f"hosts bootstrap {host}: no admin login: set admin = \"user@host\" under [hosts.servers.\"{host}\"]")
        return EXIT_FAILED
    try:
        keys, vouched = _host_keys(h, run)
    except ValueError as exc:
        say(f"hosts bootstrap {host}: {exc}; nothing was pinned or changed")
        if confirm is not None:
            _log(cfg, "bootstrap", host, "host key check failed")
        return EXIT_FAILED
    if confirm is None:
        return _plan(cfg, host, h, keys, run, say, session)

    if not vouched:
        # trust on first use: the fingerprints once more, right before they are pinned (compare on the host)
        say(f"{host} is not in your known_hosts: trusting these host keys on first use")
        for line, fp in keys:
            say(f"  {line.split()[1]} {fp}")
    store.pin_host_keys(cfg.out, host, [line for line, _ in keys])
    say(f"pinned {len(keys)} host key(s) for {host}: " + ", ".join(fp for _, fp in keys))
    try:
        pub = _audit_public_key(Path(cfg.hosts.key), run, say)
        authorized_keys_line(pub)
    except (ValueError, OSError) as exc:
        say(f"hosts bootstrap {host}: audit key: {exc}")
        _log(cfg, "bootstrap", host, "audit key failed")
        return EXIT_FAILED
    say(f"audit key {_key_fingerprint(pub)}")
    doc = _collect_doc(cfg, host, h, run, once=True)
    if doc is not None and str(doc.get("collector")) == parse.SHIPPED_VERSION:
        say(f"{host} is already bootstrapped: the audit login returns collector {parse.SHIPPED_VERSION}")
        _log(cfg, "bootstrap", host, "already bootstrapped")
        return EXIT_OK

    ctl = _control_dir()
    opened = []
    try:
        with session(h.admin, ctl, run=run) as s:
            opened.append(s)
            if s.privilege() is None:
                rc, outcome = _bootstrap_manual(cfg, host, h, pub, say), "needs manual run"
            else:
                rc, outcome = _run_bootstrap(cfg, host, h, s, pub, run, say, sleep)
    except transport.AdminError as exc:
        say(f"hosts bootstrap {host}: {exc}")
        rc, outcome = EXIT_FAILED, "admin login failed"
    finally:
        _cleanup(ctl, opened)
    _log(cfg, "bootstrap", host, outcome)
    return rc


# --------------------------------------------------------------------------- unbootstrap

def _forget(cfg, host: str) -> None:
    store.unpin_host_keys(cfg.out, host)
    record_path(cfg.out, host).unlink(missing_ok=True)


def _unbootstrap_manual(host: str, h, arg: str, say) -> int:
    q = shlex.quote
    run_cmd = f"sudo sh -s -- {q(arg)} < sbom-audit-unbootstrap.sh; rm -f sbom-audit-unbootstrap.sh"
    say(f"hosts unbootstrap {host}: the admin login {h.admin} has no root and no passwordless sudo.")
    say("nothing was changed. Run these yourself (sudo may ask for your password):")
    for line in _manual_steps(h.admin, [("sbom-audit-unbootstrap.sh",
                                         f"cat {q(str(TEMPLATES / 'unbootstrap.sh'))}")], run_cmd):
        say(line)
    say(f"then run `{_rerun('unbootstrap', host)}` again to remove the pinned keys here")
    return EXIT_FAILED


def _run_unbootstrap(cfg, host: str, h, s, arg: str, run, say, sleep) -> tuple[int, str]:
    recorded = arg if SSHD_FILE.fullmatch(arg) else None
    state = _unbootstrap_state(recorded)
    proc = _in_flight(s, h, run, say, state, sleep,
                      lambda: s.sh(script_text("unbootstrap.sh"), [arg], timeout=UNBOOTSTRAP_TIMEOUT))
    code = _reported(proc, UNBOOTSTRAP_EXITS)
    if code == 5:
        say(f"removing sbom-audit from AllowUsers was rejected and restored: {_detail(proc.out)}")
        return EXIT_FAILED, "allowusers restored"
    if code == 8:
        # the marker proves the script's own edit failed and it made the backup moments ago: restoring it is right
        _keep_session(s, h, say, _rollback_failed_message(_sshd_file(_markers(proc.out, "ALLOWUSERS_RESTORE_FAILED"),
                                                                     recorded)))
        return EXIT_FAILED, "rollback failed"
    if code == 9:
        say(_reload_failed_message(_sshd_file(_markers(proc.out, "ALLOWUSERS_RELOAD_FAILED"), recorded)))
        return EXIT_FAILED, "reload failed"
    if _stopped_itself(proc):
        say(f"unbootstrap failed on the host (exit {proc.rc}): {_detail(proc.err) or 'no error output'}")
        return EXIT_FAILED, "failed"
    if not _finished(proc):
        say(f"unbootstrap did not finish on the host (exit {proc.rc}): {_detail(proc.err) or 'no error output'}")
        _state_unknown(s, h, run, say, state, sleep)
        return EXIT_FAILED, "state unknown"
    for file in _markers(proc.out, "ALLOWUSERS_LEFT"):
        say(f"note: an AllowUsers line in {_sshd_file([file], 'an sshd config file')} still names sbom-audit; "
            "remove it by hand if bootstrap added it")
    _forget(cfg, host)
    say(f"removed the audit login from {host} (lynis stays installed) and its pinned host keys here")
    return EXIT_OK, "ok"


def unbootstrap(cfg, host: str, confirm: str | None, *, run=subprocess.run, say=print,
                session=transport.AdminSession, sleep=time.sleep, env=os.environ) -> int:
    store.check_host(host)
    if _refused("unbootstrap", host, confirm, env, say):
        return EXIT_FAILED
    h = cfg.hosts.servers[host]
    if not h.admin:
        say(f"hosts unbootstrap {host}: no admin login: set admin = \"user@host\" under [hosts.servers.\"{host}\"]")
        return EXIT_FAILED
    recorded = _read_record(cfg.out, host)
    arg = recorded or "-"
    if confirm is None:
        say(f"hosts unbootstrap {host}: plan (nothing is changed without --confirm {host})")
        say(f"  admin login: {h.admin}")
        say("  on the host (as root): remove /etc/sudoers.d/sbom-audit, the user sbom-audit, /var/lib/sbom-audit")
        say("    and /usr/local/lib/sbom-audit; lynis stays installed")
        say(f"  AllowUsers: {'remove sbom-audit from ' + recorded if recorded else 'bootstrap edited no file; only reported if a line still names sbom-audit'}")
        say(f"  here: drop the pinned host keys of {host} and its bootstrap record")
        say(f"run `{_rerun('unbootstrap', host)}` to apply")
        return EXIT_OK

    ctl = _control_dir()
    opened = []
    try:
        with session(h.admin, ctl, run=run) as s:
            opened.append(s)
            if s.privilege() is None:
                gone = s.command("id -u sbom-audit").rc != 0 and \
                    s.command("test -e /usr/local/lib/sbom-audit || test -e /var/lib/sbom-audit").rc != 0
                if gone:
                    _forget(cfg, host)
                    say(f"{host}: the audit user and its files are gone; removed the pinned host keys here "
                        "(sudoers and AllowUsers cannot be checked without root)")
                    rc, outcome = EXIT_OK, "already removed"
                else:
                    rc, outcome = _unbootstrap_manual(host, h, arg, say), "needs manual run"
            else:
                rc, outcome = _run_unbootstrap(cfg, host, h, s, arg, run, say, sleep)
    except transport.AdminError as exc:
        say(f"hosts unbootstrap {host}: {exc}")
        rc, outcome = EXIT_FAILED, "admin login failed"
    finally:
        _cleanup(ctl, opened)
    _log(cfg, "unbootstrap", host, outcome)
    return rc


# --------------------------------------------------------------------------- patch

# The one list of packages that `hosts patch` holds back unless --include-docker. It is passed to patch.sh as
# trailing arguments (the script names no package itself) and is what the plan and the apply result are checked
# against.
DOCKER_PACKAGES = ("docker-ce", "docker-ce-cli", "docker-ce-rootless-extras", "docker-buildx-plugin",
                   "docker-compose-plugin", "containerd.io", "docker.io", "containerd", "runc")
PATCH_PLAN_TIMEOUT, PATCH_APPLY_TIMEOUT = 900, 3600
PATCH_PLAN_MAX_AGE = dt.timedelta(hours=24)
PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9.+-]*")
SERVICE_NAME = re.compile(r"[A-Za-z0-9@._:\\-]+")
PLAN_LINE = "Packages that will be upgraded:"
NOTHING_TO_UPGRADE = "No packages found that can be upgraded unattended"   # unattended-upgrade's own "none" line
DOCKER_FAMILY = ("docker", "containerd", "runc")
BUSY_MARKERS = ("Lock could not be acquired", "apt is busy")
APPLIED_LINES = (PLAN_LINE, "Packages that were upgraded:")
KERNEL_STATES = {"0": "unknown", "1": "up to date", "2": "an ABI-compatible kernel update is pending",
                 "3": "a kernel version upgrade is pending"}
SHOWN_LINES, SHOWN_WIDTH = 20, 200


def _package_names(text: str, prefixes: tuple[str, ...]) -> list[str]:
    """Package names from every line that carries one of `prefixes` (space-separated after the colon; some
    versions repeat the line once per pass), without `:arch`, deduplicated in first-seen order. A token that is
    not a Debian package name is dropped: host output is never passed on unchecked."""
    names: dict[str, None] = {}
    for line in text.splitlines():
        for prefix in prefixes:
            at = line.find(prefix)
            if at < 0:
                continue
            for token in line[at + len(prefix):].split():
                name = token.split(":", 1)[0]
                if PACKAGE_NAME.fullmatch(name):
                    names.setdefault(name, None)
    return list(names)


def parse_dry_run(text: str) -> list[str]:
    """The packages `unattended-upgrade --dry-run -v` would upgrade ("Packages that will be upgraded:" lines)."""
    return _package_names(text, (PLAN_LINE,))


def parse_installed(text: str) -> list[str]:
    """The packages an `unattended-upgrade -v` run upgraded (the same line, or the older "were upgraded")."""
    return _package_names(text, APPLIED_LINES)


def patch_plan_path(out: Path, host: str) -> Path:
    return Path(out) / ".cache" / "hosts" / f"patch-{store.check_host(host)}.json"


def _read_patch_plan(out: Path, host: str) -> dict | None:
    try:
        doc = json.loads(patch_plan_path(out, host).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    ok = isinstance(doc, dict) and doc.get("host") == host and isinstance(doc.get("include_docker"), bool) \
        and isinstance(doc.get("created"), str) and isinstance(doc.get("packages"), list) \
        and all(isinstance(p, str) for p in doc["packages"])
    return doc if ok else None


def _save_patch_plan(out: Path, host: str, packages: list[str], include_docker: bool, now: dt.datetime) -> None:
    doc = {"host": host, "packages": sorted(packages), "include_docker": include_docker,
           "created": now.astimezone(dt.timezone.utc).isoformat(timespec="seconds")}
    atomic_write(patch_plan_path(out, host), json.dumps(doc, indent=2) + "\n")


def _forget_patch_plan(out: Path, host: str) -> None:
    patch_plan_path(out, host).unlink(missing_ok=True)


def _plan_usable(saved: dict | None, include_docker: bool, now: dt.datetime) -> str | None:
    """Why the saved plan cannot authorise an apply with `include_docker` now (missing, no valid timestamp, older
    than 24 hours or made with the other --include-docker setting), or None when it can."""
    if saved is None:
        return "no saved plan for this host"
    try:
        created = dt.datetime.fromisoformat(saved["created"])
        if created.tzinfo is None:
            raise ValueError
    except ValueError:
        return "the saved plan has no valid timestamp"
    age = now - created
    if age < dt.timedelta(0):
        return "saved plan has a timestamp in the future"
    if age > PATCH_PLAN_MAX_AGE:
        return "the saved plan is older than 24 hours"
    if saved["include_docker"] != include_docker:
        return "the saved plan was made with a different --include-docker setting"
    return None


def _plan_matches(saved: dict | None, packages: list[str], include_docker: bool, now: dt.datetime) -> str | None:
    """Why the saved plan does not authorise this run, or None when it does."""
    why = _plan_usable(saved, include_docker, now)
    if why:
        return why
    if sorted(set(saved["packages"])) != sorted(set(packages)):
        return "the package list changed since the saved plan"
    return None


def _show(text: str, say, indent: str = "    ") -> None:
    """The tail of host output, one safe line each: control characters and escape sequences never reach the
    terminal."""
    lines = [ln for ln in text.splitlines() if ln.strip()][-SHOWN_LINES:]
    for line in lines:
        say(indent + "".join(c if c.isprintable() else "?" for c in line)[:SHOWN_WIDTH])


def _patch_args(mode: str, include_docker: bool, only: list[str] | None = None) -> list[str]:
    """`<mode> <0|1> <held-back>...`, and for apply `-- <confirmed package>...` (the script pins the upgrade to
    them)."""
    args = [mode, "1" if include_docker else "0", *DOCKER_PACKAGES]
    return args + ["--", *only] if only else args


def _patch_manual(host: str, h, mode: str, include_docker: bool, say, saved: dict | None = None,
                  now: dt.datetime | None = None) -> None:
    q = shlex.quote
    if mode == "apply":
        # the same age and --include-docker checks as the confirmed path; the package list cannot be re-checked
        # here (no root), so the apply command is pinned to the saved plan's packages
        why = _plan_usable(saved, include_docker, now or dt.datetime.now(dt.timezone.utc))
        if why:
            say(f"hosts patch {host}: no install command: {why}. Save a fresh plan first:")
            mode = "plan"
    only = [p for p in (saved or {}).get("packages", []) if PACKAGE_NAME.fullmatch(p)]
    if mode == "apply" and not only:
        mode = "plan"                                # nothing confirmed to pin an apply to: start with the plan
    remote = "sudo sh -s -- " + " ".join(q(a) for a in _patch_args(mode, include_docker, only if mode == "apply" else None))
    say(f"hosts patch {host}: the admin login {h.admin} has no root and no passwordless sudo.")
    say("nothing was changed on the host. Run this yourself (sudo may ask for your password):")
    say(f"  ssh -t {q(h.admin)} {q(remote)} < {q(str(TEMPLATES / 'patch.sh'))}")
    if mode == "plan":
        say(f"then run `hosts patch {host}` again once the admin login has passwordless sudo")
    else:
        say("(the command installs exactly the packages of the saved plan)")


def _held_docker(names: list[str]) -> list[str]:
    return [n for n in names if n in DOCKER_PACKAGES]


def _ended(proc) -> str:
    """"done" (rc 0, DONE last), "error" (rc 1 with the script's own ERROR line) or "unknown": the only
    outcomes the script reports. A timeout (124), a dropped ssh (255), a signal or a missing marker is unknown."""
    if _finished(proc):
        return "done"
    return "error" if _stopped_itself(proc) else "unknown"


def _reboot_state(out: str, marker: str) -> str:
    value = (_markers(out, marker) or [""])[0]
    return {"0": "no", "1": "yes"}.get(value, "unknown")


def _unknown_hint(apply: bool, say) -> None:
    if apply:
        say("packages may be partly installed: check /var/log/unattended-upgrades/ and `apt list --upgradable` "
            "on the host")
    else:
        say("nothing was installed (the plan run only updates the package index and does a dry run)")


def _patch_unknown(proc, apply: bool, say) -> None:
    say(f"hosts patch did not finish on the host (exit {proc.rc}): state unknown")
    _unknown_hint(apply, say)
    if proc.out.strip():
        say("partial output:")
        _show(proc.out, say)
    detail = _detail(proc.err)
    if detail:
        say(f"  last error output: {detail[:SHOWN_WIDTH]}")


def _dry_run(host: str, s, include_docker: bool, say, what: str):
    """Runs the plan on the host. Returns (result, packages, output): `result` is (exit code, log outcome) when the
    run must stop here (state unknown, a reported failure, the hold-back not applied), else None."""
    proc = s.sh(script_text("patch.sh"), _patch_args("plan", include_docker), timeout=PATCH_PLAN_TIMEOUT)
    ended = _ended(proc)
    if ended == "unknown":
        _patch_unknown(proc, False, say)
        return (EXIT_FAILED, "state unknown"), [], ""
    if ended == "error":
        say(f"hosts patch {host}: the {what} failed on the host: {_detail(proc.err) or 'no error output'}")
        say("nothing was installed")
        return (EXIT_FAILED, "aborted: plan failed"), [], ""
    packages = parse_dry_run(proc.out)
    if not packages and NOTHING_TO_UPGRADE not in proc.out:
        # no package line is not proof of "nothing to do": unattended-upgrade also logs nothing on a day outside
        # its Update-Days. Only its own "no packages" line counts.
        say(f"hosts patch {host}: the dry run named no packages and did not say there were none: state unknown")
        _unknown_hint(False, say)
        _show(proc.out, say)
        return (EXIT_FAILED, "state unknown"), [], proc.out
    held = _held_docker(packages)
    if held and not include_docker:
        say(f"Docker hold-back did not apply; nothing installed (the plan lists: {', '.join(held)})")
        say("not continuing: fix the hold-back or pass --include-docker on purpose")
        return (EXIT_FAILED, "aborted: docker hold-back did not apply"), packages, proc.out
    unlisted = [n for n in packages if n.startswith(DOCKER_FAMILY) and n not in DOCKER_PACKAGES]
    if unlisted and not include_docker:
        for name in unlisted:
            say(f"{name} is Docker-related but not in the hold-back list; nothing installed")
        say("not continuing: add it to DOCKER_PACKAGES (or pass --include-docker on purpose)")
        return (EXIT_FAILED, f"aborted: {', '.join(unlisted)} is Docker-related but not in the hold-back list"), \
            packages, proc.out
    return None, packages, proc.out


def _patch_plan(cfg, host: str, s, include_docker: bool, say, now) -> tuple[int, str]:
    stop, packages, out = _dry_run(host, s, include_docker, say, "plan")
    return stop or _after_plan(cfg, host, packages, out, include_docker, say, now)


def _after_plan(cfg, host, packages, out, include_docker, say, now) -> tuple[int, str]:
    reboot = _reboot_state(out, "REBOOT_ALREADY")
    if not packages:
        _forget_patch_plan(cfg.out, host)
        say(f"hosts patch {host}: nothing to install (reboot-required already pending: {reboot})")
        return EXIT_OK, "plan: 0 packages"
    say(f"hosts patch {host}: {len(packages)} package(s) would be installed"
        f"{' (Docker packages included)' if include_docker else ' (Docker packages held back)'}:")
    say("  " + " ".join(packages))
    say(f"  reboot-required already pending: {reboot}")
    try:
        _save_patch_plan(cfg.out, host, packages, include_docker, now)
    except OSError as exc:
        say(f"hosts patch {host}: the plan could not be saved ({type(exc).__name__}); --confirm will not work")
        return EXIT_FAILED, f"plan: {len(packages)} packages (not saved)"
    flag = " --include-docker" if include_docker else ""
    say("nothing was installed, restarted or rebooted")
    say(f"run `hosts patch {host} --confirm {host}{flag}` within 24 h to install exactly this list")
    return EXIT_OK, f"plan: {len(packages)} packages"


def _apply_report(host: str, out: str, say) -> None:
    say(f"  reboot-required: {_reboot_state(out, 'REBOOT_REQUIRED')}")
    lines = out.splitlines()
    if "unknown" in _markers(out, "NEEDRESTART"):
        say("  needrestart: not available on the host; services on old libraries were not checked")
    else:
        services = [ln.split(":", 1)[1].strip() for ln in lines if ln.startswith("NEEDRESTART-SVC:")]
        if "NEEDRESTART listed" in lines:
            if services:
                say("  services running on old libraries (not restarted):")
                for name in services:
                    say(f"    {name if SERVICE_NAME.fullmatch(name) else '(unprintable name)'}")
            else:
                say("  needrestart: no service needs a restart")
        else:
            say("  needrestart: no answer; services on old libraries were not checked")
        for ln in lines:
            if ln.startswith("NEEDRESTART-KSTA:"):
                state = KERNEL_STATES.get(ln.split(":", 1)[1].strip(), "unknown")
                say(f"  kernel: {state}")
    say(f"sbom-audit rebooted and restarted nothing on {host} and suppressed needrestart's automatic restarts; "
        "package maintainer scripts may have restarted their own services (for example ssh, cron): see "
        "/var/log/unattended-upgrades/unattended-upgrades-dpkg.log")


def _patch_apply(cfg, host: str, s, include_docker: bool, confirmed: list[str], say) -> tuple[int, str]:
    # the saved plan is spent the moment apply starts, whatever happens next: a confirmation never replays
    _forget_patch_plan(cfg.out, host)
    try:
        proc = s.sh(script_text("patch.sh"), _patch_args("apply", include_docker, confirmed),
                    timeout=PATCH_APPLY_TIMEOUT)
    except transport.AdminError:
        raise
    except BaseException:                           # an interrupt or crash while it runs: the state is unknown
        say(f"hosts patch {host}: interrupted while the upgrade ran: state unknown")
        _unknown_hint(True, say)
        _log(cfg, "patch", host, "interrupted: state unknown")
        raise
    ended = _ended(proc)
    if ended == "unknown":
        _patch_unknown(proc, True, say)
        return EXIT_FAILED, "state unknown"
    if ended == "error":
        detail = _detail(proc.err) or "no error output"
        if any(m in proc.out or m in proc.err for m in BUSY_MARKERS):
            say(f"hosts patch {host}: nothing was installed: apt is busy (another apt or unattended-upgrades run "
                "holds the lock); run the plan again later")
            return EXIT_FAILED, "aborted: apt busy"
        if "not in force" in detail:
            say(f"hosts patch {host}: nothing was installed: {detail}")
            return EXIT_FAILED, "aborted: settings not in force"
        say(f"hosts patch {host}: the upgrade failed on the host: {detail}")
        say("packages may be partly installed: check /var/log/unattended-upgrades/ and `apt list --upgradable`")
        return EXIT_FAILED, "failed"
    installed = parse_installed(proc.out)
    say(f"hosts patch {host}: {len(installed)} package(s) installed" + (":" if installed else ""))
    if installed:
        say("  " + " ".join(installed))
    problems = []
    held = [n for n in _held_docker(installed) if not include_docker]
    if held:
        say(f"WARNING: hold-back failed after install: {', '.join(held)} was installed although it should "
            "have been held back")
        say("the container runtime may have been restarted: check your containers now")
        problems.append(f"hold-back failed after install: {', '.join(held)}")
    outside = [n for n in installed if n not in confirmed and n not in held]
    if outside:
        say(f"WARNING: installed outside the confirmed plan: {', '.join(outside)}")
        problems.append(f"installed outside the plan: {', '.join(outside)}")
    skipped = [n for n in confirmed if n not in installed]
    if skipped:
        say(f"skipped (will show in the next plan): {', '.join(skipped)}")
    _apply_report(host, proc.out, say)
    if problems:
        return EXIT_FINDINGS, "; ".join(problems)
    return EXIT_OK, f"{len(installed)} packages installed" + (f"; skipped: {', '.join(skipped)}" if skipped else "")


def patch(cfg, host: str, confirm: str | None, include_docker: bool, *, run=subprocess.run, say=print,
          session=transport.AdminSession, now=lambda: dt.datetime.now(dt.timezone.utc),
          env=os.environ) -> int:
    """`hosts patch`: without `confirm` the plan (dry run, saved for 24 h); with `confirm` (the host name) a
    fresh plan that must equal the saved one, then the upgrade. Never reboots, never restarts a service or
    container; the held-back Docker packages stay out unless `include_docker`."""
    store.check_host(host)
    if _refused("patch", host, confirm, env, say):
        return EXIT_FAILED
    h = cfg.hosts.servers[host]
    if not h.admin:
        say(f"hosts patch {host}: no admin login: set admin = \"user@host\" under [hosts.servers.\"{host}\"]")
        return EXIT_FAILED
    mode = "plan" if confirm is None else "apply"
    ctl = _control_dir()
    opened = []
    try:
        with session(h.admin, ctl, run=run) as s:
            opened.append(s)
            if s.privilege() is None:
                _patch_manual(host, h, mode, include_docker, say, _read_patch_plan(cfg.out, host), now())
                rc, outcome = EXIT_FAILED, "needs manual run"
            else:
                rc, outcome = _patch_run(cfg, host, s, confirm, include_docker, say, now())
    except transport.AdminError as exc:
        say(f"hosts patch {host}: {exc}")
        rc, outcome = EXIT_FAILED, "admin login failed"
    finally:
        _cleanup(ctl, opened)
    _log(cfg, "patch", host, outcome)
    return rc


def _patch_run(cfg, host: str, s, confirm: str | None, include_docker: bool, say, now) -> tuple[int, str]:
    if confirm is None:
        return _patch_plan(cfg, host, s, include_docker, say, now)
    saved = _read_patch_plan(cfg.out, host)
    stop, packages, _ = _dry_run(host, s, include_docker, say, "re-check")
    if stop:
        return stop
    if not packages:
        _forget_patch_plan(cfg.out, host)
        say(f"hosts patch {host}: nothing to install")
        return EXIT_OK, "plan: 0 packages"
    why = _plan_matches(saved, packages, include_docker, now)
    if why:
        say(f"hosts patch {host}: not installing: {why}. The list is now ({len(packages)}):")
        say("  " + " ".join(packages))
        flag = " --include-docker" if include_docker else ""
        say(f"review it, run `hosts patch {host}{flag}` to save this plan, then `--confirm {host}` again")
        return EXIT_FAILED, "aborted: plan changed"
    return _patch_apply(cfg, host, s, include_docker, packages, say)
