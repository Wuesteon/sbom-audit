"""Host mode admin: `hosts bootstrap` / `hosts unbootstrap`, the admin ssh session and the lockout guard.

Nothing here opens a connection: `run` is a fake keyed on argv patterns (ssh -G, ssh-keyscan, ssh-keygen, the
audit login, the fresh admin login) and the admin session is a fake that records the scripts it is handed.
The remote scripts' pure decision functions run in the local `sh`. Hosts and addresses are example data
(box-a, 203.0.113.0/24, 198.51.100.0/24).
"""
import base64
import contextlib
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import cli, config
from sbomaudit.hosts import admin, parse, store, transport
from tests.hosts_fixture import collector_doc

ROOT = Path(__file__).resolve().parent.parent / "plugin"
TEMPLATES = ROOT / "templates" / "hosts"
PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExample0 sbom-audit"
KEY_LINE = 'restrict,command="sudo -n /usr/local/lib/sbom-audit/collect" ' + PUB


def _blob(key_type: str, filler: int) -> str:
    raw = key_type.encode()
    data = struct.pack(">I", len(raw)) + raw + struct.pack(">I", 32) + bytes([filler]) * 32
    return base64.b64encode(data).decode()


def _fp(blob: str) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(blob)).digest()).decode().rstrip("=")


ED = _blob("ssh-ed25519", 1)
ED_OTHER = _blob("ssh-ed25519", 2)
ECDSA = _blob("ecdsa-sha2-nistp256", 3)


def _proc(rc=0, out="", err=""):
    return subprocess.CompletedProcess([], rc, out.encode(), err.encode())


class FakeRun:
    """Answers the local commands bootstrap runs; anything else fails the test."""

    def __init__(self, tmp: Path, *, ssh_g="hostname 203.0.113.10\nport 22\n", scan=None, known=None,
                 collect_ok=True, fresh_admin=(True,), collector=parse.SHIPPED_VERSION):
        self.tmp = tmp
        self.known_file = tmp / "user_known_hosts"
        self.ssh_g = ssh_g + f"userknownhostsfile {self.known_file}\n"
        self.scan = scan if scan is not None else f"203.0.113.10 ssh-ed25519 {ED}\n203.0.113.10 ecdsa-sha2-nistp256 {ECDSA}\n"
        if known is not None:
            self.known_file.write_text(known)
        self.known = known
        self.collect_ok = collect_ok
        self.fresh_admin = list(fresh_admin)
        self.collector = collector
        self.bootstrapped = False
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kw):
        argv = list(argv)
        self.calls.append(argv)
        if argv[:2] == ["ssh", "-G"]:
            return _proc(0, self.ssh_g)
        if argv[0] == "ssh-keyscan":
            return _proc(0, self.scan, "# 203.0.113.10:22 SSH-2.0-OpenSSH_9.6\n")
        if argv[0] == "ssh-keygen" and "-F" in argv:
            if self.known is None:
                return _proc(1)
            return _proc(0, "# Host 203.0.113.10 found: line 1\n" + self.known)
        if argv[0] == "ssh-keygen" and "-t" in argv:
            path = Path(argv[argv.index("-f") + 1])
            path.write_text("private\n")
            Path(f"{path}.pub").write_text(PUB + "\n")
            return _proc(0)
        if argv[0] == "ssh" and "-l" in argv and argv[argv.index("-l") + 1] == "sbom-audit":
            if self.bootstrapped and self.collect_ok:
                doc = collector_doc()
                doc["collector"] = self.collector
                return _proc(0, json.dumps(doc))
            if self.bootstrapped:
                return _proc(1, "", "sudo: a password is required")
            return _proc(255, "", "sbom-audit@203.0.113.10: Permission denied (publickey).")
        if argv[0] == "ssh" and argv[-1] == "true" and "ControlPath=none" in argv:
            ok = self.fresh_admin.pop(0) if len(self.fresh_admin) > 1 else self.fresh_admin[0]
            return _proc(0 if ok else 255, "", "" if ok else "Permission denied")
        raise AssertionError(f"unexpected local command {argv}")

    def audit_logins(self) -> int:
        return sum(1 for a in self.calls if a[0] == "ssh" and "-l" in a)


class FakeSession:
    """Stands in for `transport.AdminSession`: records what runs through the admin login."""

    def __init__(self, run: FakeRun, *, privilege="root", bootstrap=None, rollback=None, unbootstrap=None,
                 sshd_t="allowusers root\n", gone=False):
        self.fake_run = run
        self.priv = privilege
        self.results = {"bootstrap": bootstrap or transport.Proc(0, "STEP os ok\nALLOWUSERS_UNCHANGED\nDONE\n", ""),
                        "rollback": rollback or transport.Proc(0, "", ""),
                        "unbootstrap": unbootstrap or transport.Proc(0, "STEP sudoers ok\nDONE\n", "")}
        self.sshd_t = sshd_t
        self.gone = gone
        self.scripts: list[tuple[str, list[str], str | None]] = []
        self.commands: list[str] = []
        self.kept = False
        self.exited = False
        self.timeouts: dict[str, int] = {}
        self.targets: list[str] = []
        self.is_root = privilege == "root"

    def __call__(self, target, control_dir, run=None):
        self.targets.append(target)
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.exited = True                       # the real session closes the master here unless kept
        return False

    def closed(self) -> bool:
        return self.exited and not self.kept

    def privilege(self):
        return self.priv

    def command(self, remote, as_root=False, timeout=60):
        self.commands.append(remote)
        if "sshd -T" in remote:
            return transport.Proc(0, self.sshd_t, "")
        if remote.startswith("id -u sbom-audit"):
            return transport.Proc(1 if self.gone else 0, "" if self.gone else "998\n", "")
        if remote.startswith("test -e"):
            return transport.Proc(1 if self.gone else 0, "", "")
        raise AssertionError(f"unexpected remote command {remote}")

    def sh(self, script, args, stdin_extra=None, timeout=900):
        name = {admin.script_text("bootstrap.sh"): "bootstrap", admin.ROLLBACK_SCRIPT: "rollback",
                admin.script_text("unbootstrap.sh"): "unbootstrap"}[script]
        self.scripts.append((name, list(args), stdin_extra))
        self.timeouts[name] = timeout
        result = self.results[name]
        if isinstance(result, BaseException):
            raise result
        if name == "bootstrap" and (result.rc == 0 or "ALLOWUSERS_EDITED" in result.out):
            self.fake_run.bootstrapped = True    # the collector is installed before the AllowUsers step
        return result

    def keep_open(self):
        self.kept = True
        return "/tmp/sbom-audit-ctl/m"

    def names(self):
        return [s[0] for s in self.scripts]


class AdminBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.out = self.tmp / "security"
        self.out.mkdir()
        self.key = self.tmp / "sbom-audit_ed25519"
        self.said: list[str] = []
        self.sleeps: list[float] = []
        env = {k: v for k, v in os.environ.items() if k not in ("SBOM_AUDIT_READ_ONLY", "SBOM_AUDIT_SCHEDULED")}
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def make_key(self):
        self.key.write_text("private\n")
        Path(f"{self.key}.pub").write_text(PUB + "\n")

    def cfg(self, address="203.0.113.10", admin_login="root@203.0.113.10"):
        servers = {"box-a": config.HostOpts(address=address, admin=admin_login)}
        opts = config.HostsOpts(enabled=True, timeout_minutes=10, key=self.key, servers=servers)
        return config.Config(out=self.out, root=self.out.parent, mode="portfolio", hosts=opts)

    def say(self, text=""):
        self.said.append(str(text))

    def text(self) -> str:
        return "\n".join(self.said)

    def bootstrap(self, run, session, confirm="box-a", cfg=None):
        return admin.bootstrap(cfg or self.cfg(), "box-a", confirm, run=run, say=self.say, session=session,
                               sleep=self.sleeps.append)

    def unbootstrap(self, run, session, confirm="box-a", cfg=None):
        return admin.unbootstrap(cfg or self.cfg(), "box-a", confirm, run=run, say=self.say, session=session,
                                 sleep=self.sleeps.append)

    def files(self) -> list[str]:
        return sorted(str(p.relative_to(self.out)) for p in self.out.rglob("*") if p.is_file())

    def log(self) -> str:
        path = self.out / "log.md"
        return path.read_text() if path.exists() else ""


class TextTests(unittest.TestCase):
    def test_authorized_keys_line_exact(self):
        self.assertEqual(admin.authorized_keys_line(PUB + "\n"), KEY_LINE)
        self.assertEqual(admin.authorized_keys_line("  " + PUB + "  "), KEY_LINE)

    def test_authorized_keys_line_rejects_anything_but_one_public_key(self):
        for bad in ("", "ssh-ed25519", PUB + "\nssh-ed25519 AAAA other", "-----BEGIN OPENSSH PRIVATE KEY-----",
                    'command="sh" ' + PUB, PUB.replace(" sbom-audit", " x\x00y")):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    admin.authorized_keys_line(bad)

    def test_sudoers_text_exact(self):
        self.assertEqual(admin.sudoers_text(),
                         "sbom-audit ALL=(root) NOPASSWD: /usr/local/lib/sbom-audit/collect \"\"\n")

    def test_fingerprint_is_openssh_sha256(self):
        self.assertEqual(admin.fingerprint(f"203.0.113.10 ssh-ed25519 {ED}"), _fp(ED))
        with self.assertRaises(ValueError):          # the blob's own type must match the line's
            admin.fingerprint(f"203.0.113.10 ssh-rsa {ED}")


class HostKeyTests(AdminBase):
    def test_pin_uses_ssh_g_hostname_and_port(self):
        run = FakeRun(self.tmp, ssh_g="hostname 203.0.113.10\nport 2222\n",
                      scan=f"[203.0.113.10]:2222 ssh-ed25519 {ED}\n")
        h = config.HostOpts(address="box-a", admin="root@box-a")
        keys = admin.host_keys(h, run)
        self.assertIn(["ssh", "-G", "box-a"], run.calls)
        self.assertIn(["ssh-keyscan", "-p", "2222", "203.0.113.10"], run.calls)
        self.assertEqual(keys, [(f"[203.0.113.10]:2222 ssh-ed25519 {ED}", _fp(ED))])
        self.make_key()
        session = FakeSession(run)
        self.assertEqual(self.bootstrap(run, session, cfg=self.cfg(address="box-a", admin_login="root@box-a")), 0)
        pinned = [ln for ln in (self.out / store.KNOWN_HOSTS).read_text().splitlines() if not ln.startswith("#")]
        self.assertEqual(pinned, [f"sbom-audit-box-a ssh-ed25519 {ED}"])
        self.assertTrue(all(ln.startswith("sbom-audit-box-a ") for ln in pinned))

    def test_cross_check_looks_up_bracketed_port(self):
        run = FakeRun(self.tmp, ssh_g="hostname 203.0.113.10\nport 2222\n",
                      scan=f"[203.0.113.10]:2222 ssh-ed25519 {ED}\n",
                      known=f"|1|abc=|def= ssh-ed25519 {ED}\n")
        admin.host_keys(config.HostOpts(address="box-a"), run)
        lookups = [a for a in run.calls if a[0] == "ssh-keygen" and "-F" in a]
        self.assertEqual(lookups[0][lookups[0].index("-F") + 1], "[203.0.113.10]:2222")

    def test_known_hosts_mismatch_aborts(self):
        self.make_key()
        run = FakeRun(self.tmp, known=f"203.0.113.10 ssh-ed25519 {ED_OTHER}\n")
        with self.assertRaisesRegex(ValueError, "does not match"):
            admin.host_keys(config.HostOpts(address="203.0.113.10"), run)
        session = FakeSession(run)
        self.assertEqual(self.bootstrap(run, session), 2)
        self.assertIn("does not match", self.text())
        self.assertFalse((self.out / store.KNOWN_HOSTS).exists())   # nothing pinned
        self.assertEqual(session.scripts, [])                       # nothing ran on the host
        self.assertEqual(run.audit_logins(), 0)

    def test_known_hosts_match_passes(self):
        """Only the key types the user's known_hosts vouches for are pinned: an unverified extra type could come
        from someone in the middle answering just that one keyscan connection."""
        run = FakeRun(self.tmp, known=f"203.0.113.10 ssh-ed25519 {ED}\n")
        keys = admin.host_keys(config.HostOpts(address="203.0.113.10"), run)
        self.assertEqual(keys, [(f"203.0.113.10 ssh-ed25519 {ED}", _fp(ED))])

    def test_no_scanned_keys_aborts(self):
        run = FakeRun(self.tmp, scan="")
        with self.assertRaisesRegex(ValueError, "no host keys"):
            admin.host_keys(config.HostOpts(address="203.0.113.10"), run)

    def test_bootstrap_repins_an_already_pinned_host(self):
        """Decision 1: re-pinning goes through store.pin_host_keys, so the pin hash changes (clears hostkey:changed)."""
        from sbomaudit.hosts import checker
        self.make_key()
        store.pin_host_keys(self.out, "box-a", [f"203.0.113.10 ssh-ed25519 {ED_OTHER}"])
        before = checker.known_hosts_sha(self.out, "box-a")
        run = FakeRun(self.tmp)
        with mock.patch.object(store, "pin_host_keys", wraps=store.pin_host_keys) as pin:
            self.assertEqual(self.bootstrap(run, FakeSession(run)), 0)
        pin.assert_called_once()
        self.assertEqual(pin.call_args.args[1], "box-a")
        after = checker.known_hosts_sha(self.out, "box-a")
        self.assertNotEqual(before, after)
        self.assertNotIn(ED_OTHER, (self.out / store.KNOWN_HOSTS).read_text())


class PlanTests(AdminBase):
    def test_plan_without_confirm_writes_nothing(self):
        run = FakeRun(self.tmp)
        session = FakeSession(run, sshd_t="allowusers root\nallowusers deploy\n")
        self.assertEqual(self.bootstrap(run, session, confirm=None), 0)
        self.assertEqual(session.scripts, [])                       # no remote `sh -s`
        self.assertEqual(self.files(), [])                          # no local file in the evidence repo
        self.assertFalse(self.key.exists())                         # no key generated
        self.assertFalse(any(a[0] == "ssh-keygen" and "-t" in a for a in run.calls))
        self.assertEqual(run.audit_logins(), 0)
        text = self.text()
        self.assertIn(_fp(ED), text)
        self.assertIn("root@203.0.113.10", text)
        self.assertIn("root", text)
        self.assertIn("--confirm box-a", text)
        self.assertIn("AllowUsers", text)
        self.assertIn("will add sbom-audit", text)
        self.assertNotIn(ED, text)                                  # fingerprints only, no key material

    def test_plan_reports_allowgroups_as_manual(self):
        run = FakeRun(self.tmp)
        session = FakeSession(run, sshd_t="allowgroups admins\n")
        self.assertEqual(self.bootstrap(run, session, confirm=None), 0)
        self.assertIn("by hand", self.text())

    def test_plan_without_admin_configured(self):
        run = FakeRun(self.tmp)
        rc = self.bootstrap(run, FakeSession(run), confirm=None, cfg=self.cfg(admin_login=None))
        self.assertEqual(rc, 2)
        self.assertIn("admin", self.text())
        self.assertEqual(run.calls, [])


class BootstrapTests(AdminBase):
    def test_generates_the_audit_key_when_missing(self):
        run = FakeRun(self.tmp)
        session = FakeSession(run)
        self.assertEqual(self.bootstrap(run, session), 0)
        gen = [a for a in run.calls if a[0] == "ssh-keygen" and "-t" in a]
        self.assertEqual(gen, [["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "sbom-audit", "-f", str(self.key)]])
        name, args, stdin_extra = session.scripts[0]
        self.assertEqual(name, "bootstrap")
        self.assertEqual(args[0], KEY_LINE)
        self.assertEqual(args[1:], [hashlib.sha256((TEMPLATES / "collect.sh").read_bytes()).hexdigest(),
                                    hashlib.sha256((TEMPLATES / "lynis.prf").read_bytes()).hexdigest()])
        self.assertTrue(stdin_extra.startswith((TEMPLATES / "collect.sh").read_text()))
        self.assertTrue(stdin_extra.endswith("\n" + admin.PAYLOAD_END + "\n"))
        self.assertNotIn("private", self.text())

    def test_non_root_without_sudo_prints_command(self):
        self.make_key()
        run = FakeRun(self.tmp)
        session = FakeSession(run, privilege=None)
        rc = self.bootstrap(run, session, cfg=self.cfg(admin_login="deploy@203.0.113.10"))
        self.assertEqual(rc, 2)
        self.assertEqual(session.scripts, [])                       # never escalates another way
        text = self.text()
        self.assertIn("ssh -t deploy@203.0.113.10", text)
        self.assertIn("sudo sh -s --", text)
        self.assertIn(str(TEMPLATES / "bootstrap.sh"), text)
        self.assertIn(str(TEMPLATES / "collect.sh"), text)
        self.assertIn("hosts bootstrap box-a --confirm box-a", text)
        self.assertIn("hosts bootstrap | box-a | needs manual run", self.log())

    def test_printed_manual_command_runs_the_bundle(self):
        """The printed pipeline assembles exactly the stdin the session would send."""
        self.make_key()
        run = FakeRun(self.tmp)
        self.bootstrap(run, FakeSession(run, privilege=None), cfg=self.cfg(admin_login="deploy@203.0.113.10"))
        line = next(ln.strip() for ln in self.said if "| ssh deploy@203.0.113.10" in ln)
        local = line.split(" | ssh ", 1)[0]
        made = subprocess.run(["sh", "-c", local], capture_output=True, check=True).stdout.decode()
        self.assertEqual(made, admin.script_text("bootstrap.sh") + admin.bootstrap_payload())

    def test_allowusers_lockout_guard_success(self):
        self.make_key()
        run = FakeRun(self.tmp, fresh_admin=(True,))
        session = FakeSession(run, bootstrap=transport.Proc(
            0, "STEP os ok\nALLOWUSERS_EDITED /etc/ssh/sshd_config\nSTEP allowusers ok\nDONE\n", ""))
        self.assertEqual(self.bootstrap(run, session), 0)
        self.assertEqual(session.names(), ["bootstrap"])            # no rollback
        record = json.loads((self.out / admin.BOOTSTRAP_DIR / "box-a.json").read_text())
        self.assertEqual(record, {"allowusers_file": "/etc/ssh/sshd_config"})
        fresh = [a for a in run.calls if a[-1] == "true" and "ControlPath=none" in a]
        self.assertEqual(len(fresh), 1)
        self.assertIn("root@203.0.113.10", fresh[0])
        self.assertGreaterEqual(run.audit_logins(), 1)
        self.assertIn("hosts bootstrap | box-a | ok", self.log())
        self.assertTrue(session.closed())                           # success closes the master

    def test_allowusers_lockout_guard_rollback(self):
        self.make_key()
        run = FakeRun(self.tmp, collect_ok=False)
        session = FakeSession(run, bootstrap=transport.Proc(
            0, "ALLOWUSERS_EDITED /etc/ssh/sshd_config.d/10-users.conf\nDONE\n", ""))
        self.assertEqual(self.bootstrap(run, session), 2)
        self.assertEqual(session.names(), ["bootstrap", "rollback"])   # through the same session
        self.assertEqual(session.scripts[1][1], ["/etc/ssh/sshd_config.d/10-users.conf"])
        self.assertFalse((self.out / admin.BOOTSTRAP_DIR / "box-a.json").exists())
        self.assertIn("hosts bootstrap | box-a | rolled back", self.log())
        self.assertFalse(session.kept)

    def test_rollback_when_the_fresh_admin_login_fails(self):
        self.make_key()
        run = FakeRun(self.tmp, fresh_admin=(False, False, True))  # fails twice (with one retry), then works
        session = FakeSession(run, bootstrap=transport.Proc(0, "ALLOWUSERS_EDITED /etc/ssh/sshd_config\nDONE\n", ""))
        self.assertEqual(self.bootstrap(run, session), 2)
        self.assertEqual(session.names(), ["bootstrap", "rollback"])
        self.assertEqual(run.audit_logins(), 1)                    # only the pre-check: no collect after the failure
        self.assertEqual(self.sleeps, [3])                          # the guard retried the fresh login once
        self.assertIn("rolled back", self.log())
        self.assertTrue(session.closed())

    def test_rollback_failure_is_loud_and_keeps_the_session_open(self):
        self.make_key()
        run = FakeRun(self.tmp, fresh_admin=(False,))
        session = FakeSession(run, bootstrap=transport.Proc(0, "ALLOWUSERS_EDITED /etc/ssh/sshd_config\nDONE\n", ""),
                              rollback=transport.Proc(8, "", "sshd -t failed"))
        self.assertEqual(self.bootstrap(run, session), 2)
        self.assertIn("ROLLBACK FAILED: the admin session is still open; restore /etc/ssh/sshd_config from "
                      "/etc/ssh/sshd_config.sbom-audit.bak by hand before closing it", self.text())
        self.assertTrue(session.kept)
        self.assertIn("ssh -S /tmp/sbom-audit-ctl/m root@203.0.113.10", self.text())
        self.assertIn("hosts bootstrap | box-a | rollback failed", self.log())
        self.assertTrue(session.exited)
        self.assertTrue(session.kept)                               # the master stays: it is the way back in

    def test_rollback_script_groups_the_reload(self):
        """Decision 3: a failed cp or sshd -t must never reach a reload."""
        self.assertIn('cp "$1.sbom-audit.bak" "$1" && sshd -t && { systemctl reload ssh || systemctl reload sshd; }',
                      admin.ROLLBACK_SCRIPT)

    def test_an_unexpected_edited_path_is_not_trusted_and_keeps_the_session(self):
        self.make_key()
        run = FakeRun(self.tmp)
        session = FakeSession(run, bootstrap=transport.Proc(0, "ALLOWUSERS_EDITED /etc/passwd\nDONE\n", ""))
        self.assertEqual(self.bootstrap(run, session), 2)
        self.assertEqual(session.names(), ["bootstrap"])          # never hands that path to a cp as root
        self.assertIn("by hand", self.text())
        self.assertTrue(session.kept)
        self.assertIn("unexpected allowusers file", self.log())

    def test_allowusers_multiple_lines_manual(self):
        self.make_key()
        run = FakeRun(self.tmp)
        session = FakeSession(run, bootstrap=transport.Proc(
            4, "STEP os ok\nALLOWUSERS_MANUAL /etc/ssh/sshd_config /etc/ssh/sshd_config.d/10-users.conf\n",
            "AllowUsers is set on 2 lines"))
        self.assertEqual(self.bootstrap(run, session), 2)
        self.assertEqual(session.names(), ["bootstrap"])           # nothing rolled back
        self.assertIn("/etc/ssh/sshd_config.d/10-users.conf", self.text())
        self.assertIn("AllowUsers is set on 2 lines", self.text())
        self.assertFalse((self.out / admin.BOOTSTRAP_DIR / "box-a.json").exists())
        self.assertIn("allowusers manual", self.log())

    def test_script_failures_map_to_exit_2(self):
        for rc, out, expect in ((3, "UNSUPPORTED alpine\n", "unsupported"), (5, "ALLOWUSERS_FAILED sshd -t\n", "restored"),
                                (6, "NEEDS_SUDO\n", "sudo"), (1, "STEP os ok\n", "failed")):
            with self.subTest(rc=rc):
                self.said.clear()
                self.make_key()
                run = FakeRun(self.tmp)
                session = FakeSession(run, bootstrap=transport.Proc(rc, out, "ERROR boom"))
                self.assertEqual(self.bootstrap(run, session), 2)
                self.assertIn(expect, self.text())
                self.assertEqual(session.names(), ["bootstrap"])
                self.assertTrue(session.closed())                   # the script said where it stopped

    def test_verify_without_allowusers_edit(self):
        self.make_key()
        run = FakeRun(self.tmp, collect_ok=False)
        session = FakeSession(run)
        self.assertEqual(self.bootstrap(run, session), 2)
        self.assertEqual(session.names(), ["bootstrap"])           # no edit: nothing to roll back
        self.assertIn("verify failed", self.log())

    def test_already_bootstrapped_short_circuit(self):
        self.make_key()
        run = FakeRun(self.tmp)
        run.bootstrapped = True
        session = FakeSession(run)
        self.assertEqual(self.bootstrap(run, session), 0)
        self.assertEqual(session.scripts, [])
        self.assertEqual(session.targets, [])                      # no admin session at all
        self.assertIn("already bootstrapped", self.text())
        self.assertIn("hosts bootstrap | box-a | already bootstrapped", self.log())
        self.assertTrue((self.out / store.KNOWN_HOSTS).exists())   # but the keys were (re-)pinned

    def test_outdated_collector_is_not_already_bootstrapped(self):
        self.make_key()
        run = FakeRun(self.tmp, collector="0")
        run.bootstrapped = True
        session = FakeSession(run)
        self.assertEqual(self.bootstrap(run, session), 0)
        self.assertEqual(session.names(), ["bootstrap"])


    # ------------------------------------------------------------------ review fixes (I1-I3, m5, m7, m11)

    def test_a_failed_record_write_rolls_back(self):
        """I1: the edit is live once EDITED arrives; an unwritable record must not leave it unproven."""
        self.make_key()
        run = FakeRun(self.tmp)
        session = FakeSession(run, bootstrap=transport.Proc(0, "ALLOWUSERS_EDITED /etc/ssh/sshd_config\nDONE\n", ""))
        with mock.patch.object(admin, "atomic_write", side_effect=OSError("disk full")):
            self.assertEqual(self.bootstrap(run, session), 2)
        self.assertEqual(session.names(), ["bootstrap", "rollback"])
        self.assertIn("the bootstrap record could not be written (OSError)", self.text())
        self.assertNotIn("disk full", self.text())
        self.assertIn("hosts bootstrap | box-a | rolled back", self.log())

    def test_bootstrap_timeout_is_far_above_the_apt_lock_waits(self):
        self.make_key()
        run = FakeRun(self.tmp)
        session = FakeSession(run)
        self.assertEqual(self.bootstrap(run, session), 0)
        self.assertGreaterEqual(session.timeouts["bootstrap"], 3 * 300 + 900)

    def test_a_timeout_after_the_edit_runs_the_guard_and_never_succeeds(self):
        """I2: rc 124 with a partial ALLOWUSERS_EDITED: the guard still runs; the rest is unknown."""
        partial = transport.Proc(124, "STEP os ok\nSTEP lynis ok\nALLOWUSERS_EDITED /etc/ssh/sshd_config\n",
                                 "timed out after 2400 s")
        for collect_ok, names in ((True, ["bootstrap"]), (False, ["bootstrap", "rollback"])):
            with self.subTest(guard_passes=collect_ok):
                self.said.clear()
                self.make_key()
                (self.out / "log.md").unlink(missing_ok=True)
                run = FakeRun(self.tmp, collect_ok=collect_ok)
                session = FakeSession(run, bootstrap=partial)
                self.assertEqual(self.bootstrap(run, session), 2)
                self.assertEqual(session.names(), names)
                self.assertGreaterEqual(len([a for a in run.calls if a[-1] == "true"]), 1)   # the guard ran
                self.assertIn("state unknown: check /etc/ssh/sshd_config", self.text())
                self.assertIn("the admin session is kept at /tmp/sbom-audit-ctl/m", self.text())
                self.assertTrue(session.kept)
                self.assertIn("hosts bootstrap | box-a | state unknown", self.log())
                self.assertNotIn("| ok", self.log())

    def test_a_dropped_connection_without_a_marker_is_state_unknown(self):
        self.make_key()
        run = FakeRun(self.tmp)
        session = FakeSession(run, bootstrap=transport.Proc(255, "STEP os ok\nSTEP user ok\n", "Connection reset"))
        self.assertEqual(self.bootstrap(run, session), 2)
        self.assertEqual(session.names(), ["bootstrap"])            # nothing to roll back: no edit was reported
        self.assertIn("state unknown: check /etc/ssh/sshd_config, /etc/ssh/sshd_config.d/*.conf", self.text())
        self.assertIn("a fresh admin login works right now", self.text())
        self.assertTrue(session.kept)
        self.assertTrue(session.exited)
        self.assertIn("hosts bootstrap | box-a | state unknown", self.log())

    def test_an_interrupt_while_the_script_runs_keeps_the_session(self):
        """m5: the remote script may still be running: never close the master on the way out."""
        self.make_key()
        run = FakeRun(self.tmp)
        session = FakeSession(run, bootstrap=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            self.bootstrap(run, session)
        self.assertTrue(session.kept)
        self.assertIn("state unknown", self.text())
        self.assertEqual([a for a in run.calls if a[-1] == "true"], [])   # no new logins after an interrupt

    def test_a_reload_failure_after_restoring_is_not_rollback_failed(self):
        """I3: exit 9 = restored on disk, the running sshd never loaded the edit: nothing to undo."""
        self.make_key()
        run = FakeRun(self.tmp)
        session = FakeSession(run, bootstrap=transport.Proc(9, "STEP lynis ok\nALLOWUSERS_RELOAD_FAILED "
                                                               "/etc/ssh/sshd_config\n", ""))
        self.assertEqual(self.bootstrap(run, session), 2)
        self.assertIn("restored /etc/ssh/sshd_config; sshd reload failed — the running sshd still has the old "
                      "config, nothing to undo", self.text())
        self.assertNotIn("ROLLBACK FAILED", self.text())
        self.assertEqual(session.names(), ["bootstrap"])
        self.assertTrue(session.closed())
        self.assertIn("hosts bootstrap | box-a | reload failed", self.log())

    def test_a_rollback_whose_reload_fails_is_reported_as_such(self):
        self.make_key()
        run = FakeRun(self.tmp, fresh_admin=(False,))
        session = FakeSession(run, bootstrap=transport.Proc(0, "ALLOWUSERS_EDITED /etc/ssh/sshd_config\nDONE\n", ""),
                              rollback=transport.Proc(9, "", ""))
        self.assertEqual(self.bootstrap(run, session), 2)
        self.assertIn("restored /etc/ssh/sshd_config on disk, but sshd did not reload", self.text())
        self.assertNotIn("ROLLBACK FAILED", self.text())
        self.assertTrue(session.kept)
        self.assertFalse((self.out / admin.BOOTSTRAP_DIR / "box-a.json").exists())
        self.assertIn("hosts bootstrap | box-a | rollback reload failed", self.log())

    def test_restore_failed_path_from_the_host_is_checked_before_it_is_printed(self):
        """m11: only an sshd config path is echoed back."""
        for out, expect in (("ALLOWUSERS_RESTORE_FAILED /etc/ssh/sshd_config.d/10-u.conf\n",
                             "restore /etc/ssh/sshd_config.d/10-u.conf from /etc/ssh/sshd_config.d/10-u.conf"),
                            ("ALLOWUSERS_RESTORE_FAILED /etc/passwd; rm -rf /\n",
                             "restore the edited sshd config file from its .sbom-audit.bak copy")):
            with self.subTest(out=out):
                self.said.clear()
                self.make_key()
                run = FakeRun(self.tmp)
                session = FakeSession(run, bootstrap=transport.Proc(8, out, ""))
                self.assertEqual(self.bootstrap(run, session), 2)
                self.assertIn(expect, self.text())
                self.assertNotIn("/etc/passwd", self.text())
                self.assertTrue(session.kept)

    def test_trust_on_first_use_prints_the_fingerprints_right_before_pinning(self):
        """m7: unknown to the user's known_hosts: the fingerprints again, at confirm, before the pin."""
        self.make_key()
        run = FakeRun(self.tmp)
        self.assertEqual(self.bootstrap(run, FakeSession(run)), 0)
        text = self.text()
        self.assertIn("trusting these host keys on first use", text)
        self.assertLess(text.index(f"ssh-ed25519 {_fp(ED)}"), text.index("pinned 2 host key(s)"))
        self.said.clear()
        run = FakeRun(self.tmp, known=f"203.0.113.10 ssh-ed25519 {ED}\n")
        self.assertEqual(self.bootstrap(run, FakeSession(run)), 0)
        self.assertNotIn("first use", self.text())                  # vouched for by known_hosts


    def test_an_exit_code_counts_only_with_its_marker_as_the_last_line(self):
        """R1: under `set -e` a bare command failure exits with its own status (usermod exits 8 when busy)."""
        for rc, out in ((8, "STEP os ok\n"),                                        # usermod: user is busy
                        (9, "STEP os ok\nSTEP user ok\n"), (3, ""), (4, "STEP os ok\n"), (5, "STEP lynis ok\n"),
                        (6, "STEP os ok\n"), (7, "STEP os ok\n"),
                        (8, "NEEDS_SUDO\n"),                                         # another code's marker
                        (8, "ALLOWUSERS_RESTORE_FAILED /etc/ssh/sshd_config\nSTEP x ok\n"),   # not the last line
                        (6, "NEEDS_SUDOERS\n")):                                     # marker prefix only
            with self.subTest(rc=rc, out=out):
                self.said.clear()
                self.make_key()
                run = FakeRun(self.tmp)
                session = FakeSession(run, bootstrap=transport.Proc(
                    rc, out, "usermod: user sbom-audit is currently used by process 4242"))
                self.assertEqual(self.bootstrap(run, session), 2)
                self.assertIn(f"bootstrap did not finish on the host (exit {rc})", self.text())
                self.assertIn("state unknown: check /etc/ssh/sshd_config", self.text())
                self.assertNotIn("ROLLBACK FAILED", self.text())
                self.assertNotIn("unsupported OS", self.text())
                self.assertNotIn("install sudo", self.text())
                self.assertEqual(session.names(), ["bootstrap"])
                self.assertTrue(session.kept)
                self.assertIn("it closes by itself after 2 h of idle time", self.text())          # r4
                self.assertTrue(self.log().rstrip().endswith("| state unknown"), self.log())
                self.assertFalse((self.out / admin.BOOTSTRAP_DIR / "box-a.json").exists())

    def test_rc_0_needs_done_as_the_last_line(self):
        self.make_key()
        run = FakeRun(self.tmp)
        session = FakeSession(run, bootstrap=transport.Proc(0, "STEP os ok\nDONE\nSTEP x ok\n", ""))
        self.assertEqual(self.bootstrap(run, session), 2)
        self.assertIn("state unknown", self.text())
        self.assertTrue(session.kept)

    def test_a_failed_rollback_says_the_kept_session_closes_after_2_h_idle(self):
        """r4"""
        self.make_key()
        run = FakeRun(self.tmp)
        session = FakeSession(run, bootstrap=transport.Proc(8, "ALLOWUSERS_RESTORE_FAILED /etc/ssh/sshd_config\n", ""))
        self.assertEqual(self.bootstrap(run, session), 2)
        self.assertIn("ROLLBACK FAILED", self.text())
        self.assertIn("it closes by itself after 2 h of idle time (ControlPersist=2h)", self.text())


class ConfirmGateTests(AdminBase):
    """M3: `bootstrap` and `unbootstrap` apply `refuse_confirm` themselves, not only through the CLI."""

    def test_wrong_confirm_or_scheduler_changes_nothing(self):
        cases = [("box-b", {}, "--confirm must equal the host name"),
                 ("box-a", {"SBOM_AUDIT_SCHEDULED": "1"}, "--confirm is refused under the scheduler")]
        for action in ("bootstrap", "unbootstrap"):
            for confirm, env, phrase in cases:
                with self.subTest(action=action, confirm=confirm, env=env), mock.patch.dict(os.environ, env):
                    self.said.clear()
                    self.make_key()
                    run = FakeRun(self.tmp)
                    session = FakeSession(run)
                    self.assertEqual(getattr(self, action)(run, session, confirm=confirm), admin.EXIT_FAILED)
                    self.assertIn(f"hosts {action} box-a: {phrase}", self.text())
                    self.assertEqual(run.calls, [])
                    self.assertEqual(session.scripts, [])
                    self.assertEqual(self.files(), [])


class RealSessionGuardTests(AdminBase):
    """The lockout guard through a real `transport.AdminSession`; only `run` is fake (it plays ssh)."""

    def fake(self, events, *, fresh_admin, rollback_rc=0):
        boot = admin.script_text("bootstrap.sh")
        test = self

        class Run(FakeRun):
            ctl = None

            def __call__(self, argv, **kw):
                argv = list(argv)
                if argv[0] == "ssh" and "-M" in argv:
                    self.ctl = argv[argv.index("-S") + 1]
                    events.append("master")
                    return _proc(0)
                if argv[0] == "ssh" and "-O" in argv:
                    test.assertEqual(argv[argv.index("-S") + 1], self.ctl)
                    events.append("exit")
                    return _proc(0)
                if argv[0] == "ssh" and "-S" in argv:
                    test.assertEqual(argv[argv.index("-S") + 1], self.ctl)
                    test.assertIn("ControlMaster=no", argv)
                    remote, data = argv[-1], kw.get("input", b"").decode()
                    if remote == "id -u":
                        return _proc(0, "0\n")
                    if data.startswith(boot):
                        events.append("bootstrap")
                        self.bootstrapped = True
                        return _proc(0, "STEP os ok\nALLOWUSERS_EDITED /etc/ssh/sshd_config\nSTEP allowusers ok\nDONE\n")
                    if data == admin.ROLLBACK_SCRIPT:
                        test.assertEqual(remote, "sh -s -- /etc/ssh/sshd_config")
                        events.append("rollback")
                        return _proc(rollback_rc)
                    raise AssertionError(f"unexpected remote command {remote}")
                if argv[0] == "ssh" and argv[-1] == "true":
                    test.assertIn("ControlPath=none", argv)
                    events.append("fresh")
                return super().__call__(argv, **kw)
        return Run(self.tmp, fresh_admin=fresh_admin)

    def test_master_stays_up_through_the_rollback_and_closes_after(self):
        self.make_key()
        events: list[str] = []
        run = self.fake(events, fresh_admin=(False, False, True))
        self.assertEqual(self.bootstrap(run, transport.AdminSession), 2)
        self.assertEqual(events, ["master", "bootstrap", "fresh", "fresh", "rollback", "fresh", "exit"])
        self.assertIn("hosts bootstrap | box-a | rolled back", self.log())
        self.assertFalse(Path(run.ctl).parent.exists())             # the control directory is gone

    def test_a_failed_rollback_never_closes_the_master(self):
        self.make_key()
        events: list[str] = []
        run = self.fake(events, fresh_admin=(False,), rollback_rc=8)
        self.assertEqual(self.bootstrap(run, transport.AdminSession), 2)
        self.addCleanup(shutil.rmtree, Path(run.ctl).parent, True)
        self.assertEqual(events, ["master", "bootstrap", "fresh", "fresh", "rollback"])   # no "exit"
        self.assertTrue(Path(run.ctl).parent.exists())              # the socket's directory stays
        self.assertIn(f"ssh -S {run.ctl} root@203.0.113.10", self.text())
        self.assertIn("ROLLBACK FAILED", self.text())

    def test_success_closes_the_master(self):
        self.make_key()
        events: list[str] = []
        run = self.fake(events, fresh_admin=(True,))
        self.assertEqual(self.bootstrap(run, transport.AdminSession), 0)
        self.assertEqual(events, ["master", "bootstrap", "fresh", "exit"])
        self.assertFalse(Path(run.ctl).parent.exists())


class UnbootstrapTests(AdminBase):
    def test_unbootstrap_removes_recorded_allowusers_entry(self):
        store.pin_host_keys(self.out, "box-a", [f"203.0.113.10 ssh-ed25519 {ED}"])
        store.pin_host_keys(self.out, "box-b", [f"198.51.100.7 ssh-ed25519 {ED_OTHER}"])
        record = self.out / admin.BOOTSTRAP_DIR / "box-a.json"
        record.parent.mkdir(parents=True)
        record.write_text(json.dumps({"allowusers_file": "/etc/ssh/sshd_config"}))
        run = FakeRun(self.tmp)
        session = FakeSession(run)
        self.assertEqual(self.unbootstrap(run, session), 0)
        self.assertEqual(session.scripts, [("unbootstrap", ["/etc/ssh/sshd_config"], None)])
        self.assertFalse(record.exists())
        pins = (self.out / store.KNOWN_HOSTS).read_text()
        self.assertNotIn("sbom-audit-box-a", pins)
        self.assertIn("sbom-audit-box-b", pins)                    # other hosts untouched
        self.assertIn("hosts unbootstrap | box-a | ok", self.log())

    def test_unbootstrap_without_record_passes_dash(self):
        run = FakeRun(self.tmp)
        session = FakeSession(run)
        self.assertEqual(self.unbootstrap(run, session), 0)
        self.assertEqual(session.scripts[0][1], ["-"])

    def test_unbootstrap_plan_writes_nothing(self):
        store.pin_host_keys(self.out, "box-a", [f"203.0.113.10 ssh-ed25519 {ED}"])
        before = (self.out / store.KNOWN_HOSTS).read_text()
        run = FakeRun(self.tmp)
        session = FakeSession(run)
        self.assertEqual(self.unbootstrap(run, session, confirm=None), 0)
        self.assertEqual(session.scripts, [])
        self.assertEqual((self.out / store.KNOWN_HOSTS).read_text(), before)
        self.assertIn("--confirm box-a", self.text())

    def test_unbootstrap_failure_keeps_local_state(self):
        store.pin_host_keys(self.out, "box-a", [f"203.0.113.10 ssh-ed25519 {ED}"])
        run = FakeRun(self.tmp)
        session = FakeSession(run, unbootstrap=transport.Proc(5, "ALLOWUSERS_FAILED sshd -t\n", ""))
        self.assertEqual(self.unbootstrap(run, session), 2)
        self.assertIn("sbom-audit-box-a", (self.out / store.KNOWN_HOSTS).read_text())

    def test_unbootstrap_without_sudo_finishes_locally_once_the_host_is_clean(self):
        store.pin_host_keys(self.out, "box-a", [f"203.0.113.10 ssh-ed25519 {ED}"])
        run = FakeRun(self.tmp)
        session = FakeSession(run, privilege=None)
        self.assertEqual(self.unbootstrap(run, session, cfg=self.cfg(admin_login="deploy@203.0.113.10")), 2)
        self.assertIn("sudo sh -s --", self.text())
        self.assertEqual(session.scripts, [])
        gone = FakeSession(run, privilege=None, gone=True)
        self.assertEqual(self.unbootstrap(run, gone, cfg=self.cfg(admin_login="deploy@203.0.113.10")), 0)
        self.assertNotIn("sbom-audit-box-a", (self.out / store.KNOWN_HOSTS).read_text())


    def test_unbootstrap_reload_failure_and_unknown_state_keep_local_state(self):
        for proc, expect, outcome, kept in (
                (transport.Proc(9, "ALLOWUSERS_RELOAD_FAILED /etc/ssh/sshd_config\n", ""),
                 "restored /etc/ssh/sshd_config; sshd reload failed — the running sshd still has the old config, "
                 "nothing to undo", "reload failed", False),
                (transport.Proc(124, "STEP sudoers ok\n", "timed out after 600 s"),
                 "state unknown: check the AllowUsers line in /etc/ssh/sshd_config", "state unknown", True),
                (transport.Proc(1, "", "ERROR must run as root"), "unbootstrap failed", "failed", False)):
            with self.subTest(outcome=outcome):
                self.said.clear()
                store.pin_host_keys(self.out, "box-a", [f"203.0.113.10 ssh-ed25519 {ED}"])
                run = FakeRun(self.tmp)
                session = FakeSession(run, unbootstrap=proc)
                self.assertEqual(self.unbootstrap(run, session), 2)
                self.assertIn(expect, self.text())
                self.assertNotIn("ROLLBACK FAILED", self.text())
                self.assertEqual(session.kept, kept)
                self.assertIn(f"hosts unbootstrap | box-a | {outcome}", self.log())
                self.assertIn("sbom-audit-box-a", (self.out / store.KNOWN_HOSTS).read_text())


    def test_unbootstrap_exit_code_without_its_marker_is_state_unknown(self):
        """R1: userdel exits 8 when sbom-audit still runs a process; that is not ROLLBACK FAILED."""
        record = self.out / admin.BOOTSTRAP_DIR / "box-a.json"
        for rc, out in ((8, "STEP sudoers ok\n"), (5, "STEP sudoers ok\n"), (9, "STEP sudoers ok\nSTEP user ok\n"),
                        (8, "ALLOWUSERS_FAILED x\n"),                     # another code's marker
                        (0, "STEP sudoers ok\nSTEP user ok\n"),          # r3: rc 0 without DONE
                        (0, "DONE\nSTEP x ok\n")):
            with self.subTest(rc=rc, out=out):
                self.said.clear()
                store.pin_host_keys(self.out, "box-a", [f"203.0.113.10 ssh-ed25519 {ED}"])
                record.parent.mkdir(parents=True, exist_ok=True)
                record.write_text(json.dumps({"allowusers_file": "/etc/ssh/sshd_config.d/10-u.conf"}))
                run = FakeRun(self.tmp)
                session = FakeSession(run, unbootstrap=transport.Proc(
                    rc, out, "userdel: user sbom-audit is currently used by process 4242"))
                self.assertEqual(self.unbootstrap(run, session), 2)
                text = self.text()
                self.assertIn(f"unbootstrap did not finish on the host (exit {rc})", text)
                self.assertIn("state unknown: check the AllowUsers line in /etc/ssh/sshd_config.d/10-u.conf by hand",
                              text)
                self.assertNotIn("ROLLBACK FAILED", text)
                self.assertNotIn("restore", text.lower())                  # never "restore the .bak" here
                self.assertIn("do not copy an old *.sbom-audit.bak over it", text)
                self.assertTrue(session.kept)
                self.assertIn("it closes by itself after 2 h of idle time", text)               # r4
                self.assertIn("sbom-audit-box-a", (self.out / store.KNOWN_HOSTS).read_text())  # pins kept
                self.assertTrue(record.exists())
                self.assertTrue(self.log().rstrip().endswith("| state unknown"), self.log())

    def test_unbootstrap_userdel_busy_reported_by_the_script_is_a_plain_failure(self):
        store.pin_host_keys(self.out, "box-a", [f"203.0.113.10 ssh-ed25519 {ED}"])
        run = FakeRun(self.tmp)
        session = FakeSession(run, unbootstrap=transport.Proc(
            1, "STEP sudoers ok\n", "ERROR userdel sbom-audit failed (exit 8): a process of sbom-audit may still run"))
        self.assertEqual(self.unbootstrap(run, session), 2)
        self.assertIn("unbootstrap failed on the host (exit 1): ERROR userdel sbom-audit failed (exit 8)", self.text())
        self.assertNotIn("state unknown", self.text())
        self.assertTrue(session.closed())
        self.assertIn("sbom-audit-box-a", (self.out / store.KNOWN_HOSTS).read_text())


class SessionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.calls = []

    def fake(self, uid="0", sudo_rc=0):
        def run(argv, **kw):
            self.calls.append((list(argv), kw))
            remote = argv[-1]
            if "-M" in argv or "-O" in argv:
                return _proc(0)
            if remote == "id -u":
                return _proc(0, uid + "\n")
            if remote == "sudo -n true":
                return _proc(sudo_rc)
            return _proc(0, "out", "err")
        return run

    def test_master_and_exit(self):
        with transport.AdminSession("root@203.0.113.10", self.dir, run=self.fake()) as s:
            pass
        master = self.calls[0][0]
        for part in ("-M", "-N", "-f", "ControlPersist=2h", "BatchMode=yes", "UpdateHostKeys=no"):
            self.assertIn(part, master)
        self.assertEqual(master[master.index("-S") + 1], str(self.dir / "m"))
        self.assertEqual(master[-1], "root@203.0.113.10")
        self.assertEqual(self.calls[-1][0][-3:], ["-O", "exit", "root@203.0.113.10"])
        self.assertIsNotNone(s)

    def test_privilege_and_sudo_prefix(self):
        for uid, sudo_rc, expect, prefix in (("0", 1, "root", "sh -s -- "), ("1000", 0, "sudo", "sudo -n sh -s -- "),
                                             ("1000", 1, None, None)):
            with self.subTest(uid=uid, sudo=sudo_rc):
                self.calls.clear()
                with transport.AdminSession("deploy@203.0.113.10", self.dir, run=self.fake(uid, sudo_rc)) as s:
                    self.assertEqual(s.privilege(), expect)
                    if prefix is None:
                        continue
                    proc = s.sh("echo hi\n", ["a b", "it's"], stdin_extra="DATA\n")
                argv, kw = self.calls[-2]
                self.assertEqual(argv[-1], prefix + "'a b' 'it'\"'\"'s'")
                self.assertEqual(argv[argv.index("-S") + 1], str(self.dir / "m"))
                self.assertIn("ControlMaster=no", argv)
                self.assertEqual(kw["input"], b"echo hi\nDATA\n")
                self.assertEqual(proc, transport.Proc(0, "out", "err"))

    def test_keep_open_skips_the_exit(self):
        with transport.AdminSession("root@203.0.113.10", self.dir, run=self.fake()) as s:
            self.assertEqual(s.keep_open(), str(self.dir / "m"))
        self.assertFalse(any("-O" in argv for argv, _ in self.calls))

    def test_master_failure_raises(self):
        def run(argv, **kw):
            return _proc(255, "", "")
        with self.assertRaises(transport.AdminError):
            with transport.AdminSession("root@203.0.113.10", self.dir, run=run):
                pass

    def test_invalid_target(self):
        for bad in ("", "-oProxyCommand=x", "root@a b", None):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                transport.AdminSession(bad, self.dir)

    def test_fresh_login_bypasses_the_master(self):
        seen = []

        def run(argv, **kw):
            seen.append(list(argv))
            return _proc(0)
        self.assertTrue(transport.fresh_login(transport.admin_argv("root@203.0.113.10"), run))
        argv = seen[0]
        self.assertEqual(argv[0], "ssh")
        self.assertEqual(argv[argv.index("ControlPath=none") - 1], "-o")
        self.assertEqual(argv[-2:], ["root@203.0.113.10", "true"])
        self.assertFalse(transport.fresh_login(["ssh", "x"], lambda a, **k: _proc(255)))

        def boom(argv, **kw):
            raise subprocess.TimeoutExpired(argv, 60)
        self.assertFalse(transport.fresh_login(["ssh", "x"], boom))


    def test_admin_logins_never_update_the_users_known_hosts(self):
        self.assertIn("UpdateHostKeys=no", transport.admin_argv("root@203.0.113.10"))
        seen = []
        transport.fresh_login(["ssh", "x"], lambda a, **k: seen.append(a) or _proc(0))
        self.assertIn("UpdateHostKeys=no", seen[0])

    def test_fresh_login_retries_once_after_a_pause(self):
        results, pauses = [255, 0], []
        self.assertTrue(transport.fresh_login(["ssh", "x"], lambda a, **k: _proc(results.pop(0)), sleep=pauses.append))
        self.assertEqual(pauses, [3])
        calls = []
        self.assertFalse(transport.fresh_login(["ssh", "x"], lambda a, **k: calls.append(a) or _proc(255),
                                               sleep=pauses.append))
        self.assertEqual(len(calls), 2)                              # exactly one retry

    def test_a_timeout_keeps_the_partial_output(self):
        def run(argv, **kw):
            if "-M" in argv or "-O" in argv or argv[-1] == "id -u":
                return _proc(0, "0\n")
            raise subprocess.TimeoutExpired(argv, 5, output=b"STEP os ok\nALLOWUSERS_EDITED /etc/ssh/sshd_config\n",
                                            stderr=b"apt: waiting for lock")
        with transport.AdminSession("root@203.0.113.10", self.dir, run=run) as s:
            proc = s.sh("echo\n", [], timeout=5)
        self.assertEqual(proc.rc, 124)
        self.assertIn("ALLOWUSERS_EDITED /etc/ssh/sshd_config", proc.out)
        self.assertIn("apt: waiting for lock", proc.err)
        self.assertIn("timed out after 5 s", proc.err)


def _function(text: str, name: str) -> str:
    m = re.search(rf"^{name}\(\) {{\n.*?^}}\n", text, re.M | re.S)
    assert m, f"{name}() not found"
    return m.group(0)


def _assignment(text: str, name: str) -> str:
    m = re.search(rf"^{name}='([^']*)'$", text, re.M)
    assert m, f"{name}= not found"
    return m.group(1)


class ScriptStaticTests(unittest.TestCase):
    BOOT = (TEMPLATES / "bootstrap.sh").read_text()
    UNBOOT = (TEMPLATES / "unbootstrap.sh").read_text()

    def code(self, text):
        return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))

    def test_bootstrap_script_static(self):
        code = self.code(self.BOOT)
        self.assertTrue(self.BOOT.startswith("#!/bin/sh\n"))
        self.assertIn("set -eu", code)
        self.assertIn("visudo -cf", code)
        self.assertIn("sshd -t", code)
        self.assertIn("systemctl reload ssh", code)
        self.assertIn("useradd --system --home-dir /var/lib/sbom-audit --shell /bin/sh", code)
        self.assertIn("usermod", code)
        self.assertIn("-p '*'", code)
        self.assertIn("DEBIAN_FRONTEND=noninteractive", code)
        self.assertIn("NEEDRESTART_SUSPEND=1", code)
        self.assertIn("apt-get install -y", code)
        self.assertIn(".sbom-audit.bak", code)
        self.assertIn(f"SUDOERS_LINE='{admin.sudoers_text().rstrip()}'", code)
        self.assertIn(f"KEY_PREFIX='{KEY_LINE[:-len(PUB)]}'", code)
        self.assertIn(f"PRF_MARKER='{admin.PRF_MARKER}'", code)
        self.assertTrue(self.BOOT.endswith(f"main \"$@\" <<'{admin.PAYLOAD_END}'\n"))

    def test_scripts_never_restart_reboot_or_touch_docker(self):
        for name, text in (("bootstrap.sh", self.BOOT), ("unbootstrap.sh", self.UNBOOT), ("rollback", admin.ROLLBACK_SCRIPT)):
            code = self.code(text)
            with self.subTest(script=name):
                self.assertNotRegex(code, r"systemctl\s+(restart|try-restart|reload-or-restart|stop|kill)")
                self.assertNotRegex(code, r"\b(service\s+\S+\s+restart|reboot|shutdown|docker)\b")
                self.assertNotIn("apt-get upgrade", code)
                self.assertNotIn("apt-get remove", code)

    def test_every_reload_is_grouped(self):
        """Decision 3: `a && b && systemctl reload ssh || systemctl reload sshd` reloads even when a or b failed."""
        for name, text in (("bootstrap.sh", self.BOOT), ("unbootstrap.sh", self.UNBOOT), ("rollback", admin.ROLLBACK_SCRIPT)):
            code = self.code(text)
            with self.subTest(script=name):
                self.assertIn("systemctl reload", code)
                for line in code.splitlines():
                    if "systemctl reload" in line:
                        self.assertIn("{ systemctl reload ssh || systemctl reload sshd; }", line, line)

    def test_unbootstrap_script_static(self):
        code = self.code(self.UNBOOT)
        self.assertIn("set -eu", code)
        self.assertIn("rm -f /etc/sudoers.d/sbom-audit", code)
        self.assertIn("userdel sbom-audit", code)
        self.assertIn("rm -rf /var/lib/sbom-audit /usr/local/lib/sbom-audit", code)
        self.assertIn("sshd -t", code)
        self.assertNotIn("lynis", code.replace("leaves lynis", ""))   # lynis stays installed

    def test_templates_end_with_newline_and_payload_is_clean(self):
        for name in ("bootstrap.sh", "unbootstrap.sh", "collect.sh", "lynis.prf"):
            self.assertTrue((TEMPLATES / name).read_text().endswith("\n"), name)
        payload = admin.bootstrap_payload()
        self.assertEqual(payload.count(f"\n{admin.PRF_MARKER}\n"), 1)
        self.assertEqual(payload.splitlines().count(admin.PAYLOAD_END), 1)

    def test_bundle_parses_in_sh(self):
        bundle = admin.script_text("bootstrap.sh") + admin.bootstrap_payload()
        proc = subprocess.run(["sh", "-n"], input=bundle.encode(), capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        proc = subprocess.run(["sh", "-n", str(TEMPLATES / "unbootstrap.sh")], capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())


class ScriptDecisionTests(unittest.TestCase):
    """The scripts' AllowUsers decision, run in the local sh: `decide <allowusers> <allowgroups> <groups> <lines>`."""
    BOOT = (TEMPLATES / "bootstrap.sh").read_text()

    def scope(self, stream: str) -> list[str]:
        prog = _assignment(self.BOOT, "SCOPE_AWK")
        proc = subprocess.run(["awk", prog], input=stream.encode(), capture_output=True, check=True)
        return proc.stdout.decode().splitlines()

    def decide(self, au: str, ag: str, groups: str, lines: str) -> str:
        funcs = "".join(_function(self.BOOT, n) for n in ("admits", "decide"))
        script = "set -eu\nAUDIT_USER=sbom-audit\n" + funcs + 'decide "$1" "$2" "$3" "$4"\n'
        proc = subprocess.run(["sh", "-c", script, "sh", au, ag, groups, lines], capture_output=True, check=True,
                              cwd=tempfile.gettempdir())
        return proc.stdout.decode().strip()

    def test_scope_awk_tracks_match_blocks(self):
        stream = ("/etc/ssh/sshd_config\t1\t# AllowUsers commented\n"
                  "/etc/ssh/sshd_config\t2\tAllowUsers root deploy\n"
                  "/etc/ssh/sshd_config\t3\t  allowgroups=admins\n"
                  "/etc/ssh/sshd_config.d/50-x.conf\t1\tMatch Address 198.51.100.0/24\n"
                  "/etc/ssh/sshd_config.d/50-x.conf\t2\t\tAllowUsers deploy\n"
                  "/etc/ssh/sshd_config\t9\tAllowUsers ops sbom-audit\r\n")
        self.assertEqual(self.scope(stream), [
            "global allowusers 0 /etc/ssh/sshd_config 2 0",
            "global allowgroups 0 /etc/ssh/sshd_config 3 0",
            "match allowusers 0 /etc/ssh/sshd_config.d/50-x.conf 2 0",
            "match allowusers 1 /etc/ssh/sshd_config 9 0",
        ])

    def test_unrestricted_or_admitted_is_unchanged(self):
        self.assertEqual(self.decide("", "", "sbom-audit", ""), "UNCHANGED")
        self.assertEqual(self.decide("root\nsbom-*", "", "sbom-audit", "global allowusers 0 /etc/ssh/sshd_config 2"),
                         "UNCHANGED")
        self.assertEqual(self.decide("*", "", "sbom-audit", "global allowusers 0 /etc/ssh/sshd_config 2"), "UNCHANGED")

    def test_single_line_is_edited(self):
        self.assertEqual(self.decide("root\ndeploy@203.0.113.5", "", "sbom-audit",
                                     "global allowusers 0 /etc/ssh/sshd_config 12"), "EDIT /etc/ssh/sshd_config 12")

    def test_multiple_lines_are_manual(self):
        lines = "global allowusers 0 /etc/ssh/sshd_config 2\nglobal allowusers 0 /etc/ssh/sshd_config.d/10-u.conf 1"
        verdict = self.decide("root\ndeploy", "", "sbom-audit", lines)
        self.assertTrue(verdict.startswith("MANUAL "), verdict)
        self.assertIn("/etc/ssh/sshd_config /etc/ssh/sshd_config.d/10-u.conf", verdict)
        self.assertTrue(self.decide("root", "", "sbom-audit", "").startswith("MANUAL "))   # set but no line found

    def test_match_block_allowusers_is_manual(self):
        """Decision 6: sshd -T does not evaluate Match blocks, so an AllowUsers inside one is never edited."""
        lines = "match allowusers 0 /etc/ssh/sshd_config.d/50-x.conf 2"
        verdict = self.decide("", "", "sbom-audit", lines)
        self.assertTrue(verdict.startswith("MANUAL "), verdict)
        self.assertIn("Match", verdict)
        self.assertIn("/etc/ssh/sshd_config.d/50-x.conf", verdict)
        # one that already names sbom-audit is fine
        self.assertEqual(self.decide("", "", "sbom-audit", "match allowusers 1 /etc/ssh/sshd_config 9"), "UNCHANGED")
        self.assertTrue(self.decide("", "", "sbom-audit", "match allowgroups 0 /etc/ssh/sshd_config 9")
                        .startswith("MANUAL "))

    def test_allowgroups_is_manual_unless_a_group_admits(self):
        """Decision 7: a user name is never appended to an AllowGroups line."""
        lines = "global allowgroups 0 /etc/ssh/sshd_config 3"
        verdict = self.decide("", "admins", "sbom-audit", lines)
        self.assertTrue(verdict.startswith("MANUAL "), verdict)
        self.assertIn("AllowGroups", verdict)
        self.assertEqual(self.decide("", "admins\nsbom-*", "sbom-audit", lines), "UNCHANGED")
        # AllowGroups admits, AllowUsers does not: the AllowUsers line is edited
        self.assertEqual(self.decide("root", "sbom-audit", "sbom-audit", lines + "\nglobal allowusers 0 /etc/ssh/sshd_config 2"),
                         "EDIT /etc/ssh/sshd_config 2")

    def test_unexpected_file_is_manual(self):
        verdict = self.decide("root", "", "sbom-audit", "global allowusers 0 /etc/ssh/other.conf 2")
        self.assertTrue(verdict.startswith("MANUAL "), verdict)

    def test_remove_awk_drops_only_the_token_outside_match(self):
        prog = _assignment((TEMPLATES / "unbootstrap.sh").read_text(), "REMOVE_AWK")
        text = ("AllowUsers root sbom-audit\nAllowUsers sbom-audit deploy\nAllowUsers sbom-audit\n"
                "PermitRootLogin no # sbom-audit\nMatch User x\n  AllowUsers x sbom-audit\n")
        proc = subprocess.run(["awk", prog], input=text.encode(), capture_output=True, check=True)
        self.assertEqual(proc.stdout.decode(), "AllowUsers root\nAllowUsers deploy\nAllowUsers sbom-audit\n"
                                               "PermitRootLogin no # sbom-audit\nMatch User x\n  AllowUsers x sbom-audit\n")


    def test_a_commented_allowusers_line_is_manual_before_anything_changes(self):
        """m2: decide() refuses it, so exit 4 still means nothing changed."""
        self.assertEqual(self.scope("/etc/ssh/sshd_config\t4\tAllowUsers root # admins only\n"),
                         ["global allowusers 0 /etc/ssh/sshd_config 4 1"])
        verdict = self.decide("root", "", "sbom-audit", "global allowusers 0 /etc/ssh/sshd_config 4 1")
        self.assertTrue(verdict.startswith("MANUAL "), verdict)
        self.assertIn("comment", verdict)

    def test_an_unresolved_include_makes_an_edit_manual(self):
        """m1: an Include nested in a sshd_config.d file (or any non-standard one) is never followed."""
        stream = ("/etc/ssh/sshd_config\t2\tAllowUsers root\n"
                  "/etc/ssh/sshd_config.d/50-x.conf\t1\tInclude (unresolved)\n")
        lines = self.scope(stream)
        self.assertEqual(lines, ["global allowusers 0 /etc/ssh/sshd_config 2 0",
                                 "match include 0 /etc/ssh/sshd_config.d/50-x.conf 1 0"])
        verdict = self.decide("root", "", "sbom-audit", "\n".join(lines))
        self.assertTrue(verdict.startswith("MANUAL "), verdict)
        self.assertIn("/etc/ssh/sshd_config.d/50-x.conf", verdict)
        # nothing to edit: the Include alone changes nothing
        self.assertEqual(self.decide("", "", "sbom-audit", "\n".join(lines[1:])), "UNCHANGED")

    def test_an_include_with_a_match_allowgroups_names_the_include(self):
        """r2: an unresolved Include is what forces the manual edit, not a Match block the plugin saw."""
        lines = ("global allowusers 0 /etc/ssh/sshd_config 2 0\n"
                 "match include 0 /etc/ssh/sshd_config.d/50-x.conf 1 0\n"
                 "match allowgroups 0 /etc/ssh/sshd_config.d/50-x.conf 3 0")
        verdict = self.decide("root", "", "sbom-audit", lines)
        self.assertTrue(verdict.startswith("MANUAL "), verdict)
        self.assertIn("after an Include outside sshd_config.d/*.conf", verdict)
        self.assertNotIn("inside a Match block", verdict)
        self.assertIn("/etc/ssh/sshd_config.d/50-x.conf", verdict)
        # an Include alone with a global AllowUsers line names the Include as the reason
        verdict = self.decide("root", "", "sbom-audit", "\n".join(lines.splitlines()[:2]))
        self.assertIn("Include", verdict)
        self.assertNotIn("Match block", verdict)

    def test_config_stream_marks_nested_includes(self):
        stream = _function(self.BOOT, "config_stream")
        self.assertEqual(stream.count('Include (unresolved)'), 2)    # the main file and the sshd_config.d files


def _one_liner(text: str, name: str) -> str:
    m = re.search(rf"^{name}\(\) {{ .*}}\n", text, re.M)
    assert m, f"{name}() not found"
    return m.group(0)


class ScriptReloadTests(unittest.TestCase):
    """I3: the sshd edit's failure paths, run in the local sh with stub `sshd` and `systemctl` on PATH."""
    BOOT = (TEMPLATES / "bootstrap.sh").read_text()
    UNBOOT = (TEMPLATES / "unbootstrap.sh").read_text()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        # sshd -t fails when SSHD_FAIL=1; systemctl fails its first $FAILS calls (each reload is `ssh || sshd`)
        stubs = {"sshd": '#!/bin/sh\n[ "${SSHD_FAIL:-0}" != 1 ]\n',
                 "systemctl": '#!/bin/sh\nn=$(cat "$STATE" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" >"$STATE"\n'
                              '[ "$n" -gt "${FAILS:-0}" ]\n'}
        for name, body in stubs.items():
            (self.bin / name).write_text(body)
            (self.bin / name).chmod(0o755)
        self.file = self.dir / "sshd_config"
        self.original = "Port 22\nAllowUsers root deploy\n"
        self.file.write_text(self.original)

    def sh(self, script, args, fails=0, sshd_fail=0):
        env = {"PATH": f"{self.bin}:/usr/bin:/bin", "STATE": str(self.dir / "count"), "FAILS": str(fails),
               "SSHD_FAIL": str(sshd_fail)}
        (self.dir / "count").unlink(missing_ok=True)
        return subprocess.run(["sh", "-c", script, "sh", *args], capture_output=True, env=env, cwd=self.dir)

    def edit(self, fails):
        funcs = _one_liner(self.BOOT, "say") + _one_liner(self.BOOT, "die") + _function(self.BOOT, "edit_allowusers")
        return self.sh("set -eu\nAUDIT_USER=sbom-audit\n" + funcs + 'edit_allowusers "$1" "$2"\n',
                       [str(self.file), "2"], fails)

    def test_edit_reloads(self):
        proc = self.edit(0)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.decode(), f"ALLOWUSERS_EDITED {self.file}\n")
        self.assertEqual(self.file.read_text(), "Port 22\nAllowUsers root deploy sbom-audit\n")

    def test_edit_reload_fails_then_the_restore_reloads(self):
        proc = self.edit(2)                                          # ssh and sshd fail once, the restore reloads
        self.assertEqual(proc.returncode, 5, proc.stderr)
        self.assertIn("ALLOWUSERS_FAILED reloading sshd failed", proc.stdout.decode())
        self.assertEqual(self.file.read_text(), self.original)

    def test_edit_reload_never_works_is_exit_9_not_restore_failed(self):
        proc = self.edit(99)
        self.assertEqual(proc.returncode, 9, proc.stderr)
        self.assertEqual(proc.stdout.decode(), f"ALLOWUSERS_RELOAD_FAILED {self.file}\n")
        self.assertEqual(self.file.read_text(), self.original)     # restored on disk

    def test_unbootstrap_reload_never_works_is_exit_9(self):
        self.file.write_text("AllowUsers root sbom-audit\n")
        funcs = (_one_liner(self.UNBOOT, "say") + _one_liner(self.UNBOOT, "die")
                 + f"REMOVE_AWK={shlex.quote(_assignment(self.UNBOOT, 'REMOVE_AWK'))}\n"
                 + _function(self.UNBOOT, "remove_token"))
        proc = self.sh("set -eu\n" + funcs + 'remove_token "$1"\n', [str(self.file)], fails=99)
        self.assertEqual(proc.returncode, 9, proc.stderr)
        self.assertIn(f"ALLOWUSERS_RELOAD_FAILED {self.file}", proc.stdout.decode())
        self.assertEqual(self.file.read_text(), "AllowUsers root sbom-audit\n")
        proc = self.sh("set -eu\n" + funcs + 'remove_token "$1"\n', [str(self.file)], fails=0)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.file.read_text(), "AllowUsers root\n")

    def test_a_busy_user_is_a_clean_error_not_a_bare_exit_8(self):
        """R1: usermod/userdel exit 8 when the user runs a process; the scripts turn that into `die` (exit 1)."""
        import re
        for script, cmd in ((self.UNBOOT, "userdel"), (self.BOOT, "usermod")):
            with self.subTest(cmd=cmd):
                m = re.search(rf"^\t*({cmd} [^\n]*\\\n\t*\|\| die [^\n]*)$", script, re.M)
                self.assertIsNotNone(m, cmd)
                stub = f'{cmd}() {{ echo "{cmd}: user sbom-audit is currently used by process 4242" >&2; return 8; }}\n'
                proc = self.sh("set -eu\n" + _one_liner(script, "say") + _one_liner(script, "die") + stub
                               + m.group(1) + "\nsay NOT_REACHED\n", [])
                self.assertEqual(proc.returncode, 1, proc.stderr)
                self.assertEqual(proc.stdout.decode(), "")
                self.assertIn(f"ERROR {cmd} sbom-audit failed (exit 8)", proc.stderr.decode())

    def test_every_user_command_is_guarded_by_die(self):
        import re
        for script in (self.BOOT, self.UNBOOT):
            for m in re.finditer(r"^\t*(useradd|usermod|userdel) [^\n]*$", script, re.M):
                tail = script[m.end():m.end() + 80]
                self.assertTrue("|| die" in m.group(0) or tail.lstrip("\\\n\t").startswith("|| die"), m.group(0))

    def rollback(self, **kw):
        head = "PATH=/usr/sbin:/usr/bin:/sbin:/bin\n"
        self.assertTrue(admin.ROLLBACK_SCRIPT.startswith(head))
        return self.sh(f"PATH={self.bin}:/usr/bin:/bin\n" + admin.ROLLBACK_SCRIPT[len(head):], [str(self.file)], **kw)

    def test_rollback_script_exit_codes(self):
        self.assertEqual(self.rollback().returncode, 8)              # no backup: nothing restored
        bak = Path(f"{self.file}{admin.BACKUP_SUFFIX}")
        for fails, sshd_fail, rc in ((0, 0, 0), (99, 0, 9), (0, 1, 8)):
            with self.subTest(fails=fails, sshd_fail=sshd_fail):
                bak.write_text(self.original)
                self.file.write_text("Port 22\nAllowUsers root deploy sbom-audit\n")
                self.assertEqual(self.rollback(fails=fails, sshd_fail=sshd_fail).returncode, rc)
                self.assertEqual(self.file.read_text(), self.original)   # cp ran in every case


class CliTests(AdminBase):
    CONFIG = """[hosts]
enabled = true
key = "{key}"

[hosts.servers."box-a"]
address = "203.0.113.10"
admin = "root@203.0.113.10"
"""

    def main(self, *argv):
        (self.out / "sbom-audit.toml").write_text(self.CONFIG.format(key=self.key))
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                rc = cli.main(["--out", str(self.out), "hosts", *argv])
            except SystemExit as exc:
                rc = exc.code
        return rc, stdout.getvalue(), stderr.getvalue()

    def test_unknown_or_invalid_host_exits_2_before_any_ssh(self):
        for sub in ("bootstrap", "unbootstrap"):
            for host in ("box-z", "-oProxyCommand=x", "box a"):
                with self.subTest(sub=sub, host=host), mock.patch("subprocess.run") as run, \
                        mock.patch.object(admin, sub) as handler:
                    rc, _, err = self.main(sub, "--", host) if host.startswith("-") else self.main(sub, host)
                    self.assertEqual(rc, 2)
                    run.assert_not_called()
                    handler.assert_not_called()

    def test_confirm_mismatch_refused_before_any_ssh(self):
        with mock.patch("subprocess.run") as run, mock.patch.object(admin, "bootstrap") as handler:
            rc, _, err = self.main("bootstrap", "box-a", "--confirm", "box-b")
        self.assertEqual(rc, 2)
        self.assertIn("must equal", err)
        run.assert_not_called()
        handler.assert_not_called()

    def test_dispatches_to_admin(self):
        for sub in ("bootstrap", "unbootstrap"):
            with self.subTest(sub=sub), mock.patch.object(admin, sub, return_value=0) as handler:
                rc, _, _ = self.main(sub, "box-a", "--confirm", "box-a")
                self.assertEqual(rc, 0)
                self.assertEqual(handler.call_args.args[1:], ("box-a", "box-a"))

    def test_a_crash_exits_2_with_the_type_only(self):
        with mock.patch.object(admin, "bootstrap", side_effect=RuntimeError("203.0.113.10 secret")):
            rc, out, err = self.main("bootstrap", "box-a")
        self.assertEqual(rc, 2)
        self.assertIn("RuntimeError", err)
        self.assertNotIn("secret", out + err)


if __name__ == "__main__":
    unittest.main()
