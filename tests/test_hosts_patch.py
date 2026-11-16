"""`hosts patch`: the plan, the saved plan, the confirmed run, the Docker hold-back and the script itself.

Nothing here opens a connection: the admin session is a fake that records the arguments of every script it is
handed and answers with canned patch.sh output; patch.sh itself runs locally against stub tools in a temp dir.
Hosts are example data (box-a, 203.0.113.0/24).
"""
import contextlib
import datetime as dt
import io
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import cli, config
from sbomaudit.hosts import admin, transport

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "templates" / "hosts" / "patch.sh"
FIXTURE = ROOT / "tests" / "fixtures" / "hosts" / "unattended-upgrade-dry-run.txt"            # a recording
FIXTURE_EMPTY = ROOT / "tests" / "fixtures" / "hosts" / "unattended-upgrade-dry-run-empty.txt"  # a recording
NONE_LINE = "No packages found that can be upgraded unattended and no pending auto-removals\n"
NOW = dt.datetime(2026, 11, 10, 12, 0, tzinfo=dt.timezone.utc)

TWO = "Packages that will be upgraded: openssl libssl3\n"
PLAN_TWO = "REBOOT_ALREADY 0\nStarting unattended upgrades script\n" + TWO + "All upgrades installed\nDONE\n"


def plan_out(names, reboot=0, extra=""):
    line = f"Packages that will be upgraded: {' '.join(names)}\n" if names else NONE_LINE
    return f"REBOOT_ALREADY {reboot}\n{extra}{line}DONE\n"


def apply_out(names, reboot=1, needrestart="NEEDRESTART-KSTA: 1\nNEEDRESTART-SVC: ssh.service\nNEEDRESTART listed\n"):
    return (f"Packages that will be upgraded: {' '.join(names)}\nAll upgrades installed\n"
            f"REBOOT_REQUIRED {reboot}\n{needrestart}DONE\n")


class FakeSession:
    """Stands in for `transport.AdminSession`: records what runs through the admin login."""

    def __init__(self, *, privilege="root", plan=None, apply=None):
        self.priv = privilege
        self.queue = {"plan": list(plan or []), "apply": list(apply or [])}
        self.calls: list[tuple[str, list[str], int]] = []
        self.kept = False

    def __call__(self, target, control_dir, run=None):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def privilege(self):
        return self.priv

    def keep_open(self):
        self.kept = True
        return "/tmp/x/m"

    def sh(self, script, args, stdin_extra=None, timeout=900):
        assert script == admin.script_text("patch.sh")
        mode = args[0]
        self.calls.append((mode, list(args), timeout))
        queue = self.queue[mode]
        result = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(result, BaseException):
            raise result
        return result

    def modes(self):
        return [c[0] for c in self.calls]


def ok(out):
    return transport.Proc(0, out, "")


class PatchBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.out = self.tmp / "security"
        self.out.mkdir()
        self.said: list[str] = []
        self.clock = NOW
        env = {k: v for k, v in os.environ.items() if k not in ("SBOM_AUDIT_READ_ONLY", "SBOM_AUDIT_SCHEDULED")}
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def cfg(self, admin_login="root@203.0.113.10"):
        servers = {"box-a": config.HostOpts(address="203.0.113.10", admin=admin_login)}
        opts = config.HostsOpts(enabled=True, timeout_minutes=10, key=self.tmp / "k", servers=servers)
        return config.Config(out=self.out, root=self.out.parent, mode="portfolio", hosts=opts)

    def say(self, text=""):
        self.said.append(str(text))

    def text(self) -> str:
        return "\n".join(self.said)

    def patch(self, session, confirm=None, include_docker=False, cfg=None):
        return admin.patch(cfg or self.cfg(), "box-a", confirm, include_docker, say=self.say, session=session,
                           now=lambda: self.clock)

    def plan_file(self) -> Path:
        return self.out / ".cache" / "hosts" / "patch-box-a.json"

    def saved(self) -> dict:
        return json.loads(self.plan_file().read_text())

    def log(self) -> str:
        path = self.out / "log.md"
        return path.read_text() if path.exists() else ""

    def save_plan(self, packages, include_docker=False, created=None):
        self.plan_file().parent.mkdir(parents=True, exist_ok=True)
        self.plan_file().write_text(json.dumps({
            "host": "box-a", "packages": sorted(packages), "include_docker": include_docker,
            "created": (created or NOW).isoformat(timespec="seconds")}))


class ParseTests(unittest.TestCase):
    def test_parse_dry_run(self):
        names = admin.parse_dry_run(FIXTURE.read_text())
        self.assertEqual(names, ["libssl3t64", "openssl", "curl", "libcurl4t64"])   # first-seen order, no :arch

    def test_parse_empty_recording(self):
        self.assertEqual(admin.parse_dry_run(FIXTURE_EMPTY.read_text()), [])

    def test_fixtures_carry_no_protocol_markers(self):
        # the script's own marker lines are added by the tests that need them, never inside a fixture
        for fixture in (FIXTURE, FIXTURE_EMPTY):
            text = fixture.read_text()
            for marker in ("REBOOT_ALREADY", "REBOOT_REQUIRED", "NEEDRESTART", "DONE"):
                self.assertNotIn(marker, text)
        self.assertEqual(FIXTURE.read_text().count("Packages that will be upgraded:"), 1)

    def test_parse_ignores_blacklist_and_checking_lines(self):
        self.assertEqual(admin.parse_dry_run("Initial blacklist: docker-ce runc\nChecking: docker-ce (x)\n"), [])

    def test_parse_empty_and_junk(self):
        self.assertEqual(admin.parse_dry_run(""), [])
        self.assertEqual(admin.parse_dry_run("Packages that will be upgraded: \n"), [])
        self.assertEqual(admin.parse_dry_run("Packages that will be upgraded: ok-pkg Bad_Name \x1b[31mx $(id) -rf\n"),
                         ["ok-pkg"])

    def test_docker_packages_are_the_briefs_list(self):
        self.assertEqual(admin.DOCKER_PACKAGES, ("docker-ce", "docker-ce-cli", "docker-ce-rootless-extras",
                                                  "docker-buildx-plugin", "docker-compose-plugin", "containerd.io",
                                                  "docker.io", "containerd", "runc"))


class PlanTests(PatchBase):
    def test_plan_lists_packages_minus_docker(self):
        session = FakeSession(plan=[ok(PLAN_TWO)])
        self.assertEqual(self.patch(session), 0)
        self.assertEqual(session.modes(), ["plan"])
        self.assertEqual(session.calls[0][1], ["plan", "0", *admin.DOCKER_PACKAGES])   # the one list, as arguments
        self.assertEqual(session.calls[0][2], 900)
        self.assertIn("openssl libssl3", self.text())
        self.assertIn("2 package(s)", self.text())
        saved = self.saved()
        self.assertEqual(saved, {"host": "box-a", "packages": ["libssl3", "openssl"], "include_docker": False,
                                 "created": "2026-11-10T12:00:00+00:00"})
        self.assertIn("| hosts patch | box-a | plan: 2 packages", self.log())

    def test_nothing_installed_without_confirm(self):
        session = FakeSession(plan=[ok(PLAN_TWO)])
        self.patch(session)
        self.assertNotIn("apply", session.modes())

    def test_hold_not_applied_fails_closed(self):
        session = FakeSession(plan=[ok(plan_out(["openssl", "docker-ce"]))])
        self.assertEqual(self.patch(session), 2)
        self.assertIn("Docker hold-back did not apply; nothing installed", self.text())
        self.assertNotIn("apply", session.modes())
        self.assertFalse(self.plan_file().exists())
        self.assertIn("aborted: docker hold-back did not apply", self.log())

    def test_hold_not_applied_also_on_confirm(self):
        self.save_plan(["openssl", "containerd.io"])
        session = FakeSession(plan=[ok(plan_out(["openssl", "containerd.io"]))])
        self.assertEqual(self.patch(session, "box-a"), 2)
        self.assertEqual(session.modes(), ["plan"])

    def test_include_docker_allows_docker(self):
        session = FakeSession(plan=[ok(plan_out(["openssl", "docker-ce"]))])
        self.assertEqual(self.patch(session, include_docker=True), 0)
        self.assertEqual(session.calls[0][1][:2], ["plan", "1"])
        self.assertEqual(self.saved()["include_docker"], True)
        self.assertEqual(self.saved()["packages"], ["docker-ce", "openssl"])
        self.assertIn("Docker packages included", self.text())

    def test_nothing_to_install_saves_no_plan(self):
        self.save_plan(["openssl"])                 # a stale plan goes away
        session = FakeSession(plan=[ok("REBOOT_ALREADY 0\n" + FIXTURE_EMPTY.read_text() + "DONE\n")])
        self.assertEqual(self.patch(session), 0)
        self.assertIn("nothing to install", self.text())
        self.assertFalse(self.plan_file().exists())

    def test_recorded_dry_run_makes_a_plan(self):
        session = FakeSession(plan=[ok("REBOOT_ALREADY 0\n" + FIXTURE.read_text() + "DONE\n")])
        self.assertEqual(self.patch(session), 0)
        self.assertEqual(self.saved()["packages"], ["curl", "libcurl4t64", "libssl3t64", "openssl"])

    def test_empty_parse_without_the_none_line_is_state_unknown(self):
        # u-u logs nothing on a day outside its Update-Days: an empty parse alone is not "nothing to install"
        silent = "REBOOT_ALREADY 0\nStarting unattended upgrades script\nInitial whitelist (not strict):\nDONE\n"
        for label, out in {"silent run": silent, "only the markers": "REBOOT_ALREADY 0\nDONE\n"}.items():
            with self.subTest(label):
                self.said.clear()
                self.save_plan(["openssl"])
                self.assertEqual(self.patch(FakeSession(plan=[ok(out)])), 2)
                self.assertIn("state unknown", self.text())
                self.assertIn("nothing was installed", self.text())
                self.assertNotIn("nothing to install", self.text())
                if out is silent:
                    self.assertIn("Starting unattended upgrades script", self.text())   # the output is shown
                self.assertIn("state unknown", self.log())

    def test_empty_parse_without_none_line_on_confirm_installs_nothing(self):
        self.save_plan(["openssl"])
        session = FakeSession(plan=[ok("REBOOT_ALREADY 0\nStarting unattended upgrades script\nDONE\n")],
                              apply=[ok(apply_out(["openssl"]))])
        self.assertEqual(self.patch(session, "box-a"), 2)
        self.assertEqual(session.modes(), ["plan"])

    def test_docker_family_not_in_the_hold_back_list_aborts(self):
        for name in ("docker-compose-v2", "docker-model-plugin", "containerd-shim", "runc-extra", "docker-ce-foo"):
            with self.subTest(name):
                self.said.clear()
                session = FakeSession(plan=[ok(plan_out(["openssl", name]))])
                self.assertEqual(self.patch(session), 2)
                self.assertIn(f"{name} is Docker-related but not in the hold-back list; nothing installed", self.text())
                self.assertEqual(session.modes(), ["plan"])
                self.assertFalse(self.plan_file().exists())
                self.assertIn("is Docker-related but not in the hold-back list", self.log())

    def test_docker_family_not_in_the_list_aborts_on_confirm_too(self):
        self.save_plan(["openssl", "docker-compose-v2"])
        session = FakeSession(plan=[ok(plan_out(["openssl", "docker-compose-v2"]))],
                              apply=[ok(apply_out(["openssl"]))])
        self.assertEqual(self.patch(session, "box-a"), 2)
        self.assertEqual(session.modes(), ["plan"])

    def test_docker_family_is_allowed_with_include_docker(self):
        session = FakeSession(plan=[ok(plan_out(["openssl", "docker-compose-v2"]))])
        self.assertEqual(self.patch(session, include_docker=True), 0)
        self.assertEqual(self.saved()["packages"], ["docker-compose-v2", "openssl"])

    def test_plan_reports_reboot_already_pending(self):
        session = FakeSession(plan=[ok(plan_out(["openssl"], reboot=1))])
        self.patch(session)
        self.assertIn("reboot-required already pending: yes", self.text())

    def test_no_privilege_prints_the_command_by_hand(self):
        session = FakeSession(privilege=None)
        self.assertEqual(self.patch(session, cfg=self.cfg("deploy@203.0.113.10")), 2)
        self.assertEqual(session.calls, [])
        text = self.text()
        self.assertIn("ssh -t deploy@203.0.113.10 'sudo sh -s -- plan 0 docker-ce", text)
        self.assertIn(f"< {SCRIPT}", text)
        self.assertIn("needs manual run", self.log())

    def test_no_admin_login(self):
        session = FakeSession()
        self.assertEqual(self.patch(session, cfg=self.cfg(admin_login=None)), 2)
        self.assertEqual(session.calls, [])

    def test_plan_error_marker(self):
        session = FakeSession(plan=[transport.Proc(1, "REBOOT_ALREADY 0\n", "ERROR apt is busy, retry later\n")])
        self.assertEqual(self.patch(session), 2)
        self.assertIn("apt is busy, retry later", self.text())
        self.assertIn("nothing was installed", self.text())
        self.assertFalse(self.plan_file().exists())

    def test_plan_unknown_outcomes_are_not_success(self):
        cases = {"timeout": transport.Proc(124, "REBOOT_ALREADY 0\nChecking: x\n", "timed out after 900 s"),
                 "dropped ssh": transport.Proc(255, "", "Connection reset"),
                 "no marker": transport.Proc(0, TWO, ""),
                 "rc 1 without ERROR": transport.Proc(1, TWO + "DONE\n", ""),
                 "ERROR with rc 0": transport.Proc(0, TWO, "ERROR x")}
        for label, proc in cases.items():
            with self.subTest(label):
                self.said.clear()
                self.plan_file().unlink(missing_ok=True)
                self.assertEqual(self.patch(FakeSession(plan=[proc])), 2)
                self.assertIn("state unknown", self.text())
                self.assertIn("nothing was installed", self.text())
                self.assertFalse(self.plan_file().exists())
        self.assertIn("state unknown", self.log())

    def test_admin_login_failure(self):
        def broken(*a, **k):
            raise transport.AdminError("admin login failed (exit 255)")
        self.assertEqual(self.patch(broken), 2)
        self.assertIn("admin login failed", self.log())


class ConfirmTests(PatchBase):
    def test_confirm_applies_the_saved_plan(self):
        self.save_plan(["openssl", "libssl3"])
        session = FakeSession(plan=[ok(PLAN_TWO)], apply=[ok(apply_out(["openssl", "libssl3"]))])
        self.assertEqual(self.patch(session, "box-a"), 0)
        self.assertEqual(session.modes(), ["plan", "apply"])
        # the confirmed list travels as arguments after `--`: the script pins the upgrade to exactly these
        self.assertEqual(session.calls[1][1], ["apply", "0", *admin.DOCKER_PACKAGES, "--", "openssl", "libssl3"])
        self.assertEqual(session.calls[1][2], 3600)
        self.assertIn("2 packages installed", self.log())
        self.assertFalse(self.plan_file().exists())          # a confirmation cannot be replayed

    def test_confirm_refused_under_scheduler(self):
        self.save_plan(["openssl", "libssl3"])
        session = FakeSession(plan=[ok(PLAN_TWO)], apply=[ok(apply_out(["openssl"]))])
        with mock.patch.dict(os.environ, {"SBOM_AUDIT_SCHEDULED": "1"}):
            self.assertEqual(self.patch(session, "box-a"), 2)
        self.assertEqual(session.calls, [])
        self.assertIn("refused under the scheduler", self.text())
        self.assertTrue(self.plan_file().exists())

    def test_confirm_must_equal_host(self):
        session = FakeSession(plan=[ok(PLAN_TWO)])
        for bad in ("Box-A", "box-a ", "other"):
            with self.subTest(bad=bad):
                self.assertEqual(self.patch(session, bad), 2)
        self.assertEqual(session.calls, [])

    def test_plan_changed_requires_new_confirmation(self):
        self.save_plan(["openssl"])
        session = FakeSession(plan=[ok(PLAN_TWO)], apply=[ok(apply_out(["openssl", "libssl3"]))])
        self.assertEqual(self.patch(session, "box-a"), 2)
        self.assertEqual(session.modes(), ["plan"])
        self.assertIn("package list changed", self.text())
        self.assertIn("openssl libssl3", self.text())
        self.assertEqual(self.saved()["packages"], ["openssl"])    # the old plan is not silently replaced
        self.assertIn("aborted: plan changed", self.log())

    def test_no_saved_plan_requires_a_plan_first(self):
        session = FakeSession(plan=[ok(PLAN_TWO)], apply=[ok(apply_out(["openssl"]))])
        self.assertEqual(self.patch(session, "box-a"), 2)
        self.assertEqual(session.modes(), ["plan"])
        self.assertIn("no saved plan", self.text())

    def test_saved_plan_expires_after_24_hours(self):
        self.save_plan(["openssl", "libssl3"], created=NOW - dt.timedelta(hours=24, seconds=1))
        session = FakeSession(plan=[ok(PLAN_TWO)], apply=[ok(apply_out(["openssl"]))])
        self.assertEqual(self.patch(session, "box-a"), 2)
        self.assertEqual(session.modes(), ["plan"])
        self.assertIn("older than 24 hours", self.text())
        self.save_plan(["openssl", "libssl3"], created=NOW - dt.timedelta(hours=23, minutes=59))
        session = FakeSession(plan=[ok(PLAN_TWO)], apply=[ok(apply_out(["openssl", "libssl3"]))])
        self.assertEqual(self.patch(session, "box-a"), 0)

    def test_saved_plan_from_the_future_has_its_own_message(self):
        self.save_plan(["openssl", "libssl3"], created=NOW + dt.timedelta(hours=1))
        session = FakeSession(plan=[ok(PLAN_TWO)], apply=[ok(apply_out(["openssl"]))])
        self.assertEqual(self.patch(session, "box-a"), 2)
        self.assertIn("saved plan has a timestamp in the future", self.text())
        self.assertNotIn("apply", session.modes())

    def test_saved_plan_for_another_host_is_not_trusted(self):
        self.save_plan(["openssl", "libssl3"])
        doc = self.saved()
        doc["host"] = "box-b"
        self.plan_file().write_text(json.dumps(doc))
        session = FakeSession(plan=[ok(PLAN_TWO)], apply=[ok(apply_out(["openssl"]))])
        self.assertEqual(self.patch(session, "box-a"), 2)
        self.assertIn("no saved plan", self.text())
        self.assertNotIn("apply", session.modes())

    def test_saved_plan_with_garbage_is_not_trusted(self):
        for created in ("yesterday", "2026-11-10T12:00:00"):
            with self.subTest(created=created):
                self.plan_file().parent.mkdir(parents=True, exist_ok=True)
                self.plan_file().write_text(json.dumps({"host": "box-a", "packages": ["libssl3", "openssl"],
                                                        "include_docker": False, "created": created}))
                session = FakeSession(plan=[ok(PLAN_TWO)], apply=[ok(apply_out(["openssl"]))])
                self.assertEqual(self.patch(session, "box-a"), 2)
                self.assertNotIn("apply", session.modes())
        self.plan_file().write_text("{not json")
        self.assertEqual(self.patch(FakeSession(plan=[ok(PLAN_TWO)]), "box-a"), 2)

    def test_include_docker_change_requires_new_confirmation(self):
        self.save_plan(["openssl", "libssl3"], include_docker=False)
        session = FakeSession(plan=[ok(PLAN_TWO)], apply=[ok(apply_out(["openssl"]))])
        self.assertEqual(self.patch(session, "box-a", include_docker=True), 2)
        self.assertNotIn("apply", session.modes())
        self.assertIn("different --include-docker", self.text())

    def test_confirm_with_nothing_left_to_install(self):
        self.save_plan(["openssl"])
        session = FakeSession(plan=[ok(plan_out([]))])
        self.assertEqual(self.patch(session, "box-a"), 0)
        self.assertEqual(session.modes(), ["plan"])
        self.assertFalse(self.plan_file().exists())

    def test_confirm_without_privilege_prints_the_apply_command_with_the_saved_list(self):
        self.save_plan(["openssl", "libssl3"])
        session = FakeSession(privilege=None)
        self.assertEqual(self.patch(session, "box-a", cfg=self.cfg("deploy@203.0.113.10")), 2)
        self.assertIn("sudo sh -s -- apply 0 docker-ce", self.text())
        self.assertIn("-- libssl3 openssl'", self.text())
        self.assertEqual(session.calls, [])

    def test_confirm_without_privilege_and_without_saved_plan_prints_the_plan_command(self):
        session = FakeSession(privilege=None)
        self.assertEqual(self.patch(session, "box-a", cfg=self.cfg("deploy@203.0.113.10")), 2)
        self.assertIn("sudo sh -s -- plan 0 docker-ce", self.text())
        self.assertNotIn(" apply ", self.text())

    def test_confirm_without_privilege_refuses_a_stale_or_mismatched_saved_plan(self):
        cases = [
            ("older than 24 hours", dict(created=NOW - dt.timedelta(hours=24, seconds=1)), False),
            ("timestamp in the future", dict(created=NOW + dt.timedelta(hours=1)), False),
            ("different --include-docker", dict(include_docker=False), True),
            ("different --include-docker", dict(include_docker=True), False),
        ]
        for why, plan, include_docker in cases:
            with self.subTest(why=why, include_docker=include_docker):
                self.said.clear()
                self.save_plan(["openssl", "libssl3"], **plan)
                session = FakeSession(privilege=None)
                self.assertEqual(self.patch(session, "box-a", include_docker=include_docker,
                                            cfg=self.cfg("deploy@203.0.113.10")), 2)
                self.assertIn("no install command: ", self.text())
                self.assertIn(why, self.text())
                self.assertIn("sudo sh -s -- plan ", self.text())
                self.assertNotIn(" apply ", self.text())
                self.assertNotIn("libssl3 openssl", self.text())
                self.assertEqual(session.calls, [])

    def test_confirm_without_privilege_accepts_a_fresh_plan_with_the_same_docker_flag(self):
        self.save_plan(["openssl"], include_docker=True, created=NOW - dt.timedelta(hours=23, minutes=59))
        session = FakeSession(privilege=None)
        self.assertEqual(self.patch(session, "box-a", include_docker=True, cfg=self.cfg("deploy@203.0.113.10")), 2)
        self.assertIn("sudo sh -s -- apply 1 docker-ce", self.text())
        self.assertNotIn("no install command", self.text())

    def test_apply_reports_reboot_and_needrestart(self):
        self.save_plan(["libssl3", "openssl"])
        session = FakeSession(plan=[ok(PLAN_TWO)], apply=[ok(apply_out(
            ["openssl", "libssl3"], reboot=1,
            needrestart="NEEDRESTART-VER: 3.6\nNEEDRESTART-KSTA: 3\nNEEDRESTART-SVC: ssh.service\n"
                        "NEEDRESTART-SVC: cron.service\nNEEDRESTART-SVC: bad\x1b[31m name\nNEEDRESTART listed\n"))])
        self.assertEqual(self.patch(session, "box-a"), 0)
        text = self.text()
        self.assertIn("openssl libssl3", text)
        self.assertIn("reboot-required: yes", text)
        self.assertIn("ssh.service", text)
        self.assertIn("cron.service", text)
        self.assertIn("a kernel version upgrade is pending", text)
        self.assertIn("(unprintable name)", text)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("no service or container was restarted", text)
        self.assertIn("sbom-audit rebooted and restarted nothing", text)
        self.assertIn("suppressed needrestart's automatic restarts", text)
        self.assertIn("maintainer scripts may have restarted their own services", text)

    def test_needrestart_missing_is_unknown(self):
        self.save_plan(["libssl3", "openssl"])
        session = FakeSession(plan=[ok(PLAN_TWO)], apply=[ok(apply_out(
            ["openssl", "libssl3"], reboot=0, needrestart="NEEDRESTART unknown\n"))])
        self.assertEqual(self.patch(session, "box-a"), 0)
        self.assertIn("reboot-required: no", self.text())
        self.assertIn("needrestart: not available on the host", self.text())

    def test_no_service_needs_restart(self):
        self.save_plan(["libssl3", "openssl"])
        session = FakeSession(plan=[ok(PLAN_TWO)], apply=[ok(apply_out(
            ["openssl", "libssl3"], needrestart="NEEDRESTART-KSTA: 1\nNEEDRESTART listed\n"))])
        self.patch(session, "box-a")
        self.assertIn("no service needs a restart", self.text())

    def test_apply_unknown_outcomes(self):
        for label, proc in {"timeout": transport.Proc(124, "Packages that will be upgraded: openssl\n", "timed out"),
                            "dropped": transport.Proc(255, "", ""),
                            "no marker": transport.Proc(0, apply_out(["openssl"]).replace("DONE\n", ""), "")}.items():
            with self.subTest(label):
                self.said.clear()
                self.save_plan(["libssl3", "openssl"])
                session = FakeSession(plan=[ok(PLAN_TWO)], apply=[proc])
                self.assertEqual(self.patch(session, "box-a"), 2)
                text = self.text()
                self.assertIn("state unknown", text)
                self.assertIn("/var/log/unattended-upgrades/", text)
                self.assertIn("apt list --upgradable", text)
                self.assertNotIn("package(s) installed", text)
                self.assertFalse(self.plan_file().exists())      # spent: no replay after a half run
        self.assertIn("state unknown", self.log())

    def test_installed_outside_the_confirmed_list_is_loud(self):
        self.save_plan(["libssl3", "openssl"])
        session = FakeSession(plan=[ok(PLAN_TWO)], apply=[ok(apply_out(["openssl", "libssl3", "curl"]))])
        self.assertEqual(self.patch(session, "box-a"), 1)
        self.assertIn("WARNING: installed outside the confirmed plan: curl", self.text())
        self.assertIn("installed outside the plan: curl", self.log())

    def test_confirmed_but_skipped_packages_are_reported(self):
        self.save_plan(["libssl3", "openssl"])
        session = FakeSession(plan=[ok(PLAN_TWO)], apply=[ok(apply_out(["openssl"]))])
        self.assertEqual(self.patch(session, "box-a"), 0)
        self.assertIn("skipped (will show in the next plan): libssl3", self.text())
        self.assertIn("1 packages installed; skipped: libssl3", self.log())

    def test_apply_lock_says_nothing_was_installed(self):
        self.save_plan(["libssl3", "openssl"])
        lock = transport.Proc(1, "Lock could not be acquired (another package manager running?)\n",
                              "ERROR unattended-upgrade failed (exit 1)\n")
        session = FakeSession(plan=[ok(PLAN_TWO)], apply=[lock])
        self.assertEqual(self.patch(session, "box-a"), 2)
        self.assertIn("nothing was installed", self.text())
        self.assertIn("apt is busy", self.text())
        self.assertNotIn("partly installed", self.text())
        self.assertIn("aborted: apt busy", self.log())

    def test_apply_settings_not_in_force_says_nothing_was_installed(self):
        for reason in ("hold-back not in force for docker-ce", "confirmed-list pin not in force for openssl",
                       "strict whitelist not in force", "Remove-Unused-Dependencies=false not in force"):
            with self.subTest(reason):
                self.said.clear()
                self.save_plan(["libssl3", "openssl"])
                session = FakeSession(plan=[ok(PLAN_TWO)], apply=[transport.Proc(1, "", f"ERROR {reason}\n")])
                self.assertEqual(self.patch(session, "box-a"), 2)
                self.assertIn("nothing was installed", self.text())
                self.assertIn(reason, self.text())
                self.assertNotIn("partly installed", self.text())

    def test_apply_error_marker(self):
        self.save_plan(["libssl3", "openssl"])
        session = FakeSession(plan=[ok(PLAN_TWO)], apply=[transport.Proc(1, "Packages that will be upgraded: x\n",
                                                                       "ERROR unattended-upgrade failed (exit 1)\n")])
        self.assertEqual(self.patch(session, "box-a"), 2)
        self.assertIn("unattended-upgrade failed (exit 1)", self.text())
        self.assertIn("apt list --upgradable", self.text())
        self.assertFalse(self.plan_file().exists())

    def test_hold_back_failed_after_install_is_loud(self):
        self.save_plan(["libssl3", "openssl"])
        session = FakeSession(plan=[ok(PLAN_TWO)], apply=[ok(apply_out(["openssl", "docker-ce", "runc"]))])
        self.assertEqual(self.patch(session, "box-a"), 1)
        self.assertIn("hold-back failed after install: docker-ce, runc", self.text())
        self.assertIn("hold-back failed after install: docker-ce, runc", self.log())
        self.assertFalse(self.plan_file().exists())

    def test_include_docker_apply_has_no_hold_back_warning(self):
        self.save_plan(["docker-ce", "openssl"], include_docker=True)
        session = FakeSession(plan=[ok(plan_out(["openssl", "docker-ce"]))],
                              apply=[ok(apply_out(["openssl", "docker-ce"]))])
        self.assertEqual(self.patch(session, "box-a", include_docker=True), 0)
        self.assertEqual(session.calls[1][1][:2], ["apply", "1"])
        self.assertEqual(session.calls[1][1][-3:], ["--", "openssl", "docker-ce"])
        self.assertNotIn("hold-back failed", self.text())

    def test_interrupt_during_apply_still_spends_the_plan(self):
        self.save_plan(["libssl3", "openssl"])
        session = FakeSession(plan=[ok(PLAN_TWO)], apply=[KeyboardInterrupt()])
        with self.assertRaises(KeyboardInterrupt):
            self.patch(session, "box-a")
        self.assertFalse(self.plan_file().exists())
        text = self.text()
        self.assertIn("state unknown", text)
        self.assertIn("/var/log/unattended-upgrades/", text)
        self.assertIn("apt list --upgradable", text)
        self.assertEqual(self.log().count("interrupted: state unknown"), 1)
        self.assertEqual(self.log().count("| hosts patch |"), 1)


class CliTests(PatchBase):
    def setUp(self):
        super().setUp()
        (self.out / "sbom-audit.toml").write_text(
            '[hosts]\nenabled = true\n[hosts.servers."box-a"]\naddress = "203.0.113.10"\nadmin = "root@203.0.113.10"\n')

    def main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(["hosts", *argv, "--out", str(self.out)])
        return rc, out.getvalue(), err.getvalue()

    def test_patch_flags_reach_admin(self):
        with mock.patch("sbomaudit.hosts.admin.patch", return_value=0) as patch:
            rc, _, _ = self.main("patch", "box-a", "--confirm", "box-a", "--include-docker")
        self.assertEqual(rc, 0)
        self.assertEqual(patch.call_args.args[1:], ("box-a", "box-a", True))
        with mock.patch("sbomaudit.hosts.admin.patch", return_value=0) as patch:
            self.main("patch", "box-a")
        self.assertEqual(patch.call_args.args[1:], ("box-a", None, False))

    def test_confirm_refused_under_scheduler_before_any_ssh(self):
        with mock.patch.dict(os.environ, {"SBOM_AUDIT_SCHEDULED": "1"}), \
                mock.patch("sbomaudit.hosts.admin.patch") as patch, mock.patch("subprocess.run") as run:
            rc, _, err = self.main("patch", "box-a", "--confirm", "box-a")
        self.assertEqual(rc, 2)
        self.assertIn("refused under the scheduler", err)
        patch.assert_not_called()
        run.assert_not_called()

    def test_unknown_host_and_wrong_confirm(self):
        with mock.patch("sbomaudit.hosts.admin.patch") as patch:
            self.assertEqual(self.main("patch", "box-z")[0], 2)
            self.assertEqual(self.main("patch", "box-a", "--confirm", "box-b")[0], 2)
            self.assertEqual(self.main("patch", "../x")[0], 2)
        patch.assert_not_called()

    def test_read_only_exits_5(self):
        with mock.patch.dict(os.environ, {"SBOM_AUDIT_READ_ONLY": "1"}), mock.patch("sbomaudit.hosts.admin.patch") as patch:
            self.assertEqual(self.main("patch", "box-a")[0], 5)
        patch.assert_not_called()


class ScriptStaticTests(unittest.TestCase):
    def test_patch_script_static(self):
        text = SCRIPT.read_text()
        # the one allowed literal: the path of the marker file that apt itself writes
        self.assertEqual(text.count("/var/run/reboot-required"), 1)
        text = text.replace("/var/run/reboot-required", "")
        for forbidden in ("docker ", "compose", "reboot", "shutdown", "systemctl restart"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)
        self.assertIn("NEEDRESTART_SUSPEND=1", text)
        self.assertIn("set -eu", text)
        self.assertIn("needrestart -b -r l", text)
        self.assertNotIn("#include", text)

    def test_every_tool_call_reads_dev_null(self):
        text = SCRIPT.read_text()
        for tool in ("apt-get update", "unattended-upgrade --dry-run", "unattended-upgrade -v", "needrestart -b -r l",
                     "apt-config dump"):
            calls = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#") and "command -v" not in ln
                     and tool in re.sub(r'"[^"]*"', "", ln)]       # a command, not a word inside a message
            self.assertTrue(calls, tool)
            for ln in calls:
                self.assertIn("</dev/null", ln, ln)

    def test_script_is_valid_sh(self):
        self.assertEqual(subprocess.run(["sh", "-n", str(SCRIPT)]).returncode, 0)


class ScriptRunTests(unittest.TestCase):
    """patch.sh run locally: /run, the reboot marker and the root check are redirected; apt-get, apt-config,
    unattended-upgrade and needrestart are stubs that log how they were called, which APT_CONFIG they saw and how
    many bytes of stdin they could read. The apt-config stub dumps the config file the way `apt-config dump` does."""

    DUMP = ("sed -E 's/^([A-Za-z:-]+) \\{ (\"[^\"]*\";) \\};$/\\1:: \\2/' \"$APT_CONFIG\"")

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.calls = self.tmp / "calls.log"
        self.stdin_log = self.tmp / "stdin.log"
        text = SCRIPT.read_text()
        text = text.replace("/run/sbom-audit", str(self.tmp / "run"))
        text = text.replace("MARK=/var/run/reboot-required", f"MARK={self.tmp}/marker")
        text = text.replace("PATH=/usr/sbin:/usr/bin:/sbin:/bin", f"PATH={self.bin}:/usr/bin:/bin")
        text = text.replace('[ "$(id -u)" = 0 ] || die "must run as root"', "true")
        self.script = self.tmp / "patch.sh"
        self.script.write_text(text)
        self.conf_copy = self.tmp / "conf.copy"

    def stub(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + f'echo "{name}:$(cat | wc -c | tr -d " ")" >> {self.stdin_log}\n' + body)
        path.chmod(0o755)

    def stubs(self, *, apt_rc=0, apt_msg="", uu_rc=0, uu_out="Packages that will be upgraded: openssl",
              needrestart=True, nr_rc=0, dump="all", dump_rc=0):
        log = self.calls
        self.stub("apt-get", f'echo "apt-get $*" >> {log}\necho "{apt_msg}" >&2\n[ {apt_rc} -eq 0 ] || echo "{apt_msg}"\nexit {apt_rc}\n')
        self.stub("unattended-upgrade",
                  f'echo "uu $* NEEDRESTART_SUSPEND=$NEEDRESTART_SUSPEND APT_CONFIG=$APT_CONFIG" >> {log}\n'
                  f'[ -z "$APT_CONFIG" ] || cp "$APT_CONFIG" {self.conf_copy}\n'
                  f'echo "{uu_out}"\nexit {uu_rc}\n')
        drop = {"all": "cat", "no-blacklist": "grep -v Package-Blacklist", "no-whitelist": "grep -v 'Package-Whitelist::'",
                "no-strict": "grep -v Whitelist-Strict", "no-remove": "grep -v 'Remove-Unused-Dependencies'",
                "remove-true": "sed 's/Remove-New-Unused-Dependencies \"false\"/Remove-New-Unused-Dependencies \"true\"/'",
                "empty": "grep -v ."}[dump]
        self.stub("apt-config", f'echo "apt-config $*" >> {log}\n[ "$1" = dump ] || exit 3\n'
                                f'[ {dump_rc} -eq 0 ] || exit {dump_rc}\n{self.DUMP} | {drop}\n')
        if needrestart:
            self.stub("needrestart", f'echo "needrestart $*" >> {log}\n'
                                     'echo "NEEDRESTART-VER: 3.6"\necho "NEEDRESTART-KSTA: 1"\n'
                                     f'echo "NEEDRESTART-SVC: ssh.service"\nexit {nr_rc}\n')

    def run_script(self, *args):
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.tmp)}
        return subprocess.run(["sh", str(self.script), *args], capture_output=True, text=True, env=env, timeout=60,
                              input="STDIN-THAT-MUST-NOT-BE-READ\n")

    def conf_files(self):
        run = self.tmp / "run"
        return sorted(run.glob("apt-*.conf")) if run.exists() else []

    def test_plan_with_hold_back(self):
        self.stubs()
        proc = self.run_script("plan", "0", "docker-ce", "containerd.io", "runc")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = proc.stdout.splitlines()
        self.assertEqual(lines[0], "REBOOT_ALREADY 0")
        self.assertEqual(lines[-1], "DONE")
        self.assertIn("Packages that will be upgraded: openssl", lines)
        calls = self.calls.read_text()
        self.assertIn("apt-get update -q", calls)
        self.assertIn("uu --dry-run -v NEEDRESTART_SUSPEND=1", calls)
        self.assertNotIn("needrestart", calls)
        conf = self.conf_copy.read_text()
        for name in ("docker-ce", "containerd.io", "runc"):
            self.assertIn(f'Unattended-Upgrade::Package-Blacklist {{ "{name}"; }};', conf)
        self.assertNotIn("Package-Whitelist", conf)          # the plan looks at everything that is pending
        self.assertNotIn("#include", conf)
        self.assertEqual(self.conf_files(), [])               # removed on exit

    def test_config_is_per_run_and_removed(self):
        self.stubs()
        self.run_script("plan", "0", "docker-ce")
        path = re.search(r"APT_CONFIG=(\S+)", self.calls.read_text()).group(1)
        self.assertRegex(path, r"/run/apt-\d+\.conf$")
        self.assertFalse(Path(path).exists())
        self.assertEqual(self.conf_files(), [])

    def test_config_is_removed_when_the_run_fails(self):
        self.stubs(uu_rc=1)
        self.run_script("apply", "0", "docker-ce", "--", "openssl")
        self.assertEqual(self.conf_files(), [])

    def test_remove_settings_are_off_in_plan_and_apply(self):
        self.stubs()
        for args in (("plan", "0", "docker-ce"), ("plan", "1"), ("apply", "0", "docker-ce", "--", "openssl"),
                     ("apply", "1", "--", "openssl")):
            with self.subTest(args=args):
                self.assertEqual(self.run_script(*args).returncode, 0)
                conf = self.conf_copy.read_text()
                for key in ("Remove-Unused-Kernel-Packages", "Remove-New-Unused-Dependencies",
                            "Remove-Unused-Dependencies"):
                    self.assertIn(f'Unattended-Upgrade::{key} "false";', conf)

    def test_plan_include_docker_has_no_blacklist(self):
        self.stubs()
        proc = self.run_script("plan", "1")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("Package-Blacklist", self.conf_copy.read_text())

    def test_apply_pins_to_the_confirmed_list(self):
        self.stubs()
        proc = self.run_script("apply", "0", "docker-ce", "--", "openssl", "containerd.io", "libstdc++6")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        conf = self.conf_copy.read_text()
        self.assertIn('Unattended-Upgrade::Package-Whitelist { "^openssl$"; };', conf)
        self.assertIn('Unattended-Upgrade::Package-Whitelist { "^containerd[.]io$"; };', conf)
        self.assertIn('Unattended-Upgrade::Package-Whitelist { "^libstdc[+][+]6$"; };', conf)
        self.assertIn('Unattended-Upgrade::Package-Whitelist-Strict "true";', conf)
        self.assertIn('Unattended-Upgrade::Package-Blacklist { "docker-ce"; };', conf)

    def test_apply_reports_state(self):
        self.stubs()
        proc = self.run_script("apply", "0", "docker-ce", "--", "openssl")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = proc.stdout.splitlines()
        self.assertEqual(lines[-1], "DONE")
        self.assertIn("REBOOT_REQUIRED 0", lines)
        self.assertIn("NEEDRESTART-SVC: ssh.service", lines)
        self.assertIn("NEEDRESTART-KSTA: 1", lines)
        self.assertNotIn("NEEDRESTART-VER: 3.6", lines)
        self.assertIn("NEEDRESTART listed", lines)
        calls = self.calls.read_text()
        self.assertIn("uu -v NEEDRESTART_SUSPEND=1", calls)
        self.assertIn("needrestart -b -r l", calls)
        self.assertNotIn("apt-get", calls)

    def test_no_tool_reads_the_scripts_stdin(self):
        self.stubs()
        for args in (("plan", "0", "docker-ce"), ("apply", "0", "docker-ce", "--", "openssl")):
            self.stdin_log.write_text("")
            self.assertEqual(self.run_script(*args).returncode, 0)
            seen = dict(ln.split(":") for ln in self.stdin_log.read_text().split())
            self.assertIn("apt-config", seen)
            self.assertIn("unattended-upgrade", seen)
            self.assertIn("apt-get" if args[0] == "plan" else "needrestart", seen)
            self.assertEqual(set(seen.values()), {"0"}, seen)

    def test_apply_needrestart_missing(self):
        self.stubs(needrestart=False)
        proc = self.run_script("apply", "0", "docker-ce", "--", "openssl")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("NEEDRESTART unknown", proc.stdout.splitlines())
        self.assertEqual(proc.stdout.splitlines()[-1], "DONE")

    def test_apply_needrestart_failing_is_unknown(self):
        self.stubs(nr_rc=1)
        proc = self.run_script("apply", "0", "docker-ce", "--", "openssl")
        self.assertIn("NEEDRESTART unknown", proc.stdout.splitlines())

    def test_reboot_required_marker_is_reported(self):
        self.stubs()
        (self.tmp / "marker").write_text("")
        proc = self.run_script("apply", "0", "docker-ce", "--", "openssl")
        self.assertIn("REBOOT_REQUIRED 1", proc.stdout.splitlines())
        self.assertIn("REBOOT_ALREADY 1", self.run_script("plan", "0", "docker-ce").stdout.splitlines())

    def test_apt_lock_is_reported_as_busy(self):
        self.stubs(apt_rc=100, apt_msg="E: Could not get lock /var/lib/apt/lists/lock")
        proc = self.run_script("plan", "0", "docker-ce")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("ERROR apt is busy, retry later", proc.stderr)
        self.assertNotEqual(proc.stdout.splitlines()[-1], "DONE")
        self.assertNotIn("uu ", self.calls.read_text())

    def test_apt_other_failure(self):
        self.stubs(apt_rc=100, apt_msg="E: boom")
        proc = self.run_script("plan", "0", "docker-ce")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("ERROR apt-get update failed (exit 100)", proc.stderr)

    def test_unattended_upgrade_failure_dies_with_error(self):
        self.stubs(uu_rc=1)
        for args in (("plan", "0", "docker-ce"), ("apply", "0", "docker-ce", "--", "openssl")):
            with self.subTest(args):
                proc = self.run_script(*args)
                self.assertEqual(proc.returncode, 1)
                self.assertIn("ERROR unattended-upgrade", proc.stderr)
                self.assertNotIn("DONE", proc.stdout)
                self.assertNotIn("REBOOT_REQUIRED", proc.stdout)

    def test_apply_lock_text_stays_on_stdout_for_the_plugin(self):
        self.stubs(uu_rc=1, uu_out="Lock could not be acquired (another package manager running?)")
        proc = self.run_script("apply", "0", "docker-ce", "--", "openssl")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Lock could not be acquired", proc.stdout)

    def test_settings_not_in_force_stop_before_unattended_upgrade(self):
        cases = [("plan", ("plan", "0", "docker-ce"), "no-blacklist", "hold-back not in force for docker-ce"),
                 ("apply", ("apply", "0", "docker-ce", "--", "openssl"), "no-blacklist", "hold-back not in force"),
                 ("apply", ("apply", "0", "docker-ce", "--", "openssl"), "no-whitelist",
                  "confirmed-list pin not in force for openssl"),
                 ("apply", ("apply", "0", "docker-ce", "--", "openssl"), "no-strict", "strict whitelist not in force"),
                 ("plan", ("plan", "1"), "no-remove", "Remove-Unused-Dependencies=false not in force"),
                 ("plan", ("plan", "0", "docker-ce"), "remove-true", "Remove-New-Unused-Dependencies=false not in force"),
                 ("plan", ("plan", "0", "docker-ce"), "empty", "apt-config dump failed"),
                 ("plan", ("plan", "0", "docker-ce"), "all", None)]
        for label, args, dump, error in cases:
            with self.subTest(label=label, dump=dump):
                self.calls.write_text("")
                self.stubs(dump=dump)
                proc = self.run_script(*args)
                if error is None:
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    continue
                self.assertEqual(proc.returncode, 1)
                self.assertIn(f"ERROR {error}", proc.stderr)
                self.assertNotIn("DONE", proc.stdout)
                self.assertNotIn("uu ", self.calls.read_text())
                self.assertEqual(self.conf_files(), [])

    def test_apt_config_dump_failing_stops_the_run(self):
        self.stubs(dump_rc=1)
        for args in (("plan", "0", "docker-ce"), ("apply", "0", "docker-ce", "--", "openssl")):
            with self.subTest(args):
                self.calls.write_text("")
                proc = self.run_script(*args)
                self.assertEqual(proc.returncode, 1)
                self.assertIn("ERROR apt-config dump failed", proc.stderr)
                self.assertNotIn("uu ", self.calls.read_text())

    def test_bad_arguments_die_before_anything_runs(self):
        self.stubs()
        cases = [(), ("plan",), ("apply", "2", "x"), ("zap", "0", "x"), ("plan", "0"),
                 ("plan", "0", "docker-ce", "bad name"), ("plan", "0", "Docker-CE"), ("plan", "0", "-rf"),
                 ("plan", "0", "a;b"), ("plan", "0", "$(id)"), ("plan", "0", "x", ""), ("plan", "0", "a\nb"),
                 ("plan", "0", "docker-ce", "--", "openssl"),                      # plan takes no confirmed list
                 ("apply", "0", "docker-ce"), ("apply", "0", "docker-ce", "--"),    # apply needs the list
                 ("apply", "0", "docker-ce", "--", "--", "openssl"),
                 ("apply", "0", "docker-ce", "--", "bad name"), ("apply", "0", "docker-ce", "--", "Open;ssl"),
                 ("apply", "0", "docker-ce", "--", "$(id)"), ("apply", "1", "--"), ("apply", "0", "--", "openssl")]
        for args in cases:
            with self.subTest(args=args):
                proc = self.run_script(*args)
                self.assertEqual(proc.returncode, 1)
                self.assertTrue(proc.stderr.startswith("ERROR "), proc.stderr)
                self.assertEqual(proc.stdout, "")
        self.assertFalse(self.calls.exists())
        self.assertFalse((self.tmp / "run").exists())

    def test_valid_names_pass_validation(self):
        self.stubs()
        proc = self.run_script("plan", "0", *admin.DOCKER_PACKAGES, "libstdc++6", "g++-13")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc = self.run_script("apply", "0", "docker-ce", "--", "libstdc++6", "g++-13", "libssl3t64")
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
