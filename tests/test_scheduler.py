"""Weekly scheduler: launchd / systemd units, the run-time-resolving wrapper, state file, Actions template."""
from __future__ import annotations

import datetime as dt
import json
import os
import plistlib
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import scheduler, status

ROOT = Path(__file__).resolve().parents[1]
NOW = dt.datetime(2026, 11, 7, 12, 0, tzinfo=dt.timezone.utc)
STUB_CLI = 'import sys\nprint("ran", sys.argv[1:])\nsys.exit(int(__import__("os").environ.get("STUB_EXIT", "0")))\n'


def write_installed(home: Path, plugin_id: str, entries: list[dict]) -> Path:
    path = home / ".claude" / "plugins" / "installed_plugins.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 2, "plugins": {plugin_id: entries}}))
    return path


def fake_install(base: Path) -> Path:
    cli = base / "scripts" / "sbom_audit_cli.py"
    cli.parent.mkdir(parents=True)
    cli.write_text(STUB_CLI)
    return base


def recorder(rc: int = 0):
    calls: list[list[str]] = []

    def run(cmd, **kwargs):
        calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, rc, "", "")

    run.calls = calls
    return run


def run_wrapper(wrapper: Path, home: Path, **env) -> subprocess.CompletedProcess:
    full = {**os.environ, "HOME": str(home), **env}
    return subprocess.run([sys.executable, str(wrapper)], env=full, text=True, capture_output=True)


class SchedulerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.out = self.tmp / "Client Portal" / "security"     # a space in the path on purpose
        self.out.mkdir(parents=True)

    def test_resolve_install_path_picks_newest_entry(self):
        installed = write_installed(self.home, "sbom-audit@wuesteon-plugins", [
            {"installPath": "/old/0.1.0", "lastUpdated": "2026-11-01T10:00:00.000Z"},
            {"installPath": "/new/0.2.0", "lastUpdated": "2026-11-05T17:06:22.069Z"},
            {"installPath": "/mid/0.1.5", "lastUpdated": "2026-11-03T10:00:00.000Z"}])
        self.assertEqual(scheduler.resolve_install_path(installed, "sbom-audit@wuesteon-plugins"), Path("/new/0.2.0"))
        self.assertIsNone(scheduler.resolve_install_path(installed, "other@x"))
        self.assertIsNone(scheduler.resolve_install_path(self.home / "missing.json", "sbom-audit@wuesteon-plugins"))

    def test_plugin_id_from_root_parses_cache_layout(self):
        root = Path("/Users/me/.claude/plugins/cache/wuesteon-plugins/sbom-audit/0.1.0")
        self.assertEqual(scheduler.plugin_id_from_root(root), "sbom-audit@wuesteon-plugins")
        self.assertIsNone(scheduler.plugin_id_from_root(Path("/Users/me/PROJECTS/sbom-audit")))
        self.assertEqual(scheduler.config_dir({"XDG_CONFIG_HOME": "/x/cfg"}), Path("/x/cfg/sbom-audit"))
        self.assertEqual(scheduler.config_dir({}, home=Path("/h")), Path("/h/.config/sbom-audit"))
        self.assertRegex(scheduler.portfolio_id(self.out), r"^[0-9a-f]{8}$")

    def test_wrapper_resolves_path_at_run_time_and_logs(self):
        install = fake_install(self.tmp / "cache" / "wuesteon-plugins" / "sbom-audit" / "0.2.0")
        write_installed(self.home, "sbom-audit@wuesteon-plugins",
                        [{"installPath": str(install), "lastUpdated": "2026-11-05T17:06:22.069Z"}])
        dev = self.tmp / "dev-checkout"        # fallback root that must NOT be used: it has no CLI
        wrapper = scheduler.write_wrapper(self.out, "sbom-audit@wuesteon-plugins", dev, self.tmp / "cfg")
        self.assertEqual(wrapper.name, f"run-weekly-{scheduler.portfolio_id(self.out)}.py")
        self.assertEqual(wrapper.stat().st_mode & 0o777, 0o755)
        proc = run_wrapper(wrapper, self.home)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        log = (self.out / ".cache" / "runs" / (dt.date.today().isoformat() + ".log")).read_text()
        self.assertIn("ran", log)
        self.assertIn(str(self.out), log)       # the CLI got --out with the space intact
        state = scheduler.read_state(self.out)
        self.assertEqual(state["last_exit"], 0)
        self.assertRegex(state["last_fired"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        # a plugin update moves the install path; the same wrapper follows it without being rewritten
        newer = fake_install(self.tmp / "cache" / "wuesteon-plugins" / "sbom-audit" / "0.3.0")
        (newer / "scripts" / "sbom_audit_cli.py").write_text('print("ran new")\n')
        write_installed(self.home, "sbom-audit@wuesteon-plugins",
                        [{"installPath": str(newer), "lastUpdated": "2026-11-06T00:00:00.000Z"}])
        run_wrapper(wrapper, self.home)
        self.assertIn("ran new", (self.out / ".cache" / "runs" / (dt.date.today().isoformat() + ".log")).read_text())
        # no install anywhere: logged and recorded, never silent
        lost = scheduler.write_wrapper(self.out, "sbom-audit@wuesteon-plugins", dev, self.tmp / "cfg2")
        write_installed(self.home, "sbom-audit@wuesteon-plugins", [])
        proc = run_wrapper(lost, self.home)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("plugin install path not found",
                      (self.out / ".cache" / "runs" / (dt.date.today().isoformat() + ".log")).read_text())
        state = scheduler.read_state(self.out)
        self.assertEqual(state["last_exit"], 127)
        self.assertIn("plugin install path not found", state["last_error"])
        # a junk entry next to a valid one does not break the lookup
        write_installed(self.home, "sbom-audit@wuesteon-plugins",
                        ["junk", {"installPath": str(install), "lastUpdated": "2026-11-05T17:06:22.069Z"}])
        self.assertEqual(run_wrapper(wrapper, self.home).returncode, 0)
        # dev checkout without a plugin id: the fallback root is used
        dev_cli = fake_install(self.tmp / "dev2")
        dev_wrapper = scheduler.write_wrapper(self.out, None, dev_cli, self.tmp / "cfg3")
        self.assertEqual(run_wrapper(dev_wrapper, self.home, STUB_EXIT="3").returncode, 3)
        self.assertEqual(scheduler.read_state(self.out)["last_exit"], 3)

    def test_wrapper_sets_scheduled_marker(self):
        """The CLI refuses `hosts ... --confirm` under this marker (an unattended run must never patch)."""
        install = self.tmp / "marker-install"
        cli = install / "scripts" / "sbom_audit_cli.py"
        cli.parent.mkdir(parents=True)
        cli.write_text('import os\nprint("scheduled=" + repr(os.environ.get("SBOM_AUDIT_SCHEDULED")))\n')
        wrapper = scheduler.write_wrapper(self.out, None, install, self.tmp / "cfg-marker")
        self.assertIn('env["SBOM_AUDIT_SCHEDULED"] = "1"', wrapper.read_text(encoding="utf-8"))
        proc = run_wrapper(wrapper, self.home, SBOM_AUDIT_SCHEDULED="0")     # an inherited value is overridden
        self.assertEqual(proc.returncode, 0, proc.stderr)
        log = (self.out / ".cache" / "runs" / (dt.date.today().isoformat() + ".log")).read_text()
        self.assertIn("scheduled='1'", log)

    def test_write_state_tmp_carries_the_pid_and_a_failure_leaves_nothing(self):
        with mock.patch("sbomaudit.cache.os.replace", wraps=os.replace) as replace:
            path = scheduler.write_state(self.out, {"installed": True})
        self.assertEqual(Path(replace.call_args[0][0]).name, f"scheduler.json.{os.getpid()}.tmp")
        with mock.patch("sbomaudit.cache.os.replace", side_effect=OSError("disk gone")):
            with self.assertRaises(OSError):
                scheduler.write_state(self.out, {"installed": False})
        self.assertEqual(scheduler.read_state(self.out), {"installed": True})
        self.assertEqual([p.name for p in path.parent.iterdir()], ["scheduler.json"])

    def test_wrapper_exits_1_without_a_traceback_when_the_state_dir_is_unwritable(self):
        install = fake_install(self.tmp / "dev")
        wrapper = scheduler.write_wrapper(self.out, None, install, self.tmp / "cfg")
        (self.out / ".cache").write_text("not a directory\n")    # every state and log write fails
        proc = run_wrapper(wrapper, self.home)
        self.assertEqual(proc.returncode, 1)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertIn("wrapper failed", proc.stderr)
        self.assertEqual((self.out / ".cache").read_text(), "not a directory\n")
        self.assertIn('STATE + ".%d.tmp" % os.getpid()', wrapper.read_text(encoding="utf-8"))

    def test_launchd_plist_contents_and_label(self):
        wrapper = Path("/cfg/run weekly.py")
        data = plistlib.loads(scheduler.launchd_plist("dev.waiser.sbom-audit.abcd1234", wrapper, Path("/o/.cache/runs")))
        self.assertEqual(data["Label"], "dev.waiser.sbom-audit.abcd1234")
        self.assertEqual(data["ProgramArguments"], ["/usr/bin/env", "python3", str(wrapper)])
        self.assertEqual(data["StartCalendarInterval"], {"Weekday": 6, "Hour": 3, "Minute": 0})
        self.assertIs(data["RunAtLoad"], False)
        self.assertEqual(data["StandardOutPath"], "/o/.cache/runs/launchd.log")
        self.assertEqual(data["StandardErrorPath"], "/o/.cache/runs/launchd.log")
        self.assertEqual(scheduler.label(self.out), "dev.waiser.sbom-audit." + scheduler.portfolio_id(self.out))

    def test_systemd_units(self):
        service, timer = scheduler.systemd_units("sbom-audit-abcd1234", Path("/cfg/run-weekly-abcd1234.py"))
        self.assertIn("Type=oneshot", service)
        self.assertIn("ExecStart=/usr/bin/env python3 /cfg/run-weekly-abcd1234.py", service)
        self.assertIn("OnCalendar=Sat 03:00", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("WantedBy=timers.target", timer)

    def test_install_and_remove_call_platform_tool(self):
        cfg = self.tmp / "cfg"
        mac = recorder()
        lines = scheduler.install_weekly(self.out, ROOT, home=self.home, platform="darwin", run=mac, now=NOW, cfg_dir=cfg)
        label = scheduler.label(self.out)
        plist = self.home / "Library" / "LaunchAgents" / f"{label}.plist"
        self.assertTrue(plist.exists())
        self.assertIn(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(plist)], mac.calls)
        state = scheduler.read_state(self.out)
        self.assertTrue(state["installed"])
        self.assertEqual((state["schedule"], state["platform"], state["label"]), ("weekly", "darwin", label))
        self.assertEqual(state["installed_at"], "2026-11-07T12:00:00Z")
        self.assertIsNone(state["last_fired"])
        self.assertTrue(Path(state["wrapper"]).exists())
        self.assertTrue(any(str(plist) in line for line in lines))
        mac.calls.clear()
        lines = scheduler.remove(self.out, home=self.home, platform="darwin", run=mac, cfg_dir=cfg)
        self.assertEqual(mac.calls, [["launchctl", "bootout", f"gui/{os.getuid()}/{label}"]])
        self.assertFalse(plist.exists())
        self.assertFalse(Path(state["wrapper"]).exists())
        self.assertFalse(scheduler.read_state(self.out)["installed"])
        self.assertEqual(scheduler.remove(self.out, home=self.home, platform="darwin", run=mac, cfg_dir=cfg),
                         ["scheduler: not installed"])
        self.assertEqual(len(mac.calls), 1)                 # the second remove touched nothing
        # linux
        lin = recorder()
        scheduler.install_weekly(self.out, ROOT, home=self.home, platform="linux", run=lin, now=NOW, cfg_dir=cfg)
        name = f"sbom-audit-{scheduler.portfolio_id(self.out)}"
        unit_dir = self.home / ".config" / "systemd" / "user"
        self.assertTrue((unit_dir / f"{name}.service").exists() and (unit_dir / f"{name}.timer").exists())
        self.assertEqual(lin.calls, [["systemctl", "--user", "daemon-reload"],
                                     ["systemctl", "--user", "enable", "--now", f"{name}.timer"]])
        lin.calls.clear()
        scheduler.remove(self.out, home=self.home, platform="linux", run=lin, cfg_dir=cfg)
        self.assertIn(["systemctl", "--user", "disable", "--now", f"{name}.timer"], lin.calls)
        self.assertFalse((unit_dir / f"{name}.timer").exists())
        self.assertFalse(scheduler.read_state(self.out)["installed"])
        # unsupported platform: one line, nothing written, nothing run
        other = recorder()
        before = scheduler.read_state(self.out)
        lines = scheduler.install_weekly(self.out, ROOT, home=self.home, platform="win32", run=other, now=NOW, cfg_dir=cfg)
        self.assertEqual(lines, ["scheduling not supported on win32; use templates/github-actions/sbom-audit.yml"])
        self.assertEqual((other.calls, scheduler.read_state(self.out)), ([], before))

    def test_install_failure_is_reported_and_not_marked_installed(self):
        cfg = self.tmp / "cfg"
        lines = scheduler.install_weekly(self.out, ROOT, home=self.home, platform="darwin", run=recorder(5),
                                         now=NOW, cfg_dir=cfg)
        self.assertTrue(any("failed" in line for line in lines), lines)
        self.assertFalse(scheduler.read_state(self.out)["installed"])
        plist = self.home / "Library" / "LaunchAgents" / f"{scheduler.label(self.out)}.plist"
        self.assertFalse(plist.exists())                       # launchd must not load what state calls not installed
        scheduler.install_weekly(self.out, ROOT, home=self.home, platform="linux", run=recorder(5), now=NOW, cfg_dir=cfg)
        unit_dir = self.home / ".config" / "systemd" / "user"
        self.assertEqual(list(unit_dir.iterdir()), [])

    def test_missing_launchctl_or_systemctl_is_a_reported_failure(self):
        def missing(cmd, **kwargs):
            raise FileNotFoundError(2, "No such file or directory", cmd[0])

        cfg = self.tmp / "cfg"
        for platform in ("darwin", "linux"):
            with self.subTest(platform=platform):
                lines = scheduler.install_weekly(self.out, ROOT, home=self.home, platform=platform, run=missing,
                                                 now=NOW, cfg_dir=cfg)
                self.assertTrue(any(line.startswith("scheduler install failed:") for line in lines), lines)
                self.assertFalse(scheduler.read_state(self.out)["installed"])
                # state says installed (an earlier successful install), the tool vanished: remove reports, does not crash
                scheduler.install_weekly(self.out, ROOT, home=self.home, platform=platform, run=recorder(), now=NOW, cfg_dir=cfg)
                lines = scheduler.remove(self.out, home=self.home, platform=platform, run=missing, cfg_dir=cfg)
                self.assertEqual(len(lines), 1)
                self.assertTrue(lines[0].startswith("scheduler remove failed:"), lines)
                self.assertTrue(scheduler.read_state(self.out)["installed"])
                scheduler.remove(self.out, home=self.home, platform=platform, run=recorder(), cfg_dir=cfg)

    def test_remove_deletes_only_a_wrapper_it_named(self):
        cfg = self.tmp / "cfg"
        scheduler.install_weekly(self.out, ROOT, home=self.home, platform="darwin", run=recorder(), now=NOW, cfg_dir=cfg)
        foreign = self.tmp / "precious.txt"
        foreign.write_text("keep")
        state = scheduler.read_state(self.out)
        scheduler.write_state(self.out, {**state, "wrapper": str(foreign)})
        scheduler.remove(self.out, home=self.home, platform="darwin", run=recorder(), cfg_dir=cfg)
        self.assertTrue(foreign.exists())

    def test_missed_fire(self):
        installed = (NOW - dt.timedelta(days=30)).isoformat()
        state = {"installed": True, "installed_at": installed, "last_fired": (NOW - dt.timedelta(days=9)).isoformat()}
        self.assertEqual(scheduler.missed_fire(state, NOW), (NOW - dt.timedelta(days=9)).date().isoformat())
        state["last_fired"] = (NOW - dt.timedelta(days=3)).isoformat()
        self.assertIsNone(scheduler.missed_fire(state, NOW))
        # never fired: measured from the install date, so a fresh install is not reported
        self.assertEqual(scheduler.missed_fire({"installed": True, "installed_at": installed, "last_fired": None}, NOW),
                         installed[:10])
        fresh = {"installed": True, "installed_at": (NOW - dt.timedelta(days=1)).isoformat(), "last_fired": None}
        self.assertIsNone(scheduler.missed_fire(fresh, NOW))
        self.assertIsNone(scheduler.missed_fire({"installed": False, "last_fired": installed}, NOW))
        self.assertIsNone(scheduler.missed_fire(None, NOW))
        # one rule everywhere: the status screen agrees
        doc = json.loads((ROOT / "tests" / "fixtures" / "status" / "clear.json").read_text())
        doc["generated_at"] = NOW.isoformat()
        stale = {"installed": True, "installed_at": installed, "last_fired": None}
        self.assertIn("scheduler did not run since", status.severity_line(doc, stale, NOW))
        self.assertNotIn("scheduler did not", status.severity_line(doc, fresh, NOW))

    def test_write_md_reads_scheduler_state_itself(self):
        doc = json.loads((ROOT / "tests" / "fixtures" / "status" / "clear.json").read_text())
        (self.out / ".cache").mkdir()
        (self.out / ".cache" / "scheduler.json").write_text(
            json.dumps({"installed": True, "last_fired": "2026-11-01T03:00:00Z", "next_fire": "2026-11-14T03:00:00+01:00"}))
        path = status.write_md(self.out, doc)
        self.assertIn("Scheduler: installed.", path.read_text())
        self.assertIn("- last fired: 2026-11-01T03:00:00Z", path.read_text())
        from sbomaudit import pipeline
        self.assertIs(pipeline.read_scheduler_state, scheduler.read_state)

    def test_install_warns_when_run_host_differs(self):
        doc = json.loads((ROOT / "tests" / "fixtures" / "status" / "clear.json").read_text())
        doc["run_host"] = "some-other-machine"
        status.write(self.out, doc)
        lines = scheduler.install_weekly(self.out, ROOT, home=self.home, platform="darwin", run=recorder(),
                                         now=NOW, cfg_dir=self.tmp / "cfg")
        self.assertTrue(any("some-other-machine" in line and socket.gethostname() in line for line in lines), lines)
        doc["run_host"] = socket.gethostname()
        status.write(self.out, doc)
        lines = scheduler.install_weekly(self.out, ROOT, home=self.home, platform="darwin", run=recorder(),
                                         now=NOW, cfg_dir=self.tmp / "cfg")
        self.assertFalse(any(line.startswith("warning:") for line in lines), lines)

    def test_actions_template_is_valid_yaml_shape_and_fails_on_public(self):
        text = (ROOT / "templates" / "github-actions" / "sbom-audit.yml").read_text()
        self.assertNotIn("\t", text)
        for needle in ("schedule:", "- cron:", "workflow_dispatch:", "actions/checkout@", "visibility",
                       "::error::evidence repository must be private", "gh api",
                       "SBOM_AUDIT_REF:", 'gh repo clone Wuesteon/sbom-audit', '--out "$GITHUB_WORKSPACE"', "SBOM_AUDIT_SECRETS_KEY: ${{ secrets.SBOM_AUDIT_SECRETS_KEY }}",
                       "syft", "osv-scanner", "gitleaks", "git commit", '"issue", "create"', "status.json", "audit.json"):
            self.assertIn(needle, text)
        # the visibility guard comes before anything is installed or run
        self.assertLess(text.index("must be private"), text.index("osv-scanner"))
        self.assertLess(text.index("must be private"), text.index("SBOM_AUDIT_SECRETS_KEY: ${{"))
        self.assertNotIn("github.event.repository.visibility", text)     # empty on schedule events
        self.assertNotIn("token: ${{", text)                              # checkout keeps the default token
        self.assertNotIn("security/", text.split("jobs:", 1)[1])         # the evidence repo is the security folder
        # every non-comment line is indented in steps of two spaces
        for line in text.splitlines():
            stripped = line.lstrip(" ")
            if stripped and not stripped.startswith("#") and not line.startswith(" " * 2 + " "):
                self.assertEqual((len(line) - len(stripped)) % 2, 0, line)

    def test_plugin_root_prefers_env(self):
        self.assertEqual(scheduler.plugin_root({"CLAUDE_PLUGIN_ROOT": "/p/root"}), Path("/p/root"))
        self.assertEqual(scheduler.plugin_root({}), ROOT)

    def test_next_fire_is_the_coming_saturday_at_three(self):
        friday = dt.datetime(2026, 11, 6, 12, 0).astimezone()
        nxt = dt.datetime.fromisoformat(scheduler.next_fire(friday))
        self.assertEqual((nxt.weekday(), nxt.hour, nxt.minute, (nxt.date() - friday.date()).days), (5, 3, 0, 1))
        saturday_late = dt.datetime(2026, 11, 7, 12, 0).astimezone()
        self.assertEqual((dt.datetime.fromisoformat(scheduler.next_fire(saturday_late)).date() - saturday_late.date()).days, 7)


if __name__ == "__main__":
    unittest.main()
