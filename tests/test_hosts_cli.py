"""Host mode CLI: `hosts check|accept`, the `--confirm` gate, read-only mode. Nothing opens a connection:
`hosts.check` is a fake. Hosts and addresses are example data (203.0.113.0/24, box-a style names)."""
import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import cli, status
from sbomaudit.hosts import cli as hosts_cli
from sbomaudit.hosts import store

CONFIG = """[hosts]
enabled = true
key = "{key}"

[hosts.servers."box-a"]
address = "203.0.113.10"

[hosts.servers."box-b"]
address = "203.0.113.11"
"""
KEV_ID = "kev:CVE-2024-1086:linux-image-6.8.0-45-generic@6.8.0-45.45"
NOW = "2026-11-09T08:00:00Z"


def entry(status="ok", critical=(), error=None, findings=()):
    return {"production": False, "projects": [], "status": status, "address": "203.0.113.10", "error": error,
            "checked_at": NOW, "attempted_at": NOW, "findings": list(findings), "critical": list(critical)}


def doc(hosts, skipped=None):
    return {"schema": 1, "generated_at": NOW, "skipped": skipped, "last_checked": NOW,
            "collector_shipped": "1", "hosts": hosts}


class HostsCliBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.out = self.tmp / "security"
        self.out.mkdir()
        (self.out / "sbom-audit.toml").write_text(CONFIG.format(key=self.tmp / "key"))
        env = {k: v for k, v in os.environ.items() if k not in ("SBOM_AUDIT_READ_ONLY", "SBOM_AUDIT_SCHEDULED")}
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def main(self, *argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                rc = cli.main(["--out", str(self.out), "hosts", *argv])
            except SystemExit as exc:
                rc = exc.code
        return rc, stdout.getvalue(), stderr.getvalue()


class CheckTests(HostsCliBase):
    def test_hosts_check_unknown_host_exit_2(self):
        with mock.patch("sbomaudit.hosts.check") as check, mock.patch("subprocess.run") as run:
            rc, _, err = self.main("check", "box-a", "box-z")
        self.assertEqual(rc, 2)
        self.assertIn("box-z", err)
        check.assert_not_called()                   # nothing is collected, not even from box-a
        run.assert_not_called()

    def test_check_passes_the_named_hosts_and_reports_clean(self):
        result = doc({"box-a": entry(), "box-b": entry()})
        with mock.patch("sbomaudit.hosts.check", return_value=result) as check:
            rc, out, _ = self.main("check", "box-a")
        self.assertEqual(rc, 0)
        self.assertEqual(check.call_args.args[1], ["box-a"])
        self.assertIn("1 checked, 0 failed, 0 critical", out)
        with mock.patch("sbomaudit.hosts.check", return_value=result) as check:
            self.main("check")
        self.assertIsNone(check.call_args.args[1])

    def test_check_exit_codes_follow_the_run(self):
        cases = [(doc({"box-a": entry(critical=["patch:timer-inactive"]), "box-b": entry()}), 1),
                 (doc({"box-a": entry(), "box-b": entry("failed", error="ssh timed out")}), 2),
                 (doc({"box-a": entry("weird"), "box-b": entry()}), 2),
                 (doc({"box-a": entry("failed", critical=["x"]), "box-b": entry("unsupported")}), 2),
                 (doc({"box-a": entry("unsupported"), "box-b": entry()}), 0)]
        for result, expected in cases:
            with self.subTest(expected=expected), mock.patch("sbomaudit.hosts.check", return_value=result):
                self.assertEqual(self.main("check")[0], expected)

    def test_named_check_ignores_other_hosts_failures(self):
        result = doc({"box-a": entry(), "box-b": entry("failed", error="unreachable")})
        with mock.patch("sbomaudit.hosts.check", return_value=result):
            self.assertEqual(self.main("check", "box-a")[0], 0)

    def test_skipped_check_exits_0_and_says_why(self):
        with mock.patch("sbomaudit.hosts.check", return_value=doc({}, skipped="no audit key on this machine")):
            rc, out, _ = self.main("check")
        self.assertEqual(rc, 0)
        self.assertIn("skipped: no audit key on this machine", out)

    def test_check_without_configured_hosts_exits_2(self):
        (self.out / "sbom-audit.toml").write_text("")
        with mock.patch("sbomaudit.hosts.check") as check:
            rc, _, err = self.main("check")
        self.assertEqual(rc, 2)
        self.assertIn("no hosts configured", err)
        check.assert_not_called()

    def test_check_disabled_hosts_exits_2(self):
        (self.out / "sbom-audit.toml").write_text(CONFIG.format(key="k").replace("enabled = true", "enabled = false"))
        with mock.patch("sbomaudit.hosts.check") as check:
            self.assertEqual(self.main("check")[0], 2)
        check.assert_not_called()

    def test_a_crash_in_check_exits_2_with_the_type_only(self):
        with mock.patch("sbomaudit.hosts.check", side_effect=RuntimeError("203.0.113.10 refused")):
            rc, out, err = self.main("check")
        self.assertEqual(rc, 2)
        self.assertIn("RuntimeError", err)
        self.assertNotIn("203.0.113.10", out + err)

    def test_read_only_blocks_hosts(self):
        with mock.patch.dict(os.environ, {"SBOM_AUDIT_READ_ONLY": "1"}), mock.patch("sbomaudit.hosts.check") as check:
            for argv in (("check",), ("check", "box-a"), ("accept", "box-a", "change:users:+x", "ok"),
                         ("bootstrap", "box-a"), ("unbootstrap", "box-a"), ("patch", "box-a")):
                with self.subTest(argv=argv):
                    rc, _, err = self.main(*argv)
                    self.assertEqual(rc, 5)
                    self.assertIn("read-only mode", err)
        check.assert_not_called()
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), ["sbom-audit.toml"])


HOOK = Path(__file__).resolve().parent.parent / "plugin" / "templates" / "session-hook" / "session-start.py"


class StatusRefreshTests(HostsCliBase):
    """A manual `hosts check` rebuilds only the hosts part of status.json / STATUS.md."""

    def seed_status(self, hosts_doc=None, **overrides):
        rep = status.empty_report()
        rep["vulnerabilities"] = [{"ecosystem": "npm", "name": "left-pad", "version": "1.0.0", "kev": True,
                                   "vulns": [{"id": "CVE-2024-0001", "kev": True}], "locations": []}]
        previous = status.build(rep, secrets=None, previous=None, duration_s=1.0, exit_code=0, run_host="h",
                                mode="local", hosts=hosts_doc if hosts_doc is not None else doc({"box-a": entry(), "box-b": entry()}))
        previous = {**previous, "generated_at": dt_now(), **overrides}
        status.write(self.out, previous)
        status.write_md(self.out, previous, scheduler={"installed": False})
        return previous

    def read(self):
        return json.loads((self.out / "status.json").read_text())

    def check(self, result, *argv):
        with mock.patch("sbomaudit.hosts.check", return_value=result):
            return self.main("check", *argv)

    def test_refreshed_critical_shows_in_status_md_and_the_hook_line(self):
        self.seed_status()
        rc, _, _ = self.check(doc({"box-a": entry(critical=["patch:timer-inactive"]), "box-b": entry()}))
        self.assertEqual(rc, 1)
        new = self.read()
        self.assertEqual(new["open"]["hosts_critical"], ["box-a patch:timer-inactive"])
        self.assertEqual(new["deltas"]["hosts_critical"], {"new": ["box-a patch:timer-inactive"], "resolved": []})
        self.assertEqual(new["counts"]["hosts"]["critical"], 1)
        self.assertEqual(new["counts"]["hosts"]["critical_hosts"], ["box-a"])
        md = (self.out / "STATUS.md").read_text()
        self.assertIn("1 critical host findings open (box-a)", md)
        self.assertIn("- hosts: 2 checked, 0 failed, 1 critical (box-a)", md)
        proc = subprocess.run(["python3", str(HOOK)], cwd=self.tmp, text=True, capture_output=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("1 critical host findings open (box-a)", json.loads(proc.stdout)["systemMessage"])

    def test_resolved_critical_is_listed_as_resolved_and_clears_the_line(self):
        self.seed_status(hosts_doc=doc({"box-a": entry(critical=["patch:timer-inactive"]), "box-b": entry()}))
        self.assertEqual(self.read()["open"]["hosts_critical"], ["box-a patch:timer-inactive"])
        self.check(doc({"box-a": entry(), "box-b": entry()}))
        new = self.read()
        self.assertEqual(new["open"]["hosts_critical"], [])
        self.assertEqual(new["deltas"]["hosts_critical"], {"new": [], "resolved": ["box-a patch:timer-inactive"]})
        self.assertNotIn("critical host findings", (self.out / "STATUS.md").read_text().split("## Since")[0])

    def test_everything_but_the_hosts_part_stays_as_it_was(self):
        before = self.seed_status()
        self.check(doc({"box-a": entry(critical=["patch:timer-inactive"]), "box-b": entry("failed", error="x")}))
        after = self.read()
        for key in before:
            if key not in ("counts", "open", "deltas"):
                self.assertEqual(after[key], before[key], key)
        self.assertEqual({k: v for k, v in after["counts"].items() if k != "hosts"},
                         {k: v for k, v in before["counts"].items() if k != "hosts"})
        self.assertEqual({k: v for k, v in after["open"].items() if k != "hosts_critical"},
                         {k: v for k, v in before["open"].items() if k != "hosts_critical"})
        self.assertEqual({k: v for k, v in after["deltas"].items() if k != "hosts_critical"},
                         {k: v for k, v in before["deltas"].items() if k != "hosts_critical"})
        self.assertEqual(after["counts"]["hosts"]["failed"], 1)
        self.assertEqual(after["open"]["kev"], before["open"]["kev"])

    def test_no_status_json_creates_nothing_and_says_so(self):
        rc, out, _ = self.check(doc({"box-a": entry(critical=["x"]), "box-b": entry()}))
        self.assertEqual(rc, 1)
        self.assertIn("status appears after the first `run`", out)
        self.assertFalse((self.out / "status.json").exists())
        self.assertFalse((self.out / "STATUS.md").exists())

    def test_skipped_check_marks_hosts_skipped_and_keeps_the_open_set(self):
        self.seed_status(hosts_doc=doc({"box-a": entry(critical=["patch:timer-inactive"]), "box-b": entry()}))
        store.write(self.out, doc({"box-a": entry(critical=["patch:timer-inactive"]), "box-b": entry()}))
        rc, _, _ = self.check(doc({}, skipped="no audit key on this machine"))
        self.assertEqual(rc, 0)
        new = self.read()
        self.assertEqual(new["counts"]["hosts"]["skipped"], "no audit key on this machine")
        self.assertEqual(new["open"]["hosts_critical"], ["box-a patch:timer-inactive"])
        self.assertEqual(new["deltas"]["hosts_critical"], {"new": [], "resolved": []})
        self.assertIn("hosts: skipped (no audit key on this machine)", (self.out / "STATUS.md").read_text())

    def test_a_named_check_keeps_the_other_hosts_entries(self):
        self.seed_status()
        self.check(doc({"box-a": entry(), "box-b": entry(critical=["patch:timer-inactive"])}), "box-a")
        self.assertEqual(self.read()["open"]["hosts_critical"], ["box-b patch:timer-inactive"])

    def test_a_status_write_failure_does_not_change_the_checks_exit_code(self):
        self.seed_status()
        with mock.patch.object(status, "write", side_effect=OSError("/secret/path")):
            rc, _, err = self.check(doc({"box-a": entry(critical=["x"]), "box-b": entry()}))
        self.assertEqual(rc, 1)
        self.assertIn("status not refreshed (OSError)", err)
        self.assertNotIn("/secret/path", err)

    def test_refresh_hosts_without_a_document_changes_nothing(self):
        before = self.seed_status()
        self.assertIs(status.refresh_hosts(before, None), before)


def dt_now() -> str:
    import datetime as dt
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat()


class AcceptTests(HostsCliBase):
    def seed(self):
        finding = {"id": KEV_ID, "group": "kev", "critical": True, "text": "x"}
        store.write(self.out, doc({"box-a": entry(critical=[KEV_ID], findings=[finding]), "box-b": entry()}))

    def test_accept_review_by_parsed(self):
        with mock.patch("sbomaudit.hosts.store.accept", return_value=[self.out / "hosts-decisions.toml"]) as accept:
            rc, out, _ = self.main("accept", "box-a", KEV_ID, "patch is scheduled", "--review-by", "2026-11-20")
        self.assertEqual(rc, 0, out)
        args = accept.call_args.args
        self.assertEqual(args[0], self.out.resolve())
        self.assertEqual(args[1:5], ("box-a", KEV_ID, "patch is scheduled", "2026-11-20"))
        self.assertEqual(args[5].isoformat() >= "2026-11-09", True)         # today, a date
        with mock.patch("sbomaudit.hosts.store.accept", return_value=[]) as accept:
            self.main("accept", "box-a", "change:users:+deploy2", "new deploy user")
        self.assertIsNone(accept.call_args.args[4])

    def test_accept_records_a_decision_and_logs_once(self):
        self.seed()
        import datetime as dt
        review = (dt.datetime.now(dt.timezone.utc).date() + dt.timedelta(days=7)).isoformat()
        rc, out, err = self.main("accept", "box-a", KEV_ID, "patch is scheduled", "--review-by", review)
        self.assertEqual(rc, 0, err)
        self.assertEqual(store.read_decisions(self.out)[("box-a", KEV_ID)].review_by, review)
        log = (self.out / "log.md").read_text()
        self.assertEqual(log.count("hosts accept"), 1)                     # store.accept logs; the CLI does not

    def test_invalid_review_by_exit_2(self):
        self.seed()
        for bad in ("2026-13-01", "next week", "2026-1-5", "20261120", ""):
            with self.subTest(bad=bad), mock.patch("sbomaudit.hosts.store.accept") as accept:
                rc, _, err = self.main("accept", "box-a", KEV_ID, "n", "--review-by", bad)
                self.assertEqual(rc, 2)
                self.assertIn("--review-by", err)
                accept.assert_not_called()
        self.assertFalse((self.out / "hosts-decisions.toml").exists())

    def test_store_errors_map_to_a_message_and_exit_2(self):
        self.seed()
        cases = {("box-a", "change:users:+nobody", None): "unknown change-id",          # unknown id
                 ("box-a", "patch:timer-inactive", None): "can only be fixed, not accepted",   # not acceptable
                 ("box-a", KEV_ID, None): "needs --review-by",                          # store rule surfaces
                 ("box-z", KEV_ID, "2026-11-20"): "unknown host"}                       # not configured
        for (host, change_id, review), text in cases.items():
            with self.subTest(change_id=change_id, host=host):
                argv = ["accept", host, change_id, "note"] + (["--review-by", review] if review else [])
                rc, out, err = self.main(*argv)
                self.assertEqual(rc, 2)
                self.assertIn(text, err)
                self.assertNotIn("Traceback", out + err)
        self.assertFalse((self.out / "hosts-decisions.toml").exists())

    def test_empty_note_exit_2(self):
        self.seed()
        with mock.patch("sbomaudit.hosts.store.accept") as accept:
            self.assertEqual(self.main("accept", "box-a", KEV_ID, "   ", "--review-by", "2026-11-20")[0], 2)
        accept.assert_not_called()

    def test_unwritable_decisions_exit_2_with_the_error_type(self):
        self.seed()
        with mock.patch("sbomaudit.hosts.store.accept", side_effect=PermissionError("/secret/path")):
            rc, out, err = self.main("accept", "box-a", "change:users:+x", "n")
        self.assertEqual(rc, 2)
        self.assertIn("PermissionError", err)
        self.assertNotIn("/secret/path", out + err)


class ConfirmTests(HostsCliBase):
    def args(self, **kw):
        import argparse
        return argparse.Namespace(host="box-a", **kw)

    def test_no_confirm_no_refusal(self):
        self.assertIsNone(hosts_cli.refuse_confirm(self.args(confirm=None), env={}))
        self.assertIsNone(hosts_cli.refuse_confirm(self.args(), env={}))

    def test_confirm_refused_under_scheduler(self):
        text = hosts_cli.refuse_confirm(self.args(confirm="box-a"), env={"SBOM_AUDIT_SCHEDULED": "1"})
        self.assertIn("scheduler", text)
        self.assertIsNone(hosts_cli.refuse_confirm(self.args(confirm="box-a"), env={"SBOM_AUDIT_SCHEDULED": "0"}))
        with mock.patch.dict(os.environ, {"SBOM_AUDIT_SCHEDULED": "1"}):       # through the CLI, and by default env
            for sub in ("bootstrap", "unbootstrap", "patch"):
                with self.subTest(sub=sub):
                    rc, out, err = self.main(sub, "box-a", "--confirm", "box-a")
                    self.assertEqual(rc, 2)
                    self.assertIn("scheduler", err)
                    self.assertNotIn("not implemented", out + err)

    def test_confirm_must_match_host(self):
        for given in ("box-b", "BOX-A", " box-a", "box-a ", "box-a\n", "", "box"):
            with self.subTest(given=given):
                self.assertIn("box-a", hosts_cli.refuse_confirm(self.args(confirm=given), env={}))
        self.assertIsNone(hosts_cli.refuse_confirm(self.args(confirm="box-a"), env={}))
        rc, _, err = self.main("patch", "box-a", "--confirm", "box-b")
        self.assertEqual(rc, 2)
        self.assertIn("must equal", err)

    def test_patch_is_wired_to_admin(self):
        for argv, expected in ((("patch", "box-a", "--include-docker"), ("box-a", None, True)),
                               (("patch", "box-a", "--confirm", "box-a"), ("box-a", "box-a", False))):
            with self.subTest(argv=argv), mock.patch("sbomaudit.hosts.admin.patch", return_value=0) as patch:
                rc, out, err = self.main(*argv)
                self.assertEqual(rc, 0)
                self.assertEqual(patch.call_args.args[1:], expected)
                self.assertNotIn("not implemented", out + err)

    def test_confirm_flag_only_on_admin_commands(self):
        rc, _, _ = self.main("check", "--confirm", "box-a")
        self.assertEqual(rc, 2)                                             # argparse rejects it


if __name__ == "__main__":
    unittest.main()
