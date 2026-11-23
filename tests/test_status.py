"""status.json / STATUS.md: open sets, deltas, atomic write, severity line, section order."""
from __future__ import annotations

import datetime as dt
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import __version__, config, pipeline, status
from sbomaudit.hosts import store as hosts_store


def row(name, version, sev, kev_ids=(), locations=(("prod", "required"),), vuln_ids=None):
    ids = list(kev_ids) or list(vuln_ids or [f"GHSA-{name}"])
    return {"ecosystem": "npm", "name": name, "version": version, "scope": "required",
            "direct_anywhere": True,
            "locations": [{"project": p, "branch": "main", "manifest": "package.json", "direct": True, "scope": s}
                          for p, s in locations],
            "vulns": [{"id": i, "kev": i in kev_ids, "fixed_in": None, "severity": sev} for i in ids],
            "max_severity": sev, "kev": bool(kev_ids)}


def make_rep(vulns=(), runtimes=(), sources=None, images=(), suppressed=()):
    return {"generated_at": "2026-11-07T10:00:00+01:00", "sources": sources or {},
            "vulnerabilities": list(vulns), "runtimes": list(runtimes), "outdated": [],
            "unpinned_images": list(images), "suppressed": list(suppressed), "notes": [],
            "stats": {"projects": 2, "branches": 3, "unique_package_versions": 10, "occurrences": 12,
                      "direct_dependencies": 5, "images": 1, "runtimes": 2},
            "production_projects": ["prod"]}


def build(rep=None, **kw):
    args = dict(secrets=None, previous=None, duration_s=12.5, exit_code=0, run_host="mac", mode="full")
    args.update(kw)
    return status.build(rep or make_rep(), **args)


def secrets_doc(a=0, b=0, c=0, oldest=0):
    findings = []
    for cls, n in (("A", a), ("B", b), ("C", c)):
        for i in range(n):
            findings.append({"fingerprint": f"fp-{cls}-{i}", "class": cls, "status": "open",
                             "age_days": oldest if i == 0 else 1})
    findings.append({"fingerprint": "fp-closed", "class": "A", "status": "resolved", "age_days": 99})
    return {"findings": findings, "engine": {"name": "gitleaks", "version": "8.30.1"},
            "scan": {"mode": "full", "repos": 3}}


def doc(**over):
    """A minimal status document for severity_line tests."""
    d = build()
    d["generated_at"] = "2026-11-07T10:00:00+01:00"
    d["last_assessment"] = "2026-11-07"
    d.update(over)
    return d


NOW = dt.datetime.fromisoformat("2026-11-07T12:00:00+01:00")


class OpenSetsTest(unittest.TestCase):
    def test_open_sets_identity_and_production_filter(self):
        rep = make_rep(vulns=[
            row("a", "1", "MEDIUM", kev_ids=("CVE-1",), locations=(("other", "required"),)),
            row("b", "2", "HIGH", locations=(("prod", "optional"),)),
            row("c", "3", "HIGH", locations=(("other", "required"),)),
        ], runtimes=[{"product": "nodejs", "cycle": "18", "status": "EOL"},
                     {"product": "python", "cycle": "3.13", "status": "supported"}])
        sets = status.open_sets(rep, None)
        self.assertEqual(sets["kev"], ["CVE-1 npm:a@1"])
        self.assertEqual(sets["critical_high_production"], [])
        self.assertEqual(sets["eol"], ["nodejs 18"])
        self.assertEqual(sets["secrets_a"], [])
        self.assertEqual(sets["secrets_b"], [])

    def test_kev_row_counts_as_critical_high_in_production_only(self):
        kev_medium = row("k", "1", "MEDIUM", kev_ids=("CVE-7",))
        sets = status.open_sets(make_rep(vulns=[kev_medium]), None)
        self.assertEqual(sets["kev"], ["CVE-7 npm:k@1"])
        self.assertEqual(sets["critical_high_production"], ["CVE-7 npm:k@1"])
        elsewhere = row("k", "1", "MEDIUM", kev_ids=("CVE-7",), locations=(("other", "required"),))
        sets = status.open_sets(make_rep(vulns=[elsewhere]), None)
        self.assertEqual(sets["kev"], ["CVE-7 npm:k@1"])
        self.assertEqual(sets["critical_high_production"], [])

    def test_counts_are_per_row_open_sets_per_advisory(self):
        two_kev = row("k", "1", "HIGH", kev_ids=("CVE-1", "CVE-2"))
        s = build(make_rep(vulns=[two_kev]))
        self.assertEqual(len(s["open"]["kev"]), 2)
        self.assertEqual(s["counts"]["kev"], 1)
        self.assertEqual(s["counts"]["critical_high_production"], 1)
        self.assertEqual(len(s["open"]["critical_high_production"]), 2)

    def test_medium_advisory_of_a_high_package_is_not_critical_high(self):
        mixed = row("l", "1", "HIGH", vuln_ids=("GHSA-high", "GHSA-medium"))
        mixed["vulns"][1]["severity"] = "MEDIUM"
        sets = status.open_sets(make_rep(vulns=[mixed]), None)
        self.assertEqual(sets["critical_high_production"], ["GHSA-high npm:l@1"])

    def test_production_high_counts(self):
        rep = make_rep(vulns=[row("d", "4", "CRITICAL")])
        sets = status.open_sets(rep, secrets_doc(a=1, b=2, c=1))
        self.assertEqual(sets["critical_high_production"], ["GHSA-d npm:d@4"])
        self.assertEqual(sets["secrets_a"], ["fp-A-0"])
        self.assertEqual(sets["secrets_b"], ["fp-B-0", "fp-B-1"])


class DeltaTest(unittest.TestCase):
    def test_deltas_against_previous(self):
        prev = build(make_rep(vulns=[row("a", "1", "LOW", kev_ids=("CVE-1",))]))
        now = build(make_rep(vulns=[row("a", "1", "LOW", kev_ids=("CVE-2",))]), previous=prev)
        self.assertEqual(now["deltas"]["kev"], {"new": ["CVE-2 npm:a@1"], "resolved": ["CVE-1 npm:a@1"]})
        self.assertFalse(now["first_run"])

    def test_open_rules_are_recorded(self):
        self.assertEqual(build()["open_rules"], status.OPEN_RULES)
        self.assertEqual(set(status.OPEN_RULES), set(status.OPEN_KEYS))

    def test_a_1_1_x_file_is_not_comparable_for_critical_high(self):
        """1.1.1 put every advisory of an actionable package into the set: its MEDIUM ones, still open now,
        must never read as resolved, and the change of rules must not read as progress."""
        mixed = row("p", "6.1.2", "HIGH", vuln_ids=("GHSA-high", "GHSA-medium"))
        mixed["vulns"][1]["severity"] = "MEDIUM"
        rep = make_rep(vulns=[mixed, row("k", "1", "LOW", kev_ids=("CVE-1",))])
        prev = {"schema": 1, "plugin_version": "1.1.1", "first_run": False,
                "open": {"kev": ["CVE-1 npm:k@1"],
                         "critical_high_production": ["CVE-1 npm:k@1", "GHSA-high npm:p@6.1.2",
                                                      "GHSA-medium npm:p@6.1.2", "GHSA-gone npm:q@1"]}}
        s = build(rep, previous=prev)
        crit = s["deltas"]["critical_high_production"]
        self.assertEqual((crit["new"], crit["resolved"]), ([], []))
        self.assertIn("sbom-audit 1.1.1", crit["not_comparable"])
        self.assertEqual(s["deltas"]["kev"], {"new": [], "resolved": []})      # same rule: compared
        text = status.render_md(s, None)
        self.assertIn("- critical_high_production: not comparable with the previous run", text)
        self.assertIn("2 open now", text)
        self.assertNotIn("GHSA-medium", text.split("## Secrets")[0])
        self.assertNotIn("new CRITICAL/HIGH", status.severity_line(s, None, NOW))
        nxt = build(rep, previous=s)                                         # the next run compares again
        self.assertEqual(nxt["deltas"]["critical_high_production"], {"new": [], "resolved": []})

    def test_a_1_2_x_file_without_open_rules_compares(self):
        rep = make_rep(vulns=[row("a", "1", "HIGH")])
        prev = build(make_rep(vulns=[row("b", "1", "HIGH")]))
        del prev["open_rules"]
        for version, comparable in (("1.2.0", True), ("1.2.1", True), ("1.1.1", False), ("0.9", False), (None, False)):
            prev["plugin_version"] = version
            crit = build(rep, previous=prev)["deltas"]["critical_high_production"]
            self.assertEqual("not_comparable" not in crit, comparable, version)
            if comparable:
                self.assertEqual(crit, {"new": ["GHSA-a npm:a@1"], "resolved": ["GHSA-b npm:b@1"]})

    def test_another_rule_number_is_not_comparable(self):
        prev = build(make_rep(vulns=[row("b", "1", "HIGH", kev_ids=("CVE-1",))]))
        prev["open_rules"] = {**status.OPEN_RULES, "kev": 99}
        s = build(make_rep(), previous=prev)
        self.assertIn("not_comparable", s["deltas"]["kev"])
        self.assertEqual(s["deltas"]["critical_high_production"]["resolved"], ["CVE-1 npm:b@1"])

    def test_a_still_reported_advisory_is_never_resolved(self):
        prev = build(make_rep(vulns=[row("a", "1", "HIGH"), row("b", "1", "HIGH")]))
        downgraded = row("a", "1", "MEDIUM")                         # re-rated: still in AUDIT.md
        s = build(make_rep(vulns=[downgraded]), previous=prev)
        crit = s["deltas"]["critical_high_production"]
        self.assertEqual(crit["resolved"], ["GHSA-b npm:b@1"])      # gone from the audit: resolved
        self.assertEqual(crit["not_counted"], ["GHSA-a npm:a@1"])
        text = status.render_md(s, None)
        self.assertIn("- critical_high_production: 0 new, 1 resolved, 1 no longer counted but still in AUDIT.md", text)
        self.assertIn("  - no longer counted: GHSA-a npm:a@1", text)

    def test_failed_run_keeps_the_rules_of_the_sets_it_carries(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            old = {"schema": 1, "plugin_version": "1.1.1", "generated_at": "2026-11-01T10:00:00+01:00",
                   "open": {"critical_high_production": ["GHSA-medium npm:p@1"]}, "counts": {}}
            status.write(out, old)
            cfg = config.Config(out=out, root=out.parent, mode="portfolio")
            pipeline._write_failed_status(cfg, RuntimeError("boom"), 0.0, lambda m: None)
            carried = status.read(out)
        self.assertEqual(carried["open_rules"]["critical_high_production"], 1)
        s = build(make_rep(vulns=[row("p", "1", "HIGH")]), previous=carried)
        self.assertIn("not_comparable", s["deltas"]["critical_high_production"])

    def test_first_status_has_empty_deltas(self):
        rep = make_rep(vulns=[row("a", "1", "LOW", kev_ids=("CVE-1",))])
        for previous in (None, {"schema": 0, "open": {"kev": ["CVE-9 npm:z@1"]}}):
            s = build(rep, previous=previous)
            self.assertTrue(s["first_run"])
            for key, delta in s["deltas"].items():
                self.assertEqual(delta, {"new": [], "resolved": []}, key)
            with tempfile.TemporaryDirectory() as tmp:
                text = status.write_md(Path(tmp), s, None).read_text(encoding="utf-8")
            self.assertIn("first run with status", text)


class DocumentTest(unittest.TestCase):
    def test_document_shape_and_defaults(self):
        s = build(make_rep(vulns=[row("a", "1", "HIGH", kev_ids=("CVE-1",))],
                           images=[{"image": "x"}], suppressed=[{"id": "y"}],
                           sources={"osv": {"queried": 3, "failed": []},
                                    "registries": {"failed": [{"what": "npm:x", "error": "boom"}]},
                                    "cisa_kev": {"error": "timeout"}}),
                  secrets=secrets_doc(a=2, b=1, oldest=40))
        self.assertEqual(s["schema"], status.SCHEMA)
        self.assertEqual(s["plugin_version"], __version__)
        self.assertEqual((s["run_host"], s["mode"], s["duration_s"], s["exit_code"]), ("mac", "full", 12.5, 0))
        self.assertEqual(s["counts"]["vulnerable"], 1)
        self.assertEqual(s["counts"]["kev"], 1)
        self.assertEqual(s["counts"]["floating_tags"], 1)
        self.assertEqual(s["counts"]["suppressed"], 1)
        self.assertEqual(s["counts"]["secrets"], {"A": 2, "B": 1, "C": 0})
        self.assertEqual(s["secrets_scan"]["oldest_open_days"], 40)
        self.assertEqual(s["secrets_scan"]["engine"], "gitleaks")
        self.assertEqual({f["source"] for f in s["failed_sources"]}, {"registries", "cisa_kev"})
        self.assertEqual(s["cra_products_open"], [])
        self.assertEqual(s["commit"], {"status": "skipped", "sha": None, "detail": "", "pending_hand_edits": []})
        self.assertEqual(s["push"], {"status": "skipped", "detail": ""})
        self.assertEqual(s["visibility"], "unknown")
        self.assertIsNone(s["assessment_proposal"])

    def test_no_secrets_scan_is_skipped_not_clean(self):
        s = build()
        self.assertEqual(s["counts"]["secrets"], {"A": 0, "B": 0, "C": 0})
        self.assertEqual(s["secrets_scan"]["mode"], "skipped")
        self.assertTrue(s["secrets_scan"]["skipped_reason"])

    def test_commit_dict_is_copied_with_pending_default(self):
        given = {"status": "committed", "sha": "abc1234", "detail": "ok"}
        s = build(commit=given)
        self.assertEqual(s["commit"]["pending_hand_edits"], [])
        self.assertNotIn("pending_hand_edits", given)


class WriteTest(unittest.TestCase):
    def test_roundtrip_and_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            self.assertIsNone(status.read(out))
            s = build()
            path = status.write(out, s)
            self.assertEqual(path, out / status.STATUS_JSON)
            self.assertEqual(status.read(out), json.loads(json.dumps(s)))
            path.write_text("{not json")
            self.assertIsNone(status.read(out))

    def test_status_written_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            with mock.patch("os.replace", side_effect=OSError("disk gone")):
                with self.assertRaises(OSError):
                    status.write(out, build())
            self.assertFalse((out / "status.json").exists())
            status.write(out, build())
            old = (out / "status.json").read_text()
            with mock.patch("os.replace", side_effect=OSError("disk gone")):
                with self.assertRaises(OSError):
                    status.write(out, build(exit_code=2))
            self.assertEqual((out / "status.json").read_text(), old)


class SeverityTest(unittest.TestCase):
    def line(self, d, scheduler=None, now=NOW):
        text = status.severity_line(d, scheduler, now)
        self.assertTrue(text.startswith(f"🛡️ sbom-audit {__version__}:"), text)
        return text

    def test_severity_order(self):
        new_kev = {"kev": {"new": ["CVE-2 npm:a@1"], "resolved": []}}
        new_ch = {"critical_high_production": {"new": ["X npm:b@1"], "resolved": []}}

        def deltas(*parts):
            d = build()["deltas"]
            for p in parts:
                d.update(p)
            return d

        everything = doc(exit_code=2, generated_at="2026-10-01T10:00:00+01:00",
                         deltas=deltas(new_kev, new_ch), assessment_proposal="reports/p.md")
        everything["counts"]["secrets"] = {"A": 1, "B": 0, "C": 0}
        self.assertIn("last run FAILED", self.line(everything))
        everything["exit_code"] = 1
        self.assertIn("days ago", self.line(everything))
        everything["generated_at"] = "2026-11-07T10:00:00+01:00"
        self.assertIn("class A", self.line(everything))
        everything["counts"]["secrets"]["A"] = 0
        self.assertIn("new KEV", self.line(everything))
        everything["deltas"] = deltas(new_ch)
        self.assertIn("new CRITICAL/HIGH", self.line(everything))
        everything["deltas"] = deltas()
        self.assertIn("/sbom-audit:assess", self.line(everything))
        everything["assessment_proposal"] = None
        self.assertEqual(self.line(everything).count("nothing new since 2026-11-07"), 1)

    def test_stale_assessment_suggests_assess(self):
        d = doc(last_assessment="2026-11-01")
        d["open"]["eol"] = ["nodejs 18"]
        self.assertIn("/sbom-audit:assess", self.line(d))

    def test_open_class_b_secret_without_assessment_suggests_assess(self):
        d = build(secrets=secrets_doc(b=1), last_assessment=None)
        self.assertEqual(d["open"]["secrets_b"], ["fp-B-0"])
        self.assertIn("/sbom-audit:assess", self.line(d, now=dt.datetime.fromisoformat(d["generated_at"])))

    def test_old_assessment_with_nothing_open_is_quiet(self):
        d = doc(last_assessment="2026-10-01")
        self.assertIn("nothing new since 2026-11-07", self.line(d))
        d["last_assessment"] = None
        self.assertIn("nothing new since 2026-11-07", self.line(d))

    def test_naive_now_does_not_raise(self):
        d = doc()
        naive = dt.datetime(2026, 11, 7, 12, 0)
        self.assertIn("sbom-audit", status.severity_line(d, {"installed": True, "last_fired": None}, naive))

    def test_class_a_line_carries_counts_and_oldest_age(self):
        d = build(secrets=secrets_doc(a=2, b=1, oldest=40))
        d["last_assessment"] = "2026-11-07"
        text = self.line(d, now=dt.datetime.fromisoformat(d["generated_at"]))
        self.assertIn("class A", text)
        self.assertIn("2 class A", text)
        self.assertIn("1 B", text)
        self.assertIn("oldest 40 days", text)

    def test_scheduler_missed_fire_line(self):
        d = doc()
        last = (NOW - dt.timedelta(days=9)).isoformat()
        text = self.line(d, {"installed": True, "last_fired": last, "next_fire": None})
        self.assertIn("scheduler did not run since", text)
        self.assertIn(last[:10], text)
        self.assertIn("scheduler did not run since", self.line(d, {"installed": True, "last_fired": None}))
        fresh = (NOW - dt.timedelta(days=1)).isoformat()
        self.assertNotIn("scheduler did not", self.line(d, {"installed": True, "last_fired": fresh}))
        self.assertNotIn("scheduler did not", self.line(d, {"installed": False, "last_fired": None}))

    def test_scheduler_overdue_line_names_the_local_day_and_how_late(self):
        d = doc()
        # the wrapper stamps UTC: Saturday 03:00 at +08:00 is Friday 19:00 UTC; the line gives the local Saturday
        now = dt.datetime.fromisoformat("2026-11-25T12:00:00+08:00")
        sched = {"installed": True, "installed_at": "2026-11-10T08:00:00Z", "last_fired": "2026-11-13T19:00:05Z",
                 "last_exit": 1, "last_error": None}
        text = self.line(d, sched, now)
        self.assertIn("scheduler did not run since 2026-11-14 (weekly run 4 days overdue)", text)
        self.assertNotIn("2026-11-13", text)
        # on time (7.7 days after the last fire, the next fire not yet due): nothing to say
        self.assertNotIn("scheduler", self.line(d, sched, dt.datetime.fromisoformat("2026-11-21T02:40:00+08:00")))
        never = {"installed": True, "installed_at": "2026-11-01T08:00:00Z", "last_fired": None}
        self.assertIn("scheduler did not run since 2026-11-01 (never fired since install)", self.line(d, never, now))

    def test_stale_run_and_missed_schedule_are_both_named(self):
        d = doc(generated_at="2026-10-20T10:00:00+01:00")
        sched = {"installed": True, "last_fired": "2026-10-17T03:00:00+01:00"}
        text = self.line(d, sched)
        self.assertIn("last run 18 days ago, scheduler did not run since 2026-10-17", text)
        self.assertIn("run /sbom-audit:run", text)
        self.assertIn("last run 18 days ago; run /sbom-audit:run", self.line(d, None))

    def test_scheduler_wrapper_failure_line(self):
        d = doc()
        fired = "2026-11-07T02:00:00Z"
        for sched in ({"installed": True, "last_fired": fired, "last_exit": 127,
                       "last_error": "plugin install path not found"},
                      {"installed": True, "last_fired": fired, "last_exit": 1, "last_error": "wrapper failed: OSError: x"},
                      {"installed": True, "last_fired": fired, "last_exit": -9, "last_error": None}):
            with self.subTest(sched=sched):
                self.assertIn("scheduled run of 2026-11-07 failed", self.line(d, sched))
        for code in (0, 1, 2):          # the CLI's own exits; 2 is reported through status.json
            self.assertNotIn("scheduled run", self.line(d, {"installed": True, "last_fired": fired, "last_exit": code}))
        started = {"installed": True, "last_fired": "2026-11-05T02:00:00Z", "last_exit": None, "last_error": None}
        self.assertIn("scheduled run of 2026-11-05 did not finish", self.line(d, started))
        self.assertNotIn("scheduled run", self.line(d, {**started, "last_fired": fired}))       # still running
        self.assertNotIn("scheduled run", self.line(d, {"installed": False, "last_fired": fired, "last_exit": 127}))

    def test_status_md_scheduler_section_computes_next_fire_and_flags_overdue(self):
        d = doc()
        now = dt.datetime.fromisoformat("2026-11-25T12:00:00+08:00")
        sched = {"installed": True, "installed_at": "2026-11-10T08:00:00Z", "last_fired": "2026-11-13T19:00:05Z",
                 "last_exit": 1, "last_error": None, "next_fire": "2026-11-14T03:00:00+08:00",
                 "platform": "darwin", "label": "dev.waiser.sbom-audit.abcd1234"}
        section = status.render_md(d, sched, now).split("## Scheduler")[1].split("## Assessment")[0]
        self.assertIn("- last fired: 2026-11-14 03:00 +0800 local (2026-11-13T19:00:05Z)", section)
        self.assertIn("- last exit: 1 (findings present)", section)
        self.assertIn("- next fire: 2026-11-28T03:00:00+08:00", section)      # computed, not the stored value
        self.assertNotIn("2026-11-14T03:00:00", section)
        self.assertIn("OVERDUE OR FAILING: scheduler did not run since 2026-11-14 (weekly run 4 days overdue)", section)
        self.assertIn("launchctl print gui/$(id -u)/dev.waiser.sbom-audit.abcd1234", section)
        on_time = status.render_md(d, sched, dt.datetime.fromisoformat("2026-11-21T02:40:00+08:00"))
        self.assertNotIn("OVERDUE", on_time)
        self.assertIn("- next fire: 2026-11-21T03:00:00+08:00", on_time)
        failed = {**sched, "last_fired": "2026-11-20T19:00:05Z", "last_exit": 127, "platform": "linux",
                  "last_error": "python 3.11 or newer not found on PATH", "plugin_install": "/p/1.3.0"}
        section = status.render_md(d, failed, now).split("## Scheduler")[1]
        self.assertIn("- last exit: 127 (the wrapper or the run failed)", section)
        self.assertIn("- last error: python 3.11 or newer not found on PATH", section)
        self.assertIn("- plugin used: /p/1.3.0", section)
        self.assertIn("scheduled run of 2026-11-21 failed (exit 127)", section)
        self.assertIn("systemctl --user list-timers", section)


class AssessmentDateTest(unittest.TestCase):
    def test_last_assessment_date_parses_latest_heading(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            self.assertIsNone(status.last_assessment_date(out))
            (out / "AUDIT.md").write_text("# Audit\n\n## Assessment 2026-10-02\nx\n\n## Summary\n"
                                          "## Assessment 2026-11-03 (rerun)\ny\n", encoding="utf-8")
            self.assertEqual(status.last_assessment_date(out), "2026-11-03")
            (out / "AUDIT.md").write_text("# Audit\nnothing\n", encoding="utf-8")
            self.assertIsNone(status.last_assessment_date(out))


class AllowedUnsupportedTest(unittest.TestCase):
    FLOOR = {"product": "python", "cycle": "3.8", "status": "minimum", "basis": "requires-python",
             "cycle_status": "EOL", "eol_date": "2024-10-07", "locations": []}

    def test_counted_apart_from_eol(self):
        s = build(make_rep(runtimes=[self.FLOOR, {"product": "nodejs", "cycle": "18", "status": "EOL",
                                                  "locations": []}]))
        self.assertEqual((s["counts"]["eol"], s["counts"]["allowed_unsupported"]), (1, 1))
        self.assertEqual(s["open"]["eol"], ["nodejs 18"])
        with tempfile.TemporaryDirectory() as tmp:
            text = status.write_md(Path(tmp), s, None).read_text(encoding="utf-8")
        self.assertIn("1 EOL, 1 allowed but unsupported (declared minimum, not counted as EOL), ", text)

    def test_go_minimum_and_old_status_files_say_nothing(self):
        go = {**self.FLOOR, "product": "go", "basis": "go.mod"}
        s = build(make_rep(runtimes=[go]))
        self.assertEqual(s["counts"]["allowed_unsupported"], 0)
        del s["counts"]["allowed_unsupported"]                  # a status.json written before the count existed
        with tempfile.TemporaryDirectory() as tmp:
            text = status.write_md(Path(tmp), s, None).read_text(encoding="utf-8")
        self.assertNotIn("allowed but unsupported", text)


class EpssCountTest(unittest.TestCase):
    EPSS = {"threshold": 0.10, "available": True, "score_date": "2026-11-23T12:00:23Z", "model_version": "v2025.03.14"}

    @staticmethod
    def scored(name, sev, max_epss, **kw):
        v = row(name, "1", sev, **kw)
        v["max_epss"] = max_epss
        return v

    def test_promoted_rows_are_counted_and_named_in_the_counts_line(self):
        rep = make_rep(vulns=[self.scored("hot", "MEDIUM", 0.5), self.scored("cold", "MEDIUM", 0.01),
                              self.scored("high", "HIGH", 0.5), self.scored("side", "MEDIUM", 0.5,
                                                                             locations=(("side", "required"),))])
        rep["epss"] = dict(self.EPSS)
        s = build(rep)
        self.assertEqual(s["counts"]["epss_promoted"], 1)
        self.assertNotIn("epss_promoted", s["open"])
        self.assertNotIn("epss_promoted", s["open_rules"])
        with tempfile.TemporaryDirectory() as tmp:
            text = status.write_md(Path(tmp), s, None).read_text(encoding="utf-8")
        self.assertIn("1 CRITICAL/HIGH in production, 1 promoted by EPSS, 0 EOL, ", text)

    def test_failed_source_counts_null_and_says_not_available(self):
        rep = make_rep(vulns=[self.scored("hot", "MEDIUM", None)])
        rep["epss"] = {**self.EPSS, "available": False}
        s = build(rep)
        self.assertIn("epss_promoted", s["counts"])
        self.assertIsNone(s["counts"]["epss_promoted"])
        self.assertIsNone(json.loads(json.dumps(s))["counts"]["epss_promoted"])
        again = build(rep, previous=s)                       # a second run compares with the first: no crash
        self.assertEqual(again["deltas"], build(make_rep(vulns=[self.scored("hot", "MEDIUM", None)]),
                                                previous=s)["deltas"])
        with tempfile.TemporaryDirectory() as tmp:
            text = status.write_md(Path(tmp), again, None).read_text(encoding="utf-8")
        self.assertIn("0 CRITICAL/HIGH in production, EPSS not available, 0 EOL, ", text)
        self.assertNotIn("None promoted", text)
        self.assertNotIn("0 promoted", text)

    def test_session_hook_reads_a_null_count(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "session_start_hook", Path(__file__).resolve().parents[1] / "plugin" / "templates" / "session-hook" / "session-start.py")
        hook = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hook)
        rep = make_rep(vulns=[self.scored("hot", "MEDIUM", None)])
        rep["epss"] = {**self.EPSS, "available": False}
        s = json.loads(json.dumps(build(rep)))
        self.assertNotIn("EPSS", "\n".join(hook.facts("line", s)))

    def test_no_epss_count_without_the_epss_step(self):
        s = build(make_rep(vulns=[self.scored("hot", "MEDIUM", 0.5)]))
        self.assertNotIn("epss_promoted", s["counts"])
        with tempfile.TemporaryDirectory() as tmp:
            text = status.write_md(Path(tmp), s, None).read_text(encoding="utf-8")
        counts_line = next(line for line in text.splitlines() if line.startswith("Counts:"))
        self.assertNotIn("EPSS", counts_line)
        self.assertIn("0 CRITICAL/HIGH in production, 0 EOL, ", counts_line)


class MarkdownTest(unittest.TestCase):
    def test_md_sections_order(self):
        s = build(make_rep(sources={"osv": {"queried": 3, "failed": []}}), secrets=secrets_doc(a=1, oldest=3),
                  commit={"status": "committed", "sha": "abc1234", "detail": "ok",
                          "pending_hand_edits": ["README.md"]})
        with tempfile.TemporaryDirectory() as tmp:
            text = status.write_md(Path(tmp), s, None).read_text(encoding="utf-8")
            self.assertEqual(Path(tmp, status.STATUS_FILE).read_text(encoding="utf-8"), text)
        order = ["## Since last run", "## Secrets", "## Sources", "## Commit", "## Scheduler",
                 "## Assessment", "## Pending hand edits"]
        positions = [text.index(h) for h in order]
        self.assertEqual(positions, sorted(positions))
        self.assertLess(text.index("🛡️ sbom-audit"), positions[0])
        self.assertIn("mac", text.split("## Since last run")[0])
        self.assertIn("not installed", text.split("## Scheduler")[1])
        self.assertIn("README.md", text.split("## Pending hand edits")[1])
        sched = {"installed": True, "last_fired": "2026-11-06T03:00:00+01:00", "next_fire": None}
        with tempfile.TemporaryDirectory() as tmp:
            text = status.write_md(Path(tmp), s, sched).read_text(encoding="utf-8")
        self.assertIn("2026-11-06", text.split("## Scheduler")[1].split("## Assessment")[0])
        s["exit_code"] = None
        with tempfile.TemporaryDirectory() as tmp:
            text = status.write_md(Path(tmp), s, None).read_text(encoding="utf-8")
        self.assertNotIn("exit None", text)
        self.assertIn("exit –", text)
        self.assertIn("0 vulnerable package versions, 0 KEV", text)


class OldestAgeAndTmpTests(unittest.TestCase):
    def test_oldest_open_age_is_unknown_when_no_open_finding_carries_an_age(self):
        aged = build(secrets=secrets_doc(a=1, oldest=40))
        self.assertEqual(aged["secrets_scan"]["oldest_open_days"], 40)
        unaged = secrets_doc(a=1, b=1, oldest=40)
        for f in unaged["findings"]:
            f["age_days"] = None
        s = build(secrets=unaged)
        self.assertIsNone(s["secrets_scan"]["oldest_open_days"])
        self.assertEqual(build(secrets=secrets_doc())["secrets_scan"]["oldest_open_days"], 0)
        self.assertEqual(build(secrets=None)["secrets_scan"]["oldest_open_days"], 0)
        s["last_assessment"] = "2026-11-07"
        text = status.severity_line(s, None, dt.datetime.fromisoformat(s["generated_at"]))
        self.assertIn("1 class A, 1 B secrets open, oldest age unknown", text)
        self.assertNotIn("None", text)
        with tempfile.TemporaryDirectory() as tmp:
            md = status.write_md(Path(tmp), s, None).read_text(encoding="utf-8")
        self.assertIn("- oldest open: age unknown", md)
        with tempfile.TemporaryDirectory() as tmp:
            md = status.write_md(Path(tmp), aged, None).read_text(encoding="utf-8")
        self.assertIn("- oldest open: 40 days", md)

    def test_status_tmp_file_carries_the_pid_and_never_lingers(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            with mock.patch("sbomaudit.cache.os.replace", wraps=os.replace) as replace:
                status.write(out, build())
            tmp_path = Path(replace.call_args[0][0])
            self.assertEqual(tmp_path.name, f"status.json.{os.getpid()}.tmp")
            self.assertEqual(tmp_path.parent, out)
            with mock.patch("sbomaudit.cache.os.replace", side_effect=OSError("disk gone")):
                with self.assertRaises(OSError):
                    status.write(out, build(exit_code=2))
            self.assertEqual(sorted(p.name for p in out.iterdir()), ["status.json"])



# --------------------------------------------------------------------------- host audit

def host(status_="ok", critical=(), findings=None, checked_at="2026-11-07T09:00:00+00:00"):
    findings = findings if findings is not None else [
        {"id": c, "group": "kev", "critical": True, "text": "x"} for c in critical]
    return {"production": True, "projects": [], "status": status_, "address": "203.0.113.10", "error": None,
            "checked_at": checked_at, "attempted_at": "2026-11-07T09:00:00+00:00", "findings": findings,
            "critical": list(critical)}


def hosts_doc(hosts, last_checked="2026-11-07T09:00:00+00:00", skipped=None):
    return {"schema": 1, "generated_at": "2026-11-07T09:00:00+00:00", "skipped": skipped,
            "last_checked": last_checked, "collector_shipped": "1", "hosts": hosts}


class HostsStatusTest(unittest.TestCase):
    def test_hosts_critical_open_set_and_deltas(self):
        self.assertIn("hosts_critical", status.OPEN_KEYS)
        self.assertEqual(status.open_sets(make_rep(), None)["hosts_critical"], [])
        first = hosts_doc({"web-1": host(critical=["kev:CVE-1:pkg@1"]), "box-a": host(critical=["hostkey:changed"]),
                           "ok-1": host()})
        sets = status.open_sets(make_rep(), None, first)
        self.assertEqual(sets["hosts_critical"], ["box-a hostkey:changed", "web-1 kev:CVE-1:pkg@1"])
        prev = build(hosts=first)
        later = hosts_doc({"web-1": host(critical=["kev:CVE-1:pkg@1"]), "box-a": host(critical=["patch:timer-inactive"])})
        now = build(hosts=later, previous=prev)
        self.assertEqual(now["deltas"]["hosts_critical"],
                         {"new": ["box-a patch:timer-inactive"], "resolved": ["box-a hostkey:changed"]})
        self.assertEqual(now["counts"]["hosts"], {"critical": 2, "critical_hosts": ["box-a", "web-1"], "failed": 0,
                                                  "failed_hosts": [], "checked": 2, "unsupported": 0,
                                                  "last_checked": "2026-11-07", "skipped": None})

    def test_counts_hosts_none_when_hosts_not_active(self):
        s = build()
        self.assertIsNone(s["counts"]["hosts"])
        self.assertEqual(s["open"]["hosts_critical"], [])

    def test_accepted_findings_do_not_count_but_failed_hosts_carry_theirs(self):
        accepted = host(critical=["kev:CVE-1:p@1"], findings=[
            {"id": "kev:CVE-1:p@1", "group": "kev", "critical": False, "accepted": True, "text": "x"}])
        failed = host("failed", critical=["hostkey:changed"])
        s = build(hosts=hosts_doc({"box-a": accepted, "web-1": failed}))
        self.assertEqual(s["open"]["hosts_critical"], ["web-1 hostkey:changed"])
        self.assertEqual(s["counts"]["hosts"]["critical"], 1)
        self.assertEqual(s["counts"]["hosts"]["critical_hosts"], ["web-1"])
        self.assertEqual((s["counts"]["hosts"]["failed"], s["counts"]["hosts"]["checked"]), (1, 1))

    def test_missing_or_unknown_status_counts_as_failed(self):
        no_status = host()
        del no_status["status"]
        s = build(hosts=hosts_doc({"a": no_status, "b": host("weird"), "c": host("ok"), "d": host("unsupported")}))
        h = s["counts"]["hosts"]
        self.assertEqual((h["failed"], h["checked"]), (2, 1))
        self.assertEqual(h["failed_hosts"], ["a", "b"])

    def test_missing_or_corrupt_hosts_document_is_never_checked(self):
        for doc_ in ({}, {"hosts": "junk", "last_checked": 5}, hosts_doc({}, last_checked=None)):
            h = build(hosts=doc_)["counts"]["hosts"]
            self.assertIsNone(h["last_checked"])
            self.assertEqual((h["critical"], h["failed"], h["checked"]), (0, 0, 0))

    def test_skipped_document_carries_the_reason_and_previous_date(self):
        s = build(hosts=hosts_doc({"a": host()}, last_checked="2026-11-01T03:00:00+00:00",
                                  skipped="no audit key on this machine"))
        self.assertEqual(s["counts"]["hosts"]["skipped"], "no audit key on this machine")
        self.assertEqual(s["counts"]["hosts"]["last_checked"], "2026-11-01")
        s = build(hosts=hosts_doc({}, last_checked=None, skipped="no audit key on this machine"))
        self.assertIsNone(s["counts"]["hosts"]["last_checked"])

    def md(self, s):
        with tempfile.TemporaryDirectory() as tmp:
            return status.write_md(Path(tmp), s, None).read_text(encoding="utf-8")

    def test_hosts_line_in_status_md(self):
        s = build(hosts=hosts_doc({"web-1": host(critical=["kev:CVE-1:p@1"]), "box-a": host(critical=["x"]),
                                   "dead": host("failed"), "fine": host()}))
        text = self.md(s)
        self.assertIn("- hosts: 3 checked, 1 failed, 2 critical (box-a, web-1); see HOSTS.md", text)
        order = [text.index(h) for h in ("## Secrets", "- hosts:", "## Sources")]
        self.assertEqual(order, sorted(order))
        skipped = build(hosts=hosts_doc({}, last_checked="2026-11-01T03:00:00+00:00",
                                        skipped="no audit key on this machine"))
        self.assertIn("- hosts: skipped (no audit key on this machine); last checked 2026-11-01", self.md(skipped))
        never = build(hosts=hosts_doc({}, last_checked=None, skipped="no audit key on this machine"))
        self.assertIn("last checked never", self.md(never))
        self.assertNotIn("- hosts:", self.md(build()))

    def line(self, d, now=NOW):
        return status.severity_line(d, None, now)

    def test_severity_hosts_critical_after_class_a(self):
        d = doc()
        d["counts"]["hosts"] = {"critical": 2, "critical_hosts": ["box-a", "web-1"], "failed": 0, "checked": 2,
                                "last_checked": "2026-11-07", "skipped": None}
        d["deltas"]["kev"]["new"] = ["CVE-2 npm:a@1"]
        self.assertIn("2 critical host findings open (box-a, web-1); see HOSTS.md", self.line(d))
        d["counts"]["secrets"] = {"A": 1, "B": 0, "C": 0}
        self.assertIn("class A", self.line(d))
        d["counts"]["secrets"]["A"] = 0
        d["exit_code"] = 2
        self.assertIn("last run FAILED", self.line(d))
        d["exit_code"] = 0
        d["counts"]["hosts"]["critical"] = 0
        self.assertIn("new KEV", self.line(d))

    def test_severity_failed_host_after_hosts_critical(self):
        d = doc()
        d["counts"]["hosts"] = {"critical": 0, "critical_hosts": [], "failed": 2, "failed_hosts": ["box-a", "web-1"],
                                "checked": 1, "last_checked": "2026-11-07", "skipped": None}
        d["deltas"]["kev"]["new"] = ["CVE-2 npm:a@1"]
        self.assertIn("2 host(s) failed the last check (box-a, web-1); see HOSTS.md", self.line(d))
        d["counts"]["hosts"].update(critical=1, critical_hosts=["box-a"])
        self.assertIn("1 critical host findings open (box-a)", self.line(d))
        d["counts"]["hosts"].update(critical=0, critical_hosts=[])
        d["counts"]["hosts"]["skipped"] = "no audit key on this machine"    # placeholders of a skipped run
        self.assertIn("new KEV", self.line(d))
        d["counts"]["hosts"].pop("failed_hosts")                            # a status written before 1.1.0's fix
        d["counts"]["hosts"]["skipped"] = None
        self.assertIn("2 host(s) failed the last check; see HOSTS.md", self.line(d))

    def test_refresh_secrets_keeps_deltas_relative_to_the_run(self):
        def finding(fp, cls, state="open", age=5):
            return {"fingerprint": fp, "class": cls, "status": state, "age_days": age}
        scan = {"scan": {"mode": "full", "repos": 2}, "engine": {"name": "gitleaks"}}
        first = build(secrets={**scan, "findings": [finding("a1", "A", age=90), finding("b1", "B")]})
        second = build(previous=first, secrets={**scan, "findings": [
            finding("a1", "A", age=90), finding("a2", "A"), finding("b1", "B")]})
        self.assertEqual(second["deltas"]["secrets_a"], {"new": ["a2"], "resolved": []})
        decided = {**scan, "findings": [finding("a1", "A", "rotated", 90), finding("a2", "A", "false_positive"),
                                        finding("b1", "B")]}
        got = status.refresh_secrets(second, decided)
        self.assertEqual(got["counts"]["secrets"], {"A": 0, "B": 1, "C": 0})
        self.assertEqual(got["open"]["secrets_a"], [])
        # a2 was new in this run and is decided now: no longer new, and resolved like a1
        self.assertEqual(got["deltas"]["secrets_a"], {"new": [], "resolved": ["a1", "a2"]})
        self.assertEqual(got["deltas"]["secrets_b"], second["deltas"]["secrets_b"])
        self.assertEqual(got["secrets_scan"], {**second["secrets_scan"], "oldest_open_days": 5})
        self.assertEqual({k: v for k, v in got["counts"].items() if k != "secrets"},
                         {k: v for k, v in second["counts"].items() if k != "secrets"})
        self.assertIs(status.refresh_secrets(second, None), second)

    def test_manual_check_with_a_failed_host_is_not_nothing_new(self):
        d = doc(**{"counts": build(hosts=hosts_doc({"box-a": host()}))["counts"]})
        self.assertIn("nothing new since", self.line(d))
        d = status.refresh_hosts(d, hosts_doc({"box-a": host("failed")}))
        self.assertEqual(d["counts"]["hosts"]["failed"], 1)
        self.assertIn("1 host(s) failed the last check (box-a); see HOSTS.md", self.line(d))

    def test_host_dates_are_local_days_not_the_utc_text(self):
        """M4: hosts.json stamps UTC; the status (and the hook) give the day in the local zone, like
        `generated_at`. 20:00 UTC on 9 Nov is 10 Nov at UTC+8 and still 9 Nov at UTC-5."""
        import importlib.util
        import time
        if not hasattr(time, "tzset"):
            self.skipTest("time.tzset is POSIX only")
        spec = importlib.util.spec_from_file_location(
            "session_start_hook", Path(__file__).resolve().parents[1] / "plugin" / "templates" / "session-hook" / "session-start.py")
        hook = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hook)

        def in_zone(tz, fn):
            old = os.environ.get("TZ")
            os.environ["TZ"] = tz
            time.tzset()
            try:
                return fn()
            finally:
                if old is None:
                    os.environ.pop("TZ", None)
                else:
                    os.environ["TZ"] = old
                time.tzset()

        stamp = "2026-11-09T20:00:00+00:00"
        counts = lambda: build(hosts=hosts_doc({"a": host()}, last_checked=stamp))["counts"]["hosts"]
        self.assertEqual(in_zone("Asia/Shanghai", counts)["last_checked"], "2026-11-10")
        self.assertEqual(in_zone("America/New_York", counts)["last_checked"], "2026-11-09")
        # the age check reads the day in `now`'s zone, also for a full timestamp, in status and hook alike
        d = doc()
        d["counts"]["hosts"] = {"critical": 0, "critical_hosts": [], "failed": 0, "failed_hosts": [], "checked": 1,
                                "last_checked": "2026-11-01T20:00:00+00:00", "skipped": None}
        east = dt.datetime(2026, 11, 10, 9, 0, tzinfo=dt.timezone(dt.timedelta(hours=8)))   # 9 days after 2 Nov
        west = dt.datetime(2026, 11, 9, 20, 0, tzinfo=dt.timezone(dt.timedelta(hours=-5)))   # 8 days after 1 Nov
        for fn in (status._hosts_not_checked, hook._hosts_not_checked):
            with self.subTest(fn=fn.__module__):
                self.assertEqual(fn(d, east), None)
                self.assertEqual(fn(d, east + dt.timedelta(days=1)), "hosts not checked since 2026-11-02")
                self.assertEqual(fn(d, west), None)
                self.assertEqual(fn(d, west + dt.timedelta(days=1)), "hosts not checked since 2026-11-01")
        for fn in (status._local_day, hook._local_day):
            self.assertIsNone(fn("not a date"))
            self.assertIsNone(fn(None))
            self.assertEqual(fn("2026-10-29"), "2026-10-29")

    def test_severity_hosts_not_checked(self):
        d = doc()
        d["counts"]["hosts"] = {"critical": 0, "critical_hosts": [], "failed": 0, "checked": 1,
                                "last_checked": None, "skipped": None}
        self.assertIn("hosts not checked since never", self.line(d))
        d["counts"]["hosts"]["last_checked"] = "2026-10-29"       # 9 days
        self.assertIn("hosts not checked since 2026-10-29", self.line(d))
        d["counts"]["hosts"]["last_checked"] = "2026-10-30"       # 8 days: still fine
        self.assertIn("nothing new since", self.line(d))
        d["counts"]["hosts"]["skipped"] = "no audit key on this machine"
        d["counts"]["hosts"]["last_checked"] = "2026-10-01"
        self.assertIn("hosts not checked since 2026-10-01", self.line(d))
        d["deltas"]["critical_high_production"]["new"] = ["X npm:b@1"]
        self.assertIn("new CRITICAL/HIGH", self.line(d))
        d["deltas"]["critical_high_production"]["new"] = []
        d["open"]["eol"] = ["nodejs 18"]
        d["last_assessment"] = None
        self.assertIn("hosts not checked", self.line(d))          # before assessment stale
        self.assertEqual(status.HOSTS_NOT_CHECKED_DAYS, 8)

    def test_old_status_without_hosts_still_renders(self):
        d = doc()
        del d["counts"]["hosts"]
        del d["open"]["hosts_critical"]
        del d["deltas"]["hosts_critical"]
        self.assertIn("nothing new since", self.line(d))
        text = self.md(d)
        self.assertNotIn("hosts", text.replace("hosts_critical", ""))
        self.assertNotIn("hosts_critical", text)


class PipelineHostsDocumentTest(unittest.TestCase):
    """`pipeline._hosts_for_status`: the document `run` hands to `status.build`."""

    def cfg(self, tmp, key_exists=True, active=True):
        key = Path(tmp) / "key"
        if key_exists:
            key.write_text("k")
        servers = {"box-a": config.HostOpts(address="203.0.113.10")} if active else {}
        return config.Config(out=Path(tmp) / "security", root=Path(tmp), mode="portfolio",
                             hosts=config.HostsOpts(enabled=True, key=key, servers=servers))

    def test_none_when_hosts_not_active(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(pipeline._hosts_for_status(self.cfg(tmp, active=False)))
            self.assertIsNone(pipeline._hosts_for_status(config.Config(out=Path(tmp), root=Path(tmp), mode="single")))

    def test_missing_and_corrupt_hosts_json_read_as_never_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.cfg(tmp)
            cfg.out.mkdir()
            self.assertEqual(status.build(make_rep(), secrets=None, previous=None, duration_s=1, exit_code=0,
                                          run_host="m", mode="full", hosts=pipeline._hosts_for_status(cfg))
                             ["counts"]["hosts"]["last_checked"], None)
            (cfg.out / hosts_store.HOSTS_JSON).write_text("{not json")
            doc_ = pipeline._hosts_for_status(cfg)
            self.assertIsNone(doc_.get("last_checked"))
            self.assertEqual(doc_["hosts"]["box-a"]["status"], "failed")

    def test_skipped_result_marks_the_previous_document_skipped_and_keeps_the_last_date(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.cfg(tmp, key_exists=False)
            cfg.out.mkdir()
            (cfg.out / hosts_store.HOSTS_JSON).write_text(json.dumps(hosts_doc({"box-a": host()})))
            skipped = {"skipped": "no audit key on this machine", "hosts": {}, "last_checked": "2099-01-01"}
            s = build(hosts=pipeline._hosts_for_status(cfg, skipped))
            self.assertEqual(s["counts"]["hosts"]["skipped"], "no audit key on this machine")
            self.assertEqual(s["counts"]["hosts"]["last_checked"], "2026-11-07")    # hosts.json, not the result

    def test_the_missing_key_is_not_checked_here_the_returned_document_decides(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.cfg(tmp, key_exists=False)
            cfg.out.mkdir()
            (cfg.out / hosts_store.HOSTS_JSON).write_text(json.dumps(hosts_doc({"box-a": host()})))
            self.assertIsNone(pipeline._hosts_for_status(cfg).get("skipped"))
            fresh = hosts_doc({"box-a": host()}, last_checked="2026-11-09T08:00:00Z")
            doc_ = pipeline._hosts_for_status(cfg, fresh)
            self.assertIsNone(doc_.get("skipped"))
            self.assertEqual(doc_["last_checked"], "2026-11-09T08:00:00Z")

    def test_fresh_result_fails_closed_on_missing_and_malformed_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.cfg(tmp)
            for hosts in ({}, {"box-a": "junk"}, "junk"):
                with self.subTest(hosts=hosts):
                    h = build(hosts=pipeline._hosts_for_status(cfg, hosts_doc(hosts)))["counts"]["hosts"]
                    self.assertGreaterEqual(h["failed"], 1)

    def test_malformed_document_fails_closed(self):
        for body in ({"hosts": "junk", "last_checked": "2026-11-09"},
                     {"hosts": {}, "last_checked": "2026-11-09"},
                     {"hosts": {"box-b": host()}, "last_checked": "2026-11-09"},
                     {"hosts": {"box-a": "junk"}, "last_checked": "2026-11-09"}):
            with self.subTest(body=body), tempfile.TemporaryDirectory() as tmp:
                cfg = self.cfg(tmp)
                cfg.out.mkdir()
                (cfg.out / hosts_store.HOSTS_JSON).write_text(json.dumps(body))
                h = build(hosts=pipeline._hosts_for_status(cfg))["counts"]["hosts"]
                self.assertGreaterEqual(h["failed"], 1)


class HostsFailClosedAndQuietTest(unittest.TestCase):
    def md(self, s):
        with tempfile.TemporaryDirectory() as tmp:
            return status.write_md(Path(tmp), s, None).read_text(encoding="utf-8")

    def test_non_dict_hosts_field_reads_as_never_checked(self):
        h = build(hosts={"hosts": "junk", "last_checked": "2026-11-09T01:00:00+00:00"})["counts"]["hosts"]
        self.assertIsNone(h["last_checked"])
        text = status.severity_line(doc(counts={**doc()["counts"], "hosts": h}), None, NOW)
        self.assertIn("hosts not checked since never", text)

    def test_non_dict_host_entry_counts_as_failed(self):
        h = build(hosts=hosts_doc({"box-a": "junk", "web-1": None, "ok-1": host()}))["counts"]["hosts"]
        self.assertEqual((h["failed"], h["checked"]), (2, 1))

    def test_no_empty_hosts_delta_line_when_hosts_inactive(self):
        s = build(previous=build())
        self.assertNotIn("hosts_critical", self.md(s))
        active = build(hosts=hosts_doc({"box-a": host()}), previous=build())
        self.assertIn("- hosts_critical: 0 new, 0 resolved", self.md(active))
        s["deltas"]["hosts_critical"]["new"] = ["box-a x"]            # real change always shown
        self.assertIn("- hosts_critical: 1 new", self.md(s))

    def test_no_empty_parentheses_with_zero_critical(self):
        text = self.md(build(hosts=hosts_doc({"box-a": host(), "web-1": host()})))
        self.assertIn("- hosts: 2 checked, 0 failed, 0 critical; see HOSTS.md", text)
        self.assertNotIn("()", text)

    def test_unsupported_hosts_are_counted_and_shown(self):
        s = build(hosts=hosts_doc({"box-a": host(), "old-1": host("unsupported")}))
        h = s["counts"]["hosts"]
        self.assertEqual((h["unsupported"], h["checked"], h["failed"]), (1, 1, 0))
        self.assertIn("- hosts: 1 checked, 0 failed, 0 critical, 1 unsupported; see HOSTS.md", self.md(s))
        self.assertNotIn("unsupported", self.md(build(hosts=hosts_doc({"box-a": host()}))))
        d = doc(counts={**doc()["counts"], "hosts": h})                 # no severity rule for it
        self.assertIn("nothing new since", status.severity_line(d, None, NOW))


if __name__ == "__main__":
    unittest.main()
