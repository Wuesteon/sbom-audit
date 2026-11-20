"""REPORT.html: the management report built from the JSON of a run."""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import cli, config, management
from sbomaudit.secrets import store as secrets_store

FIXTURE = Path(__file__).resolve().parent.parent / "evals" / "fixtures" / "security"
PLANTED = "PLANTED-NOT-A-SECRET-7f3a9c"   # stands in for a value that must never reach the report


def text_of(page: str) -> str:
    """The visible text, tags removed, whitespace collapsed."""
    body = page.split("</style>", 1)[1]
    return " ".join(re.sub(r"<[^>]+>", " ", body).split())


def vuln(name, sev, project, kev=False):
    return {"ecosystem": "npm", "name": name, "version": "1.0.0", "scope": "required", "direct_anywhere": True,
            "locations": [{"project": project, "branch": "main", "manifest": "package-lock.json", "direct": True,
                           "scope": "required"}],
            "vulns": [{"id": f"GHSA-{name}", "cves": [], "summary": "s", "severity": sev, "kev": kev,
                       "fixed_in": "1.2.0"}],
            "max_severity": sev, "kev": kev}


def write_json(path: Path, doc) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")


def full_folder(out: Path, *, project="shop", title="lodash 1.0.0") -> Path:
    """A run with every source answered, one KEV, one class A secret, a VEX and a secrets decision."""
    out.mkdir(parents=True, exist_ok=True)
    (out / config.CONFIG_NAME).write_text('[projects]\n"shop" = { production = true }\n', encoding="utf-8")
    write_json(out / "inventory.json", {
        "generated_at": "2026-11-10T09:58:00Z", "branches": ["main"],
        "inventories": [{"project": project, "branch": "main", "commit": "abcdef1234", "errors": []}],
        "skipped": [{"project": "old-thing", "reason": "archived"}]})
    write_json(out / "audit.json", {
        "generated_at": "2026-11-10T10:00:00Z", "production_projects": [project],
        "vulnerabilities": [vuln("lodash", "HIGH", project, kev=True)],
        "runtimes": [{"product": "nodejs", "cycle": "16", "status": "EOL", "locations": []},
                     {"product": "python", "cycle": "3.9", "status": "EOL soon", "locations": []}],
        "unpinned_images": [], "suppressed": [{"name": "x"}],
        "sources": {"osv-scanner": {"scanned": 1, "failed": []}, "cisa_kev": {"loaded": 1200, "flagged": 1},
                    "endoflife": {"queried": 2, "unknown": [], "failed": []},
                    "registries": {"queried": 3, "major_behind": 0, "failed": []},
                    "openvex": {"statements": 1, "suppressed": 1}}})
    write_json(out / "secrets.json", {
        "generated_at": "2026-11-10T09:59:00Z", "engine": {"name": "gitleaks", "version": "8.21.0"},
        "scan": {"mode": "full", "repos": 1, "failed": []},
        "findings": [{"fingerprint": "fp-aaaa", "repo": project, "file": ".env", "line": 3, "rule_id": "stripe",
                      "provider": "stripe", "class": "A", "status": "open", "age_days": 2,
                      "first_seen": "2026-11-08", "branches": ["main"], "commit": "abc", "match": PLANTED},
                     {"fingerprint": "fp-bbbb", "repo": project, "file": "test/key.pem", "line": 1,
                      "rule_id": "pk", "class": "B", "status": "test_fixture", "first_seen": "2026-10-01"}]})
    write_json(out / "status.json", {
        "generated_at": "2026-11-10T10:01:00Z", "plugin_version": "1.2.1", "first_run": False,
        "counts": {"projects": 1, "branches": 1, "kev": 1, "critical_high_production": 1, "eol": 1,
                   "secrets": {"A": 1, "B": 0, "C": 0}, "hosts": None},
        "deltas": {"kev": {"new": ["GHSA-lodash"], "resolved": []},
                   "critical_high_production": {"new": [], "resolved": ["GHSA-old"]},
                   "eol": {"new": [], "resolved": []}, "secrets_a": {"new": ["fp-aaaa"], "resolved": []},
                   "secrets_b": {"new": [], "resolved": []}},
        "failed_sources": [],
        "secrets_scan": {"mode": "full", "engine": "gitleaks 8.21.0", "repos": 1, "skipped_reason": None}})
    write_json(out / "issues.json", {
        "generated_at": "2026-11-10T10:01:00Z", "incomplete": [],
        "issues": [{"id": "s1", "kind": "secret", "priority": 1, "reason": "secret_a", "production": True,
                    "title": title, "where": {"project": project, "branches": ["main"], "path": ".env", "line": 3},
                    "fix": {"action": "rotate", "target": None}, "first_seen": "2026-11-08"},
                   {"id": "v1", "kind": "vulnerability", "priority": 2, "reason": "kev", "severity": "HIGH",
                    "production": True, "title": "lodash 1.0.0",
                    "where": {"project": project, "branches": ["main", "dev", "a", "b"], "path": "package-lock.json"},
                    "fix": {"action": "upgrade", "target": "1.2.0"}, "first_seen": "2026-11-10"},
                   {"id": "e1", "kind": "eol", "priority": 5, "reason": "eol", "title": "nodejs 16",
                    "where": {"project": project}, "fix": {"action": "upgrade_runtime", "target": "22"}}]})
    write_json(out / "vex" / f"{project}.openvex.json", {
        "author": "sec@example.org", "timestamp": "2026-11-01T10:00:00Z",
        "statements": [{"vulnerability": {"name": "GHSA-xyz"},
                        "products": [{"@id": "pkg:npm/shop", "subcomponents": [{"@id": "pkg:npm/minimist@1.0.0"}]}],
                        "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path",
                        "impact_statement": "only used at build time", "timestamp": "2026-11-02T08:00:00Z"}]})
    secrets_store.add_decision(out, "fp-bbbb", "test_fixture", "fixture key, never deployed", date="2026-10-02")
    return out


class ManagementTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def fixture_copy(self, name: str = "security") -> Path:
        out = self.tmp / name
        shutil.copytree(FIXTURE, out)
        (out / management.REPORT_FILE).unlink(missing_ok=True)
        return out


class TestFixture(ManagementTestCase):
    def test_generates_from_the_demo_fixture(self):
        out = self.fixture_copy()
        written = management.write(out)
        self.assertEqual([p.relative_to(out).as_posix() for p in written],
                         ["REPORT.html", "reports/2026-11-07-report.html"])
        page = (out / "REPORT.html").read_text(encoding="utf-8")
        self.assertEqual(page, (out / "reports" / "2026-11-07-report.html").read_text(encoding="utf-8"))
        text = text_of(page)
        for heading in ("1. Overall state", "2. What needs action now", "3. Decisions on record",
                        "4. Coverage and limits", "5. Evidence mapping"):
            self.assertIn(heading, text)
        self.assertIn("lodash 4.17.20", text)
        self.assertIn("Upgrade to 4.17.21", text)
        self.assertIn("evidence tooling, not legal advice", text.lower())
        self.assertIn("first run: no comparison", text)

    def test_committed_sample_is_current(self):
        out = self.fixture_copy()
        management.write(out, dated=False)
        self.assertEqual((out / "REPORT.html").read_text(encoding="utf-8"),
                         (FIXTURE / "REPORT.html").read_text(encoding="utf-8"),
                         "evals/fixtures/security/REPORT.html is stale: run evals/fixtures/build_security.py")

    def test_self_contained(self):
        page = management.render(management.load(self.fixture_copy()))
        self.assertNotIn("<script", page)
        self.assertNotIn("<link", page)
        self.assertNotIn("<img", page)
        self.assertNotRegex(page, r"(src|href)=\"?https?:")
        self.assertNotIn("@import", page)
        self.assertNotIn("url(", page)
        self.assertIn("@page { size: A4", page)

    def test_set_counted_by_other_rules_is_not_comparable(self):
        out = full_folder(self.tmp / "security")
        doc = json.loads((out / "status.json").read_text())
        doc["deltas"]["critical_high_production"] = {"new": [], "resolved": [], "not_comparable": "other rules"}
        (out / "status.json").write_text(json.dumps(doc))
        for lang, needle in (("en", "not comparable"), ("de", "nicht vergleichbar")):
            text = text_of(management.render(management.load(out), lang=lang))
            self.assertIn(needle, text)
            self.assertNotIn("1 resolved", text)          # the fixture's crit delta reported 1 resolved

    def test_deterministic(self):
        out = self.fixture_copy()
        self.assertEqual(management.render(management.load(out)), management.render(management.load(out)))


class TestFullRun(ManagementTestCase):
    def test_numbers_deltas_and_decisions(self):
        out = full_folder(self.tmp / "security")
        text = text_of(management.render(management.load(out)))
        self.assertIn("Action needed now.", text)
        self.assertIn("1 package version(s) carry a vulnerability that CISA lists", text)
        self.assertIn("1 leaked credential(s) of class A", text)
        self.assertIn("1 new, 0 resolved", text)
        self.assertIn("0 new, 1 resolved", text)
        self.assertIn("1 more reach end of life soon", text)
        self.assertNotIn("allowed but unsupported", text)
        self.assertIn("P1", text)
        self.assertIn("Rotate the credential at the provider", text)
        self.assertIn("branches: main, dev, a +1 more", text)
        self.assertIn("1 × End of life", text)
        # decisions
        self.assertIn("GHSA-xyz", text)
        self.assertIn("vulnerable code not in execute path", text)
        self.assertIn("only used at build time", text)
        self.assertIn("sec@example.org", text)
        self.assertIn("fp-bbbb", text)
        self.assertIn("fixture key, never deployed", text)
        self.assertIn("test/key.pem:1", text)
        self.assertIn("records no author", text)
        # coverage
        self.assertIn("old-thing (archived)", text)
        self.assertIn("full scan with gitleaks 8.21.0 over 1 repositories", text)
        self.assertIn("2026-11-10T09:59:00Z", text)

    def test_declared_minimum_is_not_counted_as_eol_but_noted(self):
        out = full_folder(self.tmp / "security")
        audit = json.loads((out / "audit.json").read_text())
        audit["runtimes"].append({"product": "python", "cycle": "3.8", "status": "minimum",
                                  "basis": "requires-python", "cycle_status": "EOL", "eol_date": "2024-10-07",
                                  "locations": []})
        write_json(out / "audit.json", audit)
        doc = json.loads((out / "issues.json").read_text())
        doc["issues"].append({"id": "m1", "kind": "eol", "priority": 6, "reason": "eol_minimum",
                              "title": "requires-python >=3.8 allows Python 3.8", "where": {"project": "shop"},
                              "fix": {"action": "raise_minimum", "target": None}})
        write_json(out / "issues.json", doc)
        metrics = {m["key"]: m for m in management._metrics(management.load(out), management.STRINGS["en"])}
        self.assertEqual(metrics["eol"]["value"], 1)
        text = text_of(management.render(management.load(out)))
        self.assertIn("1 more reach end of life soon; 1 allowed but unsupported", text)
        self.assertIn("1 × Declared minimum allows an end-of-life version", text)
        de = text_of(management.render(management.load(out), lang="de"))
        self.assertIn("1 erlaubt, aber ohne Support", de)

    def test_direct_and_transitive_are_counted_and_direct_listed_first(self):
        out = full_folder(self.tmp / "security")
        doc = json.loads((out / "issues.json").read_text())
        # an issues.json in the old order: the transitive issue before the direct one of the same priority
        doc["issues"][1:2] = [
            {"id": "t1", "kind": "vulnerability", "priority": 3, "reason": "critical_high_production",
             "severity": "CRITICAL", "production": True, "title": "deep 1.0.0", "where": {"project": "shop"},
             "details": {"direct": False, "dev_only": False}, "fix": {"action": "upgrade", "target": "2.0.0"}},
            {"id": "d1", "kind": "vulnerability", "priority": 3, "reason": "critical_high_production",
             "severity": "HIGH", "production": True, "title": "top 1.0.0", "where": {"project": "shop"},
             "details": {"direct": True, "dev_only": False}, "fix": {"action": "upgrade", "target": "2.0.0"}},
            {**doc["issues"][1], "details": {"direct": False, "dev_only": True}}]
        write_json(out / "issues.json", doc)
        en = text_of(management.render(management.load(out)))
        self.assertIn("Vulnerability issues at priority 2 and 3 (KEV, or CRITICAL/HIGH in production or a supported "
                      "release): 3, of which 1 in direct dependencies and 2 in transitive ones.", en)
        self.assertIn("Transitive does not mean harmless", en)
        self.assertIn("no reachability analysis", en)
        self.assertLess(en.index("lodash 1.0.0"), en.index("top 1.0.0"))   # priority first
        self.assertLess(en.index("top 1.0.0"), en.index("deep 1.0.0"))     # then direct before transitive
        self.assertIn("top 1.0.0 direct dependency", en)
        self.assertIn("deep 1.0.0 transitive dependency", en)
        self.assertIn("lodash 1.0.0 transitive dependency, dev-only", en)
        de = text_of(management.render(management.load(out), lang="de"))
        self.assertIn("Schwachstellen mit Priorität 2 und 3 (KEV, oder CRITICAL/HIGH in Produktion oder einem "
                      "unterstützten Release): 3, davon 1 in direkten und 2 in transitiven Abhängigkeiten.", de)
        self.assertIn("Transitiv heißt nicht harmlos", de)
        self.assertIn("keine Erreichbarkeitsanalyse", de)
        self.assertIn("top 1.0.0 direkte Abhängigkeit", de)

    def test_unknown_dependency_type_is_not_counted_or_shown_as_transitive(self):
        out = full_folder(self.tmp / "security")
        doc = json.loads((out / "issues.json").read_text())
        doc["issues"][1:2] = [
            {"id": "u1", "kind": "vulnerability", "priority": 3, "reason": "critical_high_production",
             "severity": "CRITICAL", "production": True, "title": "vague 1.0.0", "where": {"project": "shop"},
             "details": {"direct": None, "dev_only": False}, "fix": {"action": "upgrade", "target": "2.0.0"}},
            {"id": "t1", "kind": "vulnerability", "priority": 3, "reason": "critical_high_production",
             "severity": "CRITICAL", "production": True, "title": "deep 1.0.0", "where": {"project": "shop"},
             "details": {"direct": False, "dev_only": False}, "fix": {"action": "upgrade", "target": "2.0.0"}}]
        write_json(out / "issues.json", doc)
        en = text_of(management.render(management.load(out)))
        self.assertIn("vague 1.0.0 dependency type unknown", en)
        self.assertNotIn("vague 1.0.0 transitive", en)
        self.assertIn("1 in transitive ones and 1 whose dependency type the scan could not tell", en)
        self.assertLess(en.index("vague 1.0.0"), en.index("deep 1.0.0"))    # unknown before transitive
        de = text_of(management.render(management.load(out), lang="de"))
        self.assertIn("vague 1.0.0 Abhängigkeitsart unbekannt", de)
        self.assertIn("1 in transitiven Abhängigkeiten und 1, bei denen der Scan die Abhängigkeitsart nicht "
                      "erkennen konnte", de)

    def test_release_breakdown_says_what_the_sboms_show(self):
        out = full_folder(self.tmp / "security")
        fixed = [{"id": "GHSA-a", "change": "affected_removed"}, {"id": "GHSA-b", "change": "upgraded"},
                 {"id": "GHSA-c", "change": "affected_removed"}, {"id": "GHSA-d"}]   # an older entry: no change
        write_json(out / "releases.json", {"schema": 1, "projects": {"shop": {"releases": [
            {"tag": "v2", "date": "2026-02-01", "previous": "v1", "fixed_since_previous": fixed},
            {"tag": "v1", "date": "2026-01-01", "previous": None, "fixed_since_previous": []}]}}})
        en = text_of(management.render(management.load(out)))
        self.assertIn("4 vs v1 1 upgraded to a higher version; 2 affected version removed, an unaffected version "
                      "that was already there remains", en)
        self.assertIn("It does not by itself mean an upgrade", en)
        de = text_of(management.render(management.load(out), lang="de"))
        self.assertIn("4 ggü. v1 1 auf eine höhere Version aktualisiert; 2 betroffene Version entfernt", de)

    def test_secret_values_never_reach_the_report(self):
        out = full_folder(self.tmp / "security")
        page = management.render(management.load(out))
        self.assertNotIn(PLANTED, page)
        self.assertIn("fp-bbbb", page)

    def test_escapes_every_value_from_the_data(self):
        evil = '<script>alert("x")</script>'
        out = full_folder(self.tmp / "security", project=evil, title=evil)
        secrets_store.add_decision(out, "fp-cccc", "accepted", evil, date="2026-10-03")
        page = management.render(management.load(out), organisation=evil)
        self.assertNotIn("<script", page)
        self.assertIn("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;", page)

    def test_clear_run_says_so(self):
        out = full_folder(self.tmp / "security")
        for name in ("issues.json",):
            (out / name).unlink()
        audit = json.loads((out / "audit.json").read_text())
        audit["vulnerabilities"], audit["runtimes"] = [], []
        write_json(out / "audit.json", audit)
        status = json.loads((out / "status.json").read_text())
        status["counts"]["secrets"] = {"A": 0, "B": 0, "C": 0}
        write_json(out / "status.json", status)
        sec = json.loads((out / "secrets.json").read_text())
        sec["findings"] = []
        write_json(out / "secrets.json", sec)
        text = text_of(management.render(management.load(out)))
        self.assertIn("No finding in this run requires immediate action.", text)
        self.assertIn("Nothing open at priority 1 to 3.", text)

    def test_clear_run_with_coverage_gaps_qualifies_the_verdict(self):
        out = full_folder(self.tmp / "security")
        (out / "issues.json").unlink()
        audit = json.loads((out / "audit.json").read_text())
        audit["vulnerabilities"], audit["runtimes"] = [], []
        audit["stats"] = {"projects_not_scanned": 1, "coverage_gaps": 2, "packages_unmatched": 3}
        write_json(out / "audit.json", audit)
        status = json.loads((out / "status.json").read_text())
        status["counts"]["secrets"] = {"A": 0, "B": 0, "C": 0}
        write_json(out / "status.json", status)
        sec = json.loads((out / "secrets.json").read_text())
        sec["findings"] = []
        write_json(out / "secrets.json", sec)
        en = text_of(management.render(management.load(out)))
        self.assertNotIn("No finding in this run requires immediate action.", en)
        self.assertIn("No finding among the checked packages requires immediate action; not checked: 1 project, "
                      "the code in 2 branches (submodules, C/C++ or firmware), 3 packages OSV cannot match "
                      "(see Limits).", en)
        de = text_of(management.render(management.load(out), lang="de"))
        self.assertNotIn("Kein Befund dieses Laufs erfordert sofortiges Handeln.", de)
        self.assertIn("Kein Befund unter den geprüften Paketen erfordert sofortiges Handeln; nicht geprüft: "
                      "1 Projekt, der Code in 2 Branches (Submodule, C/C++ oder Firmware), 3 Pakete, die OSV "
                      "nicht zuordnen kann (siehe Grenzen).", de)
        audit["stats"] = {"projects_not_scanned": 0, "coverage_gaps": 1, "packages_unmatched": 0}
        write_json(out / "audit.json", audit)
        en = text_of(management.render(management.load(out)))
        self.assertIn("immediate action; not checked: the code in 1 branch (submodules, C/C++ or firmware) "
                      "(see Limits).", en)


class TestSkippedIsNotClean(ManagementTestCase):
    def test_skipped_secrets_scan_is_never_zero_or_clean(self):
        out = self.fixture_copy()
        page = management.render(management.load(out))
        text = text_of(page)
        self.assertIn("SKIPPED", text)
        self.assertIn("not the same as clean", text)
        for cls in "ABC":
            row = re.search(rf"Leaked credentials, open, class {cls}</td><td[^>]*>(.*?)</td>", page).group(1)
            self.assertIn("not available", row)
            self.assertNotRegex(text_of("</style>" + row), r"^\s*0\b")
        self.assertNotIn("No finding in this run requires immediate action", text)

    def test_skipped_scan_does_not_clear_the_verdict(self):
        out = full_folder(self.tmp / "security")
        (out / "issues.json").unlink()
        audit = json.loads((out / "audit.json").read_text())
        audit["vulnerabilities"] = []
        write_json(out / "audit.json", audit)
        status = json.loads((out / "status.json").read_text())
        status["counts"]["secrets"] = {"A": 0, "B": 0, "C": 0}
        status["secrets_scan"] = {"mode": "skipped", "skipped_reason": "gitleaks not installed"}
        write_json(out / "status.json", status)
        (out / "secrets.json").unlink()
        text = text_of(management.render(management.load(out)))
        self.assertIn("but this run is incomplete", text)
        self.assertIn("gitleaks not installed", text)

    def test_failed_secrets_source_is_not_clean(self):
        out = full_folder(self.tmp / "security")
        audit = json.loads((out / "audit.json").read_text())
        audit["sources"]["secrets"] = {"error": "boom"}
        write_json(out / "audit.json", audit)
        text = text_of(management.render(management.load(out)))
        self.assertIn("the secrets scan failed; not the same as clean", text)
        self.assertNotIn("boom", text)                 # raw error text is never printed


class TestMissingData(ManagementTestCase):
    def test_no_audit_json_exits_2(self):
        out = self.tmp / "security"
        out.mkdir()
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["report", "--out", str(out)]), 2)
        self.assertIn("no audit.json", err.getvalue())
        self.assertFalse((out / "REPORT.html").exists())

    def test_without_status_and_issues(self):
        out = self.fixture_copy()
        (out / "status.json").unlink()
        text = text_of(management.render(management.load(out)))
        self.assertIn("no previous run on record", text)
        self.assertIn("status.json (end of run) not present", text)
        self.assertIn("derived from the reports", text)

    def test_unreadable_files_are_named(self):
        out = self.fixture_copy()
        (out / "inventory.json").write_text("{not json", encoding="utf-8")
        (out / "vex").mkdir()
        (out / "vex" / "x.openvex.json").write_text("[]", encoding="utf-8")
        (out / "secrets-decisions.toml").write_text("not = [toml", encoding="utf-8")
        text = text_of(management.render(management.load(out)))
        self.assertIn("inventory.json (scan) PRESENT BUT UNREADABLE", text)
        self.assertIn("vex/x.openvex.json could not be read", text)
        self.assertIn("secrets-decisions.toml could not be read", text)

    def test_missing_sources_read_not_available_not_zero(self):
        out = self.fixture_copy()               # the fixture recorded only the osv-scanner source
        page = management.render(management.load(out))
        for label in ("Actively exploited vulnerabilities", "Runtimes and base images past end of life"):
            row = re.search(rf"{label}[^<]*</td><td[^>]*>(.*?)</td>", page).group(1)
            self.assertIn("not available", row)

    def test_incomplete_osv_is_flagged(self):
        out = full_folder(self.tmp / "security")
        audit = json.loads((out / "audit.json").read_text())
        audit["sources"]["osv-scanner"]["failed"] = [{"project": "shop", "branch": "main"}]
        write_json(out / "audit.json", audit)
        text = text_of(management.render(management.load(out)))
        self.assertIn("incomplete: 1 branch(es) could not be matched against OSV", text)


class TestLanguageAndConfig(ManagementTestCase):
    def test_german(self):
        out = self.fixture_copy()
        page = management.render(management.load(out), lang="de", organisation="Muster AG")
        text = text_of(page)
        self.assertIn('<html lang="de">', page)
        self.assertIn("Sicherheitsbericht: Muster AG", text)
        self.assertIn("1. Gesamtlage", text)
        self.assertIn("ÜBERSPRUNGEN", text)
        self.assertIn("nicht dasselbe wie unbedenklich", text)
        self.assertIn("keine Rechtsberatung", text)
        self.assertNotIn("Overall state", text)

    def test_both_languages_have_the_same_keys(self):
        en, de = management.STRINGS["en"], management.STRINGS["de"]
        self.assertEqual(set(en), set(de))
        for key, value in en.items():
            if isinstance(value, dict):
                self.assertEqual(set(value), set(de[key]), key)
            if isinstance(value, list):
                self.assertEqual(len(value), len(de[key]), key)

    def test_unknown_language_is_refused(self):
        with self.assertRaises(ValueError):
            management.render(management.load(self.fixture_copy()), lang="fr")

    def test_config_keys(self):
        out = self.fixture_copy()
        (out / config.CONFIG_NAME).write_text('[report]\norganisation = "Beispiel GmbH"\nlanguage = "de"\n',
                                              encoding="utf-8")
        cfg = config.load(out)
        self.assertEqual((cfg.report.organisation, cfg.report.language), ("Beispiel GmbH", "de"))
        management.write(out, dated=False)
        text = text_of((out / "REPORT.html").read_text(encoding="utf-8"))
        self.assertIn("Sicherheitsbericht: Beispiel GmbH", text)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["report", "--out", str(out), "--lang", "en"]), 0)
        self.assertIn("Security report: Beispiel GmbH", (out / "REPORT.html").read_text(encoding="utf-8"))

    def test_config_defaults_and_bad_language(self):
        out = self.tmp / "security"
        out.mkdir()
        self.assertEqual((config.load(out).report.organisation, config.load(out).report.language), (None, "en"))
        (out / config.CONFIG_NAME).write_text('[report]\nlanguage = "fr"\n', encoding="utf-8")
        with self.assertRaises(config.ConfigError):
            config.load(out)
        (out / config.CONFIG_NAME).write_text('report = 3\n', encoding="utf-8")
        with self.assertRaises(config.ConfigError):
            config.load(out)

    def test_write_default_mentions_report_commented(self):
        out = self.tmp / "security"
        text = config.write_default(out, config.load(out), []).read_text()
        self.assertIn("# [report]", text)
        self.assertIn('# language = "en"', text)


class TestWordingAndTimes(ManagementTestCase):
    def cra_folder(self) -> Path:
        from sbomaudit import cra
        out = full_folder(self.tmp / "security")
        obligations = [{"id": k, "ref": ref, "status": "missing", "evidence": []}
                       for k, (ref, _) in {**cra.OBLIGATIONS, **cra.MANUFACTURER}.items()]
        write_json(out / "cra.json", {"generated_at": "2026-11-10T10:00:00Z",
                                      "products": {"shop": {"name": "Shop", "branch": "main",
                                                            "obligations": obligations}}})
        return out

    def test_german_cra_references_cite_the_same_provisions_in_german(self):
        from sbomaudit import cra
        self.assertEqual(set(management.STRINGS["de"]["cra_ref"]), set(cra.ORDER))
        out = self.cra_folder()
        de = text_of(management.render(management.load(out), lang="de"))
        self.assertIn("Anhang I Teil II Nr. 6; Anhang II Nr. 2 (RFC 9116 ist ein verbreiteter Weg, keine "
                      "Anforderung des CRA)", de)
        for english in ("Annex", "RFC 9116 is one common way", " point ", "Art. 13(", "Teil II (", "Nummer"):
            self.assertNotIn(english, de)
        en = text_of(management.render(management.load(out), lang="en"))
        self.assertIn(cra.OBLIGATIONS["security_txt"][0], en)
        # the same article, paragraph and point numbers: only the words around them differ
        digits = lambda s: set(re.findall(r"\d+", s))
        roman = lambda s: set(re.findall(r"\b[IVX]+\b", s))
        for key, ref in management.STRINGS["de"]["cra_ref"].items():
            en_ref = {**cra.OBLIGATIONS, **cra.MANUFACTURER}[key][0]
            self.assertEqual(digits(ref), digits(en_ref), key)
            self.assertEqual(roman(ref), roman(en_ref), key)

    def test_times_are_shown_in_the_run_zone(self):
        out = full_folder(self.tmp / "security")
        doc = json.loads((out / "audit.json").read_text())
        doc["generated_at"] = "2026-11-18T02:47:00+08:00"
        (out / "audit.json").write_text(json.dumps(doc))
        doc = json.loads((out / "secrets.json").read_text())
        doc["generated_at"] = "2026-11-17T18:46:00Z"            # the same run, recorded in UTC
        (out / "secrets.json").write_text(json.dumps(doc))
        for lang, needle in (("en", "run's time zone (UTC+08:00)"), ("de", "Zeitzone des Laufs (UTC+08:00)")):
            page = management.render(management.load(out), lang=lang)
            text = text_of(page).replace("&#x27;", "'")
            self.assertIn(needle, text)
            self.assertIn("2026-11-18T02:46:00+08:00", text)     # secrets.json converted
            self.assertNotIn("2026-11-17T18:46", text)
            self.assertIn("2026-11-18T02:47:00+08:00", text)
        self.assertEqual(management._in_zone("2026-11-17", None), "2026-11-17")      # a day stays as recorded

    def test_limits_name_the_secrets_history_and_unchecked_actions(self):
        out = full_folder(self.tmp / "security")
        en = text_of(management.render(management.load(out)))
        self.assertIn("the secrets scan reads the whole git history of every branch", en)
        self.assertNotIn("Only the configured branches are read", en)
        self.assertNotIn("GitHub Actions", en)                    # none in this run: no line
        doc = json.loads((out / "audit.json").read_text())
        doc["stats"] = {"github_actions_unchecked": 7}
        (out / "audit.json").write_text(json.dumps(doc))
        en = text_of(management.render(management.load(out)))
        self.assertIn("GitHub Actions used in workflows are inventoried but not checked for vulnerabilities "
                      "(OSV does not match versions for this ecosystem): 7 in this run", en)
        de = text_of(management.render(management.load(out), lang="de"))
        self.assertIn("der Secrets-Scan liest die gesamte git-Historie aller Branches", de)
        self.assertIn("nicht auf Schwachstellen geprüft (OSV gleicht für dieses Ökosystem keine Versionen ab): 7", de)
        self.assertIn("RELEASES.md, ISSUES.md, CRA.md und die übrigen Markdown- und JSON-Dateien sind immer "
                      "englisch", de)
        self.assertIn("Scan (vollständig)", de)


class TestWiring(ManagementTestCase):
    def test_read_only_mode_refuses(self):
        out = self.fixture_copy()
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"SBOM_AUDIT_READ_ONLY": "1"}), contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["report", "--out", str(out)]), cli.EXIT_READ_ONLY)
        self.assertFalse((out / "REPORT.html").exists())

    def test_cli_prints_the_paths(self):
        out = self.fixture_copy()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(cli.main(["report", "--out", str(out)]), 0)
        self.assertEqual(buf.getvalue().split(), ["REPORT.html", "reports/2026-11-07-report.html"])

    def test_try_write_never_raises(self):
        out = self.tmp / "security"
        out.mkdir()
        said = []
        self.assertEqual(management.try_write(out, said.append), [])
        self.assertRegex(said[0], r"^management report: not written \(FileNotFoundError: audit\.json "
                                  r"\(management\.py:\d+ in write\)\)$")
        with mock.patch.object(management, "render", side_effect=RuntimeError(PLANTED)):
            self.assertEqual(management.try_write(self.fixture_copy("fixture"), said.append), [])
        self.assertRegex(said[-1], r"^management report: not written \(RuntimeError \(\w+\.py:\d+ in \w+\)\)$")
        self.assertNotIn(PLANTED, said[-1])          # a message may quote report data: only the place is logged

    def test_describe_error_names_the_raising_frame(self):
        def boom():
            raise ValueError("x\ny")
        try:
            boom()
        except ValueError as exc:
            text = management.describe_error(exc)
        self.assertRegex(text, r"^ValueError \(test_management\.py:\d+ in boom\)$")
        self.assertEqual(management.describe_error(KeyError("k")), "KeyError")      # never raised: no frame
        long = OSError(13, "Permission denied " * 30, "/a/b/secret-dir/file.json")
        text = management.describe_error(long)                  # OSError(13, ...) is a PermissionError
        self.assertTrue(text.startswith("PermissionError: Permission denied"), text)
        self.assertEqual(len(text), len("PermissionError: ") + 200)
        self.assertNotIn("secret-dir", text)                     # the file name only, not its directory


if __name__ == "__main__":
    unittest.main()
