"""Coverage gaps: versionless packages (never vulnerable, listed as not checked), Maven `group:artifact` names in
lookup/incident, and advisories without a severity ("not rated", derived from aliases or the osv-scanner group)."""
from __future__ import annotations

import contextlib
import io
import os
import json
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from sbomaudit import cli, coverage, issues, lookup, matching, pomresolve, report, scan, status
from sbomaudit.config import Config, ProjectOpts
from sbomaudit.model import BranchInventory, Component, Finding, qualified_name
from tests.test_lookup import stub_fetch


def maven(group, artifact, version, location="pom.xml", direct=True):
    purl = f"pkg:maven/{group}/{artifact}" + (f"@{version}" if version and version != "UNKNOWN" else "")
    return Component(kind="package", ecosystem="Maven", name=artifact, version=version, purl=purl,
                     scope="required", locations=[location], direct=direct)


PG_UNKNOWN = maven("org.postgresql", "postgresql", "UNKNOWN", "dex/benchmark/pom.xml")
PG_OLD = maven("org.postgresql", "postgresql", "42.2.0", "alpine/pom.xml")
NPM_NOLOCK = Component(kind="package", ecosystem="npm", name="react", version="", purl="pkg:npm/react",
                       scope="required", locations=["docs/package.json"], direct=True,
                       props={"requirement": "^18"})
LOCAL_WF = Component(kind="package", ecosystem="github", name="$/.github/workflows/build.yaml", version="UNKNOWN",
                     purl="", scope="required", locations=[".github/workflows/ci.yaml"])


def osv_pkg(name, version, ecosystem, purl, records, groups=None):
    return {"package": {"name": name, "version": version, "ecosystem": ecosystem, "purl": purl},
            "vulnerabilities": records, "groups": groups or []}


def record(vid, aliases=(), severity=None, db=None):
    r = {"id": vid, "aliases": list(aliases), "summary": vid, "affected": []}
    if severity:
        r["severity"] = [{"type": "CVSS_V3", "score": severity}]
    if db:
        r["database_specific"] = {"severity": db}
    return r


CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class VersionUnresolvedTests(unittest.TestCase):
    def test_placeholders(self):
        for v in ("", None, "UNKNOWN", "unknown", " ", "${lib.version}", "1.${x}"):
            self.assertTrue(matching.version_unresolved(v), v)
        for v in ("42.7.14", "0", "1.0.0-SNAPSHOT"):
            self.assertFalse(matching.version_unresolved(v), v)

    def test_unknown_maven_version_is_never_a_finding(self):
        inv = BranchInventory(project="dt", branch="main", ref="main", commit="x", components=[PG_UNKNOWN, PG_OLD])
        osv = {"results": [{"packages": [
            osv_pkg("org.postgresql:postgresql", "UNKNOWN", "Maven", "pkg:maven/org.postgresql/postgresql",
                    [record("GHSA-24rp-q3w6-vc56", severity=CRIT)]),
            osv_pkg("org.postgresql:postgresql", "42.2.0", "Maven", "pkg:maven/org.postgresql/postgresql@42.2.0",
                    [record("GHSA-old", severity=CRIT)]),
            osv_pkg("ghost", "", "npm", "pkg:npm/ghost", [record("GHSA-ghost", severity=CRIT)]),
        ]}]}
        found = matching.findings(inv, osv)
        self.assertEqual([(f.component.version, f.vulns[0]["id"]) for f in found], [("42.2.0", "GHSA-old")])


class SeverityTests(unittest.TestCase):
    def test_own_severity_unchanged(self):
        s = matching.summarize(record("GHSA-1", severity=CRIT), "npm", "x")
        self.assertEqual((s["severity"], s["cvss"]), ("CRITICAL", 9.8))
        self.assertNotIn("severity_source", s)
        self.assertEqual(matching.summarize(record("GHSA-1", db="MODERATE"), "npm", "x")["severity"], "MEDIUM")

    def test_from_aliased_record(self):
        go = record("GO-2026-1", aliases=["CVE-2026-9", "GHSA-a"])
        ghsa = record("GHSA-a", aliases=["CVE-2026-9"], db="HIGH")
        s = matching.summarize(go, "Go", "x", related=[go, ghsa])
        self.assertEqual((s["severity"], s["severity_source"]), ("HIGH", "alias GHSA-a"))
        self.assertIsNone(s["cvss"])                       # no score is invented

    def test_from_group_max_severity(self):
        go = record("GO-2026-1")
        s = matching.summarize(go, "Go", "x", related=[go], groups=[{"ids": ["GO-2026-1"], "max_severity": "7.5"}])
        self.assertEqual((s["severity"], s["severity_source"]), ("HIGH", "osv-scanner group score"))

    def test_unrated_stays_unknown(self):
        go = record("GO-2026-5932", db="UNKNOWN")
        s = matching.summarize(go, "Go", "x", related=[go], groups=[{"ids": ["GO-2026-5932"], "max_severity": ""}])
        self.assertEqual(s["severity"], "UNKNOWN")
        self.assertNotIn("severity_source", s)
        self.assertEqual(coverage.severity_text("UNKNOWN"), "not rated")
        self.assertEqual(coverage.severity_text(None), "not rated")
        self.assertEqual(coverage.severity_text("HIGH(~v4)"), "HIGH(~v4)")


class QualifiedNameTests(unittest.TestCase):
    def test_maven_and_others(self):
        self.assertEqual(PG_UNKNOWN.qualified_name(), "org.postgresql:postgresql")
        self.assertEqual(qualified_name("Maven", "a:b", "pkg:maven/a/b@1"), "a:b")
        self.assertEqual(qualified_name("Maven", "b", ""), "b")
        self.assertEqual(qualified_name("Go", "golang.org/x/net", "pkg:golang/golang.org/x/net@v0.1.0"),
                         "golang.org/x/net")
        self.assertEqual(qualified_name("npm", "core", "pkg:npm/%40babel/core@7.0.0"), "core")


def _state(tmp: Path, invs, findings, production=("dt",)) -> Config:
    root = tmp / "root"
    out = root / "security"
    out.mkdir(parents=True)
    cfg = Config(out=out, root=root, mode="portfolio", fetch=False,
                 projects={p: ProjectOpts(production=True) for p in production})
    scan.write_inventory(cfg, scan.ScanResult(inventories=invs, generated_at="2026-11-01T10:00:00Z"))
    rep = report.build(cfg, invs, findings, [], [], [], {"osv-scanner": {"scanned": len(invs), "failed": []}})
    report.write_json(rep, out)
    return cfg


def _sv(vid, severity, cvss_score=None):
    return {"id": vid, "aliases": [], "cves": [], "summary": vid, "severity": severity, "cvss": cvss_score,
            "fixed": [], "published": "2026-01-01", "modified": "2026-01-02", "withdrawn": False}


class ReportCoverageTests(unittest.TestCase):
    def test_unresolved_versions_listed_and_counted(self):
        invs = [BranchInventory(project="dt", branch="main", ref="main", commit="x",
                                components=[PG_UNKNOWN, PG_OLD, NPM_NOLOCK, LOCAL_WF])]
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _state(Path(tmp), invs, [])
            rep = json.loads((cfg.out / report.JSON_FILE).read_text())
            self.assertEqual(rep["stats"]["unresolved_versions"], 2)
            row = rep["unresolved_versions"][0]
            self.assertEqual((row["project"], row["branch"], row["count"]), ("dt", "main", 2))
            self.assertEqual([p["name"] for p in row["packages"]], ["org.postgresql:postgresql", "react"])
            self.assertEqual(row["packages"][1]["requirement"], "^18")
            md = report.write_audit_md(rep, cfg.out).read_text()
            self.assertIn("## Version not resolved", md)
            self.assertIn("dt@main: 2 packages (Maven, npm): `org.postgresql:postgresql`, `react`", md)
            self.assertIn("version not resolved, not checked for vulnerabilities", md)

    def test_no_gap_keeps_audit_json_shape(self):
        invs = [BranchInventory(project="dt", branch="main", ref="main", commit="x", components=[PG_OLD])]
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _state(Path(tmp), invs, [])
            rep = json.loads((cfg.out / report.JSON_FILE).read_text())
            self.assertNotIn("unresolved_versions", rep)
            self.assertNotIn("## Version not resolved", report.write_audit_md(rep, cfg.out).read_text())

    def test_unrated_in_production_ranks_priority_3(self):
        invs = [BranchInventory(project="dt", branch="main", ref="main", commit="x", components=[PG_OLD]),
                BranchInventory(project="lab", branch="main", ref="main", commit="x", components=[PG_OLD])]
        findings = [Finding("dt", "main", PG_OLD, [_sv("GO-1", "UNKNOWN"), _sv("GHSA-low", "LOW", 2.0)]),
                    Finding("lab", "main", PG_OLD, [_sv("GO-1", "UNKNOWN")])]
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _state(Path(tmp), invs, findings)
            rep = json.loads((cfg.out / report.JSON_FILE).read_text())
            entry = rep["vulnerabilities"][0]
            self.assertEqual((entry["package"], entry["purl"]),
                             ("org.postgresql:postgresql", "pkg:maven/org.postgresql/postgresql@42.2.0"))
            md = report.write_audit_md(rep, cfg.out).read_text()
            self.assertIn("## Severity not rated", md)
            self.assertIn("Severity not rated in production", md)
            doc = issues.build(rep, None, None)
            vulns = [i for i in doc["issues"] if i["kind"] == "vulnerability"]
            prod = [i for i in vulns if i["production"]]
            self.assertEqual([(i["priority"], i["reason"]) for i in prod], [(3, "unrated_production")])
            self.assertIn("2 advisories, worst LOW, 1 not rated", prod[0]["title"])
            self.assertEqual(prod[0]["details"]["package"], "org.postgresql:postgresql")
            st = status.build(rep, secrets=None, previous=None, duration_s=1, exit_code=0, run_host="h", mode="m")
            self.assertEqual(st["counts"]["unrated_production"], 1)
            self.assertEqual(st["counts"]["unresolved_versions"], 0)

    def test_status_counts_line_names_gaps(self):
        invs = [BranchInventory(project="dt", branch="main", ref="main", commit="x", components=[PG_UNKNOWN])]
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _state(Path(tmp), invs, [])
            rep = json.loads((cfg.out / report.JSON_FILE).read_text())
            st = status.build(rep, secrets=None, previous=None, duration_s=1, exit_code=0, run_host="h", mode="m")
            self.assertIn("1 packages with version not resolved, not checked for vulnerabilities",
                          status.render_md(st, None))


GHSA_PG = {"id": "GHSA-24rp-q3w6-vc56", "aliases": ["CVE-2024-1597"], "summary": "SQL injection",
           "affected": [{"package": {"ecosystem": "Maven", "name": "org.postgresql:postgresql"},
                         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "42.2.28"}]}]}]}
PG_URL = "https://api.osv.dev/v1/vulns/GHSA-24rp-q3w6-vc56"


class MavenLookupTests(unittest.TestCase):
    def _cfg(self, tmp, invs, findings):
        return _state(Path(tmp), invs, findings)

    def test_lookup_full_and_bare_name(self):
        invs = [BranchInventory(project="dt", branch="main", ref="main", commit="x", components=[PG_OLD])]
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._cfg(tmp, invs, [])
            for q in ("org.postgresql:postgresql", "postgresql", "org.postgresql:*"):
                rows = lookup.rows(cfg.out, [q])
                self.assertEqual([(r.name, r.version) for r in rows], [("org.postgresql:postgresql", "42.2.0")], q)

    def test_incident_hits_maven_and_never_answers_absent(self):
        invs = [BranchInventory(project="dt", branch="main", ref="main", commit="x", components=[PG_OLD]),
                BranchInventory(project="other", branch="main", ref="main", commit="x", components=[],
                                manifests={})]       # scanned, no manifest: absent, not unknown
        findings = [Finding("dt", "main", PG_OLD, [_sv("GHSA-24rp-q3w6-vc56", "CRITICAL", 10.0)])]
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._cfg(tmp, invs, findings)
            inc = lookup.incident(cfg.out, "GHSA-24rp-q3w6-vc56", fetch=stub_fetch({PG_URL: GHSA_PG}))
            by = {(v.project, v.branch): v for v in inc.verdicts}
            self.assertEqual(by[("dt", "main")].verdict, lookup.VERDICT_HIT)
            self.assertEqual(by[("dt", "main")].name, "org.postgresql:postgresql")
            self.assertEqual(by[("other", "main")].verdict, lookup.VERDICT_ABSENT)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                 unittest.mock.patch.object(lookup, "http_get_json", stub_fetch({PG_URL: GHSA_PG})):
                rc = cli.main(["--out", str(cfg.out), "incident", "GHSA-24rp-q3w6-vc56"])
            self.assertEqual(rc, 1)
            files = lookup.record_absent(cfg, inc, author="test@example.invalid")
            doc = json.loads(files[0].read_text())
            self.assertEqual(doc["statements"][0]["products"][0]["subcomponents"][0]["@id"],
                             "pkg:maven/org.postgresql/postgresql")

    def test_audit_finding_wins_over_a_missed_inventory_match(self):
        """An audit.json finding whose package the inventory names differently is still a hit, never absent."""
        invs = [BranchInventory(project="dt", branch="main", ref="main", commit="x", components=[PG_OLD])]
        findings = [Finding("dt", "main", PG_OLD, [_sv("GHSA-24rp-q3w6-vc56", "CRITICAL", 10.0)])]
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._cfg(tmp, invs, findings)
            empty = [BranchInventory(project="dt", branch="main", ref="main", commit="x", components=[])]
            scan.write_inventory(cfg, scan.ScanResult(inventories=empty, generated_at="2026-11-01T10:00:00Z"))
            inc = lookup.incident(cfg.out, "GHSA-24rp-q3w6-vc56", fetch=stub_fetch({PG_URL: GHSA_PG}))
            self.assertEqual([v.verdict for v in inc.verdicts], [lookup.VERDICT_HIT])
            self.assertIn("from audit.json", inc.verdicts[0].evidence)

    def test_unresolved_version_is_unknown_not_present(self):
        invs = [BranchInventory(project="dt", branch="main", ref="main", commit="x", components=[PG_UNKNOWN])]
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._cfg(tmp, invs, [])
            inc = lookup.incident(cfg.out, "GHSA-24rp-q3w6-vc56", fetch=stub_fetch({PG_URL: GHSA_PG}))
            v = inc.verdicts[0]
            self.assertEqual(v.verdict, lookup.VERDICT_UNKNOWN)
            self.assertIn("version not resolved, not checked for vulnerabilities", v.evidence)
            self.assertEqual(lookup.record_absent(cfg, inc, author="test@example.invalid"), [])


POM_PARENT = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>org.example</groupId><artifactId>parent</artifactId><version>5.0.0-SNAPSHOT</version>
  <properties><lib.postgresql.version>42.7.14</lib.postgresql.version><lib.bom.version>2.0</lib.bom.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId><version>${lib.postgresql.version}</version></dependency>
    <dependency><groupId>org.example</groupId><artifactId>bom</artifactId><version>${project.version}</version><type>pom</type><scope>import</scope></dependency>
    <dependency><groupId>com.external</groupId><artifactId>ext-bom</artifactId><version>${lib.bom.version}</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
</project>"""
POM_BOM = """<project><parent><groupId>org.example</groupId><artifactId>parent</artifactId><version>5.0.0-SNAPSHOT</version></parent>
  <artifactId>bom</artifactId>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.example</groupId><artifactId>lib</artifactId><version>${project.version}</version></dependency>
  </dependencies></dependencyManagement>
</project>"""
POM_CHILD = """<project><parent><groupId>org.example</groupId><artifactId>parent</artifactId><version>4.0.0</version></parent>
  <artifactId>bench</artifactId>
  <dependencies>
    <dependency><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId></dependency>
    <dependency><groupId>org.example</groupId><artifactId>lib</artifactId></dependency>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId></dependency>
  </dependencies>
</project>"""


class PomResolveTests(unittest.TestCase):
    def test_in_repo_management_resolves_external_bom_does_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp)
            (src / "bom").mkdir()
            (src / "bench").mkdir()
            (src / "pom.xml").write_text(POM_PARENT)
            (src / "bom" / "pom.xml").write_text(POM_BOM)
            (src / "bench" / "pom.xml").write_text(POM_CHILD)
            comps = [maven("org.postgresql", "postgresql", "UNKNOWN", "bench/pom.xml"),
                     maven("org.example", "lib", "UNKNOWN", "bench/pom.xml"),
                     maven("com.fasterxml.jackson.core", "jackson-databind", "UNKNOWN", "bench/pom.xml")]
            bom = {"components": [{"name": c.name, "version": "UNKNOWN", "purl": c.purl, "properties": [
                {"name": "syft:location:0:path", "value": "/bench/pom.xml"}]} for c in comps]}
            self.assertEqual(pomresolve.resolve_managed(src, bom, comps), 2)
            self.assertEqual([c.version for c in comps], ["42.7.14", "5.0.0-SNAPSHOT", "UNKNOWN"])
            self.assertEqual(comps[0].purl, "pkg:maven/org.postgresql/postgresql@42.7.14")
            self.assertEqual(comps[0].props["version_source"], "pom.xml (in-repo pom)")
            self.assertEqual(comps[1].props["version_source"], "bom/pom.xml (in-repo pom)")
            entries = bom["components"]
            self.assertEqual([e["version"] for e in entries], ["42.7.14", "5.0.0-SNAPSHOT", "UNKNOWN"])
            self.assertIn({"name": pomresolve.SOURCE_PROPERTY, "value": "pom.xml (in-repo pom)"},
                          entries[0]["properties"])

    def test_poms_outside_the_tree_and_fifos_are_never_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / "outside"
            outside.mkdir()
            (outside / "pom.xml").write_text(POM_PARENT)
            src = Path(tmp) / "src"
            (src / "inside").mkdir(parents=True)
            (src / "inside" / "pom.xml").write_text(POM_BOM)
            (src / "a").mkdir()
            (src / "a" / "pom.xml").symlink_to(outside / "pom.xml")      # a file link out of the tree
            (src / "linked").symlink_to(outside, target_is_directory=True)  # a directory link out of it
            (src / "b").mkdir()
            os.mkfifo(src / "b" / "pom.xml")                               # would block a reader forever
            (src / "c").mkdir()
            (src / "c" / "pom.xml").symlink_to(src / "inside" / "pom.xml")  # a link inside the tree is fine
            poms = pomresolve.index(src)
            self.assertEqual(sorted(poms), ["c/pom.xml", "inside/pom.xml"])
            self.assertIsNone(pomresolve.parse(src / "a" / "pom.xml", "a/pom.xml", root=src))
            self.assertIsNone(pomresolve.parse(src / "b" / "pom.xml", "b/pom.xml", root=src))

    def test_malformed_pom_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp)
            (src / "pom.xml").write_text("<project><broken")
            comps = [maven("org.postgresql", "postgresql", "UNKNOWN", "pom.xml")]
            self.assertEqual(pomresolve.resolve_managed(src, {"components": []}, comps), 0)
            self.assertEqual(comps[0].version, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
