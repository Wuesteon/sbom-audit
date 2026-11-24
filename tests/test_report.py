"""Report writers: audit.json, AUDIT.md (triage order, carry-over), INVENTORY.md, dated copy, log."""
from __future__ import annotations

import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import report, vex
from sbomaudit.config import Config, ProjectOpts
from sbomaudit.model import BranchInventory, Component, Finding
from sbomaudit.readers import image_component, runtime_component


def vuln(vid, severity, cvss=None, fixed=(), kev=False, aliases=()):
    return {"id": vid, "aliases": list(aliases), "cves": [a for a in aliases if a.startswith("CVE-")],
            "summary": f"{vid} does something bad", "severity": severity, "cvss": cvss,
            "fixed": list(fixed), "published": "2026-01-01", "modified": "2026-01-02",
            "withdrawn": False, "kev": kev}


def pkg(name, version, scope="required", ecosystem="npm", manifest="package.json", direct=True):
    return Component(kind="package", ecosystem=ecosystem, name=name, version=version,
                     purl=f"pkg:{ecosystem.lower()}/{name}@{version}", scope=scope,
                     locations=[manifest], direct=direct)


def inv(project, branch, components, commit="abc1234def", behind=0):
    return BranchInventory(project=project, branch=branch, ref=branch, commit=commit,
                           behind=behind, components=components)


def config(tmp: Path, production=("zeta",)) -> Config:
    return Config(out=tmp / "security", root=tmp, mode="portfolio",
                  projects={p: ProjectOpts(production=True) for p in production})


LODASH = pkg("lodash", "4.17.20")
ESBUILD = pkg("esbuild", "0.17.0", scope="optional", manifest="package-lock.json")
NGINX = image_component("nginx:alpine", "Dockerfile")
QDRANT = image_component("qdrant/qdrant:latest", "docker-compose.yml")
NODE18 = runtime_component("nodejs", "18", "package.json", "engines.node >=18")

SOURCES_OK = {"osv-scanner": {"scanned": 3, "failed": []}, "cisa_kev": {"loaded": 2, "error": None},
              "endoflife": {"queried": 1}, "registries": {"queried": 1, "resolved": 1}}


def headings(text: str) -> list[str]:
    return [line[3:].strip() for line in text.splitlines() if line.startswith("## ")]


def section(text: str, heading: str) -> str:
    start = text.index(f"\n## {heading}")
    end = text.find("\n## ", start + 1)
    return text[start:end if end >= 0 else len(text)]


class BuildTests(unittest.TestCase):
    def test_build_groups_findings_by_package_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = config(Path(tmp))
            invs = [inv("zeta", "main", [LODASH, NGINX, NODE18]), inv("zeta", "dev", [LODASH]),
                    inv("alpha", "main", [LODASH, ESBUILD])]
            findings = [Finding("zeta", "main", LODASH, [vuln("GHSA-1", "HIGH", 7.5, ["4.17.21"])]),
                        Finding("zeta", "dev", LODASH, [vuln("GHSA-1", "HIGH", 7.5, ["4.17.21"])]),
                        Finding("alpha", "main", LODASH, [vuln("GHSA-1", "HIGH", 7.5, ["4.17.21"]),
                                                         vuln("GHSA-2", "LOW", 2.0)])]
            rep = report.build(cfg, invs, findings, [], [], [], SOURCES_OK)
        self.assertEqual(sorted(rep), sorted(["generated_at", "sources", "vulnerabilities", "runtimes",
                                              "outdated", "unpinned_images", "suppressed", "notes",
                                              "stats", "production_projects"]))
        self.assertEqual(len(rep["vulnerabilities"]), 1)
        v = rep["vulnerabilities"][0]
        self.assertEqual((v["ecosystem"], v["name"], v["version"], v["scope"]), ("npm", "lodash", "4.17.20", "required"))
        self.assertTrue(v["direct_anywhere"])
        self.assertEqual([(l["project"], l["branch"], l["manifest"], l["direct"]) for l in v["locations"]],
                         [("alpha", "main", "package.json", True), ("zeta", "dev", "package.json", True),
                          ("zeta", "main", "package.json", True)])
        self.assertEqual([x["id"] for x in v["vulns"]], ["GHSA-1", "GHSA-2"])
        self.assertEqual(v["vulns"][0]["fixed_in"], "4.17.21")
        self.assertEqual(v["max_severity"], "HIGH")
        self.assertEqual(rep["unpinned_images"], [{"project": "zeta", "branch": "main", "image": "nginx:alpine",
                                                   "source": "Dockerfile", "own": False}])
        self.assertEqual(rep["production_projects"], ["zeta"])
        self.assertEqual(rep["stats"]["projects"], 2)
        self.assertEqual(rep["stats"]["branches"], 3)
        self.assertEqual(rep["stats"]["unique_package_versions"], 2)

    def build_with_epss(self, scores, epss=None):
        """One lodash row whose advisories carry the given `epss` values (key absent when scores is None)."""
        vulns = []
        for i, score in enumerate(scores or [None]):
            v = vuln(f"GHSA-{i + 1}", "HIGH", 7.5)
            if scores is not None:
                v["epss"], v["epss_percentile"] = score, None if score is None else 0.5
            vulns.append(v)
        with tempfile.TemporaryDirectory() as tmp:
            return report.build(config(Path(tmp)), [inv("zeta", "main", [LODASH])],
                                [Finding("zeta", "main", LODASH, vulns)], [], [], [], SOURCES_OK, epss=epss)

    def test_no_max_epss_without_the_epss_key(self):
        rep = self.build_with_epss(None)
        self.assertNotIn("max_epss", rep["vulnerabilities"][0])
        self.assertNotIn("epss", rep["vulnerabilities"][0]["vulns"][0])
        self.assertNotIn("epss", rep)

    def test_max_epss_is_the_highest_advisory_score(self):
        block = {"threshold": 0.1, "available": True, "score_date": "2026-11-23T12:00:23Z",
                 "model_version": "v2026.06.15"}
        rep = self.build_with_epss([None, 0.2, 0.05], epss=block)
        self.assertEqual(rep["vulnerabilities"][0]["max_epss"], 0.2)
        self.assertEqual(rep["epss"], block)
        self.assertIsNone(self.build_with_epss([None, None])["vulnerabilities"][0]["max_epss"])


class AuditMdTests(unittest.TestCase):
    def write(self, tmp: Path, findings, suppressed=(), eol=(), outdated=(), sources=SOURCES_OK,
              invs=None, production=("zeta",)) -> str:
        cfg = config(tmp, production)
        invs = invs or [inv("zeta", "main", [LODASH, ESBUILD, NGINX, NODE18]), inv("alpha", "main", [LODASH])]
        rep = report.build(cfg, invs, findings, list(suppressed), list(eol), list(outdated), sources)
        cfg.out.mkdir(parents=True, exist_ok=True)
        path = report.write_audit_md(rep, cfg.out)
        return path.read_text(encoding="utf-8")

    def test_triage_order_of_sections(self):
        with tempfile.TemporaryDirectory() as tmp:
            text = self.write(Path(tmp), [Finding("zeta", "main", LODASH, [vuln("GHSA-1", "HIGH", 7.5)])])
        expected = ["Source status", "Summary", "🔴 Actively exploited (CISA KEV)",
                    "Critical and high severity by project", "Runtimes and base images",
                    "Floating image tags", "Outdated direct dependencies (≥1 major version behind)",
                    "Dev-only findings", "Suppressed by VEX", "Notes"]
        self.assertEqual(headings(text), expected)
        self.assertTrue(text.startswith("# Dependency Audit — "))

    def test_production_projects_listed_first(self):
        findings = [Finding("alpha", "main", LODASH, [vuln("GHSA-1", "HIGH", 7.5, ["4.17.21"])]),
                    Finding("zeta", "main", LODASH, [vuln("GHSA-1", "HIGH", 7.5, ["4.17.21"])])]
        with tempfile.TemporaryDirectory() as tmp:
            text = self.write(Path(tmp), findings)
        sec = section(text, "Critical and high severity by project")
        self.assertIn("### zeta (production)", sec)
        self.assertIn("### alpha", sec)
        self.assertLess(sec.index("### zeta (production)"), sec.index("### alpha"))
        self.assertIn("| lodash | 4.17.20 |", sec)
        self.assertIn("4.17.21", sec)

    def test_dev_only_labelled_not_counted_as_production(self):
        findings = [Finding("zeta", "main", ESBUILD, [vuln("GHSA-9", "HIGH", 8.1, ["0.25.0"])])]
        with tempfile.TemporaryDirectory() as tmp:
            text = self.write(Path(tmp), findings)
        self.assertNotIn("esbuild", section(text, "Critical and high severity by project"))
        dev = section(text, "Dev-only findings")
        self.assertIn("esbuild", dev)
        self.assertIn("dev-only", dev)
        self.assertIn("| CRITICAL/HIGH in production projects (excluding dev-only) | 0 |", section(text, "Summary"))
        self.assertIn("| Vulnerable package versions | 1 |", section(text, "Summary"))

    def test_assessment_sections_carried_over_verbatim(self):
        old = ("# Dependency Audit — 2026-11-04\n\n## Summary\n\nold stuff\n\n"
               "## Assessment 2026-11-04\n\n| Advisory | Hit |\n|---|---|\n| undici | yes |\n\n"
               "## Assessment 2026-11-04 (addendum)\n\nSecond note.\n")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "security"
            out.mkdir()
            (out / "AUDIT.md").write_text(old, encoding="utf-8")
            text = self.write(Path(tmp), [])
        tail = old[old.index("## Assessment 2026-11-04"):]
        self.assertTrue(text.endswith("\n" + tail))
        self.assertEqual(text.count("## Summary"), 1)
        self.assertNotIn("old stuff", text)

    def test_suppressed_appendix_lists_justification(self):
        st = vex.Statement(vuln="GHSA-1", product="pkg:github/example-org/zeta", subcomponents=["pkg:npm/lodash"],
                           status="not_affected", justification="vulnerable_code_not_in_execute_path",
                           impact="the vulnerable template path is never called", timestamp="2026-11-06T00:00:00+00:00",
                           project="zeta", path="security/vex/zeta.openvex.json")
        sup = vex.Suppressed(Finding("zeta", "main", LODASH, [vuln("GHSA-1", "HIGH", 7.5)]), st)
        with tempfile.TemporaryDirectory() as tmp:
            text = self.write(Path(tmp), [], suppressed=[sup])
        sec = section(text, "Suppressed by VEX")
        self.assertIn("GHSA-1", sec)
        self.assertIn("lodash", sec)
        self.assertIn("vulnerable_code_not_in_execute_path", sec)
        self.assertIn("never called", sec)
        self.assertIn("zeta.openvex.json", sec)
        self.assertNotIn("lodash", section(text, "Critical and high severity by project"))
        self.assertIn("| Suppressed by VEX | 1 |", section(text, "Summary"))

    def test_source_status_shows_failed_branch(self):
        sources = {"osv-scanner": {"scanned": 1, "failed": [("zeta", "dev", "exit 127: osv-scanner not found")]},
                   "cisa_kev": {"loaded": 0, "error": "CISA KEV fetch failed: URLError: timeout"}}
        with tempfile.TemporaryDirectory() as tmp:
            cfg = config(Path(tmp))
            rep = report.build(cfg, [inv("zeta", "main", [LODASH])], [], [], [], [], sources)
            cfg.out.mkdir(parents=True)
            text = report.write_audit_md(rep, cfg.out).read_text(encoding="utf-8")
        self.assertEqual(rep["sources"]["osv-scanner"]["failed"],
                         [{"project": "zeta", "branch": "dev", "error": "exit 127: osv-scanner not found"}])
        sec = section(text, "Source status")
        self.assertIn("zeta@dev", sec)
        self.assertIn("exit 127", sec)
        self.assertIn("failed", sec)
        self.assertIn("URLError: timeout", sec)
        self.assertLess(text.index("## Source status"), text.index("## Summary"))

    def test_unknown_dependency_type_is_printed_unknown_not_transitive(self):
        unk = pkg("mystery", "1.0.0", direct=None)
        dev = pkg("devmystery", "1.0.0", scope="optional", direct=None)
        loose = pkg("loose", "", direct=None)                      # unresolved: in coverage
        trans = pkg("deep", "1.0.0", direct=False)
        findings = [Finding("zeta", "main", unk, [vuln("GHSA-u", "HIGH", 7.5)]),
                    Finding("zeta", "main", dev, [vuln("GHSA-d", "HIGH", 7.5)]),
                    Finding("zeta", "main", trans, [vuln("GHSA-t", "HIGH", 7.5)])]
        invs = [inv("zeta", "main", [unk, dev, loose, trans])]
        with tempfile.TemporaryDirectory() as tmp:
            cfg = config(Path(tmp))
            rep = report.build(cfg, invs, findings, [], [], [], SOURCES_OK)
            text = self.write(Path(tmp), findings, invs=invs)
        rows = {v["name"]: v for v in rep["vulnerabilities"]}
        self.assertIsNone(rows["mystery"]["locations"][0]["direct"])
        self.assertFalse(rows["deep"]["locations"][0]["direct"])
        self.assertFalse(rows["mystery"]["direct_anywhere"])
        [cov] = rep["unresolved_versions"]
        self.assertIsNone(cov["packages"][0]["direct"])
        by_project = section(text, "Critical and high severity by project")
        self.assertRegex(by_project, r"\| mystery \| 1\.0\.0 \|[^\n]*\| unknown \| `package.json`")
        self.assertRegex(by_project, r"\| deep \| 1\.0\.0 \|[^\n]*\| no \| `package.json`")
        self.assertIn("`unknown` = the scan could not tell", by_project)
        self.assertRegex(section(text, "Dev-only findings"), r"\| devmystery \| 1\.0\.0 \|[^\n]*\| unknown \| zeta@main")

    def test_maven_packages_are_named_group_and_artifact_everywhere(self):
        def maven(group, artifact, scope="required"):
            return Component(kind="package", ecosystem="Maven", name=artifact, version="1.0",
                             purl=f"pkg:maven/{group}/{artifact}@1.0", scope=scope, locations=["pom.xml"], direct=True)
        kev = maven("org.kev", "kev-core")
        high = maven("org.high", "high-core")
        dev = maven("org.dev", "dev-core", scope="optional")
        unrated = maven("org.unrated", "unrated-core")
        hidden = maven("org.hidden", "hidden-core")
        unrated_vuln = vuln("GHSA-u", None)
        findings = [Finding("zeta", "main", kev, [vuln("GHSA-k", "HIGH", 7.5, kev=True)]),
                    Finding("zeta", "main", high, [vuln("GHSA-h", "HIGH", 7.5)]),
                    Finding("zeta", "main", dev, [vuln("GHSA-d", "HIGH", 7.5)]),
                    Finding("zeta", "main", unrated, [unrated_vuln])]
        st = vex.Statement(vuln="GHSA-x", product="pkg:github/example-org/zeta",
                           subcomponents=["pkg:maven/org.hidden/hidden-core"], status="not_affected",
                           justification="vulnerable_code_not_present", impact="", timestamp="2026-11-06T00:00:00+00:00",
                           project="zeta", path="security/vex/zeta.openvex.json")
        sup = vex.Suppressed(Finding("zeta", "main", hidden, [vuln("GHSA-x", "HIGH", 7.5)]), st)
        invs = [inv("zeta", "main", [kev, high, dev, unrated, hidden])]
        with tempfile.TemporaryDirectory() as tmp:
            text = self.write(Path(tmp), findings, suppressed=[sup], invs=invs)
            cfg = config(Path(tmp))
            inventory = report.write_inventory_md(cfg, invs, cfg.out).read_text(encoding="utf-8")
        self.assertIn("**org.kev:kev-core@1.0**", section(text, "🔴 Actively exploited (CISA KEV)"))
        self.assertIn("| org.high:high-core | 1.0 |", section(text, "Critical and high severity by project"))
        self.assertIn("| org.dev:dev-core | 1.0 |", section(text, "Dev-only findings"))
        self.assertIn("| GHSA-x | org.hidden:hidden-core | 1.0 |", section(text, "Suppressed by VEX"))
        self.assertIn("| org.unrated:unrated-core | 1.0 |", section(text, "Severity not rated"))
        self.assertIn("| org.high:high-core | Maven |", inventory)

    def test_go_mod_minimum_is_listed_apart_and_not_counted_as_eol(self):
        eol = [{"project": "zeta", "branch": "main", "product": "go", "cycle": "1.20", "status": "minimum",
                "basis": "go.mod", "cycle_status": "EOL", "eol_date": "2024-02-06", "latest": "1.20.14",
                "source": "go.mod: go.mod go 1.20 (minimum Go for the build)"},
               {"project": "alpha", "branch": "main", "product": "go", "cycle": "1.20", "status": "EOL",
                "eol_date": "2024-02-06", "latest": "1.20.14", "source": "Dockerfile: image golang:1.20"}]
        with tempfile.TemporaryDirectory() as tmp:
            cfg = config(Path(tmp))
            rep = report.build(cfg, [inv("zeta", "main", [LODASH]), inv("alpha", "main", [LODASH])], [], [], eol,
                               [], SOURCES_OK)
            text = self.write(Path(tmp), [], eol=eol)
        # the go.mod row and the image row of the same cycle are not merged into one status
        self.assertEqual(sorted((r["status"], r.get("basis")) for r in rep["runtimes"]),
                         [("EOL", None), ("minimum", "go.mod")])
        self.assertIn("| Runtimes / images past end-of-life | 1 |", section(text, "Summary"))
        self.assertEqual(rep["stats"]["allowed_unsupported"], 0)     # Go is unchanged: not counted
        sec = section(text, "Runtimes and base images")
        self.assertIn("| build minimum (cycle EOL) | go | 1.20 | 2024-02-06 |", sec)
        self.assertNotIn("Pinned runtime", sec)
        self.assertIn("zeta@main", sec)
        self.assertIn("not the Go that runs", sec)
        self.assertLess(sec.index("🔴 EOL"), sec.index("build minimum"))

    def test_declared_floor_is_a_minimum_counted_as_allowed_but_unsupported(self):
        """`requires-python` / `engines.node`: status `minimum`, not counted as EOL; an end-of-life lowest cycle is
        counted as allowed but unsupported, and the row says "allows", never "runs"."""
        eol = [{"project": "zeta", "branch": "main", "product": "python", "cycle": "3.8", "status": "minimum",
                "basis": "requires-python", "cycle_status": "EOL", "eol_date": "2024-10-07", "latest": "3.8.20",
                "source": "pyproject.toml: requires-python >=3.8", "declared": ["requires-python >=3.8"],
                "pinned": []},
               {"project": "alpha", "branch": "main", "product": "nodejs", "cycle": "18", "status": "minimum",
                "basis": "engines.node", "cycle_status": "EOL", "eol_date": "2025-04-30", "latest": "18.20.8",
                "source": "package.json: engines.node >=18", "declared": ["engines.node >=18"],
                "pinned": [{"cycle": "22", "source": "Dockerfile: image node:22-alpine"}]},
               {"project": "alpha", "branch": "main", "product": "nodejs", "cycle": "22", "status": "supported",
                "eol_date": "2027-04-30", "latest": "22.21.1", "source": "Dockerfile: image node:22-alpine"},
               {"project": "alpha", "branch": "main", "product": "python", "cycle": "3.12", "status": "minimum",
                "basis": "requires-python", "cycle_status": "supported", "eol_date": "2028-10-31", "latest": "",
                "source": "api/pyproject.toml: requires-python >=3.12", "declared": ["requires-python >=3.12"],
                "pinned": []}]
        with tempfile.TemporaryDirectory() as tmp:
            cfg = config(Path(tmp))
            rep = report.build(cfg, [inv("zeta", "main", [LODASH]), inv("alpha", "main", [LODASH])], [], [], eol,
                               [], SOURCES_OK)
            text = self.write(Path(tmp), [], eol=eol)
        self.assertEqual(rep["stats"]["allowed_unsupported"], 2)
        self.assertEqual(sum(1 for r in rep["runtimes"] if r["status"] == "EOL"), 0)
        floor = next(r for r in rep["runtimes"] if r["product"] == "nodejs" and r["cycle"] == "18")
        self.assertEqual(floor["locations"][0]["pinned"], [{"cycle": "22", "source": "Dockerfile: image node:22-alpine"}])
        summary = section(text, "Summary")
        self.assertIn("| Runtimes / images past end-of-life | 0 |", summary)
        self.assertIn("| Allowed but unsupported: declared minimum allows an end-of-life version (not counted as EOL) "
                      "| 2 |", summary)
        sec = section(text, "Runtimes and base images")
        self.assertIn("| build minimum (cycle EOL) | python | 3.8 | 2024-10-07 |", sec)
        self.assertIn("- zeta@main (pyproject.toml): build minimum: `requires-python >=3.8` allows Python 3.8, which "
                      "reached end of life on 2024-10-07. The runtime actually used is not stated in this repository. "
                      "Add `.python-version`, a Dockerfile image or a build SBOM to confirm it.", sec)
        self.assertIn("- alpha@main (package.json): build minimum: `engines.node >=18` allows Node.js 18, which "
                      "reached end of life on 2025-04-30. Pinned runtime: Node.js 22 (Dockerfile); its own row "
                      "gives the end-of-life status.", sec)
        self.assertIn("allows Python 3.12, which is supported until 2028-10-31. The runtime actually used", sec)
        self.assertNotIn(" runs Python", sec)
        self.assertNotIn("not the Go that runs", sec)            # the Go note only with a go.mod row

    def test_allowed_unsupported_counts_no_go_minimum(self):
        go = {"status": "minimum", "basis": "go.mod", "cycle_status": "EOL"}
        self.assertFalse(report.allowed_unsupported(go))
        self.assertTrue(report.allowed_unsupported({**go, "basis": "engines.node"}))
        self.assertFalse(report.allowed_unsupported({**go, "basis": "engines.node", "cycle_status": "EOL soon"}))
        self.assertFalse(report.allowed_unsupported({"status": "EOL", "basis": None}))

    def test_runtime_and_floating_sections(self):
        eol = [{"project": "zeta", "branch": "main", "product": "nodejs", "cycle": "18", "status": "EOL",
                "eol_date": "2025-04-30", "latest": "18.20.8", "source": "package.json: engines.node >=18"}]
        outdated = [{"project": "zeta", "branch": "main", "name": "lodash", "ecosystem": "npm",
                     "current": "3.10.1", "latest": "4.17.21", "major_behind": 1, "scope": "required"}]
        with tempfile.TemporaryDirectory() as tmp:
            text = self.write(Path(tmp), [], eol=eol, outdated=outdated)
        self.assertIn("🔴 EOL | nodejs | 18 | 2025-04-30", section(text, "Runtimes and base images"))
        self.assertIn("`nginx:alpine`", section(text, "Floating image tags"))
        self.assertIn("| 1 | lodash | 3.10.1 | 4.17.21 | zeta | main |", section(text, "Outdated direct dependencies (≥1 major version behind)"))


REP_EPSS = {"threshold": 0.10, "available": True, "score_date": "2026-11-23T12:00:23Z", "model_version": "v2026.06.15"}
MINIMIST = pkg("minimist", "1.2.5")


def scored(v: dict, score):
    """An advisory as the EPSS step leaves it: `epss` and `epss_percentile` set (None without a score)."""
    return {**v, "epss": score, "epss_percentile": None if score is None else 0.9}


class EpssAuditMdTests(unittest.TestCase):
    def render(self, tmp: Path, findings, epss=REP_EPSS, sources=SOURCES_OK) -> str:
        cfg = config(tmp)
        invs = [inv("zeta", "main", [LODASH, MINIMIST, ESBUILD])]
        rep = report.build(cfg, invs, findings, [], [], [], sources, epss=epss)
        cfg.out.mkdir(parents=True, exist_ok=True)
        return report.write_audit_md(rep, cfg.out).read_text(encoding="utf-8")

    def findings(self, high=0.4413, medium=None, dev=None, with_epss=True):
        mark = scored if with_epss else (lambda v, _s: v)
        return [Finding("zeta", "main", LODASH, [mark(vuln("GHSA-1", "HIGH", 7.5, aliases=["CVE-2021-23337"]), high)]),
                Finding("zeta", "main", MINIMIST, [mark(vuln("GHSA-2", "MEDIUM", 5.0), medium)]),
                Finding("zeta", "main", ESBUILD, [mark(vuln("GHSA-9", "HIGH", 8.1), dev)])]

    def test_epss_promoted_predicate(self):
        prod = {"zeta"}
        row = lambda **kw: {"kev": False, "max_severity": "MEDIUM", "max_epss": 0.2, "vulns": [{"id": "CVE-1", "severity": "MEDIUM"}],
                            "locations": [{"project": "zeta", "branch": "main", "manifest": "m", "scope": "required"}], **kw}
        self.assertTrue(report.epss_promoted(row(), prod, 0.10))
        for changed in (dict(kev=True), dict(max_severity="HIGH"), dict(max_epss=0.0999), dict(max_epss=None),
                        dict(locations=[{"project": "zeta", "branch": "main", "manifest": "m", "scope": "optional"}]),
                        dict(locations=[{"project": "other", "branch": "main", "manifest": "m", "scope": "required"}])):
            self.assertFalse(report.epss_promoted(row(**changed), prod, 0.10), changed)
        self.assertFalse(report.epss_promoted(row(), prod, 0))
        self.assertFalse(report.epss_promoted(row(), prod, None))

    def test_audit_md_shows_epss_column_and_section(self):
        # one HIGH row max_epss 0.4413 in production project zeta, one MEDIUM row max_epss None, and a dev-only
        # HIGH row without a score (so a table shows `no EPSS`)
        with tempfile.TemporaryDirectory() as tmp:
            text = self.render(Path(tmp), self.findings())
        self.assertIn("| Sev | EPSS | Package |", text)
        self.assertIn("44.1%", text); self.assertIn("no EPSS", text)
        self.assertIn("## Likely to be exploited (EPSS)", text)
        self.assertIn("EPSS 44.1%", text)
        sec = section(text, "Likely to be exploited (EPSS)")
        self.assertIn("(scores of 2026-11-23)", sec)
        self.assertIn("- **lodash@4.17.20** (npm, runtime scope): EPSS 44.1%, GHSA-1 CVE-2021-23337 - used by zeta@main",
                      sec)
        self.assertNotIn("minimist", sec)
        self.assertEqual(headings(text).index("Likely to be exploited (EPSS)"),
                         headings(text).index("🔴 Actively exploited (CISA KEV)") + 1)
        self.assertIn("| HIGH 7.5 | 44.1% | lodash |", section(text, "Critical and high severity by project"))
        self.assertIn("| HIGH 8.1 | no EPSS | esbuild |", section(text, "Dev-only findings"))
        self.assertIn("| Promoted by EPSS (at or above 10.0%, in production or a supported release) | 0 |",
                      section(text, "Summary"))
        self.assertIn("never lowers a rank", text)

    def test_summary_counts_promoted_rows_and_says_off_at_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            text = self.render(Path(tmp), self.findings(medium=0.25))
            off = self.render(Path(tmp), self.findings(medium=0.25), epss={**REP_EPSS, "threshold": 0})
        self.assertIn("| Promoted by EPSS (at or above 10.0%, in production or a supported release) | 1 |",
                      section(text, "Summary"))
        self.assertIn("- **minimist@1.2.5** (npm, runtime scope): EPSS 25.0%, GHSA-2 - used by zeta@main; "
                      "promoted to priority 3", section(text, "Likely to be exploited (EPSS)"))
        self.assertIn("| Promoted by EPSS | off |", section(off, "Summary"))
        self.assertIn("Promotion by EPSS is turned off ([epss] promote_at = 0); scores are shown in the tables.",
                      section(off, "Likely to be exploited (EPSS)"))
        self.assertIn("44.1%", section(off, "Critical and high severity by project"))

    def test_section_marks_the_rows_the_summary_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            sec = section(self.render(Path(tmp), self.findings(medium=0.25, dev=0.5)), "Likely to be exploited (EPSS)")
        self.assertIn("Rows marked promoted are the ones the summary counts; the others were already urgent or are "
                      "not ranked like production.", sec)
        lines = {line.split("**")[1]: line for line in sec.splitlines() if line.startswith("- **")}
        self.assertEqual(sorted(lines), ["esbuild@0.17.0", "lodash@4.17.20", "minimist@1.2.5"])
        self.assertTrue(lines["minimist@1.2.5"].endswith("; promoted to priority 3"))
        self.assertNotIn("promoted", lines["lodash@4.17.20"])       # HIGH: already urgent
        self.assertNotIn("promoted", lines["esbuild@0.17.0"])       # dev-only: not ranked like production

    def test_section_says_so_when_no_listed_row_is_promoted(self):
        with tempfile.TemporaryDirectory() as tmp:
            sec = section(self.render(Path(tmp), self.findings()), "Likely to be exploited (EPSS)")
        self.assertIn("- **lodash@4.17.20**", sec)
        self.assertNotIn("Rows marked promoted", sec)
        self.assertIn("a low or missing score does not mean safe. None of the rows below is promoted: each was "
                      "already urgent or is not ranked like production. Package versions at or above 10.0%:", sec)

    def test_score_exactly_at_the_threshold_is_counted_and_listed(self):
        with tempfile.TemporaryDirectory() as tmp:
            at = self.render(Path(tmp), self.findings(high=0.01, medium=0.10))
            under = self.render(Path(tmp), self.findings(high=0.01, medium=0.0999))
        self.assertIn("| Promoted by EPSS (at or above 10.0%, in production or a supported release) | 1 |",
                      section(at, "Summary"))
        self.assertIn("- **minimist@1.2.5** (npm, runtime scope): EPSS 10.0%", section(at, "Likely to be exploited (EPSS)"))
        self.assertIn("| Promoted by EPSS (at or above 10.0%, in production or a supported release) | 0 |",
                      section(under, "Summary"))
        self.assertNotIn("minimist", section(under, "Likely to be exploited (EPSS)"))

    def test_summary_says_not_available_when_the_source_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            text = self.render(Path(tmp), self.findings(high=None), epss={**REP_EPSS, "available": False})
        self.assertIn("| Promoted by EPSS | not available |", section(text, "Summary"))
        self.assertNotIn("| Promoted by EPSS (at or above", text)

    def test_no_row_at_or_above_the_threshold(self):
        with tempfile.TemporaryDirectory() as tmp:
            text = self.render(Path(tmp), self.findings(high=0.05))
        self.assertIn("None of the vulnerable package versions has an EPSS score at or above 10.0%.",
                      section(text, "Likely to be exploited (EPSS)"))

    def test_by_project_rows_sort_by_epss_within_a_severity(self):
        axios = pkg("axios", "0.21.0")
        findings = [Finding("zeta", "main", axios, [scored(vuln("GHSA-3", "HIGH", 7.5), 0.01)]),
                    Finding("zeta", "main", LODASH, [scored(vuln("GHSA-1", "HIGH", 7.5), 0.5)])]
        with tempfile.TemporaryDirectory() as tmp:
            cfg = config(Path(tmp))
            rep = report.build(cfg, [inv("zeta", "main", [axios, LODASH])], findings, [], [], [], SOURCES_OK,
                               epss=REP_EPSS)
            cfg.out.mkdir(parents=True)
            sec = section(report.write_audit_md(rep, cfg.out).read_text(encoding="utf-8"),
                          "Critical and high severity by project")
        self.assertLess(sec.index("| lodash |"), sec.index("| axios |"))

    def test_audit_md_without_epss_block_is_unchanged(self):
        # the same report without rep["epss"] and without the row and advisory keys
        with tempfile.TemporaryDirectory() as tmp:
            text = self.render(Path(tmp), self.findings(with_epss=False), epss=None)
        self.assertNotIn("EPSS", text)

    def test_audit_md_says_when_epss_was_not_available(self):
        # rep["epss"]["available"] = False, every max_epss None
        with tempfile.TemporaryDirectory() as tmp:
            text = self.render(Path(tmp), self.findings(high=None), epss={**REP_EPSS, "available": False})
        self.assertIn("EPSS scores were not available in this run. No finding was promoted or demoted because of it.", text)
        self.assertNotIn("no EPSS", text)
        self.assertIn("| HIGH 7.5 | n/a | lodash |", text)

    def test_source_status_shows_stale_and_failed_epss(self):
        base = {"loaded": 2, "scored": 1, "score_date": "2026-11-22T12:00:00Z", "model_version": "v2026.06.15",
                "origin": "stale", "fetched_at": "2026-11-22T13:00:00Z", "error": None,
                "warning": "EPSS download failed: URLError: timeout"}
        with tempfile.TemporaryDirectory() as tmp:
            stale = self.render(Path(tmp), self.findings(), sources={**SOURCES_OK, "epss": base})
            failed = self.render(Path(tmp), self.findings(high=None), epss={**REP_EPSS, "available": False},
                                 sources={**SOURCES_OK, "epss": {**base, "loaded": 0, "origin": None, "warning": None,
                                                                  "error": "EPSS fetch failed: URLError: down"}})
        self.assertIn("| epss | stale | ", section(stale, "Source status"))
        self.assertIn("EPSS download failed: URLError: timeout |", section(stale, "Source status"))
        self.assertIn("| epss | **failed** | EPSS fetch failed: URLError: down |", section(failed, "Source status"))


class FilesTests(unittest.TestCase):
    def test_log_line_dedupes_floating_images(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = config(Path(tmp))
            invs = [inv("zeta", "main", [LODASH, NGINX]), inv("zeta", "dev", [LODASH, NGINX]),
                    inv("alpha", "main", [QDRANT])]
            findings = [Finding("zeta", "main", LODASH, [vuln("GHSA-1", "HIGH", 7.5)])]
            rep = report.build(cfg, invs, findings, [], [], [], SOURCES_OK)
            self.assertEqual(len(rep["unpinned_images"]), 3)
            cfg.out.mkdir(parents=True)
            report.append_log(cfg.out, rep, invs)
            report.append_log(cfg.out, rep, invs)
            lines = (cfg.out / "log.md").read_text(encoding="utf-8").splitlines()
        self.assertTrue(lines[0].startswith("# "))
        runs = [l for l in lines if " | run | " in l]
        self.assertEqual(len(runs), 2)
        fields = runs[-1].split(" | ")
        self.assertEqual(fields[1:], ["run", "2", "1", "0", "0", "1", "0", "2", "0"])
        dt.datetime.fromisoformat(fields[0])

    def test_json_and_dated_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = config(Path(tmp))
            rep = report.build(cfg, [inv("zeta", "main", [LODASH])], [], [], [], [], SOURCES_OK)
            cfg.out.mkdir(parents=True)
            jp = report.write_json(rep, cfg.out)
            self.assertEqual(json.loads(jp.read_text())["stats"]["projects"], 1)
            report.write_audit_md(rep, cfg.out)
            dated = report.write_dated_copy(cfg.out)
            self.assertEqual(dated.name, f"{dt.date.today().isoformat()}-audit.md")
            self.assertEqual(dated.read_text(), (cfg.out / "AUDIT.md").read_text())

    def test_inventory_overview_lists_runtimes_frameworks_and_images(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = config(Path(tmp))
            invs = [inv("zeta", "main", [LODASH, ESBUILD, NGINX, NODE18, pkg("astro", "5.2.0"),
                                          pkg("fastapi", "0.115.0", ecosystem="PyPI", manifest="uv.lock")], behind=2),
                    inv("alpha", "main", [pkg("left-pad", "1.3.0", direct=False)])]
            cfg.out.mkdir(parents=True)
            text = report.write_inventory_md(cfg, invs, cfg.out).read_text(encoding="utf-8")
        self.assertTrue(text.startswith("# Inventory"))
        self.assertIn("| Project | Branch | Node | Python | Deno | Expo/React Native | SvelteKit | NestJS | Astro | Vite | FastAPI | Postgres | Images |", text)
        row = next(l for l in text.splitlines() if l.startswith("| zeta | main |"))
        self.assertIn("| 18 |", row)
        self.assertIn("| 5.2.0 |", row)
        self.assertIn("| 0.115.0 |", row)
        self.assertIn("nginx:alpine", row)
        self.assertIn("## zeta", text)
        self.assertIn("2 behind origin", text)
        self.assertIn("| lodash | npm | `package.json` |", text)
        self.assertIn("esbuild", text)
        self.assertNotIn("| left-pad", text)
        self.assertNotIn("Java/JDK", text)               # optional columns only when a branch has a value
        assert_tables_well_formed(self, text)

    def test_inventory_overview_has_java_go_dotnet_and_other_runtimes(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = config(Path(tmp))
            invs = [inv("jvm", "main", [runtime_component("eclipse-temurin", "21", "pom.xml", "java.version")]),
                    inv("gosvc", "main", [runtime_component("go", "1.23", "go.mod", "go directive")]),
                    inv("api", "main", [runtime_component("dotnet", "8.0", "global.json", "sdk.version"),
                                        runtime_component("ruby", "3.3", ".ruby-version", "pin"),
                                        runtime_component("redis", "7", "compose.yml", "image", image="redis:7")])]
            cfg.out.mkdir(parents=True)
            text = report.write_inventory_md(cfg, invs, cfg.out).read_text(encoding="utf-8")
        header = next(l for l in text.splitlines() if l.startswith("| Project | Branch |"))
        self.assertTrue(header.endswith("| Postgres | Java/JDK | Go | .NET | ruby | Images |"), header)
        self.assertNotIn("redis |", header)              # derived from an image: the Images column shows it
        self.assertIn("| jvm | main |", text)
        jvm = next(l for l in text.splitlines() if l.startswith("| jvm | main |"))
        self.assertIn("| eclipse-temurin 21 |", jvm)     # several names in the column: the name is shown
        go = next(l for l in text.splitlines() if l.startswith("| gosvc | main |"))
        self.assertIn("| 1.23 |", go)
        api = next(l for l in text.splitlines() if l.startswith("| api | main |"))
        self.assertIn("dotnet 8.0", api)
        self.assertIn("| 3.3 |", api)
        assert_tables_well_formed(self, text)

    def test_github_actions_are_counted_as_not_checked(self):
        action = Component(kind="package", ecosystem="github", name="actions/checkout", version="v4",
                           purl="pkg:github/actions/checkout@v4", scope="required",
                           locations=[".github/workflows/ci.yml"], direct=True)
        with tempfile.TemporaryDirectory() as tmp:
            cfg = config(Path(tmp))
            invs = [inv("zeta", "main", [LODASH, action]), inv("zeta", "dev", [action])]
            rep = report.build(cfg, invs, [], [], [], [], SOURCES_OK)
            self.assertEqual(rep["stats"]["github_actions_unchecked"], 2)
            self.assertIn("zeta@main: 1 GitHub Actions are inventoried but not checked for vulnerabilities (OSV does "
                          "not match versions for this ecosystem): `actions/checkout`", rep["notes"])
            cfg.out.mkdir(parents=True)
            text = report.write_audit_md(rep, cfg.out).read_text(encoding="utf-8")
            self.assertIn("| GitHub Actions inventoried, not checked for vulnerabilities | 2 |", text)
            assert_tables_well_formed(self, text)
            rep = report.build(cfg, [inv("zeta", "main", [LODASH])], [], [], [], [], SOURCES_OK)
            self.assertEqual(rep["stats"]["github_actions_unchecked"], 0)
            self.assertNotIn("GitHub Actions", report.write_audit_md(rep, cfg.out).read_text(encoding="utf-8"))


def assert_tables_well_formed(case: unittest.TestCase, text: str) -> None:
    """Every Markdown table's delimiter row has one `---` cell per header cell and starts with `|`."""
    lines = text.splitlines()
    for i, line in enumerate(lines[1:], 1):
        if line.startswith("|") and set(line.replace("|", "").replace(" ", "")) <= {"-", ":"} and "---" in line:
            header = lines[i - 1]
            cells = header.strip().strip("|").split(" | ")
            case.assertEqual(line, "|" + "---|" * len(cells), f"delimiter under {header!r}")


def maven(version, manifest, purl_version=True):
    """org.a:core as one manifest declares it; an unresolved Gradle declaration has no version in the purl."""
    purl = "pkg:maven/org.a/core" + (f"@{version}" if version and purl_version else "")
    return Component(kind="package", ecosystem="Maven", name="core", version=version, purl=purl,
                     scope="required", locations=[manifest], direct=True)


class SameCoordinateTwoManifestsTests(unittest.TestCase):
    """One package declared in a pom.xml and a build.gradle: two inventory rows (evidence), one package in
    every count of distinct packages, one INVENTORY.md line naming both manifests."""
    POM = maven("${core.version}", "pom.xml")
    GRADLE = maven("", "build.gradle")

    def build(self, invs, findings=()):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = config(Path(tmp), production=("jvm",))
            rep = report.build(cfg, invs, list(findings), [], [], [], SOURCES_OK)
            cfg.out.mkdir(parents=True)
            inventory = report.write_inventory_md(cfg, invs, cfg.out).read_text(encoding="utf-8")
            audit = report.write_audit_md(rep, cfg.out).read_text(encoding="utf-8")
        return rep, inventory, audit

    def test_inventory_md_shows_one_line_naming_both_manifests(self):
        invs = [inv("jvm", "main", [self.POM, self.GRADLE])]
        self.assertEqual(len(invs[0].components), 2)                       # both rows stay
        _, text, _ = self.build(invs)
        lines = [l for l in text.splitlines() if l.startswith("| org.a:core")]
        self.assertEqual(lines, ["| org.a:core | Maven | same coordinate, 2 manifests: `pom.xml`, `build.gradle` "
                                 "| unresolved | required |"])
        self.assertIn("**Direct dependencies** (1;", text)
        assert_tables_well_formed(self, text)

    def test_different_resolved_versions_stay_separate_lines(self):
        _, text, _ = self.build([inv("jvm", "main", [maven("1.0", "pom.xml"), maven("2.0", "build.gradle")])])
        lines = [l for l in text.splitlines() if l.startswith("| org.a:core")]
        self.assertEqual(lines, ["| org.a:core | Maven | `build.gradle` | 2.0 | required |",
                                 "| org.a:core | Maven | `pom.xml` | 1.0 | required |"])
        self.assertIn("2 distinct packages (Maven 2; 2 direct, 0 dev-only)", text)

    def test_branch_package_total_counts_the_coordinate_once(self):
        _, text, _ = self.build([inv("jvm", "main", [self.POM, self.GRADLE, pkg("lodash", "4.17.21")])])
        self.assertIn("2 distinct packages in 3 manifest rows (Maven 1, npm 1; 2 direct, 0 dev-only)", text)

    def test_branch_line_uses_the_singular_for_one(self):
        _, text, _ = self.build([inv("jvm", "main", [self.POM, self.GRADLE])])
        self.assertIn("1 distinct package in 2 manifest rows (Maven 1;", text)
        self.assertNotIn("1 distinct packages", text)
        self.assertIn("0 images, 0 runtime pins", text)

    def test_release_package_total_counts_the_coordinate_once(self):
        rel = BranchInventory(project="jvm", branch="tags/v1", ref="refs/tags/v1", commit="abc1234def",
                              components=[self.POM, self.GRADLE], release={"tag": "v1", "date": "2026-01-01",
                                                                           "index": 0})
        _, text, _ = self.build([inv("jvm", "main", [self.POM]), rel])
        self.assertIn("| Distinct packages |", text)
        self.assertIn("| jvm | `v1` | abc1234 | 2026-01-01 | 1 | 0 | 0 | – |", text)

    def test_audit_json_stats_distinct_versus_declarations(self):
        rep, _, audit = self.build([inv("jvm", "main", [self.POM, self.GRADLE]),
                                    inv("jvm", "dev", [self.POM, self.GRADLE])])
        st = rep["stats"]
        self.assertEqual(st["unique_package_versions"], 1)       # distinct over the portfolio
        self.assertEqual(st["occurrences"], 4)                   # inventory rows, deliberately
        self.assertEqual(st["direct_dependencies"], 2)           # distinct per project and branch
        self.assertEqual(st["unresolved_versions"], 2)           # one per branch
        self.assertEqual([r["count"] for r in rep["unresolved_versions"]], [1, 1])
        self.assertEqual(rep["unresolved_versions"][0]["packages"][0]["manifests"], ["pom.xml", "build.gradle"])
        self.assertIn("| Distinct package versions (ecosystem, name, version) | 1 |", audit)

    def test_distinct_package_versions_say_how_many_were_not_checked(self):
        action = Component(kind="package", ecosystem="github", name="actions/checkout", version="v4",
                           purl="pkg:github/actions/checkout@v4", scope="required", locations=[".github/x.yml"])
        components = [pkg("lodash", "4.17.21"), pkg("zlib", "1.3", ecosystem="generic", manifest="bom.json"),
                      pkg("fmt", "10.0", ecosystem="vcpkg", manifest="bom.json"), action, self.POM]
        rep, _, audit = self.build([inv("jvm", "main", components), inv("jvm", "dev", components)])
        st = rep["stats"]
        self.assertEqual(st["unique_package_versions"], 5)
        self.assertEqual(st["unique_package_versions_unchecked"], 4)   # generic, vcpkg, action, unresolved
        self.assertIn("| Distinct package versions (ecosystem, name, version) | 5 |", audit)
        self.assertIn("| … of these not checked for vulnerabilities (OSV cannot match the type, GitHub Actions, "
                      "version not resolved) | 4 |", audit)

    def test_no_unchecked_row_when_every_version_was_checked(self):
        rep, _, audit = self.build([inv("jvm", "main", [maven("1.0", "pom.xml")])])
        self.assertEqual(rep["stats"]["unique_package_versions_unchecked"], 0)
        self.assertNotIn("of these not checked", audit)

    def test_status_counts_are_not_inflated(self):
        from sbomaudit import status
        resolved_pom, resolved_gradle = maven("1.0", "pom.xml"), maven("1.0", "build.gradle")
        advisory = [vuln("GHSA-core", "HIGH", 7.5, ["1.1"])]
        rep, _, audit = self.build(
            [inv("jvm", "main", [self.POM, self.GRADLE]), inv("jvm", "dev", [resolved_pom, resolved_gradle])],
            [Finding("jvm", "dev", resolved_pom, advisory), Finding("jvm", "dev", resolved_gradle, advisory)])
        self.assertEqual(len(rep["vulnerabilities"]), 1)
        self.assertEqual(sorted(l["manifest"] for l in rep["vulnerabilities"][0]["locations"]),
                         ["build.gradle", "pom.xml"])
        counts = status.build(rep, secrets=None, previous=None, duration_s=1.0, exit_code=1, run_host="h",
                              mode="full")["counts"]
        self.assertEqual((counts["vulnerable"], counts["critical_high_production"], counts["unresolved_versions"]),
                         (1, 1, 1))
        self.assertIn("| Vulnerable package versions | 1 |", audit)

    def test_sbom_check_counts_component_entries_and_says_so(self):
        from sbomaudit import sbomquality
        entries = [{"bom-ref": "a", "type": "library", "name": "core", "version": "${core.version}",
                    "purl": "pkg:maven/org.a/core@${core.version}"},
                   {"bom-ref": "b", "type": "library", "name": "core", "purl": "pkg:maven/org.a/core"}]
        result = sbomquality.check({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                                    "components": entries})
        self.assertEqual((result["coverage"]["components"], result["coverage"]["version"]), (2, 1))
        self.assertIn("  data fields of 2 component entries:", sbomquality.render("x.cdx.json", result))
        text = sbomquality.cra_note(sbomquality.summary(result))         # CRA.md's SBOM evidence note
        self.assertIn("2 component entries: version 50%", text)


class MdEscapeTests(unittest.TestCase):
    def test_md_keeps_untrusted_text_on_one_inert_line(self):
        self.assertEqual(report.md("a|b\nc\x1b[31mred\u202eevil\x00z\u2028end"), "a\\|b c [31mred evil z end")

    def test_worst_advisory_is_shared_by_audit_and_issues(self):
        advisories = [{"id": "GHSA-b", "severity": "HIGH", "cvss": 7.2}, {"id": "GHSA-a", "severity": "HIGH", "cvss": 8.1},
                      {"id": "GHSA-m", "severity": "MEDIUM", "cvss": 6.5}]
        self.assertEqual(report.worst_advisory(advisories)["id"], "GHSA-a")
        self.assertEqual(report.worst_advisory(advisories + [{"id": "GHSA-k", "severity": "LOW", "kev": True}])["id"], "GHSA-k")
        self.assertIsNone(report.worst_advisory([]))

if __name__ == "__main__":
    unittest.main()


class AppendNoteTests(unittest.TestCase):
    def test_append_note_on_empty_header_only_and_hand_written_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            log = out / "log.md"
            report.append_note(out, "removed sbom/gone")           # missing file
            lines = log.read_text().splitlines()
            self.assertEqual(log.read_text(), report.LOG_HEADER + "removed sbom/gone\n")
            self.assertEqual(lines[-1], "removed sbom/gone")
            self.assertFalse(lines[-1].startswith(" | "))
            log.write_text("")                                     # empty file
            report.append_note(out, "removed sbom/a")
            self.assertEqual(log.read_text().splitlines()[-1], "removed sbom/a")
            self.assertTrue(log.read_text().startswith(report.LOG_HEADER.splitlines()[0]))
            log.write_text(report.LOG_HEADER)                      # header only
            report.append_note(out, "removed sbom/b")
            self.assertEqual(log.read_text().splitlines()[-1], "removed sbom/b")
            log.write_text(report.LOG_HEADER + "my own remark\n")  # hand-written last line
            report.append_note(out, "removed sbom/c")
            self.assertEqual(log.read_text().splitlines()[-2:], ["my own remark", "removed sbom/c"])
            log.write_text(report.LOG_HEADER + "2026-11-07 10:00 | run | 0 vulnerable\n")
            report.append_note(out, "removed sbom/d")
            self.assertEqual(log.read_text().splitlines()[-1],
                             "2026-11-07 10:00 | run | 0 vulnerable | removed sbom/d")
            self.assertTrue(log.read_text().endswith("\n"))


class AppendAssessLogTests(unittest.TestCase):
    def test_header_created_and_one_line_per_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            report.append_assess_log(out, "reports/2026-11-08-assessment-proposal.md", 0.4)
            text = (out / "log.md").read_text()
            self.assertTrue(text.startswith(report.LOG_HEADER))
            line = text.splitlines()[-1]
            self.assertRegex(line, r"^\d{4}-\d{2}-\d{2}\S* \| assess-proposal \| cost 0\.40 \| "
                                   r"reports/2026-11-08-assessment-proposal\.md$")
            self.assertEqual(text, report.LOG_HEADER + line + "\n")

    def test_assess_line_uses_the_run_lines_clock(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(report, "_now", return_value="2026-11-08T03:00:00+01:00"):
            report.append_assess_log(Path(tmp), "reports/2026-11-08-assessment-proposal.md", 1.0)
            line = (Path(tmp) / "log.md").read_text().splitlines()[-1]
        self.assertEqual(line, "2026-11-08T03:00:00+01:00 | assess-proposal | cost 1.00 | "
                               "reports/2026-11-08-assessment-proposal.md")

    def test_cost_unknown_and_appends_after_existing_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "log.md").write_text(report.LOG_HEADER + "2026-11-07 10:00 | run | 0\n")
            report.append_assess_log(out, "reports/x-assessment-proposal.md", None)
            lines = (out / "log.md").read_text().splitlines()
            self.assertEqual(lines[-2], "2026-11-07 10:00 | run | 0")
            self.assertRegex(lines[-1], r" \| assess-proposal \| cost unknown \| reports/x-assessment-proposal\.md$")
