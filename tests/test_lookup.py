"""lookup (who uses what) and incident (are we affected) from the last scan and audit."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from sbomaudit import cli, lookup, report, scan, vex
from sbomaudit.config import Config, ProjectOpts
from sbomaudit.model import BranchInventory, Component, Finding
from sbomaudit.readers import image_component, runtime_component
from tests.helpers import not_found


def pkg(name, version, ecosystem="npm", direct=True, scope="required", manifest="package-lock.json"):
    purl_type = {"npm": "npm", "PyPI": "pypi"}[ecosystem]
    return Component(kind="package", ecosystem=ecosystem, name=name, version=version,
                     purl=f"pkg:{purl_type}/{name.lower()}@{version}", scope=scope,
                     locations=[manifest], direct=direct)


LODASH_OLD = pkg("lodash", "4.17.20")
LODASH_NEW = pkg("lodash", "4.17.21")
FLASK_LOGIN = pkg("Flask-Login", "0.6.3", ecosystem="PyPI", manifest="pyproject.toml")
EXPO = pkg("expo", "54.0.0")
EXPO_ROUTER = pkg("expo-router", "6.0.0")
EXPO_FONT = pkg("expo-font", "14.0.0", direct=False)
NGINX = image_component("nginx:alpine", "Dockerfile")
NODE18 = runtime_component("nodejs", "18", "package.json", "engines.node >=18")


def inv(project, branch, components):
    return BranchInventory(project=project, branch=branch, ref=branch, commit="abc1234def",
                           components=list(components), sbom_path=f"sbom/{project}/{branch}.cdx.json")


INVS = [inv("zeta", "main", [LODASH_OLD, FLASK_LOGIN, EXPO_ROUTER, EXPO_FONT, NGINX, NODE18]),
        inv("alpha", "dev", [LODASH_NEW, EXPO]),
        inv("beta", "main", [EXPO])]


def vuln(vid="GHSA-1", aliases=("CVE-2026-1",)):
    return {"id": vid, "aliases": list(aliases), "cves": ["CVE-2026-1"], "summary": "prototype pollution",
            "severity": "HIGH", "cvss": 7.5, "fixed": ["4.17.21"], "published": "2026-01-01",
            "modified": "2026-01-02", "withdrawn": False}


OSV_RECORD = {"id": "GHSA-1", "aliases": ["CVE-2026-1"], "summary": "prototype pollution",
              "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                            "ranges": [{"type": "SEMVER",
                                        "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}
OSV_URL = "https://api.osv.dev/v1/vulns/CVE-2026-1"
INVENTORY_STAMP = "2026-11-01T10:00:00Z"     # safely before any audit.json written by report.build (now)


def stub_fetch(table: dict):
    calls = []

    def fetch(url):
        calls.append(url)
        if url not in table:
            raise not_found(url)
        return table[url]

    fetch.calls = calls
    return fetch


def write_state(tmp: Path, with_audit=True, inventories=None) -> Config:
    invs = INVS if inventories is None else inventories
    root = tmp / "root"
    out = root / "security"
    out.mkdir(parents=True)
    cfg = Config(out=out, root=root, mode="portfolio", fetch=False,
                 projects={"zeta": ProjectOpts(production=True)})
    scan.write_inventory(cfg, scan.ScanResult(inventories=invs, generated_at=INVENTORY_STAMP))
    if with_audit:
        findings = [Finding("zeta", "main", LODASH_OLD, [vuln()])]
        rep = report.build(cfg, invs, findings, [], [], [], {"osv-scanner": {"scanned": 3, "failed": []}})
        report.write_json(rep, out)
    return cfg


class RowsTests(unittest.TestCase):
    def test_lookup_glob_and_pypi_normalisation(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_state(Path(tmp))
            rows = lookup.rows(cfg.out, ["flask_login"])
            self.assertEqual([(r.name, r.version, r.project, r.branch, r.how, r.manifest) for r in rows],
                             [("Flask-Login", "0.6.3", "zeta", "main", "direct", "pyproject.toml")])
            rows = lookup.rows(cfg.out, ["expo-*"])
            self.assertEqual([(r.name, r.how) for r in rows], [("expo-font", "transitive"), ("expo-router", "direct")])
            self.assertEqual([(r.name, r.how, r.version) for r in lookup.rows(cfg.out, ["nginx"])],
                             [("nginx", "image", "alpine")])
            self.assertEqual(len(lookup.rows(cfg.out, ["nginx:alpine"])), 1)
            self.assertEqual([(r.name, r.how, r.version) for r in lookup.rows(cfg.out, ["nodejs"])],
                             [("nodejs", "runtime", "18")])
            self.assertEqual(len(lookup.rows(cfg.out, ["LODASH"])), 2)
            self.assertEqual(lookup.rows(cfg.out, ["nothing-here"]), [])

    def test_how_is_unknown_when_the_scan_could_not_tell(self):
        def c(direct):
            return Component(kind="package", ecosystem="npm", name="x", version="1", purl="pkg:npm/x@1",
                             scope="required", locations=["package.json"], direct=direct)
        self.assertEqual([lookup._how(c(d)) for d in (True, False, None)], ["direct", "transitive", "unknown"])

    def test_lookup_cli_table_and_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_state(Path(tmp))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.main(["--out", str(cfg.out), "lookup", "expo-*", "lodash"])
            self.assertEqual(rc, 0)
            text = buf.getvalue()
            self.assertIn("| expo-router |", text)
            self.assertIn("| lodash | 4.17.20 | zeta | main |", text)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["--out", str(cfg.out), "lookup", "nothing-here"]), 1)


class IncidentTests(unittest.TestCase):
    def test_incident_verdicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_state(Path(tmp))
            fetch = stub_fetch({OSV_URL: OSV_RECORD})
            inc = lookup.incident(cfg.out, "cve-2026-1", fetch=fetch)
            self.assertEqual(fetch.calls, [OSV_URL])
            self.assertFalse(inc.unknown)
            self.assertEqual(inc.kind, "vuln")
            self.assertEqual(inc.affected, [("npm", "lodash")])
            self.assertEqual({(v.project, v.branch, v.verdict) for v in inc.verdicts},
                             {("zeta", "main", "hit"), ("alpha", "dev", "present_not_affected"),
                              ("beta", "main", "absent")})
            hit = next(v for v in inc.verdicts if v.verdict == "hit")
            self.assertEqual((hit.name, hit.version), ("lodash", "4.17.20"))
            self.assertIn("4.17.21", hit.evidence)
            present = next(v for v in inc.verdicts if v.verdict == "present_not_affected")
            self.assertEqual(present.version, "4.17.21")

    def test_incident_verdicts_are_per_version(self):
        """Two versions of one package in a branch: only the vulnerable one is a hit."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_state(Path(tmp), inventories=[inv("zeta", "main", [LODASH_OLD, LODASH_NEW])])
            inc = lookup.incident(cfg.out, "CVE-2026-1", fetch=stub_fetch({OSV_URL: OSV_RECORD}))
            self.assertEqual([(v.verdict, v.version) for v in inc.verdicts],
                             [("hit", "4.17.20"), ("present_not_affected", "4.17.21")])
            self.assertIn("4.17.21 not in the affected range", inc.verdicts[1].evidence)

    def test_incident_unknown_id_falls_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_state(Path(tmp))
            inc = lookup.incident(cfg.out, "GHSA-nope", fetch=stub_fetch({}))
            self.assertTrue(inc.unknown)
            self.assertEqual(inc.verdicts, [])
            self.assertEqual(inc.rows, [])
            fetch = stub_fetch({})
            inc = lookup.incident(cfg.out, "lodash", fetch=fetch)
            self.assertEqual(fetch.calls, [])
            self.assertEqual(inc.kind, "package")
            self.assertEqual([(r.project, r.version) for r in inc.rows], [("alpha", "4.17.21"), ("zeta", "4.17.20")])

    def test_incident_without_audit_json_does_not_claim_not_affected(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_state(Path(tmp), with_audit=False)
            inc = lookup.incident(cfg.out, "CVE-2026-1", fetch=stub_fetch({OSV_URL: OSV_RECORD}))
            self.assertEqual(inc.verdicts, [])
            self.assertIn("audit", inc.note)
            self.assertEqual([(r.project, r.version) for r in inc.rows], [("alpha", "4.17.21"), ("zeta", "4.17.20")])

    def test_incident_follows_aliases_when_record_has_no_packages(self):
        """CVE-flavoured OSV records often carry only GIT ranges; the GHSA alias names the package."""
        cve_record = {"id": "CVE-2026-1", "aliases": ["GHSA-1"], "summary": "prototype pollution",
                      "affected": [{"ranges": [{"type": "GIT", "repo": "https://github.com/lodash/lodash",
                                                "events": [{"introduced": "abc"}, {"fixed": "def"}]}]}]}
        ghsa_url = "https://api.osv.dev/v1/vulns/GHSA-1"
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_state(Path(tmp))
            fetch = stub_fetch({OSV_URL: cve_record, ghsa_url: OSV_RECORD})
            inc = lookup.incident(cfg.out, "CVE-2026-1", fetch=fetch)
            self.assertEqual(fetch.calls, [OSV_URL, ghsa_url])
            self.assertEqual(inc.affected, [("npm", "lodash")])
            self.assertEqual(inc.fixed[("npm", "lodash")], ["4.17.21"])
            by = {(v.project, v.branch): v for v in inc.verdicts}
            self.assertEqual(by[("zeta", "main")].verdict, lookup.VERDICT_HIT)
            self.assertEqual(by[("alpha", "dev")].verdict, lookup.VERDICT_PRESENT)
            self.assertEqual(by[("beta", "main")].verdict, lookup.VERDICT_ABSENT)

    def test_incident_without_affected_packages_gives_no_verdicts(self):
        bare = {"id": "CVE-2026-1", "aliases": [], "summary": "something in a git repo",
                "affected": [{"ranges": [{"type": "GIT", "repo": "https://example.com/x",
                                          "events": [{"introduced": "abc"}]}]}]}
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_state(Path(tmp))
            inc = lookup.incident(cfg.out, "CVE-2026-1", fetch=stub_fetch({OSV_URL: bare}))
            self.assertEqual(inc.affected, [])
            self.assertEqual(inc.verdicts, [])          # never "absent" for every project
            self.assertIn("no affected packages", inc.note)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                 unittest.mock.patch.object(lookup, "http_get_json", stub_fetch({OSV_URL: bare})):
                rc = cli.main(["--out", str(cfg.out), "incident", "CVE-2026-1"])
            self.assertEqual(rc, 2)
            self.assertNotIn("| absent |", buf.getvalue())

    def test_incident_warns_when_osv_record_is_newer_than_audit(self):
        newer = dict(OSV_RECORD, modified="2099-01-01T00:00:00Z")
        older = dict(OSV_RECORD, modified="2020-01-01T00:00:00.123456789Z")
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_state(Path(tmp))
            inc = lookup.incident(cfg.out, "CVE-2026-1", fetch=stub_fetch({OSV_URL: newer}))
            self.assertIn("2099-01-01", inc.warning)
            self.assertIn("run", inc.warning)
            inc = lookup.incident(cfg.out, "CVE-2026-1", fetch=stub_fetch({OSV_URL: older}))
            self.assertEqual(inc.warning, "")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                 unittest.mock.patch.object(lookup, "http_get_json", stub_fetch({OSV_URL: newer})):
                cli.main(["--out", str(cfg.out), "incident", "CVE-2026-1"])
            self.assertIn("2099-01-01", buf.getvalue())

    def test_incident_records_vex_for_absent_projects(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_state(Path(tmp))
            inc = lookup.incident(cfg.out, "CVE-2026-1", fetch=stub_fetch({OSV_URL: OSV_RECORD}))
            files = lookup.record_absent(cfg, inc, author="test@example.invalid")
            self.assertEqual([f.name for f in files], ["beta.openvex.json"])
            sts = vex.load_all(cfg.out)
            self.assertEqual([(s.project, s.vuln, s.status, s.justification, s.subcomponents) for s in sts],
                             [("beta", "CVE-2026-1", "not_affected", "component_not_present", ["pkg:npm/lodash"])])

    def test_incident_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_state(Path(tmp))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                 unittest.mock.patch.object(lookup, "http_get_json", stub_fetch({OSV_URL: OSV_RECORD})):
                rc = cli.main(["--out", str(cfg.out), "incident", "CVE-2026-1"])
            text = buf.getvalue()
            self.assertEqual(rc, 1)
            self.assertIn("| zeta | main | lodash | 4.17.20 | hit |", text)
            self.assertIn("| beta | main |", text)
            self.assertIn("absent", text)
            with contextlib.redirect_stdout(io.StringIO()), \
                 unittest.mock.patch.object(lookup, "http_get_json", stub_fetch({})):
                self.assertEqual(cli.main(["--out", str(cfg.out), "incident", "GHSA-nope"]), 2)

    def _rewrite_audit(self, cfg, **fields):
        path = cfg.out / report.JSON_FILE
        rep = json.loads(path.read_text())
        for key, value in fields.items():
            if key == "osv_failed":
                rep["sources"]["osv-scanner"]["failed"] = value
            else:
                rep[key] = value
        path.write_text(json.dumps(rep))

    def test_incident_reports_unknown_for_branch_whose_scanner_failed(self):
        """osv-scanner failed on alpha@dev: no finding there proves nothing, so the verdict is unknown."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_state(Path(tmp))
            self._rewrite_audit(cfg, osv_failed=[{"project": "alpha", "branch": "dev", "error": "exit 127"}])
            inc = lookup.incident(cfg.out, "CVE-2026-1", fetch=stub_fetch({OSV_URL: OSV_RECORD}))
            by = {(v.project, v.branch): v for v in inc.verdicts}
            alpha = by[("alpha", "dev")]
            self.assertEqual(alpha.verdict, lookup.VERDICT_UNKNOWN)
            self.assertEqual((alpha.name, alpha.version), ("lodash", "4.17.21"))
            self.assertIn("incomplete", alpha.evidence)
            self.assertIn("exit 127", alpha.evidence)
            self.assertEqual(by[("zeta", "main")].verdict, lookup.VERDICT_HIT)
            self.assertEqual(by[("beta", "main")].verdict, lookup.VERDICT_ABSENT)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                 unittest.mock.patch.object(lookup, "http_get_json", stub_fetch({OSV_URL: OSV_RECORD})):
                rc = cli.main(["--out", str(cfg.out), "incident", "CVE-2026-1"])
            self.assertEqual(rc, 1)                      # a hit outranks an unknown branch
            self.assertIn("| alpha | dev | lodash | 4.17.21 | unknown |", buf.getvalue())

    def test_incident_exits_2_when_a_verdict_is_unknown_and_nothing_hit(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_state(Path(tmp), inventories=[inv("alpha", "dev", [LODASH_NEW]), inv("beta", "main", [EXPO])])
            self._rewrite_audit(cfg, osv_failed=[{"project": "alpha", "branch": "dev", "error": "exit 127"}])
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                 unittest.mock.patch.object(lookup, "http_get_json", stub_fetch({OSV_URL: OSV_RECORD})):
                rc = cli.main(["--out", str(cfg.out), "incident", "CVE-2026-1"])
            self.assertEqual(rc, 2)
            self.assertIn("| unknown |", buf.getvalue())
            inc = lookup.incident(cfg.out, "CVE-2026-1", fetch=stub_fetch({OSV_URL: OSV_RECORD}))
            files = lookup.record_absent(cfg, inc, author="test@example.invalid")
            self.assertEqual([f.name for f in files], ["beta.openvex.json"])   # never for the unknown project

    def test_incident_reports_unknown_for_branch_with_inventory_errors(self):
        """A branch whose git checkout or readers failed (errors, no components) is unknown, not absent."""
        broken = BranchInventory(project="gamma", branch="main", ref="main", commit="", errors=["git: no such ref"])
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_state(Path(tmp), inventories=INVS + [broken])
            inc = lookup.incident(cfg.out, "CVE-2026-1", fetch=stub_fetch({OSV_URL: OSV_RECORD}))
            by = {(v.project, v.branch): v for v in inc.verdicts}
            self.assertEqual(by[("gamma", "main")].verdict, lookup.VERDICT_UNKNOWN)
            self.assertIn("git: no such ref", by[("gamma", "main")].evidence)
            self.assertEqual(by[("beta", "main")].verdict, lookup.VERDICT_ABSENT)

    def test_incident_warns_when_inventory_is_newer_than_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_state(Path(tmp))
            self._rewrite_audit(cfg, generated_at="2026-10-31T10:00:00Z")
            inc = lookup.incident(cfg.out, "CVE-2026-1", fetch=stub_fetch({OSV_URL: OSV_RECORD}))
            self.assertIn("inventory", inc.warning)
            self.assertIn("2026-11-01", inc.warning)
            self.assertIn("2026-10-31", inc.warning)
            self.assertIn("run", inc.warning)

    def test_incident_without_audit_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_state(Path(tmp), with_audit=False)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                 unittest.mock.patch.object(lookup, "http_get_json", stub_fetch({OSV_URL: OSV_RECORD})):
                rc = cli.main(["--out", str(cfg.out), "incident", "CVE-2026-1"])
            self.assertEqual(rc, 2)
            self.assertIn("audit", buf.getvalue())
            self.assertNotIn("present_not_affected", buf.getvalue())


def osv(vid, *pairs, fixed=None):
    return {"id": vid, "aliases": [], "summary": "s",
            "affected": [{"package": {"ecosystem": eco, "name": name},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed or "9"}]}]}
                         for eco, name in pairs]}


SWIFT_NIO = Component(kind="package", ecosystem="swift", name="swift-nio", version="2.40.0",
                      purl="pkg:swift/github.com/apple/swift-nio@2.40.0", scope="required",
                      locations=["Package.resolved"], direct=None)
GO_121 = runtime_component("go", "1.21.0", "Dockerfile", "image golang:1.21.0", image="golang:1.21.0")
GO_MIN = runtime_component("go", "1.21", "go.mod", "go.mod go 1.21 (minimum Go for the build, not necessarily "
                                                   "the Go that builds the release)")
GO_PKG = Component(kind="package", ecosystem="Go", name="github.com/lib/pq", version="v1.10.9",
                   purl="pkg:golang/github.com/lib/pq@v1.10.9", scope="required", locations=["go.mod"], direct=True)


def verdicts(invs, record, hits=None):
    affected, fixed = lookup._affected(record)
    return lookup._verdicts(invs, affected, fixed, hits or {}, {})


class EcosystemTests(unittest.TestCase):
    """Advisory ecosystems compare in OSV form; what the scan cannot see is unknown, never absent."""

    def test_osv_names_for_purl_types_and_internal_names(self):
        from sbomaudit import ecosystems
        for internal, osv_name in (("swift", "SwiftURL"), ("golang", "Go"), ("go", "Go"), ("pypi", "PyPI"),
                                   ("gem", "RubyGems"), ("cargo", "crates.io"), ("composer", "Packagist"),
                                   ("github", "GitHub Actions"), ("SwiftURL", "SwiftURL"), ("npm", "npm")):
            self.assertEqual(ecosystems.osv_name(internal), osv_name, internal)
        for no_osv in ("cocoapods", "deno", "jsr", "docker", "generic"):
            self.assertIsNone(ecosystems.osv_name(no_osv), no_osv)

    def test_swift_package_matches_swifturl_advisory(self):
        """The review's case: ("SwiftURL", "github.com/apple/swift-nio") against pkg:swift/... is not absent."""
        rec = osv("GHSA-s", ("SwiftURL", "github.com/apple/swift-nio"), fixed="2.41.0")
        out = verdicts([inv("app", "main", [SWIFT_NIO])], rec)
        self.assertEqual([(v.verdict, v.name, v.version) for v in out],
                         [("present_not_affected", "swift-nio", "2.40.0")])
        hits = {("app", "main", "swifturl", "github.com/apple/swift-nio", "2.40.0"): "GHSA-s HIGH"}
        self.assertEqual([v.verdict for v in verdicts([inv("app", "main", [SWIFT_NIO])], rec, hits)], ["hit"])
        url_form = osv("GHSA-s", ("SwiftURL", "https://github.com/apple/swift-nio.git"))
        self.assertEqual([v.verdict for v in verdicts([inv("app", "main", [SWIFT_NIO])], url_form)],
                         ["present_not_affected"])

    def test_go_stdlib_advisory_against_go_runtime_is_unknown(self):
        """Runtime rows count: Go 1.21.0 from an image, or a go.mod minimum, is never absent for Go stdlib."""
        rec = osv("GO-1", ("Go", "stdlib"), fixed="1.21.5")
        out = verdicts([inv("app", "main", [GO_121])], rec)
        self.assertEqual([(v.verdict, v.name, v.version) for v in out], [("unknown", "stdlib", "1.21.0")])
        self.assertIn("1.21.5", out[0].evidence)
        out = verdicts([inv("app", "main", [GO_MIN])], dict(rec, affected=rec["affected"] + osv(
            "x", ("Go", "toolchain"))["affected"]))
        self.assertEqual({v.verdict for v in out}, {"unknown"})
        self.assertIn("minimum", out[0].evidence)
        out = verdicts([inv("app", "main", [GO_PKG])], rec)        # Go code, no Go version read
        self.assertEqual([v.verdict for v in out], ["unknown"])
        out = verdicts([inv("web", "main", [LODASH_NEW])], rec)    # no Go anywhere on the branch
        self.assertEqual([v.verdict for v in out], ["absent"])

    def test_ecosystem_outside_scan_coverage_is_unknown(self):
        rec = osv("X-1", ("CRAN", "jsonlite"))
        out = verdicts([inv("web", "main", [LODASH_NEW])], rec)
        self.assertEqual([v.verdict for v in out], ["unknown"])
        self.assertIn("CRAN", out[0].evidence)
        self.assertIn("does not inventory", out[0].evidence)

    def test_os_package_advisory_is_unknown_only_where_an_image_is_used(self):
        rec = osv("DEBIAN-1", ("Debian:12", "openssl"))
        out = verdicts([inv("web", "main", [LODASH_NEW, NGINX]), inv("lib", "main", [LODASH_NEW])], rec)
        by = {v.project: v for v in out}
        self.assertEqual(by["web"].verdict, "unknown")
        self.assertIn("nginx", by["web"].evidence)
        self.assertEqual(by["lib"].verdict, "absent")

    def test_manifest_present_but_nothing_inventoried_is_unknown(self):
        rec = osv("PYSEC-1", ("PyPI", "requests"))
        broken = inv("api", "main", [LODASH_NEW])
        broken.manifests = {"npm": ["package-lock.json"], "PyPI": ["poetry.lock"]}
        clean = inv("web", "main", [LODASH_NEW])
        clean.manifests = {"npm": ["package-lock.json"]}
        by = {v.project: v for v in verdicts([broken, clean], rec)}
        self.assertEqual(by["api"].verdict, "unknown")
        self.assertIn("poetry.lock", by["api"].evidence)
        self.assertEqual(by["web"].verdict, "absent")

    def test_empty_inventory_is_unknown_unless_the_branch_has_no_manifest(self):
        """Syft exited 0 but listed nothing: unknown. A branch with no manifest at all may be absent."""
        rec = osv("GHSA-1", ("npm", "lodash"))
        empty = inv("api", "main", [NGINX])
        empty.manifests = {"npm": ["package-lock.json"]}
        legacy = inv("old", "main", [])                      # inventory.json from before `manifests`
        static = inv("site", "main", [])
        static.manifests = {}
        by = {v.project: v for v in verdicts([empty, legacy, static], rec)}
        self.assertEqual(by["api"].verdict, "unknown")
        self.assertIn("package-lock.json", by["api"].evidence)
        self.assertEqual(by["old"].verdict, "unknown")
        self.assertEqual(by["site"].verdict, "absent")

    def test_manifests_round_trip_and_legacy_inventory_has_none(self):
        i = inv("api", "main", [])
        self.assertNotIn("manifests", i.to_dict())
        i.manifests = {"npm": ["package.json"]}
        self.assertEqual(BranchInventory.from_dict(i.to_dict()).manifests, {"npm": ["package.json"]})


class RecordAbsentTests(unittest.TestCase):
    def test_statement_is_scoped_to_the_examined_branch_and_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_state(Path(tmp), inventories=INVS + [inv("beta", "tags/v1", [EXPO])])
            inc = lookup.incident(cfg.out, "CVE-2026-1", fetch=stub_fetch({OSV_URL: OSV_RECORD}))
            lookup.record_absent(cfg, inc, author="test@example.invalid")
            sts = vex.load_all(cfg.out)
            self.assertEqual(sorted(vex.split_product(s.product)[1] for s in sts), ["main", "tags/v1"])
            for s in sts:
                self.assertIn("abc1234def", s.impact)
                self.assertIn("beta@", s.impact)
            on_dev = Finding("beta", "dev", pkg("lodash", "4.17.20"), [vuln()])   # not examined: not covered
            kept, suppressed = vex.apply([on_dev], sts, {"beta": vex.split_product(sts[0].product)[0]})
            self.assertEqual((len(kept), len(suppressed)), (1, 0))

    def test_vex_refuses_unknown_and_uncovered_ecosystems(self):
        record = {"id": "CVE-2026-1", "aliases": [], "summary": "s",
                  "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}},
                               {"package": {"ecosystem": "CRAN", "name": "jsonlite"}}]}
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_state(Path(tmp))
            inc = lookup.incident(cfg.out, "CVE-2026-1", fetch=stub_fetch({OSV_URL: record}))
            self.assertNotIn("absent", {v.verdict for v in inc.verdicts})
            self.assertEqual(lookup.record_absent(cfg, inc, author="test@example.invalid"), [])
            self.assertFalse((cfg.out / "vex").exists())
            refusals = lookup.vex_refusals(inc)
            self.assertTrue(any("CRAN" in r for r in refusals), refusals)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                 unittest.mock.patch.object(lookup, "http_get_json", stub_fetch({OSV_URL: record})):
                rc = cli.main(["--out", str(cfg.out), "incident", "CVE-2026-1", "--vex"])
            self.assertEqual(rc, 1)
            self.assertIn("not recorded", buf.getvalue())
            self.assertFalse((cfg.out / "vex").exists())

    def test_record_absent_never_writes_for_an_unknown_verdict(self):
        """Even a hand-built Incident: a project with any unknown verdict gets no component_not_present."""
        inc = lookup.Incident(ident="CVE-2026-1", kind="vuln", affected=[("npm", "lodash")],
                              verdicts=[lookup.Verdict("beta", "main", lookup.VERDICT_ABSENT, evidence="not in SBOM"),
                                        lookup.Verdict("beta", "dev", lookup.VERDICT_UNKNOWN, evidence="x")])
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_state(Path(tmp))
            self.assertEqual(lookup.record_absent(cfg, inc, author="test@example.invalid"), [])
            self.assertTrue(any("beta" in r for r in lookup.vex_refusals(inc)))


if __name__ == "__main__":
    unittest.main()
