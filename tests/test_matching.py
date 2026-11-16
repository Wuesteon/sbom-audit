"""osv-scanner matching.

tests/fixtures/osv-scanner-output.json was captured on 2026-11-06 with
`osv-scanner scan source -L sbom/npm-lock/main.cdx.json --format json` (osv-scanner 2.7.0)
on the Task 6 SBOM of tests/fixtures/npm-lock; the run exited 1 (vulnerabilities found).
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import cvss, matching, model
from sbomaudit.errors import ToolError

FIXTURES = Path(__file__).resolve().parent / "fixtures"
OSV_FIXTURE = json.loads((FIXTURES / "osv-scanner-output.json").read_text())
HAVE_OSV = shutil.which("osv-scanner") is not None

V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def vuln(**over) -> dict:
    base = {
        "id": "GHSA-xxxx-yyyy-zzzz", "aliases": ["CVE-2026-1"], "summary": "An issue",
        "details": "Long details", "published": "2026-07-08T16:16:34Z",
        "modified": "2026-07-20T22:03:00Z",
        "affected": [{"package": {"ecosystem": "npm", "name": "protobufjs"},
                      "ranges": [{"type": "SEMVER",
                                  "events": [{"introduced": "7.5.0"}, {"fixed": "7.6.5"}]}]}],
    }
    base.update(over)
    return base


def lodash_inventory(project="app", branch="main", sbom_path="") -> model.BranchInventory:
    return model.BranchInventory(project=project, branch=branch, ref=branch, commit="abc",
                                 sbom_path=sbom_path, components=[
        model.Component(kind="package", ecosystem="npm", name="lodash", version="4.17.20",
                        purl="pkg:npm/lodash@4.17.20", scope="required",
                        locations=["package-lock.json"], direct=True),
        model.Component(kind="package", ecosystem="npm", name="left-pad", version="1.3.0",
                        purl="pkg:npm/left-pad@1.3.0", scope="optional",
                        locations=["package-lock.json"], direct=True),
    ])


class CvssTests(unittest.TestCase):
    def test_score31_and_label(self):
        self.assertEqual(cvss.score31(V3), 5.3)
        self.assertEqual(cvss.label(5.3), "MEDIUM")
        self.assertEqual(cvss.score31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(cvss.label(9.8), "CRITICAL")
        self.assertIsNone(cvss.score31("garbage"))
        self.assertEqual(cvss.label(None), "UNKNOWN")

    def test_v4_to_31(self):
        self.assertEqual(cvss.v4_to_31(V4), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertIsNone(cvss.v4_to_31(V3))


class SummarizeTests(unittest.TestCase):
    def test_summarize_prefers_v3_vector(self):
        s = matching.summarize(vuln(severity=[{"type": "CVSS_V4", "score": V4},
                                              {"type": "CVSS_V3", "score": V3}],
                                    database_specific={"severity": "CRITICAL"}),
                               "npm", "protobufjs")
        self.assertEqual((s["severity"], s["cvss"]), ("MEDIUM", 5.3))
        self.assertEqual(s["fixed"], ["7.6.5"])
        self.assertEqual(s["cves"], ["CVE-2026-1"])
        self.assertEqual((s["published"], s["modified"]), ("2026-07-08", "2026-07-20"))
        self.assertEqual(s["summary"], "An issue")
        self.assertFalse(s["withdrawn"])

    def test_summarize_marks_v4_approximation(self):
        s = matching.summarize(vuln(severity=[{"type": "CVSS_V4", "score": V4}]), "npm", "protobufjs")
        self.assertEqual(s["severity"], "CRITICAL(~v4)")
        self.assertIsNone(s["cvss"])

    def test_summarize_uses_database_severity_before_v4(self):
        s = matching.summarize(vuln(severity=[{"type": "CVSS_V4", "score": V4}],
                                    database_specific={"severity": "MODERATE"}), "npm", "protobufjs")
        self.assertEqual(s["severity"], "MEDIUM")

    def test_summarize_fixed_only_from_matching_package(self):
        s = matching.summarize(vuln(affected=[
            {"package": {"ecosystem": "PyPI", "name": "requests-toolbelt"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]},
            {"package": {"ecosystem": "PyPI", "name": "other"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9"}]}]},
        ]), "PyPI", "Requests_Toolbelt")
        self.assertEqual(s["fixed"], ["1.0.1"])


class FindingsTests(unittest.TestCase):
    def test_fixture_lodash_has_findings(self):
        found = matching.findings(lodash_inventory(), OSV_FIXTURE)
        self.assertEqual(len(found), 1)
        f = found[0]
        self.assertEqual((f.project, f.branch, f.component.name), ("app", "main", "lodash"))
        self.assertTrue(f.component.direct)
        ids = {v["id"] for v in f.vulns}
        self.assertIn("GHSA-35jh-r3h4-6jhm", ids)
        by_id = {v["id"]: v for v in f.vulns}
        self.assertEqual(by_id["GHSA-35jh-r3h4-6jhm"]["cves"], ["CVE-2021-23337"])
        self.assertEqual(by_id["GHSA-35jh-r3h4-6jhm"]["severity"], "HIGH")
        self.assertEqual(by_id["GHSA-35jh-r3h4-6jhm"]["fixed"], ["4.17.21"])
        self.assertEqual(model.Finding.from_dict(f.to_dict()), f)

    def test_findings_attach_by_normalised_pypi_name(self):
        inv = model.BranchInventory(project="p", branch="main", ref="main", commit="x", components=[
            model.Component(kind="package", ecosystem="PyPI", name="Requests_Toolbelt",
                            version="1.0.0", purl="pkg:pypi/requests-toolbelt@1.0.0",
                            scope="required", locations=["uv.lock"]),
        ])
        osv = {"results": [{"source": {"path": "x", "type": "sbom"}, "packages": [{
            "package": {"name": "requests-toolbelt", "version": "1.0.0", "ecosystem": "PyPI"},
            "vulnerabilities": [vuln(id="PYSEC-2026-1", aliases=[], affected=[
                {"package": {"ecosystem": "PyPI", "name": "requests-toolbelt"},
                 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]}])],
        }]}]}
        found = matching.findings(inv, osv)
        self.assertEqual(len(found), 1)
        self.assertIs(found[0].component, inv.components[0])
        self.assertEqual(found[0].vulns[0]["fixed"], ["1.0.1"])

    def test_unmatched_osv_package_still_reported(self):
        inv = model.BranchInventory(project="p", branch="main", ref="main", commit="x", components=[])
        osv = {"results": [{"packages": [{
            "package": {"name": "ghost", "version": "1.0.0", "ecosystem": "npm",
                        "purl": "pkg:npm/ghost@1.0.0"},
            "vulnerabilities": [vuln(id="GHSA-1", affected=[])]}]}]}
        found = matching.findings(inv, osv)
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0].component.name, found[0].component.scope), ("ghost", "unknown"))


class MatchAllTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.out = Path(self._tmp.name).resolve() / "security"
        (self.out / "sbom" / "app").mkdir(parents=True)
        for b in ("main", "dev"):
            (self.out / "sbom" / "app" / f"{b}.cdx.json").write_text("{}")

    def tearDown(self):
        self._tmp.cleanup()

    def test_osv_scanner_failure_is_reported_not_fatal(self):
        invs = [lodash_inventory(branch="main", sbom_path="sbom/app/main.cdx.json"),
                lodash_inventory(branch="dev", sbom_path="sbom/app/dev.cdx.json")]

        def fake(sbom: Path, out_json: Path) -> dict:
            if sbom.name == "dev.cdx.json":
                raise ToolError("osv-scanner", 127, "boom")
            return OSV_FIXTURE

        with mock.patch.object(matching, "run_osv_scanner", side_effect=fake):
            found, sources = matching.match_all(invs, self.out)
        self.assertEqual(sources["osv-scanner"]["scanned"], 1)
        self.assertEqual(sources["osv-scanner"]["failed"], [("app", "dev", "osv-scanner failed (exit 127): boom")])
        self.assertEqual([(f.branch, f.component.name) for f in found], [("main", "lodash")])

    def test_branch_without_sbom_is_skipped_not_scanned(self):
        inv = lodash_inventory(branch="main", sbom_path="")
        inv.errors.append("git: boom")
        with mock.patch.object(matching, "run_osv_scanner") as run:
            found, sources = matching.match_all([inv], self.out)
        run.assert_not_called()
        self.assertEqual((found, sources["osv-scanner"]["scanned"]), ([], 0))


@unittest.skipUnless(HAVE_OSV, "osv-scanner not installed")
class OsvScannerRunTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()

    def tearDown(self):
        self._tmp.cleanup()

    def _sbom(self, components: list[dict]) -> Path:
        path = self.tmp / "x.cdx.json"
        path.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
                                    "components": components}))
        return path

    def test_run_osv_scanner_vulnerable_package_exit_1_is_success(self):
        sbom = self._sbom([{"bom-ref": "l", "type": "library", "name": "lodash", "version": "4.17.20",
                            "purl": "pkg:npm/lodash@4.17.20"}])
        result = matching.run_osv_scanner(sbom, self.tmp / "out" / "osv.json")
        names = {p["package"]["name"] for r in result["results"] for p in r["packages"]}
        self.assertEqual(names, {"lodash"})
        self.assertTrue((self.tmp / "out" / "osv.json").exists())

    def test_run_osv_scanner_without_scannable_packages_returns_empty(self):
        sbom = self._sbom([{"bom-ref": "r", "type": "platform", "name": "nodejs", "version": "22",
                            "purl": "pkg:generic/nodejs@22"}])
        result = matching.run_osv_scanner(sbom, self.tmp / "osv.json")
        self.assertEqual(result["results"], [])

    def test_run_osv_scanner_missing_file_raises_tool_error(self):
        with self.assertRaises(ToolError):
            matching.run_osv_scanner(self.tmp / "missing.cdx.json", self.tmp / "osv.json")


if __name__ == "__main__":
    unittest.main()
