import contextlib
import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import cli, config, cyclonedx, issues, report, sbomimport, scan, status
from sbomaudit.errors import ConfigError
from sbomaudit.model import Component

from .helpers import make_repo

POM = ("<project><groupId>org.example</groupId><artifactId>app</artifactId><version>1.0</version>"
       "<modules><module>core</module></modules><dependencies>"
       "<dependency><groupId>org.lib</groupId><artifactId>lib</artifactId><version>1.0</version></dependency>"
       "<dependency><groupId>org.junit</groupId><artifactId>junit</artifactId><version>4.13</version>"
       "<scope>test</scope></dependency>"
       "</dependencies></project>")
CORE_POM = ("<project><parent><groupId>org.example</groupId><artifactId>app</artifactId></parent>"
            "<artifactId>core</artifactId></project>")
SBOM_TOOLS_14 = [{"vendor": "OWASP Foundation", "name": "CycloneDX Maven plugin", "version": "2.9.3"}]


def maven_doc(graph: bool = True, spec: str = "1.6") -> dict:
    """An aggregate Maven BOM: subject app, own module core (no scope), lib direct, lib-core transitive, junit."""
    comps = [
        {"bom-ref": "pkg:maven/org.example/core@1.0?type=jar", "name": "core", "group": "org.example",
         "purl": "pkg:maven/org.example/core@1.0?type=jar"},
        {"bom-ref": "pkg:maven/org.lib/lib@1.0?type=jar", "scope": "required", "name": "lib",
         "purl": "pkg:maven/org.lib/lib@1.0?type=jar"},
        {"bom-ref": "pkg:maven/org.lib/lib-core@2.0?type=jar", "scope": "required", "name": "lib-core",
         "purl": "pkg:maven/org.lib/lib-core@2.0?type=jar"},
        {"bom-ref": "pkg:maven/org.junit/junit@4.13?type=jar", "scope": "required", "name": "junit",
         "purl": "pkg:maven/org.junit/junit@4.13?type=jar"},
        {"bom-ref": "pkg:maven/org.opt/opt@1.0?type=jar", "scope": "optional", "name": "opt",
         "purl": "pkg:maven/org.opt/opt@1.0?type=jar"},
    ]
    doc = {"bomFormat": "CycloneDX", "specVersion": spec, "version": 1,
           "metadata": {"timestamp": "2026-11-01T10:00:00Z",
                        "tools": ({"components": [{"name": "CycloneDX Maven plugin", "version": "2.9.3"}]}
                                  if spec != "1.4" else SBOM_TOOLS_14),
                        "component": {"bom-ref": "root", "name": "app",
                                      "purl": "pkg:maven/org.example/app@1.0?type=pom"}},
           "components": comps}
    if graph:
        doc["dependencies"] = [
            {"ref": "root", "dependsOn": ["pkg:maven/org.example/core@1.0?type=jar"]},
            {"ref": "pkg:maven/org.example/core@1.0?type=jar",
             "dependsOn": ["pkg:maven/org.lib/lib@1.0?type=jar", "pkg:maven/org.junit/junit@4.13?type=jar",
                           "pkg:maven/org.opt/opt@1.0?type=jar"]},
            {"ref": "pkg:maven/org.lib/lib@1.0?type=jar", "dependsOn": ["pkg:maven/org.lib/lib-core@2.0?type=jar"]},
        ]
    return doc


def raw(doc) -> bytes:
    return json.dumps(doc).encode()


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, text=True, capture_output=True).stdout.strip()


class ParseTests(unittest.TestCase):
    def test_purl_parts(self):
        self.assertEqual(sbomimport.purl_parts("pkg:maven/org.lib/lib@1.0?type=jar"), ("maven", "lib", "1.0"))
        self.assertEqual(sbomimport.purl_parts("pkg:npm/%40scope/x@1.2.3"), ("npm", "@scope/x", "1.2.3"))
        self.assertEqual(sbomimport.purl_parts("pkg:golang/example.com/a/b@v1.0.0"),
                         ("golang", "example.com/a/b", "v1.0.0"))
        self.assertEqual(sbomimport.purl_parts("pkg:npm/x"), ("npm", "x", ""))
        for bad in ("npm/x@1", "pkg:", "pkg:npm", "pkg:NP M/x@1", "pkg:npm/x\n@1", "pkg:" + "a" * 5000):
            self.assertIsNone(sbomimport.purl_parts(bad), bad)

    def test_maven_aggregate_with_graph(self):
        doc = sbomimport.parse(raw(maven_doc()))
        self.assertEqual((doc.spec, doc.tool, doc.timestamp), ("1.6", "CycloneDX Maven plugin 2.9.3",
                                                               "2026-11-01T10:00:00Z"))
        comps, via = sbomimport.packages(doc, own={("Maven", "org.example:core")}, direct_fallback={})
        self.assertEqual(via, "graph")
        got = {c.name: (c.ecosystem, c.version, c.direct, c.scope) for c in comps}
        self.assertEqual(got, {"lib": ("Maven", "1.0", True, "required"),
                               "lib-core": ("Maven", "2.0", False, "required"),
                               "junit": ("Maven", "4.13", True, "required"),
                               "opt": ("Maven", "1.0", True, "required")})   # CycloneDX optional is not dev-only
        self.assertTrue(all(c.props == {"imported": True} for c in comps))

    def test_own_module_dropped_by_subject_graph_even_without_reader(self):
        """The subject's dependencies are own modules when the reader did not find them (no pom in the tree)."""
        doc = sbomimport.parse(raw(maven_doc()))
        comps, via = sbomimport.packages(doc, own=set(), direct_fallback={})
        # core is not in `own` and not a sub-component of the subject: it stays as a direct dependency
        self.assertEqual(via, "graph")
        self.assertEqual({c.name: c.direct for c in comps}["core"], True)

    def test_maven_without_graph_falls_back_to_manifests(self):
        doc = sbomimport.parse(raw(maven_doc(graph=False, spec="1.4")))
        self.assertEqual(doc.tool, "CycloneDX Maven plugin 2.9.3")
        comps, via = sbomimport.packages(doc, own={("Maven", "org.example:core")},
                                         direct_fallback={("Maven", "org.lib:lib"): ["pom.xml"]})
        self.assertEqual(via, "manifests")
        self.assertEqual({c.name: c.direct for c in comps},
                         {"lib": True, "lib-core": False, "junit": False, "opt": False})

    def test_ecosystem_without_reader_is_unknown_not_transitive(self):
        doc = sbomimport.parse(raw({"bomFormat": "CycloneDX", "specVersion": "1.5",
                                    "components": [{"name": "rand", "purl": "pkg:cargo/rand@0.8.5"}]}))
        comps, via = sbomimport.packages(doc, own=set(), direct_fallback={})
        self.assertEqual((via, comps[0].ecosystem, comps[0].direct), ("manifests", "crates.io", None))

    def test_npm_dev_property_excluded_and_optional(self):
        doc = sbomimport.parse(raw({
            "bomFormat": "CycloneDX", "specVersion": "1.4",
            "metadata": {"component": {"bom-ref": "demo@1.0.0", "purl": "pkg:npm/demo@1.0.0"}},
            "components": [
                {"bom-ref": "express@4.21.2", "name": "express", "purl": "pkg:npm/express@4.21.2"},
                {"bom-ref": "minimist@1.2.8", "name": "minimist", "purl": "pkg:npm/minimist@1.2.8",
                 "properties": [{"name": "cdx:npm:package:development", "value": "true"}]},
                {"bom-ref": "lodash@4.17.21", "name": "lodash", "scope": "optional",
                 "purl": "pkg:npm/lodash@4.17.21"},
                {"bom-ref": "gone@1.0.0", "name": "gone", "scope": "excluded", "purl": "pkg:npm/gone@1.0.0"},
                {"bom-ref": "@s/x@1.0.0", "name": "x", "group": "@s", "purl": "pkg:npm/%40s/x@1.0.0",
                 "components": [{"bom-ref": "nested", "name": "y", "purl": "pkg:npm/y@2.0.0"}]},
            ],
            "dependencies": [{"ref": "demo@1.0.0", "dependsOn": ["express@4.21.2", "minimist@1.2.8",
                                                                 "lodash@4.17.21"]}]}))
        comps, via = sbomimport.packages(doc, own=set(), direct_fallback={})
        got = {c.name: (c.direct, c.scope) for c in comps}
        self.assertEqual(via, "graph")
        self.assertEqual(got, {"express": (True, "required"), "minimist": (True, "optional"),
                               "lodash": (True, "required"), "gone": (False, "optional"),
                               "@s/x": (False, "required"), "y": (False, "required")})

    def test_rejects_other_formats_with_the_json_option(self):
        cases = {
            b'<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.4"/>': "XML",
            b"\xef\xbb\xbf  <bom/>": "XML",
            b"SPDXVersion: SPDX-2.3\n": "SPDX",
            raw({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}): "SPDX",
        }
        for data, word in cases.items():
            with self.assertRaises(sbomimport.Rejected) as ctx:
                sbomimport.parse(data)
            self.assertIn(word, str(ctx.exception))
            self.assertIn("-DoutputFormat=json", str(ctx.exception))

    def test_rejects_malformed_documents(self):
        for data in (b"{", b"[]", b"\xff\xfe", raw({"bomFormat": "SPDX"}),
                     raw({"bomFormat": "CycloneDX", "specVersion": "1.3"}),
                     raw({"bomFormat": "CycloneDX", "specVersion": 1.6}),
                     b"[" * 100_000 + b"]" * 100_000):
            with self.assertRaises(sbomimport.Rejected):
                sbomimport.parse(data)

    def test_oversize_is_rejected(self):
        with mock.patch.object(sbomimport, "MAX_BYTES", 100):
            with self.assertRaises(sbomimport.Rejected) as ctx:
                sbomimport.parse(raw(maven_doc()))
        self.assertIn("byte limit", str(ctx.exception))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "big.json"
            path.write_bytes(b" " * 200)
            with mock.patch.object(sbomimport, "MAX_BYTES", 100), self.assertRaises(sbomimport.Rejected):
                sbomimport.read_capped(path)

    def test_wrong_types_are_counted_not_fatal(self):
        doc = sbomimport.parse(raw({
            "bomFormat": "CycloneDX", "specVersion": "1.7",
            "metadata": {"tools": "nope", "component": ["x"], "timestamp": 5},
            "components": [1, "x", None, {"name": "no-purl"}, {"purl": ""}, {"purl": 7},
                           {"purl": "not a purl"}, {"purl": "pkg:npm/v@1.0.0", "version": 3},
                           {"purl": "pkg:npm/ok@1.0.0", "properties": "x", "components": "x"},
                           {"purl": "pkg:weird-type/thing@1"}],
            "dependencies": [5, {"ref": 3}, {"ref": "a", "dependsOn": "b"}, {"ref": "c", "dependsOn": [1, "d"]}]}))
        self.assertEqual((doc.skipped_no_purl, doc.invalid), (3, 5))
        self.assertEqual([(e.component.ecosystem, e.component.name) for e in doc.entries],
                         [("npm", "ok"), ("weird-type", "thing")])   # an unknown purl type is kept
        self.assertEqual(doc.graph, {"a": [], "c": ["d"]})
        self.assertEqual((doc.tool, doc.timestamp), ("", ""))


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.doc = sbomimport.parse(raw(maven_doc()))
        self.raw = raw(maven_doc())
        self.digest = hashlib.sha256(self.raw).hexdigest()

    def test_current_stale_and_not_recorded(self):
        prov = {"sha256": self.digest, "commit": "a" * 40, "imported_at": "2026-11-02T00:00:00Z"}
        current = sbomimport.source(self.doc, self.raw, "imports/p/main.cdx.json", True, prov, "a" * 40)
        self.assertEqual((current["stale"], sbomimport.staleness(current)), (False, ""))
        stale = sbomimport.source(self.doc, self.raw, "imports/p/main.cdx.json", True, prov, "b" * 40)
        self.assertTrue(stale["stale"])
        self.assertEqual(sbomimport.staleness(stale), "built from commit aaaaaaa, not the scanned one")
        changed = sbomimport.source(self.doc, self.raw, "imports/p/main.cdx.json", True,
                                    dict(prov, sha256="0" * 64), "a" * 40)   # file replaced after import
        self.assertIsNone(changed["commit"])
        self.assertEqual(sbomimport.staleness(changed), "commit not recorded")
        committed = sbomimport.source(self.doc, self.raw, "target/bom.json", False, prov, "a" * 40)
        self.assertEqual((committed["in"], committed["stale"]), ("repository", None))
        self.assertIn("committed in the repository", sbomimport.describe(dict(committed, replaced=["Maven"])))
        # git history could not name the file's last commit: the wording stays "commit not recorded"
        self.assertEqual(sbomimport.staleness(committed), "commit not recorded")
        self.assertIsNone(sbomimport.source(self.doc, self.raw, "target/bom.json", False, {}, "a" * 40,
                                            last_change="not a sha")["commit"])
        # an evidence file never takes a git-history commit
        self.assertIsNone(sbomimport.source(self.doc, self.raw, "imports/p/main.cdx.json", True, {}, "a" * 40,
                                            last_change="a" * 40)["commit"])

    def test_last_change_is_none_when_git_fails(self):
        from sbomaudit import gitio
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(gitio.last_change(Path(tmp), "a" * 40, "target/bom.json"))   # not a repository
            self.assertIsNone(gitio.last_change(Path(tmp), "--output=/tmp/x", "bom.json"))

    def test_import_hint_does_not_point_at_a_manifest_line(self):
        self.assertIn("refresh the lockfile", issues._upgrade_hint(False, [{"direct": False}]))
        hint = issues._upgrade_hint(False, [{"direct": False, "imported": True}])
        self.assertIn("imported build SBOM", hint)
        self.assertIn("<dependencyManagement>", hint)
        self.assertEqual(issues._upgrade_hint(True, [{"imported": True}]),
                         "bump the package in the manifest and refresh the lockfile")


class ScanImportTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()
        self.root = self.tmp / "PROJECTS"
        self.root.mkdir()
        self.out = self.root / "security"
        files = {"pom.xml": POM, "core/pom.xml": CORE_POM,
                 "web/package.json": '{"name": "web", "dependencies": {"left-pad": "1.3.0"}}'}
        self.repo = make_repo(self.root, "java", files, branches=["main", "dev"])
        git(self.repo, "tag", "v1.0", "main")
        self.syft_bom = {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1, "components": [
            {"bom-ref": "s1", "type": "library", "name": "lib", "version": "", "purl": "pkg:maven/org.lib/lib",
             "properties": [{"name": "syft:location:0:path", "value": "/pom.xml"}]},
            {"bom-ref": "s2", "type": "library", "name": "left-pad", "version": "1.3.0",
             "purl": "pkg:npm/left-pad@1.3.0"}]}
        self.syft_comps = [
            Component(kind="package", ecosystem="Maven", name="lib", version="", purl="pkg:maven/org.lib/lib",
                      scope="required", locations=["pom.xml"], props={"unresolved": True}),
            Component(kind="package", ecosystem="npm", name="left-pad", version="1.3.0",
                      purl="pkg:npm/left-pad@1.3.0", scope="required", locations=["web/package.json"])]

    def tearDown(self):
        self._tmp.cleanup()

    def run_scan(self):
        cfg = config.load(self.out)
        bom = json.loads(json.dumps(self.syft_bom))
        comps = [Component(**{**c.__dict__, "locations": list(c.locations), "props": dict(c.props)})
                 for c in self.syft_comps]
        with mock.patch.object(scan.syft, "inventory", return_value=(bom, comps)):
            return scan.scan(cfg, only=["java"], fetch=False)

    def cli(self, *args: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--out", str(self.out), "import", "--project", "java", *args])
        return code, out.getvalue(), err.getvalue()

    def write_doc(self, doc: dict) -> Path:
        path = self.tmp / "bom.json"
        path.write_bytes(raw(doc))
        return path

    def test_import_replaces_maven_keeps_npm_and_records_source(self):
        code, out, err = self.cli("--branch", "main", str(self.write_doc(maven_doc())))
        self.assertEqual(code, 0, err)
        prov = json.loads((self.out / "imports" / "java" / "main.import.json").read_text())
        self.assertEqual(prov["commit"], git(self.repo, "rev-parse", "main"))
        result = self.run_scan()
        inv = next(i for i in result.inventories if i.branch == "main")
        pkgs = {(c.ecosystem, c.name): c for c in inv.components if c.kind == "package"}
        self.assertEqual(sorted(pkgs), [("Maven", "junit"), ("Maven", "lib"), ("Maven", "lib-core"),
                                        ("Maven", "opt"), ("npm", "left-pad")])
        self.assertEqual(pkgs[("Maven", "lib")].version, "1.0")
        self.assertEqual(pkgs[("Maven", "lib")].locations, ["pom.xml"])           # the scan's manifest
        self.assertEqual(pkgs[("Maven", "lib-core")].locations, ["imports/java/main.cdx.json"])
        self.assertEqual(pkgs[("Maven", "junit")].scope, "optional")             # <scope>test</scope> in pom
        self.assertEqual(pkgs[("Maven", "lib-core")].direct, False)
        self.assertFalse(pkgs[("npm", "left-pad")].props.get("imported"))
        src = inv.package_source
        self.assertEqual((src["replaced"], src["direct_from"], src["stale"], src["in"]),
                         (["Maven"], "graph", False, "evidence"))
        self.assertEqual(inv.errors, [])
        dev = next(i for i in result.inventories if i.branch == "dev")
        self.assertIsNone(dev.package_source)
        # the SBOM document carries the components and the source
        sbom = json.loads(scan.sbom_path(self.out, "java", "main").read_text())
        props = {p["name"]: p["value"] for p in sbom["metadata"]["properties"]}
        self.assertEqual(props["sbom-audit:package_source:replaced"], "Maven")
        self.assertEqual(props["sbom-audit:package_source:tool"], "CycloneDX Maven plugin 2.9.3")
        purls = {c.get("purl") for c in sbom["components"]}
        self.assertIn("pkg:maven/org.lib/lib-core@2.0?type=jar", purls)
        self.assertNotIn("pkg:maven/org.lib/lib", purls)
        self.assertNotIn("pkg:maven/org.example/core@1.0?type=jar", purls)
        read = {c.name: c for c in cyclonedx.read_components(scan.sbom_path(self.out, "java", "main"))}
        self.assertIs(read["lib"].props.get("imported"), True)
        # inventory round trip and reports
        back = scan.read_inventory(self.out)[0]
        self.assertEqual(next(i for i in back if i.branch == "main").package_source["replaced"], ["Maven"])
        notes = report._import_notes(result.inventories)
        self.assertEqual(len(notes), 1)
        self.assertIn("imported build SBOM `imports/java/main.cdx.json` for Maven; 4 packages from the import", notes[0])

    def test_import_supplements_the_scan_and_never_drops_a_package_silently(self):
        # the scan found two Maven packages the build SBOM does not name: one resolved, one not
        self.syft_bom["components"] += [
            {"bom-ref": "s3", "type": "library", "name": "testcontainers", "version": "1.19.0",
             "purl": "pkg:maven/org.testcontainers/testcontainers@1.19.0",
             "properties": [{"name": "syft:location:0:path", "value": "/core/pom.xml"}]},
            {"bom-ref": "s4", "type": "library", "name": "mystery", "version": "",
             "purl": "pkg:maven/org.mystery/mystery",
             "properties": [{"name": "syft:location:0:path", "value": "/core/pom.xml"}]}]
        self.syft_comps += [
            Component(kind="package", ecosystem="Maven", name="testcontainers", version="1.19.0",
                      purl="pkg:maven/org.testcontainers/testcontainers@1.19.0", scope="required",
                      locations=["core/pom.xml"]),
            Component(kind="package", ecosystem="Maven", name="mystery", version="",
                      purl="pkg:maven/org.mystery/mystery", scope="required", locations=["core/pom.xml"],
                      props={"unresolved": True})]
        code, _, err = self.cli("--branch", "main", str(self.write_doc(maven_doc())))
        self.assertEqual(code, 0, err)
        result = self.run_scan()
        inv = next(i for i in result.inventories if i.branch == "main")
        pkgs = {(c.ecosystem, c.name): c for c in inv.components if c.kind == "package"}
        self.assertEqual(sorted(pkgs), [("Maven", "junit"), ("Maven", "lib"), ("Maven", "lib-core"),
                                        ("Maven", "mystery"), ("Maven", "opt"), ("Maven", "testcontainers"),
                                        ("npm", "left-pad")])
        kept = pkgs[("Maven", "testcontainers")]
        self.assertEqual((kept.version, kept.locations), ("1.19.0", ["core/pom.xml"]))
        self.assertIs(kept.props.get("not_in_build_sbom"), True)
        self.assertFalse(kept.props.get("imported"))
        self.assertIs(pkgs[("Maven", "mystery")].props.get("not_in_build_sbom"), True)
        self.assertFalse(pkgs[("Maven", "lib")].props.get("not_in_build_sbom"))   # named by both: import wins
        self.assertEqual(pkgs[("Maven", "lib")].version, "1.0")
        self.assertFalse(pkgs[("npm", "left-pad")].props.get("not_in_build_sbom"))  # ecosystem not imported
        # the unresolved one is still listed as not checked
        from sbomaudit import coverage
        rows = coverage.unresolved_versions(result.inventories)
        main = next(r for r in rows if r["branch"] == "main")
        self.assertEqual([p["name"] for p in main["packages"] if p["ecosystem"] == "Maven"], ["org.mystery:mystery"])
        src = inv.package_source
        self.assertEqual((src["packages"], src["kept_from_scan"], src["kept_unresolved"], src["replaced_entries"]),
                         (4, 2, 1, 1))
        line = sbomimport.describe(src)
        self.assertIn("4 packages from the import", line)
        self.assertIn("2 kept from the repository scan (not in the build SBOM, 1 with version not resolved)", line)
        self.assertIn("1 repository entry replaced", line)
        # the SBOM document keeps the scan's entries and marks them
        sbom = json.loads(scan.sbom_path(self.out, "java", "main").read_text())
        props = {p["name"]: p["value"] for p in sbom["metadata"]["properties"]}
        self.assertEqual((props["sbom-audit:package_source:packages"], props["sbom-audit:package_source:kept_from_scan"],
                          props["sbom-audit:package_source:kept_unresolved"],
                          props["sbom-audit:package_source:replaced_entries"]), ("4", "2", "1", "1"))
        read = {c.name: c for c in cyclonedx.read_components(scan.sbom_path(self.out, "java", "main"))}
        self.assertIs(read["testcontainers"].props.get("not_in_build_sbom"), True)
        self.assertIs(read["lib"].props.get("imported"), True)
        self.assertNotIn("pkg:maven/org.lib/lib", {c.get("purl") for c in sbom["components"]})
        # INVENTORY.md names the kept packages
        cfg = config.load(self.out)
        text = report.write_inventory_md(cfg, result.inventories, self.out).read_text()
        self.assertIn("kept from the repository scan (not in the build SBOM", text)
        self.assertIn("org.testcontainers:testcontainers 1.19.0", text)

    def test_stale_import_is_used_and_reported(self):
        first = git(self.repo, "rev-parse", "main")
        code, _, err = self.cli("--branch", "main", "--commit", first, str(self.write_doc(maven_doc())))
        self.assertEqual(code, 0, err)
        (self.repo / "NEW").write_text("x\n")
        git(self.repo, "add", "NEW")
        git(self.repo, "commit", "-q", "-m", "later")
        result = self.run_scan()
        inv = next(i for i in result.inventories if i.branch == "main")
        self.assertTrue(inv.package_source["stale"])
        self.assertIn(first[:7], sbomimport.describe(inv.package_source))
        rows = report.imported_sboms(result.inventories)
        self.assertEqual(len(rows), 1)
        self.assertEqual(report._imports_line(rows)[0].count("not the scanned one"), 1)

    def test_release_tag_label(self):
        code, out, err = self.cli("--tag", "v1.0", str(self.write_doc(maven_doc())))
        self.assertEqual(code, 0, err)
        path = self.out / "imports" / "java" / "tags__v1.0.cdx.json"
        self.assertTrue(path.is_file())
        prov = json.loads(sbomimport.provenance_path(path).read_text())
        self.assertEqual(prov["commit"], git(self.repo, "rev-parse", "v1.0^{commit}"))
        self.assertEqual(sbomimport.import_path(self.out, "java", "tags/v1.0"), path)

    def test_cli_rejections(self):
        xml = self.tmp / "bom.xml"
        xml.write_text('<?xml version="1.0"?><bom/>')
        code, _, err = self.cli("--branch", "main", str(xml))
        self.assertEqual(code, 2)
        self.assertIn("-DoutputFormat=json", err)
        self.assertEqual(self.cli("--branch", "nope", str(xml))[0], 2)
        self.assertEqual(self.cli("--tag", "v9", str(xml))[0], 2)
        self.assertEqual(self.cli("--branch", "main", "--commit=--help", str(xml))[0], 2)
        empty = self.write_doc({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"name": "x"}]})
        code, _, err = self.cli("--branch", "main", str(empty))
        self.assertEqual(code, 2)
        self.assertIn("no component with a usable purl", err)
        self.assertFalse((self.out / "imports").exists())

    def test_broken_import_is_an_error_and_the_repo_scan_stands(self):
        path = sbomimport.import_path(self.out, "java", "main")
        path.parent.mkdir(parents=True)
        path.write_text("<bom/>")
        inv = next(i for i in self.run_scan().inventories if i.branch == "main")
        self.assertIsNone(inv.package_source)
        self.assertEqual(len(inv.errors), 1)
        self.assertTrue(inv.errors[0].startswith("import: imports/java/main.cdx.json: XML"), inv.errors)
        lib = next(c for c in inv.components if c.name == "lib")
        self.assertFalse(lib.props.get("imported"))                   # the repository scan's package

    def test_config_path_is_read_from_the_tree_and_evidence_file_wins(self):
        (self.repo / "target").mkdir()
        (self.repo / "target" / "bom.json").write_bytes(raw(maven_doc()))
        git(self.repo, "add", "-f", "target/bom.json")
        git(self.repo, "commit", "-q", "-m", "bom")
        config_file = self.out / config.CONFIG_NAME
        self.out.mkdir(exist_ok=True)
        config_file.write_text('[projects."java"]\nsbom = "target/bom.json"\n')
        (self.repo / "target" / "bom.json").write_text("changed in the working tree, never read")
        inv = next(i for i in self.run_scan().inventories if i.branch == "main")
        self.assertEqual(inv.errors, [])
        self.assertEqual((inv.package_source["file"], inv.package_source["in"]), ("target/bom.json", "repository"))
        bom_commit = git(self.repo, "log", "-1", "--format=%H", "main", "--", "target/bom.json")
        self.assertEqual((inv.package_source["commit"], inv.package_source["commit_from"]),
                         (bom_commit, "git history"))
        self.assertEqual(sbomimport.staleness(inv.package_source), "")       # last change is the scanned commit
        self.assertIn(f"committed in {bom_commit[:7]} (the scanned commit)", sbomimport.describe(inv.package_source))
        (self.repo / "LATER").write_text("x\n")
        git(self.repo, "add", "LATER")
        git(self.repo, "commit", "-q", "-m", "later")
        inv = next(i for i in self.run_scan().inventories if i.branch == "main")
        self.assertEqual(inv.package_source["commit"], bom_commit)
        self.assertTrue(inv.package_source["stale"])
        self.assertEqual(sbomimport.staleness(inv.package_source),
                         f"file last changed in commit {bom_commit[:7]}, not the scanned one")
        dev =next(i for i in self.run_scan().inventories if i.branch == "dev")
        self.assertIn("is not a file in the tree", dev.errors[0])      # dev was cut before the commit
        npm = {"bomFormat": "CycloneDX", "specVersion": "1.5",
               "components": [{"name": "left-pad", "purl": "pkg:npm/left-pad@1.3.0"}]}
        self.assertEqual(self.cli("--branch", "main", str(self.write_doc(npm)))[0], 0)
        inv = next(i for i in self.run_scan().inventories if i.branch == "main")
        self.assertEqual((inv.package_source["in"], inv.package_source["replaced"]), ("evidence", ["npm"]))
        lib = next(c for c in inv.components if c.name == "lib")
        self.assertFalse(lib.props.get("imported"))                   # Maven stays as the repository scan found it


class ConfigAndReportTests(unittest.TestCase):
    def test_tree_path(self):
        self.assertEqual(config._tree_path("target/bom.json", "k"), "target/bom.json")
        self.assertIsNone(config._tree_path(None, "k"))
        for bad in ("/etc/passwd", "../x.json", "a/../../x", "a\\b", "a\nb", 5):
            with self.assertRaises(ConfigError):
                config._tree_path(bad, "k")

    def test_status_and_management_name_unrecorded_imports(self):
        rep = {"stats": {"imported_sboms": 2, "imported_sboms_not_current": 1}, "vulnerabilities": []}
        counts = status._counts(rep, {"kev": set(), "critical_high_production": set(), "eol": set()}, None)
        self.assertEqual(counts["imported_sboms"], {"total": 2, "not_current": 1})
        rows = [{"project": "p", "branch": "main", "kind": "import", "commit": None},
                {"project": "p", "branch": "dev", "kind": "import", "commit": "a" * 40, "stale": False}]
        self.assertEqual([sbomimport.staleness(r) for r in rows], ["commit not recorded", ""])
        line = report._imports_line(rows)[0]
        self.assertIn("p@main (commit not recorded)", line)
        self.assertNotIn("p@dev (", line)


if __name__ == "__main__":
    unittest.main()
