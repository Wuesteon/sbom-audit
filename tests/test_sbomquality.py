import contextlib
import copy
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import cli, config, cyclonedx, integration, report, sbomquality, scan
from sbomaudit.errors import ToolError
from sbomaudit.model import BranchInventory, Component

from .helpers import make_repo

FIXTURES = Path(__file__).resolve().parent / "fixtures"
HAVE_SYFT = shutil.which("syft") is not None
SERIAL = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"


def good() -> dict:
    """A small, structurally sound CycloneDX 1.6 document (synthetic)."""
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": SERIAL, "version": 1,
        "metadata": {
            "timestamp": "2026-11-18T10:00:00Z",
            "tools": {"components": [{"type": "application", "name": "builder", "version": "1"}]},
            "component": {"bom-ref": "app", "type": "application", "name": "app", "version": "1.0.0"},
        },
        "components": [
            {"bom-ref": "pkg:npm/a@1.0.0", "type": "library", "name": "a", "version": "1.0.0",
             "purl": "pkg:npm/a@1.0.0", "licenses": [{"license": {"id": "MIT"}}],
             "hashes": [{"alg": "SHA-512", "content": "ab" * 64}], "supplier": {"name": "A Org"}},
            {"bom-ref": "pkg:npm/b@2.0.0", "type": "library", "name": "b", "version": "2.0.0",
             "purl": "pkg:npm/b@2.0.0", "licenses": [{"expression": "MIT OR Apache-2.0"}],
             "components": [{"bom-ref": "inner", "type": "library", "name": "inner", "cpe": "cpe:2.3:a:x:inner"}]},
            {"bom-ref": "file-1", "type": "file", "name": "/package-lock.json"},
        ],
        "dependencies": [{"ref": "app", "dependsOn": ["pkg:npm/a@1.0.0"]},
                         {"ref": "pkg:npm/a@1.0.0", "dependsOn": ["pkg:npm/b@2.0.0"]},
                         {"ref": "pkg:npm/b@2.0.0", "dependsOn": []}],
    }


def codes(result: dict, level: str | None = None) -> set[str]:
    return {f["code"] for f in result["findings"] if level is None or f["level"] == level}


class CheckTests(unittest.TestCase):
    def test_sound_document_and_coverage(self):
        r = sbomquality.check(good())
        self.assertTrue(r["valid"], r["findings"])
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["spec"], "1.6")
        cov = r["coverage"]
        self.assertEqual((cov["components"], cov["files"]), (3, 1))       # a, b, inner; the file apart
        self.assertEqual((cov["version"], cov["purl"], cov["identifier"]), (2, 2, 3))   # inner: cpe only
        self.assertEqual((cov["licence"], cov["hash"], cov["sha512"], cov["supplier"]), (2, 1, 1, 1))
        self.assertEqual(cov["in_graph"], 2)
        self.assertTrue(all(cov[k] for k in ("graph", "timestamp", "tools", "author", "subject")))
        self.assertFalse(cov["compositions"])

    def test_header_errors_and_warnings(self):
        doc = good()
        doc.update(bomFormat="SPDX", specVersion="1.2", serialNumber="1234", version=0)
        doc["metadata"]["timestamp"] = "yesterday"
        r = sbomquality.check(doc)
        self.assertFalse(r["valid"])
        self.assertTrue({"bom-format", "spec-version", "serial-number-format", "version-invalid",
                         "timestamp-format"} <= codes(r, "error"))
        doc = good()
        for key in ("serialNumber", "version"):
            del doc[key]
        doc["metadata"] = {}
        r = sbomquality.check(doc)
        self.assertEqual(codes(r, "error"), {"dependency-ref-dangling"})  # the graph still names the subject
        doc["dependencies"] = doc["dependencies"][1:]
        r = sbomquality.check(doc)
        self.assertTrue(r["valid"])                                       # all optional in CycloneDX
        self.assertEqual(codes(r, "warning"), {"serial-number-missing", "version-missing", "timestamp-missing",
                                               "tools-missing", "subject-missing"})
        self.assertFalse(r["coverage"]["author"])

    def test_legacy_tool_list_and_boolean_version(self):
        doc = good()
        doc["metadata"]["tools"] = [{"vendor": "x", "name": "old-tool", "version": "1"}]
        self.assertTrue(sbomquality.check(doc)["coverage"]["tools"])
        doc["version"] = True
        self.assertIn("version-invalid", codes(sbomquality.check(doc)))

    def test_component_and_subject_errors(self):
        doc = good()
        doc["metadata"]["component"] = {"bom-ref": "app", "type": "service"}
        doc["components"] += [{"bom-ref": "x", "name": "no-type"}, {"bom-ref": "y", "type": "gizmo", "name": "y"},
                              {"bom-ref": "z", "type": "library"}, "text", {"type": "library", "name": "v",
                                                                            "version": 3}]
        r = sbomquality.check(doc)
        self.assertTrue({"subject-type-invalid", "subject-name-missing", "component-type-missing",
                         "component-type-invalid", "component-name-missing", "component-not-object",
                         "version-type"} <= codes(r, "error"))
        self.assertFalse(r["coverage"]["subject"])

    def test_duplicate_and_dangling_refs(self):
        doc = good()
        doc["components"].append({"bom-ref": "pkg:npm/a@1.0.0", "type": "library", "name": "a2"})
        doc["dependencies"] += [{"ref": "ghost", "dependsOn": ["phantom", 7]}, {"ref": 5}, "row",
                                {"ref": "app", "dependsOn": "pkg:npm/a@1.0.0"}]
        r = sbomquality.check(doc)
        self.assertTrue({"bom-ref-duplicate", "dependency-ref-dangling", "depends-on-dangling", "depends-on-type",
                         "dependency-ref-type", "dependency-not-object"} <= codes(r, "error"))
        self.assertIn("dependency-ref-repeated", codes(r, "warning"))
        dangling = next(f for f in r["findings"] if f["code"] == "dependency-ref-dangling")
        self.assertEqual(dangling["examples"], ["ghost"])

    def test_refs_of_subject_children_and_services_resolve(self):
        doc = good()
        doc["metadata"]["component"]["components"] = [{"bom-ref": "module", "type": "library", "name": "m"}]
        doc["services"] = [{"bom-ref": "svc", "name": "api", "services": [{"bom-ref": "svc2", "name": "inner"}]}]
        doc["dependencies"].append({"ref": "module", "dependsOn": ["svc", "svc2", "inner"]})
        self.assertTrue(sbomquality.check(doc)["valid"])

    def test_purl_syntax(self):
        for purl in ("npm/a@1", "pkg:", "pkg:NO TYPE/a", "", 42, "pkg:npm/" + "a" * 5000, "pkg:npm/a\n@1"):
            doc = good()
            doc["components"][0]["purl"] = purl
            with self.subTest(purl=purl):
                r = sbomquality.check(doc)
                self.assertIn("purl-syntax", codes(r, "error"))
                self.assertEqual(r["coverage"]["purl"], 1)

    def test_coverage_never_counts_empty_or_malformed_values(self):
        doc = good()
        a = doc["components"][0]
        a.update(version="  ", licenses=[{"license": {}}, "MIT"], hashes=[{"alg": "SHA-512"}],
                 supplier={"name": ""}, purl="pkg:npm/a")
        r = sbomquality.check(doc)
        cov = r["coverage"]
        self.assertEqual((cov["version"], cov["licence"], cov["hash"], cov["supplier"]), (1, 1, 0, 0))

    def test_hash_in_external_reference_and_manufacturer_count(self):
        doc = good()
        b = doc["components"][1]
        b["externalReferences"] = [{"type": "distribution", "url": "https://x",
                                    "hashes": [{"alg": "SHA-256", "content": "00" * 32}]}]
        b["manufacturer"] = {"url": ["https://b.example"]}
        cov = sbomquality.check(doc)["coverage"]
        self.assertEqual((cov["hash"], cov["sha512"], cov["supplier"]), (2, 1, 2))


class HostileInputTests(unittest.TestCase):
    def test_non_objects(self):
        for value in (None, [], "x", 3, [{"bomFormat": "CycloneDX"}]):
            with self.subTest(value=value):
                r = sbomquality.check(value)
                self.assertFalse(r["valid"])
                self.assertEqual(codes(r), {"not-object"})

    def test_wrong_types_everywhere_never_raise(self):
        weird = [None, 1, 1.5, True, "s", [], {}, [1, "x", None], {"a": []}]
        keys = ("bomFormat", "specVersion", "serialNumber", "version", "metadata", "components", "dependencies",
                "services", "compositions")
        for key in keys:
            for value in weird:
                doc = good()
                doc[key] = value
                with self.subTest(key=key, value=value):
                    sbomquality.check(doc)
        for key in ("timestamp", "tools", "component", "authors", "manufacturer", "supplier"):
            for value in weird:
                doc = good()
                doc["metadata"][key] = value
                with self.subTest(meta=key, value=value):
                    sbomquality.check(doc)
        for key in ("bom-ref", "type", "name", "version", "purl", "licenses", "hashes", "supplier",
                    "manufacturer", "externalReferences", "components", "swid", "omniborId", "cpe"):
            for value in weird:
                doc = good()
                doc["components"][0][key] = value
                with self.subTest(component=key, value=value):
                    sbomquality.check(doc)

    def test_deep_nesting_is_capped(self):
        inner: dict = {"type": "library", "name": "leaf"}
        for i in range(sbomquality.MAX_DEPTH + 10):
            inner = {"type": "library", "name": f"n{i}", "components": [inner]}
        doc = good()
        doc["components"] = [inner]
        r = sbomquality.check(doc)
        self.assertIn("nesting-too-deep", codes(r, "warning"))
        self.assertEqual(r["coverage"]["components"], sbomquality.MAX_DEPTH)

    def test_deep_json_and_bad_bytes(self):
        deep = sbomquality.check_bytes(b"[" * 100_000 + b"]" * 100_000)     # RecursionError or a list
        self.assertFalse(deep["valid"])
        self.assertLessEqual(codes(deep), {"not-json", "not-object"})
        doc = good()
        doc["components"][0]["properties"] = "PLACEHOLDER"
        raw = json.dumps(doc).replace('"PLACEHOLDER"', '{"a": ' * 50_000 + "1" + "}" * 50_000).encode()
        self.assertIn(codes(sbomquality.check_bytes(raw)), ({"not-json"}, set()))
        self.assertEqual(codes(sbomquality.check_bytes(b"\xff\xfe{")), {"not-json"})
        self.assertEqual(codes(sbomquality.check_bytes(b'{"version": ' + b"9" * 10_000 + b"}")), {"not-json"})
        r = sbomquality.check_bytes(b"\xef\xbb\xbf" + json.dumps(good()).encode())
        self.assertTrue(r["valid"])

    def test_size_and_component_caps(self):
        with mock.patch.object(sbomquality, "MAX_BYTES", 100):
            r = sbomquality.check_bytes(b" " * 101)
        self.assertEqual((codes(r), r["readable"]), ({"too-large"}, False))
        doc = good()
        doc["components"] = [{"type": "library", "name": f"c{i}"} for i in range(50)]
        with mock.patch.object(sbomquality, "MAX_COMPONENTS", 10):
            r = sbomquality.check(doc)
        self.assertIn("too-many-components", codes(r, "error"))
        self.assertEqual(r["coverage"]["components"], 10)

    def test_findings_stay_bounded(self):
        doc = good()
        doc["components"] = [{"bom-ref": "same", "type": "library", "name": "x"} for _ in range(5000)]
        r = sbomquality.check(doc)
        dup = next(f for f in r["findings"] if f["code"] == "bom-ref-duplicate")
        self.assertEqual((dup["count"], len(dup["examples"])), (4999, sbomquality.EXAMPLES))
        text = "\n".join(sbomquality.render("x", r))
        self.assertLess(len(text), 4000)

    def test_control_characters_are_not_echoed(self):
        doc = good()
        doc["components"][0]["purl"] = "\x1b[31mred\x07"
        text = "\n".join(sbomquality.render("x", sbomquality.check(doc)))
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x07", text)


class SummaryTests(unittest.TestCase):
    def test_summary_text_and_cra_note(self):
        s = sbomquality.summary(sbomquality.check(good()))
        self.assertEqual((s["valid"], s["errors"], s["components"], s["licence"]), (True, 0, 3, 2))
        text = sbomquality.coverage_text(s)
        self.assertIn("3 component entries (+1 files)", text)
        self.assertIn("licence 67%", text)
        self.assertIn("dependency graph yes", text)
        doc = good()
        doc["dependencies"].append({"ref": "ghost"})
        s = sbomquality.summary(sbomquality.check(doc))
        note = sbomquality.cra_note(s)
        self.assertTrue(note.startswith("1 structural errors (dependency-ref-dangling)"), note)
        self.assertIn("sbom check", note)

    def test_share_rounding(self):
        self.assertEqual([sbomquality.share(p, w) for p, w in ((0, 0), (0, 5), (1, 1000), (999, 1000), (5, 5))],
                         ["-", "0%", "<1%", ">99%", "100%"])

    def test_inventory_section(self):
        good_q = sbomquality.summary(sbomquality.check(good()))
        bad = good()
        bad["bomFormat"] = "x"
        bad_q = sbomquality.summary(sbomquality.check(bad))
        nograph = good()
        del nograph["dependencies"]
        invs = [BranchInventory("shop", "main", "main", "a" * 40, sbom_quality=good_q),
                BranchInventory("sh|op", "dev", "dev", "b" * 40, sbom_quality=bad_q),
                BranchInventory("api", "main", "main", "c" * 40,
                                sbom_quality=sbomquality.summary(sbomquality.check(nograph))),
                BranchInventory("gone", "main", "main", "", errors=["git: x"])]
        L = sbomquality.inventory_section(invs)
        text = "\n".join(L)
        self.assertIn("## SBOM quality", text)
        self.assertIn("| shop | main | yes | 3 | 67% | 67% | 67% | 33% | 33% | 67% |", text)
        self.assertIn("| sh\\|op | dev | no (1 errors) |", text)
        self.assertIn("no graph |", text)
        self.assertNotIn("gone", text)
        self.assertNotIn("complies", text.lower())
        self.assertEqual(sbomquality.inventory_section(invs[3:]), [])

    def test_inventory_round_trip_and_old_entries(self):
        q = sbomquality.summary(sbomquality.check(good()))
        inv = BranchInventory("shop", "main", "main", "a" * 40, sbom_quality=q)
        self.assertEqual(BranchInventory.from_dict(json.loads(json.dumps(inv.to_dict()))).sbom_quality, q)
        old = BranchInventory("shop", "main", "main", "a" * 40).to_dict()
        self.assertNotIn("sbom_quality", old)
        self.assertIsNone(BranchInventory.from_dict(old).sbom_quality)


class CommandTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()
        self.out = self.tmp / "security"
        (self.out / "sbom" / "shop").mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def run_cli(self, *argv, read_only: bool = True) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        env = {"SBOM_AUDIT_READ_ONLY": "1" if read_only else ""}
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), mock.patch.dict(os.environ, env):
            code = cli.main(["--out", str(self.out), *argv])
        return code, out.getvalue(), err.getvalue()

    def test_project_and_branch_cannot_leave_the_sbom_folder(self):
        outside = self.tmp / "elsewhere"
        outside.mkdir()
        (outside / "main.cdx.json").write_text("{}", encoding="utf-8")
        for argv in (("--project", "../../elsewhere"), ("--project", str(outside)), ("--project", ".."),
                     ("--project", "shop", "--branch", "../../../elsewhere/main")):
            code, out, err = self.run_cli("sbom", "check", *argv)
            self.assertEqual(code, 2, argv)
            self.assertEqual(out, "", argv)
            self.assertIn("takes a", err, argv)

    def write(self, rel: str, doc) -> Path:
        path = self.out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(doc if isinstance(doc, str) else json.dumps(doc))
        return path

    def test_registered_read_only_and_autonomous(self):
        self.assertIn("sbom", cli.COMMANDS)
        self.assertNotIn("sbom", cli.WRITING_COMMANDS)
        self.assertIn("sbom check", integration.AUTONOMOUS_SUBCOMMANDS)
        self.assertFalse(cli._writes(cli.build_parser().parse_args(["sbom", "check"])))

    def test_exit_codes_and_writes_nothing(self):
        self.write("sbom/shop/main.cdx.json", good())
        before = sorted(p.relative_to(self.out) for p in self.out.rglob("*"))
        code, out, _ = self.run_cli("sbom", "check")
        self.assertEqual(code, 0, out)
        self.assertIn("sbom/shop/main.cdx.json: valid (CycloneDX 1.6)", out)
        self.assertIn("licence", out)
        bad = good()
        bad["dependencies"].append({"ref": "ghost"})
        self.write("sbom/shop/tags__v1.cdx.json", bad)
        before = sorted(p.relative_to(self.out) for p in self.out.rglob("*"))
        code, out, _ = self.run_cli("sbom", "check")
        self.assertEqual(code, 1, out)
        self.assertIn("dependency-ref-dangling", out)
        self.assertIn("2 SBOMs checked, 1 with errors or unreadable", out)
        self.assertEqual(self.run_cli("sbom", "check", "--project", "shop", "--branch", "main")[0], 0)
        self.assertEqual(self.run_cli("sbom", "check", "--project", "shop", "--branch", "tags/v1")[0], 1)
        self.write("sbom/shop/dev.cdx.json", "{not json")
        code, out, _ = self.run_cli("sbom", "check", "--project", "shop")
        self.assertEqual(code, 2, out)
        self.assertIn("not-json", out)
        self.assertEqual(self.run_cli("sbom", "check", "--project", "nope")[0], 2)
        self.assertEqual(self.run_cli("sbom", "check", str(self.tmp / "missing.json"))[0], 2)
        self.assertEqual(sorted(p.relative_to(self.out) for p in self.out.rglob("*")),
                         sorted(before + [Path("sbom/shop/dev.cdx.json")]))

    def test_empty_folder_and_argument_errors(self):
        self.assertEqual(self.run_cli("sbom", "check")[0], 2)
        self.assertEqual(self.run_cli("sbom", "check", "x.json", "--project", "shop")[0], 2)
        self.assertEqual(self.run_cli("sbom", "check", "--branch", "main")[0], 2)

    def test_path_argument_and_json(self):
        path = self.write("imports/shop/main.cdx.json", good())
        code, out, _ = self.run_cli("sbom", "check", str(path), "--json")
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual(doc[0]["coverage"]["components"], 3)
        self.assertTrue(doc[0]["valid"])


class OwnSbomTests(unittest.TestCase):
    """The SBOMs this tool writes pass its own check (synthetic repositories)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()
        self.root = self.tmp / "PROJECTS"
        self.root.mkdir()
        self.out = self.root / "security"

    def tearDown(self):
        self._tmp.cleanup()

    def assert_sound(self, inv):
        r = sbomquality.check_path(self.out / inv.sbom_path)
        self.assertEqual([f for f in r["findings"] if f["code"] != "subject-missing"], [], inv.sbom_path)
        self.assertEqual(inv.sbom_quality, sbomquality.summary(r) | {})
        return r

    def test_syft_failure_document_has_serial_and_timestamp(self):
        make_repo(self.root, "app", {"Dockerfile": "FROM node:20-alpine\n", ".nvmrc": "20\n"})
        with mock.patch.object(scan.syft, "inventory", side_effect=ToolError("syft", 1, "boom")):
            inv = scan.scan(config.load(self.out), fetch=False).inventories[0]
        r = self.assert_sound(inv)
        self.assertTrue(r["coverage"]["timestamp"] and r["coverage"]["subject"] and r["coverage"]["tools"])
        doc = json.loads((self.out / inv.sbom_path).read_text())
        self.assertRegex(doc["serialNumber"], sbomquality._SERIAL_RE)
        written = json.loads((self.out / "inventory.json").read_text())["inventories"][0]
        self.assertTrue(written["sbom_quality"]["valid"])

    def test_dropped_own_package_leaves_no_dangling_ref(self):
        make_repo(self.root, "app", {"package.json": json.dumps({"name": "app", "version": "1.0.0"})})
        bom = cyclonedx.empty_bom()
        bom["components"] = [
            {"bom-ref": "own", "type": "library", "name": "app", "version": "1.0.0", "purl": "pkg:npm/app@1.0.0"},
            {"bom-ref": "dep", "type": "library", "name": "dep", "version": "2.0.0", "purl": "pkg:npm/dep@2.0.0"}]
        bom["dependencies"] = [{"ref": "own", "dependsOn": ["dep"]}, {"ref": "dep", "dependsOn": []}]
        dep = Component(kind="package", ecosystem="npm", name="dep", version="2.0.0", purl="pkg:npm/dep@2.0.0",
                        scope="required", locations=["package-lock.json"])
        with mock.patch.object(scan.syft, "inventory", return_value=(copy.deepcopy(bom), [dep])):
            inv = scan.scan(config.load(self.out), fetch=False).inventories[0]
        r = self.assert_sound(inv)
        self.assertEqual(r["coverage"]["in_graph"], 1)

    def test_merge_into_legacy_tool_list(self):
        bom = cyclonedx.empty_bom()
        bom["metadata"]["tools"] = [{"vendor": "x", "name": "old", "version": "1"}]
        cyclonedx.merge(bom, [])
        cyclonedx.merge(bom, [])
        self.assertEqual([t["name"] for t in bom["metadata"]["tools"]], ["old", "sbom-audit"])
        self.assertTrue(sbomquality.check(bom)["coverage"]["tools"])

    @unittest.skipUnless(HAVE_SYFT, "syft not installed")
    def test_real_syft_sbom_is_sound(self):
        make_repo(self.root, "app", {
            "package.json": (FIXTURES / "npm-lock" / "package.json").read_text(),
            "package-lock.json": (FIXTURES / "npm-lock" / "package-lock.json").read_text(),
            "Dockerfile": "FROM node:20-alpine\n"})
        inv = scan.scan(config.load(self.out), fetch=False).inventories[0]
        r = self.assert_sound(inv)
        self.assertTrue(r["coverage"]["graph"])
        self.assertGreater(r["coverage"]["version"], 0)

    def test_inventory_md_has_the_quality_table(self):
        make_repo(self.root, "app", {"Dockerfile": "FROM node:20-alpine\n"})
        with mock.patch.object(scan.syft, "inventory", side_effect=ToolError("syft", 1, "boom")):
            result = scan.scan(config.load(self.out), fetch=False)
        path = report.write_inventory_md(config.load(self.out), result.inventories, self.out)
        text = path.read_text()
        self.assertIn("## SBOM quality", text)
        self.assertIn("| app | main | yes |", text)


if __name__ == "__main__":
    unittest.main()
