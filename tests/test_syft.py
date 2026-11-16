import shutil
import unittest
from pathlib import Path

from sbomaudit import model, syft

FIXTURES = Path(__file__).resolve().parent / "fixtures"
HAVE_SYFT = shutil.which("syft") is not None


class ModelTests(unittest.TestCase):
    def test_component_roundtrip(self):
        c = model.Component(kind="package", ecosystem="npm", name="lodash", version="4.17.20",
                            purl="pkg:npm/lodash@4.17.20", scope="required",
                            locations=["package-lock.json"], direct=None, props={"a": 1})
        self.assertEqual(model.Component.from_dict(c.to_dict()), c)

    def test_inventory_roundtrip(self):
        inv = model.BranchInventory(project="p", branch="main", ref="origin/main", commit="abc",
                                    behind=1, components=[], sbom_path="sbom/p/main.cdx.json",
                                    errors=["x"])
        self.assertEqual(model.BranchInventory.from_dict(inv.to_dict()), inv)


class ComponentsFromBomTests(unittest.TestCase):
    """Pure parsing of a CycloneDX document; no syft binary needed."""

    BOM = {
        "bomFormat": "CycloneDX", "specVersion": "1.7",
        "components": [
            {"type": "library", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20",
             "properties": [{"name": "syft:location:0:path", "value": "/package-lock.json"},
                            {"name": "syft:package:foundBy", "value": "javascript-lock-cataloger"}]},
            {"type": "library", "name": "Requests_Toolbelt", "version": "1.0.0",
             "purl": "pkg:pypi/requests-toolbelt@1.0.0",
             "properties": [{"name": "syft:location:0:path", "value": "/backend/uv.lock"}]},
            {"type": "library", "name": "Alamofire", "version": "5.9.0", "purl": "pkg:cocoapods/Alamofire@5.9.0",
             "properties": [{"name": "syft:location:0:path", "value": "/ios/Podfile.lock"}]},
            {"type": "file", "name": "/package-lock.json"},
        ],
    }

    def test_components_have_purl_ecosystem_and_location(self):
        comps = syft.components(self.BOM)
        self.assertEqual([c.name for c in comps], ["lodash", "Requests_Toolbelt", "Alamofire"])
        lodash = comps[0]
        self.assertEqual(lodash.ecosystem, "npm")
        self.assertEqual(lodash.locations, ["package-lock.json"])
        self.assertEqual(lodash.purl, "pkg:npm/lodash@4.17.20")
        self.assertEqual(lodash.kind, "package")
        self.assertEqual(lodash.scope, "unknown")
        self.assertEqual(comps[1].ecosystem, "PyPI")
        self.assertEqual(comps[1].locations, ["backend/uv.lock"])
        self.assertEqual(comps[2].ecosystem, "cocoapods")

    def test_file_entries_skipped(self):
        self.assertFalse(any(c.name.startswith("/") for c in syft.components(self.BOM)))


@unittest.skipUnless(HAVE_SYFT, "syft not installed")
class SyftRunTests(unittest.TestCase):
    def test_lock_components_have_purl_and_location(self):
        bom = syft.run(FIXTURES / "npm-lock", include_dev=False)
        comps = {c.name: c for c in syft.components(bom)}
        self.assertIn("lodash", comps)
        self.assertEqual(comps["lodash"].version, "4.17.20")
        self.assertEqual(comps["lodash"].locations, ["package-lock.json"])
        self.assertNotIn("left-pad", comps)

    def test_dev_only_scope_from_two_runs(self):
        bom, comps = syft.inventory(FIXTURES / "npm-lock")
        by_name = {c.name: c for c in comps}
        self.assertEqual(by_name["left-pad"].scope, "optional")
        self.assertEqual(by_name["lodash"].scope, "required")
        scopes = {c["name"]: [p["value"] for p in c.get("properties", []) if p["name"] == "sbom-audit:scope"]
                  for c in bom["components"] if c.get("purl")}
        self.assertEqual(scopes["left-pad"], ["optional"])
        self.assertEqual(scopes["lodash"], ["required"])

    def test_uv_lock_component(self):
        _, comps = syft.inventory(FIXTURES / "uv")
        by_name = {c.name: c for c in comps}
        self.assertEqual(by_name["requests"].version, "2.31.0")
        self.assertEqual(by_name["requests"].ecosystem, "PyPI")
        self.assertEqual(by_name["requests"].locations, ["uv.lock"])

    def test_bare_package_json_yields_nothing_from_syft(self):
        # Documented Syft behaviour (1.56): no lockfile, no components. Task 5's reader covers it.
        _, comps = syft.inventory(FIXTURES / "npm-nolock")
        self.assertEqual(comps, [])

    def test_missing_directory_raises_tool_error(self):
        with self.assertRaises(syft.ToolError) as ctx:
            syft.run(FIXTURES / "does-not-exist", include_dev=False)
        self.assertEqual(ctx.exception.tool, "syft")


if __name__ == "__main__":
    unittest.main()
