"""Coverage gaps of C/C++ and firmware code: detected, reported as not checked, never as clean."""
from __future__ import annotations

import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from sbomaudit import gaps, report, status
from sbomaudit.model import BranchInventory, Component
from tests.test_report import LODASH, SOURCES_OK, assert_tables_well_formed, config, inv

GITMODULES = """[submodule "lib/mbedtls"]
\tpath = lib/mbedtls
\turl = https://github.com/ARMmbed/mbedtls.git
[submodule "lib/lwip"]
\tpath = lib/lwip
\turl = https://git.savannah.nongnu.org/r/lwip.git
"""


def tree(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


class DetectTest(unittest.TestCase):
    def test_firmware_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = tree(Path(tmp), {
                ".gitmodules": GITMODULES,
                "west.yml": "manifest:\n  projects: []\n",
                "ports/esp32/main/idf_component.yml": "dependencies:\n  espressif/mdns: '~1.3.0'\n",
                "platformio.ini": "[env:x]\nlib_deps = foo\n",
                "vcpkg.json": json.dumps({"name": "app", "dependencies": ["zlib", {"name": "openssl"}]}),
                "sub/vcpkg.json": json.dumps({"name": "nodeps"}),
                "CMakeLists.txt": "include(FetchContent)\nFetchContent_Declare(fmt GIT_REPOSITORY x)\n",
                "lib/FreeRTOS/tasks.c": "int x;\n", "lib/FreeRTOS/task.h": "", "src/main.cpp": "",
                "node_modules/dep/x.c": "", "README.md": "",
            })
            gap = gaps.detect(src)
        self.assertEqual(gap["submodule_count"], 2)
        self.assertEqual(gap["submodules"][0], {"path": "lib/mbedtls", "url": "https://github.com/ARMmbed/mbedtls.git"})
        files = {m["file"]: m["kind"] for m in gap["manifests"]}
        self.assertEqual(set(files), {"west.yml", "ports/esp32/main/idf_component.yml", "platformio.ini",
                                      "vcpkg.json", "CMakeLists.txt"})       # vcpkg.json without deps: read by Syft
        self.assertIn("2 dependencies not read", files["vcpkg.json"])
        self.assertIn("fmt", files["CMakeLists.txt"])
        self.assertEqual(gap["c_sources"], 3)                                 # node_modules skipped
        text = gaps.describe(gap)
        self.assertIn("2 git submodule(s) not scanned (`lib/mbedtls`, `lib/lwip`)", text)
        self.assertIn("3 C/C++ source files", text)
        self.assertIn("import a build SBOM", text)
        self.assertIn("check that it covers these", gaps.describe(gap, imported=True))

    def test_vcpkg_feature_dependencies_count(self):
        manifest = {"name": "libsndfile", "features": {"external-libs": {"dependencies": ["libflac", "opus"]},
                                                       "mpeg": {"dependencies": [{"name": "mpg123"}]},
                                                       "empty": {"description": "x"}}}
        with tempfile.TemporaryDirectory() as tmp:
            gap = gaps.detect(tree(Path(tmp), {"vcpkg.json": json.dumps(manifest)}))
        self.assertIn("3 dependencies not read", gap["manifests"][0]["kind"])

    def test_plain_web_project_has_no_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = tree(Path(tmp), {"package.json": "{}", "src/index.ts": "", "README.md": ""})
            self.assertIsNone(gaps.detect(src))

    def test_broken_gitmodules_is_no_crash(self):
        self.assertEqual(gaps.submodules("[submodule \"x\"\npath = \n"), [])

    def test_old_inventory_entry_loads_and_none_is_not_written(self):
        entry = {"project": "p", "branch": "main", "ref": "main", "commit": "abc", "components": []}
        b = BranchInventory.from_dict(entry)
        self.assertIsNone(b.coverage_gaps)
        self.assertNotIn("coverage_gaps", b.to_dict())
        b.coverage_gaps = {"c_sources": 4, "submodules": [], "submodule_count": 0, "manifests": [],
                           "manifest_count": 0}
        self.assertEqual(BranchInventory.from_dict(b.to_dict()).coverage_gaps["c_sources"], 4)


def imported(ecosystem, name, version):
    return Component(kind="package", ecosystem=ecosystem, name=name, version=version,
                     purl=f"pkg:{ecosystem}/{name}@{version}", scope="required",
                     locations=["imports/fw/main.cdx.json"], direct=True, props={"imported": True})


class ReportTest(unittest.TestCase):
    def test_gaps_skipped_and_unmatched_are_reported_not_clean(self):
        fw = inv("fw", "main", [imported("github", "Mbed-TLS/mbedtls", "v2.28.0"),
                                imported("generic", "freertos-kernel", "9.0.0"),
                                imported("conan", "zlib", "1.2.11")])
        fw.coverage_gaps = {"submodules": [{"path": "lib/lwip", "url": ""}], "submodule_count": 1,
                            "manifests": [], "manifest_count": 0, "c_sources": 120}
        fw.package_source = {"file": "imports/fw/main.cdx.json"}
        with tempfile.TemporaryDirectory() as tmp:
            cfg = config(Path(tmp))
            rep = report.build(cfg, [fw, inv("zeta", "main", [LODASH])], [], [], [], [], SOURCES_OK,
                               skipped=[{"project": "legacy", "reason": "none of ['main', 'dev'] exist"}])
            st = rep["stats"]
            self.assertEqual(st["packages_unmatched"], 3)
            self.assertEqual(st["github_actions_unchecked"], 0)      # an imported pkg:github is no workflow action
            self.assertEqual(st["coverage_gaps"], 1)
            self.assertEqual(st["projects_not_scanned"], 1)
            self.assertEqual(rep["skipped_projects"][0]["project"], "legacy")
            notes = "\n".join(rep["notes"])
            self.assertIn("legacy: not scanned", notes)
            self.assertIn("`branches`", notes)
            self.assertIn("fw@main: 3 packages are inventoried but not checked", notes)
            self.assertIn("fw@main: coverage gap: 1 git submodule(s)", notes)
            cfg.out.mkdir(parents=True)
            text = report.write_audit_md(rep, cfg.out).read_text(encoding="utf-8")
            self.assertIn("| Projects not scanned (see Notes) | 1 |", text)
            self.assertIn("not checked for vulnerabilities | 3 |", text)
            self.assertIn("firmware manifests not inventoried (see Notes) | 1 |", text)
            assert_tables_well_formed(self, text)

            doc = status.build(rep, secrets=None, previous=None, duration_s=1.0, exit_code=0, run_host="h",
                               mode=cfg.mode)
            md = status.render_md(doc, None, dt.datetime.now().astimezone())
            self.assertNotIn("All sources answered.", md)
            self.assertIn("1 projects not scanned", md)
            self.assertIn("1 branches with submodules", md)

    def test_clean_portfolio_keeps_audit_json_as_before(self):
        with tempfile.TemporaryDirectory() as tmp:
            rep = report.build(config(Path(tmp)), [inv("zeta", "main", [LODASH])], [], [], [], [], SOURCES_OK)
        for key in ("packages_unmatched", "coverage_gaps", "projects_not_scanned"):
            self.assertNotIn(key, rep["stats"])
        self.assertNotIn("skipped_projects", rep)


if __name__ == "__main__":
    unittest.main()
