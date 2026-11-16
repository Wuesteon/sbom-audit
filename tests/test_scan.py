import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit.model import Component
from sbomaudit import config, cyclonedx, model, scan
from sbomaudit.errors import ToolError

from .helpers import make_repo

FIXTURES = Path(__file__).resolve().parent / "fixtures"
HAVE_SYFT = shutil.which("syft") is not None

LOCK_FILES = {
    "package.json": (FIXTURES / "npm-lock" / "package.json").read_text(),
    "package-lock.json": (FIXTURES / "npm-lock" / "package-lock.json").read_text(),
    "Dockerfile": "FROM node:20-alpine\nCOPY . .\n",
}


def snapshot(folder: Path) -> list[tuple[str, float]]:
    out = []
    for dirpath, dirnames, filenames in os.walk(folder):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in filenames:
            p = Path(dirpath) / name
            out.append((str(p.relative_to(folder)), p.stat().st_mtime))
    return sorted(out)


class CycloneDxTests(unittest.TestCase):
    """Pure merge/write/read round trip; no syft binary needed."""

    def test_merge_and_read_components_round_trip(self):
        bom = {
            "bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
            "components": [{
                "bom-ref": "pkg:npm/lodash@4.17.20?package-id=1", "type": "library",
                "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20",
                "properties": [{"name": "syft:location:0:path", "value": "/package-lock.json"},
                               {"name": "sbom-audit:scope", "value": "required"},
                               {"name": "sbom-audit:direct", "value": "true"}],
            }],
        }
        image = model.Component(kind="image", ecosystem="docker", name="node", version="20-alpine",
                                purl="pkg:docker/node@20-alpine", scope="required",
                                locations=["Dockerfile"], direct=True,
                                props={"image": "node:20-alpine", "source": "Dockerfile",
                                       "floating": False, "own": False, "digest": False,
                                       "pin_level": "major",
                                       "unpinned_requirements": ["requirements.txt"]})
        runtime = model.Component(kind="runtime", ecosystem="nodejs", name="nodejs", version="20",
                                  purl="pkg:generic/nodejs@20", scope="required",
                                  locations=["Dockerfile"], direct=True,
                                  props={"source": "Dockerfile", "detail": "image node:20-alpine",
                                         "image": "node:20-alpine"})
        unresolved = model.Component(kind="package", ecosystem="npm", name="express", version="",
                                     purl="pkg:npm/express", scope="required",
                                     locations=["api/package.json"], direct=True,
                                     props={"requirement": "^4.18.0", "unresolved": True})
        merged = cyclonedx.merge(bom, [image, runtime, unresolved])
        types = {c["purl"]: c["type"] for c in merged["components"]}
        self.assertEqual(types["pkg:docker/node@20-alpine"], "container")
        self.assertEqual(types["pkg:generic/nodejs@20"], "platform")
        self.assertEqual(types["pkg:npm/express"], "library")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x" / "main.cdx.json"
            cyclonedx.write(merged, path)
            comps = cyclonedx.read_components(path)
        by_purl = {c.purl: c for c in comps}
        self.assertEqual(by_purl["pkg:docker/node@20-alpine"], image)
        self.assertEqual(by_purl["pkg:generic/nodejs@20"], runtime)
        self.assertEqual(by_purl["pkg:npm/express"], unresolved)
        lodash = by_purl["pkg:npm/lodash@4.17.20"]
        self.assertEqual((lodash.kind, lodash.ecosystem, lodash.scope, lodash.direct,
                          lodash.locations), ("package", "npm", "required", True,
                                              ["package-lock.json"]))

    def test_sbom_path_and_purl_for_project_with_spaces(self):
        out = Path("/x/security")
        self.assertEqual(scan.sbom_path(out, "Client Portal Web", "feature/x"),
                         out / "sbom" / "Client Portal Web" / "feature__x.cdx.json")
        p = config.Project(name="Client Portal Web", path=Path("/x/Client Portal Web"))
        self.assertEqual(config.project_purl(p), "pkg:generic/Client%20Portal%20Web")


class ScanTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()
        self.root = self.tmp / "PROJECTS"
        self.root.mkdir()
        self.out = self.root / "security"

    def tearDown(self):
        self._tmp.cleanup()

    @unittest.skipUnless(HAVE_SYFT, "syft not installed")
    def test_scan_writes_sbom_per_branch(self):
        make_repo(self.root, "app", LOCK_FILES, branches=["main", "dev"])
        cfg = config.load(self.out)
        result = scan.scan(cfg, only=None, fetch=False)
        self.assertEqual([(i.project, i.branch) for i in result.inventories],
                         [("app", "main"), ("app", "dev")])
        for branch in ("main", "dev"):
            path = scan.sbom_path(self.out, "app", branch)
            self.assertTrue(path.exists(), path)
            comps = cyclonedx.read_components(path)
            names = {(c.kind, c.name): c for c in comps}
            self.assertIn(("package", "lodash"), names)
            self.assertEqual(names[("package", "lodash")].scope, "required")
            self.assertTrue(names[("package", "lodash")].direct)
            self.assertEqual(names[("package", "left-pad")].scope, "optional")
            self.assertNotIn(("package", "probe"), names, "project's own package must be dropped")
            self.assertEqual(names[("image", "node")].version, "20-alpine")
            self.assertEqual(names[("runtime", "nodejs")].version, "20")
            doc = json.loads(path.read_text())
            self.assertEqual(doc["metadata"]["component"]["name"], "app")
            self.assertEqual(doc["metadata"]["component"]["purl"], "pkg:generic/app")
            refs = {c["bom-ref"] for c in doc["components"]} | {doc["metadata"]["component"]["bom-ref"]}
            for dep in doc.get("dependencies", []):
                self.assertIn(dep["ref"], refs)
                for d in dep.get("dependsOn", []):
                    self.assertIn(d, refs)
        inv_file = json.loads((self.out / "inventory.json").read_text())
        self.assertEqual(len(inv_file["inventories"]), 2)
        back = model.BranchInventory.from_dict(inv_file["inventories"][0])
        self.assertEqual(back.sbom_path, "sbom/app/main.cdx.json")
        self.assertEqual(sorted({c.kind for c in back.components}), ["image", "package", "runtime"])

    @unittest.skipUnless(HAVE_SYFT, "syft not installed")
    def test_single_mode_excludes_security_dir(self):
        evil = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
                           "components": [{"bom-ref": "e", "type": "library", "name": "evil",
                                           "version": "1.0.0", "purl": "pkg:npm/evil@1.0.0"}]})
        files = dict(LOCK_FILES, **{"security/sbom/repo/main.cdx.json": evil})
        repo = make_repo(self.tmp, "repo", files)
        out = repo / "security"
        cfg = config.load(out)
        self.assertEqual(cfg.mode, "single")
        result = scan.scan(cfg, only=None, fetch=False)
        self.assertEqual([(i.project, i.branch) for i in result.inventories], [("repo", "main")])
        comps = result.inventories[0].components
        self.assertNotIn("evil", {c.name for c in comps})
        idents = [(c.purl, tuple(c.locations)) for c in comps]
        self.assertEqual(len(idents), len(set(idents)), "no duplicate components")
        self.assertTrue(scan.sbom_path(out, "repo", "main").exists())

    @unittest.skipUnless(HAVE_SYFT, "syft not installed")
    def test_worktree_untouched_after_scan(self):
        repo = make_repo(self.root, "app", LOCK_FILES, branches=["main", "dev"])
        (repo / "scratch.txt").write_text("uncommitted\n")
        before = snapshot(repo)
        status_before = subprocess.run(["git", "-C", str(repo), "status", "--porcelain"],
                                       capture_output=True, text=True).stdout
        scan.scan(config.load(self.out), only=None, fetch=False)
        self.assertEqual(snapshot(repo), before)
        status_after = subprocess.run(["git", "-C", str(repo), "status", "--porcelain"],
                                      capture_output=True, text=True).stdout
        self.assertEqual(status_after, status_before)
        self.assertFalse((repo / "security").exists())

    def test_syft_failure_is_recorded_not_fatal(self):
        make_repo(self.root, "app", LOCK_FILES)
        cfg = config.load(self.out)
        with mock.patch.object(scan.syft, "inventory", side_effect=ToolError("syft", 1, "boom")):
            result = scan.scan(cfg, only=["app"], fetch=False)
        inv = result.inventories[0]
        self.assertTrue(any(e.startswith("syft:") for e in inv.errors), inv.errors)
        self.assertIn(("image", "node"), {(c.kind, c.name) for c in inv.components})
        self.assertTrue(scan.sbom_path(self.out, "app", "main").exists())

    def test_reader_packages_already_catalogued_by_syft_are_not_duplicated(self):
        """If a future Syft lists esm.sh packages itself, the deno.lock reader must not add a second copy."""
        lock = '{"version": "4", "remote": {"https://esm.sh/inngest@3.52.7": "h"}}'
        make_repo(self.root, "fn", {"deno.lock": lock})
        cfg = config.load(self.out)
        inngest = Component(kind="package", ecosystem="npm", name="inngest", version="3.52.7",
                            purl="pkg:npm/inngest@3.52.7", scope="required", locations=["deno.lock"])
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1, "components": []}
        with mock.patch.object(scan.syft, "inventory", return_value=(bom, [inngest])):
            result = scan.scan(cfg, only=["fn"], fetch=False)
        comps = [c for c in result.inventories[0].components if c.name == "inngest"]
        self.assertEqual([(c.version, c.purl) for c in comps], [("3.52.7", "pkg:npm/inngest@3.52.7")])

    def test_only_filters_and_reports_unknown_names(self):
        make_repo(self.root, "a", {"README": "a\n"})
        make_repo(self.root, "b", {"README": "b\n"})
        cfg = config.load(self.out)
        with mock.patch.object(scan.syft, "inventory", return_value=({"bomFormat": "CycloneDX",
                                                                      "specVersion": "1.7",
                                                                      "version": 1,
                                                                      "components": []}, [])):
            result = scan.scan(cfg, only=["b", "nope"], fetch=False)
        self.assertEqual([i.project for i in result.inventories], ["b"])
        self.assertEqual([s["project"] for s in result.skipped], ["nope"])


if __name__ == "__main__":
    unittest.main()
