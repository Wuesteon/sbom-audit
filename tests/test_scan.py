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

    def test_tag_named_like_a_branch_is_warned_about_and_not_read(self):
        repo = make_repo(self.root, "app", {"Dockerfile": "FROM node:20-alpine\n"})
        git = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)
        git("tag", "main")                                   # the tag holds the old Dockerfile
        (repo / "Dockerfile").write_text("FROM python:3.12-slim\n")
        git("commit", "-q", "-am", "python")
        lines = []
        with mock.patch.object(scan.syft, "inventory", side_effect=ToolError("syft", 1, "boom")):
            result = scan.scan(config.load(self.out), only=["app"], fetch=False, log=lines.append)
        inv = result.inventories[0]
        self.assertEqual(inv.ref, "refs/heads/main")
        self.assertIn(("image", "python"), {(c.kind, c.name) for c in inv.components})
        self.assertNotIn(("image", "node"), {(c.kind, c.name) for c in inv.components})
        self.assertTrue(any("tag named 'main'" in line for line in lines), lines)

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

    def test_maven_go_direct_test_scope_own_modules_and_unknown_direct(self):
        pom = ("<project><groupId>org.example</groupId><artifactId>app</artifactId><version>1.0</version>"
               "<properties><maven.compiler.release>21</maven.compiler.release></properties><dependencies>"
               "<dependency><groupId>org.lib</groupId><artifactId>lib</artifactId></dependency>"
               "<dependency><groupId>org.junit</groupId><artifactId>junit</artifactId><scope>test</scope></dependency>"
               "<dependency><groupId>org.example</groupId><artifactId>mod</artifactId></dependency>"
               "</dependencies></project>")
        mod_pom = ("<project><parent><groupId>org.example</groupId><artifactId>app</artifactId></parent>"
                   "<artifactId>mod</artifactId></project>")
        gomod = ("module example.com/svc\n\ngo 1.22\n\nrequire (\n\texample.com/dep v1.0.0\n"
                 "\texample.com/ind v1.0.0 // indirect\n)\n")
        make_repo(self.root, "java", {"pom.xml": pom, "mod/pom.xml": mod_pom, "svc/go.mod": gomod})
        cfg = config.load(self.out)

        def entry(name, purl):
            return {"bom-ref": purl, "type": "library", "name": name, "purl": purl,
                    "properties": [{"name": "sbom-audit:scope", "value": "required"}]}
        rows = [("lib", "pkg:maven/org.lib/lib@1.0"), ("lib-core", "pkg:maven/org.lib/lib-core@1.0"),
                ("junit", "pkg:maven/org.junit/junit@4.13"), ("mod", "pkg:maven/org.example/mod@1.0"),
                ("example.com/dep", "pkg:golang/example.com/dep@v1.0.0"),
                ("example.com/ind", "pkg:golang/example.com/ind@v1.0.0"),
                ("hex", "pkg:hex/hex@1.0.0")]
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
               "components": [entry(n, p) for n, p in rows]}
        comps = [cyclonedx.components({"components": [entry(n, p)]})[0] for n, p in rows]
        with mock.patch.object(scan.syft, "inventory", return_value=(bom, comps)):
            result = scan.scan(cfg, only=["java"], fetch=False)
        got = {c.name: (c.direct, c.scope) for c in result.inventories[0].components if c.kind == "package"}
        self.assertEqual(got, {"lib": (True, "required"), "lib-core": (False, "required"),
                               "junit": (True, "optional"), "example.com/dep": (True, "required"),
                               "example.com/ind": (False, "required"), "hex": (None, "required")})
        runtimes = {(c.ecosystem, c.version) for c in result.inventories[0].components if c.kind == "runtime"}
        self.assertTrue({("java", "21"), ("go", "1.22")} <= runtimes, runtimes)
        sbom = {c.name: c for c in cyclonedx.read_components(scan.sbom_path(self.out, "java", "main"))}
        self.assertNotIn("mod", sbom, "the reactor's own module is not a dependency")
        self.assertEqual((sbom["junit"].scope, sbom["junit"].direct), ("optional", True))
        self.assertIsNone(sbom["hex"].direct)

    def test_go_module_imported_only_by_tests_is_dev_only(self):
        make_repo(self.root, "gosvc", {
            "go.mod": "module example.com/svc\n\ngo 1.22\n\nrequire (\n\tgithub.com/stretchr/testify v1.9.0\n"
                      "\tgithub.com/lib/pq v1.10.9\n)\n",
            "main.go": 'package main\n\nimport _ "github.com/lib/pq"\n',
            "main_test.go": 'package main\n\nimport "github.com/stretchr/testify/assert"\n'})
        cfg = config.load(self.out)

        def entry(name, purl):
            return {"bom-ref": purl, "type": "library", "name": name, "purl": purl, "version": purl.split("@")[1],
                    "properties": [{"name": "sbom-audit:scope", "value": "required"}]}
        rows = [("github.com/stretchr/testify", "pkg:golang/github.com/stretchr/testify@v1.9.0"),
                ("github.com/lib/pq", "pkg:golang/github.com/lib/pq@v1.10.9")]
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1, "components": [entry(*r) for r in rows]}
        comps = [cyclonedx.components({"components": [entry(*r)]})[0] for r in rows]
        with mock.patch.object(scan.syft, "inventory", return_value=(bom, comps)):
            result = scan.scan(cfg, only=["gosvc"], fetch=False)
        got = {c.name: (c.direct, c.scope) for c in result.inventories[0].components if c.kind == "package"}
        self.assertEqual(got, {"github.com/stretchr/testify": (True, "optional"), "github.com/lib/pq": (True, "required")})
        sbom = {c.name: c for c in cyclonedx.read_components(scan.sbom_path(self.out, "gosvc", "main"))}
        self.assertEqual(sbom["github.com/stretchr/testify"].scope, "optional")

    def test_gradle_direct_scope_unknown_direct_and_unlocked_modules(self):
        make_repo(self.root, "droid", {
            "settings.gradle.kts": 'include(":app", ":lib", ":legacy")\n',
            "app/build.gradle.kts": 'dependencies {\n implementation("org.a:core:1.0")\n'
                                    ' testImplementation("org.t:junit:4.13")\n}\n',
            "app/gradle.lockfile": "org.a:core:1.0=runtimeClasspath\norg.a:dep:2.0=runtimeClasspath\n"
                                   "org.t:junit:4.13=testRuntimeClasspath\norg.t:hamcrest:1.3=testRuntimeClasspath\n",
            "lib/build.gradle.kts": 'dependencies {\n implementation(Deps.mystery)\n}\n',
            "lib/gradle.lockfile": "org.m:mystery:3.0=runtimeClasspath\n",
            "legacy/build.gradle": "dependencies {\n implementation 'org.u:unlocked:5.1'\n"
                                   " implementation 'org.u:dynamic:1.+'\n}\n"})
        cfg = config.load(self.out)

        def entry(name, purl, loc):
            return {"bom-ref": purl, "type": "library", "name": name, "purl": purl, "version": purl.split("@")[1],
                    "properties": [{"name": "sbom-audit:scope", "value": "required"},
                                   {"name": "syft:location:0:path", "value": "/" + loc}]}
        rows = [("core", "pkg:maven/org.a/core@1.0", "app/gradle.lockfile"),
                ("dep", "pkg:maven/org.a/dep@2.0", "app/gradle.lockfile"),
                ("junit", "pkg:maven/org.t/junit@4.13", "app/gradle.lockfile"),
                ("hamcrest", "pkg:maven/org.t/hamcrest@1.3", "app/gradle.lockfile"),
                ("mystery", "pkg:maven/org.m/mystery@3.0", "lib/gradle.lockfile")]
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
               "components": [entry(*r) for r in rows]}
        comps = [cyclonedx.components({"components": [entry(*r)]})[0] for r in rows]
        with mock.patch.object(scan.syft, "inventory", return_value=(bom, comps)):
            result = scan.scan(cfg, only=["droid"], fetch=False)
        got = {c.name: (c.direct, c.scope, c.version) for c in result.inventories[0].components
               if c.kind == "package"}
        self.assertEqual(got["core"], (True, "required", "1.0"))
        self.assertEqual(got["dep"], (False, "required", "2.0"))
        self.assertEqual(got["junit"], (True, "optional", "4.13"))
        # test-only in the lock file, but `legacy` has no lock state: other routes onto a classpath are unknown
        self.assertEqual(got["hamcrest"][:2], (False, "required"))
        self.assertEqual(got["mystery"][:2], (None, "required"))   # its module declares something not understood
        self.assertEqual(got["unlocked"], (True, "required", "5.1"))
        self.assertEqual(got["dynamic"], (True, "required", ""))
        self.assertEqual(got["Deps.mystery"][2], "")
        sbom = {c.name: c for c in cyclonedx.read_components(scan.sbom_path(self.out, "droid", "main"))}
        self.assertEqual(sbom["junit"].scope, "optional")
        self.assertTrue(sbom["dynamic"].props.get("unresolved"))

    def test_pom_and_gradle_declaring_one_unresolved_coordinate_keep_two_rows(self):
        """Each manifest's row is evidence and stays; reports group them (coverage.coordinate)."""
        from sbomaudit import coverage, sbomquality
        pom = ("<project><dependencies><dependency><groupId>org.a</groupId><artifactId>core</artifactId>"
               "<version>${core.version}</version></dependency></dependencies></project>\n")
        make_repo(self.root, "java", {"pom.xml": pom, "build.gradle": "dependencies {\n implementation 'org.a:core'\n}\n"})
        cfg = config.load(self.out)
        purl = "pkg:maven/org.a/core@${core.version}"
        entry = {"bom-ref": purl, "type": "library", "name": "core", "version": "${core.version}", "purl": purl,
                 "properties": [{"name": "sbom-audit:scope", "value": "required"},
                                {"name": "syft:location:0:path", "value": "/pom.xml"}]}
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1, "components": [entry]}
        comps = cyclonedx.components({"components": [dict(entry)]})
        with mock.patch.object(scan.syft, "inventory", return_value=(bom, comps)):
            result = scan.scan(cfg, only=["java"], fetch=False)
        rows = [c for c in result.inventories[0].components if c.kind == "package"]
        self.assertEqual(sorted((c.version, tuple(c.locations)) for c in rows),
                         [("", ("build.gradle",)), ("${core.version}", ("pom.xml",))])
        self.assertEqual(len(coverage.distinct_packages(rows)), 1)
        quality = sbomquality.check_path(scan.sbom_path(self.out, "java", "main"))
        self.assertEqual(quality["coverage"]["components"], 2)          # two entries in the document, labelled so

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
