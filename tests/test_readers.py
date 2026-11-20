import json
import shutil
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from sbomaudit import readers
from sbomaudit.model import Component


def write(root: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return root


class ReaderTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.src = Path(self._tmp.name).resolve()

    def tearDown(self):
        self._tmp.cleanup()

    def by(self, comps, kind):
        return [c for c in comps if c.kind == kind]

    def test_dockerfile_from_with_arg_and_stage(self):
        write(self.src, {"Dockerfile": (
            "ARG NODE_VERSION=20.11\n"
            "FROM node:${NODE_VERSION}-alpine AS builder\n"
            "RUN npm ci\n"
            "FROM builder AS test\n"
            "FROM nginx:alpine\n"
            "COPY --from=builder /app/dist /usr/share/nginx/html\n")})
        images = self.by(readers.read_tree(self.src, []), "image")
        self.assertEqual([(c.name, c.version) for c in images], [("node", "20.11-alpine"), ("nginx", "alpine")])
        self.assertEqual(images[0].purl, "pkg:docker/node@20.11-alpine")
        self.assertEqual(images[0].ecosystem, "docker")
        self.assertEqual(images[0].locations, ["Dockerfile"])
        self.assertFalse(images[0].props["floating"])
        self.assertTrue(images[1].props["floating"])

    def test_compose_images_and_own_build(self):
        write(self.src, {"docker-compose.yml": (
            "services:\n"
            "  api:\n"
            "    build: .\n"
            "    image: myapp-api:latest\n"
            "  db:\n"
            "    image: \"postgres:15\"  # pinned major\n"
            "  cache:\n"
            "    image: redis@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
            "  proxy:\n"
            "    image: ghcr.io/example-org/edge:1.2.3\n")})
        images = self.by(readers.read_tree(self.src, [], remote="git@github.com:Example-Org/myapp.git"), "image")
        names = {c.name: c for c in images}
        self.assertEqual(set(names), {"myapp-api", "postgres", "redis", "ghcr.io/example-org/edge"})
        self.assertTrue(names["myapp-api"].props["own"])
        self.assertTrue(names["ghcr.io/example-org/edge"].props["own"])
        self.assertFalse(names["postgres"].props["own"])
        self.assertEqual(names["postgres"].version, "15")
        self.assertTrue(names["redis"].props["digest"])
        self.assertFalse(names["redis"].props["floating"])
        self.assertEqual(names["postgres"].locations, ["docker-compose.yml"])

    def test_floating_tag_detection(self):
        cases = {
            "nginx:alpine": (True, "none"),
            "nginx": (True, "none"),
            "qdrant/qdrant:latest": (True, "none"),
            "debian:bookworm-slim": (True, "none"),
            "node:20.11-alpine": (False, "minor"),
            "node:20.11.1": (False, "patch"),
            "caddy:2-alpine": (False, "major"),
            "caddy@sha256:aaaa": (False, "digest"),
            "debian:trixie-20260918-slim": (False, "dated"),
        }
        for image, (floating, level) in cases.items():
            info = readers.parse_image(image)
            self.assertEqual((info["floating"], info["pin_level"]), (floating, level), image)

    def test_runtime_pins(self):
        write(self.src, {
            "package.json": '{"name": "app", "engines": {"node": ">=18.0.0"}}',
            "package-lock.json": '{"lockfileVersion": 3, "packages": {}}',
            ".nvmrc": "v20.11.1\n",
            "backend/pyproject.toml": '[project]\nname = "svc"\nrequires-python = ">=3.12,<3.14"\n',
            "backend/uv.lock": "version = 1\n",
            "backend/.python-version": "3.12.4\n",
            "supabase/config.toml": '[db]\nmajor_version = 15\n[edge_runtime]\ndeno_version = 2\n',
            "deno.json": "{}",
        })
        runtimes = self.by(readers.read_tree(self.src, []), "runtime")
        got = sorted((c.ecosystem, c.version, c.locations[0]) for c in runtimes)
        self.assertEqual(got, sorted([
            ("nodejs", "18", "package.json"),
            ("nodejs", "20", ".nvmrc"),
            ("python", "3.12", "backend/pyproject.toml"),
            ("python", "3.12", "backend/.python-version"),
            ("postgresql", "15", "supabase/config.toml"),
            ("deno", "2", "supabase/config.toml"),
            ("deno", "", "deno.json"),
        ]))
        node = next(c for c in runtimes if c.locations == ["package.json"])
        self.assertEqual(node.purl, "pkg:generic/nodejs@18")
        self.assertEqual(node.props["detail"], "engines.node >=18.0.0")

    def test_runtime_from_image(self):
        cases = {
            "node:20-alpine": ("nodejs", "20"),
            "python:3.12-slim": ("python", "3.12"),
            "postgres:15": ("postgresql", "15"),
            "caddy:2-alpine": ("caddy", "2"),
            "nginx:alpine": ("nginx", ""),
            "denoland/deno:2.1.4": ("deno", "2.1"),
            "alpine:3.20": ("alpine", "3.20"),
            "ghcr.io/example-org/edge:1.2.3": None,
        }
        for image, expected in cases.items():
            c = readers.image_component(image, "Dockerfile")
            rt = readers.runtime_from_image(c)
            if expected is None:
                self.assertIsNone(rt, image)
            else:
                self.assertEqual((rt.ecosystem, rt.version), expected, image)
                self.assertEqual(rt.kind, "runtime")
                self.assertEqual(rt.locations, ["Dockerfile"])
                self.assertEqual(rt.props["image"], image)

    def test_unpinned_requirements_flag(self):
        write(self.src, {
            "Dockerfile": "FROM python:3.12-slim\nCOPY requirements.txt .\nRUN pip install -r requirements.txt\n",
            "requirements.txt": "fastapi>=0.100\nuvicorn\nhttpx==0.27.0\n",
        })
        images = self.by(readers.read_tree(self.src, []), "image")
        self.assertEqual(images[0].props["unpinned_requirements"], ["requirements.txt"])

    def test_symlinked_files_outside_the_tree_are_never_read(self):
        outside = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, outside, True)
        (outside / "secret").write_text("SECRET_TOKEN=abc123\n")
        (outside / "Dockerfile").write_text("FROM evil:1\n")
        (outside / "package-lock.json").write_text("{}")
        write(self.src, {"Dockerfile.real": "FROM python:3.12-slim\n",
                         "package.json": '{"dependencies": {"left-pad": "^1.0.0"}}'})
        (self.src / "sub").mkdir()
        for name in (".nvmrc", ".node-version", ".python-version", "pyproject.toml", "deno.lock"):
            (self.src / name).symlink_to(outside / "secret")
        (self.src / "sub" / "Dockerfile").symlink_to(outside / "Dockerfile")
        (self.src / "package-lock.json").symlink_to(outside / "package-lock.json")  # no lockfile from outside
        (self.src / "Dockerfile").symlink_to("Dockerfile.real")                     # inside: still read
        comps = readers.read_tree(self.src, [])
        dump = json.dumps([[c.name, c.version, c.locations, c.props] for c in comps])
        self.assertNotIn("SECRET_TOKEN", dump)
        self.assertNotIn("evil", dump)
        self.assertEqual([c.props for c in comps if "error" in c.props], [])
        self.assertEqual(sorted({c.locations[0] for c in self.by(comps, "image")}), ["Dockerfile", "Dockerfile.real"])
        self.assertTrue(any(c.name == "left-pad" for c in comps))  # the outside lockfile does not count
        self.assertEqual([rel for rel, _ in readers.walk(self.src, [])],
                         ["Dockerfile", "Dockerfile.real", "package.json"])

    def test_requirements_outside_the_tree_are_never_read(self):
        # a scanned repo chooses the -r path: a symlink, ../ or an absolute path must not reach outside the export
        outside = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, outside, True)
        (outside / "requirements.txt").write_text("flask\n")
        write(self.src, {
            "Dockerfile": (f"FROM python:3.12-slim\nRUN pip install -r link-requirements.txt\n"
                           f"RUN pip install -r ../{outside.name}/requirements.txt\n"
                           f"RUN pip install -r {outside}/requirements.txt\n"),
        })
        (self.src / "link-requirements.txt").symlink_to(outside / "requirements.txt")
        real_read = readers._read
        read: list[Path] = []
        with mock.patch.object(readers, "_read", side_effect=lambda f: (read.append(Path(f)), real_read(f))[1]):
            comps = readers.read_tree(self.src, [])
        self.assertNotIn((outside / "requirements.txt").resolve(), [f.resolve() for f in read])
        self.assertEqual([c.props for c in comps if "error" in c.props], [])
        images = self.by(comps, "image")
        self.assertEqual([c.name for c in images], ["python"])  # the image is still listed
        self.assertNotIn("unpinned_requirements", images[0].props)
        self.assertNotIn(str(outside), json.dumps([c.props for c in comps]))

    def test_package_json_without_lockfile_lists_unresolved(self):
        write(self.src, {
            "package.json": '{"name": "nolock", "dependencies": {"express": "^4.18.0"}, "devDependencies": {"vitest": "^2"}}',
            "packages/sub/package.json": '{"name": "@nolock/sub", "dependencies": {"lodash": "^4"}}',
            "with-lock/package.json": '{"name": "locked", "dependencies": {"left-pad": "^1"}}',
            "with-lock/package-lock.json": "{}",
        })
        pkgs = self.by(readers.read_tree(self.src, []), "package")
        got = {(c.name, c.locations[0]): c for c in pkgs}
        self.assertIn(("express", "package.json"), got)
        self.assertIn(("vitest", "package.json"), got)
        self.assertIn(("lodash", "packages/sub/package.json"), got)
        self.assertNotIn(("left-pad", "with-lock/package.json"), got)
        express = got[("express", "package.json")]
        self.assertEqual(express.version, "")
        self.assertEqual(express.props["requirement"], "^4.18.0")
        self.assertTrue(express.props["unresolved"])
        self.assertEqual(express.purl, "pkg:npm/express")
        self.assertEqual(express.scope, "required")
        self.assertTrue(express.direct)
        self.assertEqual(got[("vitest", "package.json")].scope, "optional")

    def test_workspace_package_json_with_root_lockfile_is_resolved(self):
        write(self.src, {
            "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
            "apps/web/package.json": '{"name": "web", "dependencies": {"svelte": "^5"}}',
        })
        self.assertEqual(self.by(readers.read_tree(self.src, []), "package"), [])

    def test_self_packages_and_direct_deps(self):
        write(self.src, {
            "package.json": '{"name": "website", "dependencies": {"astro": "^5"}, "devDependencies": {"vitest": "^2"}}',
            "apps/api/package.json": '{"name": "@acme/api", "dependencies": {"@nestjs/core": "^10"}}',
            "backend/pyproject.toml": '[project]\nname = "Shop_Backend"\ndependencies = ["FastAPI>=0.100", "crewai[tools]==0.80"]\n[dependency-groups]\ndev = ["pytest"]\n',
            "backend/requirements.txt": "Requests_Toolbelt==1.0\n",
        })
        self.assertEqual(readers.self_packages(self.src), {("npm", "website"), ("npm", "@acme/api"), ("PyPI", "shop-backend")})
        direct = readers.direct_deps(self.src, [])
        self.assertEqual(direct[("npm", "astro")], ["package.json"])
        self.assertEqual(direct[("npm", "@nestjs/core")], ["apps/api/package.json"])
        self.assertEqual(direct[("PyPI", "fastapi")], ["backend/pyproject.toml"])
        self.assertEqual(direct[("PyPI", "crewai")], ["backend/pyproject.toml"])
        self.assertEqual(direct[("PyPI", "pytest")], ["backend/pyproject.toml"])
        self.assertEqual(direct[("PyPI", "requests-toolbelt")], ["backend/requirements.txt"])

    def test_ignore_paths_and_skip_dirs(self):
        write(self.src, {
            "targets/widget/Dockerfile": "FROM node:20\n",
            "node_modules/x/Dockerfile": "FROM node:18\n",
            "ops/Dockerfile": "FROM node:22\n",
        })
        images = self.by(readers.read_tree(self.src, ["targets/"]), "image")
        self.assertEqual([c.locations[0] for c in images], ["ops/Dockerfile"])


if __name__ == "__main__":
    unittest.main()


class DenoLockTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.src = Path(self._tmp.name).resolve()

    def tearDown(self):
        self._tmp.cleanup()

    def by(self, comps, kind):
        return [c for c in comps if c.kind == kind]

    def test_deno_lock_lists_npm_packages_served_by_cdns(self):
        lock = {"version": "4", "specifiers": {"npm:@types/node@*": "22.5.4"},
                "npm": {"@types/node@22.5.4": {"integrity": "sha512-x"}},
                "redirects": {"https://esm.sh/inngest@3": "https://esm.sh/inngest@3.52.7",
                              "https://esm.sh/ws@^8.18.0?target=denonext": "https://esm.sh/ws@8.18.2?target=denonext"},
                "remote": {"https://deno.land/std@0.224.0/assert/assert.ts": "h1",
                           "https://esm.sh/inngest@3.52.7": "h2",
                           "https://esm.sh/inngest@3.52.7/edge": "h3",
                           "https://esm.sh/@supabase/auth-js@2.69.1/denonext/auth-js.mjs": "h4",
                           "https://esm.sh/ws@8.18.2?target=denonext": "h5",
                           "https://esm.sh/ws@8.18.2/denonext/ws.mjs": "h6",
                           "https://esm.sh/v135/ms@2.1.3/denonext/ms.mjs": "h7",
                           "https://esm.sh/@types/ws@8.18.1/index.d.mts": "h8",
                           "https://unpkg.com/left-pad@1.3.0/index.js": "h9",
                           "https://esm.sh/gh/owner/repo@v1.0.0/mod.ts": "h10"}}
        write(self.src, {"supabase/functions/deno.lock": json.dumps(lock)})
        pkgs = self.by(readers.read_tree(self.src, []), "package")
        got = {(c.name, c.version): c for c in pkgs}
        self.assertEqual(sorted(got), [("@supabase/auth-js", "2.69.1"), ("@types/ws", "8.18.1"),
                                       ("inngest", "3.52.7"), ("left-pad", "1.3.0"), ("ms", "2.1.3"),
                                       ("ws", "8.18.2")])
        self.assertEqual(len(pkgs), 6)                       # one component per name@version
        self.assertNotIn(("@types/node", "22.5.4"), got)     # the npm section is Syft's
        inngest = got[("inngest", "3.52.7")]
        self.assertEqual((inngest.ecosystem, inngest.purl, inngest.locations, inngest.scope),
                         ("npm", "pkg:npm/inngest@3.52.7", ["supabase/functions/deno.lock"], "required"))
        self.assertEqual(got[("@supabase/auth-js", "2.69.1")].purl, "pkg:npm/%40supabase/auth-js@2.69.1")
        self.assertEqual({n: c.direct for (n, _v), c in got.items()},
                         {"inngest": True, "ws": False, "@supabase/auth-js": False, "ms": False,
                          "@types/ws": False, "left-pad": False})
        self.assertEqual(inngest.props.get("cdn"), "esm.sh")
        self.assertEqual(got[("left-pad", "1.3.0")].props.get("cdn"), "unpkg.com")

    def test_deno_lock_without_remote_section_adds_nothing(self):
        write(self.src, {"deno.lock": json.dumps({"version": "4", "npm": {"a@1.0.0": {"integrity": "x"}}})})
        self.assertEqual(self.by(readers.read_tree(self.src, []), "package"), [])


ROOT_POM = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>org.example</groupId><artifactId>parent</artifactId><version>1.0-SNAPSHOT</version>
  <packaging>pom</packaging>
  <properties><maven.compiler.release>17</maven.compiler.release><jackson.group>com.fasterxml.jackson.core</jackson.group></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.junit</groupId><artifactId>junit-bom</artifactId><version>5.10.0</version>
      <type>pom</type><scope>import</scope></dependency>
    <dependency><groupId>org.mockito</groupId><artifactId>mockito-core</artifactId><version>5.0.0</version>
      <scope>test</scope></dependency>
    <dependency><groupId>org.managed</groupId><artifactId>only-managed</artifactId><version>1.0</version></dependency>
  </dependencies></dependencyManagement>
  <build><plugins><plugin><artifactId>maven-surefire-plugin</artifactId>
    <dependencies><dependency><groupId>org.plugin</groupId><artifactId>plugin-dep</artifactId></dependency></dependencies>
  </plugin></plugins></build>
</project>"""

CHILD_POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent><groupId>org.example</groupId><artifactId>parent</artifactId><version>1.0-SNAPSHOT</version></parent>
  <artifactId>core</artifactId>
  <dependencies>
    <dependency><groupId>${jackson.group}</groupId><artifactId>jackson-databind</artifactId></dependency>
    <dependency><groupId>${project.groupId}</groupId><artifactId>api</artifactId><version>${project.version}</version></dependency>
    <dependency><groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter</artifactId><scope>test</scope></dependency>
    <dependency><groupId>org.mockito</groupId><artifactId>mockito-core</artifactId></dependency>
    <dependency><groupId>jakarta.servlet</groupId><artifactId>jakarta.servlet-api</artifactId><scope>provided</scope></dependency>
    <dependency><groupId>org.both</groupId><artifactId>both</artifactId><scope>test</scope></dependency>
  </dependencies>
  <profiles><profile><dependencies>
    <dependency><groupId>org.profile</groupId><artifactId>profiled</artifactId></dependency>
  </dependencies></profile></profiles>
</project>"""

API_POM = """<project><parent><groupId>org.example</groupId><artifactId>parent</artifactId></parent>
  <artifactId>api</artifactId>
  <dependencies><dependency><groupId>org.both</groupId><artifactId>both</artifactId></dependency></dependencies>
  <build><pluginManagement><plugins><plugin><groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-compiler-plugin</artifactId><configuration><release>21</release></configuration>
  </plugin></plugins></pluginManagement></build>
</project>"""

GO_MOD = """module github.com/example/app

go 1.22.3

toolchain go1.23.4

require github.com/single/dep v1.0.0
require github.com/single/indirect v1.0.0 // indirect

require (
\tgithub.com/a/direct v1.2.3
\tgolang.org/x/net v0.62.0 // some note
\tgolang.org/x/crypto v0.58.0 // indirect
\t"github.com/quoted/mod" v0.1.0
)

replace github.com/a/direct => ../local
"""


class ManifestEcosystemTests(unittest.TestCase):
    """Maven, Go and .NET manifests: own modules, direct dependencies, test-only scope, runtimes."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.src = Path(self._tmp.name).resolve()

    def tearDown(self):
        self._tmp.cleanup()

    def maven_tree(self):
        write(self.src, {"pom.xml": ROOT_POM, "core/pom.xml": CHILD_POM, "api/pom.xml": API_POM})

    def test_maven_ga_and_package_key(self):
        self.assertEqual(readers.maven_ga("pkg:maven/org.example/lib@1.0?type=jar"), "org.example:lib")
        self.assertEqual(readers.maven_ga("pkg:maven/org.example/lib"), "org.example:lib")
        self.assertIsNone(readers.maven_ga("pkg:npm/lib@1.0"))
        self.assertEqual(readers.package_key("Maven", "lib", "pkg:maven/org.example/lib@1.0"), "org.example:lib")
        self.assertEqual(readers.package_key("PyPI", "Foo_Bar", ""), "foo-bar")
        self.assertEqual(readers.package_key("Go", "golang.org/x/net", "pkg:golang/golang.org/x/net@v1"),
                         "golang.org/x/net")

    def test_vcpkg_manifest_names_are_self_packages(self):
        write(self.src, {"vcpkg.json": '{"name": "My-App", "version": "1.2.0", "dependencies": ["zlib"]}',
                         "libs/x/vcpkg.json": '{"name": "inner-lib"}', "bad/vcpkg.json": "{not json"})
        own = {k for k in readers.self_packages(self.src) if k[0] == "vcpkg"}
        self.assertEqual(own, {("vcpkg", "my-app"), ("vcpkg", "inner-lib")})
        self.assertEqual(readers.package_key("vcpkg", "My-App", "pkg:vcpkg/my-app@1.2.0"), "my-app")

    def test_maven_own_modules_are_self_packages(self):
        self.maven_tree()
        own = {k for k in readers.self_packages(self.src) if k[0] == "Maven"}
        self.assertEqual(own, {("Maven", "org.example:parent"), ("Maven", "org.example:core"),
                               ("Maven", "org.example:api")})

    def test_maven_direct_reads_dependencies_not_management_or_plugins(self):
        self.maven_tree()
        direct = {k[1]: v for k, v in readers.direct_deps(self.src, []).items() if k[0] == "Maven"}
        self.assertEqual(sorted(direct), [
            "com.fasterxml.jackson.core:jackson-databind",      # ${…} resolved from the parent's properties
            "jakarta.servlet:jakarta.servlet-api", "org.both:both", "org.example:api",
            "org.junit.jupiter:junit-jupiter", "org.mockito:mockito-core", "org.profile:profiled"])
        self.assertEqual(sorted(direct["org.both:both"]), ["api/pom.xml", "core/pom.xml"])
        self.assertNotIn("org.managed:only-managed", direct)
        self.assertNotIn("org.plugin:plugin-dep", direct)

    def test_maven_test_scope_with_dependency_management(self):
        self.maven_tree()
        self.assertEqual(readers.dev_only_deps(self.src, []), {
            ("Maven", "org.junit.jupiter:junit-jupiter"),      # explicit <scope>test</scope>
            ("Maven", "org.mockito:mockito-core"),             # scope from the parent's dependencyManagement
        })                                                    # provided, and test+compile ("both"), stay production

    def test_maven_ignore_patterns_apply(self):
        self.maven_tree()
        direct = readers.direct_deps(self.src, ["core"])
        self.assertNotIn(("Maven", "org.junit.jupiter:junit-jupiter"), direct)

    def test_broken_pom_is_reported_and_skipped(self):
        write(self.src, {"pom.xml": "<project><artifactId>x</artifactId>", "ok/pom.xml": API_POM})
        comps = readers.read_tree(self.src, [])
        errors = [c for c in comps if c.props.get("error")]
        self.assertEqual([c.name for c in errors], ["pom.xml"])
        self.assertIn("ParseError", errors[0].props["error"])
        self.assertIn(("Maven", "org.both:both"), readers.direct_deps(self.src, []))

    def test_java_language_level_runtime(self):
        self.maven_tree()
        rts = [c for c in readers.read_tree(self.src, []) if c.kind == "runtime" and c.ecosystem == "java"]
        got = {c.locations[0]: (c.version, c.props["detail"]) for c in rts}
        self.assertEqual(set(got), {"pom.xml", "api/pom.xml"})   # core sets none of its own
        self.assertEqual(got["pom.xml"][0], "17")
        self.assertIn("maven.compiler.release = 17", got["pom.xml"][1])
        self.assertIn("not the JDK it runs on", got["pom.xml"][1])
        self.assertEqual(got["api/pom.xml"][0], "21")
        self.assertIn("maven-compiler-plugin <release>", got["api/pom.xml"][1])

    def test_java_level_from_properties_and_legacy_notation(self):
        write(self.src, {"pom.xml": "<project><groupId>g</groupId><artifactId>a</artifactId><properties>"
                                    "<java.version>1.8</java.version><maven.compiler.source>${java.version}"
                                    "</maven.compiler.source></properties></project>"})
        rts = [c for c in readers.read_tree(self.src, []) if c.ecosystem == "java"]
        self.assertEqual([c.version for c in rts], ["8"])
        self.assertIn("maven.compiler.source = 1.8", rts[0].props["detail"])

    def test_go_mod_parse(self):
        mod = readers.parse_go_mod(GO_MOD)
        self.assertEqual((mod["module"], mod["go"], mod["toolchain"]),
                         ("github.com/example/app", "1.22.3", "go1.23.4"))
        self.assertEqual(mod["require"], [
            ("github.com/single/dep", False), ("github.com/single/indirect", True),
            ("github.com/a/direct", False), ("golang.org/x/net", False), ("golang.org/x/crypto", True),
            ("github.com/quoted/mod", False)])

    def test_go_direct_own_and_runtime(self):
        write(self.src, {"go.mod": GO_MOD, "tools/go.mod": "module github.com/example/tools\n\ngo 1.21\n"
                                                          "require github.com/tool/x v1.0.0\n"})
        direct = {k[1] for k in readers.direct_deps(self.src, []) if k[0] == "Go"}
        self.assertEqual(direct, {"github.com/single/dep", "github.com/a/direct", "golang.org/x/net",
                                  "github.com/quoted/mod", "github.com/tool/x"})
        own = {k for k in readers.self_packages(self.src) if k[0] == "Go"}
        self.assertEqual(own, {("Go", "github.com/example/app"), ("Go", "github.com/example/tools")})
        rts = {c.locations[0]: c for c in readers.read_tree(self.src, []) if c.ecosystem == "go"}
        self.assertEqual(rts["go.mod"].version, "1.23")              # toolchain wins over the go line
        self.assertIn("toolchain go1.23.4", rts["go.mod"].props["detail"])
        self.assertEqual(rts["tools/go.mod"].version, "1.21")
        self.assertIn("minimum Go", rts["tools/go.mod"].props["detail"])

    def test_dotnet_runtimes(self):
        """Unit-tested only: not yet checked against a real .NET repository."""
        write(self.src, {
            "global.json": '{"sdk": {"version": "8.0.100", "rollForward": "latestFeature"}}',
            "src/App/App.csproj": "<Project><PropertyGroup><TargetFramework>net9.0</TargetFramework>"
                                  "</PropertyGroup></Project>",
            "src/Lib/Lib.csproj": "<Project><PropertyGroup><TargetFrameworks>netstandard2.0;net48;net6.0;"
                                  "netcoreapp3.1</TargetFrameworks></PropertyGroup></Project>",
            "Directory.Build.props": "<Project><PropertyGroup><TargetFramework>net8.0-windows"
                                     "</TargetFramework></PropertyGroup></Project>"})
        rts = sorted((c.locations[0], c.version) for c in readers.read_tree(self.src, []) if c.ecosystem == "dotnet")
        self.assertEqual(rts, [("Directory.Build.props", "8"), ("global.json", "8"), ("src/App/App.csproj", "9"),
                               ("src/Lib/Lib.csproj", "3.1"), ("src/Lib/Lib.csproj", "6")])


class ManifestFilesTests(unittest.TestCase):
    """Which ecosystems' manifests a branch has: lets `incident` tell "absent" from "nothing was read"."""

    def test_manifest_files_by_osv_ecosystem(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp)
            for rel in ("package.json", "web/pnpm-lock.yaml", "api/poetry.lock", "api/requirements-dev.txt",
                        "svc/go.mod", "App/Package.resolved", "node_modules/x/package.json",
                        "lib/Cargo.lock", "legacy/old/pom.xml", "README.md"):
                (src / rel).parent.mkdir(parents=True, exist_ok=True)
                (src / rel).write_text("x")
            found = readers.manifest_files(src, ["legacy/"])
        self.assertEqual(found, {"npm": ["package.json", "web/pnpm-lock.yaml"],
                                 "PyPI": ["api/poetry.lock", "api/requirements-dev.txt"],
                                 "Go": ["svc/go.mod"], "SwiftURL": ["App/Package.resolved"],
                                 "crates.io": ["lib/Cargo.lock"]})

    def test_no_manifest_is_an_empty_dict(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "index.html").write_text("x")
            self.assertEqual(readers.manifest_files(Path(tmp), []), {})
