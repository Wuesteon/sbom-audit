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
