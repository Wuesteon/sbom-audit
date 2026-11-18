"""Inventory Syft cannot produce: container images, runtime pins, unresolved manifests.

These readers only add inventory. Vulnerability matching is never done here.
"""
from __future__ import annotations

import json
import os
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import unquote

from . import gradleread
from .model import Component
from .versions import min_version_from_range, norm_py, runtime_cycle

SKIP_DIRS = {"node_modules", "dist", "build", "Pods", "ios", "android", "coverage",
             "venv", ".venv", "__pycache__", "vendor", "target"}
JS_LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock",
                "bun.lockb", "bun.lock", "deno.lock"}
PY_LOCKFILES = {"uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock"}

# docker repository -> endoflife.date product slug
IMAGE_PRODUCT = {
    "node": "nodejs", "python": "python", "nginx": "nginx", "postgres": "postgresql",
    "redis": "redis", "alpine": "alpine", "debian": "debian", "ubuntu": "ubuntu",
    "caddy": "caddy", "traefik": "traefik", "mongo": "mongodb", "mysql": "mysql",
    "mariadb": "mariadb", "denoland/deno": "deno", "deno": "deno", "golang": "go",
    "php": "php", "ruby": "ruby", "rabbitmq": "rabbitmq", "elasticsearch": "elasticsearch",
    "haproxy": "haproxy", "memcached": "memcached", "eclipse-temurin": "eclipse-temurin",
}

COMPOSE_RE = re.compile(r"^(docker-)?compose[^/]*\.ya?ml$")
NPM_CDN_RE = re.compile(
    r"^https?://(?P<host>esm\.sh|unpkg\.com|cdn\.skypack\.dev|cdn\.jsdelivr\.net)/"
    r"(?:npm/)?(?:v\d+/|stable/)?\*?"
    r"(?P<name>(?:@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*)@(?P<version>\d+\.\d+\.\d+[0-9A-Za-z.+-]*)"
    r"(?P<subpath>/[^?#]*)?(?P<query>\?[^#]*)?$", re.I)
REQ_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(==|===|>=|~=|<=|!=|>|<)?\s*([^;,\s#]+)?")
PEP508 = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([^;]*)")


# --------------------------------------------------------------------------- tree walking

def _norm_ignore(ignore: list[str]) -> list[str]:
    out = []
    for entry in ignore:
        entry = entry.strip().lstrip("./")
        if entry and not entry.endswith("/"):
            entry += "/"
        if entry:
            out.append(entry)
    return out


def _inside_file(root: Path, ref: Path) -> Path | None:
    """`ref` resolved (symlinks followed) when it is a regular file inside `root` (resolved); else None. The
    scanned repo chooses `ref` (a Dockerfile `-r` argument, a symlink committed to its tree): nothing outside
    the export, and no FIFO or device, is ever read."""
    try:
        resolved = ref.resolve()
    except (OSError, RuntimeError):  # a symlink loop
        return None
    if not resolved.is_relative_to(root):
        return None
    return resolved if resolved.is_file() else None


def walk(src: Path, ignore: list[str]):
    """Yield (repo-relative path, Path) for every regular file, pruning build and ignored dirs. A symlink is
    yielded only when it resolves to a regular file inside the tree (os.walk does not descend into symlinked
    directories)."""
    prefixes = _norm_ignore(ignore)
    root = src.resolve()
    for dirpath, dirnames, filenames in os.walk(src):
        rel_dir = os.path.relpath(dirpath, src)
        rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
        keep = []
        for d in sorted(dirnames):
            rel = f"{rel_dir}/{d}/" if rel_dir else f"{d}/"
            if d in SKIP_DIRS or d.startswith(".") or any(rel.startswith(p) for p in prefixes):
                continue
            keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            rel = f"{rel_dir}/{name}" if rel_dir else name
            path = Path(dirpath) / name
            if _inside_file(root, path) is not None:
                yield rel, path


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _load_json_lenient(text: str) -> dict:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        text = re.sub(r"(?m)^\s*//.*$", "", text)
        text = re.sub(r",(\s*[}\]])", r"\1", text)
        data = json.loads(text)
    return data if isinstance(data, dict) else {}


def _has_lockfile(src: Path, folder: Path, names: set[str]) -> bool:
    folder = folder.resolve()
    src = src.resolve()
    while True:
        if any(_inside_file(src, folder / n) is not None for n in names):
            return True
        if folder == src or src not in folder.parents:
            return False
        folder = folder.parent


# --------------------------------------------------------------------------- images

def parse_image(image: str) -> dict:
    """'node:20.11-alpine' -> repo node, tag 20.11-alpine, product nodejs, cycle 20, pin minor."""
    ref, _, digest = image.partition("@")
    head, _, last = ref.rpartition("/")
    name_part, _, tag = last.partition(":")
    name = f"{head}/{name_part}" if head else name_part
    short = name
    first = short.split("/", 1)[0]
    if "/" in short and ("." in first or ":" in first or first == "localhost"):
        short = short.split("/", 1)[1]
    if short.startswith("library/"):
        short = short[len("library/"):]
    product = IMAGE_PRODUCT.get(short.lower())
    if digest:
        level = "digest"
    elif re.search(r"\d{8}", tag):
        level = "dated"
    else:
        m = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", tag)
        if not m:
            level = "none"
        elif m.group(3):
            level = "patch"
        elif m.group(2):
            level = "minor"
        else:
            level = "major"
    numeric = re.match(r"^v?(\d+(?:\.\d+)*)", tag)
    cycle = runtime_cycle(product, numeric.group(1)) if product and numeric else ""
    return {
        "image": image, "name": name, "repo": short, "tag": tag,
        "digest": bool(digest), "dated": level == "dated", "pin_level": level,
        "floating": level == "none", "product": product, "cycle": cycle,
    }


def _owner(remote: str | None) -> str | None:
    if not remote:
        return None
    m = re.search(r"github\.com[:/]([^/]+)/", remote)
    return m.group(1).lower() if m else None


def image_component(image: str, source: str, own: bool = False) -> Component:
    info = parse_image(image)
    purl = f"pkg:docker/{info['name']}" + (f"@{info['tag']}" if info["tag"] else "")
    return Component(
        kind="image", ecosystem="docker", name=info["name"], version=info["tag"], purl=purl,
        scope="required", locations=[source], direct=True,
        props={"image": image, "source": source, "floating": info["floating"], "own": own,
               "digest": info["digest"], "pin_level": info["pin_level"]},
    )


def runtime_from_image(c: Component) -> Component | None:
    info = parse_image(c.props.get("image", f"{c.name}:{c.version}" if c.version else c.name))
    product = info["product"]
    if not product:
        return None
    return runtime_component(product, info["cycle"], c.locations[0] if c.locations else "",
                             detail=f"image {info['image']}", image=info["image"])


def runtime_component(product: str, cycle: str, source: str, detail: str, **extra) -> Component:
    purl = f"pkg:generic/{product}" + (f"@{cycle}" if cycle else "")
    props = {"source": source, "detail": detail}
    props.update(extra)
    return Component(kind="runtime", ecosystem=product, name=product, version=cycle, purl=purl,
                     scope="required", locations=[source], direct=True, props=props)


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        return s[1:-1]
    return s


def _subst_vars(value: str, args: dict) -> str:
    def braced(m):
        name, op, default = m.group(1), m.group(2), m.group(3)
        if name in args:
            return args[name]
        return default if (op and default is not None) else m.group(0)
    value = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(:?[-+])?([^}]*)?\}", braced, value)
    return re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)", lambda m: args.get(m.group(1), m.group(0)), value)


def parse_dockerfile(text: str) -> tuple[list[str], list[str]]:
    """Returns (images in FROM order, requirements files installed by RUN lines)."""
    args: dict[str, str] = {}
    images: list[str] = []
    stages: set[str] = set()
    requirements: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?$", line, re.I)
        if m:
            args[m.group(1)] = _unquote(m.group(2) or "")
            continue
        m = re.match(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", line, re.I)
        if m:
            image = _subst_vars(m.group(1), args)
            if m.group(2):
                stages.add(m.group(2).lower())
            if image.lower() in stages:
                continue
            if image not in images:
                images.append(image)
            continue
        if re.match(r"^RUN\b", line, re.I):
            for ref in re.findall(r"(?:-r|--requirement)[\s=]+(\S+)", line):
                requirements.append(ref.strip("'\""))
            for ref in re.findall(r"(\S*requirements\S*\.txt)", line):
                if ref not in requirements:
                    requirements.append(ref.strip("'\""))
    return images, requirements


def parse_compose(text: str) -> list[tuple[str, bool]]:
    """Returns [(image, service has a build: key)] for every service with an image."""
    services: dict[str, dict] = {}
    in_services = False
    services_indent = None
    current = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()
        if re.match(r"^services:\s*$", line):
            in_services, services_indent, current = True, indent, None
            continue
        if not in_services:
            continue
        if services_indent is not None and indent <= services_indent:
            in_services = False
            continue
        m = re.match(r"^([A-Za-z0-9_.-]+):\s*(.*)$", line)
        if not m:
            continue
        key, value = m.group(1), m.group(2).split("#", 1)[0].strip()
        if current is None or indent <= services[current]["indent"]:
            current = key
            services[key] = {"indent": indent, "image": None, "build": False}
            continue
        if indent == services[current]["indent"] + 2 or key in ("image", "build"):
            if key == "image" and value:
                services[current]["image"] = _subst_vars(_unquote(value), {})
            elif key == "build":
                services[current]["build"] = True
    return [(s["image"], s["build"]) for s in services.values() if s["image"]]


def requirements_unpinned(text: str) -> bool:
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = REQ_LINE.match(line)
        if m and m.group(3) not in ("==", "===") and "@" not in line:
            return True
    return False


# --------------------------------------------------------------------------- manifests

def _package_json_deps(d: dict) -> list[tuple[str, str, str]]:
    """[(name, requirement, scope)] from a parsed package.json."""
    out = []
    for group, scope in (("dependencies", "required"), ("optionalDependencies", "required"),
                         ("devDependencies", "optional")):
        deps = d.get(group)
        if isinstance(deps, dict):
            out.extend((name, str(req), scope) for name, req in deps.items())
    return out


def _pep508_name(item: str) -> str | None:
    m = PEP508.match(item)
    return norm_py(m.group(1)) if m else None


def _pyproject_deps(d: dict) -> list[tuple[str, str, str]]:
    out = []
    project = d.get("project") or {}
    for item in project.get("dependencies") or []:
        if isinstance(item, str) and (n := _pep508_name(item)):
            out.append((n, item, "required"))
    for items in (project.get("optional-dependencies") or {}).values():
        for item in items or []:
            if isinstance(item, str) and (n := _pep508_name(item)):
                out.append((n, item, "required"))
    for items in (d.get("dependency-groups") or {}).values():
        for item in items or []:
            if isinstance(item, str) and (n := _pep508_name(item)):
                out.append((n, item, "optional"))
    tool = d.get("tool") or {}
    for item in (tool.get("uv") or {}).get("dev-dependencies") or []:
        if isinstance(item, str) and (n := _pep508_name(item)):
            out.append((n, item, "optional"))
    poetry = tool.get("poetry") or {}
    for name, spec in (poetry.get("dependencies") or {}).items():
        if name.lower() != "python":
            out.append((norm_py(name), spec if isinstance(spec, str) else json.dumps(spec), "required"))
    for group in (poetry.get("group") or {}).values():
        for name, spec in (group.get("dependencies") or {}).items():
            out.append((norm_py(name), spec if isinstance(spec, str) else json.dumps(spec), "optional"))
    return out


def _requirements_deps(text: str) -> list[tuple[str, str, str]]:
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = REQ_LINE.match(line)
        if m:
            out.append((norm_py(m.group(1)), line, "required"))
    return out


def _is_requirements(name: str) -> bool:
    return name.endswith(".txt") and "requirements" in name.lower()


def _pyproject_name(d: dict) -> str | None:
    name = (d.get("project") or {}).get("name") or ((d.get("tool") or {}).get("poetry") or {}).get("name")
    return norm_py(name) if name else None


def self_packages(src: Path) -> set[tuple[str, str]]:
    """(ecosystem, key) of every package the tree itself defines: npm and PyPI names, Go module paths and
    Maven `groupId:artifactId` (the reactor modules); the key is `package_key`'s."""
    out: set[tuple[str, str]] = set()
    for rel, path in walk(src, []):
        try:
            if path.name == "package.json":
                name = _load_json_lenient(_read(path)).get("name")
                if isinstance(name, str) and name:
                    out.add(("npm", name))
            elif path.name == "pyproject.toml":
                name = _pyproject_name(tomllib.loads(_read(path)))
                if name:
                    out.add(("PyPI", name))
            elif path.name == "go.mod":
                module = parse_go_mod(_read(path))["module"]
                if module:
                    out.add(("Go", module))
        except (ValueError, tomllib.TOMLDecodeError):
            continue
    poms = maven_poms(src, [])
    props = _maven_global_props(poms)
    for pom in poms:
        ga = _maven_ga(pom.group or pom.parent_group, pom.artifact, pom, props)   # no groupId: the parent's
        if ga:
            out.add(("Maven", ga))
    return out


def direct_deps(src: Path, ignore: list[str]) -> dict[tuple[str, str], list[str]]:
    """(ecosystem, key) -> manifest paths that declare it directly. The key is `package_key`'s: the
    normalised name, a Go module path, a Maven `groupId:artifactId`. Ecosystems outside DIRECT_ECOSYSTEMS
    have no reader here, so their packages are neither direct nor transitive but unknown."""
    out: dict[tuple[str, str], list[str]] = {}

    def add(eco: str, name: str, rel: str) -> None:
        out.setdefault((eco, name), [])
        if rel not in out[(eco, name)]:
            out[(eco, name)].append(rel)

    for rel, path in walk(src, ignore):
        try:
            if path.name == "package.json":
                for name, _, _ in _package_json_deps(_load_json_lenient(_read(path))):
                    add("npm", name, rel)
            elif path.name == "pyproject.toml":
                for name, _, _ in _pyproject_deps(tomllib.loads(_read(path))):
                    add("PyPI", name, rel)
            elif _is_requirements(path.name):
                for name, _, _ in _requirements_deps(_read(path)):
                    add("PyPI", name, rel)
            elif path.name == "go.mod":
                for module, indirect in parse_go_mod(_read(path))["require"]:
                    if not indirect:
                        add("Go", module, rel)
        except (ValueError, tomllib.TOMLDecodeError):
            continue
    poms = maven_poms(src, ignore)
    props = _maven_global_props(poms)
    for pom in poms:
        for group, artifact, _ in pom.deps:
            ga = _maven_ga(group, artifact, pom, props)
            if ga:
                add("Maven", ga, pom.rel)
    for ga, rels in gradleread.direct(gradleread.analyse(src, ignore)).items():   # build.gradle(.kts)
        for rel in rels:
            add("Maven", ga, rel)
    return out


def dev_only_deps(src: Path, ignore: list[str]) -> set[tuple[str, str]]:
    """(ecosystem, key) of the packages every declaration in the tree marks as test-only. Maven and Gradle: a
    dependency whose every `<dependencies>` entry has `<scope>test</scope>`, its own or the one a
    `<dependencyManagement>` entry of any pom in the tree sets. `provided`, `runtime` and `system` count as
    production (provided code is on the production classpath, only supplied by the container or JDK). In
    Gradle, every declaration and lock file configuration is a test, debug or build-tool one
    (`gradleread.config_is_dev`); a package declared in both needs both to agree."""
    poms = maven_poms(src, ignore)
    props = _maven_global_props(poms)
    managed: dict[str, set[str]] = {}
    for pom in poms:
        for group, artifact, scope in pom.managed:
            ga = _maven_ga(group, artifact, pom, props)
            if ga and scope:
                managed.setdefault(ga, set()).add(_resolve(scope, pom, props).strip().lower())
    scopes: dict[str, set[str]] = {}
    for pom in poms:
        for group, artifact, scope in pom.deps:
            ga = _maven_ga(group, artifact, pom, props)
            if not ga:
                continue
            if scope:
                found = {_resolve(scope, pom, props).strip().lower()}
            else:
                found = managed.get(ga) or {"compile"}
            scopes.setdefault(ga, set()).update(found)
    dev = {ga: s == {"test"} for ga, s in scopes.items()}
    for ga, found in gradleread.scopes(gradleread.analyse(src, ignore)).items():   # Gradle configurations
        dev[ga] = dev.get(ga, True) and found == {True}
    return {("Maven", ga) for ga, is_dev in dev.items() if is_dev}


def gradle_unknown_direct(src: Path, ignore: list[str]) -> set[str]:
    """Gradle lock files whose packages cannot be told direct or transitive (see gradleread)."""
    return gradleread.unknown_direct_locations(gradleread.analyse(src, ignore))


# --------------------------------------------------------------------------- Maven, Go, .NET

# Ecosystems whose manifests `direct_deps` reads; for any other, a package's `direct` stays None (unknown).
DIRECT_ECOSYSTEMS = frozenset({"npm", "PyPI", "Go", "Maven"})
JAVA_LEVEL_KEYS = ("maven.compiler.release", "maven.compiler.target", "maven.compiler.source", "java.version")
DOTNET_PROJECT_SUFFIXES = (".csproj", ".fsproj", ".vbproj")
PROP_REF = re.compile(r"\$\{([^}]+)\}")


def maven_ga(purl: str) -> str | None:
    """'pkg:maven/org.example/lib@1.0?type=jar' -> 'org.example:lib'."""
    if not purl.startswith("pkg:maven/"):
        return None
    body = purl[len("pkg:maven/"):].split("?", 1)[0].split("#", 1)[0].split("@", 1)[0]
    group, _, artifact = body.rpartition("/")
    if not group or not artifact:
        return None
    return f"{unquote(group)}:{unquote(artifact)}"


def package_key(ecosystem: str, name: str, purl: str = "") -> str:
    """The name `direct_deps`, `self_packages` and `dev_only_deps` key a package by."""
    if ecosystem == "PyPI":
        return norm_py(name)
    if ecosystem == "Maven":
        return maven_ga(purl) or name
    return name


def parse_go_mod(text: str) -> dict:
    """{'module', 'go', 'toolchain', 'require': [(module path, indirect)]} from a go.mod; single-line and
    block `require`. A module marked `// indirect` is needed only by a dependency (or by a dependency's
    tests); go.mod has no marker for modules only the project's own tests need."""
    out: dict = {"module": "", "go": "", "toolchain": "", "require": []}
    in_require = False
    for raw in text.splitlines():
        code, _, comment = raw.partition("//")
        line = code.strip()
        indirect = re.match(r"^\s*indirect\b", comment) is not None
        if in_require:
            if line.startswith(")"):
                in_require = False
            elif line:
                out["require"].append((_unquote(line.split()[0]), indirect))
            continue
        m = re.match(r"^(module|go|toolchain|require)\s*(.*)$", line)
        if not m:
            continue
        key, rest = m.group(1), m.group(2).strip()
        if key == "require":
            if rest.startswith("("):
                in_require = True
            elif rest:
                out["require"].append((_unquote(rest.split()[0]), indirect))
        elif rest:
            out[key] = _unquote(rest.split()[0])
    return out


class Pom:
    """What the readers need from one pom.xml."""

    def __init__(self, rel: str):
        self.rel = rel
        self.group = self.artifact = self.version = ""
        self.parent_group = self.parent_version = ""
        self.props: dict[str, str] = {}
        self.deps: list[tuple[str, str, str]] = []       # <dependencies> (incl. profiles): (group, artifact, scope)
        self.managed: list[tuple[str, str, str]] = []    # <dependencyManagement>
        self.java: list[tuple[str, str]] = []            # (where, raw value), most specific first


def _local(tag) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _child(el, name: str):
    for c in el:
        if _local(c.tag) == name:
            return c
    return None


def _children(el, name: str) -> list:
    return [c for c in el if _local(c.tag) == name] if el is not None else []


def _text(el, name: str) -> str:
    c = _child(el, name) if el is not None else None
    return (c.text or "").strip() if c is not None else ""


def _dep_list(deps_el) -> list[tuple[str, str, str]]:
    return [(_text(d, "groupId"), _text(d, "artifactId"), _text(d, "scope"))
            for d in _children(deps_el, "dependency") if _text(d, "artifactId")]


def parse_pom(text: str, rel: str = "pom.xml") -> Pom:
    """Coordinates, properties, declared and managed dependencies and the Java language level of a pom.
    Plugin dependencies are not read: they are build tools, not dependencies of the code."""
    root = ET.fromstring(text)               # expat: no external entities, no DTD fetches
    pom = Pom(rel)
    pom.group, pom.artifact, pom.version = _text(root, "groupId"), _text(root, "artifactId"), _text(root, "version")
    parent = _child(root, "parent")
    if parent is not None:
        pom.parent_group, pom.parent_version = _text(parent, "groupId"), _text(parent, "version")
    props = _child(root, "properties")
    for p in props if props is not None else []:
        if _local(p.tag):
            pom.props[_local(p.tag)] = (p.text or "").strip()
    pom.deps = _dep_list(_child(root, "dependencies"))
    for profile in _children(_child(root, "profiles"), "profile"):
        pom.deps += _dep_list(_child(profile, "dependencies"))
    dm = _child(root, "dependencyManagement")
    if dm is not None:
        pom.managed = [d for d in _dep_list(_child(dm, "dependencies")) if d[2] != "import"]
    build = _child(root, "build")
    plugins = _children(_child(build, "plugins"), "plugin") if build is not None else []
    if build is not None and _child(build, "pluginManagement") is not None:
        plugins += _children(_child(_child(build, "pluginManagement"), "plugins"), "plugin")
    compiler = [_child(p, "configuration") for p in plugins if _text(p, "artifactId") == "maven-compiler-plugin"]
    for key in ("release", "target", "source"):
        for conf in compiler:
            if conf is not None and _text(conf, key):
                pom.java.append((f"maven-compiler-plugin <{key}>", _text(conf, key)))
        prop = f"maven.compiler.{key}"
        if pom.props.get(prop):
            pom.java.append((prop, pom.props[prop]))
    if pom.props.get("java.version"):
        pom.java.append(("java.version", pom.props["java.version"]))
    return pom


def maven_poms(src: Path, ignore: list[str]) -> list[Pom]:
    """Every pom.xml in the tree that parses; a broken one is skipped (read_tree reports it)."""
    out = []
    for rel, path in walk(src, ignore):
        if path.name == "pom.xml":
            try:
                out.append(parse_pom(_read(path), rel))
            except (ET.ParseError, ValueError):
                continue
    return out


def _maven_global_props(poms: list[Pom]) -> dict[str, str]:
    """Properties of every pom in the tree: a fallback for `${…}` a child inherits from a parent in the repo."""
    out: dict[str, str] = {}
    for pom in sorted(poms, key=lambda p: (p.rel.count("/"), p.rel), reverse=True):   # shallower poms win
        out.update(pom.props)
    return out


def _resolve(value: str, pom: Pom, global_props: dict[str, str]) -> str:
    """`${…}` references replaced from the pom's own properties and coordinates, then the tree's."""
    own = {"project.groupId": pom.group or pom.parent_group, "pom.groupId": pom.group or pom.parent_group,
           "project.artifactId": pom.artifact, "project.version": pom.version or pom.parent_version,
           "project.parent.groupId": pom.parent_group, "project.parent.version": pom.parent_version}
    for _ in range(5):
        new = PROP_REF.sub(lambda m: pom.props.get(m.group(1)) or own.get(m.group(1))
                           or global_props.get(m.group(1)) or m.group(0), value)
        if new == value:
            break
        value = new
    return value


def _maven_ga(group: str, artifact: str, pom: Pom, global_props: dict[str, str]) -> str | None:
    """'groupId:artifactId' with `${…}` resolved; None when either part stays unknown."""
    group, artifact = _resolve(group, pom, global_props), _resolve(artifact, pom, global_props)
    if not group or not artifact or "${" in group + artifact:
        return None
    return f"{group}:{artifact}"


def java_runtimes(src: Path, ignore: list[str]) -> list[Component]:
    """One `java` runtime per pom that sets a Java language level (compiler release, target or source, or
    the `java.version` property). It is the level the code is compiled for, not the JDK that runs it."""
    poms = maven_poms(src, ignore)
    props = _maven_global_props(poms)
    out = []
    for pom in poms:
        for where, raw in pom.java:
            value = _resolve(raw, pom, props)
            if re.fullmatch(r"\d+(\.\d+)?", value):
                out.append(runtime_component(
                    "java", runtime_cycle("java", value), pom.rel,
                    detail=f"{where} = {value} (Java language level the code is compiled for, not the JDK "
                           "it runs on)"))
                break
    return out


def go_runtime(text: str, rel: str) -> Component | None:
    """The Go version a go.mod asks for: its `toolchain` line, else its `go` line. Both are minimums for the
    build; the binary carries the runtime of whichever Go toolchain builds it."""
    mod = parse_go_mod(text)
    toolchain = mod["toolchain"].removeprefix("go")
    if toolchain and re.match(r"\d+\.\d+", toolchain):
        version, detail = toolchain, f"toolchain {mod['toolchain']}"
    elif mod["go"] and re.match(r"\d+\.\d+", mod["go"]):
        version, detail = mod["go"], f"go {mod['go']}"
    else:
        return None
    return runtime_component("go", runtime_cycle("go", version), rel,
                             detail=f"go.mod {detail} (minimum Go for the build, not necessarily the Go that "
                                    "builds the release)")


def dotnet_runtimes(text: str, rel: str) -> list[Component]:
    """.NET from global.json (`sdk.version`: the SDK that builds it) or from a project file's
    `<TargetFramework(s)>` (`net8.0`, `netcoreapp3.1`: the runtime the code targets). .NET Framework
    (`net48`) and .NET Standard targets are not runtimes endoflife.date tracks as `dotnet`; they are skipped."""
    out = []
    if rel.rsplit("/", 1)[-1] == "global.json":
        sdk = (_load_json_lenient(text).get("sdk") or {})
        version = sdk.get("version") if isinstance(sdk, dict) else None
        if isinstance(version, str) and re.match(r"\d+\.\d+", version):
            out.append(runtime_component("dotnet", runtime_cycle("dotnet", version), rel,
                                         detail=f"global.json sdk.version = {version} (the SDK that builds it)"))
        return out
    seen = set()
    for value in re.findall(r"<TargetFrameworks?>([^<]+)</TargetFrameworks?>", text):
        for tf in value.split(";"):
            tf = tf.strip()
            m = re.match(r"^net(?:coreapp)?(\d+)\.(\d+)", tf)
            if not m or (tf.startswith("net") and not tf.startswith("netcoreapp") and int(m.group(1)) < 5):
                continue
            cycle = runtime_cycle("dotnet", f"{m.group(1)}.{m.group(2)}")
            if cycle not in seen:
                seen.add(cycle)
                out.append(runtime_component("dotnet", cycle, rel,
                                             detail=f"TargetFramework {tf} (the .NET the code targets)"))
    return out


# --------------------------------------------------------------------------- main entry

def deno_remote_packages(lock: dict, rel: str) -> list[Component]:
    """npm packages a deno.lock pulls through a CDN (esm.sh, unpkg, jsDelivr, Skypack).

    Syft catalogues the lockfile's `npm`/`jsr` sections; the `remote`/`redirects` URLs are ours.
    A URL is a direct import when it has no query and at most one bare path segment
    (`inngest@3.52.7`, `inngest@3.52.7/edge`); esm.sh's own dependency rewrites carry
    `?target=` or a build directory (`/denonext/ws.mjs`). deno.land modules have no OSV
    ecosystem and are not listed.
    """
    urls = list((lock.get("remote") or {}).keys()) + list((lock.get("redirects") or {}).values())
    found: dict[tuple[str, str], Component] = {}
    for url in urls:
        m = NPM_CDN_RE.match(str(url))
        if not m:
            continue
        name, version, sub = m["name"], m["version"], m["subpath"] or ""
        direct = not m["query"] and (sub in ("", "/") or re.fullmatch(r"/[\w-]+", sub) is not None)
        c = found.get((name, version))
        if c is None:
            found[(name, version)] = Component(
                kind="package", ecosystem="npm", name=name, version=version,
                purl=f"pkg:npm/{name.replace('@', '%40', 1)}@{version}", scope="required",
                locations=[rel], direct=direct, props={"cdn": m["host"].lower()})
        elif direct:
            c.direct = True
    return list(found.values())


def read_tree(src: Path, ignore: list[str], remote: str | None = None) -> list[Component]:
    comps: list[Component] = []
    has_pom = False
    owner = _owner(remote)
    root = src.resolve()

    def own(image: str, has_build: bool = False) -> bool:
        return has_build or bool(owner and owner in image.lower())

    for rel, path in walk(src, ignore):
        base = path.name
        try:
            if base == "Dockerfile" or base.startswith("Dockerfile.") or base.lower().endswith((".dockerfile",)):
                images, reqs = parse_dockerfile(_read(path))
                unpinned = []
                for ref in reqs:
                    candidate = _inside_file(root, path.parent / ref) or _inside_file(root, src / ref)
                    if candidate is not None and requirements_unpinned(_read(candidate)):
                        unpinned.append(str(candidate.relative_to(root)).replace(os.sep, "/"))
                for image in images:
                    c = image_component(image, rel, own=own(image))
                    if unpinned:
                        c.props["unpinned_requirements"] = unpinned
                    comps.append(c)
            elif COMPOSE_RE.match(base):
                for image, has_build in parse_compose(_read(path)):
                    comps.append(image_component(image, rel, own=own(image, has_build)))
            elif base == "package.json":
                d = _load_json_lenient(_read(path))
                node = (d.get("engines") or {}).get("node") if isinstance(d.get("engines"), dict) else None
                if node:
                    comps.append(runtime_component("nodejs", runtime_cycle("nodejs", min_version_from_range(str(node))),
                                                   rel, detail=f"engines.node {node}"))
                if not _has_lockfile(src, path.parent, JS_LOCKFILES):
                    for name, req, scope in _package_json_deps(d):
                        comps.append(Component(kind="package", ecosystem="npm", name=name, version="",
                                               purl=f"pkg:npm/{name}", scope=scope, locations=[rel], direct=True,
                                               props={"requirement": req, "unresolved": True}))
            elif base in (".nvmrc", ".node-version"):
                value = (_read(path).strip().splitlines() or [""])[0].strip().lstrip("v")
                if value:
                    comps.append(runtime_component("nodejs", runtime_cycle("nodejs", value), rel,
                                                   detail=f"{base} = {value}"))
            elif base == ".python-version":
                value = (_read(path).strip().splitlines() or [""])[0].strip()
                if value:
                    comps.append(runtime_component("python", runtime_cycle("python", value), rel,
                                                   detail=f".python-version = {value}"))
            elif base == "pyproject.toml":
                d = tomllib.loads(_read(path))
                project = d.get("project") or {}
                poetry = (d.get("tool") or {}).get("poetry") or {}
                rp = project.get("requires-python") or (poetry.get("dependencies") or {}).get("python")
                if isinstance(rp, str) and rp:
                    comps.append(runtime_component("python", runtime_cycle("python", min_version_from_range(rp)),
                                                   rel, detail=f"requires-python {rp}"))
                if not _has_lockfile(src, path.parent, PY_LOCKFILES):
                    for name, req, scope in _pyproject_deps(d):
                        comps.append(Component(kind="package", ecosystem="PyPI", name=name, version="",
                                               purl=f"pkg:pypi/{name}", scope=scope, locations=[rel], direct=True,
                                               props={"requirement": req, "unresolved": True}))
            elif base == "pom.xml":
                parse_pom(_read(path), rel)            # only to report a broken pom; java_runtimes reads them all
                has_pom = True
            elif base == "go.mod":
                runtime = go_runtime(_read(path), rel)
                if runtime is not None:
                    comps.append(runtime)
            elif base == "global.json" or base == "Directory.Build.props" or base.endswith(DOTNET_PROJECT_SUFFIXES):
                comps.extend(dotnet_runtimes(_read(path), rel))
            elif base == "deno.lock":
                comps.extend(deno_remote_packages(_load_json_lenient(_read(path)), rel))
            elif base in ("deno.json", "deno.jsonc"):
                comps.append(runtime_component("deno", "", rel, detail=f"{base} present (version not pinned)"))
            elif base == "config.toml" and path.parent.name == "supabase":
                d = tomllib.loads(_read(path))
                pg = (d.get("db") or {}).get("major_version")
                if pg:
                    comps.append(runtime_component("postgresql", str(pg), rel,
                                                   detail=f"supabase db.major_version = {pg}"))
                deno = (d.get("edge_runtime") or {}).get("deno_version")
                if deno:
                    comps.append(runtime_component("deno", str(deno), rel,
                                                   detail=f"supabase edge_runtime.deno_version = {deno}"))
        except (ValueError, tomllib.TOMLDecodeError, OSError, ET.ParseError) as exc:
            comps.append(Component(kind="package", ecosystem="", name=rel, version="", purl="",
                                   scope="unknown", locations=[rel], props={"error": f"{type(exc).__name__}: {exc}"}))
    gradle = gradleread.analyse(src, ignore)            # declarations Syft does not read; never raises
    if gradle.modules or gradle.locks:
        dev = {key for eco, key in dev_only_deps(src, ignore) if eco == "Maven"}
        comps.extend(gradleread.components(gradle, dev))
    if has_pom:                                        # `${…}` in a child pom may resolve from a parent's properties
        comps.extend(java_runtimes(src, ignore))
    return comps
