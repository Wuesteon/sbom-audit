"""Inventory Syft cannot produce: container images, runtime pins, unresolved manifests.

These readers only add inventory. Vulnerability matching is never done here.
"""
from __future__ import annotations

import json
import os
import re
import tomllib
from pathlib import Path

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
    """(ecosystem, name) of every package the tree itself defines."""
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
        except (ValueError, tomllib.TOMLDecodeError):
            continue
    return out


def direct_deps(src: Path, ignore: list[str]) -> dict[tuple[str, str], list[str]]:
    """(ecosystem, normalised name) -> manifest paths that declare it directly."""
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
        except (ValueError, tomllib.TOMLDecodeError):
            continue
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
        except (ValueError, tomllib.TOMLDecodeError, OSError) as exc:
            comps.append(Component(kind="package", ecosystem="", name=rel, version="", purl="",
                                   scope="unknown", locations=[rel], props={"error": f"{type(exc).__name__}: {exc}"}))
    return comps
