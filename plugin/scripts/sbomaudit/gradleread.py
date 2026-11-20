"""Gradle builds read statically: direct dependencies, their scope and the versions the repository states.

Syft (verified with 1.56.0) catalogues only files named exactly `gradle.lockfile`: every `group:artifact:version`
in it, with no configuration, so no scope and no direct/transitive split. It reads nothing from `build.gradle`,
`build.gradle.kts`, `settings.gradle(.kts)`, `gradle/libs.versions.toml`, `gradle.properties`,
`gradle/verification-metadata.xml`, `buildscript-gradle.lockfile` or the legacy per-configuration lock state
`gradle/dependency-locks/<configuration>.lockfile`. This module adds, without running Gradle:

- the declarations in `dependencies { }` blocks of every build file (string, map and `kotlin("x")` notation,
  `platform()`/`enforcedPlatform()`, version-catalog accessors `libs.x` and `libs.bundles.x`, local variables
  and simple string constants), keyed by `group:artifact` for `readers.direct_deps`;
- per declaration and per lockfile configuration whether it is test or build tooling only, for
  `readers.dev_only_deps`;
- package components for declared dependencies of a module without lock state (version as written, or an
  unresolved package when the version cannot be determined statically) and for legacy lock files.

Build files are programs; this is a reader of common notations, not an evaluator. What it cannot determine it
reports as unresolved (version) or unknown (direct), never as a guess. The files come from scanned
repositories: only regular files inside the exported tree are read (no symlinks), each at most MAX_FILE_BYTES,
at most MAX_BUILD_FILES build files, and a path from `settings.gradle` that leaves the tree is ignored.
"""
from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .model import Component

MAX_FILE_BYTES = 1 << 20
MAX_BUILD_FILES = 2000
MAX_DECLARATIONS = 50_000
MAX_NAME = 120
SKIP_DIRS = {"build", "node_modules", "Pods", "vendor", "target", "out", "__pycache__", "venv", ".venv"}
BUILD_FILES = ("build.gradle", "build.gradle.kts")
SETTINGS_FILES = ("settings.gradle", "settings.gradle.kts")
LOCKFILE = "gradle.lockfile"

# configuration name -> test or build tooling only (not in what ships). Anything unknown counts as production.
TOOL_CONFIGS = {
    "annotationprocessor", "kapt", "ksp", "developmentonly", "testanddevelopmentonly", "checkstyle", "pmd",
    "spotbugs", "spotbugsplugins", "detekt", "detektplugins", "ktlint", "lintchecks", "jacocoagent",
    "jacocoant", "errorprone", "codenarc", "classpath", "kotlincompilerclasspath",
    "kotlincompilerpluginclasspath", "kotlinklibcommonizerclasspath", "kotlinnativecompilerpluginclasspath",
    "kotlinbuildtoolsapiclasspath", "kotlinscriptdef", "kotlinscriptdefextensions", "lintclasspath",
}
KEYWORDS = {"if", "else", "for", "while", "when", "return", "val", "var", "def", "fun", "import", "exclude",
            "because", "version", "force", "transitive", "attributes", "capabilities", "println", "logger",
            "throw", "try", "catch", "apply", "plugins", "repositories", "constraints", "components", "modules",
            "dependencies", "configurations", "project", "projects", "files", "fileTree", "add", "foreach"}
DYNAMIC_HINT = re.compile(r"[+\[\](),]|^latest\.", re.I)
CONCRETE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._\-]*$")
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


# --------------------------------------------------------------------------- safe file access

def _inside(root: Path, path: Path) -> Path | None:
    """`path` when it is a regular, non-symlinked file inside `root` (resolved), else None."""
    try:
        if path.is_symlink() or not path.is_file():
            return None
        resolved = path.resolve()
    except (OSError, RuntimeError):
        return None
    return resolved if resolved.is_relative_to(root) else None


def _read(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _rel(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root).as_posix()


def _walk(root: Path, ignore: list[str]):
    prefixes = [p.strip().lstrip("./").rstrip("/") + "/" for p in ignore if p.strip().strip("./")]
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = [d for d in sorted(dirnames)
                       if d not in SKIP_DIRS and not d.startswith(".")
                       and not any(f"{rel_dir}/{d}/".lstrip("/").startswith(p) for p in prefixes)]
        for name in sorted(filenames):
            yield Path(dirpath) / name


# --------------------------------------------------------------------------- lexing

def _clean(text: str) -> tuple[str, str]:
    """(text with comments blanked, the same with string contents blanked as well). Offsets are kept, so a match
    in the masked text indexes the same characters in the clean one. Groovy/Kotlin strings: '…', "…", '''…''',
    \"\"\"…\"\"\"."""
    clean, masked = list(text), list(text)
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n and text[i + 1] in "/*":
            end = text.find("\n", i) if text[i + 1] == "/" else text.find("*/", i + 2)
            end = n if end < 0 else (end if text[i + 1] == "/" else end + 2)
            for j in range(i, end):
                if text[j] != "\n":
                    clean[j] = masked[j] = " "
            i = end
            continue
        if ch in "'\"":
            quote = ch * 3 if text.startswith(ch * 3, i) else ch
            j = i + len(quote)
            while j < n and not text.startswith(quote, j):
                if text[j] == "\\":
                    j += 1
                elif len(quote) == 1 and text[j] == "\n":
                    break
                j += 1
            end = min(n, j + len(quote))
            for k in range(i + len(quote), min(j, n)):
                if text[k] != "\n":
                    masked[k] = " "
            i = end
            continue
        i += 1
    return "".join(clean), "".join(masked)


@dataclass
class Block:
    open: int
    close: int
    header: str
    parent: int | None
    children: list[int] = field(default_factory=list)


def _blocks(clean: str, masked: str) -> list[Block]:
    """Every `{…}` with the statement text in front of it, in source order."""
    out: list[Block] = []
    stack: list[int] = []
    boundary = 0
    for i, ch in enumerate(masked):
        if ch == "{":
            header = clean[boundary:i]
            parent = stack[-1] if stack else None
            out.append(Block(i, len(masked), _last_statement(header), parent))
            if parent is not None:
                out[parent].children.append(len(out) - 1)
            stack.append(len(out) - 1)
            boundary = i + 1
        elif ch == "}":
            if stack:
                out[stack.pop()].close = i
            boundary = i + 1
        elif ch == ";":
            boundary = i + 1
    return out


def _last_statement(header: str) -> str:
    """The statement a `{` belongs to: the last line, joined with the lines before it while brackets are open
    or the line continues an expression (`)`, `.`)."""
    lines = [l for l in header.split("\n")]
    out = ""
    for line in reversed(lines):
        out = (line + " " + out) if out else line
        if out.count("(") >= out.count(")") and not out.lstrip().startswith((")", ".", ",")) and out.strip():
            break
    return " ".join(out.split())


def _strings(arg: str) -> list[tuple[str, str]]:
    """[(quote, content)] of the string literals in `arg`, in order."""
    return [(m.group(1), m.group(2)) for m in re.finditer(r"('''|\"\"\"|'|\")(.*?)\1", arg, re.S)]


def _balanced(masked: str, start: int, open_ch: str = "(", close_ch: str = ")") -> int:
    """Index just past the bracket matching the one at `start` (masked text); len when unbalanced."""
    depth = 0
    for i in range(start, len(masked)):
        if masked[i] == open_ch:
            depth += 1
        elif masked[i] == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
    return len(masked)


# --------------------------------------------------------------------------- configurations

def _segments(name: str) -> list[str]:
    return [s.lower() for s in re.findall(r"[a-z0-9]+|[A-Z][a-z0-9]*", name)]


def config_is_dev(name: str) -> bool:
    """A configuration (declaration or lockfile) whose dependencies do not ship: tests (`testImplementation`,
    `androidTestImplementation`, `kspTest`, `testFixturesApi`, `debugUnitTestRuntimeClasspath`), debug-only
    variants (`debugImplementation`, `debugRuntimeClasspath`), annotation processors (`kapt`, `ksp`,
    `annotationProcessor` and their variants) and build tools (`checkstyle`, `developmentOnly`, …)."""
    low = name.lower()
    segs = _segments(name)
    if not segs:
        return False
    if low in TOOL_CONFIGS or "test" in segs or segs[0] == "debug":
        return True
    if segs[0] in ("kapt", "ksp") or low.endswith("annotationprocessor") or low.startswith("kotlin"):
        return True
    return False


# --------------------------------------------------------------------------- data

@dataclass
class Declaration:
    rel: str                      # build file
    config: str
    dev: bool
    group: str = ""
    artifact: str = ""
    version: str = ""             # resolved version, "" when unresolved or absent
    raw: str = ""                 # the notation as written (trimmed)
    reason: str = ""              # why the version is unresolved, "" when resolved
    platform: bool = False
    unknown: str = ""             # the expression when the coordinates themselves are not known

    @property
    def ga(self) -> str:
        return f"{self.group}:{self.artifact}" if self.group and self.artifact else ""


@dataclass
class Module:
    rel: str                      # build file
    dir: str                      # repo-relative directory ("" for the root)
    root: str                     # Gradle build root (directory of its settings file)
    tooling: bool = False         # buildSrc or a plugin build: everything it declares is build tooling
    declarations: list[Declaration] = field(default_factory=list)
    constraints: dict[str, str] = field(default_factory=dict)   # ga -> version from a constraints block
    locked: set[str] = field(default_factory=set)              # ga in this module's lock state
    lockfiles: list[str] = field(default_factory=list)


@dataclass
class Lock:
    rel: str
    ga: str
    group: str
    artifact: str
    version: str
    configs: list[str]
    legacy: bool                  # gradle/dependency-locks/<configuration>.lockfile: not read by Syft


@dataclass
class Analysis:
    modules: list[Module] = field(default_factory=list)
    locks: list[Lock] = field(default_factory=list)
    has_pom: bool = False

    def declarations(self):
        for m in self.modules:
            yield from m.declarations


# --------------------------------------------------------------------------- catalogs, properties, constants

def _catalog_version(value, versions: dict) -> tuple[str, str]:
    """(version, reason) of a catalog `version` value."""
    if isinstance(value, str):
        return _version(value)
    if isinstance(value, dict):
        if "ref" in value:
            ref = versions.get(value["ref"])
            if ref is None:
                return "", f"version.ref `{value['ref']}` not in the catalog"
            return _catalog_version(ref, versions)
        for key in ("strictly", "require", "prefer"):
            if isinstance(value.get(key), str):
                return _version(value[key])
    return "", "no version in the catalog (managed by a platform/BOM or plugin)"


def parse_catalog(text: str) -> dict[str, list[tuple[str, str, str, str]]]:
    """accessor (lower case, without the catalog name) -> [(group, artifact, version, reason)] from a
    `*.versions.toml`; bundles as `bundles.<name>`. Plugins are build tools and not read."""
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return {}
    versions = data.get("versions") if isinstance(data.get("versions"), dict) else {}
    libs: dict[str, list] = {}
    for alias, spec in (data.get("libraries") or {}).items() if isinstance(data.get("libraries"), dict) else []:
        group = artifact = ""
        version, reason = "", "no version in the catalog (managed by a platform/BOM or plugin)"
        if isinstance(spec, str):
            parts = spec.split(":")
            if len(parts) >= 2:
                group, artifact = parts[0], parts[1]
                if len(parts) >= 3:
                    version, reason = _version(parts[2])
        elif isinstance(spec, dict):
            if isinstance(spec.get("module"), str) and ":" in spec["module"]:
                group, _, artifact = spec["module"].partition(":")
            else:
                group, artifact = str(spec.get("group") or ""), str(spec.get("name") or "")
            if "version" in spec:
                version, reason = _catalog_version(spec["version"], versions)
        if group and artifact:
            libs[_accessor(alias)] = [(group, artifact, version, reason)]
    for name, members in (data.get("bundles") or {}).items() if isinstance(data.get("bundles"), dict) else []:
        found = []
        for alias in members if isinstance(members, list) else []:
            found += libs.get(_accessor(str(alias)), [("", "", "", f"bundle member `{alias}` not in the catalog")])
        libs["bundles." + _accessor(name)] = found
    return libs


def _accessor(alias: str) -> str:
    return re.sub(r"[-_.]+", ".", alias).lower()


def parse_properties(text: str) -> dict[str, str]:
    out = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#!":
            continue
        m = re.match(r"^([^=:\s]+)\s*[=:\s]\s*(.*)$", line)
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


CONST_PATTERNS = [
    re.compile(r"(?m)^\s*(?:(?:private|internal|public|const)\s+)*va[lr]\s+(\w+)\s*(?::\s*String\s*)?=\s*"
               r"(\"(?:[^\"\\\n]|\\.)*\")"),                                           # Kotlin val
    re.compile(r"(?m)^\s*val\s+(\w+)\s+by\s+extra\s*\(\s*(\"[^\"\n]*\")\s*\)"),       # val x by extra("…")
    re.compile(r"(?m)^\s*(?:def|String)\s+(\w+)\s*=\s*('[^'\n]*'|\"[^\"\n]*\")"),    # Groovy def
    re.compile(r"(?m)^\s*(?:project\.|rootProject\.)?ext\.(\w+)\s*=\s*('[^'\n]*'|\"[^\"\n]*\")"),
    re.compile(r"(?:ext|extra)\s*(?:\.set)?\s*[(\[]\s*['\"](\w+)['\"]\s*[,\]]\s*=?\s*,?\s*('[^'\n]*'|\"[^\"\n]*\")"),
    re.compile(r"extra\s*\[\s*\"(\w+)\"\s*\]\s*=\s*(\"[^\"\n]*\")"),
]


def _constants(path_text: list[tuple[str, str]]) -> dict[str, set[str]]:
    """name -> every literal value assigned to it in the given files (build scripts, buildSrc sources): Kotlin
    `val`, Groovy `def`, `ext.x =`, `ext { x = … }`, `extra["x"] =`, `val x by extra("…")`, Groovy maps in
    `ext` (`versions = [kotlin: '1.9']` as `versions.kotlin`), and `object X { const val y = "…" }` as `X.y`."""
    out: dict[str, set[str]] = {}

    def put(name: str, value: str) -> None:
        out.setdefault(name, set()).add(value)

    for name, text in path_text:
        clean, masked = _clean(text)
        for pat in CONST_PATTERNS:
            for m in pat.finditer(clean):
                put(m.group(1), m.group(2)[1:-1])
        blocks = _blocks(clean, masked)
        for b in blocks:
            body = _own_text(clean, blocks, b)
            if re.search(r"(?:^|\.)\s*ext$", b.header):                 # ext { x = '…' }
                for m in re.finditer(r"(?m)^\s*(?:set\s*\(\s*)?['\"]?(\w+)['\"]?\s*[=,]\s*('[^'\n]*'|\"[^\"\n]*\")",
                                     body):
                    put(m.group(1), m.group(2)[1:-1])
            obj = re.match(r"^(?:\w+\s+)*object\s+(\w+)", b.header)
            if obj:
                chain = [obj.group(1)]
                p = b.parent
                while p is not None:
                    outer = re.match(r"^(?:\w+\s+)*object\s+(\w+)", blocks[p].header)
                    if outer:
                        chain.insert(0, outer.group(1))
                    p = blocks[p].parent
                for m in re.finditer(r"(?m)^\s*(?:(?:private|internal|public|const)\s+)*va[lr]\s+(\w+)\s*"
                                     r"(?::\s*String\s*)?=\s*\"((?:[^\"\\\n]|\\.)*)\"", body):
                    for k in range(len(chain)):
                        put(".".join(chain[k:] + [m.group(1)]), m.group(2))
        for m in re.finditer(r"(\w+)\s*=\s*\[([^\[\]]*)\]", clean):          # Groovy map literal
            for e in re.finditer(r"(\w+)\s*:\s*('[^'\n]*'|\"[^\"\n]*\")", m.group(2)):
                put(f"{m.group(1)}.{e.group(1)}", e.group(2)[1:-1])
    return out


def _own_text(clean: str, blocks: list[Block], b: Block) -> str:
    """The text of block `b` with its child blocks blanked."""
    start = b.open + 1
    body = list(clean[start:b.close])
    for ci in b.children:
        c = blocks[ci]
        for k in range(c.open - start, min(c.close + 1, b.close) - start):
            if body[k] != "\n":
                body[k] = " "
    return "".join(body)


# --------------------------------------------------------------------------- versions and references

def _version(raw: str) -> tuple[str, str]:
    """(version, reason): a concrete version, or "" and why it is not one."""
    v = raw.strip()
    if v.endswith("!!"):                     # strictly shorthand
        v = v[:-2]
    if not v:
        return "", "no version (managed by a platform/BOM, a constraint or a plugin)"
    if "$" in v:
        return "", f"version `{v[:60]}` uses a variable that was not resolved"
    if DYNAMIC_HINT.search(v) or v in ("+",):
        return "", f"dynamic version or range `{v[:60]}`"
    if not CONCRETE.match(v):
        return "", f"version `{v[:60]}` not understood"
    return v, ""


class Resolver:
    def __init__(self, constants: dict[str, set[str]], catalogs: dict[str, dict]):
        self.constants = constants
        self.catalogs = catalogs              # catalog name -> parse_catalog()

    def constant(self, ref: str) -> str | None:
        ref = re.sub(r"^(?:rootProject|project)\.(?:ext\.|extra\.)?|^(?:ext|extra)\.", "", ref.strip())
        ref = re.sub(r"^(?:rootProject\.|project\.)?(?:extra|ext)\[\s*['\"](\w+)['\"]\s*\]$", r"\1", ref)
        m = re.match(r"^(?:rootProject\.|project\.)?(?:property|findProperty|providers\.gradleProperty)\(\s*['\"]"
                     r"([\w.]+)['\"]\s*\)(?:\.get\(\))?$", ref)
        if m:
            ref = m.group(1)
        values = self.constants.get(ref)
        if values and len(values) == 1:
            return next(iter(values))
        return None

    def expand(self, s: str, depth: int = 0) -> str:
        """`$name`, `${name}`, `${rootProject.ext.name}`, `${libs.versions.x.get()}` replaced when unambiguous."""
        if depth > 5 or "$" not in s:
            return s

        def braced(m):
            inner = m.group(1).strip()
            cat = re.match(r"^(\w+)\.versions\.([\w.]+?)(?:\.get\(\))?$", inner)
            if cat and cat.group(1) in self.catalogs:
                v = self.catalogs[cat.group(1)].get("versions." + _accessor(cat.group(2)))
                if v:
                    return v[0][2] or m.group(0)
            value = self.constant(inner)
            return value if value is not None else m.group(0)

        new = re.sub(r"\$\{([^{}]+)\}", braced, s)
        new = re.sub(r"\$([A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)*)",
                     lambda m: self.constant(m.group(1)) if self.constant(m.group(1)) is not None else m.group(0), new)
        return new if new == s else self.expand(new, depth + 1)

    def catalog_ref(self, expr: str) -> list[tuple[str, str, str, str]] | None:
        """[(group, artifact, version, reason)] for `libs.x.y` (or another catalog's accessor); None when `expr`
        is not a catalog reference; [] entries carry a reason when the alias is unknown."""
        m = re.match(r"^(\w+)\.([\w.]+?)(?:\.get\(\)|\.asProvider\(\))?$", expr)
        if not m or m.group(1) not in self.catalogs:
            return None
        key = _accessor(m.group(2))
        if key.startswith(("plugins.", "versions.")):
            return []
        return self.catalogs[m.group(1)].get(key)


def _add_catalog_versions(catalog: dict, text: str) -> None:
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return
    versions = data.get("versions") if isinstance(data.get("versions"), dict) else {}
    for alias, value in versions.items():
        v, reason = _catalog_version(value, versions)
        catalog["versions." + _accessor(alias)] = [("", "", v, reason)]


# --------------------------------------------------------------------------- build files

DECL = re.compile(r"(?P<conf>\"[A-Za-z_]\w*\"|[A-Za-z_]\w*)\s*(?P<paren>\()?")


def _statement_starts(text: str):
    """Positions of statements: after a newline, `{` or `;`, skipping blanks."""
    yield from (m.end() for m in re.finditer(r"(?:^|[\n;{])[ \t]*", text))


def _argument(clean: str, masked: str, start: int, paren: bool) -> tuple[str, int]:
    """(argument text, end) of a declaration whose argument starts at `start`."""
    if paren:
        end = _balanced(masked, start)
        return clean[start + 1:end - 1], end
    end = start
    while True:
        nl = masked.find("\n", end)
        nl = len(masked) if nl < 0 else nl
        line = masked[end:nl].rstrip()
        end = nl
        if not line.endswith(",") or end >= len(masked):
            break
        end += 1
    return clean[start:end], end


def _parse_notation(arg: str, local: dict[str, str], res: Resolver) -> list[tuple]:
    """[(group, artifact, version, reason, platform, unknown, raw)] for one declaration argument."""
    a = " ".join(arg.split())
    platform = False
    m = re.match(r"^(?:platform|enforcedPlatform)\s*\((.*)\)\s*$", a)
    if m:
        a, platform = m.group(1).strip(), True
    m = re.match(r"^testFixtures\s*\((.*)\)\s*$", a)
    if m:
        a = m.group(1).strip()
    if re.match(r"^(?:project\s*\(|projects\.|files\s*\(|fileTree\s*\(|gradleApi\(|gradleTestKit\(|localGroovy\()", a):
        return []                                               # a module of this build or a local file
    if a in local:                                              # a local `val x = platform(libs.y)`
        inner = local[a]
        found = _parse_notation(inner, {}, res)
        return [(g, art, v, r, p or platform, u, raw) for g, art, v, r, p, u, raw in found]
    m = re.match(r"^kotlin\s*\(\s*\"([\w.-]+)\"\s*(?:,\s*\"([^\"]*)\"\s*)?\)", a)
    if m:
        version, reason = _version(res.expand(m.group(2))) if m.group(2) else (
            "", "no version (set by the Kotlin Gradle plugin)")
        return [("org.jetbrains.kotlin", f"kotlin-{m.group(1)}", version, reason, platform, "", a)]
    if re.search(r"\b(?:group|module)\s*[:=]", a) and re.search(r"\bname\s*[:=]", a):
        fields = {}
        for f in re.finditer(r"\b(group|name|version)\s*[:=]\s*(?:('[^']*'|\"[^\"]*\")|([\w.]+))", a):
            fields[f.group(1)] = f.group(2)[1:-1] if f.group(2) else (res.constant(f.group(3)) or f"${f.group(3)}")
        group, artifact = res.expand(fields.get("group", "")), res.expand(fields.get("name", ""))
        version, reason = _version(res.expand(fields.get("version", ""))) if "version" in fields else _version("")
        if "$" in group + artifact:
            return [("", "", "", "coordinates use a variable that was not resolved", platform, a[:MAX_NAME], a)]
        return [(group, artifact, version, reason, platform, "", a)]
    strings = [(q, s) for q, s in _strings(a) if ":" in s]
    if strings and a[:1] in "'\"":
        out = []
        for _, s in strings:
            out.append(_coordinate(res.expand(s), platform, s))
        return out
    expr = re.sub(r"\s", "", a).split("{", 1)[0].rstrip(",")
    if not re.fullmatch(r"[A-Za-z_][\w.]*(?:\(\))?(?:\[['\"]\w+['\"]\])?", expr):
        return [("", "", "", "notation not understood", platform, expr[:MAX_NAME] or "?", a)] if expr else []
    found = res.catalog_ref(expr)
    if found is not None:
        if not found:
            return [("", "", "", "catalog alias not found (catalog from a plugin or published artifact?)",
                     platform, expr[:MAX_NAME], a)] if not expr.split(".")[1] in ("plugins", "versions") else []
        return [(g, art, v, r, platform, "" if g else expr[:MAX_NAME], a) for g, art, v, r in found]
    m = re.match(r"^(\w+)\.", expr)
    if m and m.group(1) in ("libs",) and m.group(1) not in res.catalogs:
        return [("", "", "", "version catalog `libs` not found in the repository", platform, expr[:MAX_NAME], a)]
    value = res.constant(expr)
    if value is not None and ":" in value:
        return [_coordinate(res.expand(value), platform, a)]
    return [("", "", "", "a variable or helper the reader cannot evaluate", platform, expr[:MAX_NAME], a)]


def _coordinate(s: str, platform: bool, raw: str) -> tuple:
    body = s.split("@", 1)[0]                                     # @aar, @jar: the artifact type
    parts = body.split(":")
    if len(parts) < 2 or not parts[0] or not parts[1] or "$" in parts[0] + parts[1] or " " in body:
        return ("", "", "", "coordinates use a variable that was not resolved", platform, raw[:MAX_NAME], raw)
    version, reason = _version(parts[2]) if len(parts) >= 3 else _version("")
    return (parts[0], parts[1], version, reason, platform, "", raw)


def parse_build_file(text: str, rel: str, res: Resolver, tooling: bool = False) -> tuple[list[Declaration], dict]:
    """(declarations, constraints {ga: version}) of one build file."""
    clean, masked = _clean(text)
    blocks = _blocks(clean, masked)
    local: dict[str, str] = {}
    for m in re.finditer(r"(?m)^\s*(?:val|def)\s+(\w+)\s*=\s*((?:platform|enforcedPlatform)\s*\(.*\)|libs\.[\w.]+)\s*$",
                         clean):
        local[m.group(1)] = m.group(2)
    decls: list[Declaration] = []
    constraints: dict[str, str] = {}

    def ancestors(i):
        p = blocks[i].parent
        while p is not None:
            yield blocks[p]
            p = blocks[p].parent

    def is_deps(b: Block) -> bool:
        return re.search(r"(?:^|\.)\s*dependencies$", b.header) is not None

    def scan(bi: int, dev_ctx: bool, into_constraints: bool):
        b = blocks[bi]
        start = b.open + 1
        own = _own_text(clean, blocks, b)
        own_masked = _own_text(masked, blocks, b)
        for pos in _statement_starts(own_masked):
            m = DECL.match(own_masked, pos)
            if not m:
                continue
            conf = m.group("conf").strip('"')
            after = m.end()
            if conf in KEYWORDS or conf.startswith(("set", "get")):
                continue
            if not m.group("paren"):
                nxt = own_masked[after:after + 1]
                if not nxt or nxt in "\n=.{}:)," or own_masked[after - 1] not in " \t":
                    continue
                arg, _ = _argument(own, own_masked, after, False)
            else:
                arg, _ = _argument(own, own_masked, after - 1, True)
            if not arg.strip():
                continue
            for g, art, version, reason, platform, unknown, raw in _parse_notation(arg, local, res):
                if into_constraints:
                    if g and art and version:
                        constraints[f"{g}:{art}"] = version
                    continue
                if len(decls) >= MAX_DECLARATIONS:
                    return
                decls.append(Declaration(rel=rel, config=conf, dev=tooling or dev_ctx or config_is_dev(conf),
                                         group=g, artifact=art, version=version, raw=" ".join(raw.split())[:200],
                                         reason=reason, platform=platform, unknown=unknown))
        for ci in b.children:                    # control flow (if/else, forEach) and constraints; not closures
            c = blocks[ci]
            if re.search(r"(?:^|\.)\s*constraints$", c.header):
                scan(ci, dev_ctx, True)
            elif re.match(r"^\}?\s*(?:if\b|else\b|for\b|when\b|\w+\.forEach\b|\w+\.each\b)", c.header):
                scan(ci, dev_ctx, into_constraints)

    for i, b in enumerate(blocks):
        if not is_deps(b) or any(is_deps(a) for a in ancestors(i)):
            continue
        headers = [b.header] + [a.header for a in ancestors(i)]
        if any(re.search(r"\bbuildscript$", h) for h in headers):
            continue                             # classpath of the build itself: Gradle plugins
        dev_ctx = any(_test_source_set(h) for h in headers)
        scan(i, dev_ctx, False)
    return decls, constraints


def _test_source_set(header: str) -> bool:
    """`commonTest.dependencies`, `val jvmTest by getting`, `sourceSets.test`, `androidUnitTest { …`."""
    head = header.removesuffix("dependencies").rstrip(". ")
    for word in re.findall(r"[A-Za-z_]\w*", head):
        if word in ("test", "androidTest", "testFixtures") or (word.endswith("Test") and len(word) > 4):
            return True
    return False


# --------------------------------------------------------------------------- settings and lock state

def _settings(text: str, settings_dir: Path, root: Path) -> dict:
    """{'build_files': [Path], 'catalogs': {name: Path}, 'plugin_builds': [Path]} from a settings file; every
    path checked to stay inside the tree."""
    clean, _ = _clean(text)
    out = {"build_files": [], "catalogs": {}, "plugin_builds": []}
    project_dirs: dict[str, Path] = {}
    for m in re.finditer(r"\binclude\b\s*\(?([^\n)]*)", clean):
        for s in re.findall(r"['\"]([^'\"]+)['\"]", m.group(1)):
            project_dirs[s.lstrip(":")] = settings_dir / s.strip(":").replace(":", "/")
    for m in re.finditer(r"project\s*\(\s*['\"]:?([^'\"]+)['\"]\s*\)\s*\.projectDir\s*=\s*"
                         r"(?:file\s*\(\s*)?(?:new\s+File\s*\(\s*settingsDir\s*,\s*)?['\"]([^'\"]+)['\"]", clean):
        project_dirs[m.group(1)] = settings_dir / m.group(2)
    for m in re.finditer(r"project\s*\(\s*['\"]:?([^'\"]+)['\"]\s*\)\s*\.buildFileName\s*=\s*['\"]([^'\"/\\]+)['\"]",
                         clean):
        d = project_dirs.get(m.group(1), settings_dir / m.group(1).replace(":", "/"))
        out["build_files"].append(d / m.group(2))
    for m in re.finditer(r"create\s*\(\s*['\"](\w+)['\"]\s*\)\s*\{[^{}]*?from\s*\(\s*files\s*\(\s*['\"]([^'\"]+)['\"]",
                         clean):
        out["catalogs"][m.group(1)] = settings_dir / m.group(2)
    pm = re.search(r"pluginManagement\s*\{", clean)
    if pm:
        _, masked = _clean(clean)
        end = _balanced(masked, pm.end() - 1, "{", "}")
        for m in re.finditer(r"includeBuild\s*\(?\s*['\"]([^'\"]+)['\"]", clean[pm.end():end]):
            out["plugin_builds"].append(settings_dir / m.group(1))
    for d in project_dirs.values():
        for name in BUILD_FILES:
            out["build_files"].append(d / name)
    norm = []
    for p in out["build_files"]:
        try:
            if os.path.normpath(p).startswith(str(root)) and Path(os.path.normpath(p)).resolve().is_relative_to(root):
                norm.append(Path(os.path.normpath(p)))
        except (OSError, RuntimeError):
            continue
    out["build_files"] = norm
    out["catalogs"] = {k: Path(os.path.normpath(v)) for k, v in out["catalogs"].items()}
    out["plugin_builds"] = [Path(os.path.normpath(p)) for p in out["plugin_builds"]]
    return out


def parse_lockfile(text: str) -> list[tuple[str, str, str, list[str]]]:
    """[(group, artifact, version, configurations)] of a `gradle.lockfile` (`g:a:v=conf1,conf2`; `empty=` lines
    skipped). A legacy per-configuration file has no `=` part: its configuration is the file name."""
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coord, _, confs = line.partition("=")
        parts = coord.split(":")
        if len(parts) < 3 or not all(parts[:3]):
            continue
        out.append((parts[0], parts[1], parts[2], [c for c in confs.split(",") if c]))
    return out


# --------------------------------------------------------------------------- the analysis

def analyse(src: Path, ignore: list[str]) -> Analysis:
    """Everything this module knows about the Gradle builds in `src`. Never raises for malformed input."""
    root = src.resolve()
    result = Analysis()
    build_files: list[Path] = []
    settings: list[Path] = []
    locks: list[Path] = []
    props_files: list[Path] = []
    kotlin_sources: list[Path] = []
    for path in _walk(root, ignore):
        name = path.name
        if _inside(root, path) is None:
            continue
        rel = _rel(root, path)
        if name in BUILD_FILES:
            build_files.append(path)
        elif name in SETTINGS_FILES:
            settings.append(path)
        elif name == LOCKFILE or (name.endswith(".lockfile") and path.parent.name == "dependency-locks"
                                  and path.parent.parent.name == "gradle"):
            locks.append(path)
        elif name == "gradle.properties":
            props_files.append(path)
        elif name == "pom.xml":
            result.has_pom = True
        elif "buildSrc/" in f"/{rel}" and name.endswith((".kt", ".kts", ".gradle", ".groovy")):
            kotlin_sources.append(path)
    if not build_files and not locks:
        return result

    roots = {p.parent.resolve() for p in settings}
    catalogs: dict[Path, dict[str, Path]] = {}
    plugin_builds: set[Path] = set()
    for s in settings:
        text = _read(s)
        if text is None:
            continue
        info = _settings(text, s.parent.resolve(), root)
        for bf in info["build_files"]:
            if bf not in build_files and _inside(root, bf) is not None and not _skipped(root, bf):
                build_files.append(bf)
        catalogs[s.parent.resolve()] = info["catalogs"]
        plugin_builds.update(info["plugin_builds"])
    build_files = sorted(set(p.resolve() for p in build_files))[:MAX_BUILD_FILES]

    texts: dict[Path, str] = {}
    for p in build_files + kotlin_sources:
        t = _read(p)
        if t is not None:
            texts[p] = t
    constants = _constants([(str(p), t) for p, t in texts.items()])
    for pf in props_files:
        t = _read(pf)
        for k, v in parse_properties(t or "").items():
            constants.setdefault(k, set()).add(v)

    def gradle_root(d: Path) -> Path:
        for cand in [d, *d.parents]:
            if cand in roots:
                return cand
            if cand == root:
                break
        return d

    catalog_cache: dict[Path, dict] = {}

    def catalogs_for(groot: Path) -> dict[str, dict]:
        out = {}
        named = dict(catalogs.get(groot, {}))
        default = groot / "gradle" / "libs.versions.toml"
        named.setdefault("libs", default)
        for name, path in named.items():
            safe = _inside(root, path)
            if safe is None:
                continue
            if safe not in catalog_cache:
                text = _read(safe) or ""
                cat = parse_catalog(text)
                _add_catalog_versions(cat, text)
                catalog_cache[safe] = cat
            out[name] = catalog_cache[safe]
        return out

    for p in build_files:
        text = texts.get(p)
        if text is None:
            continue
        rel = _rel(root, p)
        d = p.parent
        groot = gradle_root(d)
        tooling = "buildSrc" in Path(rel).parts or any(d == b or b in d.parents for b in plugin_builds)
        res = Resolver(constants, catalogs_for(groot))
        decls, constraints = parse_build_file(text, rel, res, tooling)
        mod = Module(rel=rel, dir=_rel(root, d) if d != root else "", root=_rel(root, groot) if groot != root else "",
                     tooling=tooling, declarations=decls, constraints=constraints)
        for d2 in decls:                                # a constraint in the same file supplies a missing version
            if not d2.version and not d2.unknown and d2.ga in constraints and "variable" not in d2.reason \
                    and "dynamic" not in d2.reason:
                d2.version, d2.reason = constraints[d2.ga], ""
        result.modules.append(mod)

    by_dir = {m.dir: m for m in result.modules}
    for lp in locks:
        text = _read(lp)
        if text is None:
            continue
        rel = _rel(root, lp)
        legacy = lp.name != LOCKFILE
        mdir_path = lp.parent.parent.parent if legacy else lp.parent
        mdir = _rel(root, mdir_path) if mdir_path.resolve() != root else ""
        conf = lp.name[:-len(".lockfile")] if legacy else ""
        for g, a, v, confs in parse_lockfile(text):
            result.locks.append(Lock(rel=rel, ga=f"{g}:{a}", group=g, artifact=a, version=v,
                                     configs=confs or ([conf] if conf else []), legacy=legacy))
            if mdir in by_dir:
                by_dir[mdir].locked.add(f"{g}:{a}")
        if mdir in by_dir and rel not in by_dir[mdir].lockfiles:
            by_dir[mdir].lockfiles.append(rel)
    return result


def _skipped(root: Path, path: Path) -> bool:
    try:
        parts = path.resolve().relative_to(root).parts[:-1]
    except ValueError:
        return True
    return any(p in SKIP_DIRS or p.startswith(".") for p in parts)


# --------------------------------------------------------------------------- what the readers use

def direct(a: Analysis) -> dict[str, list[str]]:
    """`group:artifact` -> build files that declare it (platforms included)."""
    out: dict[str, list[str]] = {}
    for d in a.declarations():
        if d.ga:
            out.setdefault(d.ga, [])
            if d.rel not in out[d.ga]:
                out[d.ga].append(d.rel)
    return out


def scopes(a: Analysis) -> dict[str, set[bool]]:
    """`group:artifact` -> {is dev} over every declaration and lockfile configuration. Lockfile evidence of a
    package nobody declares counts only when every module that declares dependencies has lock state and no
    pom.xml shares the tree; otherwise the package's other routes onto a classpath are unknown."""
    out: dict[str, set[bool]] = {}
    declared = set()
    for d in a.declarations():
        if d.ga:
            out.setdefault(d.ga, set()).add(d.dev)
            declared.add(d.ga)
    fully_locked = not a.has_pom and all(m.lockfiles for m in a.modules if m.declarations)
    for lock in a.locks:
        if lock.ga not in declared and not fully_locked:
            continue
        found = {config_is_dev(c) for c in lock.configs} or {False}
        out.setdefault(lock.ga, set()).update(found)
    return out


def unknown_direct_locations(a: Analysis) -> set[str]:
    """Lock files whose packages cannot be told direct or transitive: the module next to them declares something
    the reader could not identify (an unknown catalog alias, a helper function), or there is no build file."""
    out = set()
    by_dir = {m.dir: m for m in a.modules}
    for lock in a.locks:
        d = lock.rel.rsplit("/", 1)[0] if "/" in lock.rel else ""
        if lock.legacy:
            d = d.rsplit("/", 2)[0] if d.count("/") >= 2 else ""
        mod = by_dir.get(d)
        if mod is None or any(x.unknown for x in mod.declarations):
            out.add(lock.rel)
    return out


def components(a: Analysis, dev_only: set[str]) -> list[Component]:
    """Packages Syft does not list: declarations of modules without lock state for them, and legacy lock files.
    `dev_only` is the tree-wide set of `group:artifact` that only tests or tooling use (Maven and Gradle)."""
    out: dict[tuple, Component] = {}
    declared = direct(a)
    unknown_locs = unknown_direct_locations(a)

    def add(key, make):
        c = out.get(key)
        if c is None:
            out[key] = make()
        return out[key]

    for m in a.modules:
        for d in m.declarations:
            if d.ga and d.ga in m.locked:
                continue                                  # the lock file has the resolved version
            if d.unknown:
                key = ("?", d.unknown, d.rel)
                c = add(key, lambda: Component(
                    kind="package", ecosystem="Maven", name=d.unknown, version="", purl="", scope="optional",
                    locations=[d.rel], direct=True,
                    props={"requirement": d.raw, "unresolved": True, "reason": d.reason, "gradle_config": d.config}))
                if not d.dev:
                    c.scope = "required"
                continue
            purl = f"pkg:maven/{d.group}/{d.artifact}" + (f"@{d.version}" if d.version else "")
            props = {"gradle_config": d.config}
            if d.version:
                props["version_source"] = f"{d.rel} (declared; Gradle may resolve a higher version)"
            else:
                props.update({"requirement": d.raw, "unresolved": True, "reason": d.reason})
            if d.platform:
                props["platform"] = True
            c = add((purl,), lambda: Component(
                kind="package", ecosystem="Maven", name=d.artifact, version=d.version, purl=purl,
                scope="optional" if d.ga in dev_only else "required", locations=[], direct=True, props=props))
            if d.rel not in c.locations:
                c.locations.append(d.rel)
    for lock in a.locks:
        if not lock.legacy:
            continue                                      # Syft reads gradle.lockfile itself
        purl = f"pkg:maven/{lock.group}/{lock.artifact}@{lock.version}"
        version, _ = _version(lock.version)
        if not version:
            purl = f"pkg:maven/{lock.group}/{lock.artifact}"
        is_direct = None if lock.rel in unknown_locs else lock.ga in declared
        c = add((purl,), lambda: Component(
            kind="package", ecosystem="Maven", name=lock.artifact, version=version, purl=purl,
            scope="optional" if lock.ga in dev_only else "required", locations=[], direct=is_direct,
            props={"version_source": "Gradle lock state"} if version else
            {"requirement": lock.version, "unresolved": True, "reason": "lock state holds no concrete version"}))
        if lock.rel not in c.locations:
            c.locations.append(lock.rel)
    return list(out.values())
