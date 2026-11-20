"""Offline Maven version resolution from the poms of the same repository.

Syft writes version `UNKNOWN` for a dependency whose `<version>` is not in its own pom: Maven takes it from
`<dependencyManagement>` of a parent pom or of an imported BOM. When that parent or BOM is a pom in the same
repository, the version is known without Maven or network access; this module fills it in, in the SBOM and
in the inventory, and marks it with `sbom-audit:version_source`. A version managed by a pom outside the
repository (a BOM from Maven Central, an external parent) stays unresolved: it is never guessed.

Parents are found by groupId:artifactId among the repository's poms (the parent's `<version>` is not
compared: a module that names an older snapshot of its own parent still inherits from the pom in the tree).
"""
from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from .matching import version_unresolved
from .model import Component, purl_namespace
from .readers import _inside_file

SOURCE_PROPERTY = "sbom-audit:version_source"
SKIP_DIRS = {"node_modules", ".git", "target", "build", ".mvn"}
MAX_POMS = 2000
_PROP = re.compile(r"\$\{([^}]+)\}")


@dataclass
class Pom:
    path: str                                        # repo-relative
    group: str = ""
    artifact: str = ""
    version: str = ""
    parent: tuple[str, str] | None = None            # (groupId, artifactId)
    props: dict[str, str] = field(default_factory=dict)
    managed: dict[str, str] = field(default_factory=dict)   # "g:a" -> raw version
    imports: list[tuple[str, str]] = field(default_factory=list)   # in-tree BOM candidates (g, a)
    deps: dict[str, str] = field(default_factory=dict)      # "g:a" -> raw version in <dependencies>


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(el, name: str):
    if el is None:
        return None
    for c in el:
        if _local(c.tag) == name:
            return c
    return None


def _text(el, name: str) -> str:
    c = _child(el, name)
    return (c.text or "").strip() if c is not None and c.text else ""


def _dependencies(container) -> list:
    deps = _child(container, "dependencies")
    return [d for d in deps if _local(d.tag) == "dependency"] if deps is not None else []


def parse(path: Path, rel: str, root: Path | None = None) -> Pom | None:
    """The pom at `path`, or None. With `root`, only a regular file inside `root` (symlinks resolved) is
    read: the audited repository chooses its symlinks, and a FIFO would block the scan."""
    if root is not None:
        path = _inside_file(Path(root).resolve(), path)
        if path is None:
            return None
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError, ValueError):
        return None
    if _local(root.tag) != "project":
        return None
    parent = _child(root, "parent")
    pom = Pom(path=rel, artifact=_text(root, "artifactId"))
    pom.group = _text(root, "groupId") or _text(parent, "groupId")
    pom.version = _text(root, "version") or _text(parent, "version")
    if parent is not None and _text(parent, "artifactId"):
        pom.parent = (_text(parent, "groupId"), _text(parent, "artifactId"))
    props = _child(root, "properties")
    if props is not None:
        pom.props = {_local(p.tag): (p.text or "").strip() for p in props}
    for dep in _dependencies(_child(root, "dependencyManagement")):
        g, a, v = _text(dep, "groupId"), _text(dep, "artifactId"), _text(dep, "version")
        if _text(dep, "scope") == "import" and _text(dep, "type") == "pom":
            pom.imports.append((g, a))
        elif g and a and v:
            pom.managed.setdefault(f"{g}:{a}", v)
    for dep in _dependencies(root):
        g, a, v = _text(dep, "groupId"), _text(dep, "artifactId"), _text(dep, "version")
        if g and a and v:
            pom.deps.setdefault(f"{g}:{a}", v)
    return pom


def index(src: Path) -> dict[str, Pom]:
    """Repo-relative path -> Pom for every `pom.xml` in the exported tree (build output and vendored trees
    are skipped)."""
    poms: dict[str, Pom] = {}
    found = []
    for dirpath, dirnames, filenames in os.walk(src):       # never descends into a symlinked directory
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if "pom.xml" in filenames:
            found.append(Path(dirpath) / "pom.xml")
    for path in sorted(found):
        rel = path.relative_to(src).as_posix()
        pom = parse(path, rel, root=src)
        if pom is not None:
            poms[rel] = pom
        if len(poms) >= MAX_POMS:
            break
    return poms


class Resolver:
    def __init__(self, poms: dict[str, Pom]):
        self.poms = poms
        self.by_ga: dict[str, Pom] = {}
        for p in poms.values():                      # the shallowest pom wins a duplicate coordinate
            key = f"{p.group}:{p.artifact}"
            if key not in self.by_ga or p.path.count("/") < self.by_ga[key].path.count("/"):
                self.by_ga[key] = p

    def chain(self, pom: Pom) -> list[Pom]:
        """The pom and its in-repo parents, nearest first."""
        out, seen = [pom], {pom.path}
        while out[-1].parent:
            nxt = self.by_ga.get(f"{out[-1].parent[0]}:{out[-1].parent[1]}")
            if nxt is None or nxt.path in seen:
                break
            out.append(nxt)
            seen.add(nxt.path)
        return out

    def properties(self, pom: Pom) -> dict[str, str]:
        props: dict[str, str] = {}
        chain = self.chain(pom)
        for p in reversed(chain):                    # the child overrides its parents
            props.update(p.props)
        props.update({"project.version": pom.version, "pom.version": pom.version, "version": pom.version,
                      "project.groupId": pom.group, "project.artifactId": pom.artifact})
        if len(chain) > 1:
            props["project.parent.version"] = chain[1].version
            props["project.parent.groupId"] = chain[1].group
        return props

    def expand(self, raw: str, props: dict[str, str]) -> str:
        value = raw
        for _ in range(10):                          # nested properties, bounded
            new = _PROP.sub(lambda m: props.get(m.group(1), m.group(0)), value)
            if new == value:
                break
            value = new
        return value

    def managed_version(self, pom: Pom, ga: str, depth: int = 0) -> tuple[str, str] | None:
        """(version, declaring pom path) that `pom` would use for `ga` from dependencyManagement, or None."""
        if depth > 5:
            return None
        props = self.properties(pom)
        for p in self.chain(pom):
            if ga in p.managed:
                version = self.expand(p.managed[ga], props)
                return (version, p.path) if not version_unresolved(version) else None
            for g, a in p.imports:                   # only BOMs that live in this repository
                bom = self.by_ga.get(f"{g}:{a}")
                if bom is not None and bom is not pom:
                    found = self.managed_version(bom, ga, depth + 1)
                    if found:
                        return found
        return None

    def resolve(self, pom: Pom, ga: str, current: str) -> tuple[str, str] | None:
        """A resolved version for dependency `ga` of `pom`, or None."""
        if current and "${" in current:
            version = self.expand(current, self.properties(pom))
            if not version_unresolved(version):
                return version, pom.path
        raw = pom.deps.get(ga)
        if raw:
            version = self.expand(raw, self.properties(pom))
            if not version_unresolved(version):
                return version, pom.path
        return self.managed_version(pom, ga)


def _versioned(purl: str, version: str) -> str:
    """The purl with `version` (any version it had, such as `${x}`, replaced; qualifiers kept)."""
    base, sep, query = purl.partition("?")
    head, at, tail = base.rpartition("@")
    if at and "/" not in tail:
        base = head
    return f"{base}@{version}" + (sep + query if sep else "")


def _entry_locations(entry: dict) -> list[str]:
    return sorted({(p.get("value") or "").lstrip("/") for p in entry.get("properties") or []
                   if str(p.get("name", "")).startswith("syft:location:") and str(p.get("name")).endswith(":path")})


def resolve_managed(src: Path, bom: dict, packages: list[Component]) -> int:
    """Fill in Maven versions Syft left unresolved, in `bom` (the Syft document osv-scanner reads) and in
    `packages`. Returns how many components were resolved. Never raises for a malformed pom."""
    todo = [c for c in packages if c.ecosystem == "Maven" and version_unresolved(c.version) and c.locations]
    if not todo:
        return 0
    poms = index(src)
    if not poms:
        return 0
    resolver = Resolver(poms)
    resolved: dict[tuple[str, tuple[str, ...]], tuple[str, str]] = {}
    for c in todo:
        group = purl_namespace(c.purl)
        pom = next((poms[loc] for loc in c.locations if loc in poms), None)
        if not group or pom is None:
            continue
        found = resolver.resolve(pom, f"{group}:{c.name}", c.version)
        if not found:
            continue
        version, declared = found
        old_purl = c.purl
        c.version = version
        c.purl = _versioned(old_purl, version)
        c.props["version_source"] = f"{declared} (in-repo pom)"
        resolved[(old_purl, tuple(c.locations))] = (version, declared)
    for entry in bom.get("components") or []:
        key = (entry.get("purl", ""), tuple(_entry_locations(entry)))
        if key not in resolved:
            continue
        version, declared = resolved[key]
        entry["version"] = version
        entry["purl"] = _versioned(entry["purl"], version)
        props = entry.setdefault("properties", [])
        props.append({"name": SOURCE_PROPERTY, "value": f"{declared} (in-repo pom)"})
    return len(resolved)
