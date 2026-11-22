"""Run Syft on an exported tree and read its CycloneDX output into Components.

Verified against Syft 1.56.0 (2026-11-05):
- npm devDependencies are left out by default; SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true
  adds them. `inventory()` runs Syft twice and labels the difference as dev-only (scope
  "optional"). Other ecosystems get "required" from the production run; scan.py then marks
  Maven dependencies declared only with `<scope>test</scope>` as "optional" (readers.dev_only_deps).
- Maven: the java-pom-cataloger lists the dependencies declared in each pom.xml (not
  <dependencyManagement>, no transitive resolution without network), one entry per purl, plus the
  reactor's own modules, which scan.py drops. Syft carries no Maven scope.
- A package.json without a lockfile yields no components; readers.py covers that case.
- The CycloneDX document also lists the scanned files (type "file", no purl) and the
  project's own package (e.g. pkg:npm/<name>@<version>); callers drop the latter via
  `self_keys`.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from .errors import ToolError
from .model import Component

ECOSYSTEM_BY_PURL_TYPE = {
    "npm": "npm",
    "pypi": "PyPI",
    "cocoapods": "cocoapods",
    "swift": "swift",
    "golang": "Go",
    "gem": "RubyGems",
    "cargo": "crates.io",
    "maven": "Maven",
    "nuget": "NuGet",
    "hex": "Hex",
    "pub": "Pub",
    "composer": "Packagist",
    "deno": "deno",
}
SCOPE_PROPERTY = "sbom-audit:scope"
SYFT_TIMEOUT = 1800   # seconds, one syft run over one exported branch


def purl_type(purl: str) -> str:
    body = purl[4:] if purl.startswith("pkg:") else purl
    return body.split("/", 1)[0].lower()


def run(src: Path, include_dev: bool, exclude: list[str] | None = None) -> dict:
    """`syft scan dir:<src> -o cyclonedx-json`; returns the parsed document."""
    env = dict(os.environ)
    env["SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES"] = "true" if include_dev else "false"
    env["SYFT_CHECK_FOR_APP_UPDATE"] = "false"
    cmd = ["syft", "scan", f"dir:{src}", "-o", "cyclonedx-json", "-q"]
    for pattern in exclude or []:
        cmd += ["--exclude", pattern]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=SYFT_TIMEOUT)
    except FileNotFoundError as exc:
        raise ToolError("syft", None, "syft is not installed") from exc
    except subprocess.TimeoutExpired:
        raise ToolError("syft", None, f"timed out after {SYFT_TIMEOUT}s") from None
    if proc.returncode != 0:
        detail = (proc.stderr.strip().splitlines() or ["no output"])[-1]
        raise ToolError("syft", proc.returncode, detail)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ToolError("syft", proc.returncode, f"invalid JSON output: {exc}") from exc


def _locations(entry: dict) -> list[str]:
    paths = []
    for prop in entry.get("properties", []) or []:
        name = prop.get("name", "")
        if name.startswith("syft:location:") and name.endswith(":path"):
            path = prop.get("value", "").lstrip("/")
            if path and path not in paths:
                paths.append(path)
    return sorted(paths)


def components(bom: dict) -> list[Component]:
    """Every component with a purl, as a package Component (scope unknown)."""
    out: list[Component] = []
    for entry in bom.get("components", []) or []:
        purl = entry.get("purl")
        if not purl:
            continue
        ptype = purl_type(purl)
        props = {}
        for prop in entry.get("properties", []) or []:
            if prop.get("name") == SCOPE_PROPERTY:
                props["scope"] = prop.get("value")
            if prop.get("name") == "syft:package:foundBy":
                props["found_by"] = prop.get("value")
        out.append(Component(
            kind="package",
            ecosystem=ECOSYSTEM_BY_PURL_TYPE.get(ptype, ptype),
            name=entry.get("name", ""),
            version=entry.get("version", "") or "",
            purl=purl,
            scope=props.pop("scope", "unknown") or "unknown",
            locations=_locations(entry),
            direct=None,
            props=props,
        ))
    return out


def _ident(c: Component) -> tuple[str, tuple[str, ...]]:
    return (c.purl, tuple(c.locations))


def inventory(src: Path, exclude: list[str] | None = None) -> tuple[dict, list[Component]]:
    """Two Syft runs: everything (incl. dev) and production only.

    Returns the full document with a `sbom-audit:scope` property on each package
    component, and the matching Component list.
    """
    full = run(src, include_dev=True, exclude=exclude)
    prod = run(src, include_dev=False, exclude=exclude)
    prod_ids = {_ident(c) for c in components(prod)}
    comps = components(full)
    scope_by_purl: dict[tuple, str] = {}
    for c in comps:
        c.scope = "required" if _ident(c) in prod_ids else "optional"
        scope_by_purl[_ident(c)] = c.scope
    for entry in full.get("components", []) or []:
        purl = entry.get("purl")
        if not purl:
            continue
        scope = scope_by_purl.get((purl, tuple(_locations(entry))), "unknown")
        props = entry.setdefault("properties", [])
        props[:] = [p for p in props if p.get("name") != SCOPE_PROPERTY]
        props.append({"name": SCOPE_PROPERTY, "value": scope})
    return full, comps
