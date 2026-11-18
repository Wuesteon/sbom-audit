"""CycloneDX helpers: merge own components into a Syft document, write, read back."""
from __future__ import annotations

import json
from pathlib import Path

from . import __version__
from .model import Component
from .syft import ECOSYSTEM_BY_PURL_TYPE, SCOPE_PROPERTY, purl_type

PREFIX = "sbom-audit:"
TYPE_BY_KIND = {"image": "container", "runtime": "platform", "package": "library"}
LIST_PROPS = {"unpinned_requirements"}
BOOL_PROPS = {"floating", "own", "digest", "unresolved", "imported", "not_in_build_sbom"}
# Set on a repository-scan package that an imported build SBOM of its ecosystem does not name: kept, not dropped
NOT_IN_BUILD_SBOM = "not_in_build_sbom"


def empty_bom() -> dict:
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
        "metadata": {}, "components": [],
    }


def _prop(name: str, value) -> dict:
    if isinstance(value, bool):
        value = "true" if value else "false"
    elif isinstance(value, list):
        value = ",".join(str(v) for v in value)
    return {"name": PREFIX + name, "value": str(value)}


def _entry(c: Component) -> dict:
    """A CycloneDX component for an own-reader Component."""
    props = [_prop("kind", c.kind), _prop("ecosystem", c.ecosystem), _prop("scope", c.scope)]
    for i, loc in enumerate(c.locations):
        props.append(_prop(f"location:{i}", loc))
    if c.direct is not None:
        props.append(_prop("direct", c.direct))
    for key in sorted(c.props):
        props.append(_prop(key, c.props[key]))
    entry = {
        "bom-ref": c.purl + "?sbom-audit=" + "|".join(c.locations),
        "type": TYPE_BY_KIND.get(c.kind, "library"),
        "name": c.name,
        "purl": c.purl,
        "properties": props,
    }
    if c.version:
        entry["version"] = c.version
    return entry


def merge(bom: dict, extra: list[Component]) -> dict:
    """Append own-reader components; the document is modified in place and returned."""
    comps = bom.setdefault("components", [])
    seen = {e.get("bom-ref") for e in comps}
    for c in extra:
        entry = _entry(c)
        if entry["bom-ref"] in seen:
            continue
        seen.add(entry["bom-ref"])
        comps.append(entry)
    tools = bom.setdefault("metadata", {}).setdefault("tools", {}).setdefault("components", [])
    if not any(t.get("name") == "sbom-audit" for t in tools):
        tools.append({"type": "application", "name": "sbom-audit", "version": __version__,
                      "author": "Nils Weiser"})
    return bom


def mark_direct(bom: dict, is_direct) -> None:
    """Add `sbom-audit:direct` to every package entry; `is_direct(entry) -> bool | None`."""
    for entry in bom.get("components", []) or []:
        if not entry.get("purl"):
            continue
        props = entry.setdefault("properties", [])
        if any(p.get("name") == PREFIX + "kind" for p in props):
            continue
        value = is_direct(entry)
        props[:] = [p for p in props if p.get("name") != PREFIX + "direct"]
        if value is not None:
            props.append(_prop("direct", value))


def mark_scope(bom: dict, scope_of) -> None:
    """Overwrite `sbom-audit:scope` on Syft package entries where `scope_of(entry)` returns a scope; None
    keeps the scope `syft.inventory` set."""
    for entry in bom.get("components", []) or []:
        if not entry.get("purl"):
            continue
        props = entry.setdefault("properties", [])
        if any(p.get("name") == PREFIX + "kind" for p in props):
            continue
        value = scope_of(entry)
        if value is None:
            continue
        props[:] = [p for p in props if p.get("name") != SCOPE_PROPERTY]
        props.append({"name": SCOPE_PROPERTY, "value": value})


def mark_not_in_build_sbom(bom: dict, should_mark) -> None:
    """Add `sbom-audit:not_in_build_sbom` = true to the Syft package entries where `should_mark(entry)`."""
    for entry in bom.get("components", []) or []:
        if not entry.get("purl") or not should_mark(entry):
            continue
        props = entry.setdefault("properties", [])
        if any(p.get("name") == PREFIX + "kind" for p in props):
            continue
        props[:] = [p for p in props if p.get("name") != PREFIX + NOT_IN_BUILD_SBOM]
        props.append(_prop(NOT_IN_BUILD_SBOM, True))


def drop_components(bom: dict, should_drop, keep_ref: str | None = None) -> list[dict]:
    """Remove entries where `should_drop(entry)`; their dependency rows move to `keep_ref`."""
    comps = bom.get("components", []) or []
    dropped = [e for e in comps if should_drop(e)]
    if not dropped:
        return []
    refs = {e.get("bom-ref") for e in dropped}
    bom["components"] = [e for e in comps if e.get("bom-ref") not in refs]
    rows = bom.get("dependencies") or []
    merged: list[str] = []
    kept: list[dict] = []
    for row in rows:
        if row.get("ref") in refs:
            merged.extend(d for d in row.get("dependsOn", []) if d not in refs)
            continue
        row["dependsOn"] = [d for d in row.get("dependsOn", []) if d not in refs]
        kept.append(row)
    if keep_ref and merged:
        existing = next((r for r in kept if r.get("ref") == keep_ref), None)
        if existing is None:
            existing = {"ref": keep_ref, "dependsOn": []}
            kept.insert(0, existing)
        for d in merged:
            if d not in existing["dependsOn"]:
                existing["dependsOn"].append(d)
    if rows or kept:
        bom["dependencies"] = kept
    return dropped


def set_subject(bom: dict, name: str, purl: str, version: str) -> str:
    """metadata.component := the project; returns its bom-ref."""
    ref = purl
    bom.setdefault("metadata", {})["component"] = {
        "bom-ref": ref, "type": "application", "name": name, "version": version, "purl": purl,
    }
    return ref


def set_package_source(bom: dict, src: dict) -> None:
    """Record an imported build SBOM in `metadata.properties` (`sbom-audit:package_source:<key>`)."""
    props = bom.setdefault("metadata", {}).setdefault("properties", [])
    props[:] = [p for p in props if not str(p.get("name", "")).startswith(PREFIX + "package_source")]
    props.append(_prop("package_source", src.get("kind", "import")))
    for key in ("file", "in", "sha256", "spec_version", "tool", "timestamp", "commit", "commit_from", "stale",
                "replaced", "direct_from", "packages", "kept_from_scan", "kept_unresolved", "replaced_entries"):
        value = src.get(key)
        if value is not None and value != "":
            props.append(_prop(f"package_source:{key}", value))


def write(bom: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bom, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _props(entry: dict) -> dict[str, str]:
    return {p.get("name", ""): p.get("value", "") for p in entry.get("properties", []) or []}


def _own_component(entry: dict, props: dict[str, str]) -> Component:
    own: dict = {}
    locations: list[str] = []
    direct = None
    for name, value in props.items():
        if not name.startswith(PREFIX):
            continue
        key = name[len(PREFIX):]
        if key in ("kind", "ecosystem", "scope"):
            continue
        if key.startswith("location:"):
            locations.append((int(key.split(":")[1]), value))
        elif key == "direct":
            direct = value == "true"
        elif key in BOOL_PROPS:
            own[key] = value == "true"
        elif key in LIST_PROPS:
            own[key] = [v for v in value.split(",") if v]
        else:
            own[key] = value
    return Component(
        kind=props[PREFIX + "kind"], ecosystem=props.get(PREFIX + "ecosystem", ""),
        name=entry.get("name", ""), version=entry.get("version", "") or "",
        purl=entry.get("purl", ""), scope=props.get(PREFIX + "scope", "unknown") or "unknown",
        locations=[loc for _, loc in sorted(locations)], direct=direct, props=own,
    )


def _syft_component(entry: dict, props: dict[str, str]) -> Component:
    purl = entry["purl"]
    locations = sorted({v.lstrip("/") for k, v in props.items()
                        if k.startswith("syft:location:") and k.endswith(":path") and v})
    extra = {}
    if props.get("syft:package:foundBy"):
        extra["found_by"] = props["syft:package:foundBy"]
    if props.get(PREFIX + NOT_IN_BUILD_SBOM) == "true":
        extra[NOT_IN_BUILD_SBOM] = True
    direct_raw = props.get(PREFIX + "direct")
    return Component(
        kind="package", ecosystem=ECOSYSTEM_BY_PURL_TYPE.get(purl_type(purl), purl_type(purl)),
        name=entry.get("name", ""), version=entry.get("version", "") or "", purl=purl,
        scope=props.get(SCOPE_PROPERTY, "unknown") or "unknown", locations=locations,
        direct=None if direct_raw is None else direct_raw == "true", props=extra,
    )


def components(bom: dict) -> list[Component]:
    out: list[Component] = []
    for entry in bom.get("components", []) or []:
        if not entry.get("purl"):
            continue
        props = _props(entry)
        if PREFIX + "kind" in props:
            out.append(_own_component(entry, props))
        else:
            out.append(_syft_component(entry, props))
    return out


def read(path: Path) -> dict:
    with path.open("rb") as fh:
        return json.load(fh)


def read_components(path: Path) -> list[Component]:
    return components(read(path))
