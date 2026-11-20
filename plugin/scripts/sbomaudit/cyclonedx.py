"""CycloneDX helpers: merge own components into a Syft document, write, read back."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .model import Component
from .syft import ECOSYSTEM_BY_PURL_TYPE, SCOPE_PROPERTY, purl_type

PREFIX = "sbom-audit:"
TYPE_BY_KIND = {"image": "container", "runtime": "platform", "package": "library"}
LIST_PROPS = {"unpinned_requirements", "gradle_unversioned"}
BOOL_PROPS = {"floating", "own", "digest", "unresolved", "imported", "not_in_build_sbom"}
# Set on a repository-scan package that an imported build SBOM of its ecosystem does not name: kept, not dropped
NOT_IN_BUILD_SBOM = "not_in_build_sbom"


def empty_bom() -> dict:
    """The document written when Syft fails: own-reader components only, with the same header Syft writes."""
    bom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
        "metadata": {}, "components": [],
    }
    ensure_header(bom)
    return bom


def ensure_header(bom: dict) -> None:
    """A `serialNumber` and `metadata.timestamp` where the document has none (both describe this document, not
    a component, so nothing is invented about the software)."""
    if not bom.get("serialNumber"):
        bom["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"
    meta = bom.setdefault("metadata", {})
    if not meta.get("timestamp"):
        meta["timestamp"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _prop(name: str, value) -> dict:
    if isinstance(value, bool):
        value = "true" if value else "false"
    elif isinstance(value, list):
        value = ",".join(str(v) for v in value)
    return {"name": PREFIX + name, "value": str(value)}


def bom_ref(c: Component) -> str:
    """The bom-ref `merge` writes an own-reader Component under."""
    return c.purl + "?sbom-audit=" + "|".join(c.locations)


def _entry(c: Component, spec: str = "") -> dict:
    """A CycloneDX component for an own-reader Component; an imported package also carries the fields of its
    build SBOM entry (`Component.cdx`, as far as the document's spec version defines them)."""
    props = [_prop("kind", c.kind), _prop("ecosystem", c.ecosystem), _prop("scope", c.scope)]
    for i, loc in enumerate(c.locations):
        props.append(_prop(f"location:{i}", loc))
    if c.direct is not None:
        props.append(_prop("direct", c.direct))
    for key in sorted(c.props):
        props.append(_prop(key, c.props[key]))
    entry = {
        "bom-ref": bom_ref(c),
        "type": TYPE_BY_KIND.get(c.kind, "library"),
        "name": c.name,
        "purl": c.purl,
        "properties": props,
    }
    if c.version:
        entry["version"] = c.version
    if c.cdx:
        from .sbomimport import for_spec
        for key, value in for_spec(c.cdx, spec).items():
            entry.setdefault(key, value)
    return entry


def merge(bom: dict, extra: list[Component]) -> dict:
    """Append own-reader components; the document is modified in place and returned."""
    comps = bom.setdefault("components", [])
    seen = {e.get("bom-ref") for e in comps}
    spec = str(bom.get("specVersion", ""))
    for c in extra:
        entry = _entry(c, spec)
        if entry["bom-ref"] in seen:
            continue
        seen.add(entry["bom-ref"])
        comps.append(entry)
    ensure_header(bom)
    meta = bom["metadata"]
    if isinstance(meta.get("tools"), list):         # legacy (spec 1.4) tool list: add an entry of that shape
        if not any(isinstance(t, dict) and t.get("name") == "sbom-audit" for t in meta["tools"]):
            meta["tools"].append({"vendor": "Nils Weiser", "name": "sbom-audit", "version": __version__})
        return bom
    tools = meta.setdefault("tools", {}).setdefault("components", [])
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


def annotate(bom: dict, notes_of) -> None:
    """Add places and properties another reader found to Syft package entries: `notes_of(entry)` returns None
    or (locations, {prop: value}); the locations are written as `sbom-audit:location:<i>`, next to Syft's own
    `syft:location:*` (`components` reads both back)."""
    for entry in bom.get("components", []) or []:
        if not entry.get("purl"):
            continue
        props = entry.setdefault("properties", [])
        if any(p.get("name") == PREFIX + "kind" for p in props):
            continue
        notes = notes_of(entry)
        if not notes:
            continue
        locations, extra = notes
        props[:] = [p for p in props if not str(p.get("name", "")).startswith(PREFIX + "location:")
                    and p.get("name") not in {PREFIX + k for k in extra}]
        for i, loc in enumerate(locations):
            props.append(_prop(f"location:{i}", loc))
        for key in sorted(extra):
            props.append(_prop(key, extra[key]))


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


def add_dependencies(bom: dict, rows: dict[str, list[str]]) -> int:
    """Add dependency rows (`ref` -> `dependsOn`), merged into an existing row of the same ref; returns how
    many edges were new. Only refs the document defines (a component or the subject) are written."""
    if not rows:
        return 0
    defined = {e.get("bom-ref") for e in bom.get("components", []) or [] if isinstance(e, dict)}
    defined.add(_dict(_dict(bom.get("metadata")).get("component")).get("bom-ref"))
    defined.discard(None)
    deps = bom.get("dependencies")
    if not isinstance(deps, list):
        deps = bom["dependencies"] = []
    index = {r.get("ref"): r for r in deps if isinstance(r, dict)}
    added = 0
    for ref, targets in rows.items():
        if ref not in defined:
            continue
        row = index.get(ref)
        if row is None:
            row = index[ref] = {"ref": ref, "dependsOn": []}
            deps.append(row)
        if not isinstance(row.get("dependsOn"), list):
            row["dependsOn"] = []
        have = set(row["dependsOn"])
        for t in targets:
            if t in defined and t not in have:
                have.add(t)
                row["dependsOn"].append(t)
                added += 1
    return added


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


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
                "replaced", "direct_from", "packages", "kept_from_scan", "kept_unresolved", "replaced_entries",
                "resolved_by_import", "graph_edges", "graph_truncated"):
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
                        if k.startswith("syft:location:") and k.endswith(":path") and v}
                       | {v for k, v in props.items() if k.startswith(PREFIX + "location:") and v})
    extra = {}
    if props.get("syft:package:foundBy"):
        extra["found_by"] = props["syft:package:foundBy"]
    if props.get(PREFIX + NOT_IN_BUILD_SBOM) == "true":
        extra[NOT_IN_BUILD_SBOM] = True
    if props.get(PREFIX + "gradle_unversioned"):
        extra["gradle_unversioned"] = [v for v in props[PREFIX + "gradle_unversioned"].split(",") if v]
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
