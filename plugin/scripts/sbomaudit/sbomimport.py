"""Imported build SBOMs: a CycloneDX JSON document from the build tool (or Syft run on a built artefact) used as
the package list of one project@branch or release tag, for each ecosystem (purl type) it contains.

Sources, the first that exists wins:
- `<out>/imports/<project>/<label>.cdx.json`, written by `import` with its provenance in `<label>.import.json`;
  `<label>` is the SBOM file's (`main`, `release__1`, `tags__v1.2.0`);
- `[projects."<name>"] sbom = "<path>"`, read from the exported tree of the scanned ref (never the working tree).

Verified 2026-11-18:
- CycloneDX Maven plugin 2.9.3 (Dependency-Track 5.2.1: the release asset `bom.json`, spec 1.4, and
  `makeAggregateBom`, spec 1.6): every dependency has `scope: required`; the reactor's own modules are components
  without a scope; `optional` only for `<optional>true</optional>` (or, with detectUnusedForOptionalScope, unused)
  dependencies; test scope is left out unless includeTestScope. A full `dependencies` graph whose root depends on
  the own modules.
- cyclonedx-npm 1.20: devDependencies carry the property `cdx:npm:package:development=true` and no scope; npm
  optionalDependencies get `scope: optional` although npm installs them in production.
  So `optional` is never read as dev-only here: only `excluded` and the npm development property are.
- Syft 1.56 on a fat JAR (`syft scan file:<jar>`): every embedded Maven package with its version, no scope, no
  graph from the subject (a file), duplicates per nested JAR.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

from . import readers, syft
from .errors import ToolError
from .model import Component

IMPORTS_DIR = "imports"
MAX_BYTES = 64 * 1024 * 1024
MAX_COMPONENTS = 200_000
MAX_DEPTH = 16              # nested `components` (assemblies)
MAX_FIELD = 4096            # purl, bom-ref
SPEC_VERSIONS = ("1.4", "1.5", "1.6", "1.7")
DEV_PROPERTY = "cdx:npm:package:development"
JSON_HINT = ("export CycloneDX JSON instead: CycloneDX Maven plugin `-DoutputFormat=json` (or "
             "<outputFormat>json</outputFormat>), cyclonedx-npm `--output-format JSON`, Syft `-o cyclonedx-json`")
_TYPE_RE = re.compile(r"^[a-z][a-z0-9.+-]{0,31}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")


class Rejected(ValueError):
    """The document cannot be used; the message says why (and, for another format, how to get CycloneDX JSON)."""


@dataclass
class Entry:
    ref: str
    component: Component


@dataclass
class Document:
    spec: str
    tool: str = ""                  # "name version" of the generating tools, as the document states them
    timestamp: str = ""
    subject_refs: set[str] = field(default_factory=set)    # metadata.component and its sub-components
    subject_purls: set[str] = field(default_factory=set)
    entries: list[Entry] = field(default_factory=list)
    graph: dict[str, list[str]] = field(default_factory=dict)
    skipped_no_purl: int = 0
    invalid: int = 0
    # set by `packages`: the import's bom-refs of the project's own modules, and every other kept bom-ref with
    # the package it became (duplicates merged)
    own_refs: set[str] = field(default_factory=set)
    by_ref: dict[str, Component] = field(default_factory=dict)


def label(branch: str) -> str:
    """The file name stem of a branch or release label (`tags/v1` -> `tags__v1`), as under `sbom/`."""
    return branch.replace("/", "__")


def import_path(out: Path, project: str, branch: str) -> Path:
    return Path(out) / IMPORTS_DIR / project / f"{label(branch)}.cdx.json"


def provenance_path(path: Path) -> Path:
    return path.with_name(path.name[:-len(".cdx.json")] + ".import.json")


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _obj(value) -> dict:
    return value if isinstance(value, dict) else {}


def _list(value) -> list:
    return value if isinstance(value, list) else []


def _text(value, limit: int = 256) -> str:
    return value[:limit] if isinstance(value, str) else ""


# --------------------------------------------------------------------------- fields carried through

MAX_ITEMS = 32              # hashes, licences, external references, urls and contacts per component
MAX_URL = 2048
MAX_EDGES = 10 * MAX_COMPONENTS
HASH_ALGS = frozenset(("MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512",
                       "BLAKE2b-256", "BLAKE2b-384", "BLAKE2b-512", "BLAKE3"))
_HASH_RE = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{96}|[0-9a-fA-F]{128})$")
_SPDX_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]{0,127}$")
# external reference types of CycloneDX 1.4; the 1.5/1.6 additions are kept only in a 1.6+ document
EXTREF_TYPES_14 = frozenset((
    "vcs", "issue-tracker", "website", "advisories", "bom", "mailing-list", "social", "chat", "documentation",
    "support", "distribution", "license", "build-meta", "build-system", "release-notes", "other"))
EXTREF_TYPES_16 = EXTREF_TYPES_14 | frozenset((
    "source-distribution", "distribution-intake", "security-contact", "model-card", "log", "configuration",
    "evidence", "formulation", "attestation", "threat-model", "adversary-model", "risk-assessment",
    "vulnerability-assertion", "exploitability-statement", "pentest-report", "static-analysis-report",
    "dynamic-analysis-report", "runtime-analysis-report", "component-analysis-report", "maturity-report",
    "certification-report", "codified-infrastructure", "quality-metrics", "poam", "electronic-signature",
    "digital-signature", "rfc-9116"))
SINCE_16 = ("manufacturer",)        # component fields that a CycloneDX document before 1.6 does not define


def _clean(value, limit: int) -> str:
    """A non-empty printable string of at most `limit` characters, else '' (never truncated: a cut hash, URL or
    licence expression would be a different value)."""
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        return ""
    return value if all(ch.isprintable() for ch in value) else ""


def _hash_list(value) -> list[dict]:
    out = []
    for h in _list(value)[:MAX_ITEMS]:
        h = _obj(h)
        alg, content = _clean(h.get("alg"), 16), _clean(h.get("content"), 128)
        if alg in HASH_ALGS and _HASH_RE.match(content):
            out.append({"alg": alg, "content": content})
    return out


def _licences(value) -> list[dict]:
    """CycloneDX `licenses`: either one SPDX expression, or licence entries (id, name, url, acknowledgement). An
    id that is not SPDX-shaped is kept as the name; licence text, bom-refs and anything else are left out."""
    items = [_obj(i) for i in _list(value)[:MAX_ITEMS]]
    for item in items:
        expression = _clean(item.get("expression"), 1024)
        if expression:
            out = {"expression": expression}
            if item.get("acknowledgement") in ("declared", "concluded"):
                out["acknowledgement"] = item["acknowledgement"]
            return [out]
    out = []
    for item in items:
        lic = _obj(item.get("license"))
        entry = {}
        lid, name = _clean(lic.get("id"), 128), _clean(lic.get("name"), 256)
        if lid and _SPDX_ID_RE.match(lid):
            entry["id"] = lid
        elif lid or name:
            entry["name"] = name or lid
        else:
            continue
        url = _clean(lic.get("url"), MAX_URL)
        if url:
            entry["url"] = url
        if lic.get("acknowledgement") in ("declared", "concluded"):
            entry["acknowledgement"] = lic["acknowledgement"]
        out.append({"license": entry})
    return out


def _party(value) -> dict:
    """An organizational entity: name, urls, contacts (name, email, phone); its bom-ref is left out."""
    party = _obj(value)
    out = {}
    name = _clean(party.get("name"), 256)
    if name:
        out["name"] = name
    urls = [u for u in (_clean(u, MAX_URL) for u in _list(party.get("url"))[:MAX_ITEMS]) if u]
    if urls:
        out["url"] = urls
    contacts = []
    for contact in _list(party.get("contact"))[:MAX_ITEMS]:
        contact = _obj(contact)
        kept = {k: v for k in ("name", "email", "phone") if (v := _clean(contact.get(k), 256))}
        if kept:
            contacts.append(kept)
    if contacts:
        out["contact"] = contacts
    return out


def _external_refs(value) -> list[dict]:
    out = []
    for ref in _list(value)[:MAX_ITEMS]:
        ref = _obj(ref)
        rtype, url = _clean(ref.get("type"), 40), _clean(ref.get("url"), MAX_URL)
        if rtype not in EXTREF_TYPES_16 or not url:
            continue
        entry = {"type": rtype, "url": url}
        comment = _clean(ref.get("comment"), 256)
        if comment:
            entry["comment"] = comment
        hashes = _hash_list(ref.get("hashes"))
        if hashes:
            entry["hashes"] = hashes
        out.append(entry)
    return out


def passthrough(entry: dict) -> dict:
    """The CycloneDX fields of an imported component that are written unchanged into the SBOM: group, publisher,
    hashes, licenses, supplier, manufacturer, cpe, externalReferences. Each value is type-checked and bounded;
    a value that fails a check is left out, never repaired or invented."""
    out: dict = {}
    for key, limit in (("group", 512), ("publisher", 256)):
        text = _clean(entry.get(key), limit)
        if text:
            out[key] = text
    cpe = _clean(entry.get("cpe"), 1024)
    if cpe.startswith("cpe:"):
        out["cpe"] = cpe
    for key, value in (("hashes", _hash_list(entry.get("hashes"))), ("licenses", _licences(entry.get("licenses"))),
                       ("supplier", _party(entry.get("supplier"))),
                       ("manufacturer", _party(entry.get("manufacturer"))),
                       ("externalReferences", _external_refs(entry.get("externalReferences")))):
        if value:
            out[key] = value
    return out


def for_spec(fields: dict, spec: str) -> dict:
    """`passthrough` fields fit for a document of CycloneDX `spec`: before 1.6 without manufacturer, licence
    acknowledgement and the external reference types 1.4 does not define."""
    if _spec_at_least(spec, "1.6"):
        return fields
    out = {k: v for k, v in fields.items() if k not in SINCE_16}
    if "licenses" in out:
        out["licenses"] = [{k: ({kk: vv for kk, vv in v.items() if kk != "acknowledgement"}
                                if isinstance(v, dict) else v)
                            for k, v in item.items() if k != "acknowledgement"} for item in out["licenses"]]
    if "externalReferences" in out:
        refs = [r for r in out["externalReferences"] if r["type"] in EXTREF_TYPES_14]
        if refs:
            out["externalReferences"] = refs
        else:
            del out["externalReferences"]
    return out


def _spec_at_least(spec, wanted: str) -> bool:
    try:
        return tuple(int(x) for x in str(spec).split(".")) >= tuple(int(x) for x in wanted.split("."))
    except ValueError:
        return False


# --------------------------------------------------------------------------- parsing

def purl_parts(purl: str) -> tuple[str, str, str] | None:
    """(type, name, version) of a purl, percent-decoded; the name as Syft writes it: the artifact for Maven
    (its group is the purl namespace), `namespace/name` otherwise (`@scope/x`, a Go module path). None when the
    text is not a usable purl."""
    if len(purl) > MAX_FIELD or not purl.startswith("pkg:") or any(ord(ch) < 32 for ch in purl):
        return None
    body = purl[4:].lstrip("/").split("#", 1)[0].split("?", 1)[0]
    ptype, sep, rest = body.partition("/")
    ptype = ptype.lower()
    if not sep or not _TYPE_RE.match(ptype):
        return None
    path, version = rest, ""
    head, at, tail = rest.rpartition("@")
    if at and head and "/" not in tail:
        path, version = head, tail
    segments = [unquote(s) for s in path.split("/") if s]
    if not segments:
        return None
    name = segments[-1] if ptype == "maven" else "/".join(segments)
    return ptype, name, unquote(version)


def _scope(entry: dict) -> str:
    """`optional` (dev-only) only on evidence: CycloneDX `excluded` or the npm development property. CycloneDX
    `optional` is not dev-only (npm optionalDependencies, Maven <optional>), so it stays `required`."""
    if entry.get("scope") == "excluded":
        return "optional"
    for prop in _list(entry.get("properties")):
        if _obj(prop).get("name") == DEV_PROPERTY and _obj(prop).get("value") == "true":
            return "optional"
    return "required"


def _tools(meta: dict) -> str:
    tools = meta.get("tools")
    if isinstance(tools, dict):                 # 1.5+: {"components": [...], "services": [...]}
        tools = _list(tools.get("components")) + _list(tools.get("services"))
    names = []
    for tool in _list(tools)[:5]:
        tool = _obj(tool)
        text = " ".join(t for t in (_text(tool.get("name"), 80), _text(tool.get("version"), 40)) if t)
        if text:
            names.append(text)
    return ", ".join(names)


def _walk(items, depth: int = 0):
    """Every component dict, nested `components` included (depth-limited)."""
    for item in _list(items):
        yield item
        if isinstance(item, dict) and depth < MAX_DEPTH:
            yield from _walk(item.get("components"), depth + 1)


def _subject(meta: dict, doc: Document) -> None:
    root = meta.get("component")
    if not isinstance(root, dict):
        return
    for c in [root, *_walk(root.get("components"))]:
        c = _obj(c)
        if _text(c.get("bom-ref"), MAX_FIELD):
            doc.subject_refs.add(c["bom-ref"])
        if _text(c.get("purl"), MAX_FIELD):
            doc.subject_purls.add(c["purl"])


def parse(raw: bytes) -> Document:
    """A CycloneDX JSON document (spec 1.4 to 1.7) as a Document; Rejected for anything else. Components without
    a purl are counted and skipped, malformed ones counted as invalid; nothing in the input is trusted."""
    if len(raw) > MAX_BYTES:
        raise Rejected(f"{len(raw)} bytes, larger than the {MAX_BYTES} byte limit")
    head = raw[:1024].lstrip(b"\xef\xbb\xbf \t\r\n")
    if head.startswith(b"<"):
        raise Rejected(f"XML is not supported; {JSON_HINT}")
    if head.startswith(b"SPDXVersion"):
        raise Rejected(f"SPDX is not supported; {JSON_HINT}")
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise Rejected(f"not valid JSON ({type(exc).__name__})") from None
    if not isinstance(data, dict):
        raise Rejected("not a JSON object")
    if "spdxVersion" in data or "SPDXID" in data:
        raise Rejected(f"SPDX is not supported; {JSON_HINT}")
    if data.get("bomFormat") != "CycloneDX":
        raise Rejected("not a CycloneDX document (bomFormat is not \"CycloneDX\")")
    spec = data.get("specVersion")
    if spec not in SPEC_VERSIONS:
        raise Rejected(f"CycloneDX specVersion {_text(spec, 20) or '?'} is not supported "
                       f"({SPEC_VERSIONS[0]} to {SPEC_VERSIONS[-1]})")
    meta = _obj(data.get("metadata"))
    doc = Document(spec=spec, tool=_tools(meta), timestamp=_text(meta.get("timestamp"), 64))
    _subject(meta, doc)
    count = 0
    for entry in _walk(data.get("components")):
        count += 1
        if count > MAX_COMPONENTS:
            raise Rejected(f"more than {MAX_COMPONENTS} components")
        if not isinstance(entry, dict):
            doc.invalid += 1
            continue
        purl = entry.get("purl")
        if not isinstance(purl, str) or not purl:
            doc.skipped_no_purl += 1
            continue
        parts = purl_parts(purl)
        version = entry.get("version")
        if parts is None or (version is not None and not isinstance(version, str)):
            doc.invalid += 1
            continue
        ptype, name, purl_version = parts
        version = purl_version or version or ""
        if len(name) > 512 or len(version) > 256:
            doc.invalid += 1
            continue
        ref = _text(entry.get("bom-ref"), MAX_FIELD) or purl
        doc.entries.append(Entry(ref=ref, component=Component(
            kind="package", ecosystem=syft.ECOSYSTEM_BY_PURL_TYPE.get(ptype, ptype), name=name, version=version,
            purl=purl, scope=_scope(entry), locations=[], direct=None, props={"imported": True},
            cdx=passthrough(entry))))
    for row in _list(data.get("dependencies")):
        row = _obj(row)
        ref = _text(row.get("ref"), MAX_FIELD)
        if ref:
            doc.graph.setdefault(ref, []).extend(d for d in _list(row.get("dependsOn")) if isinstance(d, str))
    return doc


# --------------------------------------------------------------------------- packages

def _key(c: Component) -> tuple[str, str]:
    return (c.ecosystem, readers.package_key(c.ecosystem, c.name, c.purl))


def packages(doc: Document, own: set[tuple[str, str]],
             direct_fallback: dict[tuple[str, str], list[str]]) -> tuple[list[Component], str]:
    """The document's package components without the project's own modules (its subject and sub-modules, and
    `own` from `readers.self_packages`), one per package version, and how `direct` was decided: "graph" when
    the root or an own module depends on it in the document's `dependencies`, else "manifests"
    (`readers.direct_deps`, None for an ecosystem it does not read). Never a guessed "transitive"."""
    own_refs = set(doc.subject_refs)
    for e in doc.entries:
        if _key(e.component) in own or e.component.purl in doc.subject_purls:
            own_refs.add(e.ref)
    kept = [e for e in doc.entries if e.ref not in own_refs]
    direct_refs = {d for r in own_refs for d in doc.graph.get(r, [])} - own_refs
    via = "graph" if direct_refs & {e.ref for e in kept} else "manifests"
    merged: dict[tuple, Component] = {}
    doc.own_refs, doc.by_ref = own_refs, {}
    for e in kept:
        c = e.component
        if via == "graph":
            c.direct = e.ref in direct_refs
        else:
            c.direct = _key(c) in direct_fallback if c.ecosystem in readers.DIRECT_ECOSYSTEMS else None
        key = (c.ecosystem, c.name, c.version, c.purl.split("?", 1)[0].split("#", 1)[0])
        seen = merged.get(key)
        if seen is None:
            merged[key] = c
            doc.by_ref[e.ref] = c
            continue
        doc.by_ref[e.ref] = seen
        if seen.direct is None or c.direct:
            seen.direct = c.direct if seen.direct is None else True
        if c.scope == "required":
            seen.scope = "required"
        for name, value in c.cdx.items():           # a field only the duplicate carries is kept, never mixed
            seen.cdx.setdefault(name, value)
    return list(merged.values()), via


def graph_rows(doc: Document, ref_of, subject_ref: str) -> tuple[dict[str, list[str]], bool]:
    """The import's dependency graph in the written SBOM's bom-refs, and whether it was cut at MAX_EDGES.
    `ref_of(component)` is the bom-ref a kept package was written under (None when it was not written). The
    project's own modules become the subject `subject_ref`; an edge through a component that was not written
    (no purl, malformed) is followed through it, so no dependency path is lost; edges between own modules and
    self-loops are left out. Call after `packages`."""
    target: dict[str, str | None] = {ref: subject_ref for ref in doc.own_refs}
    for ref, comp in doc.by_ref.items():
        target[ref] = ref_of(comp)
    passed: dict[str, set[str]] = {}

    def reach(start: str) -> set[str]:
        """The written refs reached from `start`, passing through refs that were not written."""
        if target.get(start):
            return {target[start]}
        if start in passed:
            return passed[start]
        found: set[str] = set()
        stack, seen = [start], {start}
        while stack and len(seen) <= MAX_COMPONENTS:
            for d in doc.graph.get(stack.pop(), []):
                if target.get(d):
                    found.add(target[d])
                elif d not in seen:
                    seen.add(d)
                    stack.append(d)
        passed[start] = found
        return found

    rows: dict[str, list[str]] = {}
    edges = 0
    for ref, deps in doc.graph.items():
        source = target.get(ref)
        if not source:
            continue
        row = rows.setdefault(source, [])
        for d in deps:
            for t in sorted(reach(d)):
                if t == source or t in row:
                    continue
                edges += 1
                if edges > MAX_EDGES:
                    return rows, True
                row.append(t)
    return rows, False


# --------------------------------------------------------------------------- sources

def read_provenance(path: Path) -> dict:
    try:
        data = json.loads(provenance_path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def find(out: Path, project: str, branch: str, tree: Path, config_path: str | None) -> tuple[Path, str, bool] | None:
    """(file, path as reported, from the evidence folder) of the import for project@branch, or None. The
    evidence-folder file wins over the config path, which is read from the exported tree `tree` (a regular file
    inside it; Rejected otherwise)."""
    path = import_path(out, project, branch)
    if path.is_file():
        return path, path.relative_to(out).as_posix(), True
    if config_path:
        found = readers._inside_file(tree.resolve(), tree / config_path)
        if found is None:
            raise Rejected(f"`{config_path}` (config `sbom`) is not a file in the tree at this commit")
        return found, config_path, False
    return None


def read_capped(path: Path) -> bytes:
    if path.stat().st_size > MAX_BYTES:
        raise Rejected(f"{path.stat().st_size} bytes, larger than the {MAX_BYTES} byte limit")
    return path.read_bytes()


def source(doc: Document, raw: bytes, where: str, from_evidence: bool, provenance: dict, commit: str,
           last_change: str | None = None) -> dict:
    """The `package_source` of an inventory built from an import. `commit` is the scanned commit. The import's
    own commit comes from its provenance (an evidence-folder file whose sha256 still matches it); for a file
    committed in the repository (config `sbom`) it is `last_change`, the last commit on the audited branch that
    changed the file (`commit_from` says which). `stale` is True when that commit differs from the scanned
    one, None when it is not recorded."""
    digest = hashlib.sha256(raw).hexdigest()
    recorded, how = None, None
    if from_evidence and provenance.get("sha256") == digest and isinstance(provenance.get("commit"), str):
        recorded = provenance["commit"] if _SHA_RE.match(provenance["commit"]) else None
        how = "provenance" if recorded else None
    elif not from_evidence and isinstance(last_change, str) and _SHA_RE.match(last_change):
        recorded, how = last_change, "git history"
    return {"kind": "import", "file": where, "in": "evidence" if from_evidence else "repository",
            "sha256": digest, "spec_version": doc.spec, "tool": doc.tool, "timestamp": doc.timestamp,
            "commit": recorded, "commit_from": how,
            "stale": None if recorded is None else recorded != commit,
            "imported_at": provenance.get("imported_at") if recorded and from_evidence else None}


def staleness(src: dict | None) -> str:
    """'' for a current import or a repository scan; else what makes it not this commit's, in English."""
    if not src or src.get("kind") != "import":
        return ""
    if src.get("commit") is None:
        return "commit not recorded"
    if src.get("stale"):
        if src.get("commit_from") == "git history":
            return f"file last changed in commit {src['commit'][:7]}, not the scanned one"
        return f"built from commit {src['commit'][:7]}, not the scanned one"
    return ""


KEPT_LISTED = 20       # kept packages named in the one-line description; the rest are counted


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def describe(src: dict) -> str:
    """One line on an imported package list (Markdown-safe text is the caller's job): the ecosystems it covers,
    how many packages came from it, how many the repository scan kept because the build SBOM does not name them
    (listed), and how many repository entries it replaced."""
    ecosystems = ", ".join(src.get("replaced") or []) or "no ecosystem"
    where = "" if src.get("in") == "evidence" else " (committed in the repository)"
    bits = [f"imported build SBOM `{src.get('file')}`{where} for {ecosystems}"]
    if src.get("packages") is not None:
        bits.append(f"{_plural(src['packages'], 'package', 'packages')} from the import")
    if src.get("kept_from_scan") is not None:
        unresolved = src.get("kept_unresolved") or 0
        text = f"{src['kept_from_scan']} kept from the repository scan (not in the build SBOM"
        text += f", {unresolved} with version not resolved)" if unresolved else ")"
        kept = [str(k) for k in src.get("kept") or []]
        if kept:
            more = len(kept) - KEPT_LISTED
            text += ": " + ", ".join(kept[:KEPT_LISTED]) + (f" and {more} more" if more > 0 else "")
        bits.append(text)
    if src.get("replaced_entries") is not None:
        text = _plural(src["replaced_entries"], "repository entry replaced", "repository entries replaced")
        if src.get("resolved_by_import"):
            text += f" ({src['resolved_by_import']} of them without a version in the repository, versioned by the import)"
        bits.append(text)
    if src.get("graph_edges") is not None:
        bits.append(f"its dependency graph kept ({_plural(src['graph_edges'], 'edge', 'edges')}"
                    + (f", cut at {MAX_EDGES})" if src.get("graph_truncated") else ")"))
    if src.get("tool"):
        bits.append(f"by {src['tool']}")
    if src.get("timestamp"):
        bits.append(f"generated {src['timestamp']}")
    bits.append(f"sha256 {str(src.get('sha256', ''))[:12]}")
    current = (f"committed in {str(src.get('commit'))[:7]} (the scanned commit)"
               if src.get("commit_from") == "git history" else f"commit {str(src.get('commit'))[:7]} (current)")
    bits.append(staleness(src) or current)
    if src.get("skipped_no_purl"):
        bits.append(f"{src['skipped_no_purl']} components without purl skipped")
    if src.get("invalid"):
        bits.append(f"{src['invalid']} malformed components skipped")
    return "; ".join(bits)


# --------------------------------------------------------------------------- the `import` command

def write_import(out: Path, project: str, branch: str, raw: bytes, commit: str | None,
                 from_artifact: str | None = None) -> tuple[Path, dict]:
    """Validate `raw` and copy it to the convention path with its provenance next to it."""
    doc = parse(raw)
    if not doc.entries:
        raise Rejected("no component with a usable purl")
    path = import_path(out, project, branch)
    prov = {"sha256": hashlib.sha256(raw).hexdigest(), "spec_version": doc.spec, "tool": doc.tool,
            "timestamp": doc.timestamp, "commit": commit, "imported_at": _now(),
            "components": len(doc.entries), "skipped_no_purl": doc.skipped_no_purl, "invalid": doc.invalid}
    if from_artifact:
        prov["from_artifact"] = True
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    provenance_path(path).write_text(json.dumps(prov, indent=1) + "\n", encoding="utf-8")
    return path, prov


SYFT_TIMEOUT = 3600   # seconds; an image artefact may have to be pulled first


def syft_artifact(target: str) -> bytes:
    """`syft scan <target> -o cyclonedx-json`: a file or directory as such, anything else as an image ref."""
    if target.startswith("-"):
        raise Rejected("the artefact must not start with '-'")
    p = Path(target)
    arg = f"file:{p}" if p.is_file() else f"dir:{p}" if p.is_dir() else target
    try:
        proc = subprocess.run(["syft", "scan", arg, "-o", "cyclonedx-json", "-q"], capture_output=True,
                              env={**os.environ, "SYFT_CHECK_FOR_APP_UPDATE": "false"}, timeout=SYFT_TIMEOUT)
    except FileNotFoundError as exc:
        raise ToolError("syft", None, "syft is not installed") from exc
    except subprocess.TimeoutExpired:
        raise ToolError("syft", None, f"timed out after {SYFT_TIMEOUT}s") from None
    if proc.returncode != 0:
        detail = (proc.stderr.decode(errors="replace").strip().splitlines() or ["no output"])[-1]
        raise ToolError("syft", proc.returncode, detail)
    return proc.stdout


def _resolve_commit(repo: Path, branch: str | None, tag: str | None, commit: str | None) -> str:
    from . import gitio
    if commit and commit.startswith("-"):
        raise gitio.GitError("a commit must not start with '-'")
    if commit:
        return gitio.git(repo, "rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}").strip()
    if tag:
        return gitio.git(repo, "rev-parse", "--verify", "--quiet", f"refs/tags/{tag}^{{commit}}").strip()
    return gitio.branch_ref(repo, branch)[1]


def cli(args) -> int:
    from . import config, gitio, releases
    cfg = config.load(args.out, root=args.root)
    projects = {p.name: p for p in config.discover(cfg)}
    project = projects.get(args.project)
    if project is None:
        print(f"import: project {args.project!r} not found under {cfg.root}", file=sys.stderr)
        return 2
    branch = releases.label(args.tag) if args.tag else args.branch
    if args.tag is None and args.branch not in gitio.pick_branches(project.path, [args.branch]):
        print(f"import: branch {args.branch!r} does not exist in {project.name}", file=sys.stderr)
        return 2
    try:
        commit = _resolve_commit(project.path, args.branch, args.tag, args.commit)
    except gitio.GitError:
        what = f"commit {args.commit!r}" if args.commit else f"tag {args.tag!r}" if args.tag else args.branch
        print(f"import: {what} not found in {project.name}", file=sys.stderr)
        return 2
    try:
        if args.from_artifact:
            raw = syft_artifact(args.from_artifact)
        else:
            raw = read_capped(Path(args.file))
        path, prov = write_import(cfg.out, project.name, branch, raw, commit, from_artifact=args.from_artifact)
    except (Rejected, ToolError, OSError) as exc:
        print(f"import: {exc}", file=sys.stderr)
        return 2
    print(f"imported {prov['components']} components ({prov['tool'] or 'tool not stated'}, CycloneDX "
          f"{prov['spec_version']}) for {project.name}@{branch} at {commit[:12]}: {path}")
    if prov["skipped_no_purl"] or prov["invalid"]:
        print(f"skipped {prov['skipped_no_purl']} without purl, {prov['invalid']} malformed")
    print("used by the next scan or run for the ecosystems it contains")
    return 0
