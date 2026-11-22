"""SBOM quality: is a CycloneDX JSON document structurally sound, and how complete are its data fields?

`check(data)` returns structural findings (level `error` or `warning`, a stable code, a short message, a count)
and a coverage table: how many components carry a version, a purl (or another unique identifier), a licence, a
hash and a supplier, whether a dependency graph is present and how many components it reaches, and whether the
SBOM names its author or tool, its timestamp and its subject with a version.

Explicit checks only (no JSON Schema): the fields below, as CycloneDX 1.4 to 1.7 define them. A document
without errors is not "valid CycloneDX" in the schema sense, only free of the errors checked here.

Nothing in the input is trusted: a size cap, a nesting cap, a component cap; wrong types are findings, never
exceptions. Findings are grouped per code (count plus the first examples), so a hostile document cannot make
the output grow without bound.

Which data fields of NTIA "The Minimum Elements for an SBOM" (2021) and BSI TR-03183-2 2.1.0 (2025) the coverage
columns correspond to: docs/reference.md, "SBOM quality".
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .errors import ConfigError
from .sbomimport import MAX_BYTES, MAX_COMPONENTS, MAX_DEPTH, MAX_FIELD, SPEC_VERSIONS, purl_parts

MAX_EDGES = 10 * MAX_COMPONENTS        # dependency rows plus dependsOn entries
EXAMPLES = 3
COMPONENT_TYPES = frozenset((
    "application", "framework", "library", "container", "platform", "operating-system", "device",
    "device-driver", "firmware", "file", "machine-learning-model", "data", "cryptographic-asset"))
_SERIAL_RE = re.compile(r"^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$")
# the per-component columns, in table order; `files` (type "file") are counted apart and are not in the base
FIELDS = ("version", "purl", "identifier", "licence", "hash", "supplier", "in_graph")
LABELS = {"version": "version", "purl": "purl", "identifier": "unique id", "licence": "licence", "hash": "hash",
          "supplier": "supplier", "in_graph": "in graph"}


def _obj(value) -> dict:
    return value if isinstance(value, dict) else {}


def _list(value) -> list:
    return value if isinstance(value, list) else []


def _str(value, limit: int = MAX_FIELD) -> str:
    """The text of a non-empty string field, else ''; never longer than `limit`."""
    return value.strip()[:limit] if isinstance(value, str) else ""


def _show(value, limit: int = 60) -> str:
    text = value if isinstance(value, str) else type(value).__name__
    text = "".join(ch if ch.isprintable() else "?" for ch in text[:limit])
    return text + ("…" if isinstance(value, str) and len(value) > limit else "")


class _Findings:
    def __init__(self) -> None:
        self.by_code: dict[str, dict] = {}

    def add(self, level: str, code: str, message: str, example: str = "") -> None:
        f = self.by_code.get(code)
        if f is None:
            f = self.by_code[code] = {"level": level, "code": code, "message": message, "count": 0, "examples": []}
        f["count"] += 1
        if example and len(f["examples"]) < EXAMPLES:
            f["examples"].append(example)

    def list(self) -> list[dict]:
        return sorted(self.by_code.values(), key=lambda f: (f["level"] != "error", f["code"]))


# --------------------------------------------------------------------------- per component

def _has_licence(c: dict) -> bool:
    for item in _list(c.get("licenses")):
        item = _obj(item)
        lic = _obj(item.get("license"))
        if _str(item.get("expression")) or _str(lic.get("id")) or _str(lic.get("name")):
            return True
    return False


def _hashes(c: dict) -> list[dict]:
    found = [_obj(h) for h in _list(c.get("hashes"))]
    for ref in _list(c.get("externalReferences")):
        found += [_obj(h) for h in _list(_obj(ref).get("hashes"))]
    return [h for h in found if _str(h.get("alg")) and _str(h.get("content"))]


def _has_party(value) -> bool:
    """An organizational entity (supplier, manufacturer) with a name, a url or a contact."""
    party = _obj(value)
    if _str(party.get("name")) or any(_str(u) for u in _list(party.get("url"))):
        return True
    return any(_str(_obj(p).get("name")) or _str(_obj(p).get("email")) for p in _list(party.get("contact")))


def _identifier(c: dict, purl_ok: bool) -> bool:
    return purl_ok or bool(_str(c.get("cpe")) or _str(_obj(c.get("swid")).get("tagId"))
                           or any(_str(i) for i in _list(c.get("omniborId")))
                           or any(_str(i) for i in _list(c.get("swhid"))))


def _walk(items, findings: _Findings, where: str, depth: int = 0):
    """(component, path) for every entry of `items`, nested `components` included, at most MAX_DEPTH deep."""
    for i, item in enumerate(_list(items)):
        path = f"{where}[{i}]"
        yield item, path
        if not isinstance(item, dict) or "components" not in item:
            continue
        if not isinstance(item["components"], list):
            findings.add("error", "component-components", "nested `components` is not a list", path)
        elif depth + 1 >= MAX_DEPTH:
            findings.add("warning", "nesting-too-deep",
                         f"components nested deeper than {MAX_DEPTH} levels were not checked", path)
        else:
            yield from _walk(item["components"], findings, path + ".components", depth + 1)


def _check_component(c, path: str, findings: _Findings, refs: dict, cov: dict) -> None:
    if not isinstance(c, dict):
        findings.add("error", "component-not-object", "a component is not a JSON object", path)
        return
    ctype = c.get("type")
    if not _str(ctype):
        findings.add("error", "component-type-missing", "a component has no `type`", path)
    elif ctype not in COMPONENT_TYPES:
        findings.add("error", "component-type-invalid", "a component `type` is not a CycloneDX type",
                     f"{path}: {_show(ctype)}")
    name = _str(c.get("name"))
    if not name:
        findings.add("error", "component-name-missing", "a component has no `name`", path)
    label = name[:80] or path
    _bom_ref(c, label, findings, refs)
    purl = c.get("purl")
    purl_ok = False
    if purl is not None:
        if isinstance(purl, str) and purl_parts(purl) is not None:
            purl_ok = True
        else:
            findings.add("error", "purl-syntax", "a `purl` is not a package URL (pkg:type/name@version)",
                         f"{label}: {_show(purl)}")
    if c.get("version") is not None and not isinstance(c.get("version"), str):
        findings.add("error", "version-type", "a component `version` is not a string", label)
    if ctype == "file":
        cov["files"] += 1
        return
    cov["components"] += 1
    cov["version"] += bool(_str(c.get("version")))
    cov["purl"] += purl_ok
    cov["identifier"] += _identifier(c, purl_ok)
    cov["licence"] += _has_licence(c)
    hashes = _hashes(c)
    cov["hash"] += bool(hashes)
    cov["sha512"] += any(_str(h.get("alg")).upper() == "SHA-512" for h in hashes)
    cov["supplier"] += _has_party(c.get("supplier")) or _has_party(c.get("manufacturer"))
    ref = c.get("bom-ref")
    if isinstance(ref, str) and ref:
        cov["_refs"].append(ref)


def _bom_ref(c: dict, label: str, findings: _Findings, refs: dict) -> None:
    if "bom-ref" not in c:
        return
    ref = c["bom-ref"]
    if not isinstance(ref, str) or not ref:
        findings.add("error", "bom-ref-type", "a `bom-ref` is not a non-empty string", label)
    elif len(ref) > MAX_FIELD:
        findings.add("error", "bom-ref-too-long", f"a `bom-ref` is longer than {MAX_FIELD} characters", label)
    elif ref in refs:
        findings.add("error", "bom-ref-duplicate", "a `bom-ref` occurs more than once", _show(ref, 120))
    else:
        refs[ref] = label


# --------------------------------------------------------------------------- document

def _check_header(data: dict, findings: _Findings) -> str:
    if data.get("bomFormat") != "CycloneDX":
        findings.add("error", "bom-format", "`bomFormat` is not \"CycloneDX\"", _show(data.get("bomFormat")))
    spec = data.get("specVersion")
    if spec not in SPEC_VERSIONS:
        findings.add("error", "spec-version",
                     f"`specVersion` is missing or not supported ({SPEC_VERSIONS[0]} to {SPEC_VERSIONS[-1]})",
                     _show(spec))
    serial = data.get("serialNumber")
    if serial is None:
        findings.add("warning", "serial-number-missing", "no `serialNumber` (urn:uuid:…) identifies this SBOM")
    elif not isinstance(serial, str) or not _SERIAL_RE.match(serial):
        findings.add("error", "serial-number-format", "`serialNumber` is not urn:uuid:<RFC 4122 UUID>",
                     _show(serial))
    version = data.get("version")
    if version is None:
        findings.add("warning", "version-missing", "no document `version`")
    elif isinstance(version, bool) or not isinstance(version, int) or version < 1:
        findings.add("error", "version-invalid", "document `version` is not an integer of 1 or more",
                     _show(str(version) if isinstance(version, (int, float)) else version))
    return spec if isinstance(spec, str) and spec in SPEC_VERSIONS else ""


def _check_metadata(data: dict, findings: _Findings, refs: dict, cov: dict) -> dict:
    """The subject (metadata.component) as checked, or {}."""
    meta = data.get("metadata")
    if meta is None:
        findings.add("warning", "metadata-missing", "no `metadata` (timestamp, tools, subject)")
        meta = {}
    elif not isinstance(meta, dict):
        findings.add("error", "metadata-type", "`metadata` is not a JSON object")
        meta = {}
    stamp = meta.get("timestamp")
    if stamp is None:
        findings.add("warning", "timestamp-missing", "no `metadata.timestamp`")
    elif not isinstance(stamp, str) or not _TIME_RE.match(stamp):
        findings.add("error", "timestamp-format", "`metadata.timestamp` is not an ISO 8601 date-time with zone",
                     _show(stamp))
    else:
        cov["timestamp"] = True
    tools = meta.get("tools")
    tool_names = []
    if tools is None:
        findings.add("warning", "tools-missing", "no `metadata.tools` names the generating tool")
    elif isinstance(tools, dict):           # 1.5+
        entries = tools.get("components", []), tools.get("services", [])
        if not all(isinstance(e, list) for e in entries):
            findings.add("error", "tools-type", "`metadata.tools.components` / `.services` is not a list")
        tool_names = [_str(_obj(t).get("name")) for e in entries for t in _list(e)]
    elif isinstance(tools, list):           # legacy (deprecated from 1.5)
        tool_names = [_str(_obj(t).get("name")) for t in tools]
    else:
        findings.add("error", "tools-type", "`metadata.tools` is neither an object nor a list")
    cov["tools"] = any(tool_names)
    cov["author"] = bool(cov["tools"] or any(_has_party(a) or _str(_obj(a).get("email"))
                                             for a in _list(meta.get("authors")))
                         or _has_party(meta.get("manufacturer")) or _has_party(meta.get("manufacture"))
                         or _has_party(meta.get("supplier")))
    subject = meta.get("component")
    if subject is None:
        findings.add("warning", "subject-missing", "no `metadata.component` names what this SBOM describes")
        return {}
    if not isinstance(subject, dict):
        findings.add("error", "subject-type", "`metadata.component` is not a JSON object")
        return {}
    if not _str(subject.get("type")) or subject.get("type") not in COMPONENT_TYPES:
        findings.add("error", "subject-type-invalid", "`metadata.component.type` is missing or not a CycloneDX type",
                     _show(subject.get("type")))
    if not _str(subject.get("name")):
        findings.add("error", "subject-name-missing", "`metadata.component` has no `name`")
    _bom_ref(subject, "metadata.component", findings, refs)
    cov["subject"] = bool(_str(subject.get("name")) and _str(subject.get("version")))
    for c, path in _walk(subject.get("components"), findings, "metadata.component.components"):
        if isinstance(c, dict):
            _bom_ref(c, _str(c.get("name"))[:80] or path, findings, refs)
    return subject


def _service_refs(items, findings: _Findings, refs: dict, depth: int = 0) -> None:
    for s in _list(items):
        if isinstance(s, dict):
            _bom_ref(s, _str(s.get("name"))[:80] or "service", findings, refs)
            if depth + 1 < MAX_DEPTH:
                _service_refs(s.get("services"), findings, refs, depth + 1)


def _check_dependencies(data: dict, findings: _Findings, refs: dict, cov: dict) -> set[str]:
    """Every ref the graph mentions (as `ref` or in `dependsOn`)."""
    rows = data.get("dependencies")
    seen: set[str] = set()
    if rows is None:
        return seen
    if not isinstance(rows, list):
        findings.add("error", "dependencies-type", "`dependencies` is not a list")
        return seen
    edges = 0
    own_rows: set[str] = set()
    for i, row in enumerate(rows):
        edges += 1
        if edges > MAX_EDGES:
            findings.add("error", "too-many-dependencies", f"more than {MAX_EDGES} dependency entries; rest not checked")
            break
        if not isinstance(row, dict):
            findings.add("error", "dependency-not-object", "a `dependencies` row is not a JSON object", f"[{i}]")
            continue
        ref = row.get("ref")
        if not isinstance(ref, str) or not ref:
            findings.add("error", "dependency-ref-type", "a `dependencies` row has no string `ref`", f"[{i}]")
        else:
            seen.add(ref)
            if ref not in refs:
                findings.add("error", "dependency-ref-dangling", "a `dependencies` row names an unknown bom-ref",
                             _show(ref, 120))
            if ref in own_rows:
                findings.add("warning", "dependency-ref-repeated", "a bom-ref has more than one `dependencies` row",
                             _show(ref, 120))
            own_rows.add(ref)
        targets = row.get("dependsOn", [])
        if not isinstance(targets, list):
            findings.add("error", "depends-on-type", "a `dependsOn` is not a list", f"[{i}]")
            continue
        for target in targets:
            edges += 1
            if edges > MAX_EDGES:
                break
            if not isinstance(target, str) or not target:
                findings.add("error", "depends-on-type", "a `dependsOn` entry is not a string", f"[{i}]")
                continue
            seen.add(target)
            if target not in refs:
                findings.add("error", "depends-on-dangling", "a `dependsOn` entry names an unknown bom-ref",
                             _show(target, 120))
    cov["graph"] = bool(rows)
    return seen


def _coverage() -> dict:
    return {"components": 0, "files": 0, **{k: 0 for k in FIELDS}, "sha512": 0, "graph": False,
            "compositions": False, "timestamp": False, "tools": False, "author": False, "subject": False,
            "_refs": []}


def check(data) -> dict:
    """Findings and coverage of a parsed CycloneDX JSON document (any JSON value; never raises on content)."""
    findings = _Findings()
    cov = _coverage()
    spec = ""
    if not isinstance(data, dict):
        findings.add("error", "not-object", "the document is not a JSON object")
    else:
        spec = _check_header(data, findings)
        refs: dict[str, str] = {}
        _check_metadata(data, findings, refs, cov)
        comps = data.get("components")
        if comps is not None and not isinstance(comps, list):
            findings.add("error", "components-type", "`components` is not a list")
        count = 0
        for c, path in _walk(comps, findings, "components"):
            count += 1
            if count > MAX_COMPONENTS:
                findings.add("error", "too-many-components", f"more than {MAX_COMPONENTS} components; rest not checked")
                break
            _check_component(c, path, findings, refs, cov)
        _service_refs(data.get("services"), findings, refs)
        graph = _check_dependencies(data, findings, refs, cov)
        cov["in_graph"] = sum(1 for r in cov["_refs"] if r in graph)
        cov["compositions"] = bool(_list(data.get("compositions")))
    del cov["_refs"]
    found = findings.list()
    return {"spec": spec, "readable": True, "valid": not any(f["level"] == "error" for f in found),
            "findings": found, "coverage": cov}


def unreadable(code: str, message: str) -> dict:
    cov = _coverage()
    del cov["_refs"]
    return {"spec": "", "readable": False, "valid": False, "coverage": cov,
            "findings": [{"level": "error", "code": code, "message": message, "count": 1, "examples": []}]}


def check_bytes(raw: bytes) -> dict:
    if len(raw) > MAX_BYTES:
        return unreadable("too-large", f"{len(raw)} bytes, larger than the {MAX_BYTES} byte limit")
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        return unreadable("not-json", f"not valid JSON ({type(exc).__name__})")
    return check(data)


def check_path(path: Path) -> dict:
    try:
        if not path.is_file():
            return unreadable("missing", f"no file {path}")
        if path.stat().st_size > MAX_BYTES:
            return unreadable("too-large", f"{path.stat().st_size} bytes, larger than the {MAX_BYTES} byte limit")
        raw = path.read_bytes()
    except OSError as exc:
        return unreadable("unreadable", f"cannot read {path.name} ({type(exc).__name__})")
    return check_bytes(raw)


# --------------------------------------------------------------------------- summaries and text

def summary(result: dict) -> dict:
    """The compact form kept in inventory.json (`sbom_quality`)."""
    cov = result["coverage"]
    errors = [f for f in result["findings"] if f["level"] == "error"]
    return {"valid": result["valid"], "spec": result["spec"],
            "errors": sum(f["count"] for f in errors),
            "warnings": sum(f["count"] for f in result["findings"] if f["level"] == "warning"),
            "error_codes": [f["code"] for f in errors],
            **{k: cov[k] for k in ("components", "files", *FIELDS, "sha512", "graph", "compositions",
                                   "timestamp", "tools", "author", "subject")}}


def share(part: int, whole: int) -> str:
    if not whole:
        return "-"
    pct = 100 * part / whole
    if 0 < pct < 1:
        return "<1%"
    if 99 < pct < 100:
        return ">99%"
    return f"{round(pct)}%"


def coverage_text(s: dict) -> str:
    """One line for evidence notes: '412 component entries: version 100%, purl 98%, ...; dependency graph: yes'."""
    n = s.get("components", 0)
    parts = [f"{LABELS[k]} {share(s.get(k, 0), n)}" for k in ("version", "purl", "licence", "hash", "supplier",
                                                                "in_graph")]
    head = f"{n} component entries" + (f" (+{s['files']} files)" if s.get("files") else "")
    flags = ", ".join(f"{label} {'yes' if s.get(key) else 'no'}"
                      for key, label in (("graph", "dependency graph"), ("timestamp", "timestamp"),
                                         ("author", "author/tool"), ("subject", "subject with version")))
    return f"{head}: {', '.join(parts)}; {flags}"


def _cell(s) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(s).replace("|", "\\|"))


def inventory_section(inventories) -> list[str]:
    """INVENTORY.md lines: one row per written SBOM with its validity and data-field coverage."""
    rows = [i for i in inventories if getattr(i, "sbom_quality", None)]
    if not rows:
        return []
    L = ["## SBOM quality", "",
         "Structural check and data-field coverage of each SBOM written by this run (`sbom check` for details). "
         "Shares are of the component entries that are not plain files (a package declared in two manifests can be "
         "two entries); a gap means the source data does not carry the "
         "field, nothing is filled in. Which NTIA and BSI TR-03183-2 data fields the columns correspond to: "
         "docs/reference.md, \"SBOM quality\".", "",
         "| Project | Branch | Valid | Component entries | Version | purl | Licence | Hash | Supplier | In graph |",
         "|---|---|---|---:|---:|---:|---:|---:|---:|---:|"]
    for inv in rows:
        q = inv.sbom_quality
        n = q.get("components", 0)
        valid = "yes" if q.get("valid") else f"no ({q.get('errors', 0)} errors)"
        graph = share(q.get("in_graph", 0), n) if q.get("graph") else "no graph"
        L.append(f"| {_cell(inv.project)} | {_cell(inv.branch)} | {valid} | {n} | "
                 + " | ".join(share(q.get(k, 0), n) for k in ("version", "purl", "licence", "hash", "supplier"))
                 + f" | {graph} |")
    L.append("")
    return L


def cra_note(s: dict) -> str:
    if s.get("valid"):
        return coverage_text(s)
    codes = ", ".join(s.get("error_codes", [])[:6])
    return f"{s.get('errors', 0)} structural errors ({codes}); see `sbom check`. {coverage_text(s)}"


# --------------------------------------------------------------------------- command

def _targets(args) -> list[tuple[str, Path]]:
    if args.path:
        return [(str(args.path), Path(args.path))]
    out = Path(args.out)
    base = out / "sbom"
    if args.project:
        # a project is one folder name under sbom/, a branch one file in it: neither may leave that folder
        if args.project in (".", "..") or "/" in args.project or "\\" in args.project:
            raise ConfigError(f"--project takes a project name, not a path: {args.project!r}")
        if args.branch and ".." in args.branch.split("/"):
            raise ConfigError(f"--branch takes a branch name: {args.branch!r}")
        folder = base / args.project
        if args.branch:
            name = args.branch.replace("/", "__") + ".cdx.json"
            return [(f"sbom/{args.project}/{name}", folder / name)]
        files = sorted(folder.glob("*.cdx.json")) if folder.is_dir() else []
        return [(p.relative_to(out).as_posix(), p) for p in files] or [(f"sbom/{args.project}/", folder)]
    files = sorted(base.glob("*/*.cdx.json")) if base.is_dir() else []
    return [(p.relative_to(out).as_posix(), p) for p in files] or [("sbom/", base)]


def render(name: str, result: dict) -> list[str]:
    status = "valid" if result["valid"] else ("unreadable" if not result["readable"] else "structural errors")
    L = [f"{name}: {status}" + (f" (CycloneDX {result['spec']})" if result["spec"] else "")]
    for f in result["findings"]:
        count = f" x{f['count']}" if f["count"] > 1 else ""
        examples = f" e.g. {'; '.join(f['examples'])}" if f["examples"] else ""
        L.append(f"  {f['level']:<7} {f['code']}{count}: {f['message']}{examples}")
    if result["readable"]:
        cov = result["coverage"]
        n = cov["components"]
        files = cov["files"]
        L.append(f"  data fields of {n} component entries"
                 + (f" (plus {files} file {'entry' if files == 1 else 'entries'}, not counted)" if files else "")
                 + ":")
        for k in FIELDS:
            L.append(f"    {LABELS[k]:<10} {cov[k]:>7}  {share(cov[k], n):>5}")
        L.append(f"    {'SHA-512':<10} {cov['sha512']:>7}  {share(cov['sha512'], n):>5}")
        for key, label in (("graph", "dependency graph"), ("compositions", "completeness (compositions)"),
                           ("timestamp", "timestamp"), ("tools", "tool named"), ("author", "author or tool"),
                           ("subject", "subject named with version")):
            L.append(f"    {label:<28} {'yes' if cov[key] else 'no'}")
    return L


def cli(args) -> int:
    """`sbom check`: 0 no structural errors, 1 structural errors, 2 a file missing or unreadable. Writes nothing."""
    results = [(name, check_path(path)) for name, path in _targets(args)]
    if args.json:
        print(json.dumps([{"file": name, **r} for name, r in results], indent=1, ensure_ascii=False))
    else:
        for name, r in results:
            print("\n".join(render(name, r)))
        if len(results) > 1:
            bad = sum(1 for _, r in results if not r["valid"])
            print(f"{len(results)} SBOMs checked, {bad} with errors or unreadable")
    if any(not r["readable"] for _, r in results):
        return 2
    return 1 if any(not r["valid"] for _, r in results) else 0
