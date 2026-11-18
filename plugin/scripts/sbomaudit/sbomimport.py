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
            purl=purl, scope=_scope(entry), locations=[], direct=None, props={"imported": True})))
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
            continue
        if seen.direct is None or c.direct:
            seen.direct = c.direct if seen.direct is None else True
        if c.scope == "required":
            seen.scope = "required"
    return list(merged.values()), via


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


def source(doc: Document, raw: bytes, where: str, from_evidence: bool, provenance: dict, commit: str) -> dict:
    """The `package_source` of an inventory built from an import. `commit` is the scanned commit; the import's
    own commit comes from its provenance (an evidence-folder file whose sha256 still matches it). `stale` is
    True when that commit differs from the scanned one, None when it is not recorded."""
    digest = hashlib.sha256(raw).hexdigest()
    recorded = None
    if from_evidence and provenance.get("sha256") == digest and isinstance(provenance.get("commit"), str):
        recorded = provenance["commit"] if _SHA_RE.match(provenance["commit"]) else None
    return {"kind": "import", "file": where, "in": "evidence" if from_evidence else "repository",
            "sha256": digest, "spec_version": doc.spec, "tool": doc.tool, "timestamp": doc.timestamp,
            "commit": recorded,
            "stale": None if recorded is None else recorded != commit,
            "imported_at": provenance.get("imported_at") if recorded else None}


def staleness(src: dict | None) -> str:
    """'' for a current import or a repository scan; else what makes it not this commit's, in English."""
    if not src or src.get("kind") != "import":
        return ""
    if src.get("commit") is None:
        return "commit not recorded"
    if src.get("stale"):
        return f"built from commit {src['commit'][:7]}, not the scanned one"
    return ""


def describe(src: dict) -> str:
    """One line on an imported package list (Markdown-safe text is the caller's job)."""
    replaced = ", ".join(src.get("replaced") or []) or "no ecosystem"
    where = "" if src.get("in") == "evidence" else " (committed in the repository)"
    bits = [f"imported build SBOM `{src.get('file')}`{where}", f"replaces {replaced}"]
    if src.get("tool"):
        bits.append(f"by {src['tool']}")
    if src.get("timestamp"):
        bits.append(f"generated {src['timestamp']}")
    bits.append(f"sha256 {str(src.get('sha256', ''))[:12]}")
    bits.append(staleness(src) or f"commit {str(src.get('commit'))[:7]} (current)")
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


def syft_artifact(target: str) -> bytes:
    """`syft scan <target> -o cyclonedx-json`: a file or directory as such, anything else as an image ref."""
    if target.startswith("-"):
        raise Rejected("the artefact must not start with '-'")
    p = Path(target)
    arg = f"file:{p}" if p.is_file() else f"dir:{p}" if p.is_dir() else target
    try:
        proc = subprocess.run(["syft", "scan", arg, "-o", "cyclonedx-json", "-q"], capture_output=True,
                              env={**os.environ, "SYFT_CHECK_FOR_APP_UPDATE": "false"})
    except FileNotFoundError as exc:
        raise ToolError("syft", None, "syft is not installed") from exc
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
