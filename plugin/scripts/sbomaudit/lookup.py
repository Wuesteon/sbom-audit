"""`lookup` (who uses what) from inventory.json and `incident` (are we affected) from OSV + audit.json."""
from __future__ import annotations

import datetime as dt
import fnmatch
import json
import re
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from . import config, ecosystems, epss, report, scan, vex
from . import hint as cli_hint
from .config import Config
from .coverage import UNRESOLVED_TEXT as UNRESOLVED_EVIDENCE
from .enrich import build_minimum, http_get_json
from .matching import version_unresolved
from .model import BranchInventory, Component, direct_text
from .versions import norm_py

OSV_VULN_API = "https://api.osv.dev/v1/vulns/"
VULN_ID_RE = re.compile(r"^(CVE|GHSA|PYSEC|OSV|GO|RUSTSEC)-", re.IGNORECASE)
# OSV ecosystem (lower case, ecosystems.key) -> purl type, for the subcomponent of a VEX statement
PURL_TYPE = {"npm": "npm", "pypi": "pypi", "go": "golang", "crates.io": "cargo", "rubygems": "gem",
             "maven": "maven", "nuget": "nuget", "packagist": "composer", "hex": "hex", "pub": "pub",
             "swifturl": "swift", "github actions": "github", "conancenter": "conan", "hackage": "hackage"}
VERDICT_HIT, VERDICT_UNKNOWN, VERDICT_PRESENT, VERDICT_ABSENT = "hit", "unknown", "present_not_affected", "absent"
ALIAS_ORDER = ("GHSA-", "PYSEC-", "RUSTSEC-", "GO-", "OSV-")   # ecosystem advisories name packages; CVE records often do not


@dataclass
class Row:
    name: str
    project: str
    branch: str
    manifest: str
    version: str
    how: str                 # direct | transitive | unknown | image | runtime
    ecosystem: str = ""


@dataclass
class Verdict:
    project: str
    branch: str
    verdict: str             # hit | unknown | present_not_affected | absent
    name: str = ""
    ecosystem: str = ""
    version: str = ""
    evidence: str = ""


@dataclass
class Incident:
    ident: str
    kind: str                # vuln | package
    id: str = ""
    aliases: list[str] = field(default_factory=list)
    summary: str = ""
    affected: list[tuple[str, str]] = field(default_factory=list)
    fixed: dict[tuple[str, str], list[str]] = field(default_factory=dict)
    unknown: bool = False
    note: str = ""           # why there are no verdicts
    warning: str = ""        # verdicts exist but deserve a caveat
    verdicts: list[Verdict] = field(default_factory=list)
    rows: list[Row] = field(default_factory=list)


# --------------------------------------------------------------------------- lookup

def _norm(ecosystem: str, name: str) -> str:
    """A package name in comparable form: PEP 503 for PyPI, a SwiftURL without scheme and `.git`, else lower case."""
    eco = ecosystems.key(ecosystem)
    if eco == "pypi":
        return norm_py(name)
    if eco == "swifturl":
        name = re.sub(r"^[a-z+]+://", "", name.strip(), flags=re.IGNORECASE)
        name = name.removesuffix("/").removesuffix(".git")
    return name.lower()


def _purl_path(purl: str) -> str:
    """`pkg:swift/github.com/apple/swift-nio@2.40.0` -> `github.com/apple/swift-nio` (namespace/name)."""
    body = purl[4:] if purl.startswith("pkg:") else purl
    body = body.split("?", 1)[0].split("#", 1)[0]
    path = body.split("/", 1)[1] if "/" in body else ""
    head, sep, tail = path.rpartition("@")
    return urllib.parse.unquote(head if sep and "/" not in tail else path)


def _how(c: Component) -> str:
    if c.kind in ("image", "runtime"):
        return c.kind
    return direct_text(c.direct)            # "unknown" when the scan could not tell, never "transitive"


def _names(c: Component) -> set[str]:
    """The normalised names a package answers to: its own and the OSV form (Maven `group:artifact`; for
    SwiftURL and GitHub Actions the purl's namespace/name, which is how OSV names them)."""
    names = {_norm(c.ecosystem, c.name), _norm(c.ecosystem, c.qualified_name())}
    if ecosystems.key(c.ecosystem) in ("swifturl", "github actions") and c.purl:
        names.add(_norm(c.ecosystem, _purl_path(c.purl)))
    return names


def _matches(c: Component, patterns: list[str]) -> bool:
    candidates = _names(c) | {c.name.lower(), c.qualified_name().lower()}
    if c.kind == "image":
        image = (c.props.get("image") or "").lower()
        candidates |= {image, image.split("@", 1)[0]}
    elif c.kind == "runtime":
        candidates.add(f"{c.name}:{c.version}".lower())
    return any(fnmatch.fnmatchcase(cand, pat) for cand in candidates for pat in patterns)


def rows(out: Path, names: list[str]) -> list[Row]:
    """Every project@branch component whose name (or image reference) matches one of `names`.

    Patterns are case-insensitive fnmatch globs; PyPI names are PEP 503 normalised on both sides. A Maven
    package matches its artifact name and its `group:artifact` (the name is listed in the latter form).
    """
    inventories, _ = scan.read_inventory(Path(out))
    patterns = [p.lower() for p in names if p]
    patterns += [norm_py(p) for p in list(patterns) if norm_py(p) != p]
    found: list[Row] = []
    for inv in inventories:
        for c in inv.components:
            if _matches(c, patterns):
                found.append(Row(name=c.qualified_name() if c.kind == "package" else c.name, project=inv.project, branch=inv.branch,
                                 manifest="; ".join(c.locations) or c.props.get("source", ""),
                                 version=c.version, how=_how(c), ecosystem=c.ecosystem))
    found.sort(key=lambda r: (r.name.lower(), r.project, r.branch, r.version))
    return found


def rows_table(found: list[Row]) -> str:
    lines = ["| Name | Version | Project | Branch | How | Ecosystem | Manifest |", "|---|---|---|---|---|---|---|"]
    for r in found:
        lines.append(f"| {report.md(r.name)} | {report.md(r.version) or '?'} | {report.md(r.project)} | "
                     f"{r.branch} | {r.how} | {r.ecosystem} | {report.md(r.manifest)} |")
    return "\n".join(lines)


# --------------------------------------------------------------------------- incident

def _osv_record(ident: str, fetch) -> dict | None:
    """The OSV record for `ident`, or None when OSV does not know the id (HTTP 404)."""
    try:
        return fetch(OSV_VULN_API + urllib.parse.quote(ident, safe=""))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def _affected(record: dict) -> tuple[list[tuple[str, str]], dict[tuple[str, str], list[str]]]:
    pairs: list[tuple[str, str]] = []
    fixed: dict[tuple[str, str], list[str]] = {}
    for aff in record.get("affected") or []:
        pkg = aff.get("package") or {}
        eco, name = (pkg.get("ecosystem") or "").split(":")[0], pkg.get("name") or ""
        if not eco or not name:
            continue
        key = (eco, name)
        if key not in pairs:
            pairs.append(key)
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if "fixed" in ev and ev["fixed"] not in fixed.setdefault(key, []):
                    fixed[key].append(ev["fixed"])
    return pairs, fixed


def _affected_with_aliases(record: dict, fetch) -> tuple[list[tuple[str, str]], dict]:
    """Affected (ecosystem, name) pairs from the record, else from the first alias record that names packages."""
    pairs, fixed = _affected(record)
    if pairs:
        return pairs, fixed
    rank = {p: i for i, p in enumerate(ALIAS_ORDER)}
    aliases = sorted((a for a in record.get("aliases") or [] if isinstance(a, str)),
                     key=lambda a: (rank.get(a.split("-", 1)[0].upper() + "-", len(rank)), a))
    for alias in aliases:
        rec = _osv_record(alias, fetch)
        if rec is None:
            continue
        pairs, fixed = _affected(rec)
        if pairs:
            return pairs, fixed
    return [], {}


def _read_audit(out: Path) -> dict:
    path = Path(out) / report.JSON_FILE
    if not path.exists():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8"))


def _as_utc(stamp: str) -> dt.datetime | None:
    """ISO 8601 with Z or offset, any fractional precision -> aware UTC datetime; None when unparsable."""
    if not stamp:
        return None
    text = re.sub(r"\.\d+", "", str(stamp).strip()).replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _stale_warning(record: dict, rep: dict, inventory_meta: dict | None = None) -> str:
    """Why the verdicts may be out of date: the OSV record or the inventory is newer than the audit."""
    changed = _as_utc(record.get("modified") or record.get("published") or "")
    audited = _as_utc(rep.get("generated_at") or "")
    scanned = _as_utc((inventory_meta or {}).get("generated_at") or "")
    reasons = []
    if changed and audited and changed > audited:
        reasons.append(f"the OSV record changed {changed.date().isoformat()}, after the last audit "
                       f"({audited.date().isoformat()})")
    if scanned and audited and scanned > audited:
        reasons.append(f"{scan.INVENTORY_FILE} ({scanned.date().isoformat()}) is newer than {report.JSON_FILE} "
                       f"({audited.date().isoformat()}), so the verdicts rest on an older inventory")
    if not reasons:
        return ""
    return "; ".join(reasons) + f": run {cli_hint.slash('run', full=False)} before trusting {VERDICT_PRESENT} verdicts."


def _incomplete(rep: dict, inventories: list[BranchInventory]) -> dict[tuple[str, str], str]:
    """(project, branch) -> why the last audit cannot vouch for that branch: its checkout or readers
    reported errors, or osv-scanner failed on it. No finding there proves nothing."""
    out: dict[tuple[str, str], str] = {}
    for inv in inventories:
        if inv.errors:
            out[(inv.project, inv.branch)] = "; ".join(inv.errors)
    for f in ((rep.get("sources") or {}).get("osv-scanner") or {}).get("failed") or []:
        if isinstance(f, dict):
            out[(f.get("project", ""), f.get("branch", ""))] = f"osv-scanner failed: {f.get('error')}"
    return out


def _audit_hits(rep: dict, ids: set[str]) -> dict[tuple[str, str, str, str, str], str]:
    """(project, branch, ecosystem, normalised name, version) -> evidence, for findings in audit.json
    that carry one of `ids`. Keyed by version: a branch can hold two versions of one package."""
    hits: dict[tuple[str, str, str, str, str], str] = {}
    for entry in rep.get("vulnerabilities") or []:
        matching_vulns = [v for v in entry.get("vulns") or []
                          if ids & ({v.get("id", "")} | set(v.get("aliases") or []))]
        if not matching_vulns:
            continue
        v = matching_vulns[0]
        evidence = f"{v.get('id')} {v.get('severity', '')}".strip()
        if "epss" in v:                      # only when the EPSS step ran; None reads "no EPSS", never 0
            evidence += f", {epss.label(v['epss'])}"
        if v.get("fixed_in"):
            evidence += f", fix {entry['version']} → {v['fixed_in']}"
        if v.get("kev"):
            evidence = "KEV, " + evidence
        # `package` is the OSV name (Maven `group:artifact`); an audit.json before it carries the bare name only
        name = entry.get("package") or entry["name"]
        for loc in entry.get("locations") or []:
            key = (loc["project"], loc["branch"], ecosystems.key(entry["ecosystem"]),
                   _norm(entry["ecosystem"], name), entry["version"])
            hits[key] = evidence + (f" ({loc['manifest']})" if loc.get("manifest") else "")
    for sup in rep.get("suppressed") or []:
        f, st = sup["finding"], sup["statement"]
        v = f["vulns"][0] if f.get("vulns") else {}
        if not ids & ({v.get("id", "")} | set(v.get("aliases") or [])):
            continue
        c = f["component"]
        name = Component.from_dict(c).qualified_name()
        key = (f["project"], f["branch"], ecosystems.key(c["ecosystem"]), _norm(c["ecosystem"], name), c["version"])
        hits.setdefault(key, f"suppressed by VEX: {st.get('status')} ({st.get('justification') or 'no justification'})")
    return hits


def _runtimes(inv: BranchInventory, product: str) -> list[Component]:
    return [c for c in inv.components if c.kind == "runtime" and (c.ecosystem or c.name).lower() == product]


def _uncovered(inv: BranchInventory, eco: str, name: str) -> str | None:
    """Why `name` (`eco`) not being in this branch's inventory proves nothing, or None when "absent" holds.

    The rule (docs/reference.md, "Unknown instead of absent"): unknown, never absent, when
    1. the advisory is against the Go runtime (`Go`/`stdlib`, `Go`/`toolchain`) and the branch has a Go
       runtime row, a Go package or a go.mod: osv-scanner does not check the Go toolchain;
    2. the ecosystem is one the repository scan does not inventory (ecosystems.PACKAGE_COVERAGE), except an
       operating-system ecosystem on a branch without any container image;
    3. the branch has no package at all although it has manifests, or its inventory predates the manifest
       record (`manifests` is None) and holds no package;
    4. the branch has a manifest or lockfile of that ecosystem but not one package of it was inventoried."""
    pkgs = [c for c in inv.components if c.kind == "package"]
    k = ecosystems.key(eco)
    product = ecosystems.runtime_product(eco, name)
    if product:
        rts = _runtimes(inv, product)
        if rts:
            def describe(c: Component) -> str:
                notes = [n for n in (c.props.get("source") or ", ".join(c.locations),
                                     "a build minimum: the Go that builds the release may be newer"
                                     if build_minimum(c) else "") if n]
                return f"Go {c.version or 'version not pinned'}" + (f" ({', '.join(notes)})" if notes else "")
            seen = "; ".join(describe(c) for c in rts)
            return f"{seen}: osv-scanner does not check the Go toolchain; compare with the advisory's fixed versions"
        if (inv.manifests or {}).get("Go") or any(ecosystems.key(c.ecosystem) == "go" for c in pkgs):
            return "Go code on this branch, but no Go version was read: osv-scanner does not check the Go toolchain"
    elif not ecosystems.covered(eco):
        if not ecosystems.from_images(eco):
            return f"the scan does not inventory {eco} packages: the SBOM cannot show whether they are used"
        images = sorted({c.props.get("image") or c.name for c in inv.components if c.kind == "image"})
        if images:
            return (f"{eco} packages come with container images, whose contents the scan does not inventory "
                    f"({', '.join(images[:5])})")
        return None
    if not pkgs and inv.manifests is None:
        return ("no package in this branch's inventory, and the scan that wrote it recorded no manifest list: "
                f"re-run {cli_hint.slash('run', full=False)}")
    if not pkgs and inv.manifests:
        files = sorted(f for paths in inv.manifests.values() for f in paths)
        return f"no package inventoried although manifests are present ({', '.join(files[:5])})"
    files = (inv.manifests or {}).get(ecosystems.osv_name(eco) or eco)
    if files and not any(ecosystems.key(c.ecosystem) == k for c in pkgs):
        return (f"{', '.join(files[:5])} present but no {eco} package was inventoried from it "
                "(a manifest or lockfile Syft could not read?)")
    return None


def _verdicts(inventories: list[BranchInventory], affected: list[tuple[str, str]],
              fixed: dict, hits: dict, incomplete: dict[tuple[str, str], str] | None = None) -> list[Verdict]:
    """One verdict per affected package occurrence, plus an `unknown` per affected package the branch's SBOM
    cannot rule out (`_uncovered`), else one `absent` per branch. Ecosystems compare in OSV form
    (ecosystems.key), names in OSV form (Maven `group:artifact` from the purl namespace). A finding
    audit.json lists is always a hit, even when the inventory no longer names the package the same way:
    the audit never answers "absent" for it."""
    wanted = {(ecosystems.key(eco), _norm(eco, name)): (eco, name) for eco, name in affected}
    incomplete = incomplete or {}
    used: set[tuple] = set()
    out: list[Verdict] = []
    for inv in inventories:
        gap = incomplete.get((inv.project, inv.branch))
        gap_evidence = f"audit incomplete for this branch: {gap}" if gap else ""
        branch_out: list[Verdict] = []
        matched: set[tuple[str, str]] = set()
        for c in inv.components:
            if c.kind != "package":
                continue
            eco_key = ecosystems.key(c.ecosystem)
            keys = [(eco_key, n) for n in sorted(_names(c))]
            key = next((k for k in keys if k in wanted), None)
            if key is None:
                continue
            matched.add(wanted[key])
            hit_key = next((hk for hk in ((inv.project, inv.branch, *k, c.version) for k in keys) if hk in hits), None)
            hit = hits.get(hit_key) if hit_key else None
            if hit_key:
                used.add(hit_key)
            name = c.qualified_name()
            if hit and not hit.startswith("suppressed by VEX"):
                branch_out.append(Verdict(inv.project, inv.branch, VERDICT_HIT, name, c.ecosystem, c.version, hit))
            elif gap and not hit:
                branch_out.append(Verdict(inv.project, inv.branch, VERDICT_UNKNOWN, name, c.ecosystem, c.version,
                                          gap_evidence))
            elif not hit and version_unresolved(c.version):
                branch_out.append(Verdict(inv.project, inv.branch, VERDICT_UNKNOWN, name, c.ecosystem,
                                          c.version or "", UNRESOLVED_EVIDENCE
                                          + (f" ({'; '.join(c.locations)})" if c.locations else "")))
            else:
                fixes = fixed.get(wanted[key]) or []
                evidence = hit or (f"{c.version} not in the affected range per osv-scanner"
                                   + (f" (fixed: {', '.join(fixes)})" if fixes else ""))
                branch_out.append(Verdict(inv.project, inv.branch, VERDICT_PRESENT, name, c.ecosystem, c.version,
                                          evidence))
        for eco, name in affected:
            if (eco, name) in matched or gap:      # an incomplete audit is reported once, below
                continue
            reason = _uncovered(inv, eco, name)
            if reason is None:
                continue
            fixes = fixed.get((eco, name)) or []
            product = ecosystems.runtime_product(eco, name)
            version = ", ".join(sorted({c.version for c in _runtimes(inv, product) if c.version})) if product else ""
            branch_out.append(Verdict(inv.project, inv.branch, VERDICT_UNKNOWN, name, eco, version,
                                      reason + (f" (fixed: {', '.join(fixes)})" if fixes else "")))
        if gap and len(matched) < len(affected) and not any(v.verdict == VERDICT_UNKNOWN for v in branch_out):
            branch_out.append(Verdict(inv.project, inv.branch, VERDICT_UNKNOWN, evidence=gap_evidence))
        if not branch_out:
            branch_out.append(Verdict(inv.project, inv.branch, VERDICT_ABSENT, evidence="not in SBOM"))
        out += branch_out
    scanned = {(inv.project, inv.branch) for inv in inventories}
    for hk, evidence in hits.items():         # audit.json says affected, the inventory match missed it
        project, branch, eco, name, version = hk
        if hk in used or evidence.startswith("suppressed by VEX") or (project, branch) not in scanned:
            continue                          # `hits` holds only the incident's ids
        out = [v for v in out if not (v.project == project and v.branch == branch and (
            v.verdict == VERDICT_ABSENT
            or (v.verdict == VERDICT_UNKNOWN and v.name and ecosystems.key(v.ecosystem) == eco
                and _norm(v.ecosystem, v.name) == _norm(v.ecosystem, name))))]
        out.append(Verdict(project, branch, VERDICT_HIT, name, eco, version, evidence + " (from audit.json)"))
    order = {VERDICT_HIT: 0, VERDICT_UNKNOWN: 1, VERDICT_PRESENT: 2, VERDICT_ABSENT: 3}
    out.sort(key=lambda v: (order[v.verdict], v.project, v.branch, v.name))
    return out


def incident(out: Path, ident: str, fetch=None) -> Incident:
    """Are we affected by `ident`? A vulnerability id is resolved through OSV and checked against
    audit.json's findings and inventory.json's components; a bare name is a plain lookup."""
    out = Path(out)
    fetch = fetch or http_get_json
    ident = ident.strip()
    if not VULN_ID_RE.match(ident):
        return Incident(ident=ident, kind="package", rows=rows(out, [ident]))
    ident = ident.upper() if ident.upper().startswith(("CVE-", "GHSA-")) else ident
    if ident.upper().startswith("GHSA-"):
        ident = "GHSA-" + ident[5:].lower()
    inc = Incident(ident=ident, kind="vuln")
    record = _osv_record(ident, fetch)
    if record is None:
        inc.unknown = True
        inc.note = f"OSV does not know {ident}; falling back to a name lookup."
        inc.rows = rows(out, [ident])
        return inc
    inc.id = record.get("id") or ident
    inc.aliases = list(record.get("aliases") or [])
    inc.summary = (record.get("summary") or (record.get("details") or "")[:160]).strip()
    inc.affected, inc.fixed = _affected_with_aliases(record, fetch)
    if not inc.affected:
        inc.note = (f"OSV lists no affected packages for {inc.id} or its aliases (source ranges only): "
                    "it cannot be mapped to the SBOMs; check the advisory by hand.")
        return inc
    ids = {ident, inc.id, *inc.aliases}
    inventories, meta = scan.read_inventory(out)
    try:
        rep = _read_audit(out)
    except FileNotFoundError:
        inc.note = (f"{report.JSON_FILE} not found: run the audit first to tell hits from "
                    "present-but-unaffected; listing where the affected packages occur instead.")
        inc.rows = rows(out, [name for _, name in inc.affected])
        return inc
    inc.verdicts = _verdicts(inventories, inc.affected, inc.fixed, _audit_hits(rep, ids),
                             _incomplete(rep, inventories))
    inc.warning = _stale_warning(record, rep, meta)
    return inc


def verdict_table(inc: Incident) -> str:
    lines = ["| Project | Branch | Package | Version | Verdict | Evidence |", "|---|---|---|---|---|---|"]
    for v in inc.verdicts:
        lines.append(f"| {report.md(v.project)} | {v.branch} | {report.md(v.name) or '—'} | "
                     f"{report.md(v.version) or '—'} | {v.verdict} | {report.md(v.evidence)} |")
    return "\n".join(lines)


def _affected_purl(eco: str, name: str, inventories: list[BranchInventory]) -> str:
    for inv in inventories:
        for c in inv.components:
            if (c.kind == "package" and ecosystems.key(c.ecosystem) == ecosystems.key(eco) and c.purl
                    and _norm(eco, name) in _names(c)):
                return vex.versionless(c.purl)
    ptype = PURL_TYPE.get(ecosystems.key(eco), ecosystems.key(eco))
    pname = norm_py(name) if ptype == "pypi" else name
    if ptype == "maven" and ":" in pname:      # OSV `group:artifact` -> purl namespace/name
        pname = "/".join(pname.split(":", 1))
    return f"pkg:{ptype}/{pname}"


def _vex_coverable(eco: str, name: str) -> bool:
    """Whether "not in the SBOM" can prove `component_not_present` for this package: the scan inventories
    its ecosystem. Go runtime advisories (`Go`/`stdlib`) are never answered from the SBOM."""
    return ecosystems.covered(eco) and not ecosystems.runtime_product(eco, name)


def _absent_projects(inc: Incident) -> list[str]:
    return sorted({v.project for v in inc.verdicts if v.verdict == VERDICT_ABSENT}
                  - {v.project for v in inc.verdicts if v.verdict != VERDICT_ABSENT})


def vex_refusals(inc: Incident) -> list[str]:
    """What `--vex` does not record as `component_not_present`, and why."""
    out = []
    for project in sorted({v.project for v in inc.verdicts if v.verdict == VERDICT_UNKNOWN}):
        branches = sorted({v.branch for v in inc.verdicts if v.project == project and v.verdict == VERDICT_UNKNOWN})
        out.append(f"{project}: verdict unknown on {', '.join(branches)}; the SBOM cannot show the component "
                   "is absent")
    for eco, name in inc.affected:
        if not _vex_coverable(eco, name):
            why = ("the Go toolchain is not in the SBOM" if ecosystems.runtime_product(eco, name)
                   else f"the scan does not inventory {eco} packages")
            out.append(f"{name} ({eco}): {why}, so its absence from the SBOM proves nothing")
    return out


def record_absent(cfg: Config, inc: Incident, author: str | None = None) -> list[Path]:
    """`not_affected` / `component_not_present` for each project whose every verdict is absent: one
    statement per examined branch (product `<purl>@<branch>`) and affected package of an ecosystem the scan
    inventories, the commit named in the impact statement. Nothing for unknown verdicts or for an
    ecosystem outside the scan's coverage (`vex_refusals`)."""
    if not inc.verdicts:
        return []
    inventories, _ = scan.read_inventory(cfg.out)
    from .pipeline import purl_of
    purls = purl_of(cfg, inventories)
    examined = {(v.project, v.branch) for v in inc.verdicts if v.verdict == VERDICT_ABSENT}
    today = dt.date.today().isoformat()
    written: list[Path] = []
    for project in _absent_projects(inc):
        for inv in sorted((i for i in inventories if i.project == project and (i.project, i.branch) in examined),
                          key=lambda i: i.branch):
            commit = (inv.commit or "")[:12] or "unknown commit"
            for eco, name in inc.affected:
                if not _vex_coverable(eco, name):
                    continue
                path = vex.add(cfg.out, project, vex.product_for_branch(purls[project], inv.branch), inc.ident,
                               "not_affected", justification="component_not_present",
                               impact=(f"{name} ({eco}) is not in the SBOM of {project}@{inv.branch} at commit "
                                       f"{commit} (sbom-audit incident, {today}); other branches and later "
                                       "commits are not covered by this statement"),
                               subcomponent=_affected_purl(eco, name, inventories), author=author)
                if path not in written:
                    written.append(path)
    return written


# --------------------------------------------------------------------------- CLI

def cli_lookup(args) -> int:
    try:
        found = rows(args.out, args.names)
    except FileNotFoundError:
        print(f"{Path(args.out) / scan.INVENTORY_FILE} not found: run `scan` (or `run`) first.")
        return 2
    if not found:
        print(f"no match for {', '.join(args.names)} in {Path(args.out) / scan.INVENTORY_FILE}")
        return 1
    print(rows_table(found))
    return 0


def cli_incident(args) -> int:
    out = Path(args.out)
    try:
        inc = incident(out, args.ident, fetch=http_get_json)
    except FileNotFoundError as exc:
        missing = Path(exc.filename or "").name or "inventory.json"
        print(f"no inventory in {out} ({missing} missing): run {cli_hint.slash('run')} first.")
        return 2
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"OSV lookup failed for {args.ident}: {exc}")
        return 2
    if inc.kind == "package":
        print(f"`{inc.ident}` is not a vulnerability id; showing where it is used.\n")
        print(rows_table(inc.rows) if inc.rows else "no match.")
        return 0
    if inc.unknown:
        print(inc.note)
        print(rows_table(inc.rows) if inc.rows else "no component of that name either.")
        return 2
    head = f"**{inc.id}**" + (f" ({', '.join(inc.aliases)})" if inc.aliases else "")
    print(f"{head}: {inc.summary}\n")
    affected = ", ".join(f"{name} ({eco})" + (f" fixed in {', '.join(inc.fixed[(eco, name)])}" if inc.fixed.get((eco, name)) else "")
                         for eco, name in inc.affected) or "no affected packages listed"
    print(f"Affected packages: {affected}\n")
    if not inc.affected:
        print(inc.note)
        return 2
    if inc.note:
        print(inc.note + "\n")
        print(rows_table(inc.rows) if inc.rows else "none of the affected packages is in any SBOM.")
        return 2
    if inc.warning:
        print(f"Warning: {inc.warning}\n")
    print(verdict_table(inc))
    hits = [v for v in inc.verdicts if v.verdict == VERDICT_HIT]
    unknown = [v for v in inc.verdicts if v.verdict == VERDICT_UNKNOWN]
    unresolved = [v for v in unknown if v.evidence.startswith(UNRESOLVED_EVIDENCE)]
    unknown = [v for v in unknown if v not in unresolved]
    uncovered = [v for v in unknown if not v.evidence.startswith("audit incomplete")]
    unknown = [v for v in unknown if v not in uncovered]
    absent = _absent_projects(inc)
    print(f"\n{len(hits)} hit(s), {len(unknown)} branch(es) with an incomplete audit, "
          + (f"{len(unresolved)} occurrence(s) with the version not resolved, " if unresolved else "")
          + (f"{len(uncovered)} unknown verdict(s) the SBOM cannot settle, " if uncovered else "")
          + f"{len(absent)} project(s) without the component.")
    if getattr(args, "vex", False):
        for reason in vex_refusals(inc):
            print(f"not recorded: {reason}")
        try:
            author = vex.resolve_author(getattr(args, "author", None)) if absent else None
        except ValueError as exc:
            print(f"not recorded: {exc}")
            return 2
        files = record_absent(config.load(out), inc, author=author) if absent else []
        for f in files:
            print(f"wrote {f}")
    elif absent:
        print(f"Record the no-hits with: /sbom-audit:incident {inc.ident} --vex "
              f"(CLI: sbom_audit_cli.py incident {inc.ident} --vex)")
    if unknown and not hits:
        print(f"Re-run /sbom-audit:run (CLI: sbom_audit_cli.py run) to complete the audit for: "
              + ", ".join(sorted({f'{v.project}@{v.branch}' for v in unknown})))
    if unresolved and not hits:
        print("A re-run does not help where the version is not resolved: check the version the build actually "
              "uses (for Maven `mvn dependency:tree` or the BOM that manages it) for: "
              + ", ".join(sorted({f'{v.project}@{v.branch} ({v.name})' for v in unresolved})))
    if uncovered and not hits:
        print("Check by hand (see the evidence column) for: "
              + ", ".join(sorted({f'{v.project}@{v.branch} ({v.name or v.ecosystem})' for v in uncovered})))
    return 1 if hits else (2 if unknown or unresolved or uncovered else 0)
