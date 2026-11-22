"""Vulnerability matching: osv-scanner reads each SBOM, findings attach to inventory components."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from . import cvss
from .errors import ToolError
from .model import BranchInventory, Component, Finding
from .versions import norm_py, ver_key

OSV_CACHE_DIR = Path(".cache") / "osv"
OSV_TIMEOUT = 1800   # seconds, one osv-scanner run (network lookups included)


def run_osv_scanner(sbom: Path, out_json: Path) -> dict:
    """`osv-scanner scan source -L <sbom> --format json --output-file <out_json>`.

    Exit 0 (clean) and 1 (vulnerabilities found) are success; anything else raises ToolError.
    """
    out_json.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["osv-scanner", "scan", "source", "-L", str(sbom), "--format", "json",
           "--output-file", str(out_json)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=OSV_TIMEOUT)
    except FileNotFoundError as exc:
        raise ToolError("osv-scanner", None, "osv-scanner is not installed") from exc
    except subprocess.TimeoutExpired:
        raise ToolError("osv-scanner", None, f"timed out after {OSV_TIMEOUT}s") from None
    if proc.returncode not in (0, 1):
        detail = (proc.stderr.strip().splitlines() or ["no output"])[-1]
        raise ToolError("osv-scanner", proc.returncode, detail)
    try:
        return json.loads(out_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolError("osv-scanner", proc.returncode, f"invalid JSON output: {exc}") from exc


def _same_package(ecosystem: str, a: str, b: str) -> bool:
    return norm_py(a) == norm_py(b) if ecosystem == "PyPI" else a == b


def version_unresolved(version: str | None) -> bool:
    """A version nothing can be matched against: empty, Syft's "UNKNOWN" placeholder (a Maven
    dependency whose version a BOM or parent outside the repo manages) or an unexpanded
    `${property}`. Such a component stays in the inventory but is never reported vulnerable:
    osv-scanner treats a missing version as "every version" and lists each advisory ever
    published for the package."""
    v = (version or "").strip()
    return not v or v.upper() == "UNKNOWN" or "${" in v


def _own_severity(v: dict) -> tuple[float | None, str | None]:
    """(CVSS 3 score, label) from the record itself: CVSS 3 vector, then database_specific.severity,
    then a CVSS 4 vector approximated as 3.1 (label suffixed "(~v4)")."""
    for s in v.get("severity") or []:
        if s.get("type") == "CVSS_V3":
            score = cvss.score31(s.get("score", ""))
            if score is not None:
                return score, cvss.label(score)
    db_sev = ((v.get("database_specific") or {}).get("severity") or "").upper()
    if db_sev and db_sev != "UNKNOWN":
        return None, "MEDIUM" if db_sev == "MODERATE" else db_sev
    for s in v.get("severity") or []:
        if s.get("type") == "CVSS_V4":
            v31 = cvss.v4_to_31(s.get("score", ""))
            approx = cvss.score31(v31) if v31 else None
            if approx is not None:
                return None, cvss.label(approx) + "(~v4)"
    return None, None


def _derived_severity(v: dict, related: list[dict], groups: list[dict]) -> tuple[str | None, str]:
    """Severity for a record that carries none, from data in the same osv-scanner result only:
    a rated record aliased to it (a GHSA or CVE for the same flaw), else the numeric
    `max_severity` of the osv-scanner group holding the record. Never a guess."""
    ids = {v.get("id", "")} | set(v.get("aliases") or [])
    ids.discard("")
    for other in related:
        if other is v or other.get("id") == v.get("id"):
            continue
        if ids & ({other.get("id", "")} | set(other.get("aliases") or [])):
            _, label = _own_severity(other)
            if label:
                return label, f"alias {other.get('id', '')}"
    for g in groups:
        if v.get("id") not in (g.get("ids") or []):
            continue
        try:
            score = float(g.get("max_severity") or "")
        except ValueError:
            continue
        return cvss.label(score), "osv-scanner group score"
    return None, ""


def summarize(v: dict, ecosystem: str, name: str, related: list[dict] | None = None,
              groups: list[dict] | None = None) -> dict:
    """One OSV record → the fields the report needs. `related` (the other records osv-scanner
    returned for the same package) and `groups` (its alias groups) let a record without a
    severity of its own borrow one; `severity_source` then says where it came from. A record
    still without one keeps severity "UNKNOWN", which reports show as "not rated"."""
    score, label = _own_severity(v)
    source = ""
    if not label:
        label, source = _derived_severity(v, related or [], groups or [])
    fixed: list[str] = []
    for aff in v.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem", "").split(":")[0] != ecosystem:
            continue
        if not _same_package(ecosystem, pkg.get("name", ""), name):
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
    aliases = list(v.get("aliases") or [])
    vid = v.get("id", "")
    cves = [a for a in aliases if a.startswith("CVE-")] + ([vid] if vid.startswith("CVE-") else [])
    out = {
        "id": vid,
        "aliases": aliases,
        "cves": sorted(set(cves)),
        "summary": (v.get("summary") or (v.get("details") or "")[:160]).strip(),
        "severity": label or "UNKNOWN",
        "cvss": score,
        "fixed": sorted(set(fixed), key=ver_key),
        "published": (v.get("published") or "")[:10],
        "modified": (v.get("modified") or "")[:10],
        "withdrawn": bool(v.get("withdrawn")),
    }
    if source:
        out["severity_source"] = source
    return out


def _key(ecosystem: str, name: str, version: str) -> tuple[str, str, str]:
    return (ecosystem, norm_py(name) if ecosystem == "PyPI" else name, version or "")


def _bare_purl(purl: str) -> str:
    return purl.split("?", 1)[0] if purl else ""


def findings(inv: BranchInventory, osv_json: dict) -> list[Finding]:
    """Attach osv-scanner results to the inventory's components by purl, else by
    (ecosystem, normalised name, version). Packages osv-scanner reports that the inventory
    does not know are still returned, with a synthetic component of scope unknown.
    A package without a resolved version (`version_unresolved`) yields no finding; the
    report lists it as a coverage gap instead."""
    by_purl = {_bare_purl(c.purl): c for c in inv.components if c.purl}
    by_key = {_key(c.ecosystem, c.name, c.version): c for c in inv.components if c.kind == "package"}
    out: list[Finding] = []
    for result in osv_json.get("results") or []:
        for pkg in result.get("packages") or []:
            info = pkg.get("package") or {}
            ecosystem = (info.get("ecosystem") or "").split(":")[0]
            name, version = info.get("name", ""), info.get("version", "") or ""
            comp = by_purl.get(_bare_purl(info.get("purl", ""))) or by_key.get(_key(ecosystem, name, version))
            if version_unresolved(version) or (comp is not None and version_unresolved(comp.version)):
                continue
            if comp is None:
                comp = Component(kind="package", ecosystem=ecosystem, name=name, version=version,
                                 purl=_bare_purl(info.get("purl", "")), scope="unknown")
            records = pkg.get("vulnerabilities") or []
            groups = pkg.get("groups") or []
            vulns = [summarize(v, ecosystem, name, records, groups) for v in records]
            if not vulns:
                continue
            out.append(Finding(project=inv.project, branch=inv.branch, component=comp, vulns=vulns))
    return out


def osv_cache_path(out: Path, inv: BranchInventory) -> Path:
    return out / OSV_CACHE_DIR / inv.project / f"{inv.branch.replace('/', '__')}.json"


def match_all(inventories: list[BranchInventory], out: Path,
              log=None) -> tuple[list[Finding], dict]:
    """Run osv-scanner on every inventory that has an SBOM. Never raises for one branch."""
    say = log or (lambda msg: None)
    found: list[Finding] = []
    sources = {"osv-scanner": {"scanned": 0, "failed": []}}
    for inv in inventories:
        if not inv.sbom_path:
            continue
        sbom = out / inv.sbom_path
        say(f"osv-scanner {inv.project}@{inv.branch} …")
        try:
            result = run_osv_scanner(sbom, osv_cache_path(out, inv))
        except ToolError as exc:
            sources["osv-scanner"]["failed"].append((inv.project, inv.branch, str(exc)))
            continue
        sources["osv-scanner"]["scanned"] += 1
        found.extend(findings(inv, result))
    return found, sources
