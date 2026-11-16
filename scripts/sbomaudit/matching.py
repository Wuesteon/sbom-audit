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


def run_osv_scanner(sbom: Path, out_json: Path) -> dict:
    """`osv-scanner scan source -L <sbom> --format json --output-file <out_json>`.

    Exit 0 (clean) and 1 (vulnerabilities found) are success; anything else raises ToolError.
    """
    out_json.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["osv-scanner", "scan", "source", "-L", str(sbom), "--format", "json",
           "--output-file", str(out_json)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise ToolError("osv-scanner", None, "osv-scanner is not installed") from exc
    if proc.returncode not in (0, 1):
        detail = (proc.stderr.strip().splitlines() or ["no output"])[-1]
        raise ToolError("osv-scanner", proc.returncode, detail)
    try:
        return json.loads(out_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolError("osv-scanner", proc.returncode, f"invalid JSON output: {exc}") from exc


def _same_package(ecosystem: str, a: str, b: str) -> bool:
    return norm_py(a) == norm_py(b) if ecosystem == "PyPI" else a == b


def summarize(v: dict, ecosystem: str, name: str) -> dict:
    """One OSV record → the fields the report needs."""
    score, label = None, None
    for s in v.get("severity") or []:
        if s.get("type") == "CVSS_V3":
            score = cvss.score31(s.get("score", ""))
            if score is not None:
                label = cvss.label(score)
                break
    db_sev = ((v.get("database_specific") or {}).get("severity") or "").upper()
    if not label and db_sev:
        label = "MEDIUM" if db_sev == "MODERATE" else db_sev
    if not label:
        for s in v.get("severity") or []:
            if s.get("type") == "CVSS_V4":
                v31 = cvss.v4_to_31(s.get("score", ""))
                approx = cvss.score31(v31) if v31 else None
                if approx is not None:
                    label = cvss.label(approx) + "(~v4)"
                    break
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
    return {
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


def _key(ecosystem: str, name: str, version: str) -> tuple[str, str, str]:
    return (ecosystem, norm_py(name) if ecosystem == "PyPI" else name, version or "")


def _bare_purl(purl: str) -> str:
    return purl.split("?", 1)[0] if purl else ""


def findings(inv: BranchInventory, osv_json: dict) -> list[Finding]:
    """Attach osv-scanner results to the inventory's components by purl, else by
    (ecosystem, normalised name, version). Packages osv-scanner reports that the inventory
    does not know are still returned, with a synthetic component of scope unknown."""
    by_purl = {_bare_purl(c.purl): c for c in inv.components if c.purl}
    by_key = {_key(c.ecosystem, c.name, c.version): c for c in inv.components if c.kind == "package"}
    out: list[Finding] = []
    for result in osv_json.get("results") or []:
        for pkg in result.get("packages") or []:
            info = pkg.get("package") or {}
            ecosystem = (info.get("ecosystem") or "").split(":")[0]
            name, version = info.get("name", ""), info.get("version", "") or ""
            comp = by_purl.get(_bare_purl(info.get("purl", ""))) or by_key.get(_key(ecosystem, name, version))
            if comp is None:
                comp = Component(kind="package", ecosystem=ecosystem, name=name, version=version,
                                 purl=_bare_purl(info.get("purl", "")), scope="unknown")
            vulns = [summarize(v, ecosystem, name) for v in pkg.get("vulnerabilities") or []]
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
