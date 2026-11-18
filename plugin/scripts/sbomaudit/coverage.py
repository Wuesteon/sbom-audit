"""What the audit could not judge: packages without a resolved version and advisories without a severity.

Both are coverage gaps, reported as such instead of as findings or as clean:

- A package whose version is empty, Syft's `UNKNOWN` or an unexpanded `${property}` is kept in the inventory
  but not matched against OSV (`matching.version_unresolved`); `audit.json` lists it under
  `unresolved_versions`, AUDIT.md under "Version not resolved".
- An advisory without a CVSS score or database severity, also after `matching.summarize` looked at its aliases
  and its osv-scanner group, keeps severity `UNKNOWN`; reports print it as "not rated". In runtime scope of a
  production project or supported release it ranks with CRITICAL/HIGH (issues.json priority 3,
  reason `unrated_production`), because "not rated" is not "low".
"""
from __future__ import annotations

from .cvss import base_label
from .matching import version_unresolved
from .model import BranchInventory

UNRATED = "UNKNOWN"
UNRATED_TEXT = "not rated"
UNRESOLVED_TEXT = "version not resolved, not checked for vulnerabilities"
RATED = {"CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW", "NONE"}
SECTION_CAP = 12                     # package names shown per project@branch in AUDIT.md


def severity_text(label: str | None) -> str:
    """A severity label for people: `UNKNOWN` (or nothing) reads "not rated"."""
    return label if label and base_label(label).upper() in RATED else UNRATED_TEXT


def is_unrated(advisory: dict) -> bool:
    return base_label(advisory.get("severity") or UNRATED).upper() not in RATED


def unrated_advisories(v: dict) -> list[dict]:
    """The advisories of one `audit.json` vulnerability row that carry no severity."""
    return [a for a in v.get("vulns") or [] if is_unrated(a)]


def _local_action(c) -> bool:
    """A reusable workflow of the same repository (`uses: ./.github/workflows/x.yaml`): versionless by design."""
    return c.ecosystem.lower() == "github" and c.name.startswith(("$/", "./", "."))


def unresolved_versions(inventories: list[BranchInventory], releases: dict | None = None) -> list[dict]:
    """Per project and branch (or supported release), the packages that were not checked for vulnerabilities
    because their version is not resolved. Out-of-support releases are left out, like their findings."""
    rows = []
    for inv in sorted(inventories, key=lambda i: (i.project.lower(), i.branch)):
        info = (releases or {}).get((inv.project, inv.branch))
        if info and not info.get("supported", True):
            continue
        packages: dict[tuple, dict] = {}
        for c in inv.components:
            if c.kind != "package" or not version_unresolved(c.version) or _local_action(c):
                continue
            name = c.qualified_name()
            entry = packages.setdefault((c.ecosystem, name), {
                "ecosystem": c.ecosystem, "name": name, "version": c.version or "", "purl": c.purl,
                "manifests": [], "direct": False, "scope": c.scope})
            for loc in c.locations:
                if loc not in entry["manifests"]:
                    entry["manifests"].append(loc)
            entry["direct"] = entry["direct"] or bool(c.direct)
            if c.props.get("requirement") and "requirement" not in entry:
                entry["requirement"] = c.props["requirement"]
        if not packages:
            continue
        row = {"project": inv.project, "branch": inv.branch, "count": len(packages),
               "packages": sorted(packages.values(), key=lambda p: (p["ecosystem"], p["name"]))}
        if info:
            row["release"] = info.get("tag")
        rows.append(row)
    return rows


def unresolved_section(rows: list[dict]) -> list[str]:
    """AUDIT.md: the packages whose version is not resolved, per project@branch."""
    from .report import md                 # report imports this module
    L = ["## Version not resolved", "",
         f"Packages with no resolved version ({UNRESOLVED_TEXT}). Syft writes `UNKNOWN` when a Maven version comes "
         "from a BOM or parent outside the repository; a manifest without a lockfile gives no version at all. "
         "osv-scanner would treat such a package as affected by every advisory ever published for it, so it is "
         "left out of the sections above: neither vulnerable nor clean. Add a lockfile, or pin the version in the "
         "manifest. The full list is in `audit.json` under `unresolved_versions`.", ""]
    if not rows:
        return L + ["None: every package has a resolved version.", ""]
    for r in rows:
        shown = [f"`{md(p['name'])}`" for p in r["packages"][:SECTION_CAP]]
        more = f" … +{r['count'] - SECTION_CAP} more" if r["count"] > SECTION_CAP else ""
        ecos = ", ".join(sorted({p["ecosystem"] for p in r["packages"]}))
        L.append(f"- {r['project']}@{r['branch']}: {r['count']} package{'' if r['count'] == 1 else 's'} ({ecos}): "
                 + ", ".join(shown) + more)
    return L + [""]


def unrated_section(vulns: list[dict], ranked) -> list[str]:
    """AUDIT.md: package versions in runtime scope of a production project or supported release with at least
    one advisory that has no severity. `ranked(v)` says whether a row is in that scope."""
    from .report import md                 # report imports this module
    L = ["## Severity not rated", "",
         "Advisories that carry no CVSS score or database severity, also not on an aliased GHSA/CVE record or in "
         "osv-scanner's group score. Not rated is not low: in runtime scope of a production project or supported "
         "release they rank with CRITICAL/HIGH in `ISSUES.md` (priority 3) until someone reads them.", ""]
    rows = [(v, unrated_advisories(v)) for v in vulns if not v.get("kev") and ranked(v)]
    rows = [(v, u) for v, u in rows if u]
    if not rows:
        return L + ["None.", ""]
    L += ["| Package | Version | Not rated | Where | Advisories |", "|---|---|---|---|---|"]
    for v, unrated in rows:
        where = ", ".join(sorted({f"{l['project']}@{l['branch']}" for l in v["locations"]}))
        ids = ", ".join(a.get("id", "?") for a in unrated[:5]) + (" …" if len(unrated) > 5 else "")
        L.append(f"| {md(v.get('package') or v['name'])} | {md(v['version'] or 'unresolved')} | {len(unrated)} of {len(v['vulns'])} | "
                 f"{md(where)} | {md(ids)} |")
    return L + [""]
