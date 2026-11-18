"""Report writers: `audit.json`, `AUDIT.md`, `INVENTORY.md`, the dated copy and `log.md`.

`build()` turns the pipeline's results into one JSON-able dict; the writers only format it.
AUDIT.md keeps the fixed triage order (KEV → CRITICAL/HIGH in production → EOL → floating tags →
dev-only) and carries every hand-written `## Assessment` section of the previous file over unchanged.
"""
from __future__ import annotations

import datetime as dt
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from . import __version__, coverage, sbomimport
from .config import Config
from .cvss import SEV_ORDER, base_label
from .enrich import fixed_in
from .model import BranchInventory, Finding, qualified_name
from .versions import ver_key
from .vex import Suppressed

AUDIT_FILE = "AUDIT.md"
INVENTORY_FILE = "INVENTORY.md"
JSON_FILE = "audit.json"
LOG_FILE = "log.md"
REPORTS_DIR = "reports"
OUTDATED_CAP = 60

SEVERITY_ROWS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
ACTIONABLE = ("CRITICAL", "HIGH")
EOL_ICON = {"EOL": "🔴 EOL", "EOL soon": "🟠 EOL soon", "supported": "🟢 supported", "unknown": "⚪ unknown"}
EOL_ORDER = {"EOL": 0, "EOL soon": 1, "unknown": 2, "supported": 3, "minimum": 4}   # minimum: enrich.build_minimum
# INVENTORY.md overview columns: (header, component kind, names)
OVERVIEW_COLUMNS = [("Node", "runtime", ("nodejs",)), ("Python", "runtime", ("python",)),
                    ("Deno", "runtime", ("deno",)), ("Expo/React Native", "package", ("expo", "react-native")),
                    ("SvelteKit", "package", ("@sveltejs/kit",)), ("NestJS", "package", ("@nestjs/core",)),
                    ("Astro", "package", ("astro",)), ("Vite", "package", ("vite",)),
                    ("FastAPI", "package", ("fastapi",)), ("Postgres", "runtime", ("postgresql",))]
# shown only when a branch has a value in them (a JavaScript portfolio keeps the table above unchanged); the
# names are endoflife.date products, as the readers write a runtime component's name
OVERVIEW_OPTIONAL = [("Java/JDK", "runtime", ("java", "jdk", "openjdk", "eclipse-temurin", "amazon-corretto",
                                              "oracle-jdk", "azul-zulu", "microsoft-build-of-openjdk",
                                              "redhat-build-of-openjdk", "sapmachine", "graalvm")),
                     ("Go", "runtime", ("go",)), (".NET", "runtime", ("dotnet", "dotnetfx"))]

LOG_HEADER = ("# sbom-audit log\n\nAppend-only. Each run appends one line with the fields: time, `run`, projects, "
              "vulnerable package versions, KEV, CRITICAL, HIGH, EOL runtimes/images, floating images, suppressed by VEX. "
              "Add your own lines for assessments and remediation.\n\n")


def _now() -> str:
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat()


_LINE_BREAKS = re.compile("\r\n|[\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]")   # every str.splitlines() separator
# the rest of C0/C1 (ESC sequences, NUL, backspace) and the bidi overrides that reorder what a reader sees
_CONTROLS = re.compile("[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def md(s) -> str:
    """One table-safe line from untrusted text (advisory summaries, paths, authors, host output)."""
    return _CONTROLS.sub(" ", _LINE_BREAKS.sub(" ", str(s).replace("|", "\\|")))


def _pkg(v: dict) -> str:
    """The package name a reader sees: Maven `group:artifact`, every other ecosystem its own full name.
    `name` (the bare artifact for Maven) stays in audit.json for the issue ids and status identities."""
    return v.get("package") or v["name"]


def _direct_cell(direct) -> str:
    """The Direct column: `yes`, `no` (transitive) or `unknown` (the scan could not tell; never shown as `no`)."""
    return {True: "yes", False: "no"}.get(direct, "unknown")


def _sev_label(v: dict) -> str:
    label = base_label(v.get("severity") or "UNKNOWN").upper()
    if label == "MODERATE":
        return "MEDIUM"
    return label if label in SEVERITY_ROWS else "UNKNOWN"


def _sev_key(v: dict) -> tuple:
    return (SEV_ORDER.get(_sev_label(v), 5), -(v.get("cvss") or 0), v.get("id", ""))


def worst_advisory(advisories: list[dict]) -> dict | None:
    """The advisory to read first: an actively exploited one, else the most severe (CVSS breaks ties).

    `AUDIT.md` and `issues.json` both use this, so they always name the same one."""
    return min(advisories, key=lambda a: (not a.get("kev"), *_sev_key(a)), default=None)


def _actionable(v: dict) -> bool:
    return bool(v.get("kev")) or v.get("max_severity") in ACTIONABLE


def _scope_of(scopes: set[str]) -> str:
    if "required" in scopes:
        return "required"
    if scopes and scopes <= {"optional"}:
        return "optional"
    return "unknown"


def _manifest(c) -> str:
    return "; ".join(c.locations) or "?"


# --------------------------------------------------------------------------- build

def failed_label(f: dict) -> str:
    """What a failed-source entry is about: a project@branch (scanner) or a lookup key (`what`)."""
    return f.get("what") or f"{f.get('project')}@{f.get('branch')}"


def _sources(sources: dict | None) -> dict:
    out = {}
    for name, info in (sources or {}).items():
        info = dict(info or {})
        failed = info.get("failed")
        if isinstance(failed, list):
            info["failed"] = [f if isinstance(f, dict) else {"project": f[0], "branch": f[1], "error": str(f[2])}
                              for f in failed]
        out[name] = info
    return out


def out_of_support(releases: dict | None, project: str, branch: str) -> bool:
    """True for a release past its support period: listed in releases.json, not counted as open work."""
    info = (releases or {}).get((project, branch))
    return bool(info) and not info.get("supported", True)


def counts_as_production(loc: dict, production: set[str]) -> bool:
    """A location ranked like production: runtime scope in a production project or in a supported release
    (a release location in `audit.json` carries `release`; out-of-support ones are not in it)."""
    return loc.get("scope") != "optional" and (loc["project"] in production or bool(loc.get("release")))


def _vulnerabilities(findings: list[Finding], releases: dict | None = None) -> list[dict]:
    groups: dict[tuple, dict] = {}
    scopes: dict[tuple, set] = defaultdict(set)
    ids: dict[tuple, dict] = defaultdict(dict)
    for f in findings:
        if out_of_support(releases, f.project, f.branch):
            continue
        c = f.component
        key = (c.ecosystem, c.name, c.version)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"ecosystem": c.ecosystem, "name": c.name, "version": c.version,
                               "package": c.qualified_name(), "purl": c.purl.split("?", 1)[0],
                               "scope": "unknown", "direct_anywhere": False, "locations": [], "vulns": []}
        scopes[key].add(c.scope)
        loc = {"project": f.project, "branch": f.branch, "manifest": _manifest(c),
               "direct": c.direct, "scope": c.scope}
        if c.props.get("imported"):          # from an imported build SBOM (only then: audit.json unchanged)
            loc["imported"] = True
        if (f.project, f.branch) in (releases or {}):
            loc["release"] = releases[(f.project, f.branch)]["tag"]
        if loc not in g["locations"]:
            g["locations"].append(loc)
        if c.direct:
            g["direct_anywhere"] = True
        for v in f.vulns:
            vid = v.get("id", "")
            if vid in ids[key]:
                if v.get("kev"):
                    ids[key][vid]["kev"] = True
                continue
            v = dict(v)
            v["kev"] = bool(v.get("kev"))
            v["fixed_in"] = v.get("fixed_in") or fixed_in(v, c.version)
            ids[key][vid] = v
            g["vulns"].append(v)
    rows = []
    for key, g in groups.items():
        g["locations"].sort(key=lambda l: (l["project"], l["branch"], l["manifest"]))
        g["vulns"].sort(key=_sev_key)
        g["scope"] = _scope_of(scopes[key])
        g["max_severity"] = _sev_label(g["vulns"][0]) if g["vulns"] else "UNKNOWN"
        g["kev"] = any(v["kev"] for v in g["vulns"])
        rows.append(g)
    rows.sort(key=lambda g: (not g["kev"], SEV_ORDER.get(g["max_severity"], 5),
                             -(g["vulns"][0].get("cvss") or 0) if g["vulns"] else 0, g["name"], g["version"]))
    return rows


def _runtimes(eol_rows: list[dict], releases: dict | None = None) -> list[dict]:
    groups: dict[tuple, dict] = {}
    for r in eol_rows:
        if out_of_support(releases, r["project"], r["branch"]):
            continue
        # a go.mod build minimum (status `minimum`, enrich.build_minimum) is its own row, never merged into
        # the runtime row of the same cycle
        key = (r["product"], r.get("cycle", ""), r.get("basis"))
        g = groups.setdefault(key, {"product": r["product"], "cycle": r.get("cycle", ""),
                                    "status": r.get("status", "unknown"), "eol_date": r.get("eol_date"),
                                    "latest": r.get("latest"), "locations": []})
        if r.get("basis"):
            g.update(basis=r["basis"], cycle_status=r.get("cycle_status", "unknown"))
        loc = {"project": r["project"], "branch": r["branch"], "source": r.get("source", "")}
        if (r["project"], r["branch"]) in (releases or {}):
            loc["release"] = releases[(r["project"], r["branch"])]["tag"]
        g["locations"].append(loc)
    rows = list(groups.values())
    for g in rows:
        g["locations"].sort(key=lambda l: (l["project"], l["branch"]))
    rows.sort(key=lambda g: (EOL_ORDER.get(g["status"], 2), g["product"], ver_key(g["cycle"] or "0")))
    return rows


def _unpinned_images(inventories: list[BranchInventory]) -> list[dict]:
    rows = []
    for inv in inventories:
        if inv.release:                      # a release is frozen: the tag is pinned on the branches
            continue
        for c in inv.components:
            if c.kind == "image" and c.props.get("floating"):
                rows.append({"project": inv.project, "branch": inv.branch, "image": c.props.get("image") or c.name,
                             "source": c.props.get("source") or (c.locations[0] if c.locations else ""),
                             "own": bool(c.props.get("own"))})
    rows.sort(key=lambda r: (r["project"], r["branch"], r["image"], r["source"]))
    return rows


def _notes(inventories: list[BranchInventory]) -> list[str]:
    notes = []
    for inv in sorted(inventories, key=lambda i: (i.project.lower(), i.branch)):
        tag = f"{inv.project}@{inv.branch}"
        for err in inv.errors:
            notes.append(f"{tag}: {err}")
        for c in inv.components:
            unpinned = c.props.get("unpinned_requirements")
            if unpinned:
                files = ", ".join(f"`{u}`" for u in unpinned)
                notes.append(f"{tag}: `{c.props.get('image', c.name)}` ({_manifest(c)}) installs {files} with "
                             "non-pinned requirements, so the image may run versions other than the lockfile "
                             "audited here. Pin them (`uv export --format requirements-txt`) or install from the lockfile.")
    # packages without a version: `unresolved_versions` (coverage.py)
    return notes + _import_notes(inventories) + _unchecked_actions_notes(inventories)


def imported_sboms(inventories: list[BranchInventory]) -> list[dict]:
    """One row per inventory whose packages (of some ecosystems) come from an imported build SBOM."""
    return [{"project": inv.project, "branch": inv.branch, "scanned_commit": inv.commit, **inv.package_source}
            for inv in sorted(inventories, key=lambda i: (i.project.lower(), i.branch)) if inv.package_source]


def _import_notes(inventories: list[BranchInventory]) -> list[str]:
    return [f"{md(r['project'])}@{md(r['branch'])}: {md(sbomimport.describe(r))}" for r in imported_sboms(inventories)]


def is_github_action(c) -> bool:
    """A GitHub Action used in a workflow (`pkg:github/<owner>/<repo>@<ref>`, Syft's workflow catalogers)."""
    return c.kind == "package" and (c.ecosystem == "github" or (c.purl or "").startswith("pkg:github/"))


def unchecked_actions(inventories: list[BranchInventory]) -> int:
    """GitHub Actions in the branches' inventories (one per action and branch). They are inventoried but not
    checked for vulnerabilities: OSV's "GitHub Actions" advisories carry only ECOSYSTEM ranges, which OSV
    does not match against a version, and workflows mostly pin a floating major tag (`v4`) or a commit."""
    return sum(1 for inv in inventories if not inv.release for c in inv.components if is_github_action(c))


def _unchecked_actions_notes(inventories: list[BranchInventory]) -> list[str]:
    notes = []
    for inv in sorted(inventories, key=lambda i: (i.project.lower(), i.branch)):
        if inv.release:
            continue
        names = sorted({c.name for c in inv.components if is_github_action(c)})
        if names:
            shown = ", ".join(f"`{md(n)}`" for n in names[:10]) + (" …" if len(names) > 10 else "")
            notes.append(f"{inv.project}@{inv.branch}: {len(names)} GitHub Actions are inventoried but not checked "
                         f"for vulnerabilities (OSV does not match versions for this ecosystem): {shown}")
    return notes


def build(cfg: Config, inventories: list[BranchInventory], findings: list[Finding],
          suppressed: list[Suppressed], eol: list[dict], outdated: list[dict], sources: dict | None,
          releases: dict | None = None) -> dict:
    """Everything the writers need, JSON-serialisable (this is `audit.json`).

    `releases` is `releases.context()`: (project, branch) -> release info for every release inventory.
    Locations in a supported release carry `release: <tag>`; out-of-support releases are left out of
    `vulnerabilities` and `runtimes` (they are listed in `releases` and in `releases.json`)."""
    packages = [c for inv in inventories for c in inv.components if c.kind == "package"]
    stats = {
        "projects": len({i.project for i in inventories}),
        "branches": sum(1 for i in inventories if not i.release),
        "unique_package_versions": len({(c.ecosystem, c.name, c.version) for c in packages}),
        "occurrences": len(packages),
        "direct_dependencies": sum(1 for c in packages if c.direct),
        "images": sum(1 for inv in inventories for c in inv.components if c.kind == "image"),
        "runtimes": sum(1 for inv in inventories for c in inv.components if c.kind == "runtime"),
        "github_actions_unchecked": unchecked_actions(inventories),
    }
    unresolved = coverage.unresolved_versions(inventories, releases)
    stats["unresolved_versions"] = sum(r["count"] for r in unresolved)
    rep = {
        "generated_at": _now(),
        "sources": _sources(sources),
        "vulnerabilities": _vulnerabilities(findings, releases),
        "runtimes": _runtimes(eol, releases),
        "outdated": [dict(o) for o in outdated],
        "unpinned_images": _unpinned_images(inventories),
        "suppressed": [s.to_dict() if isinstance(s, Suppressed) else dict(s) for s in suppressed],
        "notes": _notes(inventories),
        "stats": stats,
        "production_projects": sorted(name for name, opts in cfg.projects.items() if opts.production),
    }
    if unresolved:                           # only when some package was not checked (coverage.py)
        rep["unresolved_versions"] = unresolved
    imports = imported_sboms(inventories)
    if imports:                              # only with an imported build SBOM (sbomimport.py)
        rep["imported_sboms"] = imports
        stats["imported_sboms"] = len(imports)
        stats["imported_sboms_not_current"] = sum(1 for r in imports if sbomimport.staleness(r))
    if releases:                             # only with release scanning: audit.json is unchanged without it
        stats["releases"] = len(releases)
        rep["releases"] = [{"project": p, "branch": b, "tag": r["tag"], "date": r.get("date"),
                            "supported": r["supported"], "support_until": r["support_until"]}
                           for (p, b), r in sorted(releases.items(), key=lambda kv: (kv[0][0].lower(), kv[0][1]))]
    return rep


def write_json(rep: dict, out: Path) -> Path:
    path = Path(out) / JSON_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rep, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


# --------------------------------------------------------------------------- AUDIT.md

def _source_status(sources: dict) -> list[str]:
    L = ["## Source status", "", "A failed source means its section below is empty, not clean.", "",
         "| Source | Status | Detail |", "|---|---|---|"]
    if not sources:
        L.append("| – | – | no sources recorded |")
    for name, info in sources.items():
        failed = info.get("failed") or []
        counts = ", ".join(f"{k}={v}" for k, v in info.items()
                           if k not in ("failed", "error", "skipped") and v is not None)
        if info.get("skipped"):
            status, detail = "skipped", md(info["skipped"]) if isinstance(info["skipped"], str) else "–"
        elif info.get("error"):
            status, detail = "**failed**", md(info["error"])
        elif failed:
            status = f"**partial** ({len(failed)} failed)"
            detail = "; ".join(f"{failed_label(f)}: {md(f['error'])}" for f in failed)
            if counts:
                detail = f"{counts}; {detail}"
        else:
            status, detail = "ok", counts or "–"
        L.append(f"| {name} | {status} | {detail} |")
    L.append("")
    return L


def _summary(rep: dict) -> list[str]:
    vulns = rep["vulnerabilities"]
    st = rep["stats"]
    production = set(rep.get("production_projects", []))
    by_sev = Counter(v["max_severity"] for v in vulns)
    prod_rows = [v for v in vulns if _actionable(v)
                 and any(counts_as_production(l, production) for l in v["locations"])]
    dev_only = [v for v in vulns if v["scope"] == "optional"]
    scanned = f"{st['projects']} / {st['branches']}"
    if st.get("releases"):
        scanned += f" (+ {st['releases']} release{'' if st['releases'] == 1 else 's'})"
    rows: list[tuple[str, object]] = [
        ("Projects / branches scanned", scanned),
        ("Unique package versions checked", st["unique_package_versions"]),
        ("Vulnerable package versions", len(vulns)),
        ("… in CISA KEV (actively exploited)", sum(1 for v in vulns if v["kev"])),
    ]
    rows += [(f"… max severity {coverage.severity_text(s)}", by_sev[s]) for s in SEVERITY_ROWS if by_sev.get(s)]
    rows += [
        ("CRITICAL/HIGH in production projects" + (" or supported releases" if st.get("releases") else "")
         + " (excluding dev-only)", len(prod_rows)),
        ("Severity not rated in production" + (" or supported releases" if st.get("releases") else "")
         + " (excluding dev-only, KEV)", sum(1 for v in vulns if unrated_in_production(v, production))),
        ("Packages with version not resolved, not checked for vulnerabilities", st.get("unresolved_versions", 0)),
        ("Dev-only vulnerable package versions", len(dev_only)),
        ("Vulnerable direct dependencies", sum(1 for v in vulns if v["direct_anywhere"])),
        ("Runtimes / images past end-of-life", sum(1 for r in rep["runtimes"] if r["status"] == "EOL")),
        ("Runtimes / images reaching EOL within 90 days", sum(1 for r in rep["runtimes"] if r["status"] == "EOL soon")),
        ("Floating container images (unique)", len({u["image"] for u in rep["unpinned_images"]})),
        ("Direct deps ≥1 major behind latest",
         len({(o["project"], o["ecosystem"], o["name"]) for o in rep["outdated"]})),
        ("Suppressed by VEX", len(rep["suppressed"])),
    ]
    if st.get("github_actions_unchecked"):
        rows.append(("GitHub Actions inventoried, not checked for vulnerabilities", st["github_actions_unchecked"]))
    L = ["## Summary", "", "| Metric | Count |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in rows]
    L.append("")
    if not production and not st.get("releases"):
        L += ["_No project is marked `production = true` in `sbom-audit.toml`, so the production row counts nothing; "
              "mark the projects that serve traffic or hold keys._", ""]
    L += ["MEDIUM and LOW advisories are not listed below, nor not-rated ones outside production; they are in "
          "`audit.json` under `vulnerabilities`.", ""]
    return L


def unrated_in_production(v: dict, production: set[str]) -> bool:
    """A package version with an advisory that has no severity, in runtime scope of a production project or
    supported release, and not already ranked as KEV. Ranks with CRITICAL/HIGH (`coverage.py`)."""
    return (not v.get("kev") and bool(coverage.unrated_advisories(v))
            and any(counts_as_production(l, production) for l in v.get("locations") or []))


def _fix_cells(v: dict) -> tuple[str, str, str]:
    """(severity cell, fix target cell, worst advisory cell) for one vulnerable package version."""
    fixes = [s.get("fixed_in") for s in v["vulns"]]
    target = max((f for f in fixes if f), key=ver_key, default=None)
    unfixed = sum(1 for f in fixes if not f)
    fix_cell = (target or "–") + (f" ({unfixed} unfixed)" if unfixed and target else "")
    worst = worst_advisory(v["vulns"]) or {"id": "?", "cves": [], "summary": ""}
    adv = worst["id"] + (f" ({worst['cves'][0]})" if worst.get("cves") and worst["id"] not in worst["cves"] else "")
    sev = coverage.severity_text(v["max_severity"]) + (f" {worst['cvss']}" if worst.get("cvss") is not None else "") + (" 🔴KEV" if v["kev"] else "")
    return sev, fix_cell, f"{adv}: {md(worst.get('summary', '')[:90])}"


def _kev_section(vulns: list[dict]) -> list[str]:
    L = ["## 🔴 Actively exploited (CISA KEV)", ""]
    rows = [v for v in vulns if v["kev"]]
    if not rows:
        return L + ["None of the vulnerable package versions is in the CISA Known Exploited Vulnerabilities catalog.", ""]
    for v in rows:
        ids = ", ".join(f"{s['id']} {' '.join(s.get('cves', []))}".strip() for s in v["vulns"] if s.get("kev"))
        where = ", ".join(sorted({f"{l['project']}@{l['branch']}" for l in v["locations"]}))
        scope = "dev-only" if v["scope"] == "optional" else "runtime scope"
        L.append(f"- **{md(_pkg(v))}@{v['version'] or 'unresolved'}** ({v['ecosystem']}, {scope}): {ids} — used by {where}")
    return L + [""]


def _by_project_section(vulns: list[dict], production: set[str]) -> list[str]:
    L = ["## Critical and high severity by project", "",
         "KEV, CRITICAL and HIGH package versions with runtime scope; dev-only occurrences are listed further down. "
         "Production projects come first. `Fix target` is the lowest version that closes every listed advisory "
         "(`–` = no fix released). Direct `yes` = the manifest declares the package itself; `no` = it is transitive "
         "and the fix is a lockfile refresh of the parent; `unknown` = the scan could not tell whether the manifest "
         "declares it, which is not the same as transitive: check the manifest first.", ""]
    per: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for v in vulns:
        if not _actionable(v):
            continue
        for l in v["locations"]:
            if l.get("scope") != "optional":
                per[l["project"]][l["branch"]].append((v, l))
    if not per:
        return L + ["None.", ""]
    for p in sorted(per, key=lambda p: (p not in production, p.lower())):
        L += [f"### {p}" + (" (production)" if p in production else ""), ""]
        for b in sorted(per[p]):
            rows = sorted(per[p][b], key=lambda vl: (not vl[0]["kev"], SEV_ORDER.get(vl[0]["max_severity"], 5), vl[0]["name"]))
            L += [f"**`{b}`** — {len(rows)} vulnerable package version{'' if len(rows) == 1 else 's'}", "",
                  "| Sev | Package | Version | Advisories | Fix target | Direct | Manifest | Worst advisory |",
                  "|---|---|---|---|---|---|---|---|"]
            for v, l in rows:
                sev, fix, worst = _fix_cells(v)
                L.append(f"| {sev} | {md(_pkg(v))} | {v['version'] or 'unresolved'} | {len(v['vulns'])} | {fix} | "
                         f"{_direct_cell(l.get('direct'))} | `{md(l['manifest'])}` | {worst} |")
            L.append("")
    return L


def _runtime_section(runtimes: list[dict]) -> list[str]:
    L = ["## Runtimes and base images", ""]
    if not runtimes:
        return L + ["No runtime or base-image cycles were checked (none found, or endoflife.date was skipped).", ""]
    L += ["| Status | Product | Cycle | EOL date | Latest in cycle | Where | Via |", "|---|---|---|---|---|---|---|"]
    for r in runtimes:
        where = ", ".join(sorted({f"{l['project']}@{l['branch']}" for l in r["locations"]}))
        via = "; ".join(sorted({l["source"] for l in r["locations"] if l.get("source")}))
        status = (f"build minimum (cycle {r.get('cycle_status') or 'unknown'})" if r["status"] == "minimum"
                  else EOL_ICON.get(r["status"], r["status"]))
        L.append(f"| {status} | {r['product']} | {r['cycle'] or '?'} | "
                 f"{r.get('eol_date') or '–'} | {r.get('latest') or '–'} | {md(where)} | {md(via)} |")
    L += ["", "_`engines` / `requires-python` give the lowest version the manifest allows (what runs depends on the "
          "host); Dockerfile and compose images are what actually runs in containers; Supabase edge runtime and "
          "Postgres are managed but still age out._", ""]
    if any(r["status"] == "minimum" for r in runtimes):
        L += ["_`build minimum`: the Go version in a go.mod (`go` or `toolchain` line) is the lowest Go that may "
              "build the module, not the Go that runs it: the binary carries the runtime of whichever toolchain "
              "builds it. It is listed for information and not counted as end of life; the cycle's own status is "
              "in brackets. To check what you ship, look at the `golang` build image or the CI's Go version._", ""]
    return L


def _floating_section(unpinned: list[dict]) -> list[str]:
    L = ["## Floating image tags", ""]
    if not unpinned:
        return L + ["None: every container image is pinned to at least a major version.", ""]
    L += ["Rebuilds silently pull whatever is current; pin a major at least. `own image` = built by this project's "
          "CI, so the tag is a deploy choice rather than an upstream risk.", ""]
    grouped: dict[tuple, dict] = {}
    for u in unpinned:
        g = grouped.setdefault((u["project"], u["image"], u["source"]), {"own": u["own"], "branches": set()})
        g["branches"].add(u["branch"])
    for (project, image, source), g in sorted(grouped.items()):
        own = " (own image)" if g["own"] else ""
        L.append(f"- `{image}`{own} — {project}@{', '.join(sorted(g['branches']))} (`{source}`)")
    return L + [""]


def _outdated_section(outdated: list[dict]) -> list[str]:
    L = ["## Outdated direct dependencies (≥1 major version behind)", ""]
    if not outdated:
        return L + ["None (or registry lookups were skipped).", ""]
    merged: dict[tuple, dict] = {}
    for o in outdated:
        key = (o["project"], o["ecosystem"], o["name"], o["current"], o["latest"])
        merged.setdefault(key, {**o, "branches": set()})["branches"].add(o["branch"])
    rows = sorted(merged.values(), key=lambda o: (-o["major_behind"], o["project"], o["name"]))
    L += [f"{len(rows)} direct dependencies are at least one major behind (branches merged). Showing the top "
          f"{min(OUTDATED_CAP, len(rows))}; the full list is in `audit.json` under `outdated`.", "",
          "| Behind | Package | Current | Latest | Project | Branches | Ecosystem | Scope |",
          "|---|---|---|---|---|---|---|---|"]
    for o in rows[:OUTDATED_CAP]:
        L.append(f"| {o['major_behind']} | {md(o['name'])} | {o['current']} | {o['latest']} | {o['project']} | "
                 f"{', '.join(sorted(o['branches']))} | {o['ecosystem']} | {o.get('scope') or ''} |")
    L += ["", "_Major-version lag is not a vulnerability by itself, but EOL majors stop receiving security fixes. "
          "Expo SDK packages (`expo-*`) use SDK-aligned version numbers, so a lag of 50+ majors there means one or "
          "two SDK generations._", ""]
    return L


def _dev_only_section(vulns: list[dict]) -> list[str]:
    L = ["## Dev-only findings", "",
         "KEV, CRITICAL and HIGH package versions that occur here only as a devDependency or build-time tool "
         "(SBOM scope `optional`, labelled dev-only). Fix them, but they are not a production exposure.", ""]
    rows = [(v, l) for v in vulns if _actionable(v) for l in v["locations"] if l.get("scope") == "optional"]
    if not rows:
        return L + ["None.", ""]
    L += ["| Sev | Package | Version | Advisories | Fix target | Direct | Project@branch | Manifest | Scope |",
          "|---|---|---|---|---|---|---|---|---|"]
    for v, l in rows:
        sev, fix, _ = _fix_cells(v)
        L.append(f"| {sev} | {md(_pkg(v))} | {v['version'] or 'unresolved'} | {len(v['vulns'])} | {fix} | "
                 f"{_direct_cell(l.get('direct'))} | {l['project']}@{l['branch']} | `{md(l['manifest'])}` | dev-only |")
    return L + [""]


def _suppressed_section(suppressed: list[dict]) -> list[str]:
    L = ["## Suppressed by VEX", "",
         "Findings removed from the sections above by an OpenVEX statement in `vex/`. "
         "Re-check them when the package version or the code path changes.", ""]
    if not suppressed:
        return L + ["None.", ""]
    L += ["| Vulnerability | Package | Version | Project@branch | Status | Justification | Impact statement | File |",
          "|---|---|---|---|---|---|---|---|"]
    for s in suppressed:
        f, st, c = s["finding"], s["statement"], s["finding"]["component"]
        vid = f["vulns"][0]["id"] if f.get("vulns") else st["vuln"]
        L.append(f"| {vid} | {md(qualified_name(c['ecosystem'], c['name'], c.get('purl') or ''))} | {c['version'] or 'unresolved'} | {f['project']}@{f['branch']} | "
                 f"{st['status']} | {st.get('justification') or '–'} | {md(st.get('impact') or '–')} | "
                 f"`{Path(st.get('path') or '').name or '–'}` |")
    return L + [""]


def _releases_section(releases: list[dict]) -> list[str]:
    """Short list of the releases under audit; details (counts, fixed advisories) are in RELEASES.md."""
    if not releases:
        return []
    L = ["## Releases under audit", "",
         "Release tags scanned like branches (location `tags/<tag>`). Findings in a supported release rank like "
         "production; out-of-support releases are left out of the sections above. Per-release counts and "
         "advisories fixed since the previous release: `RELEASES.md` / `releases.json`.", ""]
    for r in releases:
        if not r.get("support_until"):
            state = "supported (no period configured)"
        elif r["supported"]:
            state = f"supported until {r['support_until']}"
        else:
            state = f"out of support since {r['support_until']}"
        L.append(f"- {r['project']} `{md(r['tag'])}` ({(r.get('date') or '?')[:10]}): {state}")
    return L + [""]


def _notes_section(notes: list[str]) -> list[str]:
    L = ["## Notes", ""]
    if not notes:
        return L + ["None.", ""]
    return L + [f"- {n}" for n in notes] + [""]


def carried_over(previous: str) -> str:
    """Every `## Assessment …` section of the previous AUDIT.md, verbatim, or ''."""
    m = re.search(r"^## Assessment ", previous, re.M)
    if not m:
        return ""
    return "\n" + previous[m.start():].rstrip("\n") + "\n"


def _imports_line(imports: list[dict]) -> list[str]:
    """Coverage: which package lists come from an imported build SBOM, and which of those are not this commit's."""
    if not imports:
        return []
    off = [r for r in imports if sbomimport.staleness(r)]
    text = (f"Imported build SBOMs: {len(imports)} project branches or releases take the packages of some ecosystems "
            "from a build SBOM; packages only the repository scan found are kept in addition (counts under Notes "
            "and in `INVENTORY.md`)")
    if off:
        text += (f"; {len(off)} of them not built from the scanned commit or with no commit recorded: "
                 + ", ".join(f"{md(r['project'])}@{md(r['branch'])} ({sbomimport.staleness(r)})" for r in off))
    return [text + ".", ""]


def write_audit_md(rep: dict, out: Path) -> Path:
    out = Path(out)
    production = set(rep.get("production_projects", []))
    L = [f"# Dependency Audit — {rep['generated_at'][:10]}", "",
         f"Generated {rep['generated_at']} by sbom-audit {__version__}. Sources: Syft SBOMs per project and branch "
         "(committed tree, not the working copy), osv-scanner against OSV.dev, CISA KEV (actively exploited), "
         "endoflife.date (runtimes and base images), npm/PyPI/JSR registries (latest versions), OpenVEX statements "
         "in `vex/`. Full data: `audit.json`; what is installed where: `INVENTORY.md`.", ""]
    L += _imports_line(rep.get("imported_sboms") or [])
    L += _source_status(rep.get("sources") or {})
    L += _summary(rep)
    L += _kev_section(rep["vulnerabilities"])
    L += _by_project_section(rep["vulnerabilities"], production)
    if any(unrated_in_production(v, production) for v in rep["vulnerabilities"]):
        L += coverage.unrated_section(rep["vulnerabilities"], lambda v: unrated_in_production(v, production))
    L += _runtime_section(rep["runtimes"])
    L += _floating_section(rep["unpinned_images"])
    L += _outdated_section(rep["outdated"])
    L += _dev_only_section(rep["vulnerabilities"])
    L += _suppressed_section(rep["suppressed"])
    L += _releases_section(rep.get("releases") or [])
    if rep.get("unresolved_versions"):
        L += coverage.unresolved_section(rep["unresolved_versions"])
    L += _notes_section(rep["notes"])
    text = "\n".join(L) + "\n"
    path = out / AUDIT_FILE
    if path.exists():
        text += carried_over(path.read_text(encoding="utf-8"))
    out.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def write_dated_copy(out: Path, date: dt.date | None = None) -> Path:
    out = Path(out)
    dated = out / REPORTS_DIR / f"{(date or dt.date.today()).isoformat()}-audit.md"
    dated.parent.mkdir(parents=True, exist_ok=True)
    dated.write_text((out / AUDIT_FILE).read_text(encoding="utf-8"), encoding="utf-8")
    return dated


def append_log(out: Path, rep: dict, inventories: list[BranchInventory]) -> Path:
    path = Path(out) / LOG_FILE
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(LOG_HEADER, encoding="utf-8")
    vulns = rep["vulnerabilities"]
    fields = [rep["generated_at"], "run", len({i.project for i in inventories}), len(vulns),
              sum(1 for v in vulns if v["kev"]), sum(1 for v in vulns if v["max_severity"] == "CRITICAL"),
              sum(1 for v in vulns if v["max_severity"] == "HIGH"),
              sum(1 for r in rep["runtimes"] if r["status"] == "EOL"),
              len({u["image"] for u in rep["unpinned_images"]}), len(rep["suppressed"])]
    line = " | ".join(str(f) for f in fields)
    problems = []
    for name, info in (rep.get("sources") or {}).items():
        if info.get("error"):
            problems.append(f"{name}: {info['error']}")
        problems += [f"{name} {failed_label(f)}: {f['error']}" for f in info.get("failed") or []]
    if problems:
        line += " | failed: " + "; ".join(md(p) for p in problems)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    return path


def append_secrets_log(out: Path, doc: dict) -> Path:
    """One `secrets` line: time, `secrets`, mode, repos, open findings per class, then the skip reason or
    the failed repositories. The document is redacted, so the line can hold no secret."""
    path = Path(out) / LOG_FILE
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(LOG_HEADER, encoding="utf-8")
    scan = doc.get("scan") or {}
    open_ = [f for f in doc.get("findings") or [] if f.get("status") == "open"]
    fields = [doc.get("generated_at"), "secrets", scan.get("mode"), f"repos {scan.get('repos', 0)}",
              *(f"{cls} {sum(1 for f in open_ if f.get('class') == cls)}" for cls in "ABC")]
    line = " | ".join(md(f) for f in fields)
    if scan.get("mode") == "skipped" and scan.get("skipped_reason"):
        line += f" | {md(scan['skipped_reason'])}"
    failed = [f"{f.get('repo')}: {f.get('error')}" for f in scan.get("failed") or []]
    if failed:
        line += " | failed: " + "; ".join(md(f) for f in failed)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    return path


def append_assess_log(out: Path, path: str, cost: float | None) -> Path:
    """One `assess-proposal` line: time, `assess-proposal`, cost (or `cost unknown`), the proposal's relative
    path. Never the proposal text."""
    log = Path(out) / LOG_FILE
    if not log.exists():
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(LOG_HEADER, encoding="utf-8")
    fields = [_now(), "assess-proposal",
              f"cost {cost:.2f}" if cost is not None else "cost unknown", path]
    with log.open("a", encoding="utf-8") as fh:
        fh.write(" | ".join(md(f) for f in fields) + "\n")
    return log


_RUN_LINE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")


def append_note(out: Path, text: str) -> Path:
    """Append ` | <text>` to the last line of log.md when it is a run line (starts with a date);
    otherwise (no file, empty file, header only, a hand-written line) the note becomes its own line."""
    path = Path(out) / LOG_FILE
    body = path.read_text(encoding="utf-8") if path.exists() else ""
    if not body.strip():
        body = LOG_HEADER
    lines = body.rstrip("\n").split("\n")
    if _RUN_LINE_RE.match(lines[-1]):
        lines[-1] += f" | {md(text)}"
        body = "\n".join(lines) + "\n"
    else:
        body = body + ("" if body.endswith("\n") else "\n") + md(text) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- INVENTORY.md

def _overview_cell(inv: BranchInventory, kind: str, names: tuple[str, ...]) -> str:
    vals = set()
    for c in inv.components:
        if c.kind != kind or c.name.lower() not in names:
            continue
        if kind == "package" and not c.direct:
            continue
        version = c.version or "?"
        vals.add(f"{c.name} {version}" if len(names) > 1 else version)
    return ", ".join(sorted(vals)) or "–"


def overview_columns(invs: list[BranchInventory]) -> list[tuple[str, str, tuple[str, ...]]]:
    """The overview table's columns: `OVERVIEW_COLUMNS` always, `OVERVIEW_OPTIONAL` when some branch has a
    value there, then one column per other runtime pinned in a manifest (not derived from an image, which
    the Images column shows), named by its endoflife.date product, so a runtime a reader learns to detect
    shows up without a change here."""
    cols = list(OVERVIEW_COLUMNS)
    cols += [col for col in OVERVIEW_OPTIONAL if any(_overview_cell(i, col[1], col[2]) != "–" for i in invs)]
    covered = {n for _, kind, names in cols + OVERVIEW_OPTIONAL if kind == "runtime" for n in names}
    extra = sorted({c.name.lower() for i in invs for c in i.components
                    if c.kind == "runtime" and c.name and "image" not in c.props and c.name.lower() not in covered})
    return cols + [(name, "runtime", (name,)) for name in extra]


def _branch_order(cfg: Config, branches: set[str]) -> list[str]:
    return sorted(branches, key=lambda b: (cfg.branches.index(b) if b in cfg.branches else len(cfg.branches), b))


def _inventory_project(cfg: Config, project: str, invs: list[BranchInventory]) -> list[str]:
    L = [f"## {project}", ""]
    for inv in invs:
        pkgs = [c for c in inv.components if c.kind == "package"]
        by_eco = Counter(c.ecosystem or "?" for c in pkgs)
        n_images = sum(1 for c in inv.components if c.kind == "image")
        n_runtimes = sum(1 for c in inv.components if c.kind == "runtime")
        sync = f"{inv.behind} behind origin" if inv.behind else "in sync with origin"
        ref = f", read `{inv.ref}`" if inv.ref != inv.branch else ""
        eco = ", ".join(f"{e} {n}" for e, n in sorted(by_eco.items())) or "none"
        L.append(f"- **`{inv.branch}`** {inv.commit[:7]} ({sync}{ref}): {len(pkgs)} packages ({eco}; "
                 f"{sum(1 for c in pkgs if c.direct)} direct, {sum(1 for c in pkgs if c.scope == 'optional')} dev-only), "
                 f"{n_images} images, {n_runtimes} runtime pins")
        if inv.package_source:
            L.append(f"  - packages: {md(sbomimport.describe(inv.package_source))}")
        for err in inv.errors:
            L.append(f"  - error: {md(err)}")
    L.append("")
    # runtimes and images
    rows: dict[tuple, set] = {}
    for inv in invs:
        for c in inv.components:
            source = c.props.get("source") or (c.locations[0] if c.locations else "")
            if c.kind == "runtime":
                key = (c.name, c.version or "?", "runtime", c.props.get("detail", ""), source)
            elif c.kind == "image":
                level = c.props.get("pin_level") or ("none" if c.props.get("floating") else "?")
                flags = ["floating tag" if level == "none" else f"pinned to {level}"]
                if c.props.get("own"):
                    flags.append("own image")
                key = (c.props.get("image", c.name), c.version or "(untagged)", "image", ", ".join(flags), source)
            else:
                continue
            rows.setdefault(key, set()).add(inv.branch)
    if rows:
        L += ["**Runtimes & images**", "", "| Product / image | Cycle / tag | Kind | Detail | Source | Branches |",
              "|---|---|---|---|---|---|"]
        for (name, cycle, kind, detail, source), branches in sorted(rows.items()):
            L.append(f"| `{md(name)}` | {md(cycle)} | {kind} | {md(detail) or '–'} | `{md(source)}` | "
                     f"{', '.join(f'`{b}`' for b in _branch_order(cfg, branches))} |")
        L.append("")
    # direct dependencies
    direct: dict[tuple, dict] = {}
    for inv in invs:
        for c in inv.components:
            if c.kind == "package" and c.direct:
                d = direct.setdefault((c.ecosystem, c.qualified_name(), _manifest(c)), {"versions": {}, "scopes": set()})
                d["versions"][inv.branch] = c.version or "unresolved"
                d["scopes"].add(c.scope)
    branches = _branch_order(cfg, {inv.branch for inv in invs})
    if direct:
        L += [f"**Direct dependencies** ({len(direct)}; `⚠︎` = version differs between branches)", "",
              "| Package | Ecosystem | Manifest | " + " | ".join(f"`{b}`" for b in branches) + " | Scope |",
              "|---|---|---|" + "---|" * len(branches) + "---|"]
        for (eco, name, manifest), d in sorted(direct.items(), key=lambda kv: (kv[0][2], kv[0][1].lower())):
            present = {d["versions"][b] for b in branches if b in d["versions"]}
            drift = " ⚠︎" if len(present) > 1 else ""
            cells = [d["versions"].get(b, "–") for b in branches]
            L.append(f"| {md(name)}{drift} | {eco} | `{md(manifest)}` | " + " | ".join(cells) + f" | {_scope_of(d['scopes'])} |")
        L.append("")
    return L


def _inventory_releases(releases: list[BranchInventory]) -> list[str]:
    """One line per release under audit; its components are in its own SBOM (not repeated here)."""
    if not releases:
        return []
    L = ["## Releases", "",
         "Release tags under audit, one SBOM each (`sbom/<project>/tags__<tag>.cdx.json`). Support status and fixed "
         "advisories: `RELEASES.md`.", "",
         "| Project | Tag | Commit | Tag date | Packages | Images | Runtime pins | SBOM |", "|---|---|---|---|---|---|---|---|"]
    for inv in sorted(releases, key=lambda i: (i.project.lower(), -int(i.release.get("index", 0)))):
        pkgs = sum(1 for c in inv.components if c.kind == "package")
        imgs = sum(1 for c in inv.components if c.kind == "image")
        rts = sum(1 for c in inv.components if c.kind == "runtime")
        sbom = f"`{inv.sbom_path}`" if inv.sbom_path else "–"
        L.append(f"| {md(inv.project)} | `{md(inv.release.get('tag', inv.branch))}` | {inv.commit[:7] or '–'} | "
                 f"{(inv.release.get('date') or '?')[:10]} | {pkgs} | {imgs} | {rts} | {sbom} |")
        if inv.package_source:
            L.append(f"| | | | | | | | packages: {md(sbomimport.describe(inv.package_source))} |")
        for err in inv.errors:
            L.append(f"| | | | | | | | error: {md(err)} |")
    return L + [""]


def write_inventory_md(cfg: Config, inventories: list[BranchInventory], out: Path) -> Path:
    releases = [i for i in inventories if i.release]
    invs = sorted((i for i in inventories if not i.release), key=lambda i: (i.project.lower(), i.branch))
    branches = ", ".join(f"`{b}`" for b in cfg.branches)
    columns = overview_columns(invs)
    L = ["# Inventory", "",
         f"Generated {_now()} from `{cfg.root}` ({cfg.mode} mode, branches {branches}). Components come from the "
         "Syft SBOM of each branch's committed tree (`sbom/<project>/<branch>.cdx.json`) plus own readers for "
         "images and runtime pins, or, for the ecosystems it holds, from a build SBOM imported for that branch (marked "
         "below); the working tree is never read. Findings: `AUDIT.md`; full data: `inventory.json`.", "",
         "## Overview", "",
         "| Project | Branch | " + " | ".join(md(h) for h, _, _ in columns) + " | Images |",
         "|" + "---|" * (len(columns) + 3)]
    for inv in invs:
        cells = [_overview_cell(inv, kind, names) for _, kind, names in columns]
        images = ", ".join(sorted({f"`{c.props.get('image', c.name)}`" for c in inv.components if c.kind == "image"})) or "–"
        L.append(f"| {md(inv.project)} | {inv.branch} | " + " | ".join(cells) + f" | {images} |")
    L.append("")
    by_project: dict[str, list[BranchInventory]] = defaultdict(list)
    for inv in invs:
        by_project[inv.project].append(inv)
    for project, group in by_project.items():
        L += _inventory_project(cfg, project, group)
    L += _inventory_releases(releases)
    path = Path(out) / INVENTORY_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(L) + "\n", encoding="utf-8")
    return path
