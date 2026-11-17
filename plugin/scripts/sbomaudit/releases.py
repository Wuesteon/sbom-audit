"""Release scanning: pick release tags, compute support periods, write `releases.json` and `RELEASES.md`.

A release is scanned like a branch (its `BranchInventory` has `branch = "tags/<tag>"` and a `release`
dict), so matching, KEV, endoflife.date and VEX run on it unchanged. This module adds what a branch does
not have: which tags are kept under audit, until when each release is supported, which runtimes reach
end of life inside that period, and which advisories are no longer present compared with the previous
release.

Evidence, not legal advice. "Fixed in release X" means exactly: the advisory matched a package in the SBOM
of the previous kept release and matches none in the SBOM of release X, both read with today's OSV data.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

from . import __version__
from .cache import atomic_write
from .config import Config, ReleasesOpts
from .model import BranchInventory, Finding

RELEASES_JSON = "releases.json"
RELEASES_FILE = "RELEASES.md"
SCHEMA = 1
BRANCH_PREFIX = "tags/"

# a tag reads as a version when, after a non-digit prefix (`v`, `app-v`), it is dotted numbers with an
# optional pre-release (`-rc.1`, `rc1`) or build (`+abc`) suffix
_VERSION_RE = re.compile(r"^[^\d]*?(\d+(?:\.\d+)*)([-+.]?[0-9A-Za-z][0-9A-Za-z.+-]*)?$")


def label(tag: str) -> str:
    """The branch label a release inventory carries: `tags/<tag>`."""
    return BRANCH_PREFIX + tag


def _literal_prefix(pattern: str) -> str:
    """The part of a glob before its first wildcard (`app2-v*` -> `app2-v`)."""
    m = re.search(r"[*?\[]", pattern or "")
    return (pattern or "")[:m.start()] if m else ""


def version_key(tag: str, pattern: str = "") -> tuple | None:
    """Sort key for a version-like tag, None otherwise. The pattern's literal prefix is dropped first, so
    digits in it (`app2-v*`) are not read as the version. A pre-release sorts before its release."""
    prefix = _literal_prefix(pattern)
    if prefix and tag.startswith(prefix):
        tag = tag[len(prefix):]
    m = _VERSION_RE.match(tag)
    if not m:
        return None
    nums = tuple(int(x) for x in m.group(1).split("."))
    nums = (nums + (0,) * 6)[:6] if len(nums) <= 6 else nums
    suffix = m.group(2) or ""
    pre = bool(suffix) and not suffix.startswith("+")
    return (nums, 0 if pre else 1, suffix)


def select(tags: list[dict], keep: int, pattern: str = "") -> tuple[list[dict], str]:
    """The newest `keep` tags, oldest first, and the order used: `version` when every tag reads as a
    version, else `date` (tag date, then name)."""
    keys = [version_key(t["tag"], pattern) for t in tags]
    if tags and all(k is not None for k in keys):
        ordered = [t for _, t in sorted(zip(keys, tags), key=lambda kt: (kt[0], kt[1]["tag"]))]
        order = "version"
    else:
        ordered = sorted(tags, key=lambda t: (_instant(t.get("date")), t["tag"]))
        order = "date"
    return ordered[-keep:] if keep else [], order


def _instant(value) -> dt.datetime:
    """An ISO 8601 timestamp as an aware datetime (UTC when it has no offset); the epoch when unreadable."""
    try:
        when = dt.datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    return when if when.tzinfo else when.replace(tzinfo=dt.timezone.utc)


def _day(value) -> dt.date | None:
    try:
        return dt.date.fromisoformat(str(value or "")[:10])
    except ValueError:
        return None


def add_months(day: dt.date, months: int) -> dt.date:
    """`day` plus whole calendar months; the 31st becomes the month's last day."""
    total = day.month - 1 + months
    year, month = day.year + total // 12, total % 12 + 1
    for d in (day.day, 30, 29, 28):
        try:
            return dt.date(year, month, d)
        except ValueError:
            continue
    raise ValueError("unreachable")


def support_until(opts: ReleasesOpts | None, released: dt.date | None) -> dt.date | None:
    """End of the support period of a release: `support_months` after its date and/or `support_until`.

    With both, the later date: a release is never treated as out of support because one of the two
    settings is shorter. None when neither is configured (the period is unknown)."""
    if opts is None:
        return None
    candidates = []
    if opts.support_months and released is not None:
        candidates.append(add_months(released, opts.support_months))
    if opts.support_until is not None:
        candidates.append(opts.support_until)
    return max(candidates) if candidates else None


def context(cfg: Config, inventories: list[BranchInventory], today: dt.date | None = None) -> dict:
    """(project, branch) -> {"tag", "date", "order", "supported", "support_until"} for every release
    inventory. Without a configured support period a release counts as supported."""
    from .config import release_opts
    today = today or dt.date.today()
    ctx = {}
    for inv in inventories:
        if not inv.release:
            continue
        until = support_until(release_opts(cfg, inv.project), _day(inv.release.get("date")))
        ctx[(inv.project, inv.branch)] = {
            "tag": inv.release.get("tag"), "date": inv.release.get("date"), "order": inv.release.get("order"),
            "support_until": until.isoformat() if until else None,
            "supported": until is None or today <= until,
        }
    return ctx


# --------------------------------------------------------------------------- releases.json

def _sev(v: dict) -> str:
    from .report import _sev_label
    return _sev_label(v)


def _open_counts(findings: list[Finding]) -> dict:
    """Package versions with an open advisory in this release, runtime scope only (dev-only left out),
    by the worst open advisory: `kev` counts every actively exploited one, `critical` and `high` the
    package versions whose worst advisory has that severity."""
    worst: dict[tuple, dict] = {}
    for f in findings:
        if f.component.scope == "optional":
            continue
        key = (f.component.ecosystem, f.component.name, f.component.version)
        w = worst.setdefault(key, {"kev": False, "sev": set()})
        for v in f.vulns:
            w["kev"] = w["kev"] or bool(v.get("kev"))
            w["sev"].add(_sev(v))
    counts = {"kev": 0, "critical": 0, "high": 0}
    for w in worst.values():
        counts["kev"] += w["kev"]
        if "CRITICAL" in w["sev"]:
            counts["critical"] += 1
        elif "HIGH" in w["sev"]:
            counts["high"] += 1
    return counts


def _present(findings: list[Finding]) -> dict[tuple[str, str], dict]:
    """(advisory id, ecosystem:package) -> {"package", "ecosystem", "versions"} for every match."""
    out: dict[tuple[str, str], dict] = {}
    for f in findings:
        c = f.component
        for v in f.vulns:
            vid = v.get("id")
            if not vid:
                continue
            e = out.setdefault((vid, f"{c.ecosystem}:{c.name}"),
                               {"package": c.name, "ecosystem": c.ecosystem, "versions": set()})
            e["versions"].add(c.version or "unresolved")
    return out


def _eol_before(rows: list[dict], until: str | None) -> list[str]:
    """Runtimes and base images whose endoflife.date end of life falls before `until` (or is already past
    with no date published), as `<product> <cycle> (EOL <date>)`."""
    if not until:
        return []
    flagged = set()
    for r in rows:
        date = r.get("eol_date") or ""
        if date and date < until:
            flagged.add(f"{r['product']} {r.get('cycle', '')} (EOL {date})")
        elif not date and r.get("status") == "EOL":
            flagged.add(f"{r['product']} {r.get('cycle', '')} (EOL, no date published)")
    return sorted(flagged)


def _failed_branches(sources: dict | None) -> set[tuple[str, str]]:
    failed = set()
    for info in (sources or {}).values():
        for f in (info or {}).get("failed") or []:
            if isinstance(f, dict) and f.get("project") is not None:
                failed.add((f.get("project"), f.get("branch")))
            elif isinstance(f, (list, tuple)) and len(f) >= 2:
                failed.add((f[0], f[1]))
    return failed


def build(cfg: Config, inventories: list[BranchInventory], present: list[Finding], kept: list[Finding],
          eol_rows: list[dict], sources: dict | None, today: dt.date | None = None,
          generated: str | None = None) -> dict:
    """The `releases.json` document. `present` are the matches before VEX (what the SBOM holds), `kept`
    those VEX left open. A project without release scanning is absent from `projects`."""
    from .config import release_opts
    today = today or dt.date.today()
    ctx = context(cfg, inventories, today)
    failed = _failed_branches(sources)
    by_branch_present: dict[tuple, list[Finding]] = defaultdict(list)
    by_branch_kept: dict[tuple, list[Finding]] = defaultdict(list)
    for f in present:
        by_branch_present[(f.project, f.branch)].append(f)
    for f in kept:
        by_branch_kept[(f.project, f.branch)].append(f)
    eol_by_branch: dict[tuple, list[dict]] = defaultdict(list)
    for r in eol_rows:
        eol_by_branch[(r["project"], r["branch"])].append(r)

    per_project: dict[str, list[BranchInventory]] = defaultdict(list)
    for inv in inventories:
        if inv.release:
            per_project[inv.project].append(inv)
    projects = {}
    for name in sorted(per_project, key=str.lower):
        invs = per_project[name]
        order = next((i.release.get("order") for i in invs if i.release.get("order")), None)
        invs.sort(key=lambda i: i.release.get("index", 0))
        opts = release_opts(cfg, name)
        presence = {(i.project, i.branch): _present(by_branch_present.get((i.project, i.branch), []))
                    for i in invs}
        rows = []
        history: list[tuple[BranchInventory, dict]] = []
        for i, inv in enumerate(invs):
            key = (inv.project, inv.branch)
            info = ctx[key]
            complete = not inv.errors and key not in failed
            row = {
                "tag": info["tag"], "commit": inv.commit, "date": info["date"],
                "supported": info["supported"], "support_until": info["support_until"],
                "sbom": inv.sbom_path or None,
                "open": _open_counts(by_branch_kept.get(key, [])),
                "eol_before_support_end": _eol_before(eol_by_branch.get(key, []), info["support_until"]),
                "fixed_since_previous": [],
                "previous": None,
                "branch": inv.branch,
                "complete": complete,
            }
            if i > 0:
                prev_inv, prev_row = history[-1]
                row["previous"] = prev_row["tag"]
                if row["complete"] and prev_row["complete"]:
                    row["fixed_since_previous"] = _fixed(inv, history, presence, info["date"])
                else:
                    row["fixed_since_previous_unknown"] = True
            history.append((inv, row))
            rows.append(row)
        projects[name] = {
            "support": {"period_months": opts.support_months if opts else None,
                        "until": opts.support_until.isoformat() if opts and opts.support_until else None},
            "tags": opts.tags if opts else None, "keep": opts.keep if opts else None, "order": order,
            "releases": list(reversed(rows)),           # newest first
        }
    return {"schema": SCHEMA, "generated": generated or _now(), "plugin_version": __version__,
            "projects": projects}


def _versions(inv: BranchInventory, ecosystem: str, name: str) -> list[str]:
    """Versions of one package in a release's inventory (empty: the package is not in its SBOM)."""
    return sorted({c.version or "unresolved" for c in inv.components
                   if c.kind == "package" and c.ecosystem == ecosystem and c.name == name})


def _fixed(inv: BranchInventory, history: list, presence: dict, fixed_date: str | None) -> list[dict]:
    """Advisories present in the previous release and absent from `inv`, each with the first kept release
    that held it in an unbroken run up to the previous one and the days from that release to this one."""
    here = presence[(inv.project, inv.branch)]
    prev_inv = history[-1][0]
    out = []
    fixed_day = _day(fixed_date)
    for (vid, pkg), e in sorted(presence[(prev_inv.project, prev_inv.branch)].items()):
        if (vid, pkg) in here:
            continue
        first_inv, first_row = history[-1]
        for old_inv, old_row in reversed(history):
            if (vid, pkg) not in presence[(old_inv.project, old_inv.branch)]:
                break
            first_inv, first_row = old_inv, old_row
        first_day = _day(first_row["date"])
        out.append({
            "id": vid, "package": e["package"], "ecosystem": e["ecosystem"],
            "versions_before": sorted(e["versions"]),
            "versions_after": _versions(inv, e["ecosystem"], e["package"]),
            "first_seen": first_row["tag"], "first_seen_date": first_row["date"],
            "first_seen_is_oldest_kept": first_inv is history[0][0],
            "days": (fixed_day - first_day).days if fixed_day and first_day else None,
        })
    return out


def _now() -> str:
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat()


def write_json(doc: dict, out: Path) -> Path:
    return atomic_write(Path(out) / RELEASES_JSON, json.dumps(doc, indent=1, ensure_ascii=False) + "\n")


def read(out: Path) -> dict | None:
    try:
        doc = json.loads((Path(out) / RELEASES_JSON).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) and isinstance(doc.get("projects"), dict) else None


# --------------------------------------------------------------------------- RELEASES.md

def _md(s) -> str:
    from .report import md
    return md(s)


def _support_text(r: dict) -> str:
    if not r.get("support_until"):
        return "supported (no period configured)"
    if r.get("supported"):
        return f"supported until {r['support_until']}"
    return f"out of support (ended {r['support_until']})"


def render_md(doc: dict) -> str:
    projects = doc.get("projects") or {}
    L = ["# Releases", "",
         f"Generated {doc.get('generated')} by sbom-audit {doc.get('plugin_version') or __version__}. One SBOM and "
         "one audit per release tag under audit (`[releases]` in `sbom-audit.toml`); full data: `releases.json`.", "",
         "\"Fixed\" below means exactly: the advisory matched a package in the SBOM of the previous release under "
         "audit and matches none in the SBOM of this release, both checked against today's OSV data. Days are "
         "counted between the two release dates, not from the advisory's publication. Out-of-support releases "
         "are listed, not counted as open work. Open counts leave dev-only packages out.", ""]
    if not projects:
        return "\n".join(L + ["No project has release scanning configured.", ""]) + "\n"
    for name, p in projects.items():
        sup = p.get("support") or {}
        period = []
        if sup.get("period_months"):
            period.append(f"{sup['period_months']} months from each release date")
        if sup.get("until"):
            period.append(f"until {sup['until']}")
        L += [f"## {_md(name)}", "",
              f"Tags `{_md(p.get('tags'))}`, newest {p.get('keep')} kept, ordered by "
              f"{'version' if p.get('order') == 'version' else 'tag date'}. Support period: "
              f"{' and '.join(period) + (' (the later of the two)' if len(period) == 2 else '') if period else 'not configured'}.",
              "",
              "| Release | Date | Commit | Support | KEV | Critical | High | EOL before support end | Fixed since previous | SBOM |",
              "|---|---|---|---|---|---|---|---|---|---|"]
        for r in p.get("releases") or []:
            o = r.get("open") or {}
            eol = ", ".join(_md(x) for x in r.get("eol_before_support_end") or []) or "–"
            if r.get("previous") is None:
                fixed = "– (oldest kept)"
            elif r.get("fixed_since_previous_unknown"):
                fixed = f"unknown (vs {_md(r['previous'])}: incomplete scan)"
            else:
                fixed = f"{len(r.get('fixed_since_previous') or [])} vs {_md(r['previous'])}"
            L.append(f"| `{_md(r['tag'])}` | {str(r.get('date') or '')[:10]} | {str(r.get('commit') or '')[:7]} | "
                     f"{_support_text(r)} | {o.get('kev', 0)} | {o.get('critical', 0)} | {o.get('high', 0)} | {eol} | "
                     f"{fixed} | `{_md(r.get('sbom') or '–')}` |")
        L.append("")
        for r in p.get("releases") or []:
            items = r.get("fixed_since_previous") or []
            if not items:
                continue
            L += [f"**No longer present in `{_md(r['tag'])}`** (compared with `{_md(r['previous'])}`)", "",
                  "| Advisory | Package | Versions before → after | First seen | Days |", "|---|---|---|---|---|"]
            for f in items:
                first = f"`{_md(f['first_seen'])}`" + (" or earlier" if f.get("first_seen_is_oldest_kept") else "")
                after = ", ".join(_md(v) for v in f.get("versions_after") or []) or "removed or no advisory"
                L.append(f"| {_md(f['id'])} | {_md(f['package'])} ({_md(f['ecosystem'])}) | "
                         f"{', '.join(_md(v) for v in f['versions_before'])} → {after} | {first} | "
                         f"{f['days'] if f.get('days') is not None else '?'}"
                         f"{'+' if f.get('first_seen_is_oldest_kept') and f.get('days') is not None else ''} |")
            L.append("")
    return "\n".join(L) + "\n"


def write_md(doc: dict, out: Path) -> Path:
    return atomic_write(Path(out) / RELEASES_FILE, render_md(doc))


# --------------------------------------------------------------------------- `releases` command

def fixed_in(doc: dict, project: str, tag: str) -> tuple[dict | None, str | None]:
    """The release row of `project`@`tag` from `releases.json`, or (None, why)."""
    p = (doc.get("projects") or {}).get(project)
    if p is None:
        return None, f"{project}: no release scanning (not in releases.json)"
    for r in p.get("releases") or []:
        if r.get("tag") == tag:
            return r, None
    kept = ", ".join(r.get("tag") for r in p.get("releases") or [])
    return None, f"{project}: {tag} is not a release under audit (kept: {kept or 'none'})"


def cli(args) -> int:
    """Print releases from `releases.json` (writes nothing)."""
    doc = read(args.out)
    if doc is None:
        print(f"no {RELEASES_JSON} in {args.out}; run `run` or `audit` first", file=sys.stderr)
        return 2
    if args.fixed:
        if not args.project:
            print("--fixed needs --project", file=sys.stderr)
            return 2
        row, why = fixed_in(doc, args.project, args.fixed)
        if row is None:
            print(why, file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps({"project": args.project, "tag": row["tag"], "previous": row.get("previous"),
                              "fixed_since_previous": row.get("fixed_since_previous") or [],
                              "unknown": bool(row.get("fixed_since_previous_unknown"))}, indent=1))
            return 0
        if row.get("previous") is None:
            print(f"{args.project} {row['tag']}: oldest release under audit, nothing to compare with")
            return 0
        if row.get("fixed_since_previous_unknown"):
            print(f"{args.project} {row['tag']} vs {row['previous']}: unknown, one of the two scans was incomplete")
            return 2
        items = row.get("fixed_since_previous") or []
        print(f"{args.project} {row['tag']} vs {row['previous']}: {len(items)} advisories no longer present "
              f"in the SBOM of {row['tag']}")
        for f in items:
            first = f["first_seen"] + (" or earlier" if f.get("first_seen_is_oldest_kept") else "")
            print(f"  {f['id']}  {f['package']} ({f['ecosystem']}) {', '.join(f['versions_before'])} → "
                  f"{', '.join(f.get('versions_after') or []) or 'removed or no advisory'}; first seen {first}, "
                  f"{f['days'] if f.get('days') is not None else '?'} days")
        return 0
    projects = doc.get("projects") or {}
    if args.project:
        if args.project not in projects:
            print(f"{args.project}: no release scanning (not in releases.json)", file=sys.stderr)
            return 1
        projects = {args.project: projects[args.project]}
    if args.json:
        print(json.dumps({**doc, "projects": projects}, indent=1, ensure_ascii=False))
        return 0
    if not projects:
        print("no project has release scanning configured")
        return 0
    for name, p in projects.items():
        print(f"{name} (tags {p.get('tags')}, ordered by {p.get('order')}):")
        for r in p.get("releases") or []:
            o = r.get("open") or {}
            print(f"  {r['tag']:<20} {str(r.get('date') or '')[:10]}  {_support_text(r):<40} "
                  f"KEV {o.get('kev', 0)}, critical {o.get('critical', 0)}, high {o.get('high', 0)}"
                  + (f"; EOL before support end: {', '.join(r['eol_before_support_end'])}"
                     if r.get("eol_before_support_end") else ""))
    return 0
