"""issues.json (machine) and ISSUES.md (human): one flat work list of every open issue and where it occurs.

A derived view of `audit.json`, `secrets.json` and `hosts.json`, rebuilt from those files on disk, never a
source of truth of its own. It holds what an agent that fixes things needs and nothing else: a stable id,
the kind, the triage priority, the place (project or host, branches, file, line) and the fix target.
Suppressed (VEX), decided (secrets), accepted (hosts) and informational findings are left out.

Priorities follow the assessment's triage order:
1 class A secret · 2 KEV and critical host findings · 3 CRITICAL/HIGH in a production project (not dev-only)
and class B secrets · 4 end-of-life runtimes and images · 5 floating image tags · 6 everything else.
"""
from __future__ import annotations

import datetime as dt
import json
import sys
from collections import Counter
from pathlib import Path

from . import __version__
from .cache import atomic_write
from .cvss import SEV_ORDER
from .report import ACTIONABLE, JSON_FILE as AUDIT_JSON, counts_as_production, md, worst_advisory
from .versions import ver_key

ISSUES_JSON = "issues.json"
ISSUES_FILE = "ISSUES.md"
SCHEMA = 1
MD_BRANCHES = 3                                  # ISSUES.md names this many branches; issues.json has all
KINDS = ("secret", "vulnerability", "eol", "floating_tag", "host")
PRIORITY_REASONS = {1: ("secret_a",), 2: ("kev", "host_critical"), 3: ("critical_high_production", "secret_b"),
                    4: ("eol",), 5: ("floating_tag",), 6: ("other",)}
# host finding groups a fixer can act on; logins, Lynis suggestions and `info` are not work items
HOST_GROUPS = ("change", "patch", "permissive", "lynis_warning", "lynis_index", "third_party")
ROTATE_HINT = ("rotate the credential at the provider, redeploy what uses it, verify the old value is dead, "
               "then `secrets resolve <fingerprint> rotated`; removing the line does not un-leak it")


def _now() -> str:
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat()


def _read(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


# --------------------------------------------------------------------------- one builder per kind

def _advisory(a: dict) -> dict:
    """Id, CVEs, severity and fix version; the long texts stay in `audit.json`. `kev` only when true."""
    entry = {"id": a.get("id"), "cves": a.get("cves") or [], "severity": a.get("severity"),
             "fixed_in": a.get("fixed_in")}
    return {**entry, "kev": True} if a.get("kev") else entry


def _worst(advisories: list[dict]) -> dict | None:
    """The advisory to read first: an actively exploited one, else the most severe, with its summary."""
    a = worst_advisory(advisories)
    if a is None:
        return None
    return {"id": a.get("id"), "severity": a.get("severity"), "summary": a.get("summary")}


def _vulnerabilities(rep: dict) -> list[dict]:
    """One issue per project, manifest and package version; the branches that hold it are listed on it."""
    production = set(rep.get("production_projects") or [])
    issues = []
    for v in rep.get("vulnerabilities") or []:
        advisories = v.get("vulns") or []
        fixes = [a.get("fixed_in") for a in advisories]
        target = max((f for f in fixes if f), key=ver_key, default=None)
        places: dict[tuple[str, str], list[dict]] = {}
        for loc in v.get("locations") or []:
            places.setdefault((loc["project"], loc["manifest"]), []).append(loc)
        for (project, manifest), locs in sorted(places.items()):
            dev_only = all(l.get("scope") == "optional" for l in locs)
            direct = any(l.get("direct") for l in locs)
            in_production = project in production
            # a supported release ranks like production (out-of-support releases are not in audit.json)
            ranked = any(counts_as_production(l, production) for l in locs)
            if v.get("kev"):
                priority, reason = 2, "kev"
            elif v.get("max_severity") in ACTIONABLE and ranked:
                priority, reason = 3, "critical_high_production"
            else:
                priority, reason = 6, "other"
            version = v.get("version") or "unresolved"
            where = {"project": project, "branches": sorted({l["branch"] for l in locs}),
                     "path": manifest, "line": None}
            tags = sorted({l["release"] for l in locs if l.get("release")})
            if tags:                         # only with release scanning: the release tags holding it
                where["releases"] = tags
            issues.append({
                "id": f"vuln:{project}:{manifest}:{v['ecosystem']}:{v['name']}@{version}",
                "kind": "vulnerability", "priority": priority, "reason": reason,
                "severity": v.get("max_severity"), "production": in_production,
                "title": f"{v['name']} {version}: {len(advisories)} advisories, worst {v.get('max_severity')}"
                         + (" (KEV, actively exploited)" if v.get("kev") else ""),
                "where": where,
                "details": {"ecosystem": v["ecosystem"], "package": v["name"], "version": v.get("version"),
                            "direct": direct, "dev_only": dev_only, "kev": bool(v.get("kev")),
                            "worst": _worst(advisories),
                            "advisories": [_advisory(a) for a in advisories]},
                "fix": {"action": "upgrade" if target else "no_fix_released", "target": target,
                        "unfixed_advisories": sum(1 for f in fixes if not f),
                        "hint": ("bump the package in the manifest and refresh the lockfile" if direct else
                                 "transitive: upgrade the parent that pulls it in, or refresh the lockfile")},
            })
    return issues


def _secrets(doc: dict | None, production: set[str]) -> list[dict]:
    issues = []
    for f in (doc or {}).get("findings") or []:
        if not isinstance(f, dict) or f.get("status") != "open":
            continue
        cls = f.get("class")
        priority, reason = {"A": (1, "secret_a"), "B": (3, "secret_b")}.get(str(cls), (6, "other"))
        issues.append({
            "id": f"secret:{f['fingerprint']}",
            "kind": "secret", "priority": priority, "reason": reason, "severity": f"class {cls}",
            "production": f.get("repo") in production,
            "title": f"{f.get('rule_id')} ({f.get('provider')}) in {f.get('file')}:{f.get('line')}",
            "where": {"project": f.get("repo"), "branches": sorted(f.get("branches") or []),
                      "path": f.get("file"), "line": f.get("line")},
            "details": {"fingerprint": f["fingerprint"], "rule_id": f.get("rule_id"), "provider": f.get("provider"),
                        "class": cls, "commit": f.get("commit"), "live_in_tree": bool(f.get("live_in_tree")),
                        "age_days": f.get("age_days")},
            "fix": {"action": "rotate", "target": None, "hint": ROTATE_HINT},
            "_first_seen": f.get("first_seen"),
        })
    return issues


def _eol(rep: dict) -> list[dict]:
    production = set(rep.get("production_projects") or [])
    issues = []
    for r in rep.get("runtimes") or []:
        if r.get("status") != "EOL":
            continue
        places: dict[tuple[str, str], set[str]] = {}
        tags: dict[tuple[str, str], set[str]] = {}
        for loc in r.get("locations") or []:
            places.setdefault((loc["project"], loc.get("source") or ""), set()).add(loc["branch"])
            if loc.get("release"):
                tags.setdefault((loc["project"], loc.get("source") or ""), set()).add(loc["release"])
        for (project, source), branches in sorted(places.items()):
            where = {"project": project, "branches": sorted(branches),
                     "path": source.split(":", 1)[0] or None, "line": None}
            if tags.get((project, source)):
                where["releases"] = sorted(tags[(project, source)])
            issues.append({
                "id": f"eol:{project}:{r['product']}@{r['cycle']}:{source}",
                "kind": "eol", "priority": 4, "reason": "eol", "severity": "EOL",
                "production": project in production,
                "title": f"{r['product']} {r['cycle']} is past end of life ({r.get('eol_date') or 'date unknown'})",
                "where": where,
                "details": {"product": r["product"], "cycle": r["cycle"], "eol_date": r.get("eol_date"),
                            "latest_in_cycle": r.get("latest"), "source": source},
                "fix": {"action": "upgrade_runtime", "target": None,
                        "hint": "move to a supported cycle of this runtime or base image"},
            })
    return issues


def _floating(rep: dict) -> list[dict]:
    production = set(rep.get("production_projects") or [])
    places: dict[tuple[str, str, str], dict] = {}
    for u in rep.get("unpinned_images") or []:
        g = places.setdefault((u["project"], u.get("source") or "", u["image"]), {"own": bool(u.get("own")), "branches": set()})
        g["branches"].add(u["branch"])
    issues = []
    for (project, source, image), g in sorted(places.items()):
        own = g["own"]
        issues.append({
            "id": f"floating:{project}:{source}:{image}",
            "kind": "floating_tag", "priority": 6 if own else 5, "reason": "other" if own else "floating_tag",
            "severity": None, "production": project in production,
            "title": f"image {image} floats on a moving tag" + (" (own image)" if own else ""),
            "where": {"project": project, "branches": sorted(g["branches"]), "path": source or None, "line": None},
            "details": {"image": image, "own_image": own},
            "fix": {"action": "pin", "target": None,
                    "hint": ("tag the image you build with a version or commit" if own else
                             "pin the image to a version tag or a digest")},
        })
    return issues


def _host_fix(f: dict) -> dict:
    fix, candidate = f.get("fix"), f.get("candidate")
    if f.get("group") == "third_party" or fix == "installable" or f.get("fixable"):
        return {"action": "apt_upgrade", "target": candidate, "hint": "`hosts patch <host>` shows the plan; it installs only after a confirmation"}
    if fix == "reboot":
        return {"action": "reboot", "target": None, "hint": "the fixed kernel is installed; reboot in a maintenance window"}
    if fix:
        return {"action": "no_fix_installable", "target": f.get("fixed"), "hint": f"fix state: {fix}"}
    return {"action": "review", "target": None, "hint": "see HOSTS.md; fix on the host or record a decision with `hosts accept`"}


def _hosts(doc: dict | None, accepted: dict[str, set[str]] | None = None) -> list[dict]:
    """Open, actionable host findings: everything critical, plus the non-informational groups and the
    vulnerable packages an installable update fixes. Accepted findings are left out: those `hosts.json`
    marks, and those in `accepted` (host -> finding ids), the decisions recorded since the last check."""
    from .hosts.report import _is_critical
    entries = (doc or {}).get("hosts")
    issues = []
    for name, h in sorted(entries.items()) if isinstance(entries, dict) else []:
        if not isinstance(h, dict):
            continue
        for f in h.get("findings") or []:
            if not isinstance(f, dict) or not f.get("id"):
                continue
            if f["id"] in (accepted or {}).get(name, ()):
                f = {**f, "accepted": True}
            critical = _is_critical(f)
            group = f.get("group")
            if not critical and (f.get("accepted") or not (
                    group in HOST_GROUPS or (group == "vuln" and f.get("fixable")))):
                continue
            issues.append({
                "id": f"host:{name}:{f['id']}",
                "kind": "host", "priority": 2 if critical else 6, "reason": "host_critical" if critical else "other",
                "severity": "critical" if critical else None, "production": bool(h.get("production")),
                "title": str(f.get("text") or f["id"]),
                "where": {"host": name, "projects": list(h.get("projects") or []), "path": None, "line": None},
                "details": {"finding": f["id"], "group": group, "package": f.get("package"),
                            "version": f.get("version") or f.get("installed"), "cve": f.get("cve")},
                "fix": _host_fix(f),
            })
    return issues


# --------------------------------------------------------------------------- document

def is_transitive(i: dict) -> bool:
    """A vulnerability whose package is not a direct dependency of that manifest. Every other kind is False."""
    details = i.get("details")
    return i.get("kind") == "vulnerability" and isinstance(details, dict) and not details.get("direct")


def dependency_split(issues: list[dict], max_priority: int = 3) -> dict:
    """Vulnerability issues at priority `max_priority` or more urgent, counted as direct and transitive
    dependencies (`dev_only` counts those of them only dev-only manifests hold). A view, not a ranking: the
    priority of an issue does not depend on it."""
    vulns = [i for i in issues if isinstance(i, dict) and i.get("kind") == "vulnerability"
             and isinstance(i.get("priority"), int) and i["priority"] <= max_priority]
    transitive = sum(1 for i in vulns if is_transitive(i))
    return {"total": len(vulns), "direct": len(vulns) - transitive, "transitive": transitive,
            "dev_only": sum(1 for i in vulns if (i.get("details") or {}).get("dev_only"))}


def _sort_key(i: dict):
    """Priority, production first, direct dependencies before transitive ones, severity, place, id."""
    place = i["where"].get("project") or i["where"].get("host") or ""
    return (i["priority"], not i["production"], is_transitive(i), SEV_ORDER.get(str(i.get("severity")), 5),
            place.lower(), i["id"])


def _counts(issues: list[dict]) -> dict:
    return {"total": len(issues),
            "by_priority": {str(p): n for p, n in sorted(Counter(i["priority"] for i in issues).items())},
            "by_kind": {k: n for k in KINDS if (n := sum(1 for i in issues if i["kind"] == k))}}


def build(rep: dict | None, secrets: dict | None, hosts: dict | None, *, previous: dict | None = None,
          incomplete: list[dict] | None = None, now: str | None = None,
          hosts_accepted: dict[str, set[str]] | None = None) -> dict:
    """The `issues.json` document. `rep` is the `audit.json` document, `secrets` and `hosts` the documents of
    those steps (None: not available, so that kind is absent and named under `sources`). `first_seen` is kept
    from `previous` by id. `incomplete` lists the sources that failed: with one there, an empty list for that
    source does not mean clean."""
    now = now or _now()
    rep = rep or {}
    production = set(rep.get("production_projects") or [])
    issues = (_vulnerabilities(rep) + _secrets(secrets, production) + _eol(rep) + _floating(rep)
              + _hosts(hosts, hosts_accepted))
    seen = {i.get("id"): i.get("first_seen") for i in (previous or {}).get("issues") or [] if isinstance(i, dict)}
    for i in issues:
        own = i.pop("_first_seen", None)
        i["first_seen"] = seen.get(i["id"]) or own or now[:10]
    issues.sort(key=_sort_key)
    return {
        "schema": SCHEMA, "generated_at": now, "plugin_version": __version__,
        "sources": {"audit": rep.get("generated_at"),
                    "secrets": (secrets or {}).get("generated_at"),
                    "hosts": (hosts or {}).get("last_checked")},
        "incomplete": list(incomplete or []),
        "counts": _counts(issues),
        "issues": issues,
    }


def dumps(doc: dict) -> str:
    """The document as JSON with one issue per line: half the size of an indented dump, one changed line per
    changed issue in a diff, and `grep '"priority": 1'` finds whole issues."""
    head = {k: v for k, v in doc.items() if k != "issues"}
    lines = [json.dumps(i, ensure_ascii=False) for i in doc.get("issues") or []]
    body = "[\n" + ",\n".join(lines) + "\n]" if lines else "[]"
    return json.dumps(head, indent=1, ensure_ascii=False)[:-2] + ',\n "issues": ' + body + "\n}\n"


def _where_cell(i: dict) -> str:
    w = i["where"]
    if i["kind"] == "host":
        return "host"
    path = f"`{md(w['path'])}`" if w.get("path") else "–"
    if w.get("line"):
        path = f"`{md(w['path'])}:{w['line']}`"
    branches = [md(b) for b in w.get("branches") or []]
    shown = ", ".join(branches[:MD_BRANCHES]) + (f" +{len(branches) - MD_BRANCHES} more" if len(branches) > MD_BRANCHES else "")
    return f"{path} ({shown or '–'})"


def _kind_cell(i: dict) -> str:
    """The kind; a vulnerability also says whether the package is a direct or transitive dependency."""
    text = i["kind"].replace("_", " ")
    if i["kind"] == "vulnerability" and isinstance(i.get("details"), dict):
        text += ", transitive" if is_transitive(i) else ", direct"
        if i["details"].get("dev_only"):
            text += ", dev-only"
    return text


def _fix_cell(i: dict) -> str:
    fix = i["fix"]
    text = fix["action"].replace("_", " ") + (f" → {md(fix['target'])}" if fix.get("target") else "")
    unfixed = fix.get("unfixed_advisories")
    return text + (f" ({unfixed} unfixed)" if unfixed and fix.get("target") else "")


def render_md(doc: dict) -> str:
    """ISSUES.md: the same list per project and host, most urgent place first."""
    counts = doc["counts"]
    L = [f"# Open issues {doc['generated_at'][:10]}", "",
         "What is open and where, for whoever fixes it. Derived from `audit.json`, `secrets.json` and `hosts.json`; "
         "the machine-readable list is `issues.json`. Never edit either by hand. Suppressed, decided, accepted and "
         "informational findings are not listed.", "",
         f"{counts['total']} open: " + (", ".join(f"{n} {k}" for k, n in counts["by_kind"].items()) or "nothing") + ".",
         "", "Priority: 1 class A secret · 2 KEV, critical host finding · 3 CRITICAL/HIGH in production or a supported "
         "release, class B secret · 4 end of life · 5 floating tag · 6 other.", ""]
    split = dependency_split(doc["issues"])
    if split["total"]:
        L += [f"Vulnerabilities at priority 2 and 3 (KEV, or CRITICAL/HIGH in production or a supported release): "
              f"{split['total']}, of which {split['direct']} in direct dependencies and {split['transitive']} in "
              "transitive ones. Within a priority, direct dependencies are listed first: they are fixed in your own "
              "manifest; a transitive one through the parent that pulls it in, or a lockfile refresh. Transitive "
              "does not mean harmless: a transitive package is installed and can run like a direct one, and there "
              "is no reachability analysis, so each one stays a finding until it is fixed or a VEX decision says "
              "otherwise.", ""]
    if doc.get("incomplete"):
        L += ["**Incomplete:** these sources failed, so their part of the list may be missing issues:", ""]
        L += [f"- {md(s.get('source'))}: {md(s.get('detail'))}" for s in doc["incomplete"]] + [""]
    places: dict[tuple[str, str], list[dict]] = {}
    for i in doc["issues"]:
        key = ("host", i["where"]["host"]) if i["kind"] == "host" else ("project", i["where"]["project"] or "?")
        places.setdefault(key, []).append(i)
    if not places:
        L += ["Nothing open." if not doc.get("incomplete") else "Nothing listed.", ""]
    for (kind, name), items in sorted(places.items(), key=lambda kv: (_sort_key(kv[1][0])[:2], kv[0])):
        flag = " (production)" if items[0]["production"] else ""
        L += [f"## {'Host ' if kind == 'host' else ''}{md(name)}{flag}", "",
              "| P | Kind | Issue | Where | Fix | Open since |", "|---|---|---|---|---|---|"]
        L += [f"| {i['priority']} | {_kind_cell(i)} | {md(i['title'])} | {_where_cell(i)} | "
              f"{_fix_cell(i)} | {i['first_seen']} |" for i in items]
        L.append("")
    return "\n".join(L)


# --------------------------------------------------------------------------- read / write

def read(out: Path) -> dict | None:
    return _read(Path(out) / ISSUES_JSON)


def _hosts_accepted(out: Path, hosts: dict | None) -> dict[str, set[str]]:
    """Finding ids accepted per host in the decisions file. An unreadable file accepts nothing: the
    findings stay listed, which is the safe side."""
    from .hosts import store
    entries = (hosts or {}).get("hosts")
    try:
        decisions = store.read_decisions(out)
    except ValueError:
        return {}
    today = dt.datetime.now(dt.timezone.utc).date()
    return {name: store.accepted_ids(decisions, name, today) for name in entries} if isinstance(entries, dict) else {}


def refresh(out: Path, hosts_active: bool | None = None) -> list[Path]:
    """Rebuild `issues.json` and `ISSUES.md` from the reports on disk and return both paths.

    Called at the end of every `run` and after each command that changes what is open between runs
    (`secrets resolve`, `hosts check`, `hosts accept`). A step the config switches off contributes nothing,
    even when an old `secrets.json` or `hosts.json` is still in the folder; `hosts_active` overrides the
    config for the host step (the run knows whether it ran). The failed sources come from `status.json`,
    which the run writes just before."""
    out = Path(out)
    secrets_active = True
    try:
        from . import config
        cfg = config.load(out)
        secrets_active = cfg.secrets.enabled
        if hosts_active is None:
            hosts_active = cfg.hosts.active
    except Exception:                               # an unreadable config: go by the files that are there
        if hosts_active is None:
            hosts_active = True
    status = _read(out / "status.json") or {}
    hosts = _read(out / "hosts.json") if hosts_active else None
    doc = build(_read(out / AUDIT_JSON), _read(out / "secrets.json") if secrets_active else None, hosts,
                previous=read(out), incomplete=status.get("failed_sources") or [],
                hosts_accepted=_hosts_accepted(out, hosts))
    return [atomic_write(out / ISSUES_JSON, dumps(doc)),
            atomic_write(out / ISSUES_FILE, render_md(doc))]


def try_refresh(out: Path, say=print, hosts_active: bool | None = None) -> list[Path]:
    """`refresh` that never raises: the command it follows has done its work and keeps its exit code."""
    try:
        return refresh(out, hosts_active)
    except Exception as exc:                        # the type only, as everywhere a report may carry findings
        say(f"issues: not refreshed ({type(exc).__name__})")
        return []


def is_query(args) -> bool:
    """True when `issues` was asked to select or print: then it reads `issues.json` and writes nothing."""
    return bool(getattr(args, "json", False) or any(
        getattr(args, name, None) is not None for name in ("project", "host", "kind", "max_priority")))


def select(doc: dict, *, project: str | None = None, host: str | None = None, kind: str | None = None,
           max_priority: int | None = None) -> list[dict]:
    """The issues of `doc` that match every given filter, in the document's order. A project also selects
    the findings of the hosts that run it."""
    chosen = []
    for i in doc.get("issues") or []:
        where = i.get("where") or {}
        if project is not None and project != where.get("project") and project not in (where.get("projects") or []):
            continue
        if host is not None and host != where.get("host"):
            continue
        if kind is not None and kind != i.get("kind"):
            continue
        if max_priority is not None and i.get("priority", 6) > max_priority:
            continue
        chosen.append(i)
    return chosen


def _line(i: dict) -> str:
    where = i["where"]
    place = where.get("host") or where.get("project") or "?"
    path = f" {where['path']}" + (f":{where['line']}" if where.get("line") else "") if where.get("path") else ""
    return f"P{i['priority']} {i['kind']:<13} {place}{path}: {i['title']} [{_fix_cell(i)}] {i['id']}"


def _query(args, out: Path) -> int:
    doc = read(out)
    if doc is None:
        print(f"no {ISSUES_JSON} yet: run /sbom-audit:run", file=sys.stderr)
        return 2
    chosen = select(doc, project=args.project, host=args.host, kind=args.kind, max_priority=args.max_priority)
    for flag, value in (("project", args.project), ("host", args.host)):
        wheres = [i.get("where") or {} for i in doc.get("issues") or []]
        known = sorted({n for w in wheres for n in [w.get(flag), *(w.get(flag + "s") or [])] if n})
        if value and value not in known:
            print(f"no open issue names {flag} {value!r}; {flag}s with open issues: {', '.join(known) or 'none'}",
                  file=sys.stderr)
    if args.json:
        print(dumps({**doc, "counts": _counts(chosen), "issues": chosen}), end="")
        return 0
    for i in chosen:
        print(_line(i))
    print(f"{len(chosen)} of {len(doc.get('issues') or [])} open issues, from {doc.get('generated_at')}")
    for s in doc.get("incomplete") or []:
        print(f"incomplete source {s.get('source')}: {s.get('detail')}")
    return 0


def cli(args) -> int:
    """`issues`: rebuild both files from the reports on disk and print the counts. Exit 2 without an audit.
    With a filter or `--json` it prints the selected issues from `issues.json` instead and writes nothing."""
    if is_query(args):
        return _query(args, Path(args.out).resolve())
    out = Path(args.out).resolve()
    if _read(out / AUDIT_JSON) is None:
        print(f"no {AUDIT_JSON} yet: run /sbom-audit:run")
        return 2
    paths = refresh(out)
    doc = read(out) or {}
    counts = doc.get("counts") or {}
    by_priority = ", ".join(f"P{p}: {n}" for p, n in (counts.get("by_priority") or {}).items()) or "none"
    print(f"{counts.get('total', 0)} open issues ({by_priority}); {paths[0].name} and {paths[1].name} written")
    for s in doc.get("incomplete") or []:
        print(f"incomplete source {s.get('source')}: {s.get('detail')}")
    return 0
