"""status.json (machine) and STATUS.md (human): open sets, deltas against the previous run, severity line."""
from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path

from . import __version__
from .cache import atomic_write
from .report import (ACTIONABLE, _actionable, _sev_label, allowed_unsupported, counts_as_production, md,
                     unrated_in_production)

STATUS_FILE = "STATUS.md"
STATUS_JSON = "status.json"
SCHEMA = 1

OPEN_KEYS = ("kev", "critical_high_production", "eol", "secrets_a", "secrets_b", "hosts_critical")
# The counting rule of each open set, stored in status.json as `open_rules`. Raise a key's number whenever
# what goes into that set changes: a delta compares only sets built by the same rule, so a rule change is
# never reported as new or resolved findings. Rule 2 of critical_high_production (1.2.0): only the KEV and
# CRITICAL/HIGH advisories of an actionable production package; rule 1 (up to 1.1.x) took all its advisories.
OPEN_RULES = {"kev": 1, "critical_high_production": 2, "eol": 1, "secrets_a": 1, "secrets_b": 1,
              "hosts_critical": 1}
# Keys whose identities are `<advisory> <eco>:<name>@<version>`: checked against the audit's own rows
REPORTED_KEYS = ("kev", "critical_high_production")
OVERDUE_DAYS = 7
SCHEDULER_MISSED_DAYS = 8
HOSTS_NOT_CHECKED_DAYS = 8
SKIPPED_SECRETS_REASON = "no secrets scan in this run"
_ASSESSMENT_HEADING = re.compile(r"^## Assessment (\d{4}-\d{2}-\d{2})", re.M)


def _now() -> str:
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat()


def empty_report(generated_at: str | None = None) -> dict:
    """The report shape of a portfolio with nothing scanned yet (setup's first status.json)."""
    return {"vulnerabilities": [], "runtimes": [], "unpinned_images": [], "suppressed": [], "sources": {},
            "generated_at": generated_at or _now(), "production_projects": []}


# --------------------------------------------------------------------------- open sets and deltas

def _open_secrets(secrets: dict | None) -> list[dict]:
    return [f for f in (secrets or {}).get("findings", []) if f.get("status") == "open"]


def _host_critical(name: str, h: dict) -> list[str]:
    """`<host> <change-id>` for each critical finding of one host that no decision accepted.

    A failed host's carried critical findings count. An accepted record-only finding has `critical: false`
    (and `accepted: true`) in `findings`, so it is dropped even when an older `critical` list still names it."""
    if not isinstance(h, dict):
        return []
    ids = h.get("critical")
    findings = h.get("findings")
    cleared = {f.get("id") for f in findings if isinstance(f, dict) and (f.get("accepted") or f.get("critical") is False)} \
        if isinstance(findings, list) else set()
    return [f"{name} {i}" for i in (ids if isinstance(ids, list) else []) if i not in cleared]


def _host_entries(hosts: dict | None) -> dict:
    entries = (hosts or {}).get("hosts")
    return entries if isinstance(entries, dict) else {}


def open_sets(rep: dict, secrets: dict | None, hosts: dict | None = None) -> dict[str, list[str]]:
    """Identities of everything currently open, sorted, per tracked key."""
    production = set(rep.get("production_projects", []))
    kev, crit = set(), set()
    for v in rep.get("vulnerabilities", []):
        ident = f"{v['ecosystem']}:{v['name']}@{v['version']}"
        kev.update(f"{x['id']} {ident}" for x in v.get("vulns", []) if x.get("kev"))
        if _actionable(v) and _in_production(v, production):
            crit.update(f"{x['id']} {ident}" for x in v.get("vulns", [])
                        if x.get("kev") or _sev_label(x) in ACTIONABLE)
    eol = {f"{r['product']} {r['cycle']}" for r in rep.get("runtimes", []) if r.get("status") == "EOL"}
    open_secrets = _open_secrets(secrets)
    by_class = {cls: {f["fingerprint"] for f in open_secrets if f.get("class") == cls} for cls in "AB"}
    return {"kev": sorted(kev), "critical_high_production": sorted(crit), "eol": sorted(eol),
            "secrets_a": sorted(by_class["A"]), "secrets_b": sorted(by_class["B"]),
            "hosts_critical": sorted(i for n, h in _host_entries(hosts).items() for i in _host_critical(n, h))}


def _version(text) -> tuple[int, ...] | None:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", str(text or ""))
    return tuple(int(p) for p in match.groups()) if match else None


def open_rules_of(doc: dict) -> dict:
    """The counting rule per open key a status.json was written with (None: unknown).

    Its `open_rules`; a file from before that field (up to 1.2.1) is dated by its `plugin_version`:
    critical_high_production took every advisory of an actionable package before 1.2.0."""
    rules = doc.get("open_rules")
    if isinstance(rules, dict):
        return {key: rules.get(key) for key in OPEN_KEYS}
    version = _version(doc.get("plugin_version"))
    legacy = dict.fromkeys(OPEN_KEYS, 1)
    legacy["critical_high_production"] = None if version is None else 2 if version >= (1, 2, 0) else 1
    return legacy


def _reported(rep: dict) -> set[str]:
    """`<advisory> <eco>:<name>@<version>` of every advisory the audit still reports (any severity, scope)."""
    return {f"{x['id']} {v['ecosystem']}:{v['name']}@{v['version']}"
            for v in rep.get("vulnerabilities", []) for x in v.get("vulns", [])}


def _deltas(now_open: dict, previous: dict | None, rep: dict | None = None) -> tuple[dict, bool]:
    """new / resolved per open key against the previous run, comparing like with like.

    A key whose previous set was built by another counting rule (`OPEN_RULES`) gets no numbers but
    `not_comparable` (the reason). An advisory that left the KEV or CRITICAL/HIGH set while the audit
    still reports it (severity, KEV flag, production scope or a VEX decision for one project changed) is
    listed under `not_counted`, never as resolved."""
    first_run = previous is None or previous.get("schema") != SCHEMA
    prev_open = {} if first_run else previous.get("open") or {}
    prev_rules = {} if first_run else open_rules_of(previous)
    reported = _reported(rep or {})
    deltas = {}
    for key in OPEN_KEYS:
        if first_run:
            deltas[key] = {"new": [], "resolved": []}
            continue
        if prev_rules.get(key) != OPEN_RULES[key]:
            deltas[key] = {"new": [], "resolved": [], "not_comparable":
                           f"the previous run (sbom-audit {previous.get('plugin_version') or 'unknown'}) "
                           "counted this set by other rules"}
            continue
        before, after = set(prev_open.get(key, [])), set(now_open[key])
        gone = before - after
        still = gone & reported if key in REPORTED_KEYS else set()
        deltas[key] = {"new": sorted(after - before), "resolved": sorted(gone - still)}
        if still:
            deltas[key]["not_counted"] = sorted(still)
    return deltas, first_run


def _failed_sources(sources: dict) -> list[dict]:
    failed = []
    for name, info in sources.items():
        if info.get("skipped"):
            continue
        parts = [f"{f.get('what') or str(f.get('project')) + '@' + str(f.get('branch'))}: {f.get('error')}"
                 for f in info.get("failed") or [] if isinstance(f, dict)]
        if info.get("error"):
            parts.append(str(info["error"]))
        if parts:
            failed.append({"source": name, "detail": "; ".join(parts)})
    return failed


def _secrets_scan(secrets: dict | None) -> dict:
    if secrets is None:
        return {"mode": "skipped", "engine": None, "repos": 0, "oldest_open_days": 0,
                "skipped_reason": SKIPPED_SECRETS_REASON}
    scan = secrets.get("scan") or {}
    engine = secrets.get("engine") or {}
    open_findings = _open_secrets(secrets)
    ages = [f["age_days"] for f in open_findings if f.get("age_days") is not None]
    # None: something is open but no finding carries an age (an undated commit); never a misleading 0
    oldest = max(ages) if ages else (None if open_findings else 0)
    return {"mode": scan.get("mode"), "engine": engine.get("name"), "repos": scan.get("repos", 0),
            "oldest_open_days": oldest, "skipped_reason": scan.get("skipped_reason")}


def oldest_text(scan: dict) -> str:
    """`<n> days`, or `age unknown` when open findings carry no age (`oldest_open_days` is null)."""
    days = scan.get("oldest_open_days")
    return "age unknown" if days is None else f"{days} days"


def _in_production(v: dict, production: set) -> bool:
    """Runtime scope in a production project or in a supported release (`report.counts_as_production`)."""
    return any(counts_as_production(l, production) for l in v.get("locations", []))


def _hosts_counts(hosts: dict | None) -> dict | None:
    """None when `[hosts]` is not active (no document passed). A host whose status is missing or unknown counts
    as failed, never as clean, and so does a non-dict host entry; a document whose `hosts` is not a dict reads as
    never checked; `unsupported` hosts are counted apart (no checks ran; no severity rule); `skipped` is the reason the run did not check anything (no key)."""
    if hosts is None:
        return None
    entries = _host_entries(hosts)
    well_formed = isinstance(hosts.get("hosts"), dict)     # anything else is a damaged document: never checked
    statuses = {n: h.get("status") if isinstance(h, dict) else None for n, h in entries.items()}
    critical = {n: _host_critical(n, h) for n, h in entries.items()}
    failed = sorted(n for n, s in statuses.items() if s not in ("ok", "unsupported"))
    last = hosts.get("last_checked") if well_formed else None
    skipped = hosts.get("skipped")
    return {"critical": sum(len(v) for v in critical.values()),
            "critical_hosts": sorted(n for n, v in critical.items() if v),
            "failed": len(failed), "failed_hosts": failed,
            "checked": sum(1 for s in statuses.values() if s == "ok"),
            "unsupported": sum(1 for s in statuses.values() if s == "unsupported"),
            "last_checked": _local_day(last),
            "skipped": str(skipped) if skipped else None}


def _local_day(value, tz: dt.tzinfo | None = None) -> str | None:
    """The calendar day of the timestamp `value` in `tz` (default: this machine's zone), the zone of
    `generated_at`: hosts.json stamps UTC, so slicing its text gives the UTC day, up to a day off. A value without
    a zone (a plain date) is taken as it is; anything unreadable gives None."""
    if not isinstance(value, str) or not value:
        return None
    try:
        when = dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    return (when.astimezone(tz) if when.tzinfo else when).date().isoformat()


def _counts(rep: dict, now_open: dict, secrets: dict | None, hosts: dict | None = None) -> dict:
    """Per package-version row, with `report._summary`'s predicates (so they equal AUDIT.md's summary rows);
    the `open` sets and deltas stay per advisory."""
    stats = rep.get("stats", {})
    open_secrets = _open_secrets(secrets)
    production = set(rep.get("production_projects", []))
    vulns = rep.get("vulnerabilities", [])
    counts = {"projects": stats.get("projects", 0), "branches": stats.get("branches", 0),
              "vulnerable": len(vulns), "kev": sum(1 for v in vulns if v.get("kev")),
              "critical_high_production": sum(1 for v in vulns if _actionable(v) and _in_production(v, production)),
              "unrated_production": sum(1 for v in vulns if unrated_in_production(v, production)),
              "unresolved_versions": stats.get("unresolved_versions", 0),
              "eol": len(now_open["eol"]),
              "allowed_unsupported": sum(1 for r in rep.get("runtimes", []) if allowed_unsupported(r)),
              "floating_tags": len(rep.get("unpinned_images", [])),
              "suppressed": len(rep.get("suppressed", [])),
              "secrets": {cls: sum(1 for f in open_secrets if f.get("class") == cls) for cls in "ABC"},
              "hosts": _hosts_counts(hosts)}
    if stats.get("imported_sboms"):          # only with an imported build SBOM
        counts["imported_sboms"] = {"total": stats["imported_sboms"],
                                    "not_current": stats.get("imported_sboms_not_current", 0)}
    if rep.get("releases"):                  # only with release scanning
        counts["releases"] = {"scanned": len(rep["releases"]),
                              "supported": sum(1 for r in rep["releases"] if r.get("supported"))}
    return counts


def build(rep: dict, *, secrets: dict | None, previous: dict | None, duration_s: float,
          exit_code: int | None, run_host: str, mode: str, commit: dict | None = None,
          push: dict | None = None, visibility: str = "unknown", last_assessment: str | None = None,
          proposal: str | None = None, hosts: dict | None = None) -> dict:
    """The `status.json` document for one run. `hosts` is the `hosts.json` document, passed only when
    `[hosts]` is active (a missing document then reads as `{}`: never checked)."""
    now_open = open_sets(rep, secrets, hosts)
    deltas, first_run = _deltas(now_open, previous, rep)
    commit = dict(commit) if commit is not None else {"status": "skipped", "sha": None, "detail": ""}
    commit.setdefault("pending_hand_edits", [])
    return {
        "schema": SCHEMA, "generated_at": _now(), "duration_s": duration_s, "exit_code": exit_code,
        "plugin_version": __version__, "run_host": run_host, "mode": mode,
        "counts": _counts(rep, now_open, secrets, hosts), "open": now_open, "open_rules": dict(OPEN_RULES),
        "deltas": deltas, "first_run": first_run,
        "failed_sources": _failed_sources(rep.get("sources") or {}),
        "secrets_scan": _secrets_scan(secrets),
        "last_assessment": last_assessment, "assessment_proposal": proposal,
        "commit": commit, "push": dict(push) if push is not None else {"status": "skipped", "detail": ""},
        "visibility": visibility, "cra_products_open": [],
    }


def refresh_hosts(status: dict, hosts: dict | None) -> dict:
    """`status` with only its hosts part rebuilt from the `hosts.json` document `hosts` (a manual `hosts check`).

    Recomputes `counts.hosts`, `open.hosts_critical` and its delta against the previous open set, with the
    same functions `build` uses. Everything else (projects, secrets, sources, run facts) stays as it was.
    None (`[hosts]` not active) returns `status` unchanged."""
    if hosts is None:
        return status
    now = open_sets({}, None, hosts)["hosts_critical"]
    before = set((status.get("open") or {}).get("hosts_critical") or [])
    after = set(now)
    return {**status,
            "counts": {**status.get("counts", {}), "hosts": _hosts_counts(hosts)},
            "open": {**(status.get("open") or {}), "hosts_critical": now},
            "deltas": {**(status.get("deltas") or {}),
                       "hosts_critical": {"new": sorted(after - before), "resolved": sorted(before - after)}}}


def refresh_secrets(status: dict, secrets: dict | None) -> dict:
    """`status` with only its secrets part rebuilt from the `secrets.json` document (after `secrets resolve`).

    Recomputes `counts.secrets`, `open.secrets_a` / `secrets_b` and the age of the oldest open finding. The
    deltas stay "since the run before": a finding decided now leaves `new` and joins `resolved`. The scan
    facts (mode, engine, repos, skipped reason) and everything else stay as the last `run` left them.
    None returns `status` unchanged."""
    if secrets is None:
        return status
    now = open_sets({}, secrets)
    was_open, deltas = status.get("open") or {}, dict(status.get("deltas") or {})
    for key in ("secrets_a", "secrets_b"):
        after, before = set(now[key]), set(was_open.get(key) or [])
        old = deltas.get(key) or {}
        deltas[key] = {"new": sorted((set(old.get("new") or []) | (after - before)) & after),
                       "resolved": sorted((set(old.get("resolved") or []) | (before - after)) - after)}
    open_secrets = _open_secrets(secrets)
    return {**status,
            "counts": {**status.get("counts", {}),
                       "secrets": {cls: sum(1 for f in open_secrets if f.get("class") == cls) for cls in "ABC"}},
            "open": {**was_open, "secrets_a": now["secrets_a"], "secrets_b": now["secrets_b"]},
            "deltas": deltas,
            "secrets_scan": {**(status.get("secrets_scan") or {}),
                             "oldest_open_days": _secrets_scan(secrets)["oldest_open_days"]}}


# --------------------------------------------------------------------------- read / write

def write(out: Path, status: dict) -> Path:
    """Atomic: write `status.json.<pid>.tmp`, then replace; a failed replace never leaves a half `status.json`."""
    return atomic_write(Path(out) / STATUS_JSON, json.dumps(status, indent=1, ensure_ascii=False) + "\n")


def read(out: Path) -> dict | None:
    try:
        data = json.loads((Path(out) / STATUS_JSON).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def last_assessment_date(out: Path) -> str | None:
    """Latest `## Assessment YYYY-MM-DD` heading in AUDIT.md."""
    try:
        text = (Path(out) / "AUDIT.md").read_text(encoding="utf-8")
    except OSError:
        return None
    return max(_ASSESSMENT_HEADING.findall(text), default=None)


# --------------------------------------------------------------------------- severity line

def _parse(ts: str | None) -> dt.datetime | None:
    try:
        return dt.datetime.fromisoformat(ts) if ts else None
    except ValueError:
        return None


def _aware(when: dt.datetime) -> dt.datetime:
    return when if when.tzinfo else when.astimezone()


def _elapsed(when: dt.datetime, now: dt.datetime) -> dt.timedelta:
    return _aware(now) - _aware(when)


def _scheduler_missed(status: dict, scheduler: dict | None, now: dt.datetime) -> str | None:
    if not scheduler or not scheduler.get("installed"):
        return None
    last = scheduler.get("last_fired") or scheduler.get("installed_at")    # a fresh install counts from its install date
    fired = _parse(last)
    if fired is None or _elapsed(fired, now) > dt.timedelta(days=SCHEDULER_MISSED_DAYS):
        since = (last or "install")[:10]
        return f"scheduler did not run since {since}"
    return None


def _hosts_not_checked(status: dict, now: dt.datetime) -> str | None:
    """`hosts not checked since <date|never>` when the host check is active and is older than 8 days."""
    hosts = status["counts"].get("hosts")
    if not hosts:
        return None
    now = _aware(now)
    day = _local_day(hosts.get("last_checked"), now.tzinfo)   # the same zone as `now`, never the UTC text
    if day is None or (now.date() - dt.date.fromisoformat(day)).days > HOSTS_NOT_CHECKED_DAYS:
        return f"hosts not checked since {day or 'never'}"
    return None


def _hosts_failed_text(hosts: dict) -> str:
    """A failed host is a failed source, never clean. A skipped document's `failed` counts the placeholders of a
    run that checked nothing, so the rule that uses this text is guarded by `not skipped`."""
    names = ", ".join(str(n) for n in hosts.get("failed_hosts") or [])
    return f"{hosts.get('failed')} host(s) failed the last check" + (f" ({names})" if names else "") + "; see HOSTS.md"


def _assessment_stale(status: dict) -> bool:
    """Assessment is missing or older than this run, and there is something open or new to assess."""
    day, assessed = (status.get("generated_at") or "")[:10], status.get("last_assessment")
    if assessed is not None and assessed >= day:
        return False
    return (any(status["open"].get(k) for k in OPEN_KEYS)
            or any(d["new"] for d in status["deltas"].values()))


def severity_line(status: dict, scheduler: dict | None, now: dt.datetime) -> str:
    """One line, most urgent condition first (the order of `rules` is the precedence)."""
    counts, deltas = status["counts"], status["deltas"]
    secrets, scan = counts["secrets"], status["secrets_scan"]
    generated = _parse(status.get("generated_at"))
    age = _elapsed(generated, now) if generated else None
    overdue = age is not None and age > dt.timedelta(days=OVERDUE_DAYS)
    missed = _scheduler_missed(status, scheduler, now)
    hosts = counts.get("hosts") or {}
    not_checked = _hosts_not_checked(status, now)
    rules = [
        (status.get("exit_code") is None, "set up, no run yet; run /sbom-audit:run"),   # setup's placeholder
        ((status.get("exit_code") or 0) >= 2,
         f"last run FAILED (exit {status.get('exit_code')}); see STATUS.md"),
        (overdue or missed,
         missed if missed and not overdue else f"last run {age.days} days ago; run /sbom-audit:run"),
        (secrets["A"] > 0,
         f"{secrets['A']} class A, {secrets['B']} B secrets open, oldest {oldest_text(scan)}"),
        ((hosts.get("critical") or 0) > 0,
         f"{hosts.get('critical')} critical host findings open ({', '.join(hosts.get('critical_hosts') or [])}); "
         "see HOSTS.md"),
        ((hosts.get("failed") or 0) > 0 and not hosts.get("skipped"), _hosts_failed_text(hosts)),
        (bool(deltas["kev"]["new"]), f"{len(deltas['kev']['new'])} new KEV since last run"),
        (bool(deltas["critical_high_production"]["new"]),
         f"{len(deltas['critical_high_production']['new'])} new CRITICAL/HIGH in production since last run"),
        (not_checked, not_checked),
        (bool(status.get("assessment_proposal")) or _assessment_stale(status),
         "findings not assessed yet; run /sbom-audit:assess"),
    ]
    text = next((line for hit, line in rules if hit),
                f"nothing new since {(status.get('generated_at') or '')[:10]}")
    return f"🛡️ sbom-audit {status['plugin_version']}: {text}"


# --------------------------------------------------------------------------- STATUS.md

def _delta_lines(status: dict) -> list[str]:
    if status.get("first_run"):
        return ["- first run with status: no earlier run to compare against"]
    lines = []
    for key in OPEN_KEYS:
        if key not in status["deltas"]:                 # a 1.0.0 status.json has no hosts_critical
            continue
        d = status["deltas"][key]
        if key == "hosts_critical" and not status["counts"].get("hosts") and not (d["new"] or d["resolved"]):
            continue                                    # [hosts] inactive: nothing to say
        if d.get("not_comparable"):
            lines.append(f"- {key}: not comparable with the previous run: {md(d['not_comparable'])}; "
                         f"{len((status.get('open') or {}).get(key) or [])} open now, compared from the next run on")
            continue
        not_counted = d.get("not_counted") or []
        lines.append(f"- {key}: {len(d['new'])} new, {len(d['resolved'])} resolved"
                     + (f", {len(not_counted)} no longer counted but still in AUDIT.md" if not_counted else ""))
        lines += ([f"  - new: {md(i)}" for i in d["new"]] + [f"  - resolved: {md(i)}" for i in d["resolved"]]
                  + [f"  - no longer counted: {md(i)}" for i in not_counted])
    return lines


def _secrets_lines(status: dict) -> list[str]:
    scan, counts = status["secrets_scan"], status["counts"]["secrets"]
    if scan["mode"] == "skipped":
        reason = scan.get("skipped_reason") or "not scanned"
        text = reason[0].upper() + reason[1:] if reason.startswith(("skipped", "unsupported")) else f"Skipped: {reason}"
        return [f"{md(text)}. Not the same as clean."]
    return [f"- scan: {scan['mode']} ({scan['engine']}, {scan['repos']} repos)",
            f"- open: {counts['A']} class A, {counts['B']} class B, {counts['C']} class C",
            f"- oldest open: {oldest_text(scan)}"]


def _hosts_lines(status: dict) -> list[str]:
    hosts = status["counts"].get("hosts")
    if not hosts:
        return []
    last = hosts.get("last_checked") or "never"
    if hosts.get("skipped"):
        return ["", "## Hosts", "", f"- hosts: skipped ({md(hosts['skipped'])}); last checked {md(last)}"]
    names = ", ".join(md(n) for n in hosts.get("critical_hosts") or [])
    unsupported = hosts.get("unsupported") or 0
    return ["", "## Hosts", "",
            f"- hosts: {hosts.get('checked', 0)} checked, {hosts.get('failed', 0)} failed, "
            f"{hosts.get('critical', 0)} critical" + (f" ({names})" if names else "")
            + (f", {unsupported} unsupported" if unsupported else "") + "; see HOSTS.md"]


def _scheduler_lines(scheduler: dict | None) -> list[str]:
    if not scheduler or not scheduler.get("installed"):
        return ["Scheduler: not installed."]
    return ["Scheduler: installed.", f"- last fired: {scheduler.get('last_fired') or 'never'}",
            f"- next fire: {scheduler.get('next_fire') or 'unknown'}"]


def render_md(status: dict, scheduler: dict | None, now: dt.datetime | None = None) -> str:
    """STATUS.md text; the severity line is relative to `now` (default: the run's own time)."""
    c, push = status["commit"], status["push"]
    now = now or _parse(status["generated_at"]) or dt.datetime.now().astimezone()
    L = [f"# sbom-audit status {status['generated_at'][:10]}", "",
         f"Run host `{status['run_host']}`, sbom-audit {status['plugin_version']}, mode {status['mode']}, "
         f"duration {status['duration_s']} s, exit {'–' if status['exit_code'] is None else status['exit_code']}.", "",
         severity_line(status, scheduler, now), "", "## Since last run", "",
         "*Resolved* means no longer open: fixed, or closed by a VEX decision. *No longer counted* means the "
         "advisory left this set (its severity, KEV flag or production scope changed, or a VEX decision covers only "
         "some projects) but AUDIT.md still reports it.",
         ""]
    n = status["counts"]
    L += [f"Counts: {n['vulnerable']} vulnerable package versions, {n['kev']} KEV, "
          f"{n['critical_high_production']} CRITICAL/HIGH in production, {n['eol']} EOL, "
          + (f"{n['allowed_unsupported']} allowed but unsupported (declared minimum, not counted as EOL), "
             if n.get("allowed_unsupported") else "") +
          f"{n['floating_tags']} floating tags, {n['suppressed']} suppressed by VEX.", ""]
    gaps = []                                # coverage gaps; absent in a status.json written before they existed
    if n.get("unrated_production"):
        gaps.append(f"{n['unrated_production']} with severity not rated in production")
    if n.get("unresolved_versions"):
        gaps.append(f"{n['unresolved_versions']} packages with version not resolved, not checked for vulnerabilities")
    imports = n.get("imported_sboms")
    if imports:
        text = f"{imports['total']} package lists from an imported build SBOM"
        if imports.get("not_current"):
            text += (f" ({imports['not_current']} not built from the scanned commit or with no commit recorded, "
                     "see AUDIT.md)")
        gaps.append(text)
    if gaps:
        L[-2] = L[-2][:-1] + "; " + ", ".join(gaps) + "."
    if n.get("releases"):
        r = n["releases"]
        L[-2] = L[-2][:-1] + (f"; {r['scanned']} releases under audit, {r['supported']} supported "
                               "(their CRITICAL/HIGH count as production; details in `RELEASES.md`).")
    L += _delta_lines(status) + ["", "## Secrets", ""] + _secrets_lines(status) + _hosts_lines(status) + ["", "## Sources", ""]
    listed = [f"- {md(f['source'])}: FAILED: {md(f['detail'])}" for f in status["failed_sources"]]
    scan = status["secrets_scan"]
    if scan["mode"] == "skipped" and not any(f["source"] == "secrets" for f in status["failed_sources"]):
        listed.append(f"- secrets: {md(scan.get('skipped_reason') or 'not scanned')}")
    L += listed or ["All sources answered."]
    L += ["", "## Commit", "", f"- commit: {c['status']}" + (f" `{c['sha']}`" if c.get("sha") else "")
          + (f" ({md(c['detail'])})" if c.get("detail") else ""),
          *([f"- configuration: {md(c['config'])}"] if c.get("config") else []),
          f"- push: {push['status']}" + (f" ({md(push['detail'])})" if push.get("detail") else ""),
          f"- remote visibility: {status['visibility']}", "", "## Scheduler", ""]
    L += _scheduler_lines(scheduler) + ["", "## Assessment", "",
         f"- last assessment: {status.get('last_assessment') or 'none'}",
         f"- proposal waiting: {status.get('assessment_proposal') or 'none'}", "", "## Pending hand edits", ""]
    L += [f"- {md(p)}" for p in c["pending_hand_edits"]] or ["None."]
    return "\n".join(L) + "\n"


def write_md(out: Path, status: dict, scheduler: dict | None = None) -> Path:
    """Write STATUS.md; without an explicit `scheduler` the scheduler's own state file is read."""
    if scheduler is None:
        from . import scheduler as scheduler_mod
        scheduler = scheduler_mod.read_state(out)
    path = Path(out) / STATUS_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_md(status, scheduler), encoding="utf-8")
    return path
