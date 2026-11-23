"""Host mode `hosts check`: collect every host over ssh, evaluate the facts, write baselines and `hosts.json`.

`check` runs the ssh calls in a thread pool (`concurrency` at a time, each bounded by `timeout_minutes`),
then evaluates the hosts one after the other in this process: osv.dev, the vendor lookups and the
baseline files are never inside an ssh timeout and never written by two threads.

`evaluate` turns one host's `facts` into its `hosts.json` entry and the baseline to write (or None).
Builder choices:
- Raw `facts` are never part of the entry (apt sources may carry URL credentials).
- A CISA KEV list that cannot be loaded is a critical `section-failed:kev` on every checked host; the
  previous `kev:` findings are carried, never "resolved" by a feed outage.
- Every collector section in `facts["errors"]` is a critical `section-failed:<section>` finding: a host
  with a failed section never looks clean. A failed fingerprint section keeps the baseline's values, so a
  failure is not reported as "everything removed"; the first run with a failed section writes no baseline.
- A failed `logins` section (or an unreadable baseline) does not advance `logins_checked_until`, so the
  next run reads that window again.
- A baseline file that exists but cannot be read is critical `baseline:unreadable`; it is neither
  overwritten nor treated as a first run.
- Decisions clear record-only findings (`login:`, `origin:`, `kev:` until `review_by`); changes and Lynis
  state clear only through the baseline that `hosts accept` writes.
- A failed host keeps its previous findings, summary and login window (`checked_at` stays the time of the
  last successful check); a changed host key adds the critical `hostkey:changed`.
"""
from __future__ import annotations

import copy
import hashlib
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from .. import enrich, epss
from ..cache import Cache
from ..enrich import http_get_json, http_post_json
from . import fingerprint, logins, osvhost, parse, report, rules, store, transport, vendors

SCHEMA = 1
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
SKIPPED_NO_KEY = "no audit key on this machine"
KNOWN_HOSTS_UNREADABLE = "known_hosts unreadable"
RETRY_AFTER_S = 300
# fingerprint section -> the collector sections it is built from
FP_SOURCES = {"users": ("passwd", "group"), "sudoers": ("sudoers",), "authorized_keys": ("authorized_keys",),
              "sockets": ("sockets",), "units": ("units",), "cron": ("cron",), "sshd": ("sshd",),
              "firewall": ("firewall",), "apt_sources": ("apt_sources",), "containers": ("containers",),
              "host_keys": ("host_keys",)}
ERROR_KIND = re.compile(r"^(rc -?[0-9]+|missing|unparseable: [A-Za-z_]+)")
SEEN_SOURCES = ("dpkg", "units", "cron", "owners")   # packages_seen only moves when the explanation could run
GROUP_RANK = {g: i for i, g in enumerate(("warning", "hostkey", "change", "kev", "login", "patch", "permissive",
                                          "lynis_index", "lynis_warning", "vuln", "third_party",
                                          "lynis_suggestion", "info"))}


def _iso(now: datetime) -> str:
    return now.astimezone(timezone.utc).strftime(TIME_FORMAT)


def _finding(id_: str, group: str, critical: bool, text: str, **extra) -> dict:
    return {"id": id_, "group": group, "critical": critical, "text": text, **extra}


def _error_kind(error: str) -> str:
    """Only the kind of a collector section error (`rc 1`, `missing`, `unparseable: X`): the rest of the text
    is a line of the section's output and may carry host data (apt source credentials)."""
    m = ERROR_KIND.match(str(error))
    return m.group(1) if m else "error reported by the collector"


def _section_failed(section: str, kind: str, text: str | None = None) -> dict:
    return _finding(f"section-failed:{section}", "warning", True,
                    text or f"collector section {section} failed: {kind}", section=section)


def _hostkey_finding(host: str, known_hosts_sha: str | None) -> dict:
    return _finding("hostkey:changed", "hostkey", True,
                    "the host key differs from the pinned one: verify it out of band, then re-pin with "
                    f"`hosts bootstrap {host}`", known_hosts_sha=known_hosts_sha)


def _repinned(finding: dict, known_hosts_sha: str | None) -> bool:
    """A `hostkey:changed` finding is cleared only by a re-pin: a stored pin hash that differs from a current
    one. A finding without a stored hash, or a host with no pinned lines now (a removed pin), keeps it."""
    stored = finding.get("known_hosts_sha")
    return stored is not None and known_hosts_sha is not None and stored != known_hosts_sha


def _carry(finding: dict, known_hosts_sha: str | None) -> dict:
    """A carried copy; a `hostkey:changed` without a stored hash takes the current one, so a later re-pin
    clears it."""
    f = dict(finding)
    if f.get("id") == "hostkey:changed" and f.get("known_hosts_sha") is None:
        f["known_hosts_sha"] = known_hosts_sha
    return f


def _carried_hostkey(previous_host: dict, known_hosts_sha: str | None) -> list[dict]:
    """`hostkey:changed` stays until the pinned lines change (a re-pin by `hosts bootstrap`)."""
    return [_carry(f, known_hosts_sha) for f in previous_host.get("findings") or []
            if f.get("id") == "hostkey:changed" and not _repinned(f, known_hosts_sha)]


class KnownHostsUnreadable(Exception):
    """`hosts/known_hosts` (or this host's lines in it) cannot be read or decoded."""


def known_hosts_sha(out: Path, host: str) -> str | None:
    """sha256 of the host's pinned lines (alias `sbom-audit-<host>`, with the `# <alias> pinned <time>` comment
    line `store.pin_host_keys` writes, so every re-pin changes it) in `hosts/known_hosts`, or None.
    Raises `KnownHostsUnreadable`; another host's undecodable line does not affect this host."""
    alias = (store.ALIAS_PREFIX + store.check_host(host)).encode()
    try:
        raw = (Path(out) / store.KNOWN_HOSTS).read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise KnownHostsUnreadable(type(exc).__name__) from exc
    mine = []
    for line in raw.splitlines():
        fields = line.split()
        if fields[:1] == [alias] or fields[:2] == [b"#", alias]:
            try:
                mine.append(line.strip().decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise KnownHostsUnreadable("UnicodeDecodeError") from exc
    return hashlib.sha256("\n".join(sorted(mine)).encode()).hexdigest() if mine else None


def _carried_kev(previous_host: dict, have: set[str]) -> list[dict]:
    """The previous `kev:` findings, critical again (a recorded decision is re-applied later), for a run where
    KEV matching did not happen: an outage must never read as "resolved"."""
    carried = []
    for f in previous_host.get("findings") or []:
        if isinstance(f, dict) and str(f.get("id", "")).startswith("kev:") and f["id"] not in have:
            f = {k: v for k, v in f.items() if k != "accepted"}
            carried.append({**f, "critical": True})
    return carried


def _kev_failed(kev_error: str, previous_host: dict, have: set[str]) -> list[dict]:
    """The CISA KEV list could not be loaded (no cache): KEV matching did not run, which is a failed section,
    never clean. The previous `kev:` findings are carried, so a feed outage never reads as "resolved"."""
    return [_section_failed("kev", "unavailable",
                            f"CISA KEV list unavailable, KEV matching did not run: {str(kev_error)[:300]}"),
            *_carried_kev(previous_host, have)]


def _critical(findings: list[dict]) -> list[str]:
    return sorted({f["id"] for f in findings if f.get("critical")})


def _base_entry(h) -> dict:
    return {"address": h.address, "production": bool(h.production), "projects": list(h.projects or [])}


def _lynis_state(facts: dict) -> dict:
    data = facts.get("lynis") or {}
    if not data.get("ok"):
        return {"index": None, "warnings": []}
    return {"index": data.get("index"), "warnings": sorted({w["id"] for w in data.get("warnings") or []})}


def _summary(facts: dict, findings: list[dict], previous_host: dict | None) -> dict:
    os_ = facts.get("os") or {}
    prev = (previous_host or {}).get("summary") or {}
    return {"os": " ".join(x for x in (os_.get("id"), os_.get("version_id") or os_.get("codename")) if x),
            "kernel": facts.get("kernel"), "reboot_required": bool(facts.get("reboot_required")),
            "index": (facts.get("lynis") or {}).get("index"), "index_prev": prev.get("index"),
            "last_unattended": facts.get("uu_last_run"), "updates_pending": len(facts.get("upgradable") or {}),
            "kev": sum(1 for f in findings if f["group"] == "kev")}


def evaluate(host: str, h, facts: dict, *, baseline: dict | None, previous_host: dict | None, decisions,
             kev: set[str], cache: Cache, now: datetime, audit_fp: str | None, fetch=http_get_json,
             post=http_post_json, vendor_cache: Cache | None = None,
             baseline_unreadable: bool = False, known_hosts_sha: str | None = None,
             kev_error: str | None = None, epss_scores: epss.Scores | None = None) -> tuple[dict, dict | None]:
    previous_host = previous_host or {}
    installed = facts.get("collector")
    entry = {**_base_entry(h), "status": "ok", "error": None, "checked_at": _iso(now), "attempted_at": _iso(now),
             "collector": {"installed": installed, "outdated": installed != parse.SHIPPED_VERSION},
             "known_hosts_sha": known_hosts_sha}
    if not (facts.get("os") or {}).get("supported"):
        os_ = facts.get("os") or {}
        carried = _carried_hostkey(previous_host, known_hosts_sha)
        entry.update(status="unsupported", findings=carried, critical=_critical(carried),
                     summary={"os": " ".join(x for x in (os_.get("id"), os_.get("version_id")) if x) or "unknown"},
                     login_window=previous_host.get("login_window"),
                     logins_checked_until=previous_host.get("logins_checked_until"))
        return entry, None

    errors = dict(facts.get("errors") or {})
    findings = _carried_hostkey(previous_host, known_hosts_sha)
    findings += [_section_failed(s, _error_kind(e)) for s, e in sorted(errors.items())]
    first_run = baseline is None and not baseline_unreadable
    if baseline_unreadable:
        findings.append(_finding("baseline:unreadable", "change", True,
                                 "the baseline file exists but cannot be read: changes cannot be checked; "
                                 "restore it from git or delete it to re-baseline"))
    current = fingerprint.build(facts)
    base_fp = (baseline or {}).get("fingerprint") or {}
    failed_fp = [s for s, srcs in FP_SOURCES.items() if any(src in errors for src in srcs)]
    for section in failed_fp:
        if section in base_fp:
            current[section] = copy.deepcopy(base_fp[section])
    new_baseline = None
    explained: dict = {}
    if first_run or baseline_unreadable:
        judge_fp = current
    else:
        judge_fp = base_fp
        missing = [s for s in fingerprint.SECTIONS if s not in base_fp and s not in failed_fp]
        if missing:
            findings.append(_finding("info:baseline-extended", "info", False,
                                     f"baseline extended with new sections: {', '.join(missing)}"))
            base_fp = {**base_fp, **{s: current[s] for s in missing}}
            judge_fp = base_fp
        seen = baseline.get("packages_seen") if isinstance(baseline.get("packages_seen"), dict) else {}
        changes, explained = fingerprint.diff(base_fp, current, facts, seen)
        findings += changes

    accepted = store.accepted_ids(decisions, host, now.astimezone(timezone.utc).date())
    login_findings, window = logins.evaluate(facts, judge_fp, since=previous_host.get("logins_checked_until"),
                                             now=now, audit_fp=audit_fp or "",
                                             previous_open=previous_host.get("findings") or [], accepted=accepted)
    findings += login_findings
    hold = "logins" in errors or baseline_unreadable
    checked_until = previous_host.get("logins_checked_until") if hold else window["until"]

    base_lynis = None if first_run or baseline_unreadable else baseline.get("lynis")
    findings += rules.patch_automation(facts, now)
    findings += rules.permissive(facts)
    base_lynis = base_lynis if isinstance(base_lynis, dict) else None
    findings += rules.lynis(facts, base_lynis)
    lynis_now = facts.get("lynis") or {}
    if (base_lynis and base_lynis.get("index") is not None and not lynis_now.get("ok")
            and "lynis" not in errors):   # a failed lynis section already has its section-failed finding
        # Lynis worked before: its failure must not hide new warnings or an index drop
        findings.append(_section_failed("lynis", lynis_now.get("error") or "no result",
                                        f"Lynis failed ({lynis_now.get('error') or 'no result'}) on a host whose "
                                        "baseline has a Lynis index: warnings and the index were not checked"))
    findings += rules.third_party(facts)
    findings += fingerprint.info(facts)
    if vendor_cache is not None:
        findings += vendors.check(facts.get("binaries") or [], vendor_cache, fetch=fetch)
        findings += vendors.os_eol(facts.get("os") or {}, vendor_cache, fetch=fetch,
                                   today=now.astimezone(timezone.utc).date())
    vuln_findings, vuln_error = osvhost.match(facts, kev, cache, post=post, fetch=fetch, epss_scores=epss_scores)
    findings += vuln_findings
    if vuln_error and getattr(vuln_error, "kind", "failed") == "unsupported":
        findings.append(_finding("vuln:unavailable", "vuln", False, str(vuln_error)))
    elif vuln_error:   # no data, osv.dev down or a record fetch failed: the vulnerability check did not run
        findings.append(_section_failed("osv", "lookup failed",
                                        f"vulnerability check failed: {vuln_error[:300]}"))
        # no OSV result means no KEV match either: the earlier `kev:` findings are carried, never "resolved"
        findings += _carried_kev(previous_host, {f["id"] for f in findings})
    if kev_error:
        findings += _kev_failed(kev_error, previous_host, {f["id"] for f in findings})
    if entry["collector"]["outdated"]:
        findings.append(_finding("info:collector-outdated", "info", False,
                                 f"collector outdated: run `hosts bootstrap {host}`"))

    for f in findings:
        if f["critical"] and f["id"] in accepted and f["id"].startswith(store.RECORD_ONLY):
            f["critical"] = False
            f["accepted"] = True
    findings.sort(key=lambda f: GROUP_RANK.get(f["group"], len(GROUP_RANK)))

    if first_run:
        if errors:
            findings.append(_finding("info:baseline-postponed", "info", False,
                                     "no baseline written: a collector section failed on the first run"))
        else:
            new_baseline = {"schema": SCHEMA, "created": _iso(now), "fingerprint": current,
                            "lynis": _lynis_state(facts), "packages_seen": fingerprint.installed_versions(facts)}
    elif not baseline_unreadable:
        new_baseline = copy.deepcopy(baseline)
        new_fp = new_baseline.setdefault("fingerprint", {})
        for s in fingerprint.SECTIONS:
            if s not in new_fp and s in base_fp:
                new_fp[s] = base_fp[s]
        for section, values in explained.items():
            new_fp.setdefault(section, {}).update(values)
        if not any(src in errors for src in SEEN_SOURCES):
            new_baseline["packages_seen"] = fingerprint.installed_versions(facts)
        lynis_base = new_baseline.get("lynis") if isinstance(new_baseline.get("lynis"), dict) else {}
        if lynis_base.get("index") is None and (facts.get("lynis") or {}).get("ok"):
            new_baseline["lynis"] = _lynis_state(facts)   # Lynis became available: that is its first baseline

    entry.update(summary=_summary(facts, findings, previous_host), fingerprint=current,
                 packages={(p.get("source") or p["name"]): (p.get("source_version") or p["version"])
                           for p in facts.get("packages") or []},
                 findings=findings, critical=_critical(findings), login_window=window,
                 logins_checked_until=checked_until)
    return entry, new_baseline


def _failed_entry(host: str, h, previous: dict | None, error: str, now: datetime,
                  host_key_changed: bool = False, known_hosts_sha: str | None = None) -> dict:
    prev = previous or {}
    findings = [_carry(f, known_hosts_sha) for f in prev.get("findings") or []
                if f.get("id") != "hostkey:changed" or not _repinned(f, known_hosts_sha)]
    if host_key_changed and not any(f.get("id") == "hostkey:changed" for f in findings):
        findings.insert(0, _hostkey_finding(host, known_hosts_sha))
    return {**_base_entry(h), "status": "failed", "error": error, "checked_at": prev.get("checked_at"),
            "attempted_at": _iso(now), "collector": prev.get("collector"), "summary": prev.get("summary"),
            "fingerprint": prev.get("fingerprint"), "packages": prev.get("packages"), "findings": findings,
            "critical": _critical(findings), "login_window": prev.get("login_window"),
            "logins_checked_until": prev.get("logins_checked_until"), "known_hosts_sha": known_hosts_sha}


def _usable_baseline(out: Path, host: str) -> tuple[dict | None, bool]:
    """(baseline, unreadable): a file that exists but is not a readable baseline is unreadable."""
    path = store.baseline_path(out, host)
    baseline = store.read_baseline(out, host)
    if baseline is not None and not isinstance(baseline.get("fingerprint"), dict):
        baseline = None
    return baseline, baseline is None and path.exists()


def outcome(doc: dict, names) -> tuple[list[dict], bool]:
    """([{"what": host, "error": text}] for failed hosts, any host with a critical finding) for `names`.

    Fails closed: a host with no entry, a non-dict entry or a status other than ok/unsupported is failed.
    A skipped document has no failed hosts and no critical ones (nothing was checked)."""
    if doc.get("skipped"):
        return [], False
    hosts = doc.get("hosts") if isinstance(doc.get("hosts"), dict) else {}
    failed, critical = [], False
    for name in names:
        entry = hosts.get(name)
        if not isinstance(entry, dict):
            failed.append({"what": name, "error": "no result for this host"})
        elif entry.get("status") not in ("ok", "unsupported"):
            error = entry.get("error")
            known = entry.get("status") == "failed"
            failed.append({"what": name, "error": error if known and isinstance(error, str) and error
                           else "failed" if known else "unknown host status"})
        else:
            critical = critical or bool(entry.get("critical"))
    return failed, critical


def check(cfg, names: list[str] | None, log, *, run=subprocess.run, sleep=time.sleep, fetch=http_get_json,
          post=http_post_json, now: datetime | None = None, fetch_bytes=None) -> dict:
    """`fetch_bytes(url) -> bytes` downloads the EPSS score file (default: epss.http_get_bytes). The EPSS step
    runs when `[epss] enabled` and either `fetch_bytes` is given or `fetch` is not injected: a caller that
    injects `fetch` alone gets no EPSS step and no EPSS key in `hosts.json`, as before 1.4.0. The scores are
    information on the findings (`hosts.json` top level `epss`); no priority, flag or alert depends on them."""
    run_epss = cfg.epss.enabled and (fetch_bytes is not None or fetch is http_get_json)
    opts = cfg.hosts
    out = Path(cfg.out)
    now = now or datetime.now(timezone.utc)
    servers = opts.servers
    unknown = [n for n in names or [] if n not in servers]
    if unknown:
        raise ValueError(f"unknown host(s), not in [hosts.servers]: {', '.join(unknown)}")
    selected = list(dict.fromkeys(names)) if names else list(servers)
    for name in selected:
        store.check_host(name)
    previous = store.read(out) or {}
    prev_hosts = previous.get("hosts") if isinstance(previous.get("hosts"), dict) else {}
    doc = {"schema": SCHEMA, "generated_at": _iso(now), "skipped": None, "last_checked": previous.get("last_checked"),
           "collector_shipped": parse.SHIPPED_VERSION, "hosts": prev_hosts}
    if not Path(opts.key).expanduser().exists():
        log(f"hosts: skipped, {SKIPPED_NO_KEY} ({opts.key})")
        doc = {**doc, "skipped": SKIPPED_NO_KEY}
        report.append_log_check(out, doc)   # records the skip; HOSTS.md and hosts.json stay as they were
        return doc

    decisions = store.read_decisions(out)
    enrich_cache = Cache(out / ".cache" / "enrich", 24)
    kev, kev_error = enrich.load_kev(enrich_cache, fetch=fetch)
    epss_scores = None
    if run_epss:   # the complete daily file, shared with the package audit through the cache; never per CVE
        scores = epss.load(enrich_cache, fetch_bytes or epss.http_get_bytes)
        epss_scores = scores.scores
        doc["epss"] = {"available": scores.available, "score_date": scores.score_date}
        if not scores.available:
            log(f"hosts: EPSS scores not available ({scores.error}); findings are listed without them")
    try:
        audit_fp = transport.audit_fingerprint(Path(opts.key).expanduser(), run=run)
    except Exception as exc:  # noqa: BLE001 - without it the plugin's own logins are judged like any other
        audit_fp = None
        log(f"hosts: audit key fingerprint unavailable ({type(exc).__name__}); its logins are not filtered")
    timeout_s = int(opts.timeout_minutes) * 60

    shas: dict[str, str | None] = {}
    unreadable_pins: set[str] = set()
    for name in selected:
        try:
            shas[name] = known_hosts_sha(out, name)
        except KnownHostsUnreadable:   # that host fails as a source; the others are checked
            shas[name] = None
            unreadable_pins.add(name)

    def collect(name: str) -> transport.CollectResult:
        if name in unreadable_pins:
            return transport.CollectResult(None, KNOWN_HOSTS_UNREADABLE)
        try:
            argv = transport.ssh_argv(opts, name, servers[name], out)
            return transport.collect(argv, timeout_s, run=run, sleep=sleep, retry_after_s=RETRY_AFTER_S,
                                     pinned=shas[name] is not None)
        except Exception as exc:  # noqa: BLE001 - one host's failure must not sink the others
            return transport.CollectResult(
                None, f"collection failed: {type(exc).__name__}: {transport._first_line(str(exc))}")

    with ThreadPoolExecutor(max_workers=max(1, int(opts.concurrency))) as pool:
        futures = {name: pool.submit(collect, name) for name in selected}
    results = {name: f.result() for name, f in futures.items()}

    osv_cache, vendor_cache = osvhost.cache_for(out), vendors.cache_for(out)
    entries: dict[str, dict] = {}
    for name in selected:
        h, prev, res, sha = servers[name], prev_hosts.get(name), results[name], shas[name]
        if res.doc is None:
            entry = _failed_entry(name, h, prev, res.error, now, res.host_key_changed, sha)
        else:
            try:
                facts = parse.parse(res.doc)
                if "os" in facts["errors"]:
                    raise parse.CollectorError(f"collector section os failed: {_error_kind(facts['errors']['os'])}")
                baseline, unreadable = _usable_baseline(out, name)
                entry, new_baseline = evaluate(
                    name, h, facts, baseline=baseline, previous_host=prev, decisions=decisions, kev=kev,
                    cache=osv_cache, now=now, audit_fp=audit_fp, fetch=fetch, post=post,
                    vendor_cache=vendor_cache, baseline_unreadable=unreadable, known_hosts_sha=sha,
                    kev_error=kev_error, epss_scores=epss_scores)
                if new_baseline is not None:
                    store.write_baseline(out, name, new_baseline)
                doc["last_checked"] = _iso(now)
            except parse.CollectorError as exc:
                entry = _failed_entry(name, h, prev, str(exc), now, known_hosts_sha=sha)
            except Exception as exc:  # noqa: BLE001 - a bug in one host's parse or checks fails it, not the run
                entry = _failed_entry(name, h, prev, f"evaluation failed: {type(exc).__name__}", now,
                                      known_hosts_sha=sha)
        entries[name] = entry
        log(f"hosts: {name}: {entry['status']}" + (f" ({entry['error']})" if entry["error"] else "")
            + (f", {len(entry['critical'])} critical" if entry["critical"] else ""))

    doc["hosts"] = {name: entries.get(name) or prev_hosts[name] for name in servers
                    if name in entries or name in prev_hosts}
    store.write(out, doc)
    report.write_md(out, doc)
    report.write_dated(out, doc, now.astimezone(timezone.utc).date())
    report.append_log_check(out, doc)
    return doc
