"""Host mode login anomalies: accepted sshd logins judged by the key fingerprint, carried until accepted.

Spec "Login anomaly". `evaluate` reads `facts["logins"]` (see `parse.py`) and the accepted baseline
fingerprint, and returns `(findings, window)`.

Finding ids (typed by the user in `hosts accept`, matched against `accepted` and `previous_open`, so they
must not change between runs): `login:<user>@<UTC time>/<fp or method>`, with the time as
`YYYY-MM-DDTHH:MM:SSZ` exactly as `parse.py` writes it (for example `login:deploy@2026-11-09T14:03:00Z/SHA256:...`)
and `<fp or method>` the key fingerprint, or the authentication method when the login carries none
(`password`, `keyboard-interactive`). The id carries no source address: a repeat from another address in
the same second is the same acknowledgement.

Rules, each critical (group `login`); every other accepted login in the window is a non-critical `login`:
- the key fingerprint is not one of the baseline's `authorized_keys` (any user). Certificates carry their
  own fingerprint and so land here. A login with neither a fingerprint nor a password or
  keyboard-interactive method (hostbased, gssapi) is treated the same way: fail closed.
- the method is `password` or `keyboard-interactive`.
- the source address has 10 or more failures in the hourly buckets covering the 24 hours before the login:
  the login's hour and the 24 hours before it (login at 14:03 -> the buckets 14:00 of the day before up to
  14:00). That covers the whole 24 hours; the first and last bucket also hold some failures outside
  them (hourly counts cannot separate those), so the rule errs toward critical.
- the user is `root` while the baseline's `permitrootlogin` is `no` (an absent setting is not `no`).

Builder choices:
- Events from `audit_fp` (the plugin's own key) are dropped; an empty or `None` `audit_fp` drops nothing.
- The id and the `time` extra use the canonical UTC time re-formatted from the parsed event time.
- Two events with the same id (same user, time and fingerprint from different addresses) are one finding,
  critical if either is, so the order of the events cannot hide one.
- A `baseline_fp` of `None` is an empty baseline: every key login is unknown.
- The window is `max(since, now - 8 days)` to `now`, both ends inclusive, in UTC. A `since` after `now`
  (clock skew, a hand-edited file) is clamped to `now`: the window is never inverted.
- Open critical `login` findings from `previous_open` that are not in `accepted` are carried into the
  result even when outside the window, and keep their stored text. A carried finding wins over a fresh
  one with the same id: accepting the key into the baseline does not accept the login.
- A fresh event whose id is in `accepted` stays listed but is not critical.
- Without a login source one `info` finding `logins:no-source` is returned ("logins: no source on this
  host"); open anomalies are still carried.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

LOOKBACK = timedelta(days=8)
FAILURE_HOURS = 24      # buckets before the login's own hour
FAILURE_LIMIT = 10
PASSWORD_METHODS = ("password", "keyboard-interactive")
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
NO_SOURCE_ID = "logins:no-source"


def _finding(id_: str, group: str, critical: bool, text: str, **extra) -> dict:
    return {"id": id_, "group": group, "critical": critical, "text": text, **extra}


def _utc(text: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def known_fingerprints(baseline_fp: dict | None) -> set[str]:
    """Every key fingerprint in the baseline's authorized_keys section ("<user>/<fp>" keys), all users."""
    return {key.partition("/")[2] for key in ((baseline_fp or {}).get("authorized_keys") or {})}


def _failures_by_ip(failures: list[dict]) -> dict[str, list[tuple[datetime, int]]]:
    out: dict[str, list[tuple[datetime, int]]] = {}
    for f in failures:
        try:
            hour = datetime.strptime(f["hour"], "%Y-%m-%dT%H").replace(tzinfo=timezone.utc)
            out.setdefault(f["ip"], []).append((hour, int(f["count"])))
        except (KeyError, TypeError, ValueError):
            continue
    return out


def _failures_before(buckets: list[tuple[datetime, int]], when: datetime) -> int:
    last = when.replace(minute=0, second=0, microsecond=0)
    first = last - timedelta(hours=FAILURE_HOURS)
    return sum(n for hour, n in buckets if first <= hour <= last)


def _describe(event: dict, reasons: list[str]) -> str:
    how = event["fp"] or event["method"]
    text = f"{event['user']} logged in from {event['ip']} at {event['time']} ({event['method']}, {how})"
    return f"{text}: {'; '.join(reasons)}" if reasons else text


def evaluate(facts: dict, baseline_fp: dict, *, since: str | None, now: datetime, audit_fp: str,
             previous_open: list[dict], accepted: set[str]) -> tuple[list[dict], dict]:
    now = now.astimezone(timezone.utc) if now.tzinfo else now.replace(tzinfo=timezone.utc)
    start = now - LOOKBACK
    last_check = _utc(since) if since else None
    if last_check and last_check > start:
        start = min(last_check, now)
    window = {"since": start.strftime(TIME_FORMAT), "until": now.strftime(TIME_FORMAT)}

    data = facts.get("logins") or {}
    findings: dict[str, dict] = {}
    if data.get("source") is None:
        findings[NO_SOURCE_ID] = _finding(NO_SOURCE_ID, "info", False, "logins: no source on this host")
    else:
        known = known_fingerprints(baseline_fp)
        permit_root = str(((baseline_fp or {}).get("sshd") or {}).get("permitrootlogin", "")).strip().lower()
        failures = _failures_by_ip(data.get("failures") or [])
        for event in data.get("accepted") or []:
            when = _utc(event.get("time"))
            if when is None or not start <= when <= now or (bool(audit_fp) and event.get("fp") == audit_fp):
                continue
            event = {**event, "time": when.strftime(TIME_FORMAT), "fp": event.get("fp") or None,
                     "method": event.get("method") or "unknown"}
            reasons = []
            if event["method"] in PASSWORD_METHODS:
                reasons.append(f"{event['method']} login")
            elif event["fp"] not in known:
                reasons.append(f"unknown key {event['fp']}" if event["fp"] else f"{event['method']} login")
            n = _failures_before(failures.get(event.get("ip"), []), when)
            if n >= FAILURE_LIMIT:
                reasons.append(f"{n} failures from {event['ip']} in the 24 hours before")
            if event["user"] == "root" and permit_root == "no":
                reasons.append("root login, PermitRootLogin is no in the baseline")
            id_ = f"login:{event['user']}@{event['time']}/{event['fp'] or event['method']}"
            finding = _finding(id_, "login", bool(reasons) and id_ not in accepted, _describe(event, reasons),
                               time=event["time"], user=event["user"], ip=event.get("ip"),
                               method=event["method"], fp=event["fp"])
            if id_ not in findings or (finding["critical"] and not findings[id_]["critical"]):
                findings[id_] = finding

    for old in previous_open:
        if old.get("group") == "login" and old.get("critical") and old.get("id") not in accepted:
            findings[old["id"]] = dict(old)
    return sorted(findings.values(), key=lambda f: (f["id"] != NO_SOURCE_ID, f.get("time", ""), f["id"])), window
