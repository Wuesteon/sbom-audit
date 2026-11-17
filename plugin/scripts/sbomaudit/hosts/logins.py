"""Host mode login anomalies: accepted sshd logins, one finding per user and key, carried until accepted.

Spec "Login anomaly". `evaluate` reads `facts["logins"]` (see `parse.py`) and the accepted baseline
fingerprint, and returns `(findings, window)`.

Two kinds of finding, both group `login` (ids are typed by the user in `hosts accept`, matched against
`accepted` and `previous_open`, so they must not change between runs):

- Per user and key (`kind: "key"`), id `login:<user>/<fp or method>`: every login of that user with that
  key fingerprint in the window, with `count`, `first`, `last` and the distinct source addresses (`ips`).
  `<fp or method>` is the key fingerprint, or the authentication method when the login carries none
  (`password`, `keyboard-interactive`). For a key the id is `login:` followed by the baseline's own
  `authorized_keys` key (`<user>/<fp>`). It carries no time and no address, so a CI user logging in a hundred
  times from changing runner addresses is one finding, and one decision covers its future logins.
- Per login (`kind: "event"`), id `login:<user>@<UTC time>/<fp or method>` (time `YYYY-MM-DDTHH:MM:SSZ`):
  a login preceded by 10 or more failures from its own source address. Each one is a separate event to
  acknowledge; it is counted in its user-and-key finding as well. This is the id format every login had
  before aggregation, so decisions recorded for single logins keep matching (see Migration).

Critical reasons of a user-and-key finding (a property of the key, the user or the config, not of one login):
- the key fingerprint is not one of the baseline's `authorized_keys` (any user). That includes a key added
  to `authorized_keys` since the baseline (its `change:authorized_keys:+...` is open too) and a key the
  collector cannot see (a user without a login shell, AuthorizedKeysCommand, certificates: a certificate
  carries its own fingerprint). A login with neither a fingerprint nor a password or keyboard-interactive
  method (hostbased, gssapi) is treated the same way: fail closed.
- the method is `password` or `keyboard-interactive`.
- the user is not in the baseline's `users` (applied only when the baseline has a users section).
- the user is `root` while the baseline's `permitrootlogin` is `no` (an absent setting is not `no`).
A known key of a known user from a new source address is not critical: the addresses are listed.

Failure rule of a per-login finding: the source address has 10 or more failures in the hourly buckets
covering the 24 hours before the login: the login's hour and the 24 hours before it (login at 14:03 -> the
buckets 14:00 of the day before up to 14:00). That covers the whole 24 hours; the first and last bucket also
hold some failures outside them (hourly counts cannot separate those), so the rule errs toward critical.

Decisions:
- A user-and-key id in `accepted` makes that finding non-critical (`accepted: true`) now and for every later
  login of that user with that key. A new key, another user or a password login is another id: still critical.
- A per-login id in `accepted` makes that one login non-critical, and it no longer counts toward its
  user-and-key finding's criticality (`legacy_accepted` counts such logins).

Migration from per-login findings (before aggregation every login was `login:<user>@<time>/<fp>`):
- Decisions on such ids keep matching exactly the login they named (above); none is widened to a key.
- Open critical per-login findings carried from an older `hosts.json` (no `kind`) are folded into their
  user-and-key finding (count, first, last, addresses), so accepting `login:<user>/<fp>` once clears them
  all. Those whose reasons include the failure rule stay per-login.

Builder choices:
- Events from `audit_fp` (the plugin's own key) are dropped; an empty or `None` `audit_fp` drops nothing.
- Times are the canonical UTC time re-formatted from the parsed event time.
- Two events with the same per-login id (same user, time and fingerprint from different addresses) are one
  per-login finding, critical if either is, so the order of the events cannot hide one.
- A `baseline_fp` of `None` is an empty baseline: every key login is unknown.
- The window is `max(since, now - 8 days)` to `now`, both ends inclusive, in UTC. A `since` after `now`
  (clock skew, a hand-edited file) is clamped to `now`: the window is never inverted.
- Open critical `login` findings from `previous_open` that are not in `accepted` are carried into the result
  even when outside the window. A carried user-and-key finding stays critical and takes in the fresh logins
  after its `last` (a re-read window is not counted twice); a carried per-login finding wins over a fresh one
  with the same id. Accepting the key into the baseline does not accept the logins already seen with it.
- Without a login source one `info` finding `logins:no-source` is returned ("logins: no source on this
  host"); open anomalies are still carried.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

LOOKBACK = timedelta(days=8)
FAILURE_HOURS = 24      # buckets before the login's own hour
FAILURE_LIMIT = 10
PASSWORD_METHODS = ("password", "keyboard-interactive")
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
NO_SOURCE_ID = "logins:no-source"
SHOWN_IPS = 5           # addresses named in the text; `ips` has all
EVENT_ID = re.compile(r"^login:(?P<user>.+?)@(?P<time>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)/(?P<how>.+)$")
FAILURE_MARK = " failures from "   # in a reason text: the per-login failure rule


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


def key_id(user: str, how: str) -> str:
    """The user-and-key id: `login:<user>/<fp or method>`."""
    return f"login:{user}/{how}"


def event_id(user: str, time: str, how: str) -> str:
    """The per-login id: `login:<user>@<time>/<fp or method>` (the format of every login before aggregation)."""
    return f"login:{user}@{time}/{how}"


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


def _describe_event(event: dict, reasons: list[str]) -> str:
    how = event["fp"] or event["method"]
    text = f"{event['user']} logged in from {event['ip']} at {event['time']} ({event['method']}, {how})"
    return f"{text}: {'; '.join(reasons)}" if reasons else text


def _describe_key(agg: dict) -> str:
    how = agg["fp"] or agg["method"]
    ips = agg["ips"]
    shown = ", ".join(str(ip) for ip in ips[:SHOWN_IPS]) + (f" and {len(ips) - SHOWN_IPS} more"
                                                             if len(ips) > SHOWN_IPS else "")
    count = agg["count"]
    if count == 1:
        text = f"{agg['user']} logged in once with {agg['method']} {how} from {shown or 'unknown'} at {agg['first']}"
    else:
        where = f"{len(ips)} address{'es' if len(ips) != 1 else ''} ({shown})" if ips else "unknown addresses"
        text = (f"{agg['user']} logged in {count} times with {agg['method']} {how} from {where}, "
                f"first {agg['first']}, last {agg['last']}")
    if agg.get("legacy_accepted"):
        text += f" ({agg['legacy_accepted']} of them accepted one by one earlier)"
    reasons = agg.get("reasons") or []
    return f"{text}: {'; '.join(reasons)}" if reasons else text


def _key_reasons(event: dict, known: set[str], users: dict, permit_root: str) -> list[str]:
    reasons = []
    if event["method"] in PASSWORD_METHODS:
        reasons.append(f"{event['method']} login")
    elif event["fp"] not in known:
        reasons.append(f"key {event['fp']} is not in the baseline's authorized_keys" if event["fp"]
                       else f"{event['method']} login without a key fingerprint")
    if users and event["user"] not in users:
        reasons.append(f"user {event['user']} is not a login user in the baseline")
    if event["user"] == "root" and permit_root == "no":
        reasons.append("root login, PermitRootLogin is no in the baseline")
    return reasons


def _new_key(user: str, fp: str | None, method: str, critical: bool = False) -> dict:
    return {"id": key_id(user, fp or method), "group": "login", "critical": critical, "text": "", "kind": "key",
            "user": user, "fp": fp, "method": method, "count": 0, "first": None, "last": None, "time": None,
            "ips": [], "reasons": []}


def _add_login(agg: dict, time: str, ip) -> None:
    agg["count"] += 1
    agg["first"] = time if agg["first"] is None or time < agg["first"] else agg["first"]
    agg["last"] = time if agg["last"] is None or time > agg["last"] else agg["last"]
    agg["time"] = agg["last"]
    if ip and ip not in agg["ips"]:
        agg["ips"] = sorted([*agg["ips"], ip])


def _add_reasons(agg: dict, reasons: list[str]) -> None:
    for r in reasons:
        if r not in agg["reasons"]:
            agg["reasons"].append(r)


def _legacy_reasons(old: dict) -> list[str]:
    """The reasons in a per-login finding's text (`... (<method>, <how>): r1; r2`)."""
    _, sep, tail = str(old.get("text", "")).partition("): ")
    return [r for r in tail.split("; ") if r] if sep else []


def _legacy_parts(old: dict) -> tuple[str, str | None, str, str] | None:
    """(user, fp, method, time) of a per-login finding, from its fields or else its id."""
    m = EVENT_ID.match(str(old.get("id", "")))
    if not m:
        return None
    how = m.group("how")
    fp = old.get("fp") if "fp" in old else (None if how in PASSWORD_METHODS or ":" not in how else how)
    method = old.get("method") or ("publickey" if fp else how)
    return old.get("user") or m.group("user"), fp or None, method, old.get("time") or m.group("time")


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
    keys: dict[str, dict] = {}
    fresh: dict[str, list[tuple[str, object, list[str]]]] = {}   # key id -> (time, ip, reasons) of each login
    if data.get("source") is None:
        findings[NO_SOURCE_ID] = _finding(NO_SOURCE_ID, "info", False, "logins: no source on this host")
    else:
        known = known_fingerprints(baseline_fp)
        users = (baseline_fp or {}).get("users") or {}
        permit_root = str(((baseline_fp or {}).get("sshd") or {}).get("permitrootlogin", "")).strip().lower()
        failures = _failures_by_ip(data.get("failures") or [])
        for event in data.get("accepted") or []:
            when = _utc(event.get("time"))
            if when is None or not start <= when <= now or (bool(audit_fp) and event.get("fp") == audit_fp):
                continue
            event = {**event, "time": when.strftime(TIME_FORMAT), "fp": event.get("fp") or None,
                     "method": event.get("method") or "unknown"}
            how = event["fp"] or event["method"]
            reasons = _key_reasons(event, known, users, permit_root)
            per_login = event_id(event["user"], event["time"], how)
            kid = key_id(event["user"], how)
            keys.setdefault(kid, _new_key(event["user"], event["fp"], event["method"]))
            fresh.setdefault(kid, []).append((event["time"], event.get("ip"),
                                              [] if per_login in accepted else reasons))
            if per_login in accepted:
                keys[kid]["legacy_accepted"] = keys[kid].get("legacy_accepted", 0) + 1
            n = _failures_before(failures.get(event.get("ip"), []), when)
            if n >= FAILURE_LIMIT:
                ev_reasons = [*reasons, f"{n}{FAILURE_MARK}{event['ip']} in the 24 hours before"]
                finding = _finding(per_login, "login", per_login not in accepted, _describe_event(event, ev_reasons),
                                   kind="event", time=event["time"], user=event["user"], ip=event.get("ip"),
                                   method=event["method"], fp=event["fp"])
                if per_login not in findings or (finding["critical"] and not findings[per_login]["critical"]):
                    findings[per_login] = finding

    # carried: open critical findings of earlier checks that no decision accepted
    for old in previous_open:
        if not isinstance(old, dict) or old.get("group") != "login" or not old.get("critical") \
                or old.get("id") in accepted:
            continue
        kind = old.get("kind")
        if kind == "key":
            agg = {**old, "ips": list(old.get("ips") or []), "reasons": list(old.get("reasons") or [])}
            agg.setdefault("count", 0)
            agg.setdefault("first", old.get("time"))
            agg.setdefault("last", old.get("time"))
            prior = keys.get(old["id"])
            keys[old["id"]] = agg
            if prior and prior.get("legacy_accepted"):
                agg["legacy_accepted"] = prior["legacy_accepted"]
            agg["carried"] = True
            continue
        parts = _legacy_parts(old) if kind is None else None
        reasons = _legacy_reasons(old)
        if parts is None or any(FAILURE_MARK in r for r in reasons):
            findings[old["id"]] = dict(old)      # a per-login finding: carried as it is
            continue
        user, fp, method, time = parts           # an older per-login finding: folded into its user and key
        kid = key_id(user, fp or method)
        if kid in accepted:
            continue
        agg = keys.setdefault(kid, _new_key(user, fp, method))
        if not agg.get("carried"):
            agg["carried"] = True
        _add_login(agg, time, old.get("ip"))
        _add_reasons(agg, reasons or ["open since an earlier check"])

    for kid, agg in keys.items():
        carried = bool(agg.pop("carried", False))
        for time, ip, reasons in sorted(fresh.get(kid, []), key=lambda e: e[0]):
            if carried and agg["last"] is not None and time <= agg["last"] and agg["count"]:
                continue   # already counted by the check this finding is carried from
            _add_login(agg, time, ip)
            _add_reasons(agg, reasons)
        if kid in accepted:
            agg["critical"] = False
            if agg["reasons"]:
                agg["accepted"] = True
        else:
            agg["critical"] = carried or bool(agg["reasons"])
            agg.pop("accepted", None)
        agg["text"] = _describe_key(agg)
        findings[kid] = agg
    return sorted(findings.values(), key=lambda f: (f["id"] != NO_SOURCE_ID, f.get("time") or "", f["id"])), window
