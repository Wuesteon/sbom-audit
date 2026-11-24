"""Host mode outputs: `HOSTS.md`, its dated copy and the `hosts` lines in `log.md`.

Input is the `hosts.json` document only. It holds findings and summaries, never raw collector facts, so
nothing secret can reach the report; everything user-controlled in it (process, unit and package names,
repo URLs, Lynis texts, error strings, host and project names) still passes through `report.md()`.

Layout decisions:
- A host's `Critical` section lists every critical finding of every group, each with its backticked
  change-id and what to do (accept it, or why it cannot be accepted). The group sections that follow list
  what is left in their group: non-critical findings and accepted record-only ones, so nothing is listed twice.
  The two groups that are always critical and never acceptable get their own explanatory section: `Failed
  checks` (group `warning`, right after Critical) and `Host key` (group `hostkey`, right after Failed checks,
  because a changed host key is a transport-level fact that comes before anything the host reported).
- KEV is always critical: a `kev` finding is listed under Critical unless a decision accepted it. `warning`
  and `hostkey` findings are critical even if the flag says otherwise.
- `vuln` findings (the non-critical per-package vulnerability summaries) have the section `Vulnerabilities`
  between `Lynis warnings` and `Third-party updates`, where the checker ranks them.
- The `Logins` section starts with `LOGIN_RULE` (what makes a login finding critical and what accepting one
  covers) whenever the host has a login finding, critical or not; the accept hint of a per-key login finding
  says that the decision covers that user's later logins with that key.
- A failed host is rendered as failed with its error and the time of its last successful check; the findings
  it carries are marked as from that check, and the host is never counted as clean.
- EPSS (only when `hosts.json` has `epss`, that is when the check ran the EPSS step): one line under the
  table names the score date or says that no scores were available; with scores, KEV lines read
  `<cve> (KEV, EPSS <score>) in ...`, and a `vuln` line whose highest score is at or above `EPSS_SHOWN_FROM`
  ends with ` - highest EPSS <score> (<cve>)`, the CVE that has that score (no CVE for a `hosts.json` written
  before 1.4.1); a lower highest score is not shown, and the line under the table says so. Without a score
  they read `(KEV, no EPSS)` and ` - no EPSS` (`epss.label`): a missing score is never left out. Information
  only: no section, order or count depends on a score.
"""
from __future__ import annotations

import datetime as dt
import re
from pathlib import Path

from .. import epss
from .. import report as core
from ..cache import atomic_write
from . import store

HOSTS_MD = store.HOSTS_MD
ADMIN_ACTIONS = ("bootstrap", "unbootstrap", "patch")
ALWAYS_CRITICAL = ("warning", "hostkey")
NOTE_MAX = 200
# a package line shows its highest EPSS score from here up; fixed, because no host rule reads `[epss] promote_at`
EPSS_SHOWN_FROM = epss.DEFAULT_THRESHOLD
# the section order after Critical, Failed checks and Host key: (heading, groups)
SECTIONS = [("KEV", ("kev",)), ("Patch automation", ("patch",)), ("Logins", ("login",)),
            ("Fingerprint changes", ("change",)), ("Permissive defaults", ("permissive",)),
            ("Lynis warnings", ("lynis_warning", "lynis_index")), ("Vulnerabilities", ("vuln",)),
            ("Third-party updates", ("third_party",))]
GROUP_LABEL = {"warning": "check did not run", "hostkey": "host key", "change": "change", "kev": "KEV",
               "login": "login", "patch": "patch automation", "permissive": "permissive default",
               "lynis_index": "Lynis index", "lynis_warning": "Lynis warning", "vuln": "vulnerability",
               "third_party": "third-party update", "lynis_suggestion": "Lynis suggestion", "info": "info"}
LOGIN_RULE = ("One finding per user and key (count, first and last time, source addresses). Critical: the key "
              "is not in the baseline's authorized_keys, a password or keyboard-interactive login, a user who is "
              "not in the baseline, or root while the baseline's PermitRootLogin is no; a login after 10 or more "
              "failures from its own address is also listed on its own. A known key of a known user from a new "
              "address is not critical. Accepting `login:<user>/<key>` covers that user's later logins with that "
              "key; a new key or a password login is a new finding.")
FIX_LABEL = {"installable": "fix installable (apply the pending update)",
             "reboot": "fixed kernel installed, reboot needed",
             "not installable": "fix released, not installable yet (stale lists, phased update, or for a "
                                "kernel no fixed image installed)",
             "pro-only": "fix only through Ubuntu Pro",
             "not released": "no fix released"}


# --------------------------------------------------------------------------- small helpers

def _code(s) -> str:
    """A code span that survives backticks in `s` (a longer delimiter) and has no line break."""
    text = str(s).replace("\n", " ").replace("\r", " ")
    runs = re.findall(r"`+", text)
    fence = "`" * (max(map(len, runs)) + 1 if runs else 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def _is_critical(f: dict) -> bool:
    """KEV, failed checks and host-key changes are critical unless a decision accepted the record-only one."""
    group = f.get("group")
    if group in ALWAYS_CRITICAL:
        return True
    if f.get("accepted"):
        return False
    return bool(f.get("critical")) or group == "kev"


def _findings(h: dict) -> list[dict]:
    return [f for f in h.get("findings") or [] if isinstance(f, dict)]


def _critical_count(h: dict) -> int:
    return sum(1 for f in _findings(h) if _is_critical(f))


def _date(iso) -> str:
    return str(iso)[:10] if iso else "never"


def _host_order(hosts: dict) -> list[str]:
    return sorted(hosts, key=lambda n: (not (hosts[n] or {}).get("production"), n))


def _decisions(out: Path) -> dict:
    try:
        return store.read_decisions(out)
    except ValueError:
        return {}   # an unreadable decisions file must not stop the report; accepted findings say "(accepted)"


def _index_cell(h: dict) -> str:
    s = h.get("summary") or {}
    index, prev = s.get("index"), s.get("index_prev")
    if not isinstance(index, int):
        return "-"
    if not isinstance(prev, int):
        return str(index)
    delta = index - prev
    return f"{index} (±0)" if delta == 0 else f"{index} ({delta:+d})"


def _reachable(h: dict) -> str:
    status = h.get("status")
    if status == "unsupported":
        return "yes (unsupported OS)"
    return "yes" if status == "ok" else "no"   # failed, missing or unknown status: not known to be reachable


def _critical_cell(h: dict) -> str:
    n = _critical_count(h)
    status = h.get("status")
    if status == "failed":
        return f"{n} (stale)" if n else "unknown"
    if status not in ("ok", "unsupported"):
        return str(n) if n else "unknown"
    return str(n)


# --------------------------------------------------------------------------- finding lines

def _fix_state(f: dict) -> str | None:
    fix = f.get("fix")
    if not fix:
        return None
    fixed, candidate = f.get("fixed"), f.get("candidate")
    label = FIX_LABEL.get(fix)
    if fix == "unknown":
        label = (f"fix state unknown: fix {core.md(fixed)} released, apt candidate "
                 f"{core.md(candidate or 'none')} cannot be compared, check by hand" if fixed
                 else "fix state unknown (osv.dev record failed)")
        return label
    if label is None:
        return f"fix state: {core.md(fix)}"
    if fixed and fix != "not released":
        label += f"; fixed version {core.md(fixed)}"
    if candidate and fix in ("installable", "not installable"):
        label += f"; apt candidate {core.md(candidate)}"
    return label


def _accepted_note(host: str, f: dict, decisions: dict) -> str:
    d = decisions.get((host, f.get("id")))
    if d is None:
        return "(accepted)"
    note = d.note.strip()
    note = note[:NOTE_MAX] + "..." if len(note) > NOTE_MAX else note
    review = f", review by {core.md(d.review_by)}" if d.review_by else ""
    return f"(accepted {core.md(d.date)}{review}: {core.md(note)})" if note \
        else f"(accepted {core.md(d.date)}{review})"


def _hint(host: str, f: dict) -> str:
    id_ = str(f.get("id", ""))
    group = f.get("group")
    if group == "warning" or id_.startswith("section-failed:"):
        return "this check did not run; fix the cause and re-run `hosts check`"
    if id_ == "hostkey:changed" or group == "hostkey":
        return (f"verify the host key out of band, then re-pin with `hosts bootstrap {core.md(host)}`")
    if id_.startswith("patch:"):
        return "only clears when fixed (cannot be accepted)"
    if id_ == "baseline:unreadable":
        return "restore the baseline file from git or delete it, then re-run `hosts check`"
    suffix = " --review-by YYYY-MM-DD" if id_.startswith("kev:") else ""
    if f.get("kind") == "key":
        suffix += " (covers this user's later logins with this key; only if you recognise the key)"
    return f"accept with: hosts accept {core.md(host)} {_code(id_)} \"<note>\"{suffix}"


def _line(host: str, h: dict, f: dict, decisions: dict, *, critical: bool = False, scores: bool = False) -> str:
    """`scores`: the check had EPSS scores, so KEV and `vuln` lines show them (`no EPSS` without one)."""
    parts = [f"- {_code(f.get('id', '?'))}"]
    if critical:
        parts[0] = f"- **{core.md(GROUP_LABEL.get(f.get('group'), f.get('group')))}** {_code(f.get('id', '?'))}"
    fix = _fix_state(f) if f.get("group") == "kev" else None
    if fix and f.get("cve") and f.get("package"):
        label = f"KEV, {epss.label(f.get('epss'))}" if scores else "KEV"
        parts.append(f"{core.md(f['cve'])} ({label}) in {core.md(f['package'])} {core.md(f.get('version') or '')}"
                     .rstrip() + f": {fix}")
    else:
        parts.append(core.md(f.get("text", "")) + (f" ({fix})" if fix else ""))
    if scores and f.get("group") == "vuln":
        top = f.get("max_epss")
        if top is None:
            parts.append(epss.label(None))
        elif top >= EPSS_SHOWN_FROM:
            cve = f.get("max_epss_cve")          # absent in a hosts.json written before 1.4.1
            parts.append(epss.label(top, "highest EPSS") + (f" ({core.md(cve)})" if cve else ""))
    line = " - ".join(parts)
    if f.get("accepted"):
        line += " " + _accepted_note(host, f, decisions)
    if critical:
        line += f" - {_hint(host, f)}"
    if h.get("status") == "failed" and f.get("group") != "hostkey":
        line += f" (from the last check {core.md(h.get('checked_at') or 'never')})"
    return line


def _section(title: str, lines: list[str]) -> list[str]:
    return [f"### {title}", "", *lines, ""] if lines else []


# --------------------------------------------------------------------------- one host

def _facts_line(h: dict) -> str:
    s = h.get("summary") or {}
    bits = [f"Address {core.md(h.get('address') or '-')}"]
    if s.get("os"):
        bits.append(f"OS {core.md(s['os'])}")
    if s.get("kernel"):
        bits.append(f"kernel {core.md(s['kernel'])}")
    if s.get("reboot_required"):
        bits.append("reboot required")
    return " · ".join(bits)


def _status_block(h: dict) -> list[str]:
    status = h.get("status")
    if status == "failed":
        checked = h.get("checked_at")
        last = f"last successful check {core.md(checked)}" if checked else "last successful check never"
        stale = ("The findings below are carried from that check and are stale." if _findings(h)
                 else "No data is available for this host.")
        return [f"**Status: failed** - {core.md(h.get('error') or 'unknown error')}. Reachable: no; {last}. {stale}",
                ""]
    if status == "unsupported":
        os_ = (h.get("summary") or {}).get("os") or "unknown"
        return [f"**Status: unsupported OS** ({core.md(os_)}) - no checks were run on this host.", ""]
    if status != "ok":
        shown = f" ({core.md(status)})" if status else ""
        return [f"**Status: unknown status**{shown} - Reachable: no. The state of this host is not known; "
                "any findings below may be stale.", ""]
    return []


def _host_section(name: str, h: dict, decisions: dict, scores: bool = False) -> list[str]:
    findings = _findings(h)
    critical = [f for f in findings if _is_critical(f)]
    rest = [f for f in findings if not _is_critical(f)]
    projects = ", ".join(core.md(p) for p in h.get("projects") or []) or "-"
    out = [f"## {core.md(name)}", "", f"Projects: {projects} · {_facts_line(h)}", "", *_status_block(h)]

    def lines(items, crit=False):
        return [_line(name, h, f, decisions, critical=crit, scores=scores) for f in items]

    out += _section("Critical", lines(critical, True))
    failed_checks = [f for f in critical if f.get("group") == "warning"]
    if failed_checks:
        out += _section("Failed checks", ["These checks did not run, so the host must not be read as clean:", "",
                                          *lines(failed_checks)])
    out += _section("Host key", lines([f for f in critical if f.get("group") == "hostkey"]))
    for title, groups in SECTIONS:
        items = lines([f for f in rest if f.get("group") in groups])
        if groups == ("login",) and any(f.get("group") == "login" for f in findings):
            items = [LOGIN_RULE, "", *items]
        out += _section(title, items)
    suggestions = [f for f in rest if f.get("group") == "lynis_suggestion"]
    if suggestions:
        out += [f"<details>", f"<summary>Lynis suggestions ({len(suggestions)})</summary>", "",
                *lines(suggestions), "", "</details>", ""]
    known = {g for _, gs in SECTIONS for g in gs} | {"lynis_suggestion"}
    info = [f for f in rest if f.get("group") not in known]
    out += _section("Informational", lines(info))
    if not findings and h.get("status") == "ok":
        out += ["No findings.", ""]
    return out


# --------------------------------------------------------------------------- document

def _summary_line(hosts: dict) -> str:
    """Counts by status and, separately, hosts with critical findings of any status, so the headline never
    reads lower than the table's Critical column (a failed or unsupported host can carry critical findings).
    A host with a missing or unknown status is never clean."""
    clean = critical = failed = unsupported = unknown = 0
    for h in hosts.values():
        status = h.get("status")
        has_critical = _critical_count(h) > 0
        critical += has_critical
        if status == "failed":
            failed += 1
        elif status == "unsupported":
            unsupported += 1
        elif status != "ok":
            unknown += 1
        elif not has_critical:
            clean += 1
    total = len(hosts)
    parts = [f"{clean} clean", f"{critical} with critical findings", f"{failed} failed",
             f"{unsupported} unsupported OS", f"{unknown} unknown status"]
    return f"{total} host{'s' if total != 1 else ''}: " + ", ".join(parts)


def _epss_line(block: dict) -> str:
    if not block.get("available"):
        return "EPSS scores were not available in this check."
    date = block.get("score_date")
    date = core.md(date[:10]) if isinstance(date, str) and date else "an unknown date"
    return (f"EPSS scores of {date} (FIRST): the probability that a CVE is exploited in the next 30 days. "
            "Shown for information; host priorities do not depend on it. A package line names its highest score "
            f"and the CVE behind it from {EPSS_SHOWN_FROM:.0%} up; a lower one is not shown, and `no EPSS` "
            "means that none of the package's open CVEs has a score.")


def render(doc: dict, decisions: dict) -> str:
    hosts = {n: h for n, h in (doc.get("hosts") or {}).items() if isinstance(h, dict)}
    lines = ["# Host audit", "", f"Generated {core.md(doc.get('generated_at') or '-')}", ""]
    if doc.get("skipped"):
        lines += [f"> Skipped: {core.md(doc['skipped'])} - last checked {core.md(_date(doc.get('last_checked')))}. "
                  "The data below is from earlier checks.", ""]
    lines += [_summary_line(hosts), "",
              "| Host | Production | Reachable | Index (Δ) | Critical | Updates pending | KEV | Last unattended run |",
              "|---|---|---|---|---|---|---|---|"]
    for name in _host_order(hosts):
        h = hosts[name]
        s = h.get("summary") or {}
        unsupported = h.get("status") == "unsupported"
        stale = " (stale)" if h.get("status") == "failed" else ""   # carried from the last successful check

        def value(cell: str) -> str:
            return cell + stale if cell != "-" else cell
        cells = [core.md(name), "yes" if h.get("production") else "no", _reachable(h), value(_index_cell(h)),
                 _critical_cell(h),
                 "-" if unsupported or "updates_pending" not in s else value(str(s["updates_pending"])),
                 "-" if unsupported or "kev" not in s else value(str(s["kev"])),
                 value(core.md(s.get("last_unattended") or "-"))]
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
    block = doc.get("epss") if isinstance(doc.get("epss"), dict) else None   # only when the EPSS step ran
    scores = bool(block and block.get("available"))
    if block is not None:
        lines += [_epss_line(block), ""]
    for name in _host_order(hosts):
        lines += _host_section(name, hosts[name], decisions, scores)
    return "\n".join(lines).rstrip("\n") + "\n"


def write_md(out: Path, doc: dict) -> Path:
    out = Path(out)
    return atomic_write(out / HOSTS_MD, render(doc, _decisions(out)))


def write_dated(out: Path, doc: dict, today: dt.date) -> Path:
    out = Path(out)
    return atomic_write(out / core.REPORTS_DIR / f"{today.isoformat()}-hosts.md", render(doc, _decisions(out)))


# --------------------------------------------------------------------------- log.md

def _append(out: Path, line: str) -> Path:
    path = Path(out) / core.LOG_FILE
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(core.LOG_HEADER, encoding="utf-8")
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    return path


def append_log_check(out: Path, doc: dict) -> Path:
    """`<time> | hosts | checked <n> | failed <m> | critical <k>`, plus ` | skipped: <reason>` or
    ` | failed: <host>: <error>; …`. n, m and k count the hosts this run attempted (a skipped run: none)."""
    generated = doc.get("generated_at")
    skipped = doc.get("skipped")
    hosts = {} if skipped else {n: h for n, h in (doc.get("hosts") or {}).items()
                                if isinstance(h, dict) and h.get("attempted_at") == generated}
    failed = [(n, h) for n, h in hosts.items() if h.get("status") == "failed"]
    line = " | ".join([core.md(generated), "hosts", f"checked {len(hosts)}", f"failed {len(failed)}",
                       f"critical {sum(_critical_count(h) for h in hosts.values())}"])
    if skipped:
        line += f" | skipped: {core.md(skipped)}"
    elif failed:
        line += " | failed: " + "; ".join(f"{core.md(n)}: {core.md(h.get('error') or 'unknown error')}"
                                          for n, h in failed)
    return _append(out, line)


def append_log_accept(out: Path, host: str, change_id: str) -> Path:
    """`<time> | hosts accept | <host> | <change-id>`; the note stays in the decisions file."""
    return _append(out, " | ".join([core._now(), "hosts accept", core.md(host), core.md(change_id)]))


def append_log_admin(out: Path, action: str, host: str, outcome: str) -> Path:
    """`<time> | hosts <action> | <host> | <outcome>` for bootstrap, unbootstrap and patch."""
    if action not in ADMIN_ACTIONS:
        raise ValueError(f"unknown hosts action {action!r}")
    return _append(out, " | ".join([core._now(), f"hosts {action}", core.md(host), core.md(outcome)]))
