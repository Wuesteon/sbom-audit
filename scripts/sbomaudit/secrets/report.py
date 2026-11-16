"""SECRETS.md: open class A and B findings with rotation hints, then the rotated and accepted appendices.

Rendered from the redacted `secrets.json` document only, so it can hold no secret value. Class C findings
(publishable keys, test keys) stay in `secrets.json` and never appear here.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from ..report import REPORTS_DIR, md
from ..scan import INVENTORY_FILE
from . import store
from .classify import Classes

SECRETS_FILE = "SECRETS.md"
CLASS_LABELS = {"A": "A (full access, rotate now)", "B": "B (scoped or billable)"}
ADVICE = ("Rotate first: revoke each credential at the provider, issue a new one and update every place "
          "that uses it. Rewriting git history is optional and does not remove the exposure: every clone, "
          "fork and CI cache made since the commit still holds the old value.")


def _line(text) -> str:
    return " ".join(str(text).split())


def _age(days) -> str:
    return "unknown" if days is None else f"{days} days"


def _inventory_projects(out: Path) -> list[tuple[str, set[str]]]:
    """(project, component names) per branch inventory in `inventory.json`; empty when it is unreadable."""
    try:
        doc = json.loads((Path(out) / INVENTORY_FILE).read_text(encoding="utf-8"))
        return [(str(inv.get("project")), {str(c.get("name")) for c in inv.get("components") or []})
                for inv in doc.get("inventories") or []]
    except (OSError, ValueError, AttributeError, TypeError):
        return []


def also_uses(inventory: list[tuple[str, set[str]]], packages, own_repo: str) -> list[str]:
    """Other projects whose inventory has one of the provider's client packages. Matching the project
    name against the repo's folder name is enough: only configured (local) projects are in the inventory."""
    wanted = set(packages)
    return sorted({project for project, names in inventory if project != own_repo and names & wanted})


def _newest_first(items: list[dict]) -> list[dict]:
    items = sorted(items, key=lambda f: f.get("fingerprint") or "")
    return sorted(items, key=lambda f: f.get("date") or "", reverse=True)


def _status_line(doc: dict) -> list[str]:
    scan = doc.get("scan") or {}
    engine = doc.get("engine") or {}
    lines = []
    if scan.get("mode") == "skipped":
        reason = scan.get("skipped_reason") or "not scanned"
        lines.append(f"Scan skipped this time: {_line(reason)}. Not the same as clean: the findings below are "
                     "from the last completed scan.")
    else:
        lines.append(f"Scan: {scan.get('mode')}, {engine.get('name')} {engine.get('version')}, "
                     f"{scan.get('repos', 0)} repos.")
    failed = [f for f in scan.get("failed") or [] if isinstance(f, dict)]
    if failed:
        lines += ["", "Repositories that could not be scanned (their findings are from the last completed scan):"]
        lines += [f"- {_line(f.get('repo'))}: {_line(f.get('error'))}" for f in failed]
    return lines


def _entry(f: dict, classes: Classes, inventory, scan_day: str) -> list[str]:
    provider = classes.providers.get(f.get("provider") or "")
    name = provider.name if provider else (f.get("provider") or "unknown")
    commit = (f.get("commit") or "")[:7]
    # branches and live-in-tree are derived from the value, which is not stored: a finding carried from an
    # earlier scan keeps them as of the day it was last seen, until a full scan finds it again
    seen = f.get("last_seen") or ""
    as_of = f" (as of {seen})" if seen and seen < scan_day else ""
    lines = [f"### {f.get('class')} · {_line(f.get('rule_id'))} · {_line(f.get('repo'))} "
             f"`{_line(f.get('file'))}:{f.get('line')}`", "",
             f"- fingerprint: `{_line(f.get('fingerprint'))}`",
             f"- repo: {_line(f.get('repo'))}, branches{as_of}: {', '.join(f.get('branches') or []) or 'none'}",
             f"- file: `{_line(f.get('file'))}:{f.get('line')}`, commit `{commit}`",
             f"- rule: {_line(f.get('rule_id'))}, provider: {_line(name)}",
             f"- age: {_age(f.get('age_days'))}, live in tree{as_of}: {'yes' if f.get('live_in_tree') else 'no'}"]
    if f.get("reopened_from"):
        lines.append(f"- reopened: same value as the rotated `{_line(f['reopened_from'])}`, committed after "
                     "its rotation")
    if provider:
        lines.append(f"- rotate: {_line(provider.hint)}")
        users = also_uses(inventory, provider.packages, f.get("repo") or "")
        if users:
            lines.append(f"- also uses {f.get('provider')}: {', '.join(users)}")
    return lines + [""]


def _appendix(title: str, items: list[dict], decisions: dict, rotated: bool) -> list[str]:
    lines = [f"## {title}", ""]
    if not items:
        return lines + ["None.", ""]
    for f in _newest_first(items):
        decision = decisions.get(f.get("fingerprint"))
        note = decision.note if decision else ""
        when = f", rotated on {f.get('rotated_on')}" if rotated and f.get("rotated_on") else ""
        lines.append(f"- `{_line(f.get('fingerprint'))}` {_line(f.get('repo'))} "
                     f"`{_line(f.get('file'))}:{f.get('line')}` ({_line(f.get('rule_id'))}){when}"
                     + (f": {_line(note)}" if note else ""))
    return lines + [""]


def render(out: Path, doc: dict, classes: Classes) -> str:
    """SECRETS.md text for `doc`; decision notes come from the decisions file (none when it is invalid)."""
    try:
        decisions = store.read_decisions(out)
    except ValueError:
        decisions = {}
    shown = [f for f in doc.get("findings") or [] if isinstance(f, dict) and f.get("class") in ("A", "B")]
    open_ = [f for f in shown if f.get("status") == "open"]
    inventory = _inventory_projects(out)
    scan_day = str(doc.get("generated_at") or "")[:10]
    L = [f"# Secrets {str(doc.get('generated_at') or '')[:10]}", "",
         "Generated by sbom-audit from `secrets.json`. No secret value is stored anywhere: a finding carries "
         "its location and a keyed hash only. Class C findings (publishable and test keys) are listed in "
         "`secrets.json` only.", ""]
    L += _status_line(doc) + ["", "| Class | Open | Oldest open |", "|---|---|---|"]
    for cls, label in CLASS_LABELS.items():
        items = [f for f in open_ if f.get("class") == cls]
        known = [f["age_days"] for f in items if f.get("age_days") is not None]
        oldest = _age(max(known)) if known else ("unknown" if items else "–")
        L.append(f"| {md(label)} | {len(items)} | {oldest} |")
    L += ["", ADVICE, "", "## Open", ""]
    if not open_:
        L += ["None.", ""]
    for cls in ("A", "B"):
        for f in _newest_first([f for f in open_ if f.get("class") == cls]):
            L += _entry(f, classes, inventory, scan_day)
    L += _appendix("Rotated", [f for f in shown if f.get("status") == "rotated"], decisions, True)
    L += _appendix("Accepted", [f for f in shown if f.get("status") == "accepted"], decisions, False)
    return "\n".join(L).rstrip("\n") + "\n"


def write_secrets_md(out: Path, doc: dict, classes: Classes) -> Path:
    return store.atomic_write(Path(out) / SECRETS_FILE, render(out, doc, classes))


def dated_path(out: Path, date) -> Path:
    day = date.isoformat() if isinstance(date, dt.date) else str(date)
    return Path(out) / REPORTS_DIR / f"{day}-secrets.md"


def write_dated_copy(out: Path, date) -> Path:
    """`reports/<date>-secrets.md`, a copy of the current SECRETS.md."""
    return store.atomic_write(dated_path(out, date), (Path(out) / SECRETS_FILE).read_text(encoding="utf-8"))
