"""`secrets scan | resolve | report`. Exit codes: 0 nothing open in class A or B, 1 open class A or B
findings, 2 a repository, the decisions file or the arguments failed, 4 no supported engine installed.

Unlike the global "4 is checked before anything is written", `secrets scan` without an engine first writes
the skipped document (secrets.json, SECRETS.md, the dated copy, a log.md line: previous findings kept,
"Not the same as clean") and then exits 4."""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

from .. import config, issues, status
from . import EXIT_CLEAN, EXIT_FAILED, EXIT_FINDINGS, EXIT_TOOL_MISSING, classify, failed, scan, store
from . import findings
from . import report as secrets_report

NO_SCAN_HINT = "no secrets scan yet: run `secrets scan` (or `run`) first"


def _open_ab(doc: dict) -> bool:
    return any(f.get("status") == "open" and f.get("class") in ("A", "B") for f in doc.get("findings") or [])


def _scan(args) -> int:
    cfg = config.load(args.out, root=args.root)
    doc = scan(cfg, full=args.full, log=print)
    if failed(doc):
        if doc["scan"].get("error"):            # the decisions file or key: names the field, never a value
            print(f"secrets: {doc['scan']['error']}", file=sys.stderr)
        return EXIT_FAILED
    if doc["scan"]["mode"] == "skipped":
        return EXIT_TOOL_MISSING
    return EXIT_FINDINGS if _open_ab(doc) else EXIT_CLEAN


def _refresh_derived(out: Path, doc: dict) -> None:
    """After a decision: the secrets part of status.json / STATUS.md and the work list follow `secrets.json`,
    so the session line and the fixers do not keep counting what was just decided. Files the first `run` has
    not made yet are not created. Never raises: the decision is recorded and keeps its exit code."""
    try:
        previous = status.read(out)
        if previous is not None and previous.get("schema") == status.SCHEMA:
            refreshed = status.refresh_secrets(previous, doc)
            status.write(out, refreshed)
            status.write_md(out, refreshed)
    except Exception as exc:                        # the type only, as everywhere a finding could be in a message
        print(f"secrets: status not refreshed ({type(exc).__name__})", file=sys.stderr)
    if issues.read(out) is not None:
        issues.try_refresh(out, lambda line: print(line, file=sys.stderr))


def _resolve(args) -> int:
    out = Path(args.out).resolve()
    doc = store.read(out)
    if doc is None:
        print(NO_SCAN_HINT, file=sys.stderr)
        return EXIT_FAILED
    now = dt.datetime.now(dt.timezone.utc)
    today = now.date().isoformat()              # UTC, like every date of the secrets step
    rotated_on = args.rotated_on or (today if args.status == "rotated" else None)
    try:
        store.read_decisions(out)               # a broken file is reported, never overwritten
        if args.fingerprint not in {f.get("fingerprint") for f in doc.get("findings") or []}:
            raise ValueError(f"unknown fingerprint: {args.fingerprint} (see SECRETS.md or secrets.json)")
        store.add_decision(out, args.fingerprint, args.status, args.note, date=today, rotated_on=rotated_on)
        decisions = store.read_decisions(out)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_FAILED
    doc["findings"], _ = store.merge(doc, [], decisions, mode="incremental", today=today, scanned_repos=set())
    findings.refresh_ages(doc["findings"], now)
    store.write_ignore_file(out, decisions)
    store.write(out, doc)
    secrets_report.write_secrets_md(out, doc, classify.load_classes())
    _refresh_derived(out, doc)
    print(f"recorded {args.status} for {args.fingerprint} in {store.DECISIONS_FILE}; "
          f"{secrets_report.SECRETS_FILE} updated")
    return EXIT_CLEAN


def _report(args) -> int:
    out = Path(args.out).resolve()
    doc = store.read(out)
    if doc is not None:
        text = secrets_report.render(out, doc, classify.load_classes())
        has_open = _open_ab(doc)
    else:
        try:
            text = (out / secrets_report.SECRETS_FILE).read_text(encoding="utf-8")
        except OSError:
            print(NO_SCAN_HINT, file=sys.stderr)
            return EXIT_FAILED
        has_open = any(line.startswith(("### A ·", "### B ·")) for line in text.splitlines())
    print(text, end="")
    return EXIT_FINDINGS if has_open else EXIT_CLEAN


def run(args) -> int:
    return {"scan": _scan, "resolve": _resolve, "report": _report}[args.secrets_command](args)
