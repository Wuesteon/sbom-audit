"""The secrets scan: every repository's git history through gitleaks, redacted into `secrets.json`,
rendered into `SECRETS.md`, and the `secrets scan | resolve | report` subcommands.

Nothing leaves the machine here: the engine runs offline with the plugin's rules, raw rows are redacted
in memory, and error messages are the engine's scrubbed `detail` or an exception's type name only.

Time is UTC throughout: `now` defaults to (and is converted to) UTC, and `generated_at`, `first_seen`,
`last_seen`, `age_days` and the decision dates written by `resolve` all derive from the UTC clock.
Every merge recomputes `age_days` from each finding's commit date.
"""
from __future__ import annotations

import datetime as dt
import subprocess
from pathlib import Path

from .. import config, gitio, preflight
from .. import report as audit_report
from ..errors import EngineError, ToolError
from . import classify, engine, findings, scope, store
from . import report as secrets_report

EXIT_CLEAN, EXIT_FINDINGS, EXIT_FAILED, EXIT_TOOL_MISSING = 0, 1, 2, 4
RAW_DIR = Path(".cache") / "secrets" / "raw"


def _problem_reason(problem: engine.EngineProblem) -> str:
    if problem.reason == "missing":
        return f"skipped (install: {problem.detail or preflight.SECRETS_INSTALL})"
    inner = problem.reason
    if inner.startswith("unsupported (") and inner.endswith(")"):
        inner = inner[len("unsupported ("):-1]
    return f"unsupported version, skipped ({inner})"


def _skipped(previous: dict | None, now: dt.datetime, reason: str, error: str | None) -> dict:
    """The document of a scan that did not run: the previous findings, repos and hashes kept (only the
    findings' `age_days` is recomputed for `now`)."""
    previous = previous or {}
    generated_at = now.replace(microsecond=0).isoformat()
    kept = findings.refresh_ages([dict(f) for f in previous.get("findings") or [] if isinstance(f, dict)], now)
    return {"schema": store.SCHEMA, "generated_at": generated_at, "engine": {"name": None, "version": None},
            "rules_hash": previous.get("rules_hash"), "plugin_minor": previous.get("plugin_minor"),
            "scan": {"mode": "skipped", "repos": 0, "failed": [], "skipped_reason": reason, "error": error},
            "repos": previous.get("repos") or {}, "findings": kept}


def _stored_path(path: Path, cfg: config.Config, out: Path) -> str | None:
    """A repository's path for secrets.json, never absolute: relative to `out` for bare clones kept there,
    to the portfolio root for local projects, else None."""
    path = Path(path).resolve()
    for base in (out, cfg.root.resolve()):
        try:
            return path.relative_to(base).as_posix()
        except ValueError:
            continue
    return None


def _live_tips(path: Path, tips: list[str], current: list[str]) -> list[str]:
    """The previous tips that still exist (a force-push plus gc can remove one; `^<gone>` would fail).
    A tip that is still a ref tip exists; only the others are looked up."""
    live, now = [], set(current)
    for tip in tips:
        if tip in now:
            live.append(tip)
            continue
        try:
            gitio.git(path, "cat-file", "-e", f"{tip}^{{commit}}")
        except gitio.GitError:
            continue
        live.append(tip)
    return live


def _scan_repo(found: engine.Engine, repo, *, previous_tips: list[str] | None, ignore: Path, raw_dir: Path,
               key: bytes, classes: classify.Classes, now: dt.datetime) -> tuple[list[str], list[dict]]:
    """(tips, redacted findings) of one repository; tips are read before the engine runs."""
    tips = store.ref_tips(repo.path)
    since = _live_tips(repo.path, previous_tips, tips) if previous_tips else []
    log_opts = engine.log_opts_since(since) if since else engine.log_opts_full()
    rows = engine.scan_repo(found, repo.path, log_opts=log_opts, ignore_file=ignore, raw_dir=raw_dir)
    return tips, [findings.redact(row, repo_name=repo.name, repo=repo.path, key=key, classes=classes, now=now)
                  for row in rows]


def scan(cfg: config.Config, *, full: bool, log=None, now: dt.datetime | None = None, gh=None,
         git=None) -> dict:
    """Scan every repository in scope, merge with the previous document, write secrets.json, SECRETS.md,
    `reports/<date>-secrets.md` and one log.md line; return the document.

    A missing or unsupported engine, an unreadable decisions file or key gives a `skipped` document with
    the previous findings kept. A repository that fails keeps its previous findings and tips and is listed
    in `scan.failed`.
    """
    say = log or (lambda msg: None)
    out = cfg.out.resolve()
    now = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    generated_at = now.replace(microsecond=0).isoformat()
    previous = store.read(out)
    classes = classify.load_classes()

    found = engine.find_engine()
    if isinstance(found, engine.EngineProblem):
        return _write(out, _skipped(previous, now, _problem_reason(found), None), classes, say)
    try:
        decisions = store.read_decisions(out)
        key = findings.load_key(out)
    except ValueError as exc:                   # names the field or file, never a note or key material
        return _write(out, _skipped(previous, now, str(exc), str(exc)), classes, say)

    ignore = store.write_ignore_file(out, decisions)
    repos, failures = scope.all_repos(cfg, out, gh=gh or subprocess.run, git=git or subprocess.run, log=say)
    failed = [{"repo": str(f.get("repo")), "error": str(f.get("error"))} for f in failures]
    rules, minor = store.rules_hash(), store.plugin_minor()
    reason = "--full" if full else store.needs_full(previous, rules, minor)
    mode = "full" if reason else "incremental"
    say(f"secrets: {found.name} {found.version}, {len(repos)} repos, {mode}" + (f" ({reason})" if reason else ""))

    old_repos = (previous or {}).get("repos") or {}
    state: dict[str, dict] = {}
    new: list[dict] = []
    scanned: set[str] = set()
    for repo in repos:
        prev = old_repos.get(repo.name) if isinstance(old_repos.get(repo.name), dict) else None
        try:
            tips, rows = _scan_repo(found, repo, previous_tips=(prev or {}).get("tips") if mode == "incremental"
                                    else None, ignore=ignore, raw_dir=out / RAW_DIR, key=key, classes=classes,
                                    now=now)
        except (EngineError, ToolError) as exc:
            error = exc.detail
        except Exception as exc:                # never str(exc): git and engine messages may quote content
            error = type(exc).__name__
        else:
            new += rows
            scanned.add(repo.name)
            state[repo.name] = {"path": _stored_path(repo.path, cfg, out), "github": repo.github, "tips": tips,
                                "scanned_at": generated_at}
            continue
        failed.append({"repo": repo.name, "error": error})
        say(f"secrets: {repo.name} failed: {error}")
        if prev is not None:
            state[repo.name] = prev
    merged, dropped = store.merge(previous, new, decisions, mode=mode, today=now.date().isoformat(),
                                  scanned_repos=scanned)
    findings.refresh_ages(merged, now)
    if dropped:
        say(f"secrets: {dropped} open findings no longer found")
    doc = {"schema": store.SCHEMA, "generated_at": generated_at,
           "engine": {"name": found.name, "version": found.version}, "rules_hash": rules, "plugin_minor": minor,
           "scan": {"mode": mode, "repos": len(scanned), "failed": failed, "skipped_reason": None, "error": None},
           "repos": state, "findings": merged}
    return _write(out, doc, classes, say)


def _write(out: Path, doc: dict, classes: classify.Classes, say) -> dict:
    store.write(out, doc)
    secrets_report.write_secrets_md(out, doc, classes)
    secrets_report.write_dated_copy(out, doc["generated_at"][:10])
    audit_report.append_secrets_log(out, doc)
    say(summary(doc))
    return doc


def _open(doc: dict, cls: str) -> int:
    return sum(1 for f in doc.get("findings") or [] if f.get("status") == "open" and f.get("class") == cls)


def summary(doc: dict) -> str:
    scan_ = doc.get("scan") or {}
    counts = ", ".join(f"{_open(doc, cls)} {cls}" for cls in "ABC")
    if scan_.get("mode") == "skipped":
        head = f"secrets: {scan_.get('skipped_reason')}; previous findings kept ({counts} open)"
    else:
        head = f"secrets: {scan_.get('mode')}, {scan_.get('repos', 0)} repos, open {counts}"
    failed = scan_.get("failed") or []
    return head + (f", {len(failed)} repos failed" if failed else "") + f" — {secrets_report.SECRETS_FILE}"


def written_paths(out: Path, doc) -> list[Path]:
    """The files a scan writes for the run's commit (never the hand-confirmed decisions file)."""
    out = Path(out)
    paths = [out / store.SECRETS_JSON, out / secrets_report.SECRETS_FILE]
    day = str(doc.get("generated_at") or "")[:10] if isinstance(doc, dict) else ""
    if day:
        paths.append(secrets_report.dated_path(out, day))
    return [p for p in paths if p.is_file()]


def failed(doc: dict) -> bool:
    """A repository or the whole step failed (exit 2); a missing engine is a skip, not a failure."""
    scan_ = doc.get("scan") or {}
    return bool(scan_.get("failed") or scan_.get("error"))


# --------------------------------------------------------------------------- CLI

def cli_secrets(args) -> int:
    """`secrets scan | resolve | report` (see `secrets.cli`). A missing engine makes `secrets scan` write the
    skipped document (previous findings kept) and then exit 4."""
    from . import cli
    return cli.run(args)
