"""`run` and `audit`: the pipeline from inventories to reports, with exit codes.

Exit codes: 0 clean, 1 findings present, 2 a source failed (a branch could not be scanned or
matched, or a database could not be reached), 3 an OpenVEX file could not be read, 4 a required
tool is missing (checked before anything is written). After the audit, `run` prunes stale sbom/ folders,
scans for secrets, refreshes the folder docs, writes status.json / STATUS.md and commits (and optionally
pushes) exactly the files it wrote. Of all that, only a failed secrets scan (a repository, the decisions
file or a crash of the step) changes the exit code, to 2; a missing secrets engine is reported as skipped
and changes nothing. The host step (`[hosts]` active) sets 2 for a failed host or a crash of the step, 1 for an
open critical host finding on an otherwise clean run, and changes nothing when skipped (no audit key here).
"""
from __future__ import annotations

import datetime as dt
import re
import socket
import time
from pathlib import Path

from . import assess, config, enrich, evidence, issues, matching, preflight, report, scan, scheduler, status, vex
from .cache import Cache
from .config import Config, Project
from .errors import VexError
from .model import BranchInventory

ENRICH_CACHE_DIR = Path(".cache") / "enrich"
EXIT_CLEAN, EXIT_FINDINGS, EXIT_SOURCE_FAILED, EXIT_VEX, EXIT_TOOL_MISSING = 0, 1, 2, 3, 4
STATUS_HINT = "no status.json yet: run /sbom-audit:setup, then /sbom-audit:run"


def secrets_step(cfg: Config, log) -> dict | None:
    """The incremental secrets scan (its document, written), or None when `[secrets] enabled = false`.

    None means "not scanned", which status.json reports as skipped, never as clean.
    """
    if not cfg.secrets.enabled:
        return None
    from . import secrets
    return secrets.scan(cfg, full=False, log=log)


def guard_refresh_step(cfg: Config, log) -> None:
    """Keep an installed pre-commit guard current after plugin updates (copies only on a version change)."""
    if not cfg.secrets.enabled:
        return
    from .secrets import guard
    cfg_dir = scheduler.config_dir()
    written = guard.refresh_installed(cfg_dir, scheduler.plugin_root())
    if written:
        log(f"guard: refreshed {', '.join(p.name for p in written)} in {cfg_dir}")


_PROPOSAL_DATE = re.compile(r"(\d{4}-\d{2}-\d{2})-assessment-proposal\.md$")


def _waiting_proposal(out: Path) -> str | None:
    """The previous status.json's proposal while it is still unreviewed: its file exists under `out` and its
    date (from the file name) is newer than the latest `## Assessment` heading of AUDIT.md. Else None."""
    try:
        prev = status.read(out)
        rel = prev.get("assessment_proposal") if isinstance(prev, dict) else None
        if not isinstance(rel, str) or not (Path(out) / rel).is_file():
            return None
        match = _PROPOSAL_DATE.search(rel)
        if not match:
            return None
        reviewed = status.last_assessment_date(out)
        return rel if reviewed is None or match.group(1) > reviewed else None
    except Exception:
        return None


def _record_secrets(out: Path, doc, rep: dict, written: list[Path]) -> bool:
    """Add the scan's files to `written`; a failed repository or step becomes the `secrets` source of `rep`.
    True when the scan failed (the run exits 2)."""
    from . import secrets
    written += secrets.written_paths(out, doc)
    scan_ = doc.get("scan") if isinstance(doc, dict) else None
    if not isinstance(scan_, dict) or not secrets.failed(doc):
        return False
    rep.setdefault("sources", {})["secrets"] = {
        "failed": [{"what": f.get("repo"), "error": f.get("error")} for f in scan_.get("failed") or []
                   if isinstance(f, dict)],
        "error": scan_.get("error")}
    return True


def hosts_step(cfg: Config, log) -> dict | None:
    """The host check (`hosts.check` over every configured server; its document, written), or None when
    `[hosts]` is not active. A skipped document (no audit key on this machine) is not a failure."""
    if not cfg.hosts.active:
        return None
    from . import hosts
    return hosts.check(cfg, None, log)


def _hosts_written(cfg: Config, doc: dict) -> list[Path]:
    """The files `hosts.check` wrote for this document, for the run's commit. A skipped run only appended
    to log.md (hosts.json and HOSTS.md stay as they were)."""
    from .hosts import store
    out = cfg.out.resolve()
    paths = [out / report.LOG_FILE]
    if doc.get("skipped"):
        return paths
    paths += [out / store.HOSTS_JSON, out / store.HOSTS_MD]
    try:
        day = dt.date.fromisoformat(str(doc.get("generated_at"))[:10]).isoformat()
        paths.append(out / report.REPORTS_DIR / f"{day}-hosts.md")
    except ValueError:
        pass
    for name in cfg.hosts.servers:
        try:
            path = store.baseline_path(out, name)
        except ValueError:
            continue
        if path.exists():
            paths.append(path)
    return paths


def _record_hosts(cfg: Config, doc: dict, rep: dict, written: list[Path], code: int) -> int:
    """Add the check's files to `written`, record skipped or failed hosts as the `hosts` source of `rep`
    and return the exit code: 2 when a host failed (unreachable, changed host key, unknown status or no
    result: never clean), 1 when a host has an open critical finding and the run was clean, else `code`."""
    from .hosts import checker
    written += _hosts_written(cfg, doc)
    sources = rep.setdefault("sources", {})
    if doc.get("skipped"):
        sources["hosts"] = {"skipped": str(doc["skipped"])}
        return code
    failed, critical = checker.outcome(doc, list(cfg.hosts.servers))
    if failed:
        sources["hosts"] = {"failed": failed}
        return EXIT_SOURCE_FAILED
    return EXIT_FINDINGS if critical and code == EXIT_CLEAN else code


# `read_scheduler_state(out) -> dict | None`: the scheduler's state for `status` (looked up at call time,
# so tests can replace it).
read_scheduler_state = scheduler.read_state


def purl_of(cfg: Config, inventories: list[BranchInventory]) -> dict[str, str]:
    """Project name -> OpenVEX product purl; projects not under root fall back to pkg:generic."""
    mapping = {p.name: config.project_purl(p) for p in config.discover(cfg)}
    for inv in inventories:
        mapping.setdefault(inv.project, config.project_purl(Project(name=inv.project, path=cfg.root / inv.project)))
    return mapping


def audit(cfg: Config, inventories: list[BranchInventory], log=None,
          http=None) -> tuple[dict, list[Path]]:
    """Match, enrich, apply VEX and write every report; returns the report and the paths written.

    Raises VexError before any matching.

    `http(url) -> obj` serves every database lookup (default: enrich.http_get_json, resolved at call time).
    """
    say = log or (lambda msg: None)
    http = http or enrich.http_get_json
    statements = vex.load_all(cfg.out)          # VexError propagates: never audit around a broken decision file
    findings, sources = matching.match_all(inventories, cfg.out, log=say)
    git_failed = [(inv.project, inv.branch, err) for inv in inventories for err in inv.errors
                  if err.startswith("git:")]
    if git_failed:                              # named under Source status: those branches were never read
        sources = {"git": {"branches": len(inventories), "failed": git_failed}, **sources}

    cache = Cache(cfg.out / ENRICH_CACHE_DIR)
    say("CISA KEV …")
    kev_ids, kev_error = enrich.load_kev(cache, http)
    sources["cisa_kev"] = {"loaded": len(kev_ids), "flagged": enrich.mark_kev(findings, kev_ids),
                           "error": kev_error}
    say("endoflife.date …")
    eol_rows, eol_failed = enrich.eol(inventories, cache, http)
    sources["endoflife"] = {"queried": len({(r["product"], r["cycle"]) for r in eol_rows if r["cycle"]}),
                            "unknown": sum(1 for r in eol_rows if r["status"] == "unknown"),
                            "failed": eol_failed}
    say("registries …")
    direct = {(c.ecosystem, c.name) for inv in inventories for c in inv.components
              if c.kind == "package" and c.direct and c.ecosystem in enrich.LATEST_ECOSYSTEMS and c.version}
    latest_rows, latest_failed = enrich.latest(inventories, cache, http)
    sources["registries"] = {"queried": len(direct), "major_behind": len(latest_rows), "failed": latest_failed}

    kept, suppressed = vex.apply(findings, statements, purl_of=purl_of(cfg, inventories))
    sources["openvex"] = {"statements": len(statements), "suppressed": len(suppressed)}

    rep = report.build(cfg, inventories, kept, suppressed, eol_rows, latest_rows, sources)
    written = [report.write_json(rep, cfg.out),
               report.write_inventory_md(cfg, inventories, cfg.out),
               report.write_audit_md(rep, cfg.out),
               report.write_dated_copy(cfg.out),
               report.append_log(cfg.out, rep, inventories)]
    return rep, written


def exit_code(rep: dict, inventories: list[BranchInventory]) -> int:
    failed = any(inv.errors for inv in inventories)
    for info in rep.get("sources", {}).values():
        if info.get("error") or info.get("failed"):
            failed = True
    if failed:
        return EXIT_SOURCE_FAILED
    if rep["vulnerabilities"] or any(r["status"] == "EOL" for r in rep["runtimes"]):
        return EXIT_FINDINGS
    return EXIT_CLEAN


def summary_line(rep: dict, cfg: Config, started: float) -> str:
    s = rep["stats"]
    vulns = rep["vulnerabilities"]
    kev = sum(1 for v in vulns if v["kev"])
    crit_high = sum(1 for v in vulns if v["max_severity"] in ("CRITICAL", "HIGH"))
    eol = sum(1 for r in rep["runtimes"] if r["status"] == "EOL")
    return (f"{s['projects']} projects, {s['branches']} branches: {len(vulns)} vulnerable package versions "
            f"({kev} KEV, {crit_high} critical/high), {eol} EOL runtimes/images, "
            f"{len(rep['suppressed'])} suppressed by VEX — {cfg.out / report.AUDIT_FILE} "
            f"({time.monotonic() - started:.1f}s)")


def tools_missing(tools, say) -> bool:
    """Say which required tools are absent (plus the install line); True when any is."""
    missing = preflight.check(tools=tools)
    if missing:
        say(preflight.message(missing))
    return bool(missing)


NOT_OWN_REPO = "security/ is not its own git repository (setup --init-git)"


def _prune(cfg: Config, inventories: list[BranchInventory], say) -> list[str]:
    """Remove sbom/<name>/ for projects neither configured, discovered nor scanned in this run.

    Nothing is pruned when discovery finds no project (a wrong root must not delete evidence), and a
    folder holding anything but `*.cdx.json` files is kept (a hand-placed file is never deleted).
    """
    discovered = {p.name for p in config.discover(cfg)}
    if not discovered:
        say("pruning skipped: no projects discovered")
        return []
    keep = set(cfg.projects) | discovered | {inv.project for inv in inventories}
    root = cfg.out / "sbom"
    if root.is_dir() and not root.is_symlink():
        for child in sorted(root.iterdir()):
            if (child.name not in keep and child.is_dir() and not child.is_symlink()
                    and not evidence.holds_only_sboms(child)):
                say(f"pruning skipped sbom/{child.name}: unexpected files")
                keep.add(child.name)
    removed = evidence.prune_sbom_dirs(cfg.out, keep)
    for name in removed:
        say(f"removed sbom/{name}")
        report.append_note(cfg.out, f"removed sbom/{name}")
    return removed


def _expected_commit(cfg: Config, own: bool) -> dict:
    """What the status files say about the commit they are part of (written before it is made)."""
    if not cfg.commit:
        return {"status": "skipped", "sha": None, "detail": "commit = false"}
    if cfg.mode != "portfolio":
        return {"status": "skipped", "sha": None, "detail": "single-repo mode"}
    if not own:
        return {"status": "skipped", "sha": None, "detail": NOT_OWN_REPO}
    return {"status": "committed", "sha": None, "detail": "this commit"}


def _expected_push(cfg: Config, own: bool, visibility: str, commit: dict) -> dict:
    """The push outcome knowable before pushing; only `pushed` means push_run will be called."""
    if not cfg.push:
        return {"status": "off", "detail": ""}
    if cfg.mode != "portfolio":
        return {"status": "skipped", "detail": "single-repo mode"}
    if not own:
        return {"status": "skipped", "detail": NOT_OWN_REPO}
    if visibility == "public":
        return {"status": "refused_public", "detail": evidence.PUBLIC_REFUSAL}
    if commit["status"] != "committed":
        return {"status": "skipped", "detail": "no commit this run"}
    if not evidence.has_upstream(cfg.out):
        return {"status": "skipped", "detail": "no upstream"}
    return {"status": "pushed", "sha": None, "detail": "this commit"}


def _do_commit(cfg: Config, expected: dict, doc: dict, written: list[Path], say) -> dict:
    """Run the commit when one is expected; return the commit entry the status files should carry."""
    if expected["status"] != "committed":
        say(f"commit: {expected['status']} ({expected['detail']})")
        return expected
    try:
        res = evidence.commit_run(cfg.out, written, evidence.subject_line(doc), evidence.body_line(doc))
        status_, sha, detail = res.status, res.sha, res.detail
    except Exception as exc:                    # commit trouble is reported, never fatal
        status_, sha, detail = "failed", None, type(exc).__name__
    if status_ == "committed":
        say(f"committed {sha}")
        return expected                         # the sha never goes into the files it is the hash of
    say(f"commit: {status_} ({detail})")
    return {**expected, "status": status_, "detail": detail}


def _do_push(cfg: Config, expected: dict, commit_status: str, visibility: str, say) -> dict:
    """Push after a commit this run (`this commit`) or an empty one (`earlier commits`, a retry)."""
    detail = expected.get("detail", "")
    if expected["status"] != "pushed":
        actual = expected
    elif commit_status not in ("committed", "nothing"):
        actual = {"status": "skipped", "detail": "no commit this run"}
        detail = actual["detail"]
    else:
        try:
            res = evidence.push_run(cfg.out, visibility)
        except Exception as exc:
            res = {"status": "failed", "detail": type(exc).__name__}
        detail = res.get("detail", "")
        if res.get("status") == "pushed":
            actual = expected if commit_status == "committed" else {**expected, "detail": "earlier commits"}
        else:
            actual = {"status": res.get("status"), "detail": detail}
    say(f"push: {actual['status']}" + (f" ({detail})" if detail else ""))
    return actual


def finish(cfg: Config, rep: dict, inventories: list[BranchInventory], written: list[Path],
           code: int, started: float, say) -> dict:
    """Everything after the audit: pruning, secrets, optional headless assessment, folder docs, status, commit, push.

    The status files are written once, before the commit, with the expected commit and push outcome,
    so a successful run leaves a clean tree; they are rewritten only when an outcome differs (and the
    next run commits the correction). Returns the final status document, whose `exit_code` is `code`, or
    2 when the secrets scan failed (`run` also guards the call). Secrets run after pruning so prune notes
    stay on the run's own log.md line.
    """
    out = cfg.out.resolve()
    written = [Path(p) if Path(p).is_absolute() else out / p for p in written]
    written.append(out / scan.INVENTORY_FILE)
    written += [out / inv.sbom_path for inv in inventories if inv.sbom_path]
    try:
        written += [out / "sbom" / name for name in _prune(cfg, inventories, say)]
    except Exception as exc:
        say(f"pruning skipped: {type(exc).__name__}")
    try:
        secrets = secrets_step(cfg, say)
    except Exception as exc:                    # never str(exc): an engine message may quote a match
        say(f"secrets: {type(exc).__name__} (scan skipped)")
        secrets = None
        if cfg.secrets.enabled:                 # the step failed, which is not the same as "not scanned"
            rep.setdefault("sources", {})["secrets"] = {"error": type(exc).__name__, "failed": []}
            code = EXIT_SOURCE_FAILED
    if secrets is not None:
        try:
            if _record_secrets(out, secrets, rep, written):
                code = EXIT_SOURCE_FAILED
        except Exception as exc:
            say(f"secrets: {type(exc).__name__} in the scan result")
    hosts_result = None
    try:
        hosts_result = hosts_step(cfg, say)
        if hosts_result is not None:
            code = _record_hosts(cfg, hosts_result, rep, written, code)
    except Exception as exc:                    # the type only: a message can carry hosts, users or key paths
        say(f"hosts: {type(exc).__name__} (step skipped)")
        hosts_result = None
        written += _hosts_written(cfg, {})      # what hosts.check wrote before it crashed still goes into the commit
        rep.setdefault("sources", {})["hosts"] = {"error": type(exc).__name__, "failed": []}
        code = EXIT_SOURCE_FAILED
    try:
        guard_refresh_step(cfg, say)
    except Exception as exc:                    # never changes the exit code
        say(f"guard refresh skipped: {type(exc).__name__}")
    try:
        written += evidence.write_folder_docs(out)
    except Exception as exc:
        say(f"folder docs skipped: {type(exc).__name__}")
    proposal = None
    if cfg.schedule.assess:
        try:                                    # never changes the exit code; never echoes the proposal
            if cfg.assess.configured:           # [assess] endpoint instead of `claude -p`
                from . import draft
                res = draft.run(cfg, out)
            else:
                res = assess.run_headless(cfg, out, scheduler.plugin_root())
            if res["status"] == "written":
                proposal = res["path"]
                written.append(out / proposal)
                written.append(report.append_assess_log(out, proposal, res.get("cost_usd")))
                via = f" (model {res['model']})" if res.get("model") else ""
                say(f"assess: proposal written to {proposal}{via}")
            else:
                say(f"assess: {res['status']} ({res.get('reason') or 'no reason'})")
        except Exception as exc:
            say(f"assess: {type(exc).__name__} (assessment skipped)")
    if proposal is None:
        proposal = _waiting_proposal(out)
    own = cfg.mode == "portfolio" and evidence.is_own_repo(out)
    visibility = evidence.remote_visibility(out) if own else "unknown"
    status_paths = [out / status.STATUS_JSON, out / status.STATUS_FILE]
    pending = (evidence.pending_hand_edits(out, set(written + status_paths))
               if own or cfg.mode == "single" else [])
    expected_commit = {**_expected_commit(cfg, own), "pending_hand_edits": pending}
    expected_push = _expected_push(cfg, own, visibility, expected_commit)

    hosts_doc = _hosts_for_status(cfg, hosts_result)

    def build(secrets_doc):
        return status.build(
            rep, secrets=secrets_doc, previous=status.read(out),
            duration_s=round(time.monotonic() - started, 1), exit_code=code, run_host=socket.gethostname(),
            mode=cfg.mode, commit=expected_commit, push=expected_push, visibility=visibility,
            last_assessment=status.last_assessment_date(out), proposal=proposal, hosts=hosts_doc)
    try:
        doc = build(secrets)
    except Exception as exc:
        if secrets is None:
            raise
        say(f"secrets: {type(exc).__name__} in the scan result (reported as skipped)")
        doc = build(None)
    written += [status.write(out, doc), status.write_md(out, doc)]
    written += issues.try_refresh(out, say, hosts_active=hosts_doc is not None)
    commit = _do_commit(cfg, doc["commit"], doc, written, say)
    push = _do_push(cfg, doc["push"], commit["status"], visibility, say)
    if commit != doc["commit"] or push != doc["push"]:
        doc = {**doc, "commit": commit, "push": push}
        status.write(out, doc)
        status.write_md(out, doc)
    say((out / status.STATUS_FILE).read_text(encoding="utf-8").rstrip("\n"))
    return doc


def _hosts_for_status(cfg: Config, result: dict | None = None) -> dict | None:
    """The `hosts.json` document for status, only when `[hosts]` is active (else None: no host line anywhere).

    `result` is what `hosts.check` returned this run, and it alone decides whether the step was skipped:
    a skipped result marks the previous `hosts.json` (kept as it was) skipped; a fresh result is used as
    returned. Without a result (the step crashed) the previous `hosts.json` stands.
    A missing or corrupt `hosts.json` reads as `{}`, which status reports as "hosts not checked since never".
    A configured server without an entry (or any server when `hosts` is not a dict) counts as failed."""
    if not cfg.hosts.active:
        return None
    from .hosts import store
    try:
        previous = store.read(cfg.out) or {}
    except Exception:                           # never breaks the run's own status
        previous = {}
    if isinstance(result, dict) and not result.get("skipped"):
        doc = result
    elif isinstance(result, dict):
        doc = {**previous, "skipped": result["skipped"]}
    else:
        doc = previous
    entries = doc.get("hosts") if isinstance(doc.get("hosts"), dict) else {}
    # fail closed: a configured server the document does not know counts as failed, never as clean
    missing = {n: {"status": "failed", "error": "no entry in hosts.json"}
               for n in cfg.hosts.servers if n not in entries}
    return {**doc, "hosts": {**entries, **missing}}


def _write_failed_status(cfg: Config, exc: Exception, started: float, say) -> None:
    """status.json and STATUS.md for a run that stopped before the audit: exit 2, the error as a failed
    source, nothing committed. Never raises."""
    rep = {**status.empty_report(), "sources": {"run": {"error": f"{type(exc).__name__}: {exc}"}}}
    try:
        previous = status.read(cfg.out)
        doc = status.build(rep, secrets=None, previous=None,
                           duration_s=round(time.monotonic() - started, 1), exit_code=EXIT_SOURCE_FAILED,
                           run_host=socket.gethostname(), mode=cfg.mode,
                           commit={"status": "skipped", "sha": None, "detail": "run failed before the audit"},
                           last_assessment=status.last_assessment_date(cfg.out))
        if previous and previous.get("schema") == status.SCHEMA:
            # nothing was read: keep the last known open sets and counts so the next run's deltas stay right
            doc.update(open=previous.get("open") or doc["open"], counts=previous.get("counts") or doc["counts"],
                       first_run=False)
        status.write(cfg.out, doc)
        status.write_md(cfg.out, doc)
    except Exception as inner:
        say(f"failed status not written: {type(inner).__name__}")


def run(cfg: Config, only: list[str] | None = None, fetch: bool | None = None, log=None,
        http=None) -> int:
    """scan + audit + status + commit. Returns the audit exit code; prints progress through `log`."""
    say = log or (lambda msg: None)
    started = time.monotonic()
    if tools_missing(preflight.RUN_TOOLS, say):
        return EXIT_TOOL_MISSING
    try:
        vex.load_all(cfg.out)
    except VexError as exc:
        say(f"OpenVEX: {exc}")
        return EXIT_VEX
    try:
        result = scan.scan(cfg, only=only, fetch=fetch, log=say)
        for s in result.skipped:
            say(f"skipped {s['project']}: {s['reason']}")
        rep, written = audit(cfg, result.inventories, log=say, http=http)
    except VexError as exc:
        say(f"OpenVEX: {exc}")
        return EXIT_VEX
    except Exception as exc:                    # last resort: never leave the previous STATUS.md as current
        say(f"run failed: {type(exc).__name__}: {exc}")
        _write_failed_status(cfg, exc, started, say)
        return EXIT_SOURCE_FAILED
    say(summary_line(rep, cfg, started))
    code = exit_code(rep, result.inventories)
    try:
        code = finish(cfg, rep, result.inventories, written, code, started, say)["exit_code"]
    except Exception as exc:                    # the exit code is the audit's, whatever happens after it
        say(f"finish failed: {type(exc).__name__}")
    return code


def cli_run(args) -> int:
    cfg = config.load(args.out, root=args.root)
    if not config.discover(cfg):                # an empty portfolio is not a clean one
        print(f"no git repository found under {cfg.root}: start Claude Code in the folder that holds your "
              f"repositories (or inside one), or check ignore_projects in {config.CONFIG_NAME}")
        return EXIT_SOURCE_FAILED
    return run(cfg, only=args.only, fetch=args.fetch, log=print)


def cli_status(args) -> int:
    """Render status.json against the current time and scheduler state and print it; writes nothing.

    Exit 2 with a hint when no run (or setup) has written status.json yet.
    """
    out = Path(args.out).resolve()
    doc = status.read(out)
    if doc is None:
        print(STATUS_HINT)
        return EXIT_SOURCE_FAILED
    try:
        text = status.render_md(doc, read_scheduler_state(out), dt.datetime.now().astimezone())
    except (KeyError, TypeError, ValueError, AttributeError):
        print(f"{out / status.STATUS_JSON} unreadable: run /sbom-audit:run")
        return EXIT_SOURCE_FAILED
    print(text, end="")
    return EXIT_CLEAN


def cli_audit(args) -> int:
    cfg = config.load(args.out, root=args.root)
    started = time.monotonic()
    if tools_missing(preflight.AUDIT_TOOLS, print):
        return EXIT_TOOL_MISSING
    try:
        inventories, _ = scan.read_inventory(cfg.out)
    except FileNotFoundError:
        print(f"{cfg.out / scan.INVENTORY_FILE} not found: run `scan` (or `run`) first.")
        return EXIT_SOURCE_FAILED
    try:
        rep, _ = audit(cfg, inventories, log=print)
    except VexError as exc:
        print(f"OpenVEX: {exc}")
        return EXIT_VEX
    print(summary_line(rep, cfg, started))
    return exit_code(rep, inventories)
