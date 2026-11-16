"""`hosts check | accept | bootstrap | unbootstrap | patch`.

Exit codes: 0 clean (or skipped: no audit key on this machine), 1 a host has an open critical finding,
2 a host failed, the arguments or the configuration were wrong, 5 read-only mode (every `hosts` subcommand,
checked in `cli.main` before anything else). `bootstrap` and `unbootstrap` (`admin`) validate the host name and
its `[hosts.servers]` entry before any ssh; `patch` does the same and takes `--include-docker`.

`--confirm <host>` is a safety gate (`refuse_confirm`): refused under the scheduler marker
`SBOM_AUDIT_SCHEDULED=1`, and refused unless it equals the host name exactly (no case folding, no stripping).
"""
from __future__ import annotations

import datetime as dt
import os
import sys
from pathlib import Path

from .. import config, issues, status
from . import checker, store

EXIT_CLEAN, EXIT_FINDINGS, EXIT_FAILED = 0, 1, 2


def _err(message: str) -> int:
    print(message, file=sys.stderr)
    return EXIT_FAILED


def _load(args) -> config.Config:
    return config.load(Path(args.out))


def _configured(cfg: config.Config) -> str | None:
    """Why `[hosts]` cannot be used, or None."""
    if not cfg.hosts.servers:
        return "no hosts configured: add servers under [hosts.servers.\"<name>\"] in sbom-audit.toml"
    return None


def _refresh_status(cfg: config.Config, result: dict) -> None:
    """Rebuild the hosts part of status.json and STATUS.md from this check, as the pipeline would.

    Only `counts.hosts`, `open.hosts_critical` and its delta change (`status.refresh_hosts`); projects, secrets,
    sources and run facts stay as the last `run` left them. A skipped check marks the previous document skipped
    (`pipeline._hosts_for_status`), the same as in a run. Without a status.json nothing is created: the first
    `run` makes it. Never raises: the check itself succeeded and keeps its exit code."""
    from .. import pipeline
    try:
        previous = status.read(cfg.out)
        if previous is None:
            print("hosts: status appears after the first `run` (no status.json yet)")
            return
        doc = status.refresh_hosts(previous, pipeline._hosts_for_status(cfg, result))
        status.write(cfg.out, doc)
        status.write_md(cfg.out, doc)
    except Exception as exc:                        # noqa: BLE001 - the type only, as everywhere in this module
        print(f"hosts: status not refreshed ({type(exc).__name__})", file=sys.stderr)
    _refresh_issues(cfg.out)


def _refresh_issues(out: Path) -> None:
    """Rebuild the work list after a check or a decision changed what is open on a host. The first `run`
    creates it; before that nothing is written."""
    if issues.read(out) is not None:
        issues.try_refresh(out, lambda line: print(line, file=sys.stderr))


def _check(args) -> int:
    from .. import hosts
    cfg = _load(args)
    problem = _configured(cfg)
    if problem is None and not cfg.hosts.enabled:
        problem = "[hosts] is disabled (enabled = false in sbom-audit.toml)"
    if problem:
        return _err(f"hosts check: {problem}")
    names = list(dict.fromkeys(args.hosts)) if args.hosts else None
    unknown = [n for n in names or [] if n not in cfg.hosts.servers]
    if unknown:                                     # before any ssh: a typo must not collect the others
        return _err(f"hosts check: unknown host(s), not in [hosts.servers]: {', '.join(unknown)}")
    try:
        doc = hosts.check(cfg, names, print)
    except Exception as exc:                        # the type only: a message can carry hosts, users or key paths
        return _err(f"hosts check: {type(exc).__name__}")
    if doc.get("skipped"):
        print(f"hosts: skipped: {doc['skipped']}")
        _refresh_status(cfg, doc)
        return EXIT_CLEAN
    failed, critical = checker.outcome(doc, names or list(cfg.hosts.servers))
    selected = names or list(cfg.hosts.servers)
    entries = doc.get("hosts") if isinstance(doc.get("hosts"), dict) else {}
    n_critical = sum(1 for n in selected if isinstance(entries.get(n), dict) and entries[n].get("critical"))
    print(f"hosts: {len(selected)} checked, {len(failed)} failed, {n_critical} critical; see {store.HOSTS_MD}")
    _refresh_status(cfg, doc)
    if failed:
        return EXIT_FAILED
    return EXIT_FINDINGS if critical else EXIT_CLEAN


def _review_by(value: str | None) -> str | None:
    """`YYYY-MM-DD` exactly, else ValueError."""
    if value is None:
        return None
    try:
        if dt.date.fromisoformat(value).isoformat() == value:
            return value
    except ValueError:
        pass
    raise ValueError("--review-by must be an ISO date (YYYY-MM-DD)")


def _accept(args) -> int:
    cfg = _load(args)
    try:
        review_by = _review_by(args.review_by)
    except ValueError as exc:
        return _err(f"hosts accept: {exc}")
    if not args.note.strip():
        return _err("hosts accept: a note is required: say why the finding is accepted")
    if args.host not in cfg.hosts.servers:
        return _err(f"hosts accept: unknown host {args.host!r}, not in [hosts.servers]")
    today = dt.datetime.now(dt.timezone.utc).date()
    try:
        written = store.accept(Path(args.out).resolve(), args.host, args.change_id, args.note, review_by, today)
    except ValueError as exc:                       # the store's messages name the problem, never the note
        return _err(f"hosts accept: {exc}")
    except OSError as exc:
        return _err(f"hosts accept: could not write ({type(exc).__name__})")
    print(f"recorded: {args.host} {args.change_id}")
    for path in written:
        print(f"wrote {path.name}")
    _refresh_issues(Path(args.out).resolve())
    return EXIT_CLEAN


def refuse_confirm(args, env=os.environ) -> str | None:
    """The refusal text when `--confirm` was given and either the scheduler marker is set or the value differs
    from the host name (exact comparison), else None."""
    confirm = getattr(args, "confirm", None)
    if confirm is None:
        return None
    if env.get("SBOM_AUDIT_SCHEDULED") == "1":
        return "--confirm is refused under the scheduler: an unattended run only collects"
    if confirm != args.host:
        return f"--confirm must equal the host name exactly ({args.host!r}): name the host the plan was shown for"
    return None


def _admin(args) -> int:
    """`bootstrap` / `unbootstrap` / `patch`: the host is validated (name, then `[hosts.servers]` membership) and the
    `--confirm` gate applied before `admin` runs anything, so a typo never reaches ssh."""
    from . import admin
    name = args.hosts_command
    cfg = _load(args)
    problem = _configured(cfg)
    if problem:
        return _err(f"hosts {name}: {problem}")
    try:
        store.check_host(args.host)
    except ValueError:
        return _err(f"hosts {name}: invalid host name")
    if args.host not in cfg.hosts.servers:
        return _err(f"hosts {name}: unknown host {args.host!r}, not in [hosts.servers]")
    refusal = refuse_confirm(args)
    if refusal:
        return _err(f"hosts {name}: {refusal}")
    try:
        if name == "patch":
            return admin.patch(cfg, args.host, args.confirm, bool(getattr(args, "include_docker", False)))
        return getattr(admin, name)(cfg, args.host, args.confirm)
    except Exception as exc:                        # the type only: a message can carry hosts, users or key paths
        return _err(f"hosts {name}: {type(exc).__name__}")


HANDLERS = {"check": _check, "accept": _accept, "bootstrap": _admin,
            "unbootstrap": _admin, "patch": _admin}


def run(args) -> int:
    return HANDLERS[args.hosts_command](args)
