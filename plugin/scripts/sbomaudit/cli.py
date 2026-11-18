"""Command-line entry point: python3 scripts/sbom_audit_cli.py <command> [...]"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, config
from .errors import ConfigError

COMMANDS = ("setup", "run", "scan", "audit", "lookup", "incident", "vex", "status", "issues", "secrets", "hosts", "code", "settings",
            "assess", "report", "cra", "releases", "import", "sbom")
WRITING_COMMANDS = ("setup", "run", "scan", "audit", "vex", "issues", "secrets", "hosts", "assess", "report", "cra",
                    "import")
EXIT_READ_ONLY = 5
SECRETS_STATUSES = ("open", "rotated", "false_positive", "test_fixture", "accepted")  # = secrets.store.STATUSES


def find_out(start: Path) -> Path:
    """Nearest `security/` directory walking up from `start`, else `start/security`."""
    start = start.resolve()
    for folder in (start, *start.parents):
        candidate = folder / "security"
        if candidate.is_dir():
            return candidate
    return start / "security"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sbom-audit",
        description="Portfolio SBOMs, vulnerability audit and OpenVEX decisions for a folder of git repos.",
    )
    parser.add_argument("--version", action="version", version=f"sbom-audit {__version__}")
    parser.add_argument("--out", type=Path, default=None,
                        help="security/ output folder (default: nearest security/ above cwd, else ./security)")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--out", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", metavar="command")
    sub.required = True
    setup_p = sub.add_parser("setup", parents=[common], help="preflight, discover projects, write config")
    setup_p.add_argument("--root", type=Path, default=None, help="folder of projects (default: parent of --out)")
    setup_p.add_argument("--init-git", action="store_true",
                         help="portfolio mode: make security/ its own git repository")
    setup_p.add_argument("--enable-dependabot", nargs="?", const="alerts", choices=("alerts", "fixes"),
                         default=None, metavar="{alerts,fixes}",
                         help="Dependabot on every GitHub repository: alerts (default) or fixes (alerts + "
                              "security updates); lists the repositories first, acts only with --yes")
    setup_p.add_argument("--yes", action="store_true",
                         help="with --enable-dependabot: confirm the listed repositories and enable")
    setup_p.add_argument("--schedule", choices=("weekly", "off"), default=None,
                         help="weekly: install a per-user timer (launchd / systemd) that runs `run` every Saturday "
                              "03:00; off: remove it")
    guard = setup_p.add_mutually_exclusive_group()
    guard.add_argument("--install-guard", action="store_true",
                       help="install the pre-commit secrets guard in every local repository (untracked "
                            ".git/hooks/pre-commit; tracked hook files only with --tracked-ok)")
    guard.add_argument("--uninstall-guard", action="store_true",
                       help="remove the guard hook and restore a chained pre-commit.local")
    setup_p.add_argument("--tracked-ok", nargs="+", metavar="NAME", default=[],
                         help="with --install-guard: repositories whose tracked hook file (husky, lefthook, "
                              "pre-commit) the user confirmed may be edited")
    run_p = sub.add_parser("run", parents=[common], help="scan + audit + report")
    add_scan_args(run_p)
    scan_p = sub.add_parser("scan", parents=[common],
                            help="write CycloneDX SBOMs per project and branch")
    add_scan_args(scan_p)
    audit_p = sub.add_parser("audit", parents=[common],
                             help="match, enrich, apply VEX and write reports from existing SBOMs")
    audit_p.add_argument("--root", type=Path, default=None, help="folder of projects (default: parent of --out)")
    lookup_p = sub.add_parser("lookup", parents=[common], help="which project uses a package, image or runtime")
    lookup_p.add_argument("names", nargs="+", metavar="NAME",
                          help="package name, glob (expo-*), image (nginx:alpine) or runtime (nodejs)")
    inc_p = sub.add_parser("incident", parents=[common], help="are we affected by a CVE / advisory / package")
    inc_p.add_argument("ident", metavar="ID", help="CVE-…, GHSA-…, PYSEC-…, or a package name")
    inc_p.add_argument("--vex", action="store_true",
                       help="record not_affected/component_not_present for every project without the component")
    inc_p.add_argument("--author", default=None, help="OpenVEX author for --vex (default: git user.email)")
    vex_p = sub.add_parser("vex", parents=[common], help="record an OpenVEX decision")
    add_vex_args(vex_p, common)
    sub.add_parser("status", parents=[common], help="print STATUS.md from the last run (writes nothing)")
    rel_p = sub.add_parser("releases", parents=[common],
                           help="releases under audit from releases.json: support status, open counts, and with "
                                "--fixed the advisories no longer present compared with the previous release "
                                "(writes nothing)")
    rel_p.add_argument("--project", default=None, help="only this project")
    rel_p.add_argument("--fixed", default=None, metavar="TAG",
                       help="with --project: advisories no longer present in the SBOM of TAG compared with the "
                            "previous release under audit")
    rel_p.add_argument("--json", action="store_true", help="print JSON instead of text")
    issues_p = sub.add_parser("issues", parents=[common],
                              help="rebuild issues.json and ISSUES.md (every open issue and where it occurs); "
                                   "with a filter or --json, print the selected issues and write nothing")
    issues_p.add_argument("--project", default=None, help="only this project (and the hosts that run it)")
    issues_p.add_argument("--host", default=None, help="only this host")
    issues_p.add_argument("--kind", default=None, choices=("secret", "vulnerability", "eol", "floating_tag", "host"))
    issues_p.add_argument("--max-priority", type=int, default=None, choices=range(1, 7), metavar="1-6",
                          help="only issues of this priority or more urgent (1 is the most urgent)")
    issues_p.add_argument("--json", action="store_true", help="print the selection as JSON instead of one line each")
    report_p = sub.add_parser("report", parents=[common],
                              help="rebuild REPORT.html, the printable management report, from the JSON of the "
                                   "last run (no scan)")
    report_p.add_argument("--lang", default=None, choices=("en", "de"),
                          help="report language (default: [report] language in the config, else en)")
    secrets_p = sub.add_parser("secrets", parents=[common],
                               help="scan git history for leaked credentials (gitleaks), record decisions")
    add_secrets_args(secrets_p, common)
    code_p = sub.add_parser("code", parents=[common],
                            help="read a project's committed code on an audited branch (grep, show, files; writes nothing)")
    add_code_args(code_p, common)
    settings_p = sub.add_parser("settings", parents=[common],
                                help="opt-in Claude Code integration in ~/.claude/settings.json: autonomous mode "
                                     "and the session status hook (no flag: show what is on)")
    settings_p.add_argument("--autonomy", choices=("on", "off"), default=None,
                            help="on: allow this plugin's local and read-only commands and the advisory "
                                 "WebFetch domains without asking (never setup or host changes)")
    settings_p.add_argument("--session-hook", choices=("on", "off"), default=None,
                            help="on: one status line at session start from security/status.json")
    hosts_p = sub.add_parser("hosts", parents=[common],
                             help="read-only audit of servers over ssh: check, accept, bootstrap, patch")
    add_hosts_args(hosts_p, common)
    assess_p = sub.add_parser("assess", parents=[common],
                              help="assessment proposal by an OpenAI-compatible endpoint ([assess] in the config)")
    assess_sub = assess_p.add_subparsers(dest="assess_command", metavar="action")
    assess_sub.required = True
    draft_p = assess_sub.add_parser("draft", parents=[common],
                                    help="send report excerpts, write reports/<date>-assessment-proposal.md "
                                         "(records no decision)")
    draft_p.add_argument("--dry-run", action="store_true",
                         help="print the request body (no key) and exit; sends and writes nothing")
    add_import_args(sub.add_parser("import", parents=[common],
                                   help="use a CycloneDX JSON build SBOM as the package list of a project branch or "
                                        "release tag (validates it, copies it to imports/, records provenance)"))
    add_cra_args(sub.add_parser("cra", parents=[common],
                                help="EU Cyber Resilience Act readiness per configured product ([cra.products]): "
                                     "evidence present, missing or stale; starter documents"), common)
    add_sbom_args(sub.add_parser("sbom", parents=[common],
                                 help="SBOM quality: structural check and data-field coverage (writes nothing)"),
                  common)
    return parser


def add_sbom_args(p: argparse.ArgumentParser, common: argparse.ArgumentParser) -> None:
    sbom_sub = p.add_subparsers(dest="sbom_command", metavar="action")
    sbom_sub.required = True
    check_p = sbom_sub.add_parser("check", parents=[common],
                                  help="structural findings and data-field coverage of CycloneDX JSON SBOMs (default: "
                                       "every SBOM under sbom/); exit 1 on structural errors, 2 when unreadable")
    check_p.add_argument("path", nargs="?", type=Path, default=None, help="one CycloneDX JSON file")
    check_p.add_argument("--project", default=None, help="the SBOMs of this project under sbom/")
    check_p.add_argument("--branch", default=None, help="with --project: only this branch or release label")
    check_p.add_argument("--json", action="store_true", help="print JSON instead of text")


def add_cra_args(p: argparse.ArgumentParser, common: argparse.ArgumentParser) -> None:
    cra_sub = p.add_subparsers(dest="cra_command", metavar="action")
    cra_sub.required = True
    cra_sub.add_parser("check", parents=[common],
                       help="check the evidence for every configured product, write CRA.md and cra.json")
    init_p = cra_sub.add_parser("init", parents=[common],
                                help="starter documents for one product in cra/<product>/ (plan without --yes; "
                                     "never writes into the product repository, never overwrites)")
    init_p.add_argument("product", help="a project listed under [cra.products]")
    init_p.add_argument("--lang", default=None, choices=("en", "de"),
                        help="template language (default: [report] language in the config, else en)")
    init_p.add_argument("--yes", action="store_true", help="write the planned files (after the user confirmed)")


def add_import_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--root", type=Path, default=None, help="folder of projects (default: parent of --out)")
    p.add_argument("--project", required=True, help="project folder name")
    ref = p.add_mutually_exclusive_group(required=True)
    ref.add_argument("--branch", default=None, help="an audited branch")
    ref.add_argument("--tag", default=None, help="a release tag")
    p.add_argument("--commit", default=None, metavar="SHA",
                   help="the commit the SBOM was built from (default: the current commit of the branch or tag)")
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path, default=None, help="CycloneDX JSON file from the build")
    source.add_argument("--from-artifact", default=None, metavar="PATH_OR_IMAGE",
                        help="generate the SBOM with Syft from a built artefact (JAR, WAR, folder or image)")


def add_code_args(p: argparse.ArgumentParser, common: argparse.ArgumentParser) -> None:
    code_sub = p.add_subparsers(dest="code_command", metavar="action")
    code_sub.required = True
    grep_p = code_sub.add_parser("grep", parents=[common], help="search the branch's tree (extended regex)")
    grep_p.add_argument("project")
    grep_p.add_argument("branch")
    grep_p.add_argument("pattern")
    grep_p.add_argument("--path", action="append", default=[], help="limit to a repository path (repeatable)")
    grep_p.add_argument("-i", "--ignore-case", action="store_true")
    show_p = code_sub.add_parser("show", parents=[common], help="print one file from the branch, numbered")
    show_p.add_argument("project")
    show_p.add_argument("branch")
    show_p.add_argument("path")
    show_p.add_argument("--lines", default=None, metavar="N-M", help="only lines N to M")
    files_p = code_sub.add_parser("files", parents=[common], help="list files on the branch")
    files_p.add_argument("project")
    files_p.add_argument("branch")
    files_p.add_argument("path", nargs="?", default=None)


def add_scan_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--root", type=Path, default=None,
                   help="folder of projects (default: parent of --out)")
    p.add_argument("--only", nargs="+", metavar="PROJECT", default=None,
                   help="scan only these project folders")
    fetch = p.add_mutually_exclusive_group()
    fetch.add_argument("--fetch", dest="fetch", action="store_true", default=None,
                       help="git fetch origin before reading (config default: fetch = true)")
    fetch.add_argument("--no-fetch", dest="fetch", action="store_false",
                       help="read local refs only")


def add_vex_args(p: argparse.ArgumentParser, common: argparse.ArgumentParser) -> None:
    vex_sub = p.add_subparsers(dest="vex_command", metavar="subcommand")
    vex_sub.required = True
    add_p = vex_sub.add_parser("add", parents=[common], help="append an OpenVEX statement for a project")
    add_p.add_argument("project", help="project folder name")
    add_p.add_argument("vuln", help="vulnerability id (CVE-..., GHSA-..., ...)")
    add_p.add_argument("status", choices=("not_affected", "affected", "fixed", "under_investigation"))
    add_p.add_argument("--justification", default=None,
                       help="required for not_affected: component_not_present, vulnerable_code_not_present, "
                            "vulnerable_code_not_in_execute_path, "
                            "vulnerable_code_cannot_be_controlled_by_adversary, inline_mitigations_already_exist")
    add_p.add_argument("--impact", default=None, help="free-text impact statement")
    add_p.add_argument("--subcomponent", default=None, help="package purl, with or without version")
    add_p.add_argument("--author", default=None, help="document author (default: git user.email)")


def add_secrets_args(p: argparse.ArgumentParser, common: argparse.ArgumentParser) -> None:
    secrets_sub = p.add_subparsers(dest="secrets_command", metavar="subcommand")
    secrets_sub.required = True
    scan_p = secrets_sub.add_parser("scan", parents=[common],
                                    help="scan every repository's history; write secrets.json and SECRETS.md "
                                         "(no gitleaks: writes the skipped document, previous findings kept, "
                                         "then exits 4)")
    scan_p.add_argument("--root", type=Path, default=None, help="folder of projects (default: parent of --out)")
    scan_p.add_argument("--full", action="store_true",
                        help="rescan all history (default: only commits since the last scan)")
    resolve_p = secrets_sub.add_parser("resolve", parents=[common],
                                       help="record a decision for one finding (the user confirms it first)")
    resolve_p.add_argument("fingerprint", help="the finding's fingerprint from SECRETS.md or secrets.json")
    resolve_p.add_argument("status", choices=SECRETS_STATUSES)
    resolve_p.add_argument("note", help="why: what was rotated, why it is a false positive or accepted")
    resolve_p.add_argument("--rotated-on", default=None, metavar="YYYY-MM-DD",
                           help="with status rotated: the day the credential was rotated (default: today)")
    secrets_sub.add_parser("report", parents=[common],
                           help="print SECRETS.md from secrets.json (writes nothing)")


def add_hosts_args(p: argparse.ArgumentParser, common: argparse.ArgumentParser) -> None:
    hosts_sub = p.add_subparsers(dest="hosts_command", metavar="subcommand")
    hosts_sub.required = True
    check_p = hosts_sub.add_parser("check", parents=[common],
                                   help="collect every configured host (or the named ones), compare, write "
                                        "hosts.json and HOSTS.md; changes nothing on the servers")
    check_p.add_argument("hosts", nargs="*", metavar="host", help="host names from [hosts.servers] (default: all)")
    accept_p = hosts_sub.add_parser("accept", parents=[common],
                                    help="record a decision for one finding (the user confirms it first)")
    accept_p.add_argument("host")
    accept_p.add_argument("change_id", metavar="change-id", help="the finding's id from HOSTS.md")
    accept_p.add_argument("note", help="why the finding is accepted")
    accept_p.add_argument("--review-by", default=None, metavar="YYYY-MM-DD",
                          help="required for a KEV finding: the date it is reviewed again (at most 30 days ahead)")
    for name, text in (("bootstrap", "create the audit user, install the collector and pin the host key"),
                       ("unbootstrap", "remove what bootstrap installed"),
                       ("patch", "apply the host's own unattended-upgrades policy once (never reboots)")):
        sp = hosts_sub.add_parser(name, parents=[common], help=text + " (plan without --confirm)")
        sp.add_argument("host")
        if name == "patch":
            sp.add_argument("--include-docker", action="store_true", help="also upgrade the held-back Docker packages")
        sp.add_argument("--confirm", default=None, metavar="HOST",
                        help="run the plan for real; must equal the host name; refused under the scheduler")


def _setup(args) -> int:
    from . import setup
    return setup.cli(args)


def _scan(args) -> int:
    from . import scan
    return scan.cli(args)


def _vex(args) -> int:
    from . import vex
    return vex.cli(args)


def _run(args) -> int:
    from . import pipeline
    return pipeline.cli_run(args)


def _audit(args) -> int:
    from . import pipeline
    return pipeline.cli_audit(args)


def _lookup(args) -> int:
    from . import lookup
    return lookup.cli_lookup(args)


def _incident(args) -> int:
    from . import lookup
    return lookup.cli_incident(args)


def _status(args) -> int:
    from . import pipeline
    return pipeline.cli_status(args)


def _issues(args) -> int:
    from . import issues
    return issues.cli(args)


def _releases(args) -> int:
    from . import releases
    return releases.cli(args)


def _report(args) -> int:
    from . import management
    return management.cli(args)


def _secrets(args) -> int:
    from . import secrets
    return secrets.cli_secrets(args)


def _hosts(args) -> int:
    from .hosts import cli as hosts_cli
    return hosts_cli.run(args)


def _code(args) -> int:
    from . import code
    return code.cli(args)


def _settings(args) -> int:
    from . import integration
    return integration.cli(args)


def _assess(args) -> int:
    from . import draft
    return draft.cli(args)


def _import(args) -> int:
    from . import sbomimport
    return sbomimport.cli(args)


def _sbom(args) -> int:
    from . import sbomquality
    if args.path is not None and args.project:
        print("sbom check: give a path or --project, not both", file=sys.stderr)
        return 2
    if args.branch and not args.project:
        print("sbom check: --branch needs --project", file=sys.stderr)
        return 2
    return sbomquality.cli(args)


def _cra(args) -> int:
    from . import cra
    return cra.cli(args)


def _refresh_integration() -> None:
    """After a plugin update, keep opted-in rules and the hook script on the current version (best effort)."""
    import os
    from . import integration
    try:
        for line in integration.refresh(Path(os.environ.get("SBOM_AUDIT_HOME") or Path.home())):
            print(line, file=sys.stderr)
    except Exception as exc:  # noqa: BLE001 - never fail a run over the integration
        print(f"settings refresh skipped: {exc}", file=sys.stderr)


def _writes(args) -> bool:
    """True when the parsed command would write to the evidence folder."""
    if args.command == "incident":
        return bool(args.vex)
    if args.command == "secrets" and getattr(args, "secrets_command", None) == "report":
        return False
    if args.command == "settings":
        return bool(args.autonomy or args.session_hook)
    if args.command == "assess":
        return not args.dry_run
    if args.command == "cra" and args.cra_command == "init":
        return bool(args.yes)
    if args.command == "issues":
        from . import issues
        return not issues.is_query(args)
    return args.command in WRITING_COMMANDS


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.out = args.out or find_out(Path.cwd())
    if config.read_only() and _writes(args):
        print(f"read-only mode: {args.command} writes nothing", file=sys.stderr)
        return EXIT_READ_ONLY
    if args.command in ("run", "setup") and not config.read_only():
        _refresh_integration()
    handler = HANDLERS.get(args.command)
    if handler is None:
        parser.error(f"{args.command}: not implemented yet")
    try:
        return handler(args)
    except ConfigError as exc:
        print(f"{config.CONFIG_NAME}: {exc}", file=sys.stderr)
        return 2


HANDLERS: dict[str, object] = {"setup": _setup, "scan": _scan, "vex": _vex, "run": _run,
                               "audit": _audit, "lookup": _lookup, "incident": _incident,
                               "status": _status, "issues": _issues, "secrets": _secrets, "hosts": _hosts,
                               "code": _code, "settings": _settings, "assess": _assess, "report": _report,
                               "cra": _cra, "releases": _releases, "import": _import, "sbom": _sbom}


if __name__ == "__main__":
    sys.exit(main())
