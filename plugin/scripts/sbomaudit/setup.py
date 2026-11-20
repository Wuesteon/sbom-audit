"""`setup`: preflight, discover projects, write config and .gitignore, optional git init and Dependabot."""
from __future__ import annotations

import json
import shlex
import shutil
import socket
import subprocess
import sys
from pathlib import Path

from . import config, evidence, gitio, preflight, scheduler, status
from .errors import ToolError

GITIGNORE_LINE = ".cache/"
DEPENDABOT_ENDPOINTS = (("alerts", "vulnerability-alerts"), ("fixes", "automated-security-fixes"))

gh_run = subprocess.run     # patchable in tests
which = shutil.which


def _ensure_gitignore(out: Path) -> str:
    path = out / ".gitignore"
    if not path.exists():
        path.write_text(GITIGNORE_LINE + "\n", encoding="utf-8")
        return "written"
    lines = path.read_text(encoding="utf-8").splitlines()
    if GITIGNORE_LINE in (line.strip() for line in lines):
        return "unchanged"
    with path.open("a", encoding="utf-8") as fh:
        fh.write(("" if not lines or lines[-1] == "" else "\n") + GITIGNORE_LINE + "\n")
    return "updated"


def _init_git(out: Path) -> str:
    if (out / ".git").exists():
        return "already a git repository"
    proc = subprocess.run(["git", "init", "-q", str(out)], text=True, capture_output=True)
    if proc.returncode != 0:
        return f"git init failed: {proc.stderr.strip()}"
    return "git init done"


def _initial_status(out: Path, mode: str) -> str:
    """A first status.json (exit_code None, zero counts, first_run) so the hook has something to read."""
    if status.read(out) is not None:
        return "unchanged (already exists)"
    doc = status.build(status.empty_report(), secrets=None, previous=None, duration_s=0.0, exit_code=None,
                       run_host=socket.gethostname(), mode=mode)
    status.write(out, doc)
    status.write_md(out, doc)
    return "written (no run yet)"


SETUP_SUBJECT = "chore: sbom-audit setup"


def _commit_setup(out: Path, cfg: config.Config, files: list[Path]) -> str | None:
    """One pathspec commit of the files setup wrote, in an own evidence repo with `commit = true`.

    Returns a line to print, or None when skipped silently (not own repo, nothing staged, no git).
    """
    if cfg.mode != "portfolio" or not cfg.commit or not evidence.is_own_repo(out):
        return None
    res = evidence.commit_run(out, files, SETUP_SUBJECT, evidence.body_line(status.read(out) or {}))
    if res.status == "committed":
        return f"{out}: committed {res.sha} ({SETUP_SUBJECT})"
    if res.status == "failed":
        return f"{out}: setup commit failed ({res.detail})"
    return None


def _visibility_lines(out: Path, cfg: config.Config, gh, which) -> list[str]:
    if cfg.mode != "portfolio":
        return [f"evidence repo visibility: not checked (single-repo mode: security/ is part of {cfg.root})"]
    visibility = (evidence.remote_visibility(out, gh=gh, which=which)
                  if evidence.is_own_repo(out) else "unknown")
    lines = [f"evidence repo visibility: {visibility}"]
    if visibility == "public":
        lines.append("push = true will be refused")
    elif visibility == "unknown":
        lines.append("keep this repository private")
    return lines


def _first_line(text: str | None) -> str:
    lines = (text or "").strip().splitlines()
    return lines[0].strip() if lines else ""


def turn_on_dependabot(slugs: list[str], gh=None, fixes: bool = False) -> list[str]:
    """PUT `vulnerability-alerts` (and `automated-security-fixes` with `fixes`) per `owner/repo` slug."""
    gh = gh or gh_run
    endpoints = DEPENDABOT_ENDPOINTS if fixes else DEPENDABOT_ENDPOINTS[:1]
    lines = []
    for slug in slugs:
        results = []
        for label, endpoint in endpoints:
            try:
                proc = gh(["gh", "api", "-X", "PUT", f"repos/{slug}/{endpoint}"],
                          text=True, capture_output=True, timeout=30)
            except subprocess.TimeoutExpired:
                results.append(f"{label}: failed (timed out)")
                continue
            except OSError as exc:
                results.append(f"{label}: failed ({type(exc).__name__})")
                continue
            if proc.returncode == 0:
                results.append(f"{label}: on")
            else:
                err = _first_line(proc.stderr) or _first_line(proc.stdout)
                results.append(f"{label}: failed ({err or 'exit ' + str(proc.returncode)})")
        lines.append(f"  {slug}: " + ", ".join(results))
    return lines


SECRET_SCANNING_NOTE = ("private repositories need GitHub Advanced Security (paid) for secret scanning; "
                        "the plugin does not enable it")


def _feature(sa, key: str) -> str:
    block = sa.get(key) if isinstance(sa, dict) else None
    value = block.get("status") if isinstance(block, dict) else None
    return value if value in ("enabled", "disabled") else "unknown"


def _repo_status(slug: str, gh) -> tuple[str, str, str]:
    """(visibility, secret scanning, push protection) for one repository; `unknown` for anything missing."""
    unknown = ("unknown", "unknown", "unknown")
    try:
        proc = gh(["gh", "api", f"repos/{slug}", "--jq", "{visibility, sa: .security_and_analysis}"],
                  capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            return unknown
        data = json.loads(proc.stdout or "")
    except Exception:  # noqa: BLE001 - a status read never breaks setup
        return unknown
    if not isinstance(data, dict):
        return unknown
    visibility = data.get("visibility")
    return (visibility if visibility in ("public", "private", "internal") else "unknown",
            _feature(data.get("sa"), "secret_scanning"), _feature(data.get("sa"), "secret_scanning_push_protection"))


def github_status(slugs: list[str], gh=subprocess.run) -> list[str]:
    """Per repository: visibility, secret scanning and push protection status (read only), then one note."""
    lines = []
    for slug in slugs:
        visibility, scanning, protection = _repo_status(slug, gh)
        lines.append(f"  {slug}: {visibility}, secret scanning: {scanning}, push protection: {protection}")
    return lines + [f"  {SECRET_SCANNING_NOTE}"]


def _dedupe(slugs: list[str]) -> list[str]:
    seen, out = set(), []
    for slug in slugs:
        if slug.lower() not in seen:
            seen.add(slug.lower())
            out.append(slug)
    return out


GUARD_CONFIRM_HEADER = "Tracked hook files (confirm per repo, then rerun with --tracked-ok <name>):"


def guard_lines(cfg: config.Config, install: bool, tracked_ok: list[str], cfg_dir: Path,
                plugin_root: Path) -> list[str]:
    """`--install-guard` / `--uninstall-guard` over every local repository: one line per repository, then the
    repositories whose tracked hook file needs the user's confirmation (`--tracked-ok <name>`)."""
    from .secrets import guard, scope
    repos = scope.local_repos(cfg)
    lines = ["Pre-commit guard:"]
    names = {r.name for r in repos}
    lines += [f"  --tracked-ok {name}: no repository with that name" for name in tracked_ok if name not in names]
    if install:
        written = guard.sync_config_dir(cfg_dir, plugin_root)
        lines.append(f"  {cfg_dir}: " + (f"written {', '.join(p.name for p in written)}" if written
                                          else "unchanged"))
    pending = []
    for repo in repos:
        try:
            summary = (guard.install(repo.path, cfg_dir, tracked_ok=repo.name in tracked_ok,
                                     plugin_root=plugin_root) if install
                       else guard.uninstall(repo.path))
        except (gitio.GitError, OSError, ValueError) as exc:
            summary = f"failed ({type(exc).__name__})"
        first, *block = summary.split("\n")  # a YAML block to paste follows the status line
        entry = [f"  {repo.name}: {first}", *(f"      {line}" for line in block)]
        if summary.startswith("needs confirmation"):
            pending += entry
            entry = [f"  {repo.name}: " + first.split(":", 1)[0] + ", listed below"]
        lines += entry
    if pending:
        lines += [GUARD_CONFIRM_HEADER, *pending]
    return lines


def branch_warnings(cfg: config.Config, projects) -> list[str]:
    """One line per project that has none of the configured branches: `run` would skip it, so say so now."""
    from .gitio import GitError, _local_branches, _remote_branches, pick_branches
    lines = []
    for p in projects:
        try:
            if pick_branches(p.path, list(cfg.branches)):
                continue
            have = sorted(_local_branches(p.path) | _remote_branches(p.path))
        except (GitError, OSError):
            continue
        lines.append(f"warning: {p.name} has none of the branches {list(cfg.branches)} and will not be scanned; "
                     f"it has {', '.join(have[:5]) or 'no branch'}{' …' if len(have) > 5 else ''}. "
                     f"Add one to `branches` in {config.CONFIG_NAME}.")
    return lines


def run(out: Path, root: Path | None, init_git: bool = False, enable_dependabot: str | None = None,
        gh=None, which=None, schedule: str | None = None, install_guard: bool = False,
        uninstall_guard: bool = False, tracked_ok: list[str] | None = None, yes: bool = False) -> int:
    """Exit 0 when set up (idempotent), 4 when a required tool is missing."""
    which = which or globals()["which"]
    missing = preflight.check(which)
    if missing:
        print(preflight.message(missing))
        return 4
    out = Path(out).resolve()
    cfg = config.load(out, root=root)
    projects = config.discover(cfg)
    names = ", ".join(p.name for p in projects) or "none"
    print(f"{cfg.mode} mode: {len(projects)} project(s) under {cfg.root}: {names}")
    if not projects:
        print(f"no git repository found under {cfg.root}: start Claude Code in the folder that holds your "
              "repositories (or inside one) and run setup again. Nothing written.")
        return 2
    had_config = (out / config.CONFIG_NAME).exists()
    path = config.write_default(out, cfg, projects)
    print(f"{path}: {'unchanged (already exists)' if had_config else 'written — set production = true for what runs in production'}")
    for line in branch_warnings(config.load(out, root=root), projects):
        print(line)
    print(f"{out / '.gitignore'}: {_ensure_gitignore(out)}")
    docs = evidence.write_folder_docs(out)
    if docs:
        print(f"folder docs: {', '.join(d.name for d in docs)}")
    print(f"{out / status.STATUS_JSON}: {_initial_status(out, cfg.mode)}")
    if init_git:
        if cfg.mode == "portfolio":
            print(f"{out}: {_init_git(out)}")
        else:
            print(f"{out}: single mode, tracked by {cfg.root} (no separate repository)")
    files = ([] if had_config else [path]) + [out / ".gitignore", *docs,
                                              out / status.STATUS_JSON, out / status.STATUS_FILE]
    line = _commit_setup(out, cfg, files)
    if line:
        print(line)
    for line in _visibility_lines(out, cfg, gh or gh_run, which):
        print(line)
    gh = gh or gh_run
    configured = _dedupe([slug for slug in (config.github_slug(p.remote) for p in projects) if slug])
    if configured:
        print("GitHub status:")
        for line in github_status(configured, gh=gh):
            print(line)
    discovered: list[dict] | None = None
    if cfg.discovery.github_owner:
        from .secrets import discovery
        try:
            discovered = [r for r in discovery.list_repos(cfg.discovery.github_owner, cfg.discovery.include_forks,
                                                          gh=gh) if not r.get("isArchived")]
        except ToolError as exc:
            print(f"  discovery: skipped ({_first_line(exc.detail)})")
    if enable_dependabot:
        fixes = enable_dependabot == "fixes"
        targets = _dedupe(configured + [r["nameWithOwner"] for r in discovered or [] if r.get("nameWithOwner")])
        print("Dependabot alerts + security updates will be enabled on:" if fixes
              else "Dependabot alerts will be enabled on:")
        for slug in targets:
            print(f"  {slug}")
        if not targets:
            print("  (no GitHub repositories)")
        elif not yes:
            print("run again with --yes to enable (no changes made)")
        else:
            for line in turn_on_dependabot(targets, gh=gh, fixes=fixes):
                print(line)
    audited = {slug.lower() for slug in configured}
    unaudited = [r["nameWithOwner"] for r in discovered or []
                 if r.get("nameWithOwner") and r["nameWithOwner"].lower() not in audited]
    if unaudited:
        print("Discovered but not audited (add to [projects] to audit):")
        for slug in _dedupe(unaudited):
            print(f"  {slug}")
    if schedule:
        print("Scheduler:")
        if schedule == "weekly":
            lines = scheduler.install_weekly(out, scheduler.plugin_root(), home=Path.home(), platform=sys.platform)
        else:
            lines = scheduler.remove(out, home=Path.home(), platform=sys.platform)
        for line in lines:
            print(f"  {line}")
    if tracked_ok and not install_guard:
        print("--tracked-ok is used only with --install-guard; ignored")
    if install_guard or uninstall_guard:
        for line in guard_lines(cfg, install_guard, list(tracked_ok or []) if install_guard else [],
                                scheduler.config_dir(), scheduler.plugin_root()):
            print(line)
    if yes and not enable_dependabot:
        print("--yes is used only with --enable-dependabot; ignored")
    cli_path = shlex.quote((scheduler.plugin_root() / "scripts" / "sbom_audit_cli.py").as_posix())
    print(f"Next: /sbom-audit:run (without Claude Code: python3 {cli_path} run)")
    return 0


def cli(args) -> int:
    return run(args.out, getattr(args, "root", None), init_git=bool(getattr(args, "init_git", False)),
               enable_dependabot=getattr(args, "enable_dependabot", None),
               yes=bool(getattr(args, "yes", False)),
               schedule=getattr(args, "schedule", None),
               install_guard=bool(getattr(args, "install_guard", False)),
               uninstall_guard=bool(getattr(args, "uninstall_guard", False)),
               tracked_ok=list(getattr(args, "tracked_ok", None) or []))
