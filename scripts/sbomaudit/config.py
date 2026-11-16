"""Configuration (`security/sbom-audit.toml`), mode detection and project discovery."""
from __future__ import annotations

import fnmatch
import os
import re
import subprocess
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

from .errors import ConfigError

CONFIG_NAME = "sbom-audit.toml"
DEFAULT_BRANCHES = ["main", "dev"]
SKIP_PROJECT_PATTERNS = ["*-local-backup-*"]
PROTOCOLS = ("ssh", "https")
PROTOCOL_ENV = "SBOM_AUDIT_GIT_PROTOCOL"


@dataclass
class ProjectOpts:
    production: bool = False
    ignore: list[str] = field(default_factory=list)
    github: str | None = None  # "owner/repo"


@dataclass
class Discovery:
    github_owner: str | None = None
    include_forks: bool = False
    protocol: str = "ssh"  # "ssh" | "https": how [discovery] repositories are cloned


@dataclass
class Schedule:
    assess: bool = False
    assess_budget_usd: float = 5.0


@dataclass
class SecretsOpts:
    enabled: bool = True


DEFAULT_HOST_KEY = "~/.ssh/sbom-audit_ed25519"
_HOST_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")   # the same rule as hosts.store.check_host


@dataclass
class HostOpts:
    address: str
    admin: str | None = None  # "user@host" used for bootstrap/patch; the audit user is always sbom-audit
    production: bool = False
    projects: list[str] = field(default_factory=list)


@dataclass
class HostsOpts:
    enabled: bool = False
    concurrency: int = 4
    timeout_minutes: int = 10
    key: Path = field(default_factory=lambda: Path(DEFAULT_HOST_KEY).expanduser())
    servers: dict[str, HostOpts] = field(default_factory=dict)

    @property
    def active(self) -> bool:
        return bool(self.enabled and self.servers)


@dataclass
class Config:
    out: Path
    root: Path
    mode: str  # "portfolio" | "single"
    branches: list[str] = field(default_factory=lambda: list(DEFAULT_BRANCHES))
    ignore_projects: list[str] = field(default_factory=list)
    fetch: bool = True
    projects: dict[str, ProjectOpts] = field(default_factory=dict)
    commit: bool = True
    push: bool = False
    discovery: Discovery = field(default_factory=Discovery)
    schedule: Schedule = field(default_factory=Schedule)
    secrets: SecretsOpts = field(default_factory=SecretsOpts)
    hosts: HostsOpts = field(default_factory=HostsOpts)


@dataclass
class Project:
    name: str
    path: Path
    remote: str | None = None
    production: bool = False
    ignore: list[str] = field(default_factory=list)


def detect_mode(out: Path) -> str:
    """`single` when `security/` sits inside a git repo, otherwise `portfolio`."""
    return "single" if (out.resolve().parent / ".git").exists() else "portfolio"


def read_only() -> bool:
    """`SBOM_AUDIT_READ_ONLY=1` makes every writing subcommand exit without writing."""
    return os.environ.get("SBOM_AUDIT_READ_ONLY") == "1"


def _bool(value, key: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{key} must be true or false")
    return value


def _float(value, key: str, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{key} must be a number")
    if positive and not value > 0:
        raise ConfigError(f"{key} must be a number greater than 0")
    return float(value)


def _int(value, key: str, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{key} must be a whole number")
    if value < minimum:
        raise ConfigError(f"{key} must be a whole number of at least {minimum}")
    return value


def _str(value, key: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{key} must be a non-empty string")
    return value


def _admin(value, source: str) -> str:
    """An admin login (`user@host` or an ssh alias) under `hosts.transport.admin_argv`'s rule: not empty, no
    leading `-` (ssh would read it as an option), no whitespace or control characters."""
    value = _str(value, source)
    if not value or value.startswith("-") or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise ConfigError(f"{source} must be a login such as user@host or an ssh alias: no leading '-', "
                          "no whitespace or control characters")
    return value


def _hosts(data) -> HostsOpts:
    if not isinstance(data, dict):
        raise ConfigError("[hosts] must be a table")
    servers_raw = data.get("servers", {})
    if not isinstance(servers_raw, dict):
        raise ConfigError("[hosts.servers] must be a table")
    servers: dict[str, HostOpts] = {}
    for name, opts in servers_raw.items():
        where = f'[hosts.servers."{name}"]'
        if not _HOST_NAME_RE.fullmatch(name):
            raise ConfigError(f'{where}: host name must match [A-Za-z0-9][A-Za-z0-9._-]*')
        if not isinstance(opts, dict):
            raise ConfigError(f"{where} must be a table")
        if "address" not in opts:
            raise ConfigError(f"{where} address is required")
        projects = opts.get("projects", [])
        if not isinstance(projects, list) or not all(isinstance(p, str) for p in projects):
            raise ConfigError(f"{where} projects must be a list of project names")
        admin = opts.get("admin")
        if admin is not None:
            admin = _admin(admin, f"{where} admin")
        servers[name] = HostOpts(
            address=_str(opts["address"], f"{where} address"),
            admin=admin,
            production=_bool(opts.get("production", False), f"{where} production"),
            projects=list(projects),
        )
    return HostsOpts(
        enabled=_bool(data.get("enabled", False), "[hosts] enabled"),
        concurrency=_int(data.get("concurrency", 4), "[hosts] concurrency"),
        timeout_minutes=_int(data.get("timeout_minutes", 10), "[hosts] timeout_minutes"),
        key=Path(_str(data.get("key", DEFAULT_HOST_KEY), "[hosts] key")).expanduser(),
        servers=servers,
    )


def _protocol(value, source: str) -> str:
    if value not in PROTOCOLS:
        raise ConfigError(f'{source} must be "ssh" or "https"')
    return value


def load(out: Path, root: Path | None = None, env: Mapping[str, str] | None = None) -> Config:
    """Read `<out>/sbom-audit.toml`; `SBOM_AUDIT_GIT_PROTOCOL` in `env` (default `os.environ`) overrides
    `[discovery] protocol`. ConfigError for a value of the wrong kind."""
    env = os.environ if env is None else env
    out = out.resolve()
    data: dict = {}
    path = out / CONFIG_NAME
    if path.exists():
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    if root is not None:
        root = root.resolve()
        mode = "single" if (root / ".git").exists() else "portfolio"
    else:
        root = out.parent
        mode = detect_mode(out)
    projects = {
        name: ProjectOpts(production=_bool(opts.get("production", False), f'[projects."{name}"] production'),
                          ignore=list(opts.get("ignore", [])),
                          github=opts.get("github"))
        for name, opts in (data.get("projects") or {}).items()
    }
    discovery = data.get("discovery") or {}
    schedule = data.get("schedule") or {}
    secrets = data.get("secrets") or {}
    protocol = _protocol(discovery.get("protocol", "ssh"), "[discovery] protocol")
    if env.get(PROTOCOL_ENV):
        protocol = _protocol(env[PROTOCOL_ENV], PROTOCOL_ENV)
    return Config(
        out=out,
        root=root,
        mode=mode,
        branches=list(data.get("branches", DEFAULT_BRANCHES)),
        ignore_projects=list(data.get("ignore_projects", [])),
        fetch=_bool(data.get("fetch", True), "fetch"),
        projects=projects,
        commit=_bool(data.get("commit", True), "commit"),
        push=_bool(data.get("push", False), "push"),
        discovery=Discovery(github_owner=discovery.get("github_owner"),
                            include_forks=_bool(discovery.get("include_forks", False),
                                                "[discovery] include_forks"),
                            protocol=protocol),
        schedule=Schedule(assess=_bool(schedule.get("assess", False), "[schedule] assess"),
                          assess_budget_usd=_float(schedule.get("assess_budget_usd", 5.0),
                                                   "[schedule] assess_budget_usd", positive=True)),
        secrets=SecretsOpts(enabled=_bool(secrets.get("enabled", True), "[secrets] enabled")),
        hosts=_hosts(data.get("hosts", {})),
    )


def remote_url(repo: Path) -> str | None:
    proc = subprocess.run(["git", "-C", str(repo), "remote", "get-url", "origin"],
                          text=True, capture_output=True)
    url = proc.stdout.strip()
    return url if proc.returncode == 0 and url else None


def _project(cfg: Config, path: Path) -> Project:
    opts = cfg.projects.get(path.name, ProjectOpts())
    return Project(name=path.name, path=path, remote=remote_url(path),
                   production=opts.production, ignore=list(opts.ignore))


_SLUG_PART_RE = re.compile(r"[A-Za-z0-9._-]+")


def bare_clone_path(out: Path, slug: str) -> Path:
    """`Owner/Name` -> `<out>/.cache/repos/owner__name.git`; rejects anything that could leave that folder."""
    if not isinstance(slug, str) or slug.count("/") != 1:
        raise ValueError("GitHub slug must be exactly 'owner/name' with one '/'")
    owner, name = slug.split("/")
    if not owner or not name:
        raise ValueError("GitHub slug has an empty owner or name")
    if ".." in slug:
        raise ValueError("GitHub slug contains '..'")
    if any(ch.isspace() for ch in slug):
        raise ValueError("GitHub slug contains whitespace")
    if "\\" in slug or any(sep and sep != "/" and sep in slug for sep in (os.sep, os.altsep)):
        raise ValueError("GitHub slug contains a path separator other than '/'")
    if not (_SLUG_PART_RE.fullmatch(owner) and _SLUG_PART_RE.fullmatch(name)):
        raise ValueError("GitHub slug contains characters outside [A-Za-z0-9._-]")
    # GitHub slugs are case-insensitive: one folder per repository whatever case the slug arrives in
    return out / ".cache" / "repos" / f"{owner.lower()}__{name.lower()}.git"


def github_only_projects(cfg: Config) -> list[tuple[str, str]]:
    """(name, slug) for `[projects."<name>"] github = "owner/repo"` entries with no local folder."""
    found = []
    for name, opts in sorted(cfg.projects.items(), key=lambda kv: kv[0].lower()):
        if not opts.github:
            continue
        if (cfg.root / name).exists() or (cfg.mode == "single" and name == cfg.root.name):
            continue
        found.append((name, opts.github))
    return found


def discover(cfg: Config) -> list[Project]:
    if cfg.mode == "single":
        return [_project(cfg, cfg.root)] + _cloned_github_projects(cfg)
    found: list[Project] = []
    out = cfg.out.resolve()
    for child in sorted(cfg.root.iterdir(), key=lambda p: p.name.lower()):
        if not child.is_dir() or not (child / ".git").exists():
            continue
        if child.resolve() == out:          # the security folder after `setup --init-git`
            continue
        if child.name in cfg.ignore_projects:
            continue
        if any(fnmatch.fnmatch(child.name, pat) for pat in SKIP_PROJECT_PATTERNS):
            continue
        found.append(_project(cfg, child))
    return found + _cloned_github_projects(cfg)


def _cloned_github_projects(cfg: Config) -> list[Project]:
    """GitHub-only projects whose bare clone already exists (no network here; the secrets step clones)."""
    found = []
    for name, slug in github_only_projects(cfg):
        if name in cfg.ignore_projects:
            continue
        try:
            path = bare_clone_path(cfg.out, slug)
        except ValueError:
            continue
        if not path.is_dir():
            continue
        opts = cfg.projects[name]
        found.append(Project(name=name, path=path, remote=remote_url(path),
                             production=opts.production, ignore=list(opts.ignore)))
    return found


_GITHUB_RE = re.compile(r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$")


def github_slug(remote: str | None) -> str | None:
    """'git@github.com:Owner/Repo.git' -> 'Owner/Repo'; None for other hosts."""
    m = _GITHUB_RE.search(remote or "")
    return f"{m['owner']}/{m['repo']}" if m else None


def project_purl(p: Project) -> str:
    """OpenVEX product identifier for a project."""
    slug = github_slug(p.remote)
    if slug:
        return "pkg:github/" + slug.lower()
    return "pkg:generic/" + quote(p.name, safe="")


def _toml_str_list(items: list[str]) -> str:
    return "[" + ", ".join(f'"{i}"' for i in items) + "]"


def write_default(out: Path, cfg: Config, discovered: list[Project] | None = None) -> Path:
    """Write `sbom-audit.toml` once; an existing file is never overwritten."""
    out.mkdir(parents=True, exist_ok=True)
    path = out / CONFIG_NAME
    if path.exists():
        return path
    lines = [
        "# sbom-audit configuration. Docs: https://github.com/Wuesteon/sbom-audit",
        f"branches = {_toml_str_list(cfg.branches)}",
        f"ignore_projects = {_toml_str_list(cfg.ignore_projects)}",
        f"fetch = {'true' if cfg.fetch else 'false'}",
        "# Commit the evidence repository after each run; push only to a private remote.",
        f"commit = {'true' if cfg.commit else 'false'}",
        f"push = {'true' if cfg.push else 'false'}",
        "",
        "# Discover repositories on GitHub in addition to local folders.",
        "# [discovery]",
        '# github_owner = "..."',
        "# include_forks = false",
        '# protocol = "ssh"  # "https" after: gh auth setup-git',
        "",
        "# Scheduled headless assessment (writes a proposal only, never a VEX statement).",
        "# [schedule]",
        "# assess = false",
        "# assess_budget_usd = 5.0",
        "",
        "# Secret scanning (gitleaks).",
        "# [secrets]",
        "# enabled = true",
        "",
        "# Per-project options: production = true puts CRITICAL/HIGH findings first;",
        "# ignore = [\"path/\"] drops subtrees from the inventory.",
        "[projects]",
    ]
    for p in discovered or []:
        lines.append(f'# "{p.name}" = {{ production = false }}')
    lines.append('# [projects."<name>"]')
    lines.append('# github = "owner/repo"')
    path.write_text("\n".join(lines) + "\n")
    return path
