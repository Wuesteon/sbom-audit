"""Configuration (`security/sbom-audit.toml`), mode detection and project discovery."""
from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import os
import re
import subprocess
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path, PurePosixPath
from urllib.parse import quote, urlsplit

from .errors import ConfigError

CONFIG_NAME = "sbom-audit.toml"
DEFAULT_BRANCHES = ["main", "dev"]
SKIP_PROJECT_PATTERNS = ["*-local-backup-*"]
PROTOCOLS = ("ssh", "https")
PROTOCOL_ENV = "SBOM_AUDIT_GIT_PROTOCOL"
# `[assess]`: an OpenAI-compatible chat completions endpoint for `assess draft`; each env var overrides its key
ASSESS_ENV = {"base_url": "SBOM_AUDIT_ASSESS_BASE_URL", "model": "SBOM_AUDIT_ASSESS_MODEL",
              "api_key_env": "SBOM_AUDIT_ASSESS_API_KEY_ENV"}
_ENV_NAME_RE = re.compile(r"[A-Z_][A-Z0-9_]*")


@dataclass
class ReleasesOpts:
    """Release scanning for one project: tags matching `tags` (a glob), the newest `keep` of them, and the
    support period of each release (`support_months` from its date and/or an explicit `support_until`).
    Pre-release tags (`-rc.1`, `-beta`) are left out unless `prereleases` is true: a release candidate is
    not a release the manufacturer supports."""
    tags: str
    keep: int = 3
    support_months: int | None = None
    support_until: date | None = None
    prereleases: bool = False


@dataclass
class ProjectOpts:
    production: bool = False
    ignore: list[str] = field(default_factory=list)
    github: str | None = None  # "owner/repo"
    releases: ReleasesOpts | bool | None = None  # None: the portfolio [releases] default; False: off
    sbom: str | None = None    # a build SBOM committed in the repository (path in the tree)


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
    """`[secrets]`. `rank_by_context` ranks findings in tests, fixtures, examples, docs, vendored code, data
    files and dev setups one class lower (never drops them); `context` adds path patterns per label to the
    defaults in classes.toml, and its `deployable` list names paths that are never context."""
    enabled: bool = True
    rank_by_context: bool = True
    context: dict[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass
class AssessProvider:
    """`[assess]`: where `assess draft` sends report excerpts. Off (`configured` False) until base_url and
    model are set. The API key is read at call time from the env var `api_key_env` names, else from
    `api_key_file`; it is never stored in the config."""
    base_url: str | None = None
    model: str | None = None
    api_key_env: str | None = None
    api_key_file: Path | None = None
    timeout_seconds: int = 600
    max_tokens: int | None = None
    include_hosts: bool = False

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.model)


REPORT_LANGUAGES = ("en", "de")


@dataclass
class ReportOpts:
    """[report]: the management report (REPORT.html)."""
    organisation: str | None = None
    language: str = "en"  # one of REPORT_LANGUAGES


@dataclass
class EpssOpts:
    """[epss]: FIRST's exploit probability scores (epss.py). `enabled = false` skips the download;
    `promote_at` is the score (a fraction, 0.10 = 10%) from which a finding is promoted; 0 turns that off."""
    enabled: bool = True
    promote_at: float = 0.10


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
    assess: AssessProvider = field(default_factory=AssessProvider)
    report: ReportOpts = field(default_factory=ReportOpts)
    epss: EpssOpts = field(default_factory=EpssOpts)
    releases: ReleasesOpts | None = None  # [releases]: the portfolio default, off when absent
    digest: str | None = None  # sha256 of the sbom-audit.toml bytes `load` read; None: no file was read


@dataclass
class Project:
    name: str
    path: Path
    remote: str | None = None
    production: bool = False
    ignore: list[str] = field(default_factory=list)
    releases: ReleasesOpts | None = None
    sbom: str | None = None


def detect_mode(out: Path) -> str:
    """`single` when `security/` sits inside a git repo, otherwise `portfolio`."""
    return "single" if (out.resolve().parent / ".git").exists() else "portfolio"


def read_only() -> bool:
    """`SBOM_AUDIT_READ_ONLY=1` makes every writing subcommand exit without writing."""
    return os.environ.get("SBOM_AUDIT_READ_ONLY") == "1"


def _secrets(source) -> SecretsOpts:
    if not isinstance(source, dict):
        raise ConfigError("[secrets] must be a table")
    context = source.get("context") or {}
    if not isinstance(context, dict):
        raise ConfigError("[secrets.context] must be a table of label = [path patterns]")
    patterns: dict[str, tuple[str, ...]] = {}
    for label, items in context.items():
        where = f"[secrets.context] {label}"
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,30}", str(label)):
            raise ConfigError(f"{where}: a label is lower-case letters, digits and '-'")
        if not isinstance(items, list) or not all(isinstance(i, str) and i.strip() for i in items):
            raise ConfigError(f"{where} must be a list of path patterns such as \"qa/\" or \"*_mock.go\"")
        patterns[label] = tuple(i.strip() for i in items)
    return SecretsOpts(enabled=_bool(source.get("enabled", True), "[secrets] enabled"),
                       rank_by_context=_bool(source.get("rank_by_context", True), "[secrets] rank_by_context"),
                       context=patterns)


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


def _tree_path(value, key: str) -> str | None:
    """A relative path inside a repository tree (no `..`, not absolute), or None when unset."""
    if value is None:
        return None
    value = _str(value, key).strip()
    parts = PurePosixPath(value).parts
    if value.startswith(("/", "\\")) or ".." in parts or "\\" in value or any(ord(c) < 32 for c in value):
        raise ConfigError(f"{key} must be a relative path inside the repository")
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


def _loopback(host: str) -> bool:
    host = host.lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def assess_url(value, source: str) -> str:
    """A chat completions base URL: https, or http only to this machine (a local model server), with no
    credentials, query or fragment. Errors never echo the value (it could hold credentials)."""
    value = _str(value, source).strip().rstrip("/")
    try:
        parts = urlsplit(value)
        host = parts.hostname
        has_userinfo = parts.username is not None or parts.password is not None
    except ValueError:
        raise ConfigError(f"{source} is not a valid URL") from None
    if has_userinfo:
        raise ConfigError(f"{source} must not contain user:password@; name the key's environment variable "
                          "in api_key_env instead")
    if parts.query or parts.fragment:
        raise ConfigError(f"{source} must not contain a query or fragment")
    if not host or parts.scheme not in ("https", "http"):
        raise ConfigError(f"{source} must be an https:// URL such as https://openrouter.ai/api/v1")
    if parts.scheme == "http" and not _loopback(host):
        raise ConfigError(f"{source}: plain http is allowed only for localhost (a local model server); "
                          "use https for any other host")
    return value


def _assess(data, env: Mapping[str, str], out: Path) -> AssessProvider:
    if not isinstance(data, dict):
        raise ConfigError("[assess] must be a table")
    if "api_key" in data:
        raise ConfigError("[assess] api_key is not supported: never put the key in the config; set "
                          "api_key_env to the name of the environment variable that holds it")
    raw = {key: data.get(key) for key in ASSESS_ENV}
    source = {key: f"[assess] {key}" for key in ASSESS_ENV}
    for key, var in ASSESS_ENV.items():
        if env.get(var):
            raw[key], source[key] = env[var], var
    if bool(raw["base_url"]) != bool(raw["model"]):
        raise ConfigError("[assess] base_url and model must be set together")
    key_env = raw["api_key_env"]
    if key_env is not None and not (isinstance(key_env, str) and _ENV_NAME_RE.fullmatch(key_env)):
        raise ConfigError(f"{source['api_key_env']} must be the NAME of an environment variable "
                          "(A-Z, 0-9, _), not the key itself")
    key_file = data.get("api_key_file")
    if key_file is not None:
        key_file = Path(_str(key_file, "[assess] api_key_file")).expanduser().resolve()
        if key_file == out or out in key_file.parents:
            raise ConfigError("[assess] api_key_file must be outside the security/ folder (it is committed)")
    max_tokens = data.get("max_tokens")
    return AssessProvider(
        base_url=assess_url(raw["base_url"], source["base_url"]) if raw["base_url"] else None,
        model=_str(raw["model"], source["model"]).strip() if raw["model"] else None,
        api_key_env=key_env,
        api_key_file=key_file,
        timeout_seconds=_int(data.get("timeout_seconds", 600), "[assess] timeout_seconds"),
        max_tokens=_int(max_tokens, "[assess] max_tokens") if max_tokens is not None else None,
        include_hosts=_bool(data.get("include_hosts", False), "[assess] include_hosts"),
    )


def _report(data) -> ReportOpts:
    if not isinstance(data, dict):
        raise ConfigError("[report] must be a table")
    org = data.get("organisation")
    language = data.get("language", "en")
    if language not in REPORT_LANGUAGES:
        raise ConfigError('[report] language must be "en" or "de"')
    return ReportOpts(organisation=None if org is None else _str(org, "[report] organisation").strip(),
                      language=language)


EPSS_KEYS = ("enabled", "promote_at")


def _epss(data) -> EpssOpts:
    if not isinstance(data, dict):
        raise ConfigError("[epss] must be a table")
    unknown = sorted(set(data) - set(EPSS_KEYS))
    if unknown:              # a typo must not go unnoticed: promote_at changes priorities
        raise ConfigError(f"[epss]: unknown key {unknown[0]} (known: {', '.join(EPSS_KEYS)})")
    promote_at = data.get("promote_at", 0.10)
    if (isinstance(promote_at, bool) or not isinstance(promote_at, (int, float))
            or not 0 <= promote_at <= 1):
        raise ConfigError("[epss] promote_at must be a fraction from 0 to 1 (0.10 for 10%; 0 turns promotion off)")
    return EpssOpts(enabled=_bool(data.get("enabled", True), "[epss] enabled"), promote_at=float(promote_at))


RELEASES_KEYS = ("tags", "keep", "support_months", "support_until", "prereleases")


def _release_keys(data, where: str) -> dict:
    """The release keys of one table, checked; an unknown key is refused (a typo must not go unnoticed)."""
    if not isinstance(data, dict):
        raise ConfigError(f"{where} must be a table")
    unknown = sorted(set(data) - set(RELEASES_KEYS))
    if unknown:
        raise ConfigError(f"{where}: unknown key {unknown[0]} (known: {', '.join(RELEASES_KEYS)})")
    keys: dict = {}
    if "tags" in data:
        keys["tags"] = _str(data["tags"], f"{where} tags").strip()
    if "keep" in data:
        keys["keep"] = _int(data["keep"], f"{where} keep")
    if "support_months" in data:
        keys["support_months"] = _int(data["support_months"], f"{where} support_months")
    if "support_until" in data:
        value = data["support_until"]
        if isinstance(value, str):
            try:
                value = date.fromisoformat(value.strip())
            except ValueError:
                raise ConfigError(f"{where} support_until must be a date YYYY-MM-DD") from None
        if not isinstance(value, date) or hasattr(value, "hour"):
            raise ConfigError(f"{where} support_until must be a date YYYY-MM-DD")
        keys["support_until"] = value
    if "prereleases" in data:
        keys["prereleases"] = _bool(data["prereleases"], f"{where} prereleases")
    return keys


def _releases_default(data) -> ReleasesOpts | None:
    keys = _release_keys(data, "[releases]")
    if not keys:
        return None
    if "tags" not in keys:
        raise ConfigError('[releases] tags is required (a glob such as "v*")')
    return ReleasesOpts(**keys)


def _project_releases(value, default: ReleasesOpts | None, where: str) -> ReleasesOpts | bool | None:
    """`releases = false` turns release scanning off for the project; a table overrides the portfolio
    default key by key."""
    if value is None or value is True:
        if value is True and default is None:
            raise ConfigError(f"{where} releases = true needs a [releases] table with tags")
        return None
    if value is False:
        return False
    keys = _release_keys(value, f"{where} releases")
    merged = {**(vars(default) if default else {}), **keys}
    if "tags" not in merged:
        raise ConfigError(f"{where} releases needs tags (here or in [releases])")
    return ReleasesOpts(**merged)


def release_opts(cfg: Config, name: str) -> ReleasesOpts | None:
    """The release scanning options of project `name`, or None when release scanning is off for it."""
    opts = cfg.projects.get(name)
    value = opts.releases if opts is not None else None
    if value is None:
        return cfg.releases
    return value or None


def load(out: Path, root: Path | None = None, env: Mapping[str, str] | None = None) -> Config:
    """Read `<out>/sbom-audit.toml`; `SBOM_AUDIT_GIT_PROTOCOL` in `env` (default `os.environ`) overrides
    `[discovery] protocol` and the `ASSESS_ENV` variables override their `[assess]` keys. ConfigError for a
    value of the wrong kind."""
    env = os.environ if env is None else env
    out = out.resolve()
    data: dict = {}
    digest = None
    path = out / CONFIG_NAME
    if path.exists():
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        data = tomllib.loads(raw.decode())      # as tomllib.load decodes: UTF-8, an error for anything else
    if root is not None:
        root = root.resolve()
        mode = "single" if (root / ".git").exists() else "portfolio"
    else:
        root = out.parent
        mode = detect_mode(out)
    releases = _releases_default(data.get("releases", {}))
    projects = {
        name: ProjectOpts(production=_bool(opts.get("production", False), f'[projects."{name}"] production'),
                          ignore=list(opts.get("ignore", [])),
                          github=opts.get("github"),
                          releases=_project_releases(opts.get("releases"), releases, f'[projects."{name}"]'),
                          sbom=_tree_path(opts.get("sbom"), f'[projects."{name}"] sbom'))
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
        secrets=_secrets(secrets),
        hosts=_hosts(data.get("hosts", {})),
        assess=_assess(data.get("assess", {}), env, out),
        report=_report(data.get("report", {})),
        epss=_epss(data.get("epss", {})),
        releases=releases,
        digest=digest,
    )


# A key name that holds a credential (the config takes only names and paths: api_key_env, api_key_file, key)
_SECRET_KEY_RE = re.compile(r"(?i)(^|[_-])(api[_-]?key|apikey|token|secret|passw(or)?d|passphrase|"
                            r"credentials?|private[_-]?key|auth|bearer)($|[_-])")
_SECRET_KEY_OK = {"api_key_env", "api_key_file"}
# A value that carries a credential: user:password@ in a URL, a private key block, well-known token prefixes
_SECRET_VALUE_RE = re.compile(r"://[^/\s@:]*:[^/\s@]+@|-----BEGIN [A-Z ]*PRIVATE KEY|\b(gh[pousr]_|github_pat_|glpat-|"
                              r"xox[abprs]-|sk-[A-Za-z0-9_-]{16}|AKIA[0-9A-Z]{16})")


def _secret_like(data, where: str = "") -> list[str]:
    """Dotted names of keys whose name or string value looks like it holds a credential (never the value)."""
    found = []
    items = data.items() if isinstance(data, dict) else enumerate(data) if isinstance(data, list) else ()
    for key, value in items:
        name = f"{where}.{key}" if where else str(key)
        if isinstance(value, str) and (isinstance(key, str) and key not in _SECRET_KEY_OK
                                       and _SECRET_KEY_RE.search(key) or _SECRET_VALUE_RE.search(value)):
            found.append(name)
        elif isinstance(value, (dict, list)):
            found += _secret_like(value, name)
    return found


def commit_refusal(out: Path, digest: str | None) -> str | None:
    """Why `<out>/sbom-audit.toml` must not go into a run's commit, or None when it may.

    It may when it is a regular file (not a link) whose bytes are the ones `load` read (`digest`) and no key
    looks like it holds a credential. The config holds names and paths, never a key value (`load` refuses
    `[assess] api_key` and credentials in `base_url`); this check also catches a value pasted under a key the
    loader does not know. A reason names keys, never values."""
    path = Path(out) / CONFIG_NAME
    if digest is None or path.is_symlink() or not path.is_file():
        return "not read by this run"
    try:
        raw = path.read_bytes()
    except OSError:
        return "unreadable"
    if hashlib.sha256(raw).hexdigest() != digest:
        return "changed during the run; the next run commits it"
    try:
        data = tomllib.loads(raw.decode())
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        return "unreadable"
    found = _secret_like(data)
    if found:
        return (f"{', '.join(found[:5])} looks like it holds a credential; keep keys out of the config "
                "(api_key_env names the variable), then the next run commits it")
    return None


def remote_url(repo: Path) -> str | None:
    from .gitio import GIT_TIMEOUT, git_env
    try:
        proc = subprocess.run(["git", "-C", str(repo), "remote", "get-url", "origin"],
                              text=True, capture_output=True, env=git_env(), timeout=GIT_TIMEOUT)
    except subprocess.TimeoutExpired:
        return None
    url = proc.stdout.strip()
    return url if proc.returncode == 0 and url else None


def _project(cfg: Config, path: Path) -> Project:
    opts = cfg.projects.get(path.name, ProjectOpts())
    return Project(name=path.name, path=path, remote=remote_url(path),
                   production=opts.production, ignore=list(opts.ignore),
                   releases=release_opts(cfg, path.name), sbom=opts.sbom)


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
                             production=opts.production, ignore=list(opts.ignore),
                             releases=release_opts(cfg, name), sbom=opts.sbom))
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
        "# Assessment drafts by an OpenAI-compatible endpoint (`assess draft`); off until base_url and model",
        "# are set. Sends report excerpts to that endpoint. The key stays in the named environment variable.",
        "# [assess]",
        '# base_url = "https://openrouter.ai/api/v1"',
        '# model = "..."',
        '# api_key_env = "OPENROUTER_API_KEY"',
        "",
        "# Secret scanning (gitleaks).",
        "# [secrets]",
        "# enabled = true",
        "# Findings in tests, fixtures, examples, docs, vendored code, data files and dev setups rank one class",
        "# lower (labelled, counted, never dropped). Patterns per label add to the defaults in classes.toml:",
        '# "dir/" matches that directory anywhere in the path, anything else the file name (glob). `deployable`',
        "# lists paths that are never context. rank_by_context = false turns the ranking off.",
        "# rank_by_context = true",
        "# [secrets.context]",
        '# test = ["qa/"]',
        '# deployable = ["deploy/examples/"]',
        "",
        "# Management report (REPORT.html): organisation name on the cover, language en or de.",
        "# [report]",
        '# organisation = "..."',
        '# language = "en"',
        "",
        "# EPSS: FIRST's daily probability that a CVE is exploited in the next 30 days (one download of the",
        "# complete score file; nothing about your packages is sent). promote_at is a fraction (0.10 for 10%);",
        "# 0 turns promotion off. enabled = false skips the download.",
        "# [epss]",
        "# enabled = true",
        "# promote_at = 0.10",
        "",
        "# Release scanning (off until tags is set): one SBOM and audit per release tag for the newest `keep`",
        "# tags, and each release's support period (months from its date and/or an end date; both: the later).",
        '# Per project: releases = { tags = "app-v*", support_months = 24 } overrides key by key; false = off.',
        "# [releases]",
        '# tags = "v*"',
        "# keep = 3",
        "# support_months = 60",
        "# support_until = 2031-12-31",
        "# prereleases = false             # true also audits pre-release tags (-rc.1, -beta, -SNAPSHOT)",
        "",
        "# Per-project options: production = true puts CRITICAL/HIGH findings first;",
        "# ignore = [\"path/\"] drops subtrees from the inventory.",
        "# sbom = \"<path>\" takes the package list of the ecosystems a CycloneDX JSON build SBOM committed at that",
        "# path contains from it (read from the scanned commit); a file written by `import` wins over it.",
        "[projects]",
    ]
    for p in discovered or []:
        lines.append(f'# "{p.name}" = {{ production = false }}')
    lines.append('# [projects."<name>"]')
    lines.append('# github = "owner/repo"')
    lines.append('# sbom = "target/bom.json"')
    path.write_text("\n".join(lines) + "\n")
    return path
