"""Host mode: binaries installed outside the package manager, checked against their upstream releases.

`vendors.toml` names the binaries to look up and where their releases live (format in that file). A
binary that a package owns (`owner` set) is the package manager's business and is skipped, as is any
binary without an entry. Lookups go through `fetch(url) -> obj` (injectable) and the `Cache` (24 h).
Outbound hosts: api.github.com, endoflife.date. `os_eol` checks the OS release itself on endoflife.date.

A failed lookup never raises: it becomes a non-critical `info` finding `vendor:<name>:lookup-failed`, so a
network problem is visible in the report and never reads as "up to date".
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

from .. import enrich
from ..cache import Cache
from ..enrich import http_get_json

VENDORS_TOML = Path(__file__).with_name("vendors.toml")
GITHUB_URL = "https://api.github.com/repos/{repo}/releases/latest"
CACHE_DIR = Path(".cache") / "vendors"
CACHE_TTL_HOURS = 24


def cache_for(out: Path) -> Cache:
    return Cache(Path(out) / CACHE_DIR, ttl_hours=CACHE_TTL_HOURS)


def load(path: Path = VENDORS_TOML) -> dict[str, dict]:
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def _tuple(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split("."))


def _extract(pattern: str, text: str) -> str | None:
    m = re.search(pattern, text or "")
    return m.group(1) if m else None


def _lookup(key: str, url: str, cache: Cache, fetch, valid):
    """Cached answer, else fetched; only an answer that `valid(data)` accepts is cached."""
    cached = cache.get(key)
    if cached is not None and valid(cached):
        return cached
    data = fetch(url)
    if not valid(data):
        raise ValueError("unexpected answer from upstream")
    cache.put(key, data)
    return data


def _failed(name: str, installed: str, exc: Exception) -> dict:
    reason = f"{type(exc).__name__}: {exc}"[:200]
    return {"id": f"vendor:{name}:lookup-failed", "group": "info", "critical": False,
            "text": f"{name} {installed}: upstream release lookup failed ({reason})", "binary": name}


def _github(name: str, spec: dict, installed: str, cache: Cache, fetch) -> list[dict]:
    repo = spec["repo"]
    pattern = spec["version"]

    def valid(data) -> bool:
        return isinstance(data, dict) and _extract(pattern, str(data.get("tag_name") or "")) is not None

    data = _lookup(f"github-{repo}", GITHUB_URL.format(repo=repo), cache, fetch, valid)
    latest = _extract(pattern, data["tag_name"])
    if _tuple(latest) <= _tuple(installed):
        return []
    return [{"id": f"vendor:{name}", "group": "third_party", "critical": False, "binary": name,
             "installed": installed, "latest": latest,
             "text": f"{name} {installed} → {latest} (github {repo})"}]


def _endoflife(name: str, spec: dict, installed: str, cache: Cache, fetch) -> list[dict]:
    product = spec["product"]
    cycle = installed.split(".")[0]
    data = _lookup(f"eol-{product}-{cycle}", enrich.eol_url(product, cycle), cache, fetch,
                   lambda d: isinstance(d, dict) and "error" not in d and ("latest" in d or "eol" in d))
    findings = []
    latest = data.get("latest")
    if isinstance(latest, str) and re.fullmatch(r"\d+(\.\d+)*", latest) and len(latest.split(".")) == 3 \
            and _tuple(latest) > _tuple(installed):
        findings.append({"id": f"vendor:{name}", "group": "third_party", "critical": False, "binary": name,
                         "installed": installed, "latest": latest,
                         "text": f"{name} {installed} → {latest} (endoflife.date {product} {cycle})"})
    status, eol_date = enrich.eol_status(data)
    if status in ("EOL", "EOL soon"):
        when = f" {eol_date}" if eol_date else ""
        findings.append({"id": f"vendor:{name}:eol", "group": "third_party", "critical": False,
                         "binary": name, "installed": installed, "eol": eol_date or True,
                         "text": f"{name} {installed}: {product} {cycle} is {status}{when}"})
    return findings


SOURCES = {"github": _github, "endoflife": _endoflife}
OS_PRODUCTS = ("ubuntu", "debian")
PAID_SUPPORT = {"ubuntu": "Ubuntu Pro (ESM)", "debian": "paid Extended LTS"}


def os_eol(os_: dict, cache: Cache, fetch=http_get_json, today=None) -> list[dict]:
    """`os:eol` when the Ubuntu or Debian release itself is past (critical) or near (not critical) the end of its
    free security support, from endoflife.date (cycle: Ubuntu `version_id`, Debian major). A failed lookup is
    the non-critical `info:os-eol-unavailable`, never a crash and never "supported"."""
    product, version = str(os_.get("id") or "").lower(), str(os_.get("version_id") or "")
    if product not in OS_PRODUCTS or not version:
        return []
    cycle = version if product == "ubuntu" else version.split(".")[0]
    def unavailable(reason: str) -> list[dict]:
        return [{"id": "info:os-eol-unavailable", "group": "info", "critical": False, "os": f"{product} {cycle}",
                 "text": f"{product} {cycle}: end-of-life lookup failed ({reason[:200]}); the release's support "
                         "state was not checked"}]

    try:
        data = _lookup(f"eol-os-{product}-{cycle}", enrich.eol_url(product, cycle), cache, fetch,
                       lambda d: isinstance(d, dict) and "error" not in d and "eol" in d)
        status, eol_date = enrich.eol_status(data, today)
    except Exception as exc:
        return unavailable(f"{type(exc).__name__}: {exc}")
    if status == "unknown":   # e.g. an `eol` value that is no date: not "supported", not silence
        return unavailable(f"unreadable end-of-life date {eol_date!r}" if eol_date else "no usable answer")
    if status not in ("EOL", "EOL soon"):
        return []
    extended = data.get("extendedSupport")
    paid = f"; {PAID_SUPPORT[product]} until {extended}" if isinstance(extended, str) else ""
    text = (f"{product} {cycle} reached the end of its security support{f' on {eol_date}' if eol_date else ''}: "
            "no more free security updates, upgrade the release" if status == "EOL"
            else f"{product} {cycle} ends its security support on {eol_date}: plan the release upgrade")
    return [{"id": "os:eol", "group": "patch", "critical": status == "EOL", "os": f"{product} {cycle}",
             "eol": eol_date or True, "text": text + paid}]


def check(binaries: list[dict], cache: Cache, fetch=http_get_json, specs: dict | None = None) -> list[dict]:
    specs = load() if specs is None else specs
    findings: list[dict] = []
    for b in binaries:
        name = b.get("name")
        spec = specs.get(name)
        if spec is None or b.get("owner") or b.get("untrusted"):  # untrusted: rules.permissive reports it
            continue
        installed = b.get("version", "")
        try:    # a malformed vendors.toml entry or a failed lookup must never break the host check
            found = _extract(spec["version"], installed)
            if found is None:
                findings.append({"id": f"vendor:{name}:version-unknown", "group": "info", "critical": False,
                                 "binary": name, "text": f"{name}: version not recognised in {installed!r}"})
                continue
            installed = found
            findings += SOURCES[spec["source"]](name, spec, installed, cache, fetch)
        except Exception as exc:
            findings.append(_failed(name, installed, exc))
    return findings
