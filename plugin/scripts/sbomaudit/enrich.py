"""Enrichment from public databases: CISA KEV, endoflife.date, package registries.

Every lookup goes through `fetch(url) -> obj` (injectable for tests) and the `Cache`.
Outbound hosts: www.cisa.gov, endoflife.date, registry.npmjs.org, pypi.org, jsr.io.
"""
from __future__ import annotations

import datetime as dt
import json
import urllib.error
import urllib.parse
import urllib.request

from . import __version__
from .cache import Cache
from .model import BranchInventory, Finding
from .versions import ver_key, ver_major

UA = f"sbom-audit/{__version__} (+https://github.com/Wuesteon/sbom-audit)"
HTTP_TIMEOUT = 60
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EOL_API = "https://endoflife.date/api"
EOL_SLUG = {"alpine": "alpine-linux"}          # readers' product name -> endoflife.date slug
EOL_SOON_DAYS = 90
LATEST_ECOSYSTEMS = ("npm", "PyPI", "jsr")


def http_get_json(url: str, timeout: int = HTTP_TIMEOUT):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        exc.close()      # the error carries the response body; callers read only .code
        raise


def http_post_json(url: str, body, timeout: int = HTTP_TIMEOUT):
    """POST `body` as JSON, return the decoded JSON answer; errors as in `http_get_json`."""
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), method="POST",
                                 headers={"User-Agent": UA, "Accept": "application/json",
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        exc.close()
        raise


def _definitive(exc: Exception) -> bool:
    """HTTP 404 is the database's own answer (unknown product, cycle or package): cacheable, not a failure."""
    return isinstance(exc, urllib.error.HTTPError) and exc.code == 404


def _describe(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"


# --------------------------------------------------------------------------- CISA KEV

def load_kev(cache: Cache, fetch=http_get_json) -> tuple[set[str], str | None]:
    """Set of CVE ids in the KEV catalog, plus an error message when the fetch failed."""
    cached = cache.get("kev-catalog")
    if cached:
        return set(cached), None
    try:
        data = fetch(KEV_URL)
        ids = sorted({v.get("cveID") for v in data.get("vulnerabilities", []) if v.get("cveID")})
    except Exception as exc:
        return set(), f"CISA KEV fetch failed: {type(exc).__name__}: {exc}"
    cache.put("kev-catalog", ids)
    return set(ids), None


def mark_kev(findings: list[Finding], kev: set[str]) -> int:
    """Set vuln["kev"] = True when the id or any alias is in the catalog; returns the count."""
    n = 0
    for f in findings:
        for v in f.vulns:
            ids = {v.get("id", "")} | set(v.get("aliases") or [])
            if ids & kev:
                v["kev"] = True
                n += 1
    return n


# --------------------------------------------------------------------------- endoflife.date

def eol_url(product: str, cycle: str) -> str:
    slug = EOL_SLUG.get(product, product)
    return f"{EOL_API}/{urllib.parse.quote(slug)}/{urllib.parse.quote(cycle)}.json"


def eol_status(data: dict | None, today: dt.date | None = None) -> tuple[str, str]:
    """-> (status, eol_date) with status EOL / EOL soon / supported / unknown."""
    today = today or dt.date.today()
    if not data or "error" in data:
        return "unknown", ""
    eol = data.get("eol")
    if eol is True:
        return "EOL", ""
    if eol is False or eol is None:
        return "supported", ""
    try:
        d = dt.date.fromisoformat(str(eol)[:10])
    except ValueError:
        return "unknown", str(eol)
    if d <= today:
        return "EOL", d.isoformat()
    if (d - today).days <= EOL_SOON_DAYS:
        return "EOL soon", d.isoformat()
    return "supported", d.isoformat()


def _eol_lookup(product: str, cycle: str, cache: Cache, fetch) -> tuple[dict, str | None]:
    """-> (data, fetch_error). A transient failure is returned, not cached: the next run retries it."""
    key = f"eol:{product}/{cycle}"
    cached = cache.get(key)
    if cached is not None:
        return cached, None
    try:
        data = fetch(eol_url(product, cycle))
        if not isinstance(data, dict):
            data = {"error": "unexpected response"}
    except Exception as exc:
        data = {"error": _describe(exc)}
        if not _definitive(exc):
            return data, data["error"]
    cache.put(key, data)
    return data, None


def _source(c) -> str:
    loc = c.locations[0] if c.locations else c.props.get("source", "")
    detail = c.props.get("detail", "")
    if loc and detail and detail != loc:
        return f"{loc}: {detail}"
    return loc or detail


def eol(inventories: list[BranchInventory], cache: Cache, fetch=http_get_json,
        today: dt.date | None = None) -> tuple[list[dict], list[dict]]:
    """One row per (project, branch, product, cycle) for every runtime component, plus the lookups
    that failed (`{"what": "<product>/<cycle>", "error": …}`), each product/cycle fetched once per run."""
    groups: dict[tuple, list[str]] = {}
    for inv in inventories:
        for c in inv.components:
            if c.kind != "runtime":
                continue
            key = (inv.project, inv.branch, c.ecosystem or c.name, c.version or "")
            groups.setdefault(key, [])
            src = _source(c)
            if src and src not in groups[key]:
                groups[key].append(src)
    rows: list[dict] = []
    failed: list[dict] = []
    memo: dict[tuple[str, str], dict] = {}
    for (project, branch, product, cycle), sources in sorted(groups.items()):
        if cycle:
            if (product, cycle) not in memo:
                memo[(product, cycle)], error = _eol_lookup(product, cycle, cache, fetch)
                if error:
                    failed.append({"what": f"{product}/{cycle}", "error": error})
            data = memo[(product, cycle)]
            status, eol_date = eol_status(data, today)
            latest = str(data.get("latest") or "") if "error" not in data else ""
        else:
            status, eol_date, latest = "unknown", "", ""
        rows.append({"project": project, "branch": branch, "product": product, "cycle": cycle,
                     "status": status, "eol_date": eol_date, "latest": latest,
                     "source": "; ".join(sources)})
    return rows, failed


# --------------------------------------------------------------------------- registries

def latest_url(ecosystem: str, name: str) -> str | None:
    if ecosystem == "npm":
        return f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}/latest"
    if ecosystem == "PyPI":
        return f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json"
    if ecosystem == "jsr":
        return f"https://jsr.io/{name}/meta.json"
    return None


def _latest_from(ecosystem: str, data) -> str | None:
    if not isinstance(data, dict):
        return None
    if ecosystem == "npm":
        return data.get("version")
    if ecosystem == "PyPI":
        return (data.get("info") or {}).get("version")
    if ecosystem == "jsr":
        return data.get("latest")
    return None


def _latest_lookup(ecosystem: str, name: str, cache: Cache, fetch) -> tuple[str | None, str | None]:
    """-> (latest version or None, fetch_error). A transient failure is not cached: retried next run."""
    url = latest_url(ecosystem, name)
    if not url:
        return None, None
    key = f"latest:{ecosystem}:{name}"
    cached = cache.get(key)
    if cached is not None:
        return cached.get("version"), None
    try:
        version = _latest_from(ecosystem, fetch(url))
    except Exception as exc:
        if not _definitive(exc):
            return None, _describe(exc)
        version = None
    cache.put(key, {"version": version})
    return version, None


def latest_version(ecosystem: str, name: str, cache: Cache, fetch=http_get_json) -> str | None:
    return _latest_lookup(ecosystem, name, cache, fetch)[0]


def latest(inventories: list[BranchInventory], cache: Cache, fetch=http_get_json) -> tuple[list[dict], list[dict]]:
    """Direct npm/PyPI/jsr dependencies at least one major version behind the registry, plus the
    lookups that failed (`{"what": "<ecosystem>:<name>", "error": …}`)."""
    rows: list[dict] = []
    failed: list[dict] = []
    seen: dict[tuple[str, str], str | None] = {}
    for inv in inventories:
        for c in inv.components:
            if c.kind != "package" or not c.direct or c.ecosystem not in LATEST_ECOSYSTEMS or not c.version:
                continue
            key = (c.ecosystem, c.name)
            if key not in seen:
                seen[key], error = _latest_lookup(c.ecosystem, c.name, cache, fetch)
                if error:
                    failed.append({"what": f"{c.ecosystem}:{c.name}", "error": error})
            newest = seen[key]
            cur_major, new_major = ver_major(c.version), ver_major(newest)
            if newest is None or cur_major is None or new_major is None:
                continue
            behind = new_major - cur_major
            if behind >= 1 and ver_key(newest) > ver_key(c.version):
                rows.append({"project": inv.project, "branch": inv.branch, "name": c.name,
                             "ecosystem": c.ecosystem, "current": c.version, "latest": newest,
                             "major_behind": behind, "scope": c.scope})
    return rows, failed


# --------------------------------------------------------------------------- fixes

def fixed_in(vuln: dict, version: str) -> str | None:
    """Smallest fixed version above the installed one, or None."""
    cur = ver_key(version)
    candidates = sorted((v for v in vuln.get("fixed") or [] if ver_key(v) > cur), key=ver_key)
    return candidates[0] if candidates else None
