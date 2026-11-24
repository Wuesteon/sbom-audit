"""OSV matching for a host's dpkg packages: the KEV join, the fix state and the running-kernel rule.

Spike (2026-11-09), osv-scanner 2.7.0: osv-scanner can do it but is not adopted. It
derives the distro from os-release and returns 0 results silently. On a fake root holding
`var/lib/dpkg/status` (openssl 3.0.2-0ubuntu1) and an Ubuntu 22.04 `etc/os-release`,
`osv-scanner scan source -L dpkg-status:<root>/var/lib/dpkg/status --format json` reported 75
`UBUNTU-CVE-*` ids with fixed versions and contacted only api.osv.dev. Without `<root>/etc/os-release`
it exits 0 with no packages, which reads as "clean". So this module asks osv.dev directly and names the
ecosystem in every query.

How a host is matched (outbound host: api.osv.dev only):
- Ecosystem from os-release: `Debian:<major>`, `Ubuntu:<version_id>:LTS` (even year, `.04`) or
  `Ubuntu:<version_id>`. No ecosystem (no VERSION_ID, as on Debian testing; other distributions) is a
  check error of kind "unsupported", never an empty clean result. An ecosystem osv.dev has no data
  for (EOL interim Ubuntu releases such as 23.04, or an outage answering 200 with empty results) is a
  "failed" one: the first request carries a sentinel query (`openssl` at version
  "0", one page) and an empty answer to it is `([], "osv.dev has no data for <eco>")`. No usable dpkg
  package at all is an error as well.
- One `POST /v1/querybatch` query per distinct (source package, source version), at most 1000 per request,
  following each result's `next_page_token`. Signed kernels are queried as their unsigned source (osv.dev
  files kernel CVEs under `linux`, `linux-hwe-6.8`, …, never `linux-signed*`) with the binary version
  (Debian's `linux-signed-amd64` carries its own version, e.g. `6.1.112+1` for linux `6.1.112-1`).
  Other signed sources (grub2-signed, shim-signed, fwupd-signed, Debian's `*-amd64-signed`) use a
  version scheme of their own (`1.202+2.12-1ubuntu7`), so they are not mapped: one `info` finding lists
  them as not assessed.
- An upgradable package is also queried at its apt candidate version: an id open at the installed version
  but not at the candidate is fixed by the pending update. That answers "how many does the update fix"
  without one record fetch per id (a host has 1–2k packages; a kernel record alone is ~450 KB). The
  candidate is a binary version: it is mapped to a source version the way the installed binary version
  maps to the source version (dropping an epoch or a `+bN` binNMU suffix the source lacks: bsdutils
  `1:2.38.1-5+deb12u1` is util-linux `2.38.1-5+deb12u1`). Any other relation (cpp `4:12.2.0-3` from
  gcc-defaults `1.203`) makes the candidate incomparable: a released fix gets the fix state "unknown"
  and the summary says "update to <candidate> pending, coverage unknown".
- KEV join by CVE: `UBUNTU-CVE-*` / `DEBIAN-CVE-*` ids name their CVE, so the join needs no record. Only
  ids whose CVE is in KEV get `GET /v1/vulns/<id>` (for the fix state), cached in the injected `Cache`
  (`.cache/osv-hosts`, 24 h), refetched when the querybatch `modified` for the id changes, trimmed to this host's
  ecosystem and its Ubuntu Pro ecosystem before caching. Aggregate advisories (USN/DSA/DLA) are not
  looked at for KEV: their CVEs come as `UBUNTU-CVE-*` / `DEBIAN-CVE-*` ids in the same answer.
- Fix state of a KEV finding: "installable" (apt candidate ≥ the smallest distro fix above the installed
  version, or the id is gone at the candidate), "reboot" (running kernel only: a kernel image of the same
  source at or above the fix is installed but not booted), "not installable" (a distro fix is released but
  apt's candidate does not reach it: stale lists or a phased update; for the kernel, no fixed kernel
  image is installed yet), "pro-only" (no distro fix; the
  `Ubuntu:Pro:<version_id>:LTS` entry has one), "not released", or "unknown" (the record fetch failed).
- Running-kernel rule: binaries built from a kernel source (the source of any `linux-image-<abi>`-like
  package, plus `linux` itself) count for KEV only when their name contains the running kernel release
  (`uname -r`); the others get an `info` finding. An unknown running kernel, or one that no installed
  kernel package carries (an `info` finding says so), counts every kernel image and modules package (fail
  closed); linux-libc-dev, headers and tools never count. Without any kernel image the running kernel is
  reported as not assessable.
- Every other open vulnerability counts into one non-critical `vuln` summary per binary package.
"""
from __future__ import annotations

import re
import urllib.parse
from pathlib import Path

from .. import epss
from ..cache import Cache
from ..enrich import http_get_json, http_post_json
from . import debver

QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/"
BATCH = 1000
MAX_ROUNDS = 100                       # pagination rounds; osv.dev pages are 1000 ids, `linux` has ~10
CACHE_DIR = Path(".cache") / "osv-hosts"
CACHE_TTL_HOURS = 24

CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")
AGGREGATE = re.compile(r"^(USN|DSA|DLA|DTSA|ELA)-")
KERNEL_BINARY = re.compile(r"^linux-(image|modules|modules-extra|headers|tools|cloud-tools|buildinfo|lib-rust)"
                           r"(-unsigned)?-\d+\.\d+")
KERNEL_IMAGE = re.compile(r"^linux-image-(unsigned-)?\d+\.\d+")
RUNNABLE_KERNEL = re.compile(r"^linux-(image-(unsigned-)?|modules-)")   # can carry the running kernel
SIGNED_SOURCE = re.compile(r"-signed($|-)")    # grub2-signed, shim-signed, fwupd-amd64-signed, …
BINNMU = re.compile(r"\+b\d+$")
SENTINEL: tuple[str, str] = ("openssl", "0")             # every Debian/Ubuntu release osv.dev covers has openssl records
GROUP_ORDER = {"kev": 0, "vuln": 1, "info": 2}


class OsvError(str):
    """The error text of `match`, with `.kind`: "unsupported" (no osv.dev ecosystem for this OS: the check
    cannot apply) or "failed" (the check did not run or is incomplete: no data for the ecosystem, network or
    HTTP errors, malformed answers, failed record fetches, no packages). Callers branch on `.kind`, never on
    the text."""
    kind: str

    def __new__(cls, text: str, kind: str = "failed") -> "OsvError":
        if kind not in ("unsupported", "failed"):
            raise ValueError(f"unknown osv error kind: {kind}")
        err = super().__new__(cls, text)
        err.kind = kind
        return err


def cache_for(out: Path) -> Cache:
    return Cache(Path(out) / CACHE_DIR, ttl_hours=CACHE_TTL_HOURS)


# --------------------------------------------------------------------------- ecosystem and ids

def ecosystem(os: dict | None) -> str | None:
    os = os or {}
    os_id, version = (os.get("id") or "").lower(), os.get("version_id") or ""
    if os_id == "debian" and re.fullmatch(r"\d+(\.\d+)*", version):
        return f"Debian:{version.split('.')[0]}"
    m = re.fullmatch(r"(\d+)\.(\d+)", version)
    if os_id == "ubuntu" and m:
        lts = int(m.group(1)) % 2 == 0 and m.group(2) == "04"
        return f"Ubuntu:{version}:LTS" if lts else f"Ubuntu:{version}"
    return None


def _pro_ecosystem(eco: str) -> str | None:
    m = re.fullmatch(r"Ubuntu:([\d.]+):LTS", eco)
    return f"Ubuntu:Pro:{m.group(1)}:LTS" if m else None


def _unsupported(os: dict | None) -> OsvError:
    os = os or {}
    what = " ".join(x for x in (os.get("id"), os.get("version_id") or os.get("codename")) if x)
    return OsvError(f"vulnerability matching unsupported for {what or 'unknown OS'}", "unsupported")


def cves(vuln: dict) -> set[str]:
    """CVE ids of an OSV record: the id itself (after `UBUNTU-`/`DEBIAN-`), aliases, upstream, related."""
    found = set()
    vid = re.sub(r"^(UBUNTU|DEBIAN)-", "", str(vuln.get("id") or ""))
    if CVE_RE.match(vid):
        found.add(vid)
    for field in ("aliases", "upstream", "related"):
        for x in vuln.get(field) or []:
            if isinstance(x, str) and CVE_RE.match(x):
                found.add(x)
    return found


def _id_cve(vid: str) -> str | None:
    c = cves({"id": vid})
    return next(iter(c)) if c else None


# --------------------------------------------------------------------------- queries

def _query_key(p: dict, eco: str) -> tuple[str, str]:
    """(osv package name, version) for one installed binary package."""
    source = p.get("source") or p["name"]
    if source.startswith("linux-signed"):
        name = "linux" if eco.startswith("Debian:") else "linux" + source[len("linux-signed"):]
        return name, p["version"]
    return source, p.get("source_version") or p["version"]


def _source_candidate(p: dict, key: tuple[str, str], candidate: str | None) -> str | None:
    """apt's candidate is a binary version; osv.dev's are source versions. Map it the way the installed
    binary version maps to the installed source version (dropping an epoch or a `+bN` binNMU suffix the
    source lacks); None when that relation is anything else, so the fix state stays conservative."""
    if not candidate or key[1] == p["version"]:
        return candidate

    def to_source(v: str) -> str:
        head, sep, rest = v.partition(":")
        if sep and head.isdigit() and ":" not in key[1]:
            v = rest
        if not BINNMU.search(key[1]):
            v = BINNMU.sub("", v)
        return v
    return to_source(candidate) if to_source(p["version"]) == key[1] else None


def _querybatch(keys: list[tuple[str, str]], eco: str, post) -> dict[tuple[str, str], dict[str, str | None]]:
    """{(name, version): {vuln id: modified}}; raises on any failure or malformed answer. The first request
    also carries the SENTINEL query (one page only): its answer says whether osv.dev has data for `eco`."""
    found: dict[tuple[str, str], dict[str, str | None]] = {k: {} for k in keys}
    found[SENTINEL] = {}
    pending: list[tuple[tuple[str, str], str | None]] = [(k, None) for k in [SENTINEL, *keys]]
    rounds = 0
    while pending:
        rounds += 1
        if rounds > MAX_ROUNDS:
            raise ValueError(f"pagination did not end after {MAX_ROUNDS} rounds")
        following: list[tuple[tuple[str, str], str | None]] = []
        for i in range(0, len(pending), BATCH):
            chunk = pending[i:i + BATCH]
            queries = []
            for (name, version), token in chunk:
                q = {"package": {"name": name, "ecosystem": eco}, "version": version}
                if token:
                    q["page_token"] = token
                queries.append(q)
            answer = post(QUERYBATCH_URL, {"queries": queries})
            results = answer.get("results") if isinstance(answer, dict) else None
            if not isinstance(results, list) or len(results) != len(chunk):
                raise ValueError("unexpected querybatch answer")
            for (key, _), r in zip(chunk, results):
                vulns = r.get("vulns", []) if isinstance(r, dict) else None
                if not isinstance(vulns, list):
                    raise ValueError("unexpected querybatch answer")
                for v in vulns:
                    if not isinstance(v, dict) or not isinstance(v.get("id"), str):
                        raise ValueError("unexpected querybatch answer")
                    found[key][v["id"]] = v.get("modified")
                if r.get("next_page_token") and key != SENTINEL:
                    following.append((key, str(r["next_page_token"])))
        pending = following
    return found


def _record(vid: str, modified: str | None, ecos: set[str], cache: Cache, fetch) -> dict:
    """The OSV record (trimmed to `ecos`), from the cache while the querybatch's `modified` for the id is the
    one it was fetched under; raises when the fetch fails."""
    key = f"vuln:{'+'.join(sorted(ecos))}:{vid}"
    cached = cache.get(key)
    if isinstance(cached, dict) and isinstance(cached.get("record"), dict) and cached.get("listed") == modified:
        return cached["record"]
    rec = fetch(VULN_URL + urllib.parse.quote(vid, safe=""))
    if not isinstance(rec, dict) or rec.get("id") != vid:
        raise ValueError("unexpected record")
    trimmed = {k: rec[k] for k in ("id", "modified", "aliases", "upstream", "related") if k in rec}
    trimmed["affected"] = [a for a in _dicts(rec.get("affected"))
                           if isinstance(a.get("package"), dict) and a["package"].get("ecosystem") in ecos]
    cache.put(key, {"listed": modified, "record": trimmed})
    return trimmed


def _dicts(x) -> list[dict]:
    return [d for d in x if isinstance(d, dict)] if isinstance(x, list) else []


def _fixed_in(records: list[dict], eco: str | None, name: str, installed: str) -> str | None:
    """Smallest `fixed` event above the installed version for (eco, name) across the records."""
    fixes = []
    for rec in records:
        for a in _dicts(rec.get("affected")):
            p = a.get("package")
            if not isinstance(p, dict) or p.get("ecosystem") != eco or p.get("name") != name:
                continue
            for r in _dicts(a.get("ranges")):
                for e in _dicts(r.get("events")):
                    f = e.get("fixed")
                    if isinstance(f, str) and debver.compare(f, installed) > 0:
                        fixes.append(f)
    best = None
    for f in fixes:
        if best is None or debver.compare(f, best) < 0:
            best = f
    return best


def _fix_state(records, gone_at_candidate: bool, eco, name, installed, candidate,
               newest_kernel: str | None = None, incomparable: bool = False) -> tuple[str, str | None]:
    """`newest_kernel`: for the running kernel, the newest installed kernel image of the same source (a
    kernel fix arrives as a new package name, so apt's candidate for the running one never reaches it)."""
    fixed = _fixed_in(records, eco, name, installed)
    if fixed:
        if candidate and debver.compare(candidate, fixed) >= 0:
            return "installable", fixed
        if gone_at_candidate:
            return "installable", fixed
        if newest_kernel and debver.compare(newest_kernel, fixed) >= 0:
            return "reboot", fixed
        if incomparable:                    # apt has a binary candidate that does not map to a source version
            return "unknown", fixed
        return "not installable", fixed
    if gone_at_candidate:
        return "installable", None
    pro = _pro_ecosystem(eco)
    pro_fixed = _fixed_in(records, pro, name, installed) if pro else None
    if pro_fixed:
        return "pro-only", pro_fixed
    return "not released", None


def _fix_text(fix: str, fixed: str | None, candidate: str | None, kernel: bool = False,
              running_known: bool = True) -> str:
    if fix == "installable":
        return f"fix installable (candidate {candidate})" if not fixed else \
            f"fix {fixed} installable (candidate {candidate})"
    if fix == "reboot":
        return f"fixed kernel {fixed} installed, reboot needed" if running_known else \
            f"fixed kernel {fixed} installed, reboot needed unless it is the running one"
    if fix == "not installable":
        if kernel:
            return f"fix {fixed} released, no fixed kernel installed yet"
        return f"fix {fixed} released, apt candidate {candidate or 'none'} (stale lists or phased update)"
    if fix == "pro-only":
        return f"fix {fixed} only through Ubuntu Pro"
    if fix == "unknown":
        if fixed:
            return f"fix {fixed} released; apt candidate {candidate} cannot be compared with source versions"
        return "fix state unknown (osv.dev record failed)"
    return "no fix released"


def _plural(n: int) -> str:
    return f"{n} open CVE" if n == 1 else f"{n} open CVEs"


def _keys(ids) -> set[str]:
    """Count keys: the CVE an id names, else the id; aggregate advisories only when nothing else is there."""
    plain = {_id_cve(i) or i for i in ids if not AGGREGATE.match(i)}
    return plain or set(ids)


# --------------------------------------------------------------------------- match

def match(facts: dict, kev: set[str], cache: Cache, post=http_post_json,
          fetch=http_get_json, epss_scores: epss.Scores | None = None) -> tuple[list[dict], OsvError | None]:
    """Findings (groups `kev`, `vuln`, `info`) and an `OsvError` or None. Never raises for bad input or a
    failed osv.dev: no ecosystem is `([], <kind "unsupported">)`; no data for the ecosystem or a failed
    querybatch is `([], <kind "failed">)`; failed record fetches keep the findings (fix "unknown") and return
    a "failed" error too.

    With `epss_scores` (the EPSS step ran; `{}` when no score file was available) every `kev` and `info:kev:`
    finding gets `epss` and `epss_percentile` of its CVE, every `vuln` finding `max_epss`, the highest score
    among the CVEs of its open ids, and `max_epss_cve`, the CVE that has it; both None without a score.
    Information only: no id, text or flag depends on it."""
    os = facts.get("os") if isinstance(facts.get("os"), dict) else None
    eco = ecosystem(os)
    if eco is None:
        return [], _unsupported(os)
    pro = _pro_ecosystem(eco)
    ecos = {eco} | ({pro} if pro else set())
    upgradable = facts.get("upgradable")
    upgradable = upgradable if isinstance(upgradable, dict) else {}
    running = facts.get("kernel")
    running = running if isinstance(running, str) else ""
    packages = facts.get("packages")
    packages = packages if isinstance(packages, list) else []

    # (name, version) -> (package, query key, apt candidate (binary), candidate as source version)
    binaries: dict[tuple[str, str], tuple[dict, tuple[str, str], str | None, str | None]] = {}
    for p in packages:
        if not isinstance(p, dict) or not all(isinstance(p.get(f), str) and p[f] for f in ("name", "version")):
            continue
        source, source_version = p.get("source"), p.get("source_version")
        p = {**p, "source": source if isinstance(source, str) else None,
             "source_version": source_version if isinstance(source_version, str) else None}
        key = _query_key(p, eco)
        up = upgradable.get(p["name"])
        up = up if isinstance(up, dict) else {}
        cand = up.get("candidate")
        candidate = cand if isinstance(cand, str) and debver.compare(cand, p["version"]) > 0 else None
        binaries.setdefault((p["name"], p["version"]), (p, key, candidate, _source_candidate(p, key, candidate)))
    if not binaries:
        return [], OsvError("no dpkg packages: dpkg section missing or failed")

    keys = {key for _, key, _, _ in binaries.values()}
    keys |= {(key[0], src_cand) for _, key, _, src_cand in binaries.values() if src_cand}
    try:
        found = _querybatch(sorted(keys), eco, post)
    except Exception as exc:
        return [], OsvError(f"osv.dev: {type(exc).__name__}: {exc}")
    if not found.pop(SENTINEL):
        return [], OsvError(f"osv.dev has no data for {eco}")

    kernel_sources = {key[0] for (name, _), (_, key, _, _) in binaries.items() if KERNEL_BINARY.match(name)}
    if any(k[0] == "linux" for k in keys):
        kernel_sources.add("linux")
    newest_image: dict[str, str] = {}      # kernel source -> newest installed kernel image version
    for (name, version), (_, key, _, _) in binaries.items():
        if KERNEL_IMAGE.match(name) and (key[0] not in newest_image
                                         or debver.compare(version, newest_image[key[0]]) > 0):
            newest_image[key[0]] = version
    kernel_names = [name for (name, _), (_, key, _, _) in binaries.items() if key[0] in kernel_sources]
    runnable = [name for name in kernel_names if RUNNABLE_KERNEL.match(name)]
    # fail closed: an unknown running kernel, or one no installed package carries, counts every kernel image
    # and modules package; libc-dev, headers and tools never carry a running kernel
    running_known = bool(running) and any(running in name for name in runnable)

    records: dict[str, dict | None] = {}
    failures: list[str] = []

    def record_for(vid: str, modified):
        if vid not in records:
            try:
                records[vid] = _record(vid, modified, ecos, cache, fetch)
            except Exception as exc:
                records[vid] = None
                failures.append(f"{vid}: {type(exc).__name__}: {exc}")
        return records[vid]

    findings: list[dict] = []
    if kernel_names and not runnable:
        findings.append({"id": f"info:running-kernel:{running or 'unknown'}", "group": "info", "critical": False,
                         "text": f"running kernel {running or 'unknown'} not assessable: no kernel image installed",
                         "kernel": running})
    elif running and runnable and not running_known:
        findings.append({"id": f"info:running-kernel:{running}", "group": "info", "critical": False,
                         "text": f"running kernel {running} not among installed packages; "
                                 "every installed kernel package is assessed", "kernel": running})
    signed = sorted({key[0] for _, key, _, _ in binaries.values() if SIGNED_SOURCE.search(key[0])})
    if signed:
        findings.append({"id": "info:signed-sources", "group": "info", "critical": False,
                         "text": "not assessed (CVEs are tracked under the unsigned source): " + ", ".join(signed),
                         "sources": signed})
    for (name, version), (p, key, candidate, src_cand) in sorted(binaries.items()):
        open_ids = found.get(key, {})
        if not open_ids:
            continue
        at_candidate = set(found.get((key[0], src_cand), {})) if src_cand else None
        kev_cves: dict[str, list[str]] = {}
        for vid in sorted(open_ids):
            cve = _id_cve(vid)
            if cve and cve in kev:
                kev_cves.setdefault(cve, []).append(vid)
        is_kernel = key[0] in kernel_sources
        if not is_kernel:
            counts = True
        elif running_known:
            counts = running in name
        else:
            counts = bool(RUNNABLE_KERNEL.match(name))
        incomparable = bool(candidate) and not src_cand
        newest_kernel = newest_image.get(key[0]) if is_kernel and counts else None
        for cve, vids in sorted(kev_cves.items()):
            recs = [record_for(v, open_ids[v]) for v in vids]
            gone = at_candidate is not None and not (set(vids) & at_candidate)
            if any(r is None for r in recs):
                fix, fixed = ("installable", None) if gone else ("unknown", None)
            else:
                fix, fixed = _fix_state(recs, gone, eco, key[0], key[1], src_cand, newest_kernel, incomparable)
            common = {"cve": cve, "package": name, "version": version, "source": key[0], "vulns": vids,
                      "fix": fix, "fixed": fixed, "candidate": candidate}
            if epss_scores is not None:
                common["epss"], common["epss_percentile"] = epss.score_of([cve], epss_scores)
            if counts:
                findings.append({"id": f"kev:{cve}:{name}@{version}", "group": "kev", "critical": True,
                                 "text": f"{cve} (KEV) in {name} {version}: "
                                         f"{_fix_text(fix, fixed, candidate, is_kernel, running_known)}",
                                 **common})
            else:
                findings.append({"id": f"info:kev:{cve}:{name}@{version}", "group": "info", "critical": False,
                                 "text": f"{cve} (KEV) in {name} {version}, a kernel package that is not the running kernel",
                                 **common})
        rest = [v for v in open_ids if _id_cve(v) not in kev_cves]
        open_keys = _keys(rest) - set(kev_cves)
        if not open_keys:
            continue
        fixable = 0
        if at_candidate is not None:
            fixable = len(open_keys - _keys(at_candidate))
        if incomparable:
            outlook = f"update to {candidate} pending, coverage unknown"
        elif fixable:
            outlook = f"{fixable} fixed by the installable update to {candidate}"
        else:
            outlook = "no fix installable"
        text = f"{_plural(len(open_keys))}, {outlook}"
        summary = {"id": f"vuln:{name}@{version}", "group": "vuln", "critical": False, "text": text,
                   "package": name, "version": version, "source": key[0], "open": len(open_keys),
                   "fixable": fixable, "candidate": candidate}
        if epss_scores is not None:
            summary["max_epss_cve"], summary["max_epss"] = epss.top({_id_cve(v) for v in rest} - {None}, epss_scores)
        findings.append(summary)

    findings.sort(key=lambda f: (GROUP_ORDER[f["group"]], f["id"]))
    error = None
    if failures:
        error = OsvError(f"osv.dev: {len(failures)} vulnerability record(s) failed: {failures[0]}")
    return findings, error
