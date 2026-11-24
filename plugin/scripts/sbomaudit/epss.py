"""EPSS: FIRST's daily probability that a CVE is exploited in the next 30 days.

One GET of the complete daily score file (no query string, no per-CVE call), so nothing about the audited
packages is sent. Outbound host: epss.empiricalsecurity.com.

The raw `.csv.gz` is kept as `<cache dir>/epss-scores.csv.gz` next to the cache entry `epss-meta` (score date,
model version, row count, SHA-256 of the file) and parsed on every run. When the download fails, an older
cached file is used ("stale") rather than none.
"""
from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import io
import math
import re
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass

from .cache import Cache, atomic_write_bytes
from .enrich import HTTP_TIMEOUT, UA
from .model import Finding

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
DEFAULT_THRESHOLD = 0.10
MAX_DOWNLOAD = 64 * 1024 * 1024       # bytes of gzip read from the network
MAX_UNPACKED = 64 * 1024 * 1024       # bytes after decompression (the real file is about 12 MB)
CACHE_FILE = "epss-scores.csv.gz"     # in cache.dir
META_KEY = "epss-meta"                # Cache entry: {"score_date", "model_version", "entries", "sha256"}

Scores = dict[str, tuple[float, float]]          # "CVE-2021-23337" -> (epss, percentile)

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass(frozen=True)
class Epss:
    scores: Scores
    score_date: str | None        # from the file's comment line, e.g. "2026-11-23T12:00:23Z"
    model_version: str | None     # e.g. "v2026.06.15"
    fetched_at: float | None      # epoch seconds the file in use was downloaded
    origin: str | None            # "live" | "cache" | "stale" | None (nothing loaded)
    error: str | None             # set only when there are no scores
    warning: str | None           # set only for origin "stale": why the download failed

    @property
    def available(self) -> bool:
        return bool(self.scores)


def http_get_bytes(url: str, timeout: int = HTTP_TIMEOUT, limit: int = MAX_DOWNLOAD) -> bytes:
    """GET `url` over https only (also after redirects); more than `limit` bytes is a ValueError."""
    if not url.startswith("https://"):
        raise ValueError(f"refusing a non-https URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/gzip"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            final = resp.geturl()
            if not final.startswith("https://"):
                raise ValueError(f"refusing a redirect to a non-https URL: {final}")
            body = resp.read(limit + 1)
    except urllib.error.HTTPError as exc:
        exc.close()      # the error carries the response body; nobody reads it
        raise
    if len(body) > limit:
        raise ValueError(f"download larger than {limit} bytes")
    return body


def parse(raw: bytes) -> tuple[Scores, dict]:
    """Scores from a gzip'd EPSS file, plus {"score_date", "model_version", "entries"}; ValueError when the
    file is not gzip, unpacks to more than MAX_UNPACKED bytes or has no valid row."""
    try:
        data = gzip.GzipFile(fileobj=io.BytesIO(raw)).read(MAX_UNPACKED + 1)
    except (OSError, EOFError, zlib.error) as exc:
        raise ValueError(f"EPSS file is not a complete gzip file: {type(exc).__name__}: {exc}") from exc
    if len(data) > MAX_UNPACKED:
        raise ValueError(f"EPSS file unpacks to more than {MAX_UNPACKED} bytes")
    lines = data.decode("utf-8", errors="replace").splitlines()

    comment: dict[str, str] = {}
    if lines and lines[0].startswith("#"):
        for pair in lines[0][1:].split(","):
            key, sep, value = pair.partition(":")
            if sep:
                comment[key.strip()] = value.strip()

    scores: Scores = {}
    in_rows = False
    for line in lines:
        if not in_rows:
            in_rows = line.startswith("cve,")
            continue
        parts = line.split(",")
        if len(parts) < 3:
            continue
        cve = parts[0].strip().upper()
        if not _CVE.match(cve):
            continue
        try:
            score, percentile = float(parts[1]), float(parts[2])
        except ValueError:
            continue
        if not (math.isfinite(score) and math.isfinite(percentile)
                and 0.0 <= score <= 1.0 and 0.0 <= percentile <= 1.0):
            continue
        scores[cve] = (score, percentile)
    if not scores:
        raise ValueError("EPSS file has no scores")
    return scores, {"score_date": comment.get("score_date"), "model_version": comment.get("model_version"),
                    "entries": len(scores)}


def _read_cached(cache: Cache, sha256: str | None = None) -> tuple[Scores, dict] | None:
    """The cached file, parsed; None when missing, unreadable, not matching `sha256` (when given) or invalid."""
    try:
        raw = (cache.dir / CACHE_FILE).read_bytes()
    except OSError:
        return None
    if sha256 is not None and hashlib.sha256(raw).hexdigest() != sha256:
        return None
    try:
        return parse(raw)
    except ValueError:
        return None


def _epss(scores: Scores, meta: dict, fetched_at: float | None, origin: str, warning: str | None = None) -> Epss:
    return Epss(scores=scores, score_date=meta.get("score_date"), model_version=meta.get("model_version"),
                fetched_at=fetched_at, origin=origin, error=None, warning=warning)


def load(cache: Cache, fetch=None) -> Epss:
    """Today's scores: the cached file while its meta entry is fresh, else a download, else (download
    failed) an older cached file as "stale", else no scores with `error` set. Never raises."""
    fetch = fetch or http_get_bytes
    meta = cache.get(META_KEY)
    if isinstance(meta, dict) and isinstance(meta.get("sha256"), str):
        cached = _read_cached(cache, meta["sha256"])
        if cached:
            return _epss(*cached, cache.stored_at(META_KEY), "cache")
    try:
        raw = fetch(EPSS_URL)
        scores, info = parse(raw)
    except Exception as exc:
        stale = _read_cached(cache)
        if stale:
            return _epss(*stale, cache.stored_at(META_KEY), "stale",
                         warning=f"EPSS download failed: {type(exc).__name__}: {exc}")
        return Epss(scores={}, score_date=None, model_version=None, fetched_at=None, origin=None,
                    error=f"EPSS fetch failed: {type(exc).__name__}: {exc}", warning=None)
    try:
        atomic_write_bytes(cache.dir / CACHE_FILE, raw)
        cache.put(META_KEY, {**info, "sha256": hashlib.sha256(raw).hexdigest()})
        fetched_at = cache.stored_at(META_KEY)
    except OSError:
        fetched_at = None        # the scores are good; the next run downloads again
    return _epss(scores, info, fetched_at, "live")


def score_of(ids, scores: Scores) -> tuple[float | None, float | None]:
    """(epss, percentile) of the highest-scoring CVE among `ids`; (None, None) when none has a score."""
    best = None
    for i in ids:
        pair = scores.get(str(i).strip().upper())
        if pair and (best is None or pair[0] > best[0]):
            best = pair
    return best if best else (None, None)


def top(ids, scores: Scores) -> tuple[str | None, float | None]:
    """(CVE, epss) of the highest-scoring CVE among `ids`, the first in sorted order on a tie; (None, None)
    when none has a score."""
    best = (None, None)
    for cve in sorted({str(i).strip().upper() for i in ids}):
        pair = scores.get(cve)
        if pair and (best[1] is None or pair[0] > best[1]):
            best = (cve, pair[0])
    return best


def mark(findings: list[Finding], data: Epss) -> int:
    """Set v["epss"] and v["epss_percentile"] on every advisory (None without a score); returns how many
    advisories have a score."""
    n = 0
    for f in findings:
        for v in f.vulns:
            ids = {v.get("id", "")} | set(v.get("aliases") or [])
            v["epss"], v["epss_percentile"] = score_of(ids, data.scores)
            if v["epss"] is not None:
                n += 1
    return n


def source(data: Epss, scored: int) -> dict:
    """The entry for sources["epss"]."""
    fetched = (dt.datetime.fromtimestamp(data.fetched_at, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
               if data.fetched_at is not None else None)
    return {"loaded": len(data.scores), "scored": scored, "score_date": data.score_date,
            "model_version": data.model_version, "origin": data.origin, "fetched_at": fetched,
            "error": data.error, "warning": data.warning}


def text(value: float | None) -> str:
    """A score as a percentage: "44.1%", "0.7%", "<0.1%"; "no EPSS" without a score (never "0%")."""
    if value is None:
        return "no EPSS"
    if value < 0.0005:
        return "<0.1%"
    return f"{value * 100:.1f}%"


def label(value: float | None, lead: str = "EPSS") -> str:
    """A score with its label, "EPSS 44.1%" (or `lead` instead of "EPSS"); "no EPSS" without a score, never
    "EPSS no EPSS"."""
    return f"{lead} {text(value)}" if value is not None else text(None)


def likely(value: float | None, threshold: float | None) -> bool:
    """True when the score reaches a threshold that is switched on (greater than 0)."""
    return (value is not None and isinstance(threshold, (int, float)) and not isinstance(threshold, bool)
            and threshold > 0 and value >= threshold)


def promoting(block: dict | None) -> bool:
    """Promotion by EPSS is switched on in an `epss` block of audit.json or issues.json (`[epss] promote_at`
    greater than 0)."""
    return isinstance(block, dict) and likely(1.0, block.get("threshold"))


def order(value: float | None, threshold: float | None) -> float:
    """Sort key, smaller first: highest score first; no score sorts as if it were the threshold."""
    return -value if value is not None else -(threshold or 0.0)
