"""EPSS: FIRST's daily score file, downloaded once, parsed, cached, and used to mark advisories."""
from __future__ import annotations

import gzip
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import epss
from sbomaudit.cache import Cache
from sbomaudit.model import Component, Finding
from tests.helpers import epss_fetch, epss_gz

RAW = epss_gz({"CVE-2021-23337": (0.0123, 0.79), "CVE-2024-0001": (0.4413, 0.975)})


class FakeResponse:
    """What urlopen returns: read(n) gives n bytes, geturl() the final URL after redirects."""

    def __init__(self, url="https://example.invalid/x", size=100):
        self.url, self.size = url, size

    def read(self, n=-1):
        return b"x" * (self.size if n < 0 else min(n, self.size))

    def geturl(self):
        return self.url

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class EpssTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cache = Cache(Path(tmp.name) / "cache")

    def test_parse_reads_scores_and_the_comment_line(self):
        scores, meta = epss.parse(RAW)
        self.assertEqual(scores["CVE-2024-0001"], (0.4413, 0.975))
        self.assertEqual(meta, {"score_date": "2026-11-23T12:00:23Z", "model_version": "v2026.06.15", "entries": 2})

    def test_bad_rows_are_skipped(self):
        body = ("#model_version:v1,score_date:2026-11-23T00:00:00Z\ncve,epss,percentile\n"
                "CVE-2024-0001,0.5,0.9\ncve-2024-0002,0.25,0.5\nCVE-2024-0003,nan,0.5\nCVE-2024-0004,inf,0.5\n"
                "CVE-2024-0005,1.5,0.5\nCVE-2024-0006,-0.1,0.5\nCVE-2024-0007,0.5\nGHSA-aaaa-bbbb-cccc,0.5,0.5\n"
                "CVE-2024-0008,abc,0.5\n\n")
        scores, meta = epss.parse(gzip.compress(body.encode()))
        self.assertEqual(sorted(scores), ["CVE-2024-0001", "CVE-2024-0002"])
        self.assertEqual(meta["entries"], 2)

    def test_no_rows_is_an_error(self):
        with self.assertRaises(ValueError):
            epss.parse(gzip.compress(b"#model_version:v1,score_date:x\ncve,epss,percentile\n"))

    def test_live_download_is_cached_and_not_fetched_again(self):
        fetch = epss_fetch(RAW)
        first, second = epss.load(self.cache, fetch), epss.load(self.cache, fetch)
        self.assertEqual((first.origin, second.origin, fetch.calls), ("live", "cache", [epss.EPSS_URL]))
        self.assertEqual(second.scores, first.scores)
        self.assertEqual(second.score_date, "2026-11-23T12:00:23Z")

    def test_html_instead_of_gzip_is_a_failed_download(self):
        data = epss.load(self.cache, epss_fetch(b"<html>blocked by proxy</html>"))
        self.assertEqual((data.scores, data.origin, data.available), ({}, None, False))
        self.assertTrue(data.error.startswith("EPSS fetch failed: "))

    def test_truncated_gzip_falls_back_to_the_cached_file(self):
        epss.load(self.cache, epss_fetch(RAW))
        expired = Cache(self.cache.dir, ttl_hours=24)
        with mock.patch("sbomaudit.cache.time.time", return_value=time.time() + 25 * 3600):
            data = epss.load(expired, epss_fetch(RAW[: len(RAW) // 2]))
        self.assertEqual((data.origin, data.error, len(data.scores)), ("stale", None, 2))
        self.assertTrue(data.warning.startswith("EPSS download failed: "))
        self.assertEqual(data.score_date, "2026-11-23T12:00:23Z")

    def test_outage_without_a_cached_file_has_no_scores(self):
        data = epss.load(self.cache, epss_fetch(OSError("no route")))
        self.assertEqual((data.scores, data.warning), ({}, None))
        self.assertIn("OSError: no route", data.error)

    def test_a_changed_cache_file_is_not_trusted(self):
        epss.load(self.cache, epss_fetch(RAW))
        (self.cache.dir / epss.CACHE_FILE).write_bytes(epss_gz({"CVE-2024-0001": (0.99, 0.99)}))
        fetch = epss_fetch(RAW)
        self.assertEqual((epss.load(self.cache, fetch).origin, len(fetch.calls)), ("live", 1))

    def test_mark_takes_the_highest_cve_and_none_without_one(self):
        f = Finding(project="app", branch="main", component=Component(ecosystem="npm", name="lodash"), vulns=[
            {"id": "GHSA-x", "aliases": ["CVE-2021-23337", "CVE-2024-0001"]},
            {"id": "CVE-2021-23337"},
            {"id": "GHSA-y", "aliases": []},
        ])
        n = epss.mark([f], epss.load(self.cache, epss_fetch(RAW)))
        self.assertEqual(n, 2)
        self.assertEqual([(v["epss"], v["epss_percentile"]) for v in f.vulns],
                         [(0.4413, 0.975), (0.0123, 0.79), (None, None)])

    def test_mark_without_scores_sets_none(self):
        f = Finding(project="app", branch="main", component=Component(name="x"),
                    vulns=[{"id": "CVE-2021-23337"}])
        self.assertEqual(epss.mark([f], epss.load(self.cache, epss_fetch(OSError("x")))), 0)
        self.assertEqual((f.vulns[0]["epss"], f.vulns[0]["epss_percentile"]), (None, None))

    def test_text_likely_order(self):
        self.assertEqual([epss.text(x) for x in (None, 0.0, 0.0004, 0.0074, 0.4413, 1.0)],
                         ["no EPSS", "<0.1%", "<0.1%", "0.7%", "44.1%", "100.0%"])
        self.assertEqual([epss.likely(v, t) for v, t in ((0.1, 0.1), (0.0999, 0.1), (None, 0.1), (0.9, 0), (0.9, None))],
                         [True, False, False, False, False])
        self.assertLess(epss.order(0.5, 0.1), epss.order(None, 0.1))
        self.assertLess(epss.order(None, 0.1), epss.order(0.05, 0.1))

    def test_label_names_the_score_or_says_no_epss(self):
        self.assertEqual([epss.label(x) for x in (0.44, 0.0004, None)], ["EPSS 44.0%", "EPSS <0.1%", "no EPSS"])
        self.assertEqual([epss.label(x, "highest EPSS") for x in (0.123, None)], ["highest EPSS 12.3%", "no EPSS"])

    def test_top_names_the_cve_behind_the_highest_score(self):
        scores = {"CVE-2024-0001": (0.05, 0.9), "CVE-2024-0002": (0.83, 0.99), "CVE-2024-0003": (0.83, 0.99)}
        self.assertEqual(epss.top({"CVE-2024-0003", "cve-2024-0002 ", "CVE-2024-0001", "CVE-2024-0009"}, scores),
                         ("CVE-2024-0002", 0.83))            # a tie goes to the first id in sorted order
        self.assertEqual(epss.top(["CVE-2024-0009"], scores), (None, None))
        self.assertEqual(epss.top([], scores), (None, None))

    def test_promoting_reads_the_threshold_of_an_epss_block(self):
        self.assertEqual([epss.promoting(b) for b in ({"threshold": 0.1}, {"threshold": 0}, {"threshold": None},
                                                      {}, None)], [True, False, False, False, False])

    def test_unpack_cap_is_64_mb(self):
        self.assertEqual(epss.MAX_UNPACKED, 64 * 1024 * 1024)

    def test_a_file_that_unpacks_beyond_the_cap_is_refused(self):
        big = epss_gz({f"CVE-2024-{n:05d}": (0.5, 0.5) for n in range(1, 2000)})
        cap = len(gzip.decompress(RAW)) + 10          # the small file fits, the big one does not
        self.assertGreater(len(gzip.decompress(big)), cap)
        with mock.patch.object(epss, "MAX_UNPACKED", cap):
            with self.assertRaises(ValueError) as ctx:
                epss.parse(big)
            self.assertIn("unpacks to more than", str(ctx.exception))
            failed = epss.load(self.cache, epss_fetch(big))
            self.assertEqual((failed.scores, failed.origin, failed.available), ({}, None, False))
            self.assertIn("unpacks to more than", failed.error)
            epss.load(self.cache, epss_fetch(RAW))
            expired = Cache(self.cache.dir, ttl_hours=24)
            with mock.patch("sbomaudit.cache.time.time", return_value=time.time() + 25 * 3600):
                stale = epss.load(expired, epss_fetch(big))
        self.assertEqual((stale.origin, stale.error, len(stale.scores)), ("stale", None, 2))
        self.assertIn("unpacks to more than", stale.warning)
        self.assertNotIn("CVE-2024-00001", stale.scores)

    def test_http_get_bytes_refuses_http_and_oversize(self):
        with self.assertRaises(ValueError):
            epss.http_get_bytes("http://example.invalid/x")
        with mock.patch.object(epss.urllib.request, "urlopen", return_value=FakeResponse(size=100)):
            self.assertEqual(epss.http_get_bytes("https://example.invalid/x", limit=100), b"x" * 100)
            with self.assertRaises(ValueError):
                epss.http_get_bytes("https://example.invalid/x", limit=10)
        with mock.patch.object(epss.urllib.request, "urlopen",
                               return_value=FakeResponse(url="http://example.invalid/x")):
            with self.assertRaises(ValueError):
                epss.http_get_bytes("https://example.invalid/x")


if __name__ == "__main__":
    unittest.main()
