"""Enrichment: CISA KEV flag, endoflife.date status, registry latest versions, cache."""
from __future__ import annotations

import datetime as dt
import io
import json
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from sbomaudit import cache as cache_mod
from sbomaudit import enrich
from sbomaudit.model import BranchInventory, Component, Finding
from sbomaudit.readers import runtime_component
from tests.helpers import not_found

FIXTURES = Path(__file__).parent / "fixtures"


def stub_fetch(table: dict):
    """fetch(url) that answers from `table` and records every URL; unknown URLs raise."""
    calls = []

    def fetch(url):
        calls.append(url)
        if url not in table:
            raise RuntimeError(f"unexpected URL {url}")
        return table[url]

    fetch.calls = calls
    return fetch


def inventory(components: list[Component], project="app", branch="main") -> BranchInventory:
    return BranchInventory(project=project, branch=branch, ref=branch, commit="abc123",
                           components=components)


class HttpGetJsonTests(unittest.TestCase):
    def test_an_http_error_is_raised_with_its_body_closed(self):
        """urlopen's HTTPError carries the response body; nobody reads it, so it is closed before propagating."""
        body = io.BytesIO(b'{"error": "nope"}')

        def urlopen(req, timeout):
            raise urllib.error.HTTPError(req.full_url, 500, "Server Error", {}, body)  # type: ignore[arg-type]

        with mock.patch.object(enrich.urllib.request, "urlopen", urlopen):
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                enrich.http_get_json("https://example.invalid/x")
        self.assertEqual(ctx.exception.code, 500)
        self.assertTrue(body.closed)


class CacheTests(unittest.TestCase):
    def test_cache_ttl_expiry(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = cache_mod.Cache(Path(tmp) / "c", ttl_hours=24)
            c.put("eol:nodejs/18", {"eol": "2025-04-30"})
            self.assertEqual(c.get("eol:nodejs/18"), {"eol": "2025-04-30"})
            later = time.time() + 25 * 3600
            with mock.patch.object(cache_mod.time, "time", return_value=later):
                self.assertIsNone(c.get("eol:nodejs/18"))

    def test_cache_missing_and_corrupt_entries_are_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = cache_mod.Cache(Path(tmp), ttl_hours=24)
            self.assertIsNone(c.get("nothing"))
            c.put("bad/key with spaces", [1, 2])
            self.assertEqual(c.get("bad/key with spaces"), [1, 2])
            for p in Path(tmp).glob("*.json"):
                p.write_text("{not json")
            self.assertIsNone(c.get("bad/key with spaces"))


class KevTests(unittest.TestCase):
    def test_load_kev_from_fixture_and_cache(self):
        data = json.loads((FIXTURES / "kev-sample.json").read_text())
        fetch = stub_fetch({enrich.KEV_URL: data})
        with tempfile.TemporaryDirectory() as tmp:
            c = cache_mod.Cache(Path(tmp))
            kev, err = enrich.load_kev(c, fetch=fetch)
            self.assertIsNone(err)
            self.assertIn("CVE-2021-44228", kev)
            self.assertEqual(len(kev), data["count"])
            kev2, _ = enrich.load_kev(c, fetch=fetch)
            self.assertEqual(kev2, kev)
            self.assertEqual(len(fetch.calls), 1, "second load must come from the cache")

    def test_load_kev_failure_is_reported_not_raised(self):
        def fetch(url):
            raise OSError("network down")
        with tempfile.TemporaryDirectory() as tmp:
            kev, err = enrich.load_kev(cache_mod.Cache(Path(tmp)), fetch=fetch)
        self.assertEqual(kev, set())
        self.assertIn("network down", err)

    def test_kev_marks_by_alias(self):
        comp = Component(ecosystem="Maven", name="org.apache.logging.log4j:log4j-core", version="2.14.1")
        f = Finding(project="app", branch="main", component=comp, vulns=[
            {"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"]},
            {"id": "GHSA-0000-0000-0000", "aliases": ["CVE-2000-0001"]},
        ])
        n = enrich.mark_kev([f], {"CVE-2021-44228"})
        self.assertEqual(n, 1)
        self.assertTrue(f.vulns[0]["kev"])
        self.assertFalse(f.vulns[1].get("kev", False))

    def test_kev_marks_by_primary_id(self):
        f = Finding(project="app", branch="main", component=Component(name="x"),
                    vulns=[{"id": "CVE-2024-3094", "aliases": []}])
        self.assertEqual(enrich.mark_kev([f], {"CVE-2024-3094"}), 1)
        self.assertTrue(f.vulns[0]["kev"])


class EolTests(unittest.TestCase):
    def test_eol_status_from_fixture(self):
        data = json.loads((FIXTURES / "eol-nodejs-18.json").read_text())
        fetch = stub_fetch({"https://endoflife.date/api/nodejs/18.json": data})
        inv = inventory([runtime_component("nodejs", "18", "package.json", detail="engines.node >=18")])
        with tempfile.TemporaryDirectory() as tmp:
            rows, _ = enrich.eol([inv], cache_mod.Cache(Path(tmp)), fetch=fetch)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual((row["project"], row["branch"], row["product"], row["cycle"]),
                         ("app", "main", "nodejs", "18"))
        self.assertEqual(row["status"], "EOL")
        self.assertEqual(row["eol_date"], "2025-04-30")
        self.assertEqual(row["latest"], "18.20.8")
        self.assertIn("package.json", row["source"])

    def test_eol_soon_within_90_days(self):
        today = dt.date.today()
        soon = (today + dt.timedelta(days=60)).isoformat()
        far = (today + dt.timedelta(days=400)).isoformat()
        fetch = stub_fetch({
            "https://endoflife.date/api/nodejs/20.json": {"eol": soon, "latest": "20.19.0"},
            "https://endoflife.date/api/nodejs/24.json": {"eol": far, "latest": "24.1.0"},
            "https://endoflife.date/api/caddy/2.json": {"eol": False, "latest": "2.10.0"},
        })
        inv = inventory([
            runtime_component("nodejs", "20", ".nvmrc", detail=".nvmrc"),
            runtime_component("nodejs", "24", "Dockerfile", detail="image node:24-alpine"),
            runtime_component("caddy", "2", "docker-compose.yml", detail="image caddy:2-alpine"),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            rows, _ = enrich.eol([inv], cache_mod.Cache(Path(tmp)), fetch=fetch)
        by_cycle = {(r["product"], r["cycle"]): r["status"] for r in rows}
        self.assertEqual(by_cycle[("nodejs", "20")], "EOL soon")
        self.assertEqual(by_cycle[("nodejs", "24")], "supported")
        self.assertEqual(by_cycle[("caddy", "2")], "supported")

    def test_eol_unknown_cycle_and_missing_product(self):
        """HTTP 404 is endoflife.date's answer (product or cycle unknown): cached, status unknown, not a failure."""
        def fetch(url):
            raise not_found(url)
        inv = inventory([
            runtime_component("deno", "", "deno.json", detail="deno.json present (version not pinned)"),
            runtime_component("deno", "2", "supabase/config.toml", detail="edge_runtime.deno_version = 2"),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            cache = cache_mod.Cache(Path(tmp))
            rows, failed = enrich.eol([inv], cache, fetch=fetch)
            self.assertEqual([r["status"] for r in rows], ["unknown", "unknown"])
            self.assertEqual(failed, [])
            self.assertIn("error", cache.get("eol:deno/2"))

    def test_eol_fetch_failure_is_reported_and_not_cached(self):
        """A network error is not an answer: counted as failed and retried next run, not 'unknown' for 24 h."""
        def fetch(url):
            raise urllib.error.URLError("name resolution failed")
        inv = inventory([runtime_component("nodejs", "18", "package.json", detail="engines.node >=18"),
                         runtime_component("nodejs", "18", "Dockerfile", detail="image node:18-alpine")])
        with tempfile.TemporaryDirectory() as tmp:
            cache = cache_mod.Cache(Path(tmp))
            rows, failed = enrich.eol([inv], cache, fetch=fetch)
            self.assertEqual([r["status"] for r in rows], ["unknown"])
            self.assertEqual(len(failed), 1)
            self.assertEqual(failed[0]["what"], "nodejs/18")
            self.assertIn("URLError", failed[0]["error"])
            self.assertIsNone(cache.get("eol:nodejs/18"))
            good = stub_fetch({"https://endoflife.date/api/nodejs/18.json": {"eol": True, "latest": "18.20.8"}})
            rows, failed = enrich.eol([inv], cache, fetch=good)
            self.assertEqual(([r["status"] for r in rows], failed), (["EOL"], []))

    def test_eol_dedupes_same_runtime_and_maps_alpine_slug(self):
        fetch = stub_fetch({"https://endoflife.date/api/alpine-linux/3.19.json": {"eol": "2025-11-01", "latest": "3.19.9"}})
        inv = inventory([
            runtime_component("alpine", "3.19", "Dockerfile", detail="image alpine:3.19"),
            runtime_component("alpine", "3.19", "docker-compose.yml", detail="image alpine:3.19"),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            rows, _ = enrich.eol([inv], cache_mod.Cache(Path(tmp)), fetch=fetch)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "EOL")
        self.assertIn("Dockerfile", rows[0]["source"])
        self.assertIn("docker-compose.yml", rows[0]["source"])
        self.assertEqual(len(fetch.calls), 1)


class LatestTests(unittest.TestCase):
    def test_latest_major_behind(self):
        fetch = stub_fetch({
            "https://registry.npmjs.org/lodash/latest": {"version": "4.17.21"},
            "https://registry.npmjs.org/@types%2Fnode/latest": {"version": "24.0.0"},
            "https://pypi.org/pypi/requests/json": {"info": {"version": "2.32.3"}},
            "https://jsr.io/@std/path/meta.json": {"latest": "1.1.6"},
        })
        inv = inventory([
            Component(ecosystem="npm", name="lodash", version="3.10.1", scope="required", direct=True),
            Component(ecosystem="npm", name="@types/node", version="22.5.0", scope="optional", direct=True),
            Component(ecosystem="npm", name="left-pad", version="1.3.0", scope="required", direct=False),
            Component(ecosystem="PyPI", name="requests", version="2.31.0", scope="required", direct=True),
            Component(ecosystem="jsr", name="@std/path", version="0.219.0", scope="required", direct=True),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            rows, _ = enrich.latest([inv], cache_mod.Cache(Path(tmp)), fetch=fetch)
        by_name = {r["name"]: r for r in rows}
        self.assertEqual(set(by_name), {"lodash", "@types/node", "@std/path"})
        self.assertEqual(by_name["lodash"], {"project": "app", "branch": "main", "name": "lodash",
                                             "ecosystem": "npm", "current": "3.10.1",
                                             "latest": "4.17.21", "major_behind": 1, "scope": "required"})
        self.assertEqual(by_name["@types/node"]["major_behind"], 2)
        self.assertEqual(by_name["@std/path"]["major_behind"], 1)
        self.assertNotIn("https://registry.npmjs.org/left-pad/latest", fetch.calls)

    def test_latest_registry_failure_is_reported_and_not_cached(self):
        def fetch(url):
            raise OSError("timeout")
        inv = inventory([Component(ecosystem="npm", name="lodash", version="3.10.1", direct=True)])
        with tempfile.TemporaryDirectory() as tmp:
            cache = cache_mod.Cache(Path(tmp))
            rows, failed = enrich.latest([inv], cache, fetch=fetch)
            self.assertEqual(rows, [])
            self.assertEqual([(f["what"], f["error"]) for f in failed], [("npm:lodash", "OSError: timeout")])
            self.assertIsNone(cache.get("latest:npm:lodash"))

    def test_latest_registry_404_is_an_answer_not_a_failure(self):
        def fetch(url):
            raise not_found(url)
        inv = inventory([Component(ecosystem="npm", name="private-pkg", version="1.0.0", direct=True)])
        with tempfile.TemporaryDirectory() as tmp:
            cache = cache_mod.Cache(Path(tmp))
            rows, failed = enrich.latest([inv], cache, fetch=fetch)
            self.assertEqual((rows, failed), ([], []))
            self.assertIsNotNone(cache.get("latest:npm:private-pkg"))


class FixedInTests(unittest.TestCase):
    def test_fixed_in_picks_smallest_fix_above_current(self):
        vuln = {"fixed": ["4.17.21", "5.0.0", "4.17.19"]}
        self.assertEqual(enrich.fixed_in(vuln, "4.17.20"), "4.17.21")
        self.assertEqual(enrich.fixed_in(vuln, "4.17.21"), "5.0.0")
        self.assertIsNone(enrich.fixed_in(vuln, "5.0.0"))
        self.assertIsNone(enrich.fixed_in({"fixed": []}, "1.0.0"))


if __name__ == "__main__":
    unittest.main()
