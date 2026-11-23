"""Host mode: Debian version comparison and OSV/KEV matching of a host's dpkg packages.

Every osv.dev answer is injected (`post` for querybatch, `fetch` for vuln records); nothing here touches
the network. `fixtures/hosts/osv/` holds osv.dev responses recorded 2026-11-09, trimmed to the affected
entries the tests need. Hosts and package sets are example data.
"""
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from sbomaudit import enrich
from sbomaudit.cache import Cache
from sbomaudit.hosts import debver, osvhost, parse
from tests.hosts_fixture import collector_doc

OSV_DIR = Path(__file__).resolve().parent / "fixtures" / "hosts" / "osv"
NOBLE = {"id": "ubuntu", "version_id": "24.04", "codename": "noble", "supported": True}
BOOKWORM = {"id": "debian", "version_id": "12", "codename": "bookworm", "supported": True}


def recorded(name: str):
    return json.loads((OSV_DIR / name).read_text())


def pkg(name, version, source=None, source_version=None, arch="amd64"):
    return {"name": name, "version": version, "arch": arch, "source": source or name,
            "source_version": source_version or version}


def facts(packages, os=NOBLE, kernel="6.8.0-45-generic", upgradable=None):
    return {"os": os, "kernel": kernel, "packages": packages, "upgradable": upgradable or {}}


SENTINEL = ("openssl", "0")


def sentinel_query(eco="Ubuntu:24.04:LTS"):
    return {"package": {"name": "openssl", "ecosystem": eco}, "version": "0"}


class FakeOSV:
    """osv.dev stand-in. `vulns[(name, version)]` is a list of ids (or of pages: a list of lists, served
    one page per request with a `next_page_token`); `records[id]` answers GET /v1/vulns/<id>. The no-data
    sentinel (openssl at version "0") has an id unless `has_data=False`."""

    def __init__(self, vulns=None, records=None, has_data=True):
        self.vulns = dict(vulns or {})
        if has_data:
            self.vulns.setdefault(SENTINEL, ["UBUNTU-CVE-2024-9143"])
        self.records = records or {}
        self.posts: list[dict] = []
        self.gets: list[str] = []

    def post(self, url, body):
        self.assertable_url = url
        self.posts.append(body)
        results = []
        for q in body["queries"]:
            key = (q["package"]["name"], q["version"])
            pages = self.vulns.get(key, [])
            if pages and isinstance(pages[0], list):
                page = int(q.get("page_token", "0"))
                ids, more = pages[page], page + 1 < len(pages)
            else:
                ids, more = pages, False
            r = {"vulns": [{"id": i, "modified": "2026-11-01T00:00:00Z"} for i in ids]} if ids else {}
            if more:
                r["next_page_token"] = str(page + 1)
            results.append(r)
        return {"results": results}

    def fetch(self, url):
        self.gets.append(url)
        vid = url.rsplit("/", 1)[1]
        if vid not in self.records:
            raise urllib.error.URLError(f"no record for {vid}")
        return self.records[vid]


def record(vid, ecosystem, name, fixed=None, upstream=None, modified="2026-11-01T00:00:00Z", extra=()):
    events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    affected = [{"package": {"ecosystem": ecosystem, "name": name}, "ranges": [{"type": "ECOSYSTEM", "events": events}]}]
    affected += list(extra)
    return {"id": vid, "modified": modified, "upstream": upstream or [], "affected": affected}


class TmpCacheCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.cache = Cache(Path(self._tmp.name) / "osv-hosts", ttl_hours=24)


class DebverTests(unittest.TestCase):
    def test_debver_cases(self):
        c = debver.compare
        self.assertEqual(c("1.0~rc1", "1.0"), -1)
        self.assertEqual(c("1:0.9", "2.0"), 1)
        self.assertEqual(c("1.0-1ubuntu0.1", "1.0-1"), 1)
        self.assertEqual(c("3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.9"), 1)
        self.assertEqual(c("2.36-9+deb12u4", "2.36-9+deb12u10"), -1)
        self.assertEqual(c("1.0", "1.0"), 0)

    def test_debver_edges(self):
        c = debver.compare
        self.assertEqual(c("0:1.0", "1.0"), 0)                 # an absent epoch is 0
        self.assertEqual(c("1.0", "1.0-0"), 0)                 # an absent revision equals "0"
        self.assertEqual(c("1.0~", "1.0~~"), 1)                # ~~ sorts before ~
        self.assertEqual(c("1.0a", "1.0+"), -1)                # letters sort before other characters
        self.assertEqual(c("1.0", "1.0a"), -1)                 # end of string sorts before a letter
        self.assertEqual(c("1.00", "1.0"), 0)                  # leading zeros do not count
        self.assertEqual(c("5:27.3.1-1~ubuntu.24.04~noble", "5:27.2.0-1~ubuntu.24.04~noble"), 1)
        self.assertEqual(c("6.8.0-45.45", "6.8.0-100.100"), -1)
        self.assertEqual(c("1.0-1", "1.0-1"), 0)
        self.assertEqual(c("2.0", "1:0.1"), -1)

    def test_dpkg_reference_vectors(self):
        """test_version_compare() in dpkg's lib/dpkg/t/t-version.c, as version strings (checked with
        `dpkg --compare-versions` on Debian 12)."""
        c = debver.compare
        self.assertEqual(c("0-0", "0-0"), 0)
        self.assertEqual(c("0-00", "00-0"), 0)
        self.assertEqual(c("1:2-3", "1:2-3"), 0)
        self.assertEqual(c("0:0-0", "1:0-0"), -1)
        self.assertEqual(c("1:0-0", "0:0-0"), 1)
        self.assertEqual(c("1-1", "2-1"), -1)
        self.assertEqual(c("1-1", "1-2"), -1)
        self.assertEqual(c("1:1-1", "2:1-1"), -1)
        self.assertEqual(c("a-0", "b-0"), -1)
        self.assertEqual(c("b-0", "a-0"), 1)
        self.assertEqual(c("0-a", "0-b"), -1)
        self.assertEqual(c("0-b", "0-a"), 1)


class EcosystemTests(TmpCacheCase):
    def test_ecosystem(self):
        e = osvhost.ecosystem
        self.assertEqual(e({"id": "ubuntu", "version_id": "24.04"}), "Ubuntu:24.04:LTS")
        self.assertEqual(e({"id": "ubuntu", "version_id": "22.04"}), "Ubuntu:22.04:LTS")
        self.assertEqual(e({"id": "ubuntu", "version_id": "24.10"}), "Ubuntu:24.10")
        self.assertEqual(e({"id": "ubuntu", "version_id": "23.04"}), "Ubuntu:23.04")
        self.assertEqual(e({"id": "debian", "version_id": "12"}), "Debian:12")
        self.assertEqual(e({"id": "debian", "version_id": "11.9"}), "Debian:11")
        self.assertIsNone(e({"id": "fedora", "version_id": "40"}))
        self.assertIsNone(e({"id": "ubuntu", "version_id": None}))
        self.assertIsNone(e({}))

    def test_unknown_release_has_no_ecosystem(self):
        trixie = {"id": "debian", "version_id": None, "codename": "trixie", "supported": True}
        self.assertIsNone(osvhost.ecosystem(trixie))
        osv = FakeOSV()
        result = osvhost.match(facts([pkg("openssl", "3.0.15-1")], os=trixie), set(), self.cache,
                               post=osv.post, fetch=osv.fetch)
        self.assertEqual(result, ([], "vulnerability matching unsupported for debian trixie"))
        self.assertEqual(result[1].kind, "unsupported")
        self.assertEqual(osv.posts, [])

    def test_unsupported_os_is_an_error_not_a_crash(self):
        osv = FakeOSV()
        for os_, text in (({"id": "fedora", "version_id": "40"}, "fedora 40"),
                          ({}, "unknown OS"), (None, "unknown OS")):
            f = facts([pkg("openssl", "1")], os=os_)
            result = osvhost.match(f, set(), self.cache, post=osv.post, fetch=osv.fetch)
            self.assertEqual(result, ([], f"vulnerability matching unsupported for {text}"))
            self.assertEqual(result[1].kind, "unsupported")


class CveTests(unittest.TestCase):
    def test_cves_from_ids(self):
        self.assertEqual(osvhost.cves({"id": "UBUNTU-CVE-2024-1086"}), {"CVE-2024-1086"})
        self.assertEqual(osvhost.cves({"id": "DEBIAN-CVE-2024-1086"}), {"CVE-2024-1086"})
        self.assertEqual(osvhost.cves({"id": "DSA-5432-1", "related": ["CVE-2023-1", "USN-1-1"]}), {"CVE-2023-1"})
        self.assertEqual(osvhost.cves({"id": "USN-1-1", "aliases": ["GHSA-xxxx-yyyy-zzzz", "CVE-2024-3"],
                                       "upstream": ["CVE-2024-4", "UBUNTU-CVE-2024-5"]}),
                         {"CVE-2024-3", "CVE-2024-4"})
        self.assertEqual(osvhost.cves({"id": "UBUNTU-CVE-2024-1086x"}), set())
        self.assertEqual(osvhost.cves({}), set())

    def test_cves_from_recorded_records(self):
        self.assertEqual(osvhost.cves(recorded("vuln-DSA-5432-1.json")), {"CVE-2023-36661"})
        self.assertEqual(osvhost.cves(recorded("vuln-UBUNTU-CVE-2024-1086.json")), {"CVE-2024-1086"})
        self.assertEqual(osvhost.cves(recorded("vuln-DEBIAN-CVE-2024-1086.json")), {"CVE-2024-1086"})


class QueryTests(TmpCacheCase):
    def test_queries_by_source_package(self):
        osv = FakeOSV()
        packages = [pkg("openssl", "3.0.13-0ubuntu3.4"),
                    pkg("libssl3t64", "3.0.13-0ubuntu3.4", "openssl"),
                    pkg("libc6", "2.39-0ubuntu8.3", "glibc"),
                    pkg("libc6", "2.39-0ubuntu8.3", "glibc", arch="i386")]
        findings, err = osvhost.match(facts(packages), set(), self.cache, post=osv.post, fetch=osv.fetch)
        self.assertEqual((findings, err), ([], None))
        self.assertEqual(osv.assertable_url, "https://api.osv.dev/v1/querybatch")
        self.assertEqual(osv.posts, [{"queries": [
            sentinel_query(),
            {"package": {"name": "glibc", "ecosystem": "Ubuntu:24.04:LTS"}, "version": "2.39-0ubuntu8.3"},
            {"package": {"name": "openssl", "ecosystem": "Ubuntu:24.04:LTS"}, "version": "3.0.13-0ubuntu3.4"},
        ]}])

    def test_batches_of_at_most_1000(self):
        osv = FakeOSV()
        packages = [pkg(f"pkg{i:04d}", "1.0-1") for i in range(2500)]
        osvhost.match(facts(packages), set(), self.cache, post=osv.post, fetch=osv.fetch)
        self.assertEqual([len(b["queries"]) for b in osv.posts], [1000, 1000, 501])
        self.assertEqual(osv.posts[0]["queries"][0], sentinel_query())
        names = [q["package"]["name"] for b in osv.posts for q in b["queries"]]
        self.assertEqual(len(set(names)), 2501)

    def test_follows_next_page_token(self):
        osv = FakeOSV(vulns={("openssl", "3.0.13-0ubuntu3.4"): [["UBUNTU-CVE-2024-1"], ["UBUNTU-CVE-2024-2"],
                                                               ["UBUNTU-CVE-2024-3"]],
                             ("glibc", "2.39-0ubuntu8.3"): ["UBUNTU-CVE-2024-9"]})
        packages = [pkg("openssl", "3.0.13-0ubuntu3.4"), pkg("libc6", "2.39-0ubuntu8.3", "glibc")]
        findings, err = osvhost.match(facts(packages), set(), self.cache, post=osv.post, fetch=osv.fetch)
        self.assertIsNone(err)
        self.assertEqual(len(osv.posts), 3)
        self.assertEqual(osv.posts[1], {"queries": [
            {"package": {"name": "openssl", "ecosystem": "Ubuntu:24.04:LTS"}, "version": "3.0.13-0ubuntu3.4",
             "page_token": "1"}]})
        by_id = {f["id"]: f for f in findings}
        self.assertEqual(by_id["vuln:openssl@3.0.13-0ubuntu3.4"]["open"], 3)
        self.assertEqual(by_id["vuln:libc6@2.39-0ubuntu8.3"]["open"], 1)

    def test_endless_pagination_is_an_error(self):
        def post(url, body):
            return {"results": [{"vulns": [], "next_page_token": "again"} for _ in body["queries"]]}
        findings, err = osvhost.match(facts([pkg("openssl", "1")]), set(), self.cache, post=post, fetch=None)
        self.assertEqual(findings, [])
        self.assertRegex(err, r"^osv\.dev: ")

    def test_signed_kernel_queries_the_unsigned_source(self):
        """osv.dev files kernel CVEs under `linux` (and its flavours), never under `linux-signed*`."""
        osv = FakeOSV()
        packages = [pkg("linux-image-6.8.0-45-generic", "6.8.0-45.45", "linux-signed"),
                    pkg("linux-modules-6.8.0-45-generic", "6.8.0-45.45", "linux"),
                    pkg("linux-image-6.8.0-49-generic", "6.8.0-49.49~22.04.1", "linux-signed-hwe-6.8")]
        osvhost.match(facts(packages), set(), self.cache, post=osv.post, fetch=osv.fetch)
        self.assertEqual([(q["package"]["name"], q["version"]) for q in osv.posts[0]["queries"]],
                         [SENTINEL, ("linux", "6.8.0-45.45"), ("linux-hwe-6.8", "6.8.0-49.49~22.04.1")])
        osv = FakeOSV()
        debian = [pkg("linux-image-6.1.0-26-amd64", "6.1.112-1", "linux-signed-amd64", "6.1.112+1")]
        osvhost.match(facts(debian, os=BOOKWORM, kernel="6.1.0-26-amd64"), set(), self.cache,
                      post=osv.post, fetch=osv.fetch)
        self.assertEqual(osv.posts[0]["queries"],
                         [sentinel_query("Debian:12"),
                          {"package": {"name": "linux", "ecosystem": "Debian:12"}, "version": "6.1.112-1"}])

    def test_upgradable_package_is_also_queried_at_its_candidate(self):
        osv = FakeOSV(vulns={("openssl", "3.0.13-0ubuntu3.4"): ["UBUNTU-CVE-2024-9143", "UBUNTU-CVE-2024-13176",
                                                               "USN-7278-1"],
                             ("openssl", "3.0.13-0ubuntu3.5"): ["UBUNTU-CVE-2024-13176"]})
        up = {"openssl": {"installed": "3.0.13-0ubuntu3.4", "candidate": "3.0.13-0ubuntu3.5", "suite": "noble-security"}}
        findings, err = osvhost.match(facts([pkg("openssl", "3.0.13-0ubuntu3.4")], upgradable=up), set(),
                                      self.cache, post=osv.post, fetch=osv.fetch)
        self.assertIsNone(err)
        self.assertEqual([(q["package"]["name"], q["version"]) for q in osv.posts[0]["queries"]],
                         [SENTINEL, ("openssl", "3.0.13-0ubuntu3.4"), ("openssl", "3.0.13-0ubuntu3.5")])
        self.assertEqual(osv.gets, [])
        [f] = findings
        self.assertEqual(f, {"id": "vuln:openssl@3.0.13-0ubuntu3.4", "group": "vuln", "critical": False,
                             "text": "2 open CVEs, 1 fixed by the installable update to 3.0.13-0ubuntu3.5",
                             "package": "openssl", "version": "3.0.13-0ubuntu3.4", "source": "openssl",
                             "open": 2, "fixable": 1, "candidate": "3.0.13-0ubuntu3.5"})

    def queried(self, osv):
        return [(q["package"]["name"], q["version"]) for b in osv.posts for q in b["queries"]][1:]

    def test_candidate_is_mapped_to_the_source_version(self):
        """bsdutils is binary 1:2.38.1-5+deb12u1 from source util-linux 2.38.1-5+deb12u1: the candidate's
        epoch is not part of the source version, so it must not win the comparison with the fix."""
        rec = record("DEBIAN-CVE-2024-28085", "Debian:12", "util-linux", fixed="2.38.1-5+deb12u2",
                     upstream=["CVE-2024-28085"])
        osv = FakeOSV(vulns={("util-linux", "2.38.1-5+deb12u1"): [rec["id"]],
                             ("util-linux", "2.38.1-5+deb12u1.1"): [rec["id"]]}, records={rec["id"]: rec})
        up = {"bsdutils": {"installed": "1:2.38.1-5+deb12u1", "candidate": "1:2.38.1-5+deb12u1.1",
                           "suite": "bookworm-updates"}}
        packages = [pkg("bsdutils", "1:2.38.1-5+deb12u1", "util-linux", "2.38.1-5+deb12u1")]
        findings, err = osvhost.match(facts(packages, os=BOOKWORM, kernel="6.1.0-26-amd64", upgradable=up),
                                      {"CVE-2024-28085"}, self.cache, post=osv.post, fetch=osv.fetch)
        self.assertIsNone(err)
        self.assertEqual(self.queried(osv), [("util-linux", "2.38.1-5+deb12u1"), ("util-linux", "2.38.1-5+deb12u1.1")])
        [kev] = findings
        self.assertEqual((kev["fix"], kev["fixed"], kev["candidate"]),
                         ("not installable", "2.38.1-5+deb12u2", "1:2.38.1-5+deb12u1.1"))

    def test_binnmu_suffix_is_stripped_from_the_candidate(self):
        osv = FakeOSV()
        up = {"libexpat1": {"installed": "2.5.0-1+b1", "candidate": "2.5.0-1+deb12u1+b1", "suite": "bookworm-security"}}
        packages = [pkg("libexpat1", "2.5.0-1+b1", "expat", "2.5.0-1")]
        osvhost.match(facts(packages, os=BOOKWORM, upgradable=up), set(), self.cache, post=osv.post, fetch=osv.fetch)
        self.assertEqual(self.queried(osv), [("expat", "2.5.0-1"), ("expat", "2.5.0-1+deb12u1")])

    def test_unexplained_binary_source_versions_drop_the_candidate(self):
        """A binary version that is neither the source version nor it plus an epoch / binNMU: no candidate."""
        rec = record("DEBIAN-CVE-2024-28085", "Debian:12", "util-linux", fixed="2.38.1-5+deb12u2",
                     upstream=["CVE-2024-28085"])
        osv = FakeOSV(vulns={("util-linux", "2.38.1-5+deb12u1"): [rec["id"]]}, records={rec["id"]: rec})
        up = {"bsdutils": {"installed": "2.38.2-1", "candidate": "2.38.2-2", "suite": "bookworm"}}
        packages = [pkg("bsdutils", "2.38.2-1", "util-linux", "2.38.1-5+deb12u1")]
        findings, err = osvhost.match(facts(packages, os=BOOKWORM, upgradable=up), {"CVE-2024-28085"}, self.cache,
                                      post=osv.post, fetch=osv.fetch)
        self.assertEqual(self.queried(osv), [("util-linux", "2.38.1-5+deb12u1")])
        [kev] = findings
        self.assertEqual((kev["fix"], kev["fixed"]), ("unknown", "2.38.1-5+deb12u2"))

    def test_ecosystem_with_data_passes_the_sentinel(self):
        osv = FakeOSV()
        self.assertEqual(osvhost.match(facts([pkg("openssl", "3.0.13-0ubuntu3.4")]), set(), self.cache,
                                       post=osv.post, fetch=osv.fetch), ([], None))

    def test_ecosystem_without_data_is_an_error_not_clean(self):
        """osv.dev has nothing for EOL interim releases (Ubuntu 23.04, checked 2026-11-09): empty answers."""
        osv = FakeOSV(has_data=False)
        lunar = {"id": "ubuntu", "version_id": "23.04", "codename": "lunar", "supported": False}
        result = osvhost.match(facts([pkg("openssl", "3.0.10-1ubuntu2")], os=lunar), set(), self.cache,
                               post=osv.post, fetch=osv.fetch)
        self.assertEqual(result, ([], "osv.dev has no data for Ubuntu:23.04"))
        self.assertEqual(result[1].kind, "failed")   # an empty answer is never "clean" nor "unsupported"
        self.assertEqual(osv.posts[0]["queries"][0], sentinel_query("Ubuntu:23.04"))

    def test_signed_sources_without_mapping_are_listed_once(self):
        osv = FakeOSV()
        packages = [pkg("grub-efi-amd64-signed", "1.202+2.12-1ubuntu7", "grub2-signed"),
                    pkg("shim-signed", "1.58+15.8-0ubuntu1"), pkg("openssl", "3.0.13-0ubuntu3.4"),
                    pkg("linux-image-6.8.0-45-generic", "6.8.0-45.45", "linux-signed")]
        findings, err = osvhost.match(facts(packages), set(), self.cache, post=osv.post, fetch=osv.fetch)
        self.assertIsNone(err)
        self.assertEqual(findings, [{
            "id": "info:signed-sources", "group": "info", "critical": False,
            "text": "not assessed (CVEs are tracked under the unsigned source): grub2-signed, shim-signed",
            "sources": ["grub2-signed", "shim-signed"]}])

    def test_clean_collector_facts(self):
        """The real facts shape from parse() goes through; a host without open vulns is clean."""
        osv = FakeOSV()
        f = parse.parse(collector_doc())
        self.assertEqual(osvhost.match(f, set(), self.cache, post=osv.post, fetch=osv.fetch), ([], None))
        names = {q["package"]["name"] for q in osv.posts[0]["queries"]}
        self.assertIn("linux", names)
        self.assertNotIn("linux-signed", names)


KERNELS = [pkg("linux-image-6.8.0-45-generic", "6.8.0-45.45", "linux-signed"),
           pkg("linux-image-6.8.0-40-generic", "6.8.0-40.40", "linux-signed")]


class KevTests(TmpCacheCase):
    def kernel_osv(self):
        rec = recorded("vuln-UBUNTU-CVE-2024-1086.json")
        return FakeOSV(vulns={("linux", "6.8.0-45.45"): ["UBUNTU-CVE-2024-1086"],
                              ("linux", "6.8.0-40.40"): ["UBUNTU-CVE-2024-1086"]},
                       records={"UBUNTU-CVE-2024-1086": rec})

    def test_kev_running_kernel_only(self):
        osv = self.kernel_osv()
        findings, err = osvhost.match(facts(KERNELS), {"CVE-2024-1086"}, self.cache, post=osv.post, fetch=osv.fetch)
        self.assertIsNone(err)
        by_group = {}
        for f in findings:
            by_group.setdefault(f["group"], []).append(f)
        self.assertEqual(set(by_group), {"kev", "info"})
        [kev] = by_group["kev"]
        self.assertEqual(kev["id"], "kev:CVE-2024-1086:linux-image-6.8.0-45-generic@6.8.0-45.45")
        self.assertIs(kev["critical"], True)
        self.assertEqual((kev["cve"], kev["package"], kev["version"]),
                         ("CVE-2024-1086", "linux-image-6.8.0-45-generic", "6.8.0-45.45"))
        self.assertEqual(kev["fix"], "not released")  # the recorded record has no Ubuntu:24.04:LTS entry
        [info] = by_group["info"]
        self.assertEqual(info["id"], "info:kev:CVE-2024-1086:linux-image-6.8.0-40-generic@6.8.0-40.40")
        self.assertIs(info["critical"], False)
        self.assertIn("not the running kernel", info["text"])
        self.assertEqual(osv.gets, ["https://api.osv.dev/v1/vulns/UBUNTU-CVE-2024-1086"])

    def test_kernel_family_packages_follow_the_running_kernel(self):
        """linux-libc-dev and the headers come from the kernel source but are not the running kernel."""
        osv = FakeOSV(vulns={("linux", "6.8.0-45.45"): ["UBUNTU-CVE-2024-1086"]},
                      records={"UBUNTU-CVE-2024-1086": recorded("vuln-UBUNTU-CVE-2024-1086.json")})
        packages = [KERNELS[0], pkg("linux-modules-6.8.0-45-generic", "6.8.0-45.45", "linux"),
                    pkg("linux-libc-dev", "6.8.0-45.45", "linux"), pkg("linux-headers-6.8.0-45", "6.8.0-45.45", "linux")]
        findings, _ = osvhost.match(facts(packages), {"CVE-2024-1086"}, self.cache, post=osv.post, fetch=osv.fetch)
        groups = {f["package"]: f["group"] for f in findings}
        self.assertEqual(groups, {"linux-image-6.8.0-45-generic": "kev", "linux-modules-6.8.0-45-generic": "kev",
                                  "linux-libc-dev": "info", "linux-headers-6.8.0-45": "info"})
        self.assertEqual(len(osv.gets), 1, "one record fetch per id per run")

    def test_unknown_running_kernel_fails_closed(self):
        osv = self.kernel_osv()
        findings, _ = osvhost.match(facts(KERNELS, kernel=""), {"CVE-2024-1086"}, self.cache,
                                    post=osv.post, fetch=osv.fetch)
        self.assertEqual(sorted(f["group"] for f in findings), ["kev", "kev"])

    def running_kernel_kev(self, packages):
        rec = record("UBUNTU-CVE-2024-1086", "Ubuntu:24.04:LTS", "linux", fixed="6.8.0-57.59", upstream=["CVE-2024-1086"])
        osv = FakeOSV(vulns={("linux", "6.8.0-45.45"): ["UBUNTU-CVE-2024-1086"]}, records={rec["id"]: rec})
        findings, err = osvhost.match(facts(packages), {"CVE-2024-1086"}, self.cache, post=osv.post, fetch=osv.fetch)
        self.assertIsNone(err)
        [kev] = [f for f in findings if f["group"] == "kev"]
        return kev

    def test_fixed_kernel_installed_but_not_running_needs_a_reboot(self):
        """A kernel fix comes as a new package name (new ABI): apt's candidate for the running one never moves."""
        newer = pkg("linux-image-6.8.0-57-generic", "6.8.0-57.59", "linux-signed")
        kev = self.running_kernel_kev([KERNELS[0], newer])
        self.assertEqual((kev["fix"], kev["fixed"]), ("reboot", "6.8.0-57.59"))
        self.assertIn("reboot", kev["text"])

    def test_fixed_kernel_not_installed_says_so(self):
        kev = self.running_kernel_kev([KERNELS[0]])
        self.assertEqual((kev["fix"], kev["fixed"]), ("not installable", "6.8.0-57.59"))
        self.assertIn("no fixed kernel installed", kev["text"])
        self.assertNotIn("stale lists", kev["text"])

    def test_running_kernel_not_installed_fails_closed(self):
        osv = self.kernel_osv()
        findings, err = osvhost.match(facts(KERNELS, kernel="6.8.0-48-generic"), {"CVE-2024-1086"}, self.cache,
                                      post=osv.post, fetch=osv.fetch)
        self.assertIsNone(err)
        self.assertEqual(sorted(f["id"] for f in findings),
                         ["info:running-kernel:6.8.0-48-generic",
                          "kev:CVE-2024-1086:linux-image-6.8.0-40-generic@6.8.0-40.40",
                          "kev:CVE-2024-1086:linux-image-6.8.0-45-generic@6.8.0-45.45"])
        info = next(f for f in findings if f["group"] == "info")
        self.assertEqual((info["critical"], info["text"]),
                         (False, "running kernel 6.8.0-48-generic not among installed packages; "
                                 "every installed kernel package is assessed"))

    def test_fail_closed_counts_only_binaries_that_can_be_the_running_kernel(self):
        """Without the running kernel's package, images and modules count; libc-dev, headers, tools stay info."""
        osv = FakeOSV(vulns={("linux", "6.8.0-45.45"): ["UBUNTU-CVE-2024-1086"]},
                      records={"UBUNTU-CVE-2024-1086": recorded("vuln-UBUNTU-CVE-2024-1086.json")})
        packages = [KERNELS[0], pkg("linux-modules-6.8.0-45-generic", "6.8.0-45.45", "linux"),
                    pkg("linux-libc-dev", "6.8.0-45.45", "linux"), pkg("linux-headers-6.8.0-45", "6.8.0-45.45", "linux"),
                    pkg("linux-tools-6.8.0-45", "6.8.0-45.45", "linux")]
        findings, _ = osvhost.match(facts(packages, kernel="6.8.0-48-generic"), {"CVE-2024-1086"}, self.cache,
                                    post=osv.post, fetch=osv.fetch)
        groups = {f.get("package", f["id"]): f["group"] for f in findings}
        self.assertEqual(groups, {"info:running-kernel:6.8.0-48-generic": "info",
                                  "linux-image-6.8.0-45-generic": "kev", "linux-modules-6.8.0-45-generic": "kev",
                                  "linux-libc-dev": "info", "linux-headers-6.8.0-45": "info",
                                  "linux-tools-6.8.0-45": "info"})

    def test_no_kernel_image_installed_is_not_assessable(self):
        osv = FakeOSV(vulns={("linux", "6.8.0-45.45"): ["UBUNTU-CVE-2024-1086"]},
                      records={"UBUNTU-CVE-2024-1086": recorded("vuln-UBUNTU-CVE-2024-1086.json")})
        for kernel in ("6.8.0-48-generic", ""):
            findings, err = osvhost.match(facts([pkg("linux-libc-dev", "6.8.0-45.45", "linux")], kernel=kernel),
                                          {"CVE-2024-1086"}, self.cache, post=osv.post, fetch=osv.fetch)
            self.assertIsNone(err)
            self.assertNotIn("kev", {f["group"] for f in findings}, kernel)
            [line] = [f for f in findings if f["id"].startswith("info:running-kernel:")]
            self.assertEqual(line["text"], f"running kernel {kernel or 'unknown'} not assessable: no kernel image installed")

    def test_kev_on_a_regular_package_and_no_summary_double_count(self):
        osv = FakeOSV(vulns={("openssl", "3.0.13-0ubuntu3.4"): ["UBUNTU-CVE-2024-9143", "UBUNTU-CVE-2024-13176",
                                                               "USN-7278-1"]},
                      records={"UBUNTU-CVE-2024-9143": recorded("vuln-UBUNTU-CVE-2024-9143.json")})
        packages = [pkg("openssl", "3.0.13-0ubuntu3.4"), pkg("libssl3t64", "3.0.13-0ubuntu3.4", "openssl")]
        findings, err = osvhost.match(facts(packages), {"CVE-2024-9143"}, self.cache, post=osv.post, fetch=osv.fetch)
        self.assertIsNone(err)
        ids = sorted(f["id"] for f in findings)
        self.assertEqual(ids, ["kev:CVE-2024-9143:libssl3t64@3.0.13-0ubuntu3.4", "kev:CVE-2024-9143:openssl@3.0.13-0ubuntu3.4",
                               "vuln:libssl3t64@3.0.13-0ubuntu3.4", "vuln:openssl@3.0.13-0ubuntu3.4"])
        summary = next(f for f in findings if f["id"] == "vuln:openssl@3.0.13-0ubuntu3.4")
        self.assertEqual(summary["text"], "1 open CVE, no fix installable")
        self.assertEqual(len(osv.gets), 1)


class FixStateTests(TmpCacheCase):
    def kev_fix(self, rec, upgradable=None, candidate_ids=None):
        vulns = {("nodejs", "18.19.1+dfsg-6ubuntu5"): [rec["id"]]}
        if upgradable:
            vulns[("nodejs", upgradable)] = candidate_ids or []
        osv = FakeOSV(vulns=vulns, records={rec["id"]: rec})
        up = {"nodejs": {"installed": "18.19.1+dfsg-6ubuntu5", "candidate": upgradable, "suite": "noble-updates"}} \
            if upgradable else {}
        findings, err = osvhost.match(facts([pkg("nodejs", "18.19.1+dfsg-6ubuntu5")], upgradable=up),
                                      {"CVE-2024-22018"}, self.cache, post=osv.post, fetch=osv.fetch)
        self.assertIsNone(err)
        [f] = [f for f in findings if f["group"] == "kev"]
        return f

    def test_fix_state(self):
        fixed = record("UBUNTU-CVE-2024-22018", "Ubuntu:24.04:LTS", "nodejs", fixed="18.19.1+dfsg-6ubuntu5.1",
                       upstream=["CVE-2024-22018"])
        f = self.kev_fix(fixed, upgradable="18.19.1+dfsg-6ubuntu5.2")
        self.assertEqual((f["fix"], f["fixed"], f["candidate"]),
                         ("installable", "18.19.1+dfsg-6ubuntu5.1", "18.19.1+dfsg-6ubuntu5.2"))

        pro = record("UBUNTU-CVE-2024-22018", "Ubuntu:24.04:LTS", "nodejs", upstream=["CVE-2024-22018"],
                     extra=[{"package": {"ecosystem": "Ubuntu:Pro:24.04:LTS", "name": "nodejs"},
                             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"},
                                                                         {"fixed": "18.19.1+dfsg-6ubuntu5+esm1"}]}]}])
        self.cache = Cache(Path(self._tmp.name) / "c2")
        f = self.kev_fix(pro)
        self.assertEqual((f["fix"], f["fixed"]), ("pro-only", "18.19.1+dfsg-6ubuntu5+esm1"))

        none = record("UBUNTU-CVE-2024-22018", "Ubuntu:24.04:LTS", "nodejs", upstream=["CVE-2024-22018"])
        self.cache = Cache(Path(self._tmp.name) / "c3")
        f = self.kev_fix(none)
        self.assertEqual((f["fix"], f["fixed"]), ("not released", None))

    def test_pro_is_looked_at_only_without_a_regular_fix(self):
        both = record("UBUNTU-CVE-2024-22018", "Ubuntu:24.04:LTS", "nodejs", fixed="18.19.1+dfsg-6ubuntu5.1",
                      upstream=["CVE-2024-22018"],
                      extra=[{"package": {"ecosystem": "Ubuntu:Pro:24.04:LTS", "name": "nodejs"},
                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"},
                                                                          {"fixed": "18.19.1+dfsg-6ubuntu5+esm1"}]}]}])
        f = self.kev_fix(both, upgradable="18.19.1+dfsg-6ubuntu5.1")
        self.assertEqual((f["fix"], f["fixed"]), ("installable", "18.19.1+dfsg-6ubuntu5.1"))

    def test_released_fix_the_candidate_does_not_reach(self):
        """A distro fix exists, but apt's candidate is older (stale lists, phased update): not "not released"."""
        fixed = record("UBUNTU-CVE-2024-22018", "Ubuntu:24.04:LTS", "nodejs", fixed="18.19.1+dfsg-6ubuntu5.3",
                       upstream=["CVE-2024-22018"])
        f = self.kev_fix(fixed, upgradable="18.19.1+dfsg-6ubuntu5.2", candidate_ids=["UBUNTU-CVE-2024-22018"])
        self.assertEqual((f["fix"], f["fixed"]), ("not installable", "18.19.1+dfsg-6ubuntu5.3"))
        f2 = self.kev_fix(fixed)
        self.assertEqual(f2["fix"], "not installable")
        self.assertIn("18.19.1+dfsg-6ubuntu5.3", f2["text"])

    def test_candidate_incomparable_with_source_versions_is_unknown(self):
        """cpp 4:12.2.0-3 is built from gcc-defaults 1.203: its candidate 4:12.2.0-4 says nothing about 1.204."""
        rec = record("DEBIAN-CVE-2023-4039", "Debian:12", "gcc-defaults", fixed="1.204", upstream=["CVE-2023-4039"])
        osv = FakeOSV(vulns={("gcc-defaults", "1.203"): [rec["id"], "DEBIAN-CVE-2022-27943"]}, records={rec["id"]: rec})
        up = {"cpp": {"installed": "4:12.2.0-3", "candidate": "4:12.2.0-4", "suite": "bookworm"}}
        findings, err = osvhost.match(facts([pkg("cpp", "4:12.2.0-3", "gcc-defaults", "1.203")], os=BOOKWORM,
                                            upgradable=up), {"CVE-2023-4039"}, self.cache, post=osv.post, fetch=osv.fetch)
        self.assertIsNone(err)
        kev, summary = findings
        self.assertEqual((kev["fix"], kev["fixed"], kev["candidate"]), ("unknown", "1.204", "4:12.2.0-4"))
        self.assertEqual(kev["text"], "CVE-2023-4039 (KEV) in cpp 4:12.2.0-3: fix 1.204 released; "
                                      "apt candidate 4:12.2.0-4 cannot be compared with source versions")
        self.assertEqual(summary["text"], "1 open CVE, update to 4:12.2.0-4 pending, coverage unknown")

    def test_recorded_openssl_fix_is_installable(self):
        rec = recorded("vuln-UBUNTU-CVE-2024-9143.json")
        osv = FakeOSV(vulns={("openssl", "3.0.13-0ubuntu3.4"): ["UBUNTU-CVE-2024-9143"]},
                      records={rec["id"]: rec})
        up = {"openssl": {"installed": "3.0.13-0ubuntu3.4", "candidate": "3.0.13-0ubuntu3.6", "suite": "noble-security"}}
        findings, err = osvhost.match(facts([pkg("openssl", "3.0.13-0ubuntu3.4")], upgradable=up), {"CVE-2024-9143"},
                                      self.cache, post=osv.post, fetch=osv.fetch)
        [kev] = [f for f in findings if f["group"] == "kev"]
        self.assertEqual((kev["fix"], kev["fixed"]), ("installable", "3.0.13-0ubuntu3.5"))
        self.assertIn("3.0.13-0ubuntu3.5", kev["text"])


class DetailTests(TmpCacheCase):
    def test_details_fetched_only_when_needed(self):
        qb = recorded("querybatch-openssl-noble.json")
        ids = [v["id"] for v in qb["results"][0]["vulns"]]
        rec = recorded("vuln-UBUNTU-CVE-2024-9143.json")
        osv = FakeOSV(vulns={("openssl", "3.0.13-0ubuntu3.4"): ids}, records={rec["id"]: rec})
        f = facts([pkg("openssl", "3.0.13-0ubuntu3.4")])

        findings, err = osvhost.match(f, {"CVE-1999-0001"}, self.cache, post=osv.post, fetch=osv.fetch)
        self.assertIsNone(err)
        self.assertEqual(osv.gets, [], "no KEV id and nothing upgradable: no record fetched")
        self.assertEqual(findings, [{"id": "vuln:openssl@3.0.13-0ubuntu3.4", "group": "vuln", "critical": False,
                                     "text": "38 open CVEs, no fix installable", "package": "openssl",
                                     "version": "3.0.13-0ubuntu3.4", "source": "openssl", "open": 38, "fixable": 0,
                                     "candidate": None}])

        findings, err = osvhost.match(f, {"CVE-2024-9143"}, self.cache, post=osv.post, fetch=osv.fetch)
        self.assertIsNone(err)
        self.assertEqual(osv.gets, ["https://api.osv.dev/v1/vulns/UBUNTU-CVE-2024-9143"])
        self.assertEqual([x["group"] for x in findings], ["kev", "vuln"])
        self.assertEqual(findings[1]["text"], "37 open CVEs, no fix installable")

        osvhost.match(f, {"CVE-2024-9143"}, self.cache, post=osv.post, fetch=osv.fetch)
        self.assertEqual(len(osv.gets), 1, "the record comes from the cache on the next run")

    def test_changed_record_is_fetched_again(self):
        rec = record("UBUNTU-CVE-2024-22018", "Ubuntu:24.04:LTS", "nodejs", upstream=["CVE-2024-22018"],
                     modified="2026-11-01T00:00:00Z")
        osv = FakeOSV(vulns={("nodejs", "1"): [rec["id"]]}, records={rec["id"]: rec})
        f = facts([pkg("nodejs", "1")])
        osvhost.match(f, {"CVE-2024-22018"}, self.cache, post=osv.post, fetch=osv.fetch)
        orig_post = osv.post

        def newer(url, body):
            out = orig_post(url, body)
            for r in out["results"]:
                for v in r.get("vulns", []):
                    v["modified"] = "2026-11-08T00:00:00Z"
            return out
        osvhost.match(f, {"CVE-2024-22018"}, self.cache, post=newer, fetch=osv.fetch)
        self.assertEqual(len(osv.gets), 2)

    def test_cached_record_is_trimmed_to_the_host_ecosystems(self):
        rec = recorded("vuln-UBUNTU-CVE-2024-9143.json")
        rec["affected"].append({"package": {"ecosystem": "Ubuntu:20.04:LTS", "name": "openssl"}, "ranges": []})
        osv = FakeOSV(vulns={("openssl", "3.0.13-0ubuntu3.4"): [rec["id"]]}, records={rec["id"]: rec})
        osvhost.match(facts([pkg("openssl", "3.0.13-0ubuntu3.4")]), {"CVE-2024-9143"}, self.cache,
                      post=osv.post, fetch=osv.fetch)
        [path] = list(self.cache.dir.glob("*.json"))
        stored = json.loads(path.read_text())["value"]["record"]
        self.assertEqual({a["package"]["ecosystem"] for a in stored["affected"]},
                         {"Ubuntu:24.04:LTS"})  # Pro:FIPS-updates and 20.04 dropped; no Ubuntu:Pro:24.04:LTS entry here

    def test_record_failure_keeps_the_kev_finding_and_reports_the_error(self):
        osv = FakeOSV(vulns={("openssl", "3.0.13-0ubuntu3.4"): ["UBUNTU-CVE-2024-9143"]})
        findings, err = osvhost.match(facts([pkg("openssl", "3.0.13-0ubuntu3.4")]), {"CVE-2024-9143"}, self.cache,
                                      post=osv.post, fetch=osv.fetch)
        [kev] = findings
        self.assertEqual((kev["group"], kev["critical"], kev["fix"]), ("kev", True, "unknown"))
        self.assertRegex(err, r"^osv\.dev: 1 vulnerability record\(s\) failed: UBUNTU-CVE-2024-9143: URLError")
        self.assertEqual(err.kind, "failed")


class EpssTests(TmpCacheCase):
    """EPSS scores on host findings: information only, never in an id or a text."""
    OPENSSL = "3.0.13-0ubuntu3.4"

    def openssl_match(self, **kw):
        osv = FakeOSV(vulns={("openssl", self.OPENSSL): ["UBUNTU-CVE-2024-9143", "UBUNTU-CVE-2024-13176",
                                                         "UBUNTU-CVE-2024-0002", "USN-7278-1"]},
                      records={"UBUNTU-CVE-2024-9143": recorded("vuln-UBUNTU-CVE-2024-9143.json")})
        findings, err = osvhost.match(facts([pkg("openssl", self.OPENSSL)]), {"CVE-2024-9143"}, self.cache,
                                      post=osv.post, fetch=osv.fetch, **kw)
        self.assertIsNone(err)
        by_id = {f["id"]: f for f in findings}
        return (findings, by_id[f"kev:CVE-2024-9143:openssl@{self.OPENSSL}"], by_id[f"vuln:openssl@{self.OPENSSL}"])

    def test_kev_and_vuln_findings_carry_epss(self):
        scores = {"CVE-2024-9143": (0.9144, 0.999), "CVE-2024-13176": (0.05, 0.9), "CVE-2024-0002": (0.01, 0.5)}
        _, kev_finding, vuln_finding = self.openssl_match(epss_scores=scores)
        self.assertEqual((kev_finding["epss"], kev_finding["epss_percentile"]), (0.9144, 0.999))
        self.assertEqual(vuln_finding["max_epss"], 0.05)
        self.assertNotIn("EPSS", kev_finding["text"] + kev_finding["id"] + vuln_finding["text"] + vuln_finding["id"])
        self.assertNotIn("epss", vuln_finding)
        self.assertNotIn("max_epss", kev_finding)

    def test_findings_without_epss_scores_are_unchanged(self):
        findings_before, _, _ = self.openssl_match()
        for f in findings_before:
            self.assertFalse({"epss", "epss_percentile", "max_epss"} & set(f), f["id"])
        findings, _, _ = self.openssl_match(epss_scores=None)
        self.assertEqual(findings, findings_before)

    def test_unscored_cve_is_none_not_zero(self):
        _, kev_finding, vuln_finding = self.openssl_match(epss_scores={})
        self.assertIsNone(kev_finding["epss"])
        self.assertIsNone(kev_finding["epss_percentile"])
        self.assertIsNone(vuln_finding["max_epss"])

    def test_kev_on_a_kernel_that_is_not_running_carries_epss(self):
        rec = recorded("vuln-UBUNTU-CVE-2024-1086.json")
        osv = FakeOSV(vulns={("linux", "6.8.0-45.45"): ["UBUNTU-CVE-2024-1086"],
                             ("linux", "6.8.0-40.40"): ["UBUNTU-CVE-2024-1086"]},
                      records={"UBUNTU-CVE-2024-1086": rec})
        findings, err = osvhost.match(facts(KERNELS), {"CVE-2024-1086"}, self.cache, post=osv.post, fetch=osv.fetch,
                                      epss_scores={"CVE-2024-1086": (0.75, 0.98)})
        self.assertIsNone(err)
        [info] = [f for f in findings if f["id"].startswith("info:kev:")]
        self.assertEqual((info["epss"], info["epss_percentile"]), (0.75, 0.98))
        self.assertNotIn("EPSS", info["text"])


class FailureTests(TmpCacheCase):
    def test_api_failure_is_error_not_clean(self):
        def post(url, body):
            raise urllib.error.URLError("connection refused")
        findings, err = osvhost.match(facts([pkg("openssl", "1")]), set(), self.cache, post=post, fetch=None)
        self.assertEqual(findings, [])
        self.assertEqual(err, "osv.dev: URLError: <urlopen error connection refused>")
        self.assertEqual(err.kind, "failed")

    def test_malformed_answer_is_error_not_clean(self):
        for answer in ({"results": []}, {"nope": 1}, [], {"results": ["x"]}, {"results": [{"vulns": "x"}]},
                       {"results": [{"vulns": [{"no-id": 1}]}]}):
            findings, err = osvhost.match(facts([pkg("openssl", "1")]), set(), self.cache,
                                          post=lambda url, body, a=answer: a, fetch=None)
            self.assertEqual(findings, [], answer)
            self.assertRegex(err or "", r"^osv\.dev: ", answer)
            self.assertEqual(err.kind, "failed")

    def test_no_packages_is_an_error_without_a_request(self):
        def post(url, body):
            raise AssertionError("no request expected")
        for packages in ([], None, [{"name": "x"}, "junk", {"name": 1, "version": 2}]):
            result = osvhost.match(facts(packages), set(), self.cache, post=post, fetch=None)
            self.assertEqual(result, ([], "no dpkg packages: dpkg section missing or failed"))
            self.assertEqual(result[1].kind, "failed")

    def test_malformed_record_never_raises(self):
        bad = {"id": "UBUNTU-CVE-2024-9143", "modified": "x", "affected": [
            "junk", {"package": "junk"},
            {"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "openssl"},
             "ranges": ["junk", {"events": "junk"}, {"events": ["junk", {"fixed": 5}, {"fixed": "3.0.13-0ubuntu3.5"}]}]}]}
        osv = FakeOSV(vulns={("openssl", "3.0.13-0ubuntu3.4"): ["UBUNTU-CVE-2024-9143"]}, records={bad["id"]: bad})
        findings, err = osvhost.match(facts([pkg("openssl", "3.0.13-0ubuntu3.4")], upgradable="junk"),
                                      {"CVE-2024-9143"}, self.cache, post=osv.post, fetch=osv.fetch)
        self.assertIsNone(err)
        [kev] = findings
        self.assertEqual((kev["fix"], kev["fixed"]), ("not installable", "3.0.13-0ubuntu3.5"))


class HttpPostJsonTests(unittest.TestCase):
    def test_posts_json_with_the_user_agent(self):
        seen = {}

        class Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                self.close()

        def urlopen(req, timeout):
            seen.update(method=req.get_method(), url=req.full_url, body=json.loads(req.data), timeout=timeout,
                        ua=req.get_header("User-agent"), ctype=req.get_header("Content-type"))
            return Resp(b'{"results": []}')

        with mock.patch.object(enrich.urllib.request, "urlopen", urlopen):
            out = enrich.http_post_json("https://example.invalid/q", {"queries": []}, timeout=7)
        self.assertEqual(out, {"results": []})
        self.assertEqual(seen, {"method": "POST", "url": "https://example.invalid/q", "body": {"queries": []},
                                "timeout": 7, "ua": enrich.UA, "ctype": "application/json"})

    def test_an_http_error_is_raised_with_its_body_closed(self):
        body = io.BytesIO(b'{"error": "nope"}')

        def urlopen(req, timeout):
            raise urllib.error.HTTPError(req.full_url, 400, "Bad Request", {}, body)  # type: ignore[arg-type]

        with mock.patch.object(enrich.urllib.request, "urlopen", urlopen):
            with self.assertRaises(urllib.error.HTTPError):
                enrich.http_post_json("https://example.invalid/q", {})
        self.assertTrue(body.closed)


if __name__ == "__main__":
    unittest.main()
