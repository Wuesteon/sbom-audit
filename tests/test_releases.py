"""Release scanning: config, tag selection, support periods, releases.json, and the run end to end."""
from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import cli, config, gitio, issues, management, pipeline, releases, report, status
from sbomaudit.config import Config, ReleasesOpts
from sbomaudit.errors import ConfigError
from sbomaudit.model import BranchInventory, Component, Finding

V3_CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def git(repo: Path, *args: str, when: str | None = None) -> str:
    env = dict(os.environ)
    if when:
        env.update(GIT_AUTHOR_DATE=when, GIT_COMMITTER_DATE=when)
    return subprocess.run(["git", "-C", str(repo), *args], check=True, text=True, capture_output=True,
                          env=env).stdout


def tagged_repo(root: Path, name: str, steps: list[tuple[str, str | None, str, bool]]) -> Path:
    """A repo on `main` with one commit per step: (tag, lodash version or None, ISO date, annotated)."""
    repo = root / name
    repo.mkdir(parents=True)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "Test")
    git(repo, "config", "commit.gpgsign", "false")
    git(repo, "config", "tag.gpgsign", "false")
    for tag, lodash, when, annotated in steps:
        (repo / "README").write_text(f"{tag}\n")
        if lodash:
            (repo / "LODASH").write_text(lodash)
        elif (repo / "LODASH").exists():
            (repo / "LODASH").unlink()
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", tag, when=when)
        if annotated:
            git(repo, "tag", "-a", tag, "-m", tag, when=when)
        else:
            git(repo, "tag", tag)
    return repo


def lodash(version: str, scope: str = "required") -> Component:
    return Component(kind="package", ecosystem="npm", name="lodash", version=version,
                     purl=f"pkg:npm/lodash@{version}", scope=scope, locations=["package-lock.json"], direct=True)


def fake_syft(src: Path, exclude=None):
    """The exported tree's LODASH file names the lodash version in it."""
    f = Path(src) / "LODASH"
    comps = [lodash(f.read_text().strip())] if f.exists() else []
    entries = [{"type": "library", "bom-ref": c.purl, "name": c.name, "version": c.version, "purl": c.purl}
               for c in comps]
    return {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1, "components": entries}, comps


def fake_osv(sbom: Path, cache: Path):
    """GHSA-1 (critical) for lodash 4.17.20, nothing else."""
    if "lodash@4.17.20" not in Path(sbom).read_text(encoding="utf-8"):
        return {"results": []}
    return {"results": [{"packages": [{
        "package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm", "purl": "pkg:npm/lodash@4.17.20"},
        "vulnerabilities": [{
            "id": "GHSA-1", "aliases": ["CVE-2026-1"], "summary": "prototype pollution",
            "severity": [{"type": "CVSS_V3", "score": V3_CRIT}],
            "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
        }]}]}]}


class TmpCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()
        self.root = self.tmp / "PROJECTS"
        self.out = self.root / "security"
        self.out.mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def toml(self, text: str) -> Config:
        (self.out / "sbom-audit.toml").write_text(text)
        return config.load(self.out)


class ConfigTests(TmpCase):
    def test_off_by_default(self):
        cfg = config.load(self.out)
        self.assertIsNone(cfg.releases)
        self.assertIsNone(config.release_opts(cfg, "anything"))

    def test_portfolio_default_and_project_overrides(self):
        cfg = self.toml('[releases]\ntags = "v*"\nsupport_months = 60\n'
                        '[projects]\n'
                        'app = { releases = { tags = "app-v*", keep = 5, support_until = 2031-12-31 } }\n'
                        'lib = { releases = false }\n'
                        'svc = { releases = true }\n')
        self.assertEqual(config.release_opts(cfg, "other"), ReleasesOpts(tags="v*", keep=3, support_months=60))
        self.assertEqual(config.release_opts(cfg, "svc"), ReleasesOpts(tags="v*", keep=3, support_months=60))
        self.assertIsNone(config.release_opts(cfg, "lib"))
        self.assertEqual(config.release_opts(cfg, "app"),
                         ReleasesOpts(tags="app-v*", keep=5, support_months=60, support_until=dt.date(2031, 12, 31)))

    def test_project_only_release_scanning(self):
        cfg = self.toml('[projects]\napp = { releases = { tags = "v*", support_until = "2030-06-30" } }\n')
        self.assertIsNone(config.release_opts(cfg, "other"))
        self.assertEqual(config.release_opts(cfg, "app").support_until, dt.date(2030, 6, 30))

    def test_refused_settings(self):
        for text, needle in (
                ('[releases]\nkeep = 2\n', "tags is required"),
                ('[releases]\ntags = "v*"\nkepp = 2\n', "unknown key kepp"),
                ('[releases]\ntags = "v*"\nkeep = 0\n', "keep"),
                ('[releases]\ntags = "v*"\nsupport_until = "soon"\n', "support_until"),
                ('[releases]\ntags = "v*"\nsupport_until = 2031-12-31T00:00:00\n', "support_until"),
                ('[projects]\napp = { releases = true }\n', "releases = true"),
                ('[projects]\napp = { releases = { keep = 2 } }\n', "needs tags")):
            with self.subTest(text=text):
                with self.assertRaises(ConfigError) as ctx:
                    self.toml(text)
                self.assertIn(needle, str(ctx.exception))

    def test_default_config_template_still_loads(self):
        config.write_default(self.out, config.load(self.out))
        self.assertIn("# [releases]", (self.out / "sbom-audit.toml").read_text())
        self.assertIsNone(config.load(self.out).releases)


class SelectionTests(unittest.TestCase):
    def tags(self, *names, dates=None):
        dates = dates or ["2025-01-01T00:00:00+00:00"] * len(names)
        return [{"tag": n, "ref": f"refs/tags/{n}", "commit": "c" * 40, "date": d} for n, d in zip(names, dates)]

    def test_version_order_beats_name_order(self):
        chosen, order = releases.select(self.tags("v1.10.0", "v1.9.0", "v1.2.0", "v2.0.0-rc.1", "v2.0.0"), 3)
        self.assertEqual(order, "version")
        self.assertEqual([t["tag"] for t in chosen], ["v1.10.0", "v2.0.0-rc.1", "v2.0.0"])

    def test_pattern_prefix_digits_are_not_the_version(self):
        chosen, order = releases.select(self.tags("app2-v1.0", "app2-v0.9"), 5, "app2-v*")
        self.assertEqual((order, [t["tag"] for t in chosen]), ("version", ["app2-v0.9", "app2-v1.0"]))

    def test_date_order_when_a_tag_is_not_a_version(self):
        tags = self.tags("stable", "v1.0", "v0.5", dates=["2025-03-01T00:00:00+00:00",
                                                          "2025-01-01T10:00:00+02:00",
                                                          "2025-02-01T00:00:00Z"])
        chosen, order = releases.select(tags, 2)
        self.assertEqual((order, [t["tag"] for t in chosen]), ("date", ["v0.5", "stable"]))

    def test_support_until_is_the_later_of_both_settings(self):
        day = dt.date(2025, 1, 31)
        self.assertEqual(releases.add_months(day, 1), dt.date(2025, 2, 28))
        self.assertEqual(releases.add_months(day, 60), dt.date(2030, 1, 31))
        self.assertIsNone(releases.support_until(ReleasesOpts(tags="v*"), day))
        self.assertEqual(releases.support_until(ReleasesOpts(tags="v*", support_months=12), day), dt.date(2026, 1, 31))
        both = ReleasesOpts(tags="v*", support_months=12, support_until=dt.date(2027, 6, 30))
        self.assertEqual(releases.support_until(both, day), dt.date(2027, 6, 30))
        self.assertEqual(releases.support_until(both, dt.date(2027, 1, 1)), dt.date(2028, 1, 1))


class ListTagsTests(TmpCase):
    def test_lightweight_annotated_and_non_commit_tags(self):
        repo = tagged_repo(self.root, "app", [("v1.0.0", None, "2025-01-02T03:04:05+00:00", False),
                                              ("v1.1.0", None, "2025-02-03T04:05:06+00:00", True)])
        git(repo, "tag", "v-tree", "HEAD^{tree}")
        git(repo, "tag", "other", "HEAD")
        tags = {t["tag"]: t for t in gitio.list_tags(repo, "v*")}
        self.assertEqual(sorted(tags), ["v1.0.0", "v1.1.0"])
        self.assertEqual(tags["v1.1.0"]["commit"], git(repo, "rev-parse", "v1.1.0^{commit}").strip())
        self.assertEqual(tags["v1.1.0"]["ref"], "refs/tags/v1.1.0")
        self.assertTrue(tags["v1.0.0"]["date"].startswith("2025-01-02T03:04:05"))
        self.assertTrue(tags["v1.1.0"]["date"].startswith("2025-02-03T04:05:06"))


class BuildTests(unittest.TestCase):
    """releases.build on hand-made inventories and findings."""

    def inv(self, tag, index, date, comps=(), errors=()):
        return BranchInventory(project="app", branch=releases.label(tag), ref=f"refs/tags/{tag}", commit=f"{index}" * 40,
                               components=list(comps), sbom_path=f"sbom/app/tags__{tag}.cdx.json", errors=list(errors),
                               release={"tag": tag, "date": date, "order": "version", "index": index})

    def finding(self, inv, comp, vid="GHSA-1", kev=False):
        return Finding(project=inv.project, branch=inv.branch, component=comp,
                       vulns=[{"id": vid, "severity": "CRITICAL", "cvss": 9.8, "kev": kev}])

    def cfg(self, **opts):
        return Config(out=Path("/nonexistent"), root=Path("/nonexistent"), mode="portfolio", fetch=False,
                      releases=ReleasesOpts(tags="v*", **opts))

    def test_fixed_first_seen_days_and_open_counts(self):
        old, bad = lodash("4.17.20"), lodash("4.17.20")
        a = self.inv("v1.0", 0, "2025-01-01T00:00:00Z", [old])
        b = self.inv("v1.1", 1, "2025-03-01T00:00:00Z", [bad])
        c = self.inv("v1.2", 2, "2025-04-01T00:00:00Z", [lodash("4.17.21")])
        present = [self.finding(a, old), self.finding(b, bad, kev=True)]
        doc = releases.build(self.cfg(support_months=12), [a, b, c], present, present, [], {},
                             today=dt.date(2026, 2, 1), generated="g")
        rows = {r["tag"]: r for r in doc["projects"]["app"]["releases"]}
        self.assertEqual([r["tag"] for r in doc["projects"]["app"]["releases"]], ["v1.2", "v1.1", "v1.0"])
        self.assertFalse(rows["v1.0"]["supported"])
        self.assertEqual(rows["v1.0"]["support_until"], "2026-01-01")
        self.assertTrue(rows["v1.2"]["supported"])
        self.assertEqual(rows["v1.1"]["open"], {"kev": 1, "critical": 1, "high": 0})
        self.assertEqual(rows["v1.1"]["fixed_since_previous"], [])
        [fixed] = rows["v1.2"]["fixed_since_previous"]
        self.assertEqual({k: fixed[k] for k in ("id", "package", "first_seen", "first_seen_is_oldest_kept", "days",
                                                "versions_before", "versions_after")},
                         {"id": "GHSA-1", "package": "lodash", "first_seen": "v1.0", "first_seen_is_oldest_kept": True,
                          "days": 90, "versions_before": ["4.17.20"], "versions_after": ["4.17.21"]})
        self.assertEqual({k: fixed[k] for k in ("change", "removed_versions", "remaining_versions", "new_versions")},
                         {"change": "upgraded", "removed_versions": ["4.17.20"], "remaining_versions": [],
                          "new_versions": ["4.17.21"]})
        self.assertIsNone(rows["v1.0"]["previous"])
        self.assertEqual(doc["projects"]["app"]["support"], {"period_months": 12, "until": None})

    def test_removed_lockfile_is_not_shown_as_a_downgrade(self):
        """The real case: two lockfiles, 4.17.21 and 4.17.23; the advisory matched 4.17.23 only and that
        lockfile was deleted. Not an upgrade and not a downgrade: the affected copy went, 4.17.21 stayed."""
        old, new = lodash("4.17.21"), lodash("4.17.23")
        a = self.inv("v1.0", 0, "2025-01-01", [old, new])
        b = self.inv("v1.1", 1, "2025-01-13", [lodash("4.17.21")])
        present = [self.finding(a, new, vid="GHSA-f23m")]
        doc = releases.build(self.cfg(), [a, b], present, present, [], {})
        [fixed] = doc["projects"]["app"]["releases"][0]["fixed_since_previous"]
        self.assertEqual((fixed["versions_before"], fixed["versions_after"]), (["4.17.23"], ["4.17.21"]))  # unchanged
        self.assertEqual({k: fixed[k] for k in ("change", "removed_versions", "remaining_versions", "new_versions")},
                         {"change": "affected_removed", "removed_versions": ["4.17.23"],
                          "remaining_versions": ["4.17.21"], "new_versions": []})
        text = releases.change_text(fixed, "v1.0")
        self.assertEqual(text, "4.17.23 removed; 4.17.21 remains (already in v1.0, not matched by this advisory); "
                               "no new version of the package")
        self.assertNotIn("→", text)
        md = releases.render_md(doc)
        self.assertIn("| GHSA-f23m | lodash (npm) | 4.17.23 removed; 4.17.21 remains (already in v1.0", md)
        self.assertNotIn("4.17.23 → 4.17.21", md)

    def test_change_kinds(self):
        c = releases.change
        self.assertEqual(c(["1.0"], ["1.0"], [])["change"], "package_gone")
        self.assertEqual(c(["1.0"], ["1.0"], ["2.0"])["change"], "upgraded")
        self.assertEqual(c(["1.10"], ["1.10"], ["1.9"])["change"], "replaced")       # lower: never "upgraded"
        up = c(["1.0"], ["1.0", "1.5"], ["1.5", "2.0"])
        self.assertEqual((up["change"], up["remaining_versions"], up["new_versions"]), ("upgraded", ["1.5"], ["2.0"]))
        self.assertEqual(c(["1.0"], ["1.0", "1.5"], ["1.5"])["change"], "affected_removed")
        self.assertEqual(c(["1.0"], ["1.0"], ["1.0"])["change"], "no_longer_matched")
        self.assertEqual(releases.change_text({"change": "package_gone", "removed_versions": ["1.0"]}, "v1"),
                         "1.0 removed; the package is no longer in the SBOM")
        self.assertEqual(releases.change_text({"change": "upgraded", "removed_versions": ["1.0"],
                                               "remaining_versions": ["1.5"], "new_versions": ["2.0"]}, "v1"),
                         "1.0 removed, upgraded to 2.0 (new in this release); 1.5 also present (already in v1, "
                         "not matched by this advisory)")
        self.assertIn("not a higher version", releases.change_text(
            {"change": "replaced", "removed_versions": ["1.10"], "new_versions": ["1.9"]}, "v1"))
        self.assertIn("still in the SBOM", releases.change_text(
            {"change": "no_longer_matched", "versions_before": ["1.0"], "versions_after": ["1.0"]}, "v1"))
        # an entry from a releases.json written before `change` existed reads as it always did
        self.assertEqual(releases.change_text({"versions_before": ["1.0"], "versions_after": ["2.0"]}, "v1"),
                         "1.0 → 2.0")

    def test_incomplete_scan_makes_fixed_unknown(self):
        a = self.inv("v1.0", 0, "2025-01-01", [lodash("4.17.20")])
        b = self.inv("v1.1", 1, "2025-03-01", errors=["syft: boom"])
        present = [self.finding(a, a.components[0])]
        rows = releases.build(self.cfg(), [a, b], present, present, [], {})["projects"]["app"]["releases"]
        self.assertTrue(rows[0]["fixed_since_previous_unknown"])
        self.assertEqual(rows[0]["fixed_since_previous"], [])
        # an osv-scanner failure on the previous release counts too
        b.errors = []
        sources = {"osv-scanner": {"failed": [("app", a.branch, "boom")]}}
        rows = releases.build(self.cfg(), [a, b], [], [], [], sources)["projects"]["app"]["releases"]
        self.assertTrue(rows[0].get("fixed_since_previous_unknown"))

    def test_dev_only_left_out_of_open_counts(self):
        a = self.inv("v1.0", 0, "2025-01-01", [lodash("4.17.20", scope="optional")])
        present = [self.finding(a, a.components[0])]
        [row] = releases.build(self.cfg(), [a], present, present, [], {})["projects"]["app"]["releases"]
        self.assertEqual(row["open"], {"kev": 0, "critical": 0, "high": 0})
        self.assertIsNone(row["support_until"])
        self.assertTrue(row["supported"])

    def test_eol_before_support_end(self):
        a = self.inv("v1.0", 0, "2025-01-01")
        eol = [{"project": "app", "branch": a.branch, "product": "nodejs", "cycle": "20", "eol_date": "2026-04-30"},
               {"project": "app", "branch": a.branch, "product": "python", "cycle": "3.13", "eol_date": "2029-10-31"},
               {"project": "app", "branch": "main", "product": "nodejs", "cycle": "18", "eol_date": "2025-04-30"}]
        [row] = releases.build(self.cfg(support_months=60), [a], [], [], eol, {})["projects"]["app"]["releases"]
        self.assertEqual(row["support_until"], "2030-01-01")
        self.assertEqual(row["eol_before_support_end"], ["nodejs 20 (EOL 2026-04-30)", "python 3.13 (EOL 2029-10-31)"])

    def test_project_without_release_scanning_is_absent(self):
        main = BranchInventory(project="app", branch="main", ref="main", commit="a" * 40)
        doc = releases.build(self.cfg(), [main], [], [], [], {})
        self.assertEqual(doc["projects"], {})
        self.assertEqual(doc["schema"], 1)
        self.assertIn("No project has release scanning configured", releases.render_md(doc))


class ReportTests(unittest.TestCase):
    def test_out_of_support_release_is_not_open_work(self):
        cfg = Config(out=Path("/nonexistent"), root=Path("/nonexistent"), mode="portfolio", fetch=False)
        comp = lodash("4.17.20")
        invs, findings = [], []
        for tag, idx in (("v1.0", 0), ("v1.1", 1)):
            inv = BranchInventory(project="app", branch=releases.label(tag), ref=tag, commit="c" * 40,
                                  components=[comp], release={"tag": tag, "date": "2025-01-01", "index": idx})
            invs.append(inv)
            findings.append(Finding(project="app", branch=inv.branch, component=comp,
                                    vulns=[{"id": "GHSA-1", "severity": "CRITICAL", "cvss": 9.8}]))
        main = BranchInventory(project="app", branch="main", ref="main", commit="d" * 40)
        ctx = {("app", "tags/v1.0"): {"tag": "v1.0", "date": "2025-01-01", "supported": False,
                                      "support_until": "2025-06-01"},
               ("app", "tags/v1.1"): {"tag": "v1.1", "date": "2025-01-01", "supported": True,
                                      "support_until": "2030-01-01"}}
        rep = report.build(cfg, [main, *invs], findings, [], [], [], {}, releases=ctx)
        [vuln] = rep["vulnerabilities"]
        self.assertEqual([(l["branch"], l.get("release")) for l in vuln["locations"]], [("tags/v1.1", "v1.1")])
        self.assertEqual(rep["stats"]["branches"], 1)
        self.assertEqual([(r["tag"], r["supported"]) for r in rep["releases"]], [("v1.0", False), ("v1.1", True)])
        self.assertTrue(report.counts_as_production(vuln["locations"][0], set()))
        self.assertFalse(report.counts_as_production({"project": "app", "scope": "required"}, set()))
        # without releases the report has no releases key (unchanged shape)
        self.assertNotIn("releases", report.build(cfg, [main], [], [], [], [], {}))


class EndToEndTests(TmpCase):
    """A real repository with four tags, scanned and audited through `pipeline.run`."""

    def setUp(self):
        super().setUp()
        tagged_repo(self.root, "app", [("v0.9.0", None, "2025-01-01T12:00:00+00:00", False),
                                       ("v1.0.0", "4.17.20", "2025-03-01T12:00:00+00:00", True),
                                       ("v1.1.0", "4.17.20", "2025-06-01T12:00:00+00:00", False),
                                       ("v1.2.0", "4.17.21", "2025-09-01T12:00:00+00:00", True)])
        tagged_repo(self.root, "web", [("v1.0.0", "4.17.20", "2025-01-01T12:00:00+00:00", False)])
        (self.out / "sbom-audit.toml").write_text(
            'branches = ["main"]\nfetch = false\nignore_projects = ["security"]\n'
            '[releases]\ntags = "v*"\nkeep = 4\nsupport_months = 1200\n'
            '[secrets]\nenabled = false\n'
            '[projects]\nweb = { releases = false }\n')
        self.cfg = config.load(self.out)
        with mock.patch("sbomaudit.preflight.shutil.which", lambda tool: f"/stub/bin/{tool}"), \
             mock.patch("sbomaudit.scan.syft.inventory", side_effect=fake_syft), \
             mock.patch.object(pipeline.matching, "run_osv_scanner", side_effect=fake_osv), \
             contextlib.redirect_stdout(io.StringIO()):
            self.said: list[str] = []
            self.rc = pipeline.run(self.cfg, http=lambda url: {}, log=self.said.append)

    def test_releases_json_shape_and_remediation(self):
        doc = json.loads((self.out / "releases.json").read_text())
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(list(doc["projects"]), ["app"])
        app = doc["projects"]["app"]
        self.assertEqual(app["support"], {"period_months": 1200, "until": None})
        self.assertEqual(app["order"], "version")
        rows = app["releases"]
        self.assertEqual([r["tag"] for r in rows], ["v1.2.0", "v1.1.0", "v1.0.0", "v0.9.0"])
        for r in rows:
            for key in ("tag", "commit", "date", "supported", "support_until", "sbom", "open",
                        "eol_before_support_end", "fixed_since_previous"):
                self.assertIn(key, r)
            self.assertTrue((self.out / r["sbom"]).exists(), r["sbom"])
        self.assertEqual(rows[0]["sbom"], "sbom/app/tags__v1.2.0.cdx.json")
        self.assertEqual(rows[2]["open"], {"kev": 0, "critical": 1, "high": 0})
        [fixed] = rows[0]["fixed_since_previous"]
        self.assertEqual((fixed["id"], fixed["package"], fixed["first_seen"], fixed["first_seen_is_oldest_kept"],
                          fixed["days"]), ("GHSA-1", "lodash", "v1.0.0", False, 184))
        self.assertTrue(any("keeping 4, ordered by version" in s for s in self.said), self.said)

    def test_fixed_command(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["releases", "--project", "app", "--fixed", "v1.2.0", "--json", "--out", str(self.out)])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual((data["previous"], [f["id"] for f in data["fixed_since_previous"]]), ("v1.1.0", ["GHSA-1"]))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(cli.main(["releases", "--project", "app", "--fixed", "v1.2.0", "--out", str(self.out)]), 0)
        self.assertIn("GHSA-1", buf.getvalue())
        self.assertIn("first seen v1.0.0", buf.getvalue())
        self.assertIn("GHSA-1  lodash (npm): 4.17.20 removed, upgraded to 4.17.21 (new in this release); "
                      "first seen v1.0.0", buf.getvalue())
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["releases", "--project", "app", "--fixed", "v9", "--out", str(self.out)]), 1)
            self.assertEqual(cli.main(["releases", "--project", "web", "--out", str(self.out)]), 1)
            self.assertEqual(cli.main(["releases", "--fixed", "v1.2.0", "--out", str(self.out)]), 2)
        with contextlib.redirect_stdout(io.StringIO()) as listing:
            self.assertEqual(cli.main(["releases", "--out", str(self.out)]), 0)
        self.assertIn("v0.9.0", listing.getvalue())

    def test_release_is_the_location_in_reports_and_work_list(self):
        audit = json.loads((self.out / "audit.json").read_text())
        [vuln] = [v for v in audit["vulnerabilities"] if v["name"] == "lodash"]
        app_locs = sorted(l["branch"] for l in vuln["locations"] if l["project"] == "app")
        self.assertEqual(app_locs, ["tags/v1.0.0", "tags/v1.1.0"])
        self.assertEqual(audit["stats"]["releases"], 4)
        work = json.loads((self.out / "issues.json").read_text())
        [issue] = [i for i in work["issues"] if "GHSA-1" in json.dumps(i) and i["where"].get("releases")]
        self.assertEqual(issue["priority"], 3)          # a supported release ranks like production
        self.assertEqual(issue["where"]["releases"], ["v1.0.0", "v1.1.0"])
        st = status.read(self.out)
        self.assertEqual(st["counts"]["releases"], {"scanned": 4, "supported": 4})
        self.assertIn("4 releases under audit", (self.out / "STATUS.md").read_text())
        self.assertIn("## Releases", (self.out / "INVENTORY.md").read_text())
        self.assertIn("## Releases under audit", (self.out / "AUDIT.md").read_text())
        self.assertIn("No longer present in `v1.2.0`", (self.out / "RELEASES.md").read_text())

    def test_management_report_en_and_de(self):
        data = management.load(self.out)
        en = management.render(data, lang="en")
        de = management.render(data, lang="de")
        self.assertIn("Releases under audit", en)
        self.assertIn("1 vs v1.1.0", en)
        self.assertIn("1 upgraded to a higher version", en)
        self.assertIn("1 auf eine höhere Version aktualisiert", de)
        self.assertIn("SBOM per released version", en)
        self.assertIn("2 project branches (app, web)", en)
        self.assertIn("4 release tags under audit", en)
        self.assertIn("Releases unter Prüfung", de)
        self.assertIn("SBOM je veröffentlichter Version", de)
        # releases are not listed again as scanned branches
        coverage = en.split("Projects and branches read", 1)[1].split("</table>", 1)[0]
        self.assertNotIn("tags/v1.0.0", coverage)

    def test_portfolio_without_release_config_is_unchanged(self):
        (self.out / "sbom-audit.toml").write_text('branches = ["main"]\nfetch = false\n[secrets]\nenabled = false\n')
        cfg = config.load(self.out)
        with mock.patch("sbomaudit.preflight.shutil.which", lambda tool: f"/stub/bin/{tool}"), \
             mock.patch("sbomaudit.scan.syft.inventory", side_effect=fake_syft), \
             mock.patch.object(pipeline.matching, "run_osv_scanner", side_effect=fake_osv), \
             contextlib.redirect_stdout(io.StringIO()):
            pipeline.run(cfg, http=lambda url: {}, log=lambda m: None)
        inv = json.loads((self.out / "inventory.json").read_text())
        self.assertFalse(any(i.get("release") for i in inv["inventories"]))
        self.assertEqual(json.loads((self.out / "releases.json").read_text())["projects"], {})
        self.assertNotIn("releases", json.loads((self.out / "audit.json").read_text()))
        self.assertNotIn("releases", status.read(self.out)["counts"])


if __name__ == "__main__":
    unittest.main()
