"""Pipeline: scan → match → enrich → VEX → report, with exit codes; a broken VEX file aborts."""
from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import __version__, cli, config, evidence, pipeline, preflight, scan, status, vex
from sbomaudit.config import Config
from sbomaudit.hosts import store as hosts_store
from sbomaudit.errors import ToolError
from sbomaudit.model import BranchInventory, Component
from sbomaudit.readers import runtime_component

from tests.helpers import epss_fetch, epss_gz, make_repo

V3_CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
LODASH = Component(kind="package", ecosystem="npm", name="lodash", version="4.17.20",
                   purl="pkg:npm/lodash@4.17.20", scope="required",
                   locations=["package-lock.json"], direct=True)


def osv_hit() -> dict:
    return {"results": [{"packages": [{
        "package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm",
                    "purl": "pkg:npm/lodash@4.17.20"},
        "vulnerabilities": [{
            "id": "GHSA-1", "aliases": ["CVE-2026-1"], "summary": "prototype pollution",
            "severity": [{"type": "CVSS_V3", "score": V3_CRIT}],
            "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                          "ranges": [{"type": "SEMVER",
                                      "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
        }]}]}]}


def offline(url: str):
    """Every enrichment answer is empty: no KEV entries, no registry data."""
    return {}


def tools_present():
    """Preflight sees every tool, whatever the machine running the tests has installed."""
    return mock.patch("sbomaudit.preflight.shutil.which", lambda tool: f"/stub/bin/{tool}")


def which_without(*missing):
    return lambda tool: None if tool in missing else f"/stub/bin/{tool}"


def make_cfg(tmp: Path) -> Config:
    root = tmp / "root"
    out = root / "security"
    out.mkdir(parents=True)
    return Config(out=out, root=root, mode="portfolio", fetch=False)


def inventory(project="zeta", branch="main", components=(LODASH,)) -> BranchInventory:
    return BranchInventory(project=project, branch=branch, ref=branch, commit="abc1234def",
                           components=list(components), sbom_path=f"sbom/{project}/{branch}.cdx.json")


def scan_result(*invs: BranchInventory) -> scan.ScanResult:
    return scan.ScanResult(inventories=list(invs), generated_at="2026-11-06T10:00:00Z")


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, text=True,
                          capture_output=True).stdout


def git_init(out: Path) -> None:
    """`out` becomes its own repository with an identity; `.cache/` excluded as setup's .gitignore does."""
    git(out, "init", "-q", "-b", "main")
    git(out, "config", "user.email", "test@example.invalid")
    git(out, "config", "user.name", "Test")
    git(out, "config", "commit.gpgsign", "false")
    (out / ".git" / "info" / "exclude").write_text(".cache/\n")


ASSESS_HEADER = "<!-- proposal written by headless assessment, not applied; review with /sbom-audit:assess -->"


class BrokenRepoTests(unittest.TestCase):
    """A project whose `.git` is an empty folder (a broken or half-cloned repo) is a failed source:
    exit 2, named under Source status, STATUS.md written. Never a traceback, never exit 1."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()
        self.cfg = make_cfg(self.tmp)
        (self.cfg.root / "broken" / ".git").mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def test_scan_records_git_failure_per_requested_branch(self):
        result = scan.scan(self.cfg, fetch=False)
        self.assertEqual([(i.project, i.branch) for i in result.inventories],
                         [("broken", b) for b in self.cfg.branches])
        self.assertTrue(all(i.errors and i.errors[0].startswith("git: ") for i in result.inventories))

    def test_run_exits_2_and_writes_status(self):
        said: list[str] = []
        with tools_present(), mock.patch.object(pipeline.matching, "run_osv_scanner") as run_osv, \
             contextlib.redirect_stdout(io.StringIO()):
            rc = pipeline.run(self.cfg, http=offline, log=said.append)
        self.assertEqual(rc, pipeline.EXIT_SOURCE_FAILED)
        run_osv.assert_not_called()
        self.assertTrue((self.cfg.out / status.STATUS_FILE).exists(), "STATUS.md not written")
        self.assertEqual(status.read(self.cfg.out)["exit_code"], 2)
        audit_md = (self.cfg.out / "AUDIT.md").read_text(encoding="utf-8")
        source_status = audit_md.split("## Source status", 1)[1].split("\n## ", 1)[0]
        self.assertIn("| git | **partial**", source_status)
        self.assertIn("broken@main", source_status)

    def test_cli_run_and_scan_exit_2(self):
        out = str(self.cfg.out)
        with tools_present(), mock.patch.object(pipeline.enrich, "http_get_json", offline), \
             mock.patch.object(pipeline.epss, "http_get_bytes", epss_fetch(epss_gz())), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["--out", out, "scan", "--no-fetch"]), 2)
            self.assertEqual(cli.main(["--out", out, "run", "--no-fetch"]), 2)
        self.assertTrue((self.cfg.out / status.STATUS_FILE).exists(), "STATUS.md not written")

    def test_read_only_still_exits_5_without_writing(self):
        with mock.patch.dict(os.environ, {"SBOM_AUDIT_READ_ONLY": "1"}), \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["--out", str(self.cfg.out), "run"]), 5)
            self.assertEqual(cli.main(["--out", str(self.cfg.out), "scan"]), 5)
        self.assertEqual(list(self.cfg.out.iterdir()), [])

    def test_unexpected_error_before_the_audit_still_writes_failed_status(self):
        said: list[str] = []
        with tools_present(), mock.patch.object(pipeline.scan, "scan", side_effect=RuntimeError("boom")), \
             contextlib.redirect_stdout(io.StringIO()):
            rc = pipeline.run(self.cfg, http=offline, log=said.append)
        self.assertEqual(rc, pipeline.EXIT_SOURCE_FAILED)
        doc = status.read(self.cfg.out)
        self.assertEqual(doc["exit_code"], 2)
        self.assertEqual(doc["failed_sources"], [{"source": "run", "detail": "RuntimeError: boom"}])
        self.assertEqual(doc["commit"]["status"], "skipped")
        md_text = (self.cfg.out / status.STATUS_FILE).read_text(encoding="utf-8")
        self.assertIn("last run FAILED (exit 2)", md_text)
        self.assertIn("- run: FAILED: RuntimeError: boom", md_text)


class RunTests(unittest.TestCase):
    def run_with(self, tmp: Path, osv, invs=None, before=None, http=offline,
                 http_bytes=None) -> tuple[int, Config]:
        cfg = make_cfg(tmp)
        if before:
            before(cfg)
        self.said: list[str] = []
        with tools_present(), \
             mock.patch.object(pipeline.scan, "scan", return_value=scan_result(*(invs or [inventory()]))), \
             mock.patch.object(pipeline.matching, "run_osv_scanner", **osv) as run_osv, \
             contextlib.redirect_stdout(io.StringIO()):
            rc = pipeline.run(cfg, http=http, log=self.said.append, http_bytes=http_bytes)
        self.osv_calls = run_osv.call_count
        return rc, cfg

    @staticmethod
    def epss_hit() -> dict:
        """osv_hit() with the alias CVE-2021-23337, the CVE epss_gz() scores (CVE-2026-1 is not a valid CVE id)."""
        hit = osv_hit()
        hit["results"][0]["packages"][0]["vulnerabilities"][0]["aliases"] = ["CVE-2021-23337"]
        return hit

    def audit_json(self, cfg: Config) -> dict:
        return json.loads((cfg.out / "audit.json").read_text())

    def test_epss_scores_reach_audit_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, cfg = self.run_with(Path(tmp), {"return_value": self.epss_hit()}, http_bytes=epss_fetch(epss_gz()))
            rep = self.audit_json(cfg)
        self.assertEqual(rc, pipeline.EXIT_FINDINGS)
        self.assertEqual(rep["epss"], {"threshold": 0.10, "available": True,
                                       "score_date": "2026-11-23T12:00:23Z", "model_version": "v2026.06.15"})
        row = rep["vulnerabilities"][0]
        self.assertEqual((row["max_epss"], row["vulns"][0]["epss"], row["vulns"][0]["epss_percentile"]),
                         (0.0123, 0.0123, 0.79))
        self.assertEqual(rep["sources"]["epss"]["origin"], "live")
        self.assertIn("EPSS …", self.said)

    def test_no_epss_step_when_only_http_is_injected(self):
        with mock.patch.object(pipeline.epss, "http_get_bytes", epss_fetch(OSError("must not be called"))) as fetch, \
             tempfile.TemporaryDirectory() as tmp:
            rc, cfg = self.run_with(Path(tmp), {"return_value": self.epss_hit()})
            rep = self.audit_json(cfg)
        self.assertEqual(rc, pipeline.EXIT_FINDINGS)
        self.assertNotIn("epss", rep)
        self.assertNotIn("epss", rep["sources"])
        self.assertNotIn("max_epss", rep["vulnerabilities"][0])
        self.assertNotIn("epss", rep["vulnerabilities"][0]["vulns"][0])
        self.assertEqual(fetch.calls, [])

    def test_epss_disabled_by_config(self):
        def disable(cfg):
            (cfg.out / config.CONFIG_NAME).write_text("[epss]\nenabled = false\n")
            cfg.epss = config.load(cfg.out).epss
        fetch = epss_fetch(epss_gz())
        with tempfile.TemporaryDirectory() as tmp:
            rc, cfg = self.run_with(Path(tmp), {"return_value": self.epss_hit()}, before=disable, http_bytes=fetch)
            rep = self.audit_json(cfg)
        self.assertEqual(rc, pipeline.EXIT_FINDINGS)
        self.assertNotIn("epss", rep)
        self.assertNotIn("epss", rep["sources"])
        self.assertNotIn("max_epss", rep["vulnerabilities"][0])
        self.assertEqual(fetch.calls, [])

    def test_epss_outage_without_cache_fails_the_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, cfg = self.run_with(Path(tmp), {"return_value": self.epss_hit()},
                                    http_bytes=epss_fetch(OSError("down")))
            rep = self.audit_json(cfg)
        self.assertEqual(rc, pipeline.EXIT_SOURCE_FAILED)
        self.assertEqual((rep["epss"]["available"], rep["vulnerabilities"][0]["max_epss"]), (False, None))
        self.assertIn("down", rep["sources"]["epss"]["error"])

    def test_epss_outage_with_an_older_file_is_stale_not_failed(self):
        real_time = pipeline.time.time
        with tempfile.TemporaryDirectory() as tmp:
            rc, cfg = self.run_with(Path(tmp), {"return_value": self.epss_hit()}, http_bytes=epss_fetch(epss_gz()))
            self.assertEqual(rc, pipeline.EXIT_FINDINGS)
            with tools_present(), mock.patch("sbomaudit.cache.time.time", lambda: real_time() + 25 * 3600), \
                 mock.patch.object(pipeline.scan, "scan", return_value=scan_result(inventory())), \
                 mock.patch.object(pipeline.matching, "run_osv_scanner", return_value=self.epss_hit()), \
                 contextlib.redirect_stdout(io.StringIO()):
                rc = pipeline.run(cfg, http=offline, http_bytes=epss_fetch(OSError("down")))
            rep = self.audit_json(cfg)
        self.assertEqual(rc, pipeline.EXIT_FINDINGS)
        self.assertEqual((rep["sources"]["epss"]["origin"], rep["vulnerabilities"][0]["max_epss"]), ("stale", 0.0123))
        self.assertIsNone(rep["sources"]["epss"]["error"])

    def test_run_refreshes_the_guard_in_the_isolated_config_dir_only(self):
        def snapshot(folder: Path):
            return sorted((str(p), p.stat().st_mtime_ns) for p in folder.rglob("*")) if folder.exists() else None
        real = Path.home() / ".config" / "sbom-audit"
        before = snapshot(real)
        xdg = Path(os.environ["XDG_CONFIG_HOME"])        # set for the whole suite by tests/__init__.py
        self.assertNotEqual(xdg.resolve(), (Path.home() / ".config").resolve())
        cfg_dir = xdg / "sbom-audit"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        (cfg_dir / "guard.py").write_text("# sbom-audit 0.0.1\n")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                rc, _ = self.run_with(Path(tmp), {"return_value": {"results": []}})
            self.assertEqual(rc, 0)
            self.assertIn(f"# sbom-audit {__version__}", (cfg_dir / "guard.py").read_text())
            self.assertTrue((cfg_dir / "classes.toml").is_file())
            self.assertTrue(any(line.startswith("guard: refreshed ") for line in self.said), self.said)
        finally:
            shutil.rmtree(cfg_dir)
        self.assertEqual(snapshot(real), before, "the run touched the real ~/.config/sbom-audit")

    def test_skipped_projects_keep_the_exit_code_and_end_with_a_warning(self):
        result = scan.ScanResult(inventories=[inventory()], generated_at="2026-11-06T10:00:00Z",
                                 skipped=[{"project": "legacy", "reason": "none of main, dev exist"},
                                          {"project": "old", "reason": "none of main, dev exist"}])
        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_cfg(Path(tmp))
            said: list[str] = []
            with tools_present(), mock.patch.object(pipeline.scan, "scan", return_value=result), \
                 mock.patch.object(pipeline.matching, "run_osv_scanner", return_value={"results": []}), \
                 contextlib.redirect_stdout(io.StringIO()):
                rc = pipeline.run(cfg, http=offline, log=said.append)
        self.assertEqual(rc, pipeline.EXIT_CLEAN)
        self.assertEqual(said[-1], "WARNING: incomplete run: 2 projects not scanned (legacy, old; reasons above); "
                                   "the exit code covers only the scanned projects")

    def test_run_writes_status_and_commits_written_files(self):
        def prepare(cfg):
            git_init(cfg.out)
            (cfg.out / "notes.md").write_text("my own notes\n")       # a hand edit the run must leave alone
        with tempfile.TemporaryDirectory() as tmp:
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}}, before=prepare)
            self.assertEqual(rc, 0)
            doc = json.loads((cfg.out / "status.json").read_text())
            self.assertEqual(doc["schema"], 1)
            self.assertEqual(doc["exit_code"], 0)
            self.assertTrue((cfg.out / "STATUS.md").exists())
            subjects = git(cfg.out, "log", "--format=%s").splitlines()
            self.assertEqual(subjects, [f"audit {doc['generated_at'][:10]}: 0 vulnerable, 0 KEV, 0 class A secrets"])
            committed = set(git(cfg.out, "show", "--name-only", "--format=", "HEAD").split())
            dated = [f"reports/{p.name}" for p in (cfg.out / "reports").glob("*-audit.md")]
            self.assertEqual(len(dated), 1)      # named by the audit's own date, not generated_at (midnight)
            day = json.loads((cfg.out / "secrets.json").read_text())["generated_at"][:10]
            run_wrote = {"AUDIT.md", "INVENTORY.md", "audit.json", "log.md", "status.json", "STATUS.md",
                         "issues.json", "ISSUES.md", "CLAUDE.md", "README.md", *dated, "secrets.json", "SECRETS.md",
                         f"reports/{day}-secrets.md", "REPORT.html", "releases.json", "RELEASES.md", "manifest.json",
                         *[d.replace("-audit.md", "-report.html") for d in dated]}
            self.assertEqual(committed, run_wrote)
            self.assertIn("?? notes.md", git(cfg.out, "status", "--porcelain"))
            self.assertEqual(doc["commit"]["status"], "committed")
            self.assertIsNone(doc["commit"]["sha"])      # a file cannot carry the hash of its own commit
            self.assertEqual(doc["commit"]["pending_hand_edits"], ["notes.md"])
            self.assertEqual(doc["push"]["status"], "off")
            self.assertEqual(json.loads(git(cfg.out, "show", "HEAD:status.json"))["commit"]["status"], "committed")
            self.assertEqual(git(cfg.out, "status", "--porcelain"), "?? notes.md\n")   # one commit, clean tree
            self.assertIn("- commit: committed", (cfg.out / "STATUS.md").read_text())
            printed = "\n".join(self.said)
            self.assertIn(f"committed {git(cfg.out, 'rev-parse', '--short', 'HEAD').strip()}", self.said)
            self.assertIn("push: off", self.said)
            self.assertIn("# sbom-audit status", printed)
            self.assertIn("- commit: committed", printed)
            self.assertNotIn("pending", (cfg.out / "STATUS.md").read_text().split("## Pending hand edits")[0])

    def test_setup_then_run_leaves_no_pending_hand_edits(self):
        from sbomaudit import setup
        def set_up(cfg):
            git_init(cfg.out)
            make_repo(cfg.root, "zeta", {"README.md": "x\n"})     # setup refuses an empty portfolio
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(setup.run(cfg.out, cfg.root, which=lambda tool: f"/stub/bin/{tool}"), 0)
            self.assertEqual(git(cfg.out, "log", "--format=%s").splitlines(), ["chore: sbom-audit setup"])
        with tempfile.TemporaryDirectory() as tmp:
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}}, before=set_up)
            self.assertEqual(rc, 0)
            doc = json.loads((cfg.out / "status.json").read_text())
            self.assertEqual(doc["commit"]["pending_hand_edits"], [])
            self.assertEqual(git(cfg.out, "status", "--porcelain"), "")

    def _config_run(self, text: str, edit_during_run: str | None = None):
        """A run whose config was read by `config.load` (it carries a digest); returns (doc, committed, porcelain)."""
        def prepare(cfg):
            git_init(cfg.out)
            (cfg.out / config.CONFIG_NAME).write_text("branches = ['main']\n")
            git(cfg.out, "add", config.CONFIG_NAME)
            git(cfg.out, "commit", "-q", "-m", "setup")
            (cfg.out / config.CONFIG_NAME).write_text(text)            # edited by hand since setup
            cfg.digest = config.load(cfg.out).digest
            if edit_during_run is not None:
                (cfg.out / config.CONFIG_NAME).write_text(edit_during_run)
        with tempfile.TemporaryDirectory() as tmp:
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}}, before=prepare)
            self.assertEqual(rc, 0)
            doc = json.loads((cfg.out / "status.json").read_text())
            committed = set(git(cfg.out, "show", "--name-only", "--format=", "HEAD").split())
            return doc, committed, git(cfg.out, "status", "--porcelain"), (cfg.out / "STATUS.md").read_text()

    def test_run_commits_the_config_it_read(self):
        doc, committed, porcelain, md = self._config_run("branches = ['main', 'dev']\ncommit = true\n")
        self.assertIn(config.CONFIG_NAME, committed)
        self.assertEqual(porcelain, "")
        self.assertEqual(doc["commit"]["pending_hand_edits"], [])
        self.assertNotIn("config", doc["commit"])
        self.assertNotIn("- configuration:", md)

    def test_run_leaves_a_config_edited_during_the_run(self):
        doc, committed, porcelain, md = self._config_run("branches = ['main', 'dev']\n",
                                                         edit_during_run="branches = ['dev']\n")
        self.assertNotIn(config.CONFIG_NAME, committed)
        self.assertIn(f" M {config.CONFIG_NAME}", porcelain)
        self.assertEqual(doc["commit"]["pending_hand_edits"], [config.CONFIG_NAME])
        self.assertIn("changed during the run", doc["commit"]["config"])
        self.assertIn("- configuration: sbom-audit.toml not committed: changed during the run", md)

    def test_run_never_commits_a_config_that_looks_like_it_holds_a_credential(self):
        token = "gh" + "p_" + "x" * 36                      # built at runtime: no token-like literal in the repo
        doc, committed, porcelain, md = self._config_run(f"branches = ['main']\n[extra]\nnote = '{token}'\n")
        self.assertNotIn(config.CONFIG_NAME, committed)
        self.assertIn(f" M {config.CONFIG_NAME}", porcelain)
        self.assertIn("extra.note looks like it holds a credential", doc["commit"]["config"])
        self.assertIn("extra.note looks like it holds a credential", md)
        self.assertNotIn(token, md + json.dumps(doc))

    def test_run_single_mode_skips_commit_with_note(self):
        def single(cfg):
            git_init(cfg.root)
            cfg.mode = "single"
        with tempfile.TemporaryDirectory() as tmp:
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}}, before=single)
            self.assertEqual(rc, 0)
            self.assertIn("single-repo mode", (cfg.out / "STATUS.md").read_text())
            doc = json.loads((cfg.out / "status.json").read_text())
            self.assertEqual(doc["commit"]["status"], "skipped")
            self.assertEqual(doc["mode"], "single")
            self.assertNotEqual(subprocess.run(["git", "-C", str(cfg.root), "rev-parse", "HEAD"],
                                               capture_output=True).returncode, 0)

    def test_run_prunes_stale_sbom_dir_and_logs_it(self):
        def stale(cfg):
            make_repo(cfg.root, "zeta", {"a": "1\n"})
            for name in ("gone", "zeta"):
                (cfg.out / "sbom" / name).mkdir(parents=True)
                (cfg.out / "sbom" / name / "main.cdx.json").write_text("{}")
        with tempfile.TemporaryDirectory() as tmp:
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}}, before=stale)
            self.assertEqual(rc, 0)
            self.assertFalse((cfg.out / "sbom" / "gone").exists())
            self.assertTrue((cfg.out / "sbom" / "zeta" / "main.cdx.json").exists())
            lines = (cfg.out / "log.md").read_text().splitlines()
            run_line = next(line for line in lines if " | run | " in line)
            self.assertTrue(run_line.endswith(" | removed sbom/gone"), run_line)
            self.assertIn(" | secrets | ", lines[-1])

    def test_prune_skipped_without_discovered_projects(self):
        def stale(cfg):
            (cfg.out / "sbom" / "gone").mkdir(parents=True)
            (cfg.out / "sbom" / "gone" / "main.cdx.json").write_text("{}")
        with tempfile.TemporaryDirectory() as tmp:
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}}, before=stale)
            self.assertEqual(rc, 0)
            self.assertTrue((cfg.out / "sbom" / "gone" / "main.cdx.json").exists())
            self.assertIn("pruning skipped: no projects discovered", self.said)

    def test_prune_keeps_a_folder_holding_hand_edits(self):
        def stale(cfg):
            make_repo(cfg.root, "zeta", {"a": "1\n"})
            (cfg.out / "sbom" / "stray").mkdir(parents=True)
            (cfg.out / "sbom" / "stray" / "main.cdx.json").write_text("{}")
            (cfg.out / "sbom" / "stray" / "notes.md").write_text("mine\n")
        with tempfile.TemporaryDirectory() as tmp:
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}}, before=stale)
            self.assertEqual(rc, 0)
            self.assertTrue((cfg.out / "sbom" / "stray" / "notes.md").exists())
            self.assertIn("pruning skipped sbom/stray: unexpected files", self.said)

    def test_failures_after_the_audit_never_change_the_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(pipeline.evidence, "prune_sbom_dirs", side_effect=OSError("disk /secret/path")), \
             mock.patch.object(pipeline.evidence, "write_folder_docs", side_effect=PermissionError("x")):
            rc, cfg = self.run_with(Path(tmp), {"return_value": osv_hit()},
                                    before=lambda c: make_repo(c.root, "zeta", {"a": "1\n"}))
            self.assertEqual(rc, 1)
            self.assertTrue((cfg.out / "status.json").exists())
            self.assertIn("pruning skipped: OSError", self.said)
            self.assertIn("folder docs skipped: PermissionError", self.said)
            self.assertNotIn("/secret/path", "\n".join(self.said))
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(pipeline.status, "write", side_effect=OSError("disk full")):
            rc, cfg = self.run_with(Path(tmp), {"return_value": osv_hit()})
            self.assertEqual(rc, 1)
            self.assertIn("finish failed: OSError", self.said)

    def test_secrets_step_failure_is_reported_by_type_only(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(pipeline, "secrets_step", side_effect=RuntimeError("AKIAsecretfragment")):
            rc, cfg = self.run_with(Path(tmp), {"return_value": osv_hit()})
            self.assertEqual(rc, 2)                 # R63: a crash of the enabled step is a failed source
            doc = json.loads((cfg.out / "status.json").read_text())
            self.assertEqual(doc["exit_code"], 2)
            self.assertIn("secrets: RuntimeError (scan skipped)", self.said)
            status_md = (cfg.out / "STATUS.md").read_text()
            self.assertTrue("- secrets: FAILED: RuntimeError" in status_md, "STATUS.md lacks the failed secrets source")
            everything = "\n".join(self.said) + (cfg.out / "status.json").read_text() + status_md
            self.assertTrue("AKIAsecretfragment" not in everything, "exception text leaked into the output")
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(pipeline, "secrets_step", return_value={"findings": "garbage"}):
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}})
            self.assertEqual(rc, 0)
            self.assertTrue((cfg.out / "status.json").exists())
            self.assertTrue(any(line.startswith("secrets: ") and "reported as skipped" in line
                                for line in self.said), self.said)

    def test_commit_false_leaves_working_tree_dirty(self):
        def no_commit(cfg):
            git_init(cfg.out)
            cfg.commit = False
        with tempfile.TemporaryDirectory() as tmp:
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}}, before=no_commit)
            self.assertEqual(rc, 0)
            self.assertNotEqual(subprocess.run(["git", "-C", str(cfg.out), "rev-parse", "HEAD"],
                                               capture_output=True).returncode, 0)
            dirty = git(cfg.out, "status", "--porcelain")
            self.assertIn("?? AUDIT.md", dirty)
            self.assertIn("?? status.json", dirty)
            doc = json.loads((cfg.out / "status.json").read_text())
            self.assertEqual((doc["commit"]["status"], doc["commit"]["detail"]), ("skipped", "commit = false"))

    def test_exit_code_unchanged_by_commit_failure(self):
        failed = evidence.CommitResult("failed", None, "fatal: index.lock exists")
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(pipeline.evidence, "commit_run", return_value=failed) as commit:
            rc, cfg = self.run_with(Path(tmp), {"return_value": osv_hit()}, before=lambda c: git_init(c.out))
            self.assertEqual(rc, 1)
            self.assertEqual(commit.call_count, 1)
            doc = json.loads((cfg.out / "status.json").read_text())
            self.assertEqual(doc["exit_code"], 1)
            self.assertEqual((doc["commit"]["status"], doc["commit"]["detail"]),
                             ("failed", "fatal: index.lock exists"))
            self.assertIn("- commit: failed", (cfg.out / "STATUS.md").read_text())
            self.assertIn("?? status.json", git(cfg.out, "status", "--porcelain"))
            self.assertIn("commit: failed (fatal: index.lock exists)", self.said)

    def test_push_refused_when_remote_public(self):
        def push_on(cfg):
            git_init(cfg.out)
            cfg.push = True
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(pipeline.evidence, "remote_visibility", return_value="public"), \
             mock.patch.object(pipeline.evidence, "push_run") as push_run:
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}}, before=push_on)
            self.assertEqual(rc, 0)
            self.assertEqual(push_run.call_count, 0)
            self.assertIn("refused", (cfg.out / "STATUS.md").read_text())
            committed = json.loads(git(cfg.out, "show", "HEAD:status.json"))
            self.assertEqual(committed["push"]["status"], "refused_public")
            self.assertEqual(committed["visibility"], "public")
            self.assertEqual(git(cfg.out, "status", "--porcelain"), "")
            self.assertIn("push: refused_public (remote is public; keep the evidence repository private)",
                          self.said)

    def test_push_failure_is_recorded_after_the_commit(self):
        def push_on(cfg):
            git_init(cfg.out)
            git(cfg.out, "config", "branch.main.remote", "origin")
            git(cfg.out, "config", "branch.main.merge", "refs/heads/main")
            cfg.push = True
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(pipeline.evidence, "remote_visibility", return_value="private"), \
             mock.patch.object(pipeline.evidence, "push_run",
                               return_value={"status": "failed", "detail": "timed out"}) as push_run:
            rc, cfg = self.run_with(Path(tmp), {"return_value": osv_hit()}, before=push_on)
            self.assertEqual(rc, 1)
            self.assertEqual(push_run.call_count, 1)
            self.assertEqual(json.loads(git(cfg.out, "show", "HEAD:status.json"))["push"]["status"], "pushed")
            doc = json.loads((cfg.out / "status.json").read_text())
            self.assertEqual((doc["push"]["status"], doc["push"]["detail"]), ("failed", "timed out"))
            self.assertEqual(doc["commit"]["status"], "committed")
            self.assertEqual(doc["exit_code"], 1)
            self.assertEqual(set(git(cfg.out, "status", "--porcelain").splitlines()),
                             {" M STATUS.md", " M status.json", " M manifest.json"})   # next run commits them
            self.assertIn("push: failed (timed out)", self.said)

    def test_push_failure_never_shows_the_remote_url(self):
        def push_on(cfg):
            git_init(cfg.out)
            git(cfg.out, "remote", "add", "origin", "https://nobody:tok3n@nonexistent.invalid/o/r.git")
            git(cfg.out, "config", "branch.main.remote", "origin")
            git(cfg.out, "config", "branch.main.merge", "refs/heads/main")
            cfg.push = True
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(pipeline.evidence, "remote_visibility", return_value="private"), \
             mock.patch.dict(os.environ, {"GIT_TERMINAL_PROMPT": "0"}):
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}}, before=push_on)
            self.assertEqual(rc, 0)
            doc = json.loads((cfg.out / "status.json").read_text())
            self.assertEqual(doc["push"]["status"], "failed")
            seen = "\n".join(self.said) + (cfg.out / "status.json").read_text() + (cfg.out / "STATUS.md").read_text()
            for needle in ("nonexistent", "o/r.git", "nobody", "tok3n"):
                self.assertNotIn(needle, seen)

    def test_enclosing_repository_is_never_committed_to(self):
        def nested(cfg):
            git_init(cfg.root.parent)        # the tmp dir is a repo; security/ is just a folder in it
            cfg.push = True
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(pipeline.evidence, "remote_visibility") as visibility, \
             mock.patch.object(pipeline.evidence, "push_run") as push_run:
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}}, before=nested)
            self.assertEqual(rc, 0)
            self.assertEqual((visibility.call_count, push_run.call_count), (0, 0))
            doc = json.loads((cfg.out / "status.json").read_text())
            self.assertEqual((doc["commit"]["status"], doc["commit"]["detail"]), ("skipped", pipeline.NOT_OWN_REPO))
            self.assertEqual((doc["push"]["status"], doc["push"]["detail"]), ("skipped", pipeline.NOT_OWN_REPO))
            self.assertEqual(doc["visibility"], "unknown")
            self.assertNotEqual(subprocess.run(["git", "-C", str(cfg.root.parent), "rev-parse", "HEAD"],
                                               capture_output=True).returncode, 0)

    def test_push_needs_a_commit_this_run_or_earlier_commits(self):
        def push_on(cfg):
            git_init(cfg.out)
            git(cfg.out, "config", "branch.main.remote", "origin")
            git(cfg.out, "config", "branch.main.merge", "refs/heads/main")
            cfg.push = True
        failed = evidence.CommitResult("failed", None, "index.lock")
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(pipeline.evidence, "remote_visibility", return_value="private"), \
             mock.patch.object(pipeline.evidence, "commit_run", return_value=failed), \
             mock.patch.object(pipeline.evidence, "push_run") as push_run:
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}}, before=push_on)
            self.assertEqual(push_run.call_count, 0)
            doc = json.loads((cfg.out / "status.json").read_text())
            self.assertEqual((doc["push"]["status"], doc["push"]["detail"]), ("skipped", "no commit this run"))
            self.assertIn("push: skipped (no commit this run)", self.said)
        nothing = evidence.CommitResult("nothing", None, "")
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(pipeline.evidence, "remote_visibility", return_value="private"), \
             mock.patch.object(pipeline.evidence, "commit_run", return_value=nothing), \
             mock.patch.object(pipeline.evidence, "push_run",
                               return_value={"status": "pushed", "detail": "abc1234"}) as push_run:
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}}, before=push_on)
            self.assertEqual(push_run.call_count, 1)
            doc = json.loads((cfg.out / "status.json").read_text())
            self.assertEqual((doc["push"]["status"], doc["push"]["detail"]), ("pushed", "earlier commits"))

    def test_visibility_is_read_with_push_off(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(pipeline.evidence, "remote_visibility", return_value="private") as visibility:
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}}, before=lambda c: git_init(c.out))
            self.assertEqual(visibility.call_count, 1)
            self.assertEqual(json.loads((cfg.out / "status.json").read_text())["visibility"], "private")
            self.assertIn("private", (cfg.out / "STATUS.md").read_text())

    def test_push_in_single_mode_is_skipped(self):
        def single(cfg):
            git_init(cfg.root)
            cfg.mode = "single"
            cfg.push = True
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(pipeline.evidence, "remote_visibility") as visibility, \
             mock.patch.object(pipeline.evidence, "push_run") as push_run:
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}}, before=single)
            self.assertEqual(rc, 0)
            self.assertEqual((visibility.call_count, push_run.call_count), (0, 0))
            doc = json.loads((cfg.out / "status.json").read_text())
            self.assertEqual((doc["push"]["status"], doc["push"]["detail"]), ("skipped", "single-repo mode"))

    def test_status_cli_prints_status_md_or_hint(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.dict(os.environ, {"SBOM_AUDIT_READ_ONLY": "1"}):
            out = Path(tmp) / "security"
            out.mkdir()
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.main(["--out", str(out), "status"])
            self.assertEqual(rc, 2)
            self.assertIn("no status.json yet: run /sbom-audit:setup, then /sbom-audit:run", buf.getvalue())
            self.assertIn("sbom_audit_cli.py setup, then run)", buf.getvalue())     # the CLI form too
            self.assertIn("python3 ", buf.getvalue())
            self.assertEqual(list(out.iterdir()), [])
            doc = status.build(status.empty_report(), secrets=None, previous=None, duration_s=1.5, exit_code=0,
                               run_host="box", mode="portfolio")
            doc["generated_at"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=10)).isoformat()
            status.write(out, doc)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.main(["--out", str(out), "status"])
            self.assertEqual(rc, 0)
            self.assertIn("last run 10 days ago", buf.getvalue())      # rendered now, not a stale snapshot
            self.assertEqual(sorted(p.name for p in out.iterdir()), ["status.json"])   # writes nothing
            doc["generated_at"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)).isoformat()
            status.write(out, doc)
            fired = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=12)).isoformat()
            buf = io.StringIO()
            with mock.patch.object(pipeline, "read_scheduler_state",
                                   return_value={"installed": True, "last_fired": fired}), \
                 contextlib.redirect_stdout(buf):
                rc = cli.main(["--out", str(out), "status"])
            self.assertEqual(rc, 0)
            local_day = dt.datetime.fromisoformat(fired).astimezone().date().isoformat()    # not the UTC text
            self.assertIn(f"scheduler did not run since {local_day} (weekly run 5 days overdue)", buf.getvalue())
            self.assertIn("- OVERDUE OR FAILING: scheduler did not run since", buf.getvalue())
            (out / "status.json").write_text("{}")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.main(["--out", str(out), "status"])
            self.assertEqual(rc, 2)
            self.assertIn("unreadable", buf.getvalue())

    def test_run_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}})
            self.assertEqual(rc, 0)
            for name in ("AUDIT.md", "INVENTORY.md", "audit.json", "log.md"):
                self.assertTrue((cfg.out / name).exists(), name)
            self.assertEqual(len(list((cfg.out / "reports").glob("*-audit.md"))), 1)
        with tempfile.TemporaryDirectory() as tmp:
            rc, cfg = self.run_with(Path(tmp), {"return_value": osv_hit()})
            self.assertEqual(rc, 1)
            rep = json.loads((cfg.out / "audit.json").read_text())
            self.assertEqual([v["name"] for v in rep["vulnerabilities"]], ["lodash"])
            self.assertEqual(rep["vulnerabilities"][0]["vulns"][0]["fixed_in"], "4.17.21")
            self.assertIn("| lodash | 4.17.20 |", (cfg.out / "AUDIT.md").read_text())
        with tempfile.TemporaryDirectory() as tmp:
            rc, cfg = self.run_with(Path(tmp), {"side_effect": ToolError("osv-scanner", 127, "not found")})
            self.assertEqual(rc, 2)
            self.assertIn("failed", (cfg.out / "AUDIT.md").read_text())

    def test_run_applies_vex_statements(self):
        def add_vex(cfg):
            vex.add(cfg.out, "zeta", "pkg:generic/zeta", "CVE-2026-1", "not_affected",
                    justification="vulnerable_code_not_in_execute_path", impact="template path unused")
        with tempfile.TemporaryDirectory() as tmp:
            rc, cfg = self.run_with(Path(tmp), {"return_value": osv_hit()}, before=add_vex)
            self.assertEqual(rc, 0)
            rep = json.loads((cfg.out / "audit.json").read_text())
            self.assertEqual(rep["vulnerabilities"], [])
            self.assertEqual(len(rep["suppressed"]), 1)
            self.assertEqual(rep["suppressed"][0]["statement"]["justification"],
                             "vulnerable_code_not_in_execute_path")

    def test_broken_vex_file_aborts_before_matching(self):
        def break_vex(cfg):
            (cfg.out / "vex").mkdir()
            (cfg.out / "vex" / "zeta.openvex.json").write_text("{not json")
        with tempfile.TemporaryDirectory() as tmp:
            rc, _ = self.run_with(Path(tmp), {"return_value": osv_hit()}, before=break_vex)
        self.assertEqual(rc, 3)
        self.assertEqual(self.osv_calls, 0)

    def test_endoflife_failure_is_reported_not_ok(self):
        """A network error towards endoflife.date is a failed source (exit 2, partial status), not 'unknown' for 24 h."""
        def flaky(url):
            if "endoflife.date" in url:
                raise OSError("timeout")
            return {}
        node = runtime_component("nodejs", "18", ".nvmrc", ".nvmrc = 18")
        with tempfile.TemporaryDirectory() as tmp:
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}},
                                    invs=[inventory(components=(LODASH, node))], http=flaky)
            self.assertEqual(rc, 2)
            rep = json.loads((cfg.out / "audit.json").read_text())
            self.assertEqual(rep["sources"]["endoflife"]["failed"][0]["what"], "nodejs/18")
            self.assertIn("timeout", rep["sources"]["endoflife"]["failed"][0]["error"])
            self.assertEqual([r["status"] for r in rep["runtimes"]], ["unknown"])
            self.assertRegex((cfg.out / "AUDIT.md").read_text(), r"\| endoflife \| \*\*partial\*\* \(1 failed\) \|")
            self.assertIn("endoflife nodejs/18: OSError: timeout", (cfg.out / "log.md").read_text())
            self.assertEqual(list((cfg.out / ".cache" / "enrich").glob("eol*")), [])

    def assess_prepare(self, cfg, assess_on=True):
        git_init(cfg.out)
        cfg.schedule.assess = assess_on

    def test_proposal_is_committed_and_in_status(self):
        def fake(cfg, out, plugin_root, **kw):
            path = Path(out) / "reports" / "2026-11-08-assessment-proposal.md"
            path.parent.mkdir(exist_ok=True)
            path.write_text(ASSESS_HEADER + "\nbody\n", encoding="utf-8")
            return {"status": "written", "path": "reports/2026-11-08-assessment-proposal.md",
                    "reason": None, "cost_usd": 0.42}
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(pipeline.assess, "run_headless", side_effect=fake) as headless:
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}}, before=self.assess_prepare)
            self.assertEqual(rc, 0)
            headless.assert_called_once()
            rel = "reports/2026-11-08-assessment-proposal.md"
            self.assertIn(rel, git(cfg.out, "show", "--name-only", "--format=", "HEAD").split())
            doc = json.loads((cfg.out / "status.json").read_text())
            self.assertEqual(doc["assessment_proposal"], rel)
            self.assertEqual(git(cfg.out, "status", "--porcelain").strip(), "")
            self.assertNotIn("body", (cfg.out / "log.md").read_text())

    def test_configured_provider_replaces_claude_in_the_scheduled_assessment(self):
        """With `[assess]` base_url and model set, the run calls `draft.run`, never `claude -p`."""
        from sbomaudit import draft
        rel = "reports/2026-11-08-assessment-proposal.md"
        def fake(cfg, out, **kw):
            path = Path(out) / rel
            path.parent.mkdir(exist_ok=True)
            path.write_text("<!-- proposal written by `assess draft` -->\nbody\n", encoding="utf-8")
            return {"status": "written", "path": rel, "reason": None, "cost_usd": None, "model": "m-1"}
        def prepare(cfg):
            self.assess_prepare(cfg)
            cfg.assess = config.AssessProvider(base_url="http://127.0.0.1:9/v1", model="m-1")
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(pipeline.assess, "run_headless") as headless, \
             mock.patch.object(draft, "run", side_effect=fake) as drafted:
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}}, before=prepare)
            self.assertEqual(rc, 0)
            headless.assert_not_called()
            drafted.assert_called_once()
            self.assertEqual(json.loads((cfg.out / "status.json").read_text())["assessment_proposal"], rel)
            self.assertIn("cost unknown", (cfg.out / "log.md").read_text())
        self.assertIn(f"assess: proposal written to {rel} (model m-1)", self.said)

    def test_assess_log_line_is_its_own_line_after_the_secrets_line(self):
        rel = "reports/2026-11-08-assessment-proposal.md"
        def fake(cfg, out, plugin_root, **kw):
            path = Path(out) / rel
            path.parent.mkdir(exist_ok=True)
            path.write_text(ASSESS_HEADER + "\nPROPOSAL-BODY-TEXT\n", encoding="utf-8")
            return {"status": "written", "path": rel, "reason": None, "cost_usd": 0.4}
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(pipeline.assess, "run_headless", side_effect=fake):
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}}, before=self.assess_prepare)
            self.assertEqual(rc, 0)
            text = (cfg.out / "log.md").read_text()
            lines = text.splitlines()
            self.assertRegex(lines[-1], r"^\d{4}-\d{2}-\d{2}\S* \| assess-proposal \| cost 0\.40 \| "
                                        r"reports/\S+-assessment-proposal\.md$")
            self.assertIn("| secrets |", lines[-2])
            self.assertNotIn("assess-proposal", lines[-2])
            self.assertNotIn("PROPOSAL-BODY-TEXT", text)
            self.assertIn("log.md", git(cfg.out, "show", "--name-only", "--format=", "HEAD").split())

    def test_unreviewed_proposal_stays_in_status_until_deleted_or_assessed(self):
        rel = "reports/2026-11-08-assessment-proposal.md"
        def fake(cfg, out, plugin_root, **kw):
            path = Path(out) / rel
            path.parent.mkdir(exist_ok=True)
            path.write_text(ASSESS_HEADER + "\nbody\n", encoding="utf-8")
            return {"status": "written", "path": rel, "reason": None, "cost_usd": None}
        skipped = {"status": "skipped", "path": None, "reason": "claude not on PATH", "cost_usd": None}
        osv = {"return_value": {"results": []}}
        def again(cfg, assess_on, **result):
            cfg.schedule.assess = assess_on
            with tools_present(), \
                 mock.patch.object(pipeline.scan, "scan", return_value=scan_result(inventory())), \
                 mock.patch.object(pipeline.matching, "run_osv_scanner", **osv), \
                 mock.patch.object(pipeline.assess, "run_headless", **result), \
                 contextlib.redirect_stdout(io.StringIO()):
                return pipeline.run(cfg, http=offline, log=lambda msg: None)
        def proposal(cfg):
            return json.loads((cfg.out / "status.json").read_text())["assessment_proposal"]
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(pipeline.assess, "run_headless", side_effect=fake):
            _, cfg = self.run_with(Path(tmp), osv, before=self.assess_prepare)
            self.assertEqual(proposal(cfg), rel)
            self.assertIn("| assess-proposal | cost unknown | " + rel, (cfg.out / "log.md").read_text())
            again(cfg, True, return_value=skipped)
            self.assertEqual(proposal(cfg), rel)                 # carried forward while unreviewed
            again(cfg, False, return_value=skipped)              # assess switched off: still waiting
            self.assertEqual(proposal(cfg), rel)
            (cfg.out / "AUDIT.md").write_text("## Assessment 2026-11-08\n")   # same day as the proposal
            again(cfg, False, return_value=skipped)
            self.assertIsNone(proposal(cfg))                     # an assessment at least as new reviewed it
            (cfg.out / "AUDIT.md").unlink()
            again(cfg, True, side_effect=fake)
            self.assertEqual(proposal(cfg), rel)
            (cfg.out / rel).unlink()
            again(cfg, False, return_value=skipped)
            self.assertIsNone(proposal(cfg))                     # file gone

    def test_assess_off_calls_nothing(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(pipeline.assess, "run_headless") as headless:
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}},
                                    before=lambda c: self.assess_prepare(c, False))
            self.assertEqual(rc, 0)
            headless.assert_not_called()
            self.assertIsNone(json.loads((cfg.out / "status.json").read_text())["assessment_proposal"])

    def test_skipped_and_failed_do_not_touch_commit_or_status(self):
        for res in ({"status": "skipped", "path": None, "reason": "claude not on PATH", "cost_usd": None},
                    {"status": "failed", "path": None, "reason": "timed out", "cost_usd": None}):
            with self.subTest(status=res["status"]), tempfile.TemporaryDirectory() as tmp, \
                 mock.patch.object(pipeline.assess, "run_headless", return_value=res):
                rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}}, before=self.assess_prepare)
                self.assertEqual(rc, 0)
                self.assertIsNone(json.loads((cfg.out / "status.json").read_text())["assessment_proposal"])
                self.assertTrue(any(f"assess: {res['status']}" in line for line in self.said), self.said)

    def test_exception_keeps_exit_code_and_names_the_class(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(pipeline.assess, "run_headless", side_effect=KeyError("SECRET-TEXT")):
            rc, cfg = self.run_with(Path(tmp), {"return_value": {"results": []}}, before=self.assess_prepare)
            self.assertEqual(rc, 0)
            self.assertTrue(any("KeyError" in line for line in self.said), self.said)
            self.assertFalse(any("SECRET-TEXT" in line for line in self.said))


HOSTS_NOW = "2026-11-09T08:00:00Z"
NO_KEY = "no audit key on this machine"


def host_entry(status_="ok", critical=(), error=None) -> dict:
    return {"production": True, "projects": [], "status": status_, "address": "203.0.113.10", "error": error,
            "checked_at": HOSTS_NOW, "attempted_at": HOSTS_NOW, "findings": [], "critical": list(critical)}


def hosts_result(hosts: dict, skipped=None) -> dict:
    return {"schema": 1, "generated_at": HOSTS_NOW, "skipped": skipped, "last_checked": HOSTS_NOW,
            "collector_shipped": "1", "hosts": hosts}


def fake_hosts_step(result: dict, write=True):
    """A `pipeline.hosts_step` that writes what the real `hosts.check` writes, then returns `result`."""
    def step(cfg, log):
        out = cfg.out
        if write and not result.get("skipped"):
            hosts_store.write(out, result)
            (out / "HOSTS.md").write_text("# Hosts\n")
            (out / "reports").mkdir(exist_ok=True)
            (out / "reports" / "2026-11-09-hosts.md").write_text("# Hosts\n")
            for name in result["hosts"]:
                hosts_store.write_baseline(out, name, {"schema": 1, "fingerprint": {}})
        with (out / "log.md").open("a", encoding="utf-8") as fh:
            fh.write("2026-11-09T08:00:00Z | hosts | checked 1\n")
        return result
    return step


class HostsStepTests(unittest.TestCase):
    """`finish` runs the hosts step after the secrets block: exit codes, sources, committed files."""
    run_with = RunTests.run_with

    def enable(self, cfg, names=("box-a",), key_exists=True):
        key = cfg.root / "audit-key"
        if key_exists:
            key.write_text("k")
        cfg.hosts = config.HostsOpts(enabled=True, key=key, servers={
            n: config.HostOpts(address=f"203.0.113.{10 + i}") for i, n in enumerate(names)})

    def run_hosts(self, step, osv=None, names=("box-a",), before=None):
        def prepare(cfg):
            self.enable(cfg, names)
            if before:
                before(cfg)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(pipeline, "hosts_step", step):
            rc, cfg = self.run_with(Path(tmp), osv or {"return_value": {"results": []}}, before=prepare)
            self.cfg = cfg
            self.status = json.loads((cfg.out / "status.json").read_text())
            self.status_md = (cfg.out / "STATUS.md").read_text()
            self.tracked = git(cfg.out, "ls-files").splitlines() if (cfg.out / ".git").exists() else []
            self.porcelain = git(cfg.out, "status", "--porcelain") if (cfg.out / ".git").exists() else ""
            self.log_md = (cfg.out / "log.md").read_text() if (cfg.out / "log.md").exists() else ""
            return rc

    def test_hosts_step_is_none_when_hosts_not_active(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch("sbomaudit.hosts.check") as check:
            cfg = make_cfg(Path(tmp))
            self.assertIsNone(pipeline.hosts_step(cfg, print))
            cfg.hosts = config.HostsOpts(enabled=False, servers={"box-a": config.HostOpts(address="203.0.113.10")})
            self.assertIsNone(pipeline.hosts_step(cfg, print))
            check.assert_not_called()

    def test_hosts_step_checks_every_configured_host(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch("sbomaudit.hosts.check", return_value={"hosts": {}}) as check:
            cfg = make_cfg(Path(tmp))
            self.enable(cfg, ("box-a", "box-b"))
            self.assertEqual(pipeline.hosts_step(cfg, print), {"hosts": {}})
            check.assert_called_once_with(cfg, None, print)

    def test_finish_runs_hosts_step_and_commits_files(self):
        rc = self.run_hosts(fake_hosts_step(hosts_result({"box-a": host_entry()})), before=lambda c: git_init(c.out))
        self.assertEqual(rc, 0)
        for path in ("hosts.json", "HOSTS.md", "reports/2026-11-09-hosts.md", "hosts/baseline/box-a.json", "log.md"):
            self.assertIn(path, self.tracked)
        self.assertEqual(self.porcelain, "")                 # nothing the step wrote was left out of the commit
        self.assertEqual(self.status["counts"]["hosts"]["checked"], 1)
        self.assertIn("hosts", self.status_md)

    def test_failed_host_exit_2_listed_under_sources(self):
        result = hosts_result({"box-a": host_entry(), "box-b": host_entry("failed", error="ssh timed out")})
        rc = self.run_hosts(fake_hosts_step(result), names=("box-a", "box-b"))
        self.assertEqual(rc, 2)
        self.assertEqual(self.status["exit_code"], 2)
        self.assertEqual(self.status["failed_sources"], [{"source": "hosts", "detail": "box-b: ssh timed out"}])
        self.assertIn("- hosts: FAILED: box-b: ssh timed out", self.status_md)

    def test_unknown_missing_or_malformed_host_result_counts_as_failed(self):
        for hosts in ({"box-a": host_entry("weird")}, {"box-a": "junk"}, {"box-a": None}, {}, {"box-b": host_entry()}):
            with self.subTest(hosts=hosts):
                self.assertEqual(self.run_hosts(fake_hosts_step(hosts_result(hosts), write=False)), 2)
                self.assertEqual([f["source"] for f in self.status["failed_sources"]], ["hosts"])
                self.assertGreaterEqual(self.status["counts"]["hosts"]["failed"], 1)

    def test_unsupported_host_is_not_a_failure(self):
        rc = self.run_hosts(fake_hosts_step(hosts_result({"box-a": host_entry("unsupported")})))
        self.assertEqual(rc, 0)
        self.assertEqual(self.status["failed_sources"], [])

    def test_hosts_critical_raises_clean_to_1(self):
        result = hosts_result({"box-a": host_entry(critical=["patch:timer-inactive"])})
        self.assertEqual(self.run_hosts(fake_hosts_step(result)), 1)
        self.assertEqual(self.status["open"]["hosts_critical"], ["box-a patch:timer-inactive"])
        self.assertEqual(self.status["exit_code"], 1)

    def test_hosts_critical_does_not_lower_a_failed_source(self):
        result = hosts_result({"box-a": host_entry(critical=["patch:timer-inactive"]),
                               "box-b": host_entry("failed", error="unreachable")})
        self.assertEqual(self.run_hosts(fake_hosts_step(result), names=("box-a", "box-b")), 2)

    def test_hosts_skipped_keeps_exit_code(self):
        previous = hosts_result({"box-a": host_entry(critical=["kev:CVE-2024-1086:pkg@1"])})

        def before(cfg):
            hosts_store.write(cfg.out, previous)                 # the last real check, kept
        result = hosts_result({"box-a": host_entry()}, skipped=NO_KEY)
        self.assertEqual(self.run_hosts(fake_hosts_step(result), before=before), 0)
        self.assertEqual(self.status["counts"]["hosts"]["skipped"], NO_KEY)
        self.assertEqual(self.status["failed_sources"], [])
        self.assertEqual(self.status["counts"]["hosts"]["last_checked"], "2026-11-09")
        # the returned document is authoritative: the previous hosts.json is shown, with `skipped` set
        self.assertEqual(self.status["open"]["hosts_critical"], ["box-a kev:CVE-2024-1086:pkg@1"])
        self.assertEqual(self.run_hosts(fake_hosts_step(result), osv={"return_value": osv_hit()},
                                        before=before), 1)       # the audit's own exit code stays

    def test_hosts_skipped_does_not_rewrite_hosts_json(self):
        self.run_hosts(fake_hosts_step(hosts_result({}, skipped=NO_KEY)))
        self.assertFalse((self.cfg.out / "hosts.json").exists())

    def test_hosts_exception_does_not_lose_status(self):
        def boom(cfg, log):
            raise RuntimeError("box-a 203.0.113.10 /home/x/.ssh/audit-key refused")
        rc = self.run_hosts(boom)
        self.assertEqual(rc, 2)
        self.assertEqual(self.status["exit_code"], 2)
        self.assertEqual(self.status["failed_sources"], [{"source": "hosts", "detail": "RuntimeError"}])
        self.assertIn("- hosts: FAILED: RuntimeError", self.status_md)
        self.assertIn("hosts: RuntimeError (step skipped)", self.said)
        everything = "\n".join(self.said) + json.dumps(self.status) + self.status_md
        for secret in ("203.0.113.10", "audit-key", "refused"):
            self.assertNotIn(secret, everything)

    def test_hosts_crash_after_writing_still_commits_what_was_written(self):
        def partial(cfg, log):
            hosts_store.write(cfg.out, hosts_result({"box-a": host_entry()}))
            (cfg.out / "HOSTS.md").write_text("# Hosts\n")
            raise RuntimeError("box-a 203.0.113.10 refused")
        rc = self.run_hosts(partial, before=lambda c: git_init(c.out))
        self.assertEqual(rc, 2)
        self.assertIn("hosts.json", self.tracked)
        self.assertIn("HOSTS.md", self.tracked)
        self.assertEqual(self.porcelain, "")

    def test_hosts_not_active_leaves_everything_as_before(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch("sbomaudit.hosts.check", side_effect=AssertionError("must not run")):
            rc, cfg = RunTests.run_with(self, Path(tmp), {"return_value": {"results": []}})
            self.assertEqual(rc, 0)
            self.assertIsNone(json.loads((cfg.out / "status.json").read_text())["counts"]["hosts"])


class PreflightTests(unittest.TestCase):
    """A missing tool stops run / scan / audit before anything is written: exit 4 and the brew line."""

    def test_run_exits_4_and_writes_nothing_when_a_tool_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_cfg(Path(tmp))
            said = []
            with mock.patch("sbomaudit.preflight.shutil.which", which_without("syft")), \
                 mock.patch.object(pipeline.scan, "scan") as scanned, \
                 mock.patch.object(pipeline.matching, "run_osv_scanner") as osv:
                rc = pipeline.run(cfg, http=offline, log=said.append)
            self.assertEqual(rc, 4)
            self.assertEqual((scanned.call_count, osv.call_count), (0, 0))
            self.assertEqual(list(cfg.out.iterdir()), [])
            text = "\n".join(said)
            self.assertIn("syft", text)
            self.assertIn(preflight.BREW_LINE, text)

    def test_scan_and_audit_commands_need_only_their_own_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_cfg(Path(tmp))
            buf = io.StringIO()
            with mock.patch("sbomaudit.preflight.shutil.which", which_without("syft", "gh")), \
                 mock.patch.object(scan, "scan_branch") as scanned, \
                 contextlib.redirect_stdout(buf):
                rc = cli.main(["--out", str(cfg.out), "scan", "--root", str(cfg.root), "--no-fetch"])
            self.assertEqual(rc, 4)
            self.assertEqual(scanned.call_count, 0)
            self.assertFalse((cfg.out / scan.INVENTORY_FILE).exists())
            self.assertIn("syft", buf.getvalue())
            self.assertIn(preflight.BREW_LINE, buf.getvalue())

            scan.write_inventory(cfg, scan_result(inventory()))
            buf = io.StringIO()
            with mock.patch("sbomaudit.preflight.shutil.which", which_without("osv-scanner")), \
                 mock.patch.object(pipeline.matching, "run_osv_scanner") as osv, \
                 contextlib.redirect_stdout(buf):
                rc = cli.main(["--out", str(cfg.out), "audit"])
            self.assertEqual(rc, 4)
            self.assertEqual(osv.call_count, 0)
            self.assertFalse((cfg.out / "AUDIT.md").exists())
            self.assertIn("osv-scanner", buf.getvalue())

            # audit needs neither syft nor gh; gh serves only `setup --enable-dependabot`
            with mock.patch("sbomaudit.preflight.shutil.which", which_without("syft", "gh")), \
                 mock.patch.object(pipeline.matching, "run_osv_scanner", return_value={"results": []}), \
                 mock.patch.object(pipeline.enrich, "http_get_json", offline), \
                 mock.patch.object(pipeline.epss, "http_get_bytes", epss_fetch(epss_gz())), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["--out", str(cfg.out), "audit"]), 0)


class CliTests(unittest.TestCase):
    def test_audit_command_reads_inventory_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_cfg(Path(tmp))
            scan.write_inventory(cfg, scan_result(inventory()))
            buf = io.StringIO()
            with tools_present(), \
                 mock.patch.object(pipeline.matching, "run_osv_scanner", return_value=osv_hit()), \
                 mock.patch.object(pipeline.enrich, "http_get_json", offline), \
                 mock.patch.object(pipeline.epss, "http_get_bytes", epss_fetch(epss_gz())), \
                 contextlib.redirect_stdout(buf):
                rc = cli.main(["--out", str(cfg.out), "audit"])
            self.assertEqual(rc, 1)
            self.assertTrue((cfg.out / "AUDIT.md").exists())
            self.assertIn("AUDIT.md", buf.getvalue())

    def test_audit_without_inventory_explains(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_cfg(Path(tmp))
            buf = io.StringIO()
            with tools_present(), contextlib.redirect_stdout(buf):
                rc = cli.main(["--out", str(cfg.out), "audit"])
            self.assertEqual(rc, 2)
            self.assertIn("scan", buf.getvalue())

    def test_run_command_prints_elapsed_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_cfg(Path(tmp))
            make_repo(cfg.root, "zeta", {"README.md": "x\n"})     # the CLI refuses an empty portfolio
            buf = io.StringIO()
            with tools_present(), \
                 mock.patch.object(pipeline.scan, "scan", return_value=scan_result(inventory())), \
                 mock.patch.object(pipeline.matching, "run_osv_scanner", return_value={"results": []}), \
                 mock.patch.object(pipeline.enrich, "http_get_json", offline), \
                 mock.patch.object(pipeline.epss, "http_get_bytes", epss_fetch(epss_gz())), \
                 contextlib.redirect_stdout(buf):
                rc = cli.main(["--out", str(cfg.out), "run", "--root", str(cfg.root), "--no-fetch"])
            self.assertEqual(rc, 0)
            self.assertRegex(buf.getvalue(), r"\d+(\.\d+)?s")


class EmptyPortfolioTests(unittest.TestCase):
    def test_run_in_a_folder_without_repositories_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "security"
            out.mkdir()
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), mock.patch.object(pipeline, "run") as run:
                rc = cli.main(["run", "--out", str(out), "--root", str(root)])
            self.assertEqual(rc, 2)
            self.assertIn("no git repository found", buf.getvalue())
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
