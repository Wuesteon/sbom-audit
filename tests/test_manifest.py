"""manifest.json and `verify`: tool versions, data source freshness, file hashes, refresh after a later command."""
from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import os
import subprocess
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import cli, integration, management, manifest, pipeline
from sbomaudit.cache import Cache

from tests.test_management import vuln
from tests.test_pipeline import git, git_init, inventory, make_cfg, offline, scan_result, tools_present

PLANTED = "Zq7Kx9PLvW3mRt8Yn2Hd"                 # stands in for the fingerprint key: must never reach the manifest

OUTPUTS = {
    "syft": "Application:   syft\nVersion:       1.18.1\nBuildDate:     2026-01-02\nGitCommit:     0123abc\n",
    "osv-scanner": "osv-scanner version: 2.0.2\ncommit: 5fe3c1a\nbuilt at: 2026-01-01\n",
    "git": "git version 2.47.1\n",
    "gh": "gh version 2.63.0 (2026-01-01)\nhttps://github.com/cli/cli/releases/tag/v2.63.0\n",
}


def fake_run(outputs=OUTPUTS, calls=None):
    def run(argv, **kwargs):
        if calls is not None:
            calls.append((list(argv), kwargs))
        name = Path(argv[0]).name
        if name not in outputs:
            raise FileNotFoundError(argv[0])
        return types.SimpleNamespace(returncode=0, stdout=outputs[name], stderr="")
    return run


def fake_which(*missing):
    return lambda tool: None if tool in missing else f"/stub/bin/{tool}"


@contextlib.contextmanager
def probed(outputs=OUTPUTS, missing=()):
    """The version probe answers from `outputs`; nothing real is executed, nothing is remembered."""
    with mock.patch.object(manifest, "_RUN", fake_run(outputs)), \
         mock.patch.object(manifest, "_WHICH", fake_which(*missing)), \
         mock.patch.object(manifest, "_versions_seen", {}):
        yield


class ToolVersionTests(unittest.TestCase):
    def test_parses_each_tool_output(self):
        got = manifest.tool_versions(("syft", "osv-scanner", "git", "gh"), run=fake_run(), which=fake_which())
        self.assertEqual(got, {"syft": "1.18.1", "osv-scanner": "2.0.2", "git": "2.47.1", "gh": "2.63.0"})

    def test_asks_each_tool_its_own_way_without_update_checks(self):
        calls = []
        manifest.tool_versions(("syft", "osv-scanner"), run=fake_run(calls=calls), which=fake_which())
        self.assertEqual([c[0] for c in calls], [["/stub/bin/syft", "version"], ["/stub/bin/osv-scanner", "--version"]])
        self.assertEqual(calls[0][1]["env"]["SYFT_CHECK_FOR_APP_UPDATE"], "false")
        self.assertTrue(all(c[1]["timeout"] for c in calls))

    def test_not_installed_and_unknown(self):
        def boom(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, 1)

        def failing(argv, **kwargs):
            return types.SimpleNamespace(returncode=1, stdout="", stderr="error")

        def silent(argv, **kwargs):
            return types.SimpleNamespace(returncode=0, stdout="no number here", stderr="")
        self.assertEqual(manifest.tool_version("syft", run=fake_run(), which=fake_which("syft")), "not installed")
        for run in (boom, failing, silent, fake_run({})):
            self.assertEqual(manifest.tool_version("syft", run=run, which=fake_which()), "unknown")

    def test_parse_version(self):
        self.assertEqual(manifest.parse_version("Version: v1.2.3-rc.1\n"), "1.2.3-rc.1")
        self.assertEqual(manifest.parse_version("tool 10.4\n"), "10.4")
        self.assertIsNone(manifest.parse_version(""))


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.cache = Cache(Path(self._tmp.name) / "enrich")

    def tearDown(self):
        self._tmp.cleanup()

    def test_kev_live_and_lookups_split_live_and_cached(self):
        self.cache.put("eol:nodejs/18", {"eol": "2025-04-30"})
        since = time.time() + 0.001
        time.sleep(0.01)
        self.cache.put("kev-catalog", ["CVE-1"])
        self.cache.put("kev-catalog-meta", {"catalogVersion": "2026.11.17", "dateReleased": "2026-11-17T15:00:00Z"})
        self.cache.put("eol:python/3.9", {"eol": True})
        sources = {"osv-scanner": {"scanned": 2, "failed": []}, "cisa_kev": {"loaded": 1, "flagged": 0, "error": None},
                   "endoflife": {"queried": 3, "unknown": 1, "failed": ["x"]},
                   "registries": {"queried": 0, "major_behind": 0, "failed": []},
                   "openvex": {"statements": 4, "suppressed": 1}}
        rows = [{"product": "nodejs", "cycle": "18"}, {"product": "python", "cycle": "3.9"},
                {"product": "go", "cycle": "1.20"}, {"product": "nginx", "cycle": ""}]
        cfg = types.SimpleNamespace(digest="d" * 64)
        prov = manifest.provenance(cfg, self.cache, since, sources=sources, eol_rows=rows, latest_keys=set(),
                                   generated_at="2026-11-18T10:00:00Z", tools={"syft": "1.18.1"})
        ds = prov["data_sources"]
        self.assertEqual(prov["config_sha256"], "d" * 64)
        self.assertEqual(ds["cisa_kev"]["origin"], "live")
        self.assertEqual(ds["cisa_kev"]["catalog_version"], "2026.11.17")
        self.assertEqual(ds["cisa_kev"]["status"], "ok")
        self.assertEqual((ds["endoflife"]["answers"], ds["endoflife"]["live"], ds["endoflife"]["cached"],
                          ds["endoflife"]["without_answer"]), (3, 1, 1, 1))
        self.assertEqual(ds["endoflife"]["status"], "partial")
        self.assertEqual(ds["registries"]["status"], "ok")
        self.assertEqual(ds["openvex"]["statements"], 4)
        self.assertEqual(ds["osv"]["queried_at"], "2026-11-18T10:00:00Z")

    def test_kev_from_cache_without_meta_and_failed(self):
        self.cache.put("kev-catalog", ["CVE-1"])
        prov = manifest.provenance(None, self.cache, time.time() + 5, sources={"cisa_kev": {"loaded": 1}}, tools={})
        self.assertEqual(prov["data_sources"]["cisa_kev"]["origin"], "cache")
        self.assertEqual(prov["data_sources"]["cisa_kev"]["catalog_date"], "unknown")
        failed = manifest.provenance(None, Cache(Path(self._tmp.name) / "none"), 0,
                                     sources={"cisa_kev": {"loaded": 0, "error": "CISA KEV fetch failed"}}, tools={})
        self.assertEqual(failed["data_sources"]["cisa_kev"]["status"], "failed")
        self.assertIsNone(failed["data_sources"]["cisa_kev"]["origin"])

    def test_try_provenance_never_raises(self):
        prov = manifest.try_provenance(None, None, 0, sources={})
        self.assertIn("error", prov)
        self.assertIn("Not recorded for this audit", "\n".join(manifest.audit_md_section(prov)))

    def test_kev_meta_is_cached_on_a_live_fetch(self):
        from sbomaudit import enrich
        doc = {"catalogVersion": "2026.11.17", "dateReleased": "2026-11-17T15:00:00Z",
               "vulnerabilities": [{"cveID": "CVE-2026-1"}]}
        enrich.load_kev(self.cache, lambda url: doc)
        self.assertEqual(self.cache.get("kev-catalog-meta")["catalogVersion"], "2026.11.17")
        self.assertIsNotNone(self.cache.stored_at("kev-catalog"))
        self.assertIsNone(self.cache.stored_at("absent"))


class RunManifestTests(unittest.TestCase):
    """A real `run` (scan and osv-scanner mocked) writes manifest.json and commits it with the rest."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()

    def tearDown(self):
        self._tmp.cleanup()

    def run_pipeline(self, commit=True):
        cfg = make_cfg(self.tmp)
        if commit:
            git_init(cfg.out)
        (cfg.out / ".cache").mkdir()
        (cfg.out / ".cache" / "fingerprint.key").write_text(PLANTED)
        (cfg.out / "vex").mkdir()
        with tools_present(), probed(), \
             mock.patch.object(pipeline.scan, "scan", return_value=scan_result(inventory())), \
             mock.patch.object(pipeline.matching, "run_osv_scanner", return_value={"results": []}), \
             contextlib.redirect_stdout(io.StringIO()):
            rc = pipeline.run(cfg, http=offline, log=lambda m: None)
        self.cfg, self.out = cfg, cfg.out
        return rc

    def verify(self, *extra):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["--out", str(self.out), "verify", *extra])
        return rc, buf.getvalue()

    def test_manifest_fields_and_commit(self):
        rc = self.run_pipeline()
        self.assertEqual(rc, 0)
        text = (self.out / "manifest.json").read_text(encoding="utf-8")
        doc = json.loads(text)
        self.assertEqual(doc["schema"], manifest.SCHEMA)
        self.assertEqual(doc["run"]["exit_code"], 0)
        start = dt.datetime.fromisoformat(doc["run"]["started_at"])
        end = dt.datetime.fromisoformat(doc["run"]["finished_at"])
        self.assertLessEqual(start, end)
        self.assertEqual(start.utcoffset(), dt.timedelta(0))
        self.assertEqual(doc["tools"]["syft"], "1.18.1")
        self.assertEqual(doc["tools"]["osv-scanner"], "2.0.2")
        self.assertEqual(doc["tools"]["git"], "2.47.1")
        self.assertEqual(doc["audited"], [{"project": "zeta", "branch": "main", "commit": "abc1234def",
                                           "complete": True}])
        for key in ("osv", "cisa_kev", "endoflife", "registries", "openvex", "secrets"):
            self.assertIn(key, doc["data_sources"])
        for rel in ("audit.json", "AUDIT.md", "INVENTORY.md", "log.md", "status.json", "STATUS.md",
                    "REPORT.html"):
            self.assertIn(rel, doc["files"], rel)
        self.assertTrue(doc["files"]["AUDIT.md"]["append_only"])
        self.assertTrue(doc["files"]["log.md"]["append_only"])
        audit_json = (self.out / "audit.json").read_bytes()
        import hashlib
        self.assertEqual(doc["files"]["audit.json"]["sha256"], hashlib.sha256(audit_json).hexdigest())
        self.assertEqual(doc["files"]["audit.json"]["bytes"], len(audit_json))
        self.assertFalse([p for p in doc["files"] if p.startswith((".cache", ".git")) or p == "manifest.json"])
        self.assertNotIn(".cache", text)
        for i in range(len(PLANTED) - 4):
            self.assertNotIn(PLANTED[i:i + 5], text)
        self.assertIn("manifest.json", git(self.out, "ls-files").splitlines())
        self.assertEqual(git(self.out, "status", "--porcelain"), "")

    def test_audit_md_and_report_name_versions_and_the_manifest(self):
        self.run_pipeline(commit=False)
        audit_md = (self.out / "AUDIT.md").read_text(encoding="utf-8")
        section = audit_md.split("## How this report was produced", 1)[1]
        self.assertIn("| syft | 1.18.1 |", section)
        self.assertIn("| CISA KEV |", section)
        self.assertIn("`manifest.json`", section)
        page = (self.out / "REPORT.html").read_text(encoding="utf-8")
        self.assertIn("How this report was produced", page)
        self.assertIn("1.18.1", page)
        self.assertIn("verify", page)
        audit = json.loads((self.out / "audit.json").read_text(encoding="utf-8"))
        self.assertEqual(audit["provenance"]["tools"]["osv-scanner"], "2.0.2")

    def test_verify_ok_changed_missing_appended(self):
        self.run_pipeline(commit=False)
        rc, text = self.verify()
        self.assertEqual(rc, 0, text)
        self.assertIn("ok       audit.json", text)
        with open(self.out / "AUDIT.md", "a", encoding="utf-8") as fh:     # a hand-written assessment
            fh.write("\n## Assessment 2026-11-18\n\nReviewed.\n")
        with open(self.out / "log.md", "a", encoding="utf-8") as fh:
            fh.write("- a note\n")
        rc, text = self.verify()
        self.assertEqual(rc, 0, text)
        self.assertIn("appended AUDIT.md", text)
        (self.out / "INVENTORY.md").write_text("tampered\n", encoding="utf-8")
        (self.out / "status.json").unlink()
        rc, text = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn("changed  INVENTORY.md", text)
        self.assertIn("missing  status.json", text)
        rc, text = self.verify("--json")
        result = json.loads(text)
        self.assertEqual(result["exit_code"], 1)
        self.assertEqual(result["counts"]["changed"], 1)

    def test_edit_inside_an_append_only_file_is_a_change(self):
        self.run_pipeline(commit=False)
        path = self.out / "AUDIT.md"
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace("# Dependency Audit", "# Dependency Audlt", 1) + "\nmore\n", encoding="utf-8")
        rc, out = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn("changed  AUDIT.md", out)

    def test_verify_names_unlisted_evidence_and_config_edit(self):
        self.run_pipeline(commit=False)
        (self.out / "vex" / "late.openvex.json").write_text("{}", encoding="utf-8")
        doc = json.loads((self.out / "manifest.json").read_text(encoding="utf-8"))
        doc["config"]["sha256"] = "0" * 64          # as if the run had read a configuration file
        (self.out / "manifest.json").write_text(json.dumps(doc), encoding="utf-8")
        (self.out / "sbom-audit.toml").write_text("# edited\n", encoding="utf-8")
        rc, text = self.verify()
        self.assertEqual(rc, 0, text)
        self.assertIn("vex/late.openvex.json", text)
        self.assertIn("differs from the digest", text)

    def test_verify_writes_nothing_and_works_read_only(self):
        self.run_pipeline(commit=False)
        (self.out / "INVENTORY.md").write_text("tampered\n", encoding="utf-8")

        def state():
            return sorted((str(p), p.stat().st_mtime_ns) for p in self.out.rglob("*"))
        before = state()
        with mock.patch.dict(os.environ, {"SBOM_AUDIT_READ_ONLY": "1"}):
            rc, _ = self.verify()
        self.assertEqual(rc, 1)
        self.assertEqual(state(), before)

    def test_writing_command_refreshes_only_what_it_wrote(self):
        self.run_pipeline(commit=False)
        (self.out / "INVENTORY.md").write_text("tampered\n", encoding="utf-8")   # a hand edit before the command
        audit = json.loads((self.out / "audit.json").read_text(encoding="utf-8"))
        audit["vulnerabilities"].append(vuln("left-pad", "HIGH", "zeta"))       # so `issues` writes new content
        (self.out / "audit.json").write_text(json.dumps(audit), encoding="utf-8")
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["--out", str(self.out), "issues"]), 0)
        doc = json.loads((self.out / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(doc["files"]["ISSUES.md"]["refreshed"]["command"], "issues")
        self.assertEqual(doc["refreshed"][-1]["command"], "issues")
        self.assertIn("ISSUES.md", doc["refreshed"][-1]["files"])
        self.assertNotIn("refreshed", doc["files"]["INVENTORY.md"])
        self.assertIn("refreshed by `issues`", err.getvalue())
        rc, text = self.verify()
        self.assertEqual(rc, 1, text)
        self.assertIn("changed  INVENTORY.md", text)
        self.assertIn("changed  audit.json", text)
        self.assertIn("ok       ISSUES.md (refreshed by `issues`", text)


class VerifyEdgeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.out = Path(self._tmp.name).resolve() / "security"
        self.out.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def test_no_manifest_and_unreadable_exit_2(self):
        self.assertEqual(manifest.verify(self.out)["exit_code"], 2)
        (self.out / "manifest.json").write_text("{not json", encoding="utf-8")
        self.assertEqual(manifest.verify(self.out)["exit_code"], 2)
        (self.out / "manifest.json").write_text('{"schema": "other"}', encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            self.assertEqual(cli.main(["--out", str(self.out), "verify"]), 2)
        self.assertIn("unreadable", buf.getvalue())

    def test_unsafe_paths_are_invalid_and_never_read(self):
        (self.out.parent / "outside.txt").write_text("x", encoding="utf-8")
        (self.out / ".cache").mkdir()
        (self.out / ".cache" / "k").write_text(PLANTED, encoding="utf-8")
        doc = {"schema": manifest.SCHEMA, "files": {
            "../outside.txt": {"sha256": "0" * 64, "bytes": 1},
            ".cache/k": {"sha256": "0" * 64, "bytes": len(PLANTED)},
            "/etc/hosts": {"sha256": "0" * 64, "bytes": 1}}}
        (self.out / "manifest.json").write_text(json.dumps(doc), encoding="utf-8")
        result = manifest.verify(self.out)
        self.assertEqual(result["exit_code"], 1)
        self.assertEqual({r["status"] for r in result["files"]}, {"invalid"})
        self.assertNotIn(PLANTED, json.dumps(result))

    def test_symlink_is_a_change(self):
        (self.out.parent / "target").write_text("x", encoding="utf-8")
        (self.out / "a.md").symlink_to(self.out.parent / "target")
        import hashlib
        doc = {"schema": manifest.SCHEMA, "files": {"a.md": {"sha256": hashlib.sha256(b"x").hexdigest(), "bytes": 1}}}
        (self.out / "manifest.json").write_text(json.dumps(doc), encoding="utf-8")
        self.assertEqual(manifest.verify(self.out)["files"][0]["status"], "changed")

    def test_refresh_without_manifest_does_nothing(self):
        self.assertIsNone(manifest.snapshot(self.out))
        self.assertEqual(manifest.refresh_changed(self.out, None, "issues"), [])
        self.assertFalse((self.out / "manifest.json").exists())


class SurfaceTests(unittest.TestCase):
    def test_verify_is_a_read_only_autonomous_command(self):
        self.assertIn("verify", cli.COMMANDS)
        self.assertNotIn("verify", cli.WRITING_COMMANDS)
        self.assertIn("verify", integration.AUTONOMOUS_SUBCOMMANDS)
        args = cli.build_parser().parse_args(["verify", "--json"])
        self.assertFalse(cli._writes(args))

    def test_management_section_in_both_languages(self):
        prov = {"sbom_audit": "9.9.9", "python": "3.12.1", "platform": "Linux", "config_sha256": "c" * 64,
                "tools": {"syft": "1.18.1", "osv-scanner": "unknown"},
                "data_sources": {"cisa_kev": {"status": "ok", "fetched_at": "2026-11-18T09:00:00+00:00",
                                              "origin": "cache", "catalog_date": "2026-11-17"},
                                 "endoflife": {"status": "partial", "answers": 0}}}
        for lang, heading, cache_word in (("en", "6. How this report was produced", "from the local cache"),
                                          ("de", "6. Wie dieser Bericht entstanden ist", "aus dem lokalen Cache")):
            data = {"audit": {"provenance": prov}, "secrets": {"engine": {"name": "gitleaks", "version": "8.21.2"}}}
            html = management._produced(data, management.STRINGS[lang])
            self.assertIn(heading, html)
            self.assertIn("1.18.1", html)
            self.assertIn("8.21.2", html)
            self.assertIn(cache_word, html)
            self.assertIn("manifest.json", html)
            none = management._produced({"audit": None, "secrets": None}, management.STRINGS[lang])
            self.assertIn(management.STRINGS[lang]["p_none"], none)
        self.assertEqual({k for k in management.STRINGS["en"] if k.startswith("p_")},
                         {k for k in management.STRINGS["de"] if k.startswith("p_")})


if __name__ == "__main__":
    unittest.main()
