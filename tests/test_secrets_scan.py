"""Secrets scan: the whole step over the planted fixture portfolio, SECRETS.md, the CLI and the run.

Assertions never print a planted value or a findings row: anything involving one is checked in memory with
`assertTrue(..., "fixed message")`, and only rule ids, files, classes and fingerprints reach a message.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import functools
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import cli, config, pipeline, status
from sbomaudit import secrets as secrets_mod
from sbomaudit.errors import EngineError
from sbomaudit.secrets import engine as eng
from sbomaudit.secrets import report as secrets_report
from sbomaudit.secrets import store
from sbomaudit.secrets.classify import load_classes
from sbomaudit.secrets.findings import FIELDS
from tests import secrets_fixture as fx
from tests import test_pipeline as tp
from tests.helpers import _git
from tests.secrets_fixture import PLANTED

HAS_GITLEAKS = shutil.which("gitleaks") is not None
NOW = dt.datetime(2026, 11, 7, 12, 0, tzinfo=dt.timezone.utc)
LATER = NOW + dt.timedelta(days=1)
REAL_SCAN_REPO = eng.scan_repo
REAL_FIND_ENGINE = eng.find_engine
CLASS_C_FILES = sorted({p.file for p in PLANTED.values() if p.expected_class == "C"})


def load_cfg(root: Path) -> config.Config:
    return config.load(root / "security")


def run_scan(cfg: config.Config, *, full: bool, now=NOW) -> dict:
    lines: list[str] = []
    return secrets_mod.scan(cfg, full=full, log=lines.append, now=now)


class Recorder:
    """Wraps engine.scan_repo: records repo, log options and the reported fingerprints (never a value)."""

    def __init__(self):
        self.calls: list[tuple[str, str, list[str]]] = []

    def __call__(self, engine, repo, **kwargs):
        rows = REAL_SCAN_REPO(engine, repo, **kwargs)
        self.calls.append((Path(repo).name, kwargs["log_opts"], [row["Fingerprint"] for row in rows]))
        return rows

    def opts(self, repo: str) -> str:
        return next(opts for name, opts, _ in self.calls if name == repo)


def finding(fp="c1:a.env:github-pat:1", repo="alpha-app", cls="A", provider="github", status_="open", **over):
    f = {name: None for name in FIELDS}
    f.update({"fingerprint": fp, "value_id": "0" * 16, "repo": repo, "branches": ["main"], "commit": "c1" * 20,
              "author": "Test", "date": "2026-10-01T10:00:00Z", "file": "a.env", "line": 1, "rule_id": "github-pat",
              "provider": provider, "class": cls, "entropy": 4.5, "live_in_tree": True, "age_days": 37,
              "status": status_, "first_seen": "2026-11-01", "last_seen": "2026-11-01"})
    f.update(over)
    return f


@unittest.skipUnless(HAS_GITLEAKS, "gitleaks not installed")
class FullScanTests(unittest.TestCase):
    """One full scan of the fixture portfolio, read by several tests."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = fx.write_fixture_portfolio(Path(cls._tmp.name).resolve())
        cls.cfg = load_cfg(cls.root)
        cls.doc = run_scan(cls.cfg, full=True)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_full_scan_finds_and_classifies_every_planted_value(self):
        self.assertEqual(self.doc["scan"]["mode"], "full")
        self.assertEqual(self.doc["scan"]["failed"], [])
        self.assertEqual(self.doc["engine"]["name"], "gitleaks")
        self.assertEqual(set(self.doc["repos"]), {"alpha-app", "beta-api", "ignored-archive"})
        for key, planted in PLANTED.items():
            hits = [f for f in self.doc["findings"]
                    if f["rule_id"] == planted.rule_id and f["file"] == planted.file]
            self.assertTrue(hits, f"no finding for {key}")
            self.assertTrue(all(f["class"] == planted.expected_class for f in hits), f"wrong class for {key}")
            for f in hits:
                self.assertEqual(set(f), set(FIELDS), key)
        history = [f for f in self.doc["findings"] if f["file"] == PLANTED[fx.HISTORY_ONLY].file]
        self.assertTrue(history and not any(f["live_in_tree"] for f in history), "history-only value is live")
        self.assertTrue(any(f["repo"] == "ignored-archive" for f in self.doc["findings"]),
                        "ignored project not scanned")
        branch_only = [f for f in self.doc["findings"] if f["file"] == PLANTED[fx.BRANCH_ONLY].file]
        self.assertTrue(branch_only and all(f["branches"] == ["dev"] for f in branch_only), "branch-only value")
        self.assertTrue(store.read(self.cfg.out) == self.doc, "secrets.json differs from the returned document")
        paths = {name: r["path"] for name, r in self.doc["repos"].items()}
        self.assertTrue(all(p is None or not p.startswith("/") for p in paths.values()), "absolute repo path stored")
        self.assertEqual(paths["alpha-app"], "alpha-app")

    def test_class_c_only_in_json(self):
        text = (self.cfg.out / "SECRETS.md").read_text(encoding="utf-8")
        self.assertTrue(any(f["class"] == "C" for f in self.doc["findings"]))
        for file in CLASS_C_FILES:
            self.assertTrue(file not in text, 'unexpected: file')
        for f in self.doc["findings"]:
            if f["class"] in ("A", "B") and f["status"] == "open":
                self.assertTrue(f["fingerprint"] in text, 'missing: f["fingerprint"]')
        self.assertTrue("## Open" in text, 'missing: "## Open"')
        self.assertTrue("rotate first" in text.lower(), 'missing: "rotate first"')
        self.assertEqual(text.lower().count("rotate first"), 1)
        dated = self.cfg.out / "reports" / f"{self.doc['generated_at'][:10]}-secrets.md"
        self.assertTrue(dated.read_text(encoding="utf-8") == text,
                        'text differs: dated.read_text(encoding="utf-8")')
        log = (self.cfg.out / "log.md").read_text(encoding="utf-8").splitlines()
        counts = {c: sum(1 for f in self.doc["findings"] if f["class"] == c and f["status"] == "open")
                  for c in "ABC"}
        expected = (f"{self.doc['generated_at']} | secrets | full | repos 3 | "
                    f"A {counts['A']} | B {counts['B']} | C {counts['C']}")
        self.assertTrue(log[-1] == expected, "last log.md line is not the secrets line")


@unittest.skipUnless(HAS_GITLEAKS, "gitleaks not installed")
class ScanStateTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = fx.write_fixture_portfolio(Path(self._tmp.name).resolve())
        self.cfg = load_cfg(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def test_incremental_scan_after_one_commit_scans_only_that_commit(self):
        first = run_scan(self.cfg, full=False)
        self.assertEqual(first["scan"]["mode"], "full")              # first scan is always full
        alpha = self.root / "alpha-app"
        old_tip = _git(alpha, "rev-parse", "HEAD").strip()
        self.assertTrue(old_tip in first["repos"]["alpha-app"]["tips"], 'missing: old_tip')
        key = "github-pat"                                           # planted in beta-api only
        (alpha / "ci" / "later.env").write_text(fx.LINES[key].format(v=PLANTED[key].value))
        _git(alpha, "add", "ci/later.env")
        _git(alpha, "commit", "-q", "-m", "add later token")
        recorder = Recorder()
        with mock.patch.object(eng, "scan_repo", recorder):
            second = run_scan(self.cfg, full=False, now=LATER)
        self.assertEqual(second["scan"]["mode"], "incremental")
        self.assertTrue(f"^{old_tip}" in recorder.opts("alpha-app"), 'missing: f"^{old_tip}"')
        self.assertTrue(recorder.opts("beta-api").startswith("--all ^"))
        reported = [fp for name, _, fps in recorder.calls for fp in fps]
        self.assertEqual(len(reported), 1)
        new = [f for f in second["findings"] if f["repo"] == "alpha-app" and f["file"] == "ci/later.env"]
        self.assertEqual(len(new), 1)
        self.assertEqual(new[0]["first_seen"], LATER.date().isoformat())
        self.assertEqual(len(second["findings"]), len(first["findings"]) + 1)   # the old ones are carried
        self.assertEqual({f["fingerprint"] for f in first["findings"]} - {f["fingerprint"] for f in second["findings"]},
                         set())

    def test_incremental_scan_recomputes_ages_and_labels_carried_fields(self):
        first = run_scan(self.cfg, full=True)
        second = run_scan(self.cfg, full=False, now=LATER)
        self.assertEqual(second["scan"]["mode"], "incremental")
        before = {f["fingerprint"]: f["age_days"] for f in first["findings"]}
        self.assertTrue(any(age is not None for age in before.values()), "fixture rows have no dates")
        for f in second["findings"]:
            if before.get(f["fingerprint"]) is not None:
                self.assertTrue(f["age_days"] == before[f["fingerprint"]] + 1, f"age not refreshed: {f['fingerprint']}")

        def oldest(doc):
            return max(f["age_days"] for f in doc["findings"] if f["status"] == "open" and f["age_days"] is not None)
        built = status.build(status.empty_report(), secrets=second, previous=None, duration_s=1.0, exit_code=1,
                             run_host="h", mode="portfolio")
        self.assertEqual(built["secrets_scan"]["oldest_open_days"], oldest(first) + 1)
        line = status.severity_line(built, None, LATER)
        self.assertTrue(f"oldest {oldest(first) + 1} days" in line, "severity line does not follow the age")

        text = (self.cfg.out / "SECRETS.md").read_text(encoding="utf-8")
        label = f"(as of {NOW.date().isoformat()})"
        self.assertTrue(f"branches {label}:" in text and f"live in tree {label}:" in text,
                        "carried finding lacks the as-of label")
        run_scan(self.cfg, full=True, now=LATER)                      # a full scan re-finds and refreshes
        text = (self.cfg.out / "SECRETS.md").read_text(encoding="utf-8")
        self.assertTrue("(as of " not in text, "as-of label after a full scan")

    def test_vanished_previous_tip_is_left_out_of_log_opts(self):
        first = run_scan(self.cfg, full=False)
        doc = store.read(self.cfg.out)
        gone = "0" * 40                                               # e.g. a force-pushed and gc'd tip
        doc["repos"]["alpha-app"]["tips"] = [gone, *doc["repos"]["alpha-app"]["tips"]]
        store.write(self.cfg.out, doc)
        recorder = Recorder()
        with mock.patch.object(eng, "scan_repo", recorder):
            again = run_scan(self.cfg, full=False)
        self.assertEqual((again["scan"]["mode"], again["scan"]["failed"]), ("incremental", []))
        self.assertTrue(gone not in recorder.opts("alpha-app"), 'unexpected: gone')
        self.assertEqual(again["repos"]["alpha-app"]["tips"], first["repos"]["alpha-app"]["tips"])
        self.assertEqual(len(again["findings"]), len(first["findings"]))

    def test_rules_change_forces_full(self):
        run_scan(self.cfg, full=False)
        doc = store.read(self.cfg.out)
        doc["rules_hash"] = "0" * 16
        store.write(self.cfg.out, doc)
        recorder = Recorder()
        with mock.patch.object(eng, "scan_repo", recorder):
            again = run_scan(self.cfg, full=False)
        self.assertEqual(again["scan"]["mode"], "full")
        self.assertEqual(again["rules_hash"], store.rules_hash())
        self.assertEqual({opts for _, opts, _ in recorder.calls}, {eng.log_opts_full()})
        recorder = Recorder()
        with mock.patch.object(eng, "scan_repo", recorder):
            forced = run_scan(self.cfg, full=True)
        self.assertEqual(forced["scan"]["mode"], "full")
        self.assertEqual({opts for _, opts, _ in recorder.calls}, {eng.log_opts_full()})

    def test_resolve_refreshes_the_status_and_the_work_list(self):
        """A decision closes the finding everywhere at once: status.json must not keep counting it until the
        next run (the session line would go on naming secrets that are decided)."""
        from sbomaudit import issues, status
        doc = run_scan(self.cfg, full=True)
        out = self.cfg.out
        open_a = [f["fingerprint"] for f in doc["findings"] if f["class"] == "A" and f["status"] == "open"]
        before = status.build(status.empty_report(), secrets=doc, previous=None, duration_s=1.0, exit_code=0,
                              run_host="mac", mode="full")
        status.write(out, before)
        status.write_md(out, before)
        issues.refresh(out)
        self.assertIn(f"secret:{open_a[0]}", {i["id"] for i in issues.read(out)["issues"]})
        with contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main(["secrets", "resolve", open_a[0], "rotated", "rolled", "--out", str(out)])
        self.assertEqual(rc, 0)
        after = status.read(out)
        self.assertEqual(after["counts"]["secrets"]["A"], before["counts"]["secrets"]["A"] - 1)
        self.assertNotIn(open_a[0], after["open"]["secrets_a"])
        self.assertEqual(after["deltas"]["secrets_a"]["resolved"], [open_a[0]])
        self.assertEqual(after["generated_at"], before["generated_at"])        # the run facts stay the run's
        self.assertEqual(after["secrets_scan"]["mode"], before["secrets_scan"]["mode"])
        self.assertIn(f"{len(open_a) - 1} class A", (out / "STATUS.md").read_text(encoding="utf-8"))
        self.assertNotIn(f"secret:{open_a[0]}", {i["id"] for i in issues.read(out)["issues"]})

    def test_resolve_before_the_first_run_creates_no_status_and_no_work_list(self):
        doc = run_scan(self.cfg, full=True)
        fp = next(f["fingerprint"] for f in doc["findings"] if f["status"] == "open")
        for name in ("status.json", "STATUS.md", "issues.json", "ISSUES.md"):
            (self.cfg.out / name).unlink(missing_ok=True)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["secrets", "resolve", fp, "accepted", "x", "--out", str(self.cfg.out)]), 0)
        for name in ("status.json", "STATUS.md", "issues.json", "ISSUES.md"):
            self.assertFalse((self.cfg.out / name).exists(), name)

    def test_resolve_then_report_moves_finding(self):
        doc = run_scan(self.cfg, full=True)
        open_a = [f for f in doc["findings"] if f["class"] == "A" and f["status"] == "open"]
        rotated, fixture = open_a[0], open_a[1]
        out = str(self.cfg.out)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main(["secrets", "resolve", rotated["fingerprint"], "rotated", "rolled in the dashboard",
                           "--rotated-on", "2026-11-07", "--out", out])
        self.assertEqual(rc, 0)
        after = store.read(self.cfg.out)
        self.assertEqual(next(f for f in after["findings"] if f["fingerprint"] == rotated["fingerprint"])["status"],
                         "rotated")
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            rc = cli.main(["secrets", "report", "--out", out])
        self.assertEqual(rc, 1)                                       # other class A findings stay open
        text = printed.getvalue()
        opened, _, appendix = text.partition("## Rotated")
        self.assertTrue(rotated["fingerprint"] not in opened, 'unexpected: rotated["fingerprint"]')
        self.assertTrue(rotated["fingerprint"] in appendix.split("## Accepted")[0],
                        'missing: rotated["fingerprint"]')
        self.assertTrue("rolled in the dashboard" in appendix, 'missing: "rolled in the dashboard"')
        self.assertTrue((self.cfg.out / "SECRETS.md").read_text(encoding="utf-8") == text,
                        'text differs: (self.cfg.out / "SECRETS.md").read_text(encoding="utf-8")')

        with contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main(["secrets", "resolve", fixture["fingerprint"], "false_positive", "fixture data",
                           "--out", out])
        self.assertEqual(rc, 0)
        ignore = (self.cfg.out / store.IGNORE_FILE).read_text(encoding="utf-8").splitlines()
        self.assertTrue(fixture["fingerprint"] in ignore, 'missing: fixture["fingerprint"]')
        recorder = Recorder()
        with mock.patch.object(eng, "scan_repo", recorder):
            rescan = run_scan(self.cfg, full=True)
        reported = {fp for _, _, fps in recorder.calls for fp in fps}
        self.assertTrue(fixture["fingerprint"] not in reported, 'unexpected: fixture["fingerprint"]')
        kept = next(f for f in rescan["findings"] if f["fingerprint"] == fixture["fingerprint"])
        self.assertEqual(kept["status"], "false_positive")
        self.assertTrue(fixture["fingerprint"] not in (self.cfg.out / "SECRETS.md").read_text(encoding="utf-8"),
                        'unexpected: fixture["fingerprint"]')

        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main(["secrets", "resolve", "no-such:fingerprint", "accepted", "x", "--out", out])
        self.assertEqual(rc, 2)
        self.assertTrue("unknown fingerprint" in err.getvalue(), 'missing: "unknown fingerprint"')

    def test_failed_repo_keeps_findings_and_exits_2(self):
        first = run_scan(self.cfg, full=True)
        beta = {f["fingerprint"] for f in first["findings"] if f["repo"] == "beta-api"}

        def failing(engine, repo, **kwargs):
            if Path(repo).name == "beta-api":
                raise EngineError("gitleaks exit 2: fatal: something broke")
            return REAL_SCAN_REPO(engine, repo, **kwargs)
        with mock.patch.object(eng, "scan_repo", failing):
            doc = run_scan(self.cfg, full=True, now=LATER)
        self.assertEqual(doc["scan"]["failed"], [{"repo": "beta-api", "error": "gitleaks exit 2: fatal: something broke"}])
        self.assertEqual(doc["repos"]["beta-api"], first["repos"]["beta-api"])        # tips not advanced
        self.assertTrue(beta <= {f["fingerprint"] for f in doc["findings"]}, "failed repo lost findings")
        last = (self.cfg.out / "log.md").read_text().splitlines()[-1]
        self.assertTrue("| failed: beta-api: gitleaks exit 2" in last,
                        'missing: "| failed: beta-api: gitleaks exit 2"')
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed), mock.patch.object(eng, "scan_repo", failing):
            rc = cli.main(["secrets", "scan", "--out", str(self.cfg.out)])
        self.assertEqual(rc, 2)


class EngineProblemTests(unittest.TestCase):
    def test_missing_engine_reports_skipped_never_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            out = root / "security"
            config.write_default(out, config.Config(out=out, root=root, mode="portfolio"))
            cfg = load_cfg(root)
            previous = {"schema": store.SCHEMA, "generated_at": "2026-11-01T10:00:00+00:00",
                        "engine": {"name": "gitleaks", "version": "8.30.1"}, "rules_hash": "r" * 16,
                        "plugin_minor": store.plugin_minor(),
                        "scan": {"mode": "full", "repos": 1, "failed": [], "skipped_reason": None, "error": None},
                        "repos": {"alpha-app": {"path": "/x", "github": None, "tips": ["a" * 40],
                                                "scanned_at": "2026-11-01T10:00:00+00:00"}},
                        "findings": [finding()]}
            store.write(out, previous)
            no_engine = functools.partial(REAL_FIND_ENGINE, which=lambda name: None)
            with mock.patch.object(eng, "find_engine", no_engine), \
                 mock.patch.object(eng, "scan_repo", side_effect=AssertionError("engine must not run")):
                doc = run_scan(cfg, full=False)
            self.assertEqual(doc["scan"]["mode"], "skipped")
            self.assertEqual(doc["scan"]["skipped_reason"], "skipped (install: brew install gitleaks)")
            self.assertEqual(doc["engine"], {"name": None, "version": None})
            self.assertEqual(doc["findings"], previous["findings"])
            self.assertEqual((doc["repos"], doc["rules_hash"]), (previous["repos"], previous["rules_hash"]))
            self.assertEqual(store.read(out)["scan"]["mode"], "skipped")
            text = (out / "SECRETS.md").read_text(encoding="utf-8")
            self.assertTrue("skipped (install: brew install gitleaks)" in text,
                            'missing: "skipped (install: brew install gitleaks)"')
            self.assertTrue("not the same as clean" in text.lower(), 'missing: "not the same as clean"')
            self.assertTrue(" | secrets | skipped | " in (out / "log.md").read_text().splitlines()[-1],
                            'missing: " | secrets | skipped | "')

            s = status.build(status.empty_report(), secrets=doc, previous=None, duration_s=1.0, exit_code=0,
                             run_host="h", mode="portfolio")
            self.assertEqual(s["secrets_scan"]["mode"], "skipped")
            self.assertIsNone(s["secrets_scan"]["engine"])
            md = status.write_md(out, s, None).read_text(encoding="utf-8")
            self.assertTrue("- secrets: skipped (install: brew install gitleaks)" in md,
                            'missing: "- secrets: skipped (install: brew install gitleaks)"')
            self.assertTrue("Not the same as clean" in md, 'missing: "Not the same as clean"')
            self.assertTrue("All sources answered" not in md, 'unexpected: "All sources answered"')

            printed = io.StringIO()
            with contextlib.redirect_stdout(printed), mock.patch.object(eng, "find_engine", no_engine):
                rc = cli.main(["secrets", "scan", "--out", str(out)])
            self.assertEqual(rc, 4)
            self.assertTrue("brew install gitleaks" in printed.getvalue(), 'missing: "brew install gitleaks"')

    def test_default_now_is_utc(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            out = root / "security"
            config.write_default(out, config.Config(out=out, root=root, mode="portfolio"))
            no_engine = functools.partial(REAL_FIND_ENGINE, which=lambda name: None)
            with mock.patch.object(eng, "find_engine", no_engine):
                doc = secrets_mod.scan(load_cfg(root), full=False)
            stamp = dt.datetime.fromisoformat(doc["generated_at"])
            self.assertEqual(stamp.utcoffset(), dt.timedelta(0))
            self.assertRegex(doc["generated_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$")

    def test_malformed_decisions_fail_the_step(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            out = root / "security"
            config.write_default(out, config.Config(out=out, root=root, mode="portfolio"))
            (out / store.DECISIONS_FILE).write_text('[decisions."fp1"]\nstatus = "bogus"\nnote = "my note"\n')
            present = eng.Engine("/x/gitleaks", "gitleaks", "8.30.1")
            with mock.patch.object(eng, "find_engine", return_value=present), \
                 mock.patch.object(eng, "scan_repo", side_effect=AssertionError("engine must not run")):
                doc = run_scan(load_cfg(root), full=False)
            self.assertEqual(doc["scan"]["mode"], "skipped")
            self.assertTrue("status is missing or unknown" in doc["scan"]["error"],
                            'missing: "status is missing or unknown"')
            self.assertTrue("my note" not in json.dumps(doc), 'unexpected: "my note"')
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                rc = cli.main(["secrets", "resolve", "fp1", "accepted", "x", "--out", str(out)])
            self.assertEqual(rc, 2)
            self.assertTrue("status is missing or unknown" in err.getvalue(),
                            'missing: "status is missing or unknown"')
            self.assertTrue("my note" not in err.getvalue(), 'unexpected: "my note"')


class CliTests(unittest.TestCase):
    def test_statuses_match_the_store(self):
        self.assertEqual(cli.SECRETS_STATUSES, store.STATUSES)

    def test_read_only_blocks_scan_and_resolve_but_not_report(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"SBOM_AUDIT_READ_ONLY": "1"}):
            out = Path(tmp) / "security"
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["secrets", "scan", "--full", "--out", str(out)]), 5)
                self.assertEqual(cli.main(["secrets", "resolve", "fp", "accepted", "x", "--out", str(out)]), 5)
                self.assertEqual(cli.main(["secrets", "report", "--out", str(out)]), 2)
            self.assertTrue("read-only mode: secrets writes nothing" in err.getvalue(),
                            'missing: "read-only mode: secrets writes nothing"')
            self.assertTrue("no secrets scan yet" in err.getvalue(), 'missing: "no secrets scan yet"')
            self.assertFalse(out.exists())


class ReportTests(unittest.TestCase):
    def test_also_uses_line_from_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            comp = {"kind": "package", "ecosystem": "npm", "name": "@supabase/supabase-js", "version": "2.0.0"}
            inv = {"inventories": [
                {"project": "beta", "branch": "main", "components": [comp]},
                {"project": "beta", "branch": "dev", "components": [comp]},
                {"project": "alpha", "branch": "main", "components": [comp]},
                {"project": "gamma", "branch": "main", "components": [{**comp, "name": "left-pad"}]}]}
            (out / "inventory.json").write_text(json.dumps(inv))
            supa = finding("c2:supabase/service.env:supabase-secret-key:1", repo="alpha", provider="supabase",
                           rule_id="supabase-secret-key", file="supabase/service.env")
            gh = finding("c3:ci/github.env:github-pat:1", repo="alpha", provider="github", date="2026-11-01T10:00:00Z")
            accepted = finding("c4:x.env:github-pat:1", repo="alpha", status_="accepted")
            doc = {"generated_at": "2026-11-07T13:00:00+01:00", "engine": {"name": "gitleaks", "version": "8.30.1"},
                   "scan": {"mode": "full", "repos": 1, "failed": [], "skipped_reason": None, "error": None},
                   "findings": [gh, supa, accepted, finding("c5:y.env:x:1", cls="C")]}
            (out / store.DECISIONS_FILE).write_text(
                '[decisions."c4:x.env:github-pat:1"]\nstatus = "accepted"\ndate = "2026-11-02"\n'
                'note = "read-only token, accepted"\n')
            text = secrets_report.write_secrets_md(out, doc, load_classes()).read_text(encoding="utf-8")
            self.assertTrue("also uses supabase: beta" in text, 'missing: "also uses supabase: beta"')
            self.assertTrue("also uses github" not in text, 'unexpected: "also uses github"')  # no match: omitted
            self.assertTrue(load_classes().providers["supabase"].hint in text,
                            'missing: load_classes().providers["supabase"].hint')
            opened = text.split("## Open")[1].split("## Rotated")[0]
            self.assertLess(opened.index("c3:ci/github.env"), opened.index("c2:supabase/service.env"))  # newest first
            self.assertTrue("c5:y.env" not in text, 'unexpected: "c5:y.env"')
            self.assertTrue("read-only token, accepted" in text.split("## Accepted")[1],
                            'missing: "read-only token, accepted"')
            self.assertTrue("c4:x.env" not in opened, 'unexpected: "c4:x.env"')
            self.assertEqual(secrets_report.write_dated_copy(out, "2026-11-07"),
                             out / "reports" / "2026-11-07-secrets.md")
            self.assertTrue((out / "reports" / "2026-11-07-secrets.md").read_text(encoding="utf-8") == text,
                            'text differs: (out / "reports" / "2026-11-07-secrets.md").read_text(enc...')


    def test_unknown_age_renders_unknown_and_is_ignored_by_oldest(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            doc = {"generated_at": "2026-11-07T12:00:00+00:00", "engine": {"name": "gitleaks", "version": "8.30.1"},
                   "scan": {"mode": "full", "repos": 1, "failed": [], "skipped_reason": None, "error": None},
                   "findings": [finding("c6:b.env:x:1", cls="B", age_days=None, last_seen="2026-11-07"),
                                finding("c7:a.env:x:1", age_days=None, last_seen="2026-11-07"),
                                finding("c8:a2.env:x:1", age_days=5, last_seen="2026-11-07")]}
            text = secrets_report.render(out, doc, load_classes())
            self.assertTrue("| B (scoped or billable) | 1 | unknown |" in text, "unknown B age not shown as unknown")
            self.assertTrue("| A (full access, rotate now) | 2 | 5 days |" in text, "oldest A ignores None")
            self.assertTrue("age: unknown" in text, "entry age not shown as unknown")
            self.assertTrue("0 days" not in text, "a None age rendered as 0 days")
            built = status.build(status.empty_report(), secrets=doc, previous=None, duration_s=1.0, exit_code=1,
                                 run_host="h", mode="portfolio")
            self.assertEqual(built["secrets_scan"]["oldest_open_days"], 5)

    def test_stored_repo_path_is_relative(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            out = root / "security"
            cfg = config.Config(out=out, root=root, mode="portfolio")
            self.assertEqual(secrets_mod._stored_path(root / "alpha", cfg, out), "alpha")
            self.assertEqual(secrets_mod._stored_path(out / ".cache" / "clones" / "o" / "r.git", cfg, out),
                             ".cache/clones/o/r.git")
            self.assertIsNone(secrets_mod._stored_path(Path(tmp).parent / "elsewhere", cfg, out))


class DecisionsFailureTests(unittest.TestCase):
    """R55 end to end: a malformed decisions file fails the step; no engine needed (it must not run)."""
    run_with = tp.RunTests.run_with
    DECISIONS = '[decisions."fp1"]\nstatus = "bogus"\nnote = "my note"\n'

    def setUp(self):
        present = eng.Engine("/x/gitleaks", "gitleaks", "8.30.1")
        for patch in (mock.patch.object(eng, "find_engine", return_value=present),
                      mock.patch.object(eng, "scan_repo", side_effect=AssertionError("engine must not run"))):
            patch.start()
            self.addCleanup(patch.stop)

    def test_run_exits_2(self):
        def prepare(cfg):
            tp.git_init(cfg.out)
            (cfg.out / store.DECISIONS_FILE).write_text(self.DECISIONS)
        with tempfile.TemporaryDirectory() as tmp:
            rc, cfg = self.run_with(Path(tmp).resolve(), {"return_value": {"results": []}}, before=prepare)
            self.assertEqual(rc, 2)
            text = (cfg.out / "STATUS.md").read_text()
            self.assertTrue("- secrets: FAILED:" in text, "STATUS.md lacks the failed secrets source")
            self.assertTrue("status is missing or unknown" in text, "STATUS.md lacks the reason")
            self.assertTrue("my note" not in text, "a decision note reached STATUS.md")

    def test_secrets_scan_cli_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            out = root / "security"
            config.write_default(out, config.Config(out=out, root=root, mode="portfolio"))
            (out / store.DECISIONS_FILE).write_text(self.DECISIONS)
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                rc = cli.main(["secrets", "scan", "--out", str(out)])
            self.assertEqual(rc, 2)
            self.assertTrue("status is missing or unknown" in err.getvalue(), "stderr lacks the reason")
            self.assertTrue("my note" not in err.getvalue(), "a decision note reached stderr")


@unittest.skipUnless(HAS_GITLEAKS, "gitleaks not installed")
class RunIntegrationTests(unittest.TestCase):
    run_with = tp.RunTests.run_with

    @staticmethod
    def fixture(cfg):
        fx.write_fixture_portfolio(cfg.root)
        cfg.ignore_projects = ["ignored-archive"]
        tp.git_init(cfg.out)

    def test_run_integration_counts_in_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, cfg = self.run_with(Path(tmp).resolve(), {"return_value": {"results": []}}, before=self.fixture)
            self.assertEqual(rc, 0)
            doc = json.loads((cfg.out / "status.json").read_text())
            secrets_doc = store.read(cfg.out)
            planted_a = sum(1 for f in secrets_doc["findings"] if f["class"] == "A" and f["status"] == "open")
            self.assertGreaterEqual(planted_a, sum(1 for p in PLANTED.values() if p.expected_class == "A"))
            self.assertEqual(doc["counts"]["secrets"]["A"], planted_a)
            self.assertEqual(doc["secrets_scan"]["engine"], "gitleaks")
            self.assertEqual(doc["secrets_scan"]["repos"], 3)
            self.assertTrue(any(" | secrets | full | repos 3 | " in line
                                for line in (cfg.out / "log.md").read_text().splitlines()))
            committed = set(tp.git(cfg.out, "show", "--name-only", "--format=", "HEAD").split())
            day = secrets_doc["generated_at"][:10]
            self.assertTrue({"SECRETS.md", "secrets.json", f"reports/{day}-secrets.md"} <= committed, committed)
            self.assertTrue(store.DECISIONS_FILE not in committed, 'unexpected: store.DECISIONS_FILE')
            self.assertTrue(f"{planted_a} class A secrets" in tp.git(cfg.out, "log", "-1", "--format=%s"),
                            'missing: f"{planted_a} class A secrets"')

    def test_run_failed_secrets_repo_exits_2(self):
        def failing(engine, repo, **kwargs):
            if Path(repo).name == "beta-api":
                raise EngineError("gitleaks exit 2: fatal: boom")
            return REAL_SCAN_REPO(engine, repo, **kwargs)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(eng, "scan_repo", failing):
            rc, cfg = self.run_with(Path(tmp).resolve(), {"return_value": {"results": []}}, before=self.fixture)
            self.assertEqual(rc, 2)
            doc = json.loads((cfg.out / "status.json").read_text())
            self.assertEqual(doc["exit_code"], 2)
            text = (cfg.out / "STATUS.md").read_text()
            self.assertTrue("- secrets: FAILED: beta-api: gitleaks exit 2: fatal: boom" in text,
                            'missing: "- secrets: FAILED: beta-api: gitleaks exit 2: fatal: boom"')

    def test_run_with_missing_engine_keeps_exit_code(self):
        no_engine = functools.partial(REAL_FIND_ENGINE, which=lambda name: None)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(eng, "find_engine", no_engine):
            rc, cfg = self.run_with(Path(tmp).resolve(), {"return_value": {"results": []}}, before=self.fixture)
            self.assertEqual(rc, 0)
            text = (cfg.out / "STATUS.md").read_text()
            self.assertTrue("- secrets: skipped (install: brew install gitleaks)" in text,
                            'missing: "- secrets: skipped (install: brew install gitleaks)"')

    def test_run_leaves_audited_repos_untouched(self):
        def snapshot(root: Path) -> dict:
            state = {}
            for repo in sorted(fx.REPOS) + [fx.WORKTREE]:
                path = root / repo
                state[repo] = (_git(path, "status", "--porcelain"), _git(path, "rev-parse", "HEAD"),
                               _git(path, "for-each-ref"),
                               sorted(str(p.relative_to(path)) for p in path.rglob("*")
                                      if ".git" not in p.relative_to(path).parts))
            return state
        with tempfile.TemporaryDirectory() as tmp:
            before = {}

            def prepare(cfg):
                self.fixture(cfg)
                before.update(snapshot(cfg.root))
            rc, cfg = self.run_with(Path(tmp).resolve(), {"return_value": {"results": []}}, before=prepare)
            self.assertEqual(rc, 0)
            self.assertTrue(store.read(cfg.out)["findings"])
            self.assertEqual(snapshot(cfg.root), before)


if __name__ == "__main__":
    unittest.main()
