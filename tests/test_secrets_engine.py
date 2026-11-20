"""Secrets engine wrapper: engine selection, gitleaks argv, raw report hygiene, real scans of the fixture.

Assertions never print a planted value: anything involving `Secret`, `Match`, `value` or `core` is compared
in memory with `assertTrue(..., "fixed message")`.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from sbomaudit import preflight
from sbomaudit.errors import EngineError
from sbomaudit.secrets import engine as eng
from tests import secrets_fixture as fx
from tests.helpers import _git
from tests.secrets_fixture import PLANTED

VALIDATION_OFF = {"BETTERLEAKS_VALIDATE": "false", "BETTERLEAKS_ANALYZE": "false"}


def _which(present: dict[str, str]):
    return lambda name: present.get(name)


def _version_run(versions: dict[str, str]):
    """A `run` stub answering `<binary> version` from a {binary path: version} map."""
    def run(argv, **kwargs):
        assert argv[1:] == ["version"], argv
        return subprocess.CompletedProcess(argv, 0, stdout=versions[argv[0]] + "\n", stderr="")
    return run


def _report_target(argv: list[str]) -> str:
    return argv[argv.index("-r") + 1]


class FindEngineTests(unittest.TestCase):
    def test_find_engine_prefers_gitleaks_8(self):
        which = _which({"gitleaks": "/x/gitleaks", "betterleaks": "/x/betterleaks"})
        run = _version_run({"/x/gitleaks": "8.30.1", "/x/betterleaks": "1.4.0"})
        found = eng.find_engine(which=which, run=run)
        self.assertEqual(found, eng.Engine("/x/gitleaks", "gitleaks", "8.30.1", {}))

    def test_find_engine_accepts_betterleaks_1_with_validation_off(self):
        for name in ("betterleaks", "betterleaks-v1"):
            with self.subTest(name=name):
                which = _which({"gitleaks": "/x/gitleaks", name: f"/x/{name}"})
                run = _version_run({"/x/gitleaks": "7.6.1", f"/x/{name}": "1.2.3"})
                found = eng.find_engine(which=which, run=run)
                self.assertIsInstance(found, eng.Engine)
                self.assertEqual((found.binary, found.name, found.version),
                                 (f"/x/{name}", name, "1.2.3"))
                self.assertEqual(found.env, VALIDATION_OFF)

        # the validation switches reach the engine process
        engine = eng.Engine("/x/betterleaks", "betterleaks", "1.2.3", dict(VALIDATION_OFF))
        seen = {}

        def run(argv, **kwargs):
            seen.update(kwargs)
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            eng.scan_repo(engine, Path(tmp) / "repo", log_opts="--all", ignore_file=None,
                          raw_dir=Path(tmp) / "raw", run=run)
        self.assertEqual({k: seen["env"][k] for k in VALIDATION_OFF}, VALIDATION_OFF)

    def test_find_engine_rejects_betterleaks_2_and_missing(self):
        found = eng.find_engine(which=_which({"betterleaks": "/x/betterleaks"}),
                                run=_version_run({"/x/betterleaks": "2.0.1"}))
        self.assertEqual(found.reason, "unsupported (betterleaks 2.0.1)")
        self.assertIsInstance(found, eng.EngineProblem)

        missing = eng.find_engine(which=_which({}), run=_version_run({}))
        self.assertIsInstance(missing, eng.EngineProblem)
        self.assertEqual(missing.reason, "missing")
        self.assertIn("brew install gitleaks", missing.detail)
        self.assertEqual(preflight.SECRETS_TOOLS, ("gitleaks",))
        self.assertEqual(preflight.SECRETS_INSTALL, "brew install gitleaks")
        self.assertNotIn("gitleaks", preflight.RUN_TOOLS)

        def failing(argv, **kwargs):
            raise OSError("exec format error")

        broken = eng.find_engine(which=_which({"gitleaks": "/x/gitleaks"}), run=failing)
        self.assertEqual(broken.reason, "missing")

        def undecodable(argv, **kwargs):
            self.assertEqual(kwargs.get("errors"), "replace")
            raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

        garbled = eng.find_engine(which=_which({"gitleaks": "/x/gitleaks"}), run=undecodable)
        self.assertEqual(garbled.reason, "missing")


class ScanRepoTests(unittest.TestCase):
    ENGINE = eng.Engine("/x/gitleaks", "gitleaks", "8.30.1", {})

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()
        self.repo = self.tmp / "repo"
        self.raw_dir = self.tmp / ".cache" / "secrets-raw"

    def tearDown(self):
        self._tmp.cleanup()

    def _scan(self, run, ignore_file=None):
        return eng.scan_repo(self.ENGINE, self.repo, log_opts="--all", ignore_file=ignore_file,
                             raw_dir=self.raw_dir, run=run)

    def test_read_rows_tolerates_invalid_utf8_and_rejects_non_lists(self):
        path = self.tmp / "raw.json"
        path.write_bytes(b'[{"RuleID": "x", "Secret": "ab\xff\xfecd", "File": "f"}]')
        rows = eng._read_rows(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["RuleID"], "x")
        self.assertIn("\ufffd", rows[0]["Secret"])
        path.write_text('{"RuleID": "x"}', encoding="utf-8")
        self.assertIsNone(eng._read_rows(path))
        path.write_text("[1, 2]", encoding="utf-8")
        self.assertIsNone(eng._read_rows(path))
        self.assertIsNone(eng._read_rows(self.tmp / "missing.json"))

    def _assert_argv(self, argv, kwargs, ignore_file=None):
        for part in ("git", "--no-banner", "--no-color", "-c", str(eng.RULES_PATH), "-f", "json", "-r",
                     "--exit-code", "1", "--log-opts", str(self.repo)):
            self.assertIn(part, argv)
        self.assertEqual(argv[0], "/x/gitleaks")
        self.assertEqual(argv[argv.index("-f") + 1], "json")
        self.assertEqual(argv[argv.index("--exit-code") + 1], "1")
        self.assertEqual(argv[argv.index("-c") + 1], str(eng.RULES_PATH))
        for forbidden in ("--platform", "--diagnostics", "--redact"):
            self.assertNotIn(forbidden, argv)
        if ignore_file is None:
            self.assertNotIn("-i", argv)
        else:
            self.assertEqual(argv[argv.index("-i") + 1], str(ignore_file))
        # no textconv or external diff driver from the repository runs inside gitleaks' `git log -p`
        self.assertEqual(argv[argv.index("--log-opts") + 1], "--no-textconv --no-ext-diff --all")
        self.assertEqual(kwargs["env"].get("GIT_CONFIG_KEY_1"), "core.hooksPath")
        self.assertEqual(Path(kwargs["cwd"]), self.raw_dir)
        self.assertTrue(kwargs.get("capture_output"))
        self.assertEqual(kwargs.get("umask"), 0o077)

    def _assert_raw_dir_empty(self):
        self.assertEqual(list(self.raw_dir.iterdir()), [])

    def test_exit_one_without_report_is_failure_not_clean(self):
        calls = []

        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="")

        with self.assertRaises(EngineError) as ctx:
            self._scan(run)
        self.assertIn("without a parsable report", ctx.exception.detail)
        self._assert_argv(*calls[0])

        def other_exit(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 126, stdout="", stderr="config error\nmore\n")

        with self.assertRaises(EngineError) as ctx:
            self._scan(other_exit)
        self.assertEqual(ctx.exception.detail, "gitleaks exit 126: config error")

        def timeout(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout"))

        with self.assertRaises(EngineError) as ctx:
            self._scan(timeout)
        self.assertEqual(ctx.exception.detail, "timed out")

        def clean(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        self.assertEqual(self._scan(clean), [])
        self._assert_raw_dir_empty()

        def left_empty(argv, **kwargs):  # gitleaks' log.Fatal path: nothing on stdout
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="")

        with self.assertRaises(EngineError) as ctx:
            self._scan(left_empty)
        self.assertIn("without a parsable report", ctx.exception.detail)
        self._assert_raw_dir_empty()

        for code in (0, 1):
            with self.subTest(exit=code):
                def empty_array(argv, **kwargs):
                    return subprocess.CompletedProcess(argv, code, stdout="[]", stderr="")

                self.assertEqual(self._scan(empty_array), [])
                self._assert_raw_dir_empty()

        def cannot_start(argv, **kwargs):
            raise FileNotFoundError(2, "No such file or directory")

        with self.assertRaises(EngineError) as ctx:
            self._scan(cannot_start)
        self.assertIn("could not start", ctx.exception.detail)
        self._assert_raw_dir_empty()

    def test_exit_zero_with_git_error_on_stderr_is_failure(self):
        stderr = ("10:08PM ERR [git] fatal: bad object " + "0" * 40 + "\n"
                  "10:08PM ERR error=\"stderr is not empty\"\n10:08PM INF 0 commits scanned.\n")

        def swallowed(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, stdout="[]", stderr=stderr)

        with self.assertRaises(EngineError) as ctx:
            self._scan(swallowed)
        self.assertEqual(ctx.exception.detail, "ERR [git] fatal: bad object " + "0" * 40)
        self._assert_raw_dir_empty()

        for prefix in ("2026-11-07T10:08:00Z ", "\x1b[90m10:08PM\x1b[0m ", ""):
            with self.subTest(prefix=prefix):
                def fatal(argv, **kwargs):
                    return subprocess.CompletedProcess(argv, 0, stdout="",
                                                       stderr=f"{prefix}FTL something broke\n")

                with self.assertRaises(EngineError) as ctx:
                    self._scan(fatal)
                self.assertTrue(ctx.exception.detail.endswith("something broke"))
                self.assertTrue(ctx.exception.detail.startswith("FTL"))
                self._assert_raw_dir_empty()

        def info_only(argv, **kwargs):
            return subprocess.CompletedProcess(
                argv, 0, stdout="",
                stderr="10:08PM INF 3 commits scanned.\n10:08PM INF scanned ~10 bytes\n10:08PM INF no leaks found\n")

        self.assertEqual(self._scan(info_only), [])
        self._assert_raw_dir_empty()

    def test_other_exit_detail_prefers_the_error_line(self):
        def run(argv, **kwargs):
            return subprocess.CompletedProcess(
                argv, 2, stdout="", stderr="10:08PM INF starting\n10:08PM FTL failed to load config\n")

        with self.assertRaises(EngineError) as ctx:
            self._scan(run)
        self.assertEqual(ctx.exception.detail, "gitleaks exit 2: FTL failed to load config")
        self._assert_raw_dir_empty()

    def test_relative_paths_are_made_absolute(self):
        calls = []

        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        cwd = os.getcwd()
        os.chdir(self.tmp)
        try:
            eng.scan_repo(self.ENGINE, Path("repo"), log_opts="--all", ignore_file=Path("ignore"),
                          raw_dir=Path(".cache/secrets-raw"), run=run)
        finally:
            os.chdir(cwd)
        argv, kwargs = calls[0]
        self.assertEqual(argv[-1], str(self.repo))
        self.assertEqual(argv[argv.index("-i") + 1], str(self.tmp / "ignore"))
        self.assertEqual(_report_target(argv), "-")
        self.assertEqual(Path(kwargs["cwd"]), self.raw_dir)

    def test_raw_report_never_touches_disk(self):
        rows = [{"RuleID": "fixture-rule", "Commit": "abc", "File": "a.env", "StartLine": 1}]
        calls = []
        ignore = self.tmp / "ignore"
        ignore.write_text("")

        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            self.assertEqual(_report_target(argv), "-")           # the report goes to the pipe
            self.assertEqual(list(self.raw_dir.iterdir()), [])     # no file next to gitleaks
            return subprocess.CompletedProcess(argv, 1, stdout=json.dumps(rows), stderr="")

        self.assertEqual(self._scan(run, ignore_file=ignore), rows)
        self._assert_argv(*calls[0], ignore_file=ignore)
        self.assertEqual(stat.S_IMODE(os.stat(self.raw_dir).st_mode), 0o700)
        self.assertEqual(list(self.raw_dir.iterdir()), [])

        def failing(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 2, stdout=json.dumps(rows), stderr="")

        with self.assertRaises(EngineError):
            self._scan(failing)
        self.assertEqual(list(self.raw_dir.iterdir()), [])

    def test_stale_raw_reports_are_deleted_before_a_scan(self):
        self.raw_dir.mkdir(parents=True)
        stale = self.raw_dir / "tmpleftover.json"           # a report left by a killed older version
        stale.write_text('[{"Secret": "FAKE-NOT-A-SECRET"}]')
        (self.raw_dir / "sub").mkdir()
        (self.raw_dir / "sub" / "x.json").write_text("[]")
        seen = []

        def run(argv, **kwargs):
            seen.append(sorted(p.name for p in self.raw_dir.iterdir()))
            return subprocess.CompletedProcess(argv, 0, stdout="[]", stderr="")

        self.assertEqual(self._scan(run), [])
        self.assertEqual(seen, [[]])
        self.assertEqual(list(self.raw_dir.iterdir()), [])

    def test_gitleaks_gets_its_own_timeout(self):
        calls = []

        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, stdout="[]", stderr="")

        self._scan(run)
        argv, kwargs = calls[0]
        self.assertEqual(argv[argv.index("--timeout") + 1], str(eng.SCAN_TIMEOUT))
        self.assertEqual(kwargs["timeout"], eng.SCAN_TIMEOUT + eng.KILL_GRACE)


class ProcessGroupTests(unittest.TestCase):
    """The engine runs in its own process group; a timeout, an exception or SIGTERM kills the whole group."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()

    def tearDown(self):
        self._tmp.cleanup()

    def _wait_for(self, path: Path, seconds: float = 10) -> None:
        deadline = time.monotonic() + seconds
        while not (path.exists() and path.read_text().strip()):
            if time.monotonic() > deadline:
                self.fail(f"{path.name} never appeared")
            time.sleep(0.05)

    def _alive(self, pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True

    def _gone(self, pid: int, seconds: float = 5) -> bool:
        deadline = time.monotonic() + seconds
        while self._alive(pid):
            if time.monotonic() > deadline:
                return False
            time.sleep(0.05)
        return True

    def test_timeout_kills_the_grandchild_too(self):
        pidfile = self.tmp / "pid"
        script = f"sleep 30 & echo $! > {pidfile}; wait"
        with self.assertRaises(subprocess.TimeoutExpired):
            eng.run_engine(["sh", "-c", script], capture_output=True, text=True, timeout=1)
        pid = int(pidfile.read_text())
        self.assertTrue(self._gone(pid), "the engine's child survived the timeout")

    def test_sigterm_kills_the_engine_group_and_leaves_no_raw_file(self):
        pidfile = self.tmp / "pid"
        fake = self.tmp / "fakeleaks.sh"
        fake.write_text("#!/bin/sh\n"
                        "echo '[{\"Secret\":\"FAKE-NOT-A-SECRET\"}]'\n"
                        f"sleep 30 & echo $! > {pidfile}; wait\n")
        fake.chmod(0o700)
        raw_dir = self.tmp / "raw"
        code = ("import sys; from pathlib import Path; from sbomaudit.secrets import engine as e; "
                f"e.scan_repo(e.Engine({str(fake)!r}, 'gitleaks', '8.30.1'), Path({str(self.tmp)!r}), "
                f"log_opts='--all', ignore_file=None, raw_dir=Path({str(raw_dir)!r}))")
        scripts = str(Path(eng.__file__).resolve().parents[2])
        child = subprocess.Popen([sys.executable, "-c", code], env={**os.environ, "PYTHONPATH": scripts},
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            self._wait_for(pidfile)
            child.send_signal(signal.SIGTERM)
            child.wait(timeout=10)
        finally:
            if child.poll() is None:
                child.kill()
        self.assertNotEqual(child.returncode, 0)
        self.assertTrue(self._gone(int(pidfile.read_text())), "the engine's child survived SIGTERM")
        self.assertEqual(list(raw_dir.iterdir()), [])

    def test_log_opts_forms(self):
        self.assertEqual(eng.log_opts_full(), "--all")
        self.assertEqual(eng.log_opts_since(["a", "b"]), "--all ^a ^b")

    def test_rules_path_is_the_plugin_rules_file(self):
        self.assertEqual(eng.RULES_PATH, Path(__file__).resolve().parent.parent / "plugin" / "secrets" / "gitleaks.toml")
        self.assertTrue(eng.RULES_PATH.is_file())


def _expected_secret(key: str) -> str:
    planted = PLANTED[key]
    return planted.core if key == "database-url-password" else planted.value


@unittest.skipUnless(shutil.which("gitleaks"), "gitleaks not installed")
class RealGitleaksTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = fx.write_fixture_portfolio(Path(self._tmp.name).resolve())
        self.raw_dir = self.root / "security" / ".cache" / "secrets-raw"
        found = eng.find_engine()
        self.assertIsInstance(found, eng.Engine)
        self.engine = found

    def tearDown(self):
        self._tmp.cleanup()

    def _scan(self, repo: Path, log_opts: str, run=subprocess.run) -> list[dict]:
        return eng.scan_repo(self.engine, repo, log_opts=log_opts, ignore_file=None, raw_dir=self.raw_dir,
                             run=run)

    def test_real_gitleaks_finds_every_planted_value(self):
        modes = []

        def checking_run(argv, **kwargs):  # the report comes through the pipe, never a file
            self.assertEqual(_report_target(argv), "-")
            proc = subprocess.run(argv, **kwargs)
            modes.append(list(self.raw_dir.iterdir()))
            return proc

        self.assertEqual(set(fx.REPOS), {"alpha-app", "beta-api", "ignored-archive"})
        for repo, keys in fx.REPOS.items():
            with self.subTest(repo=repo):
                rows = self._scan(self.root / repo, eng.log_opts_full(), run=checking_run)
                rule_ids = {row["RuleID"] for row in rows}
                missing_rules = sorted({PLANTED[k].rule_id for k in keys} - rule_ids)
                self.assertEqual(missing_rules, [])
                for key in keys:
                    expected = _expected_secret(key)
                    hit = any(row["RuleID"] == PLANTED[key].rule_id and row["Secret"] == expected
                              for row in rows)
                    self.assertTrue(hit, f"secret mismatch for {key}")
                self.assertEqual(list(self.raw_dir.iterdir()), [])
                if repo == "alpha-app":  # the allowlist targets the captured secret: `password` is dropped
                    self.assertEqual([row["File"] for row in rows if row["File"] == fx.PLACEHOLDER_FILE], [])
        self.assertIn(fx.BRANCH_ONLY, fx.REPOS["beta-api"])
        self.assertIn("supabase-jwt-secret-example-name", fx.REPOS["beta-api"])  # ...but a key name does not hide
        self.assertEqual(modes, [[]] * len(fx.REPOS))

    def test_real_gitleaks_runs_no_diff_driver_from_repository_config(self):
        repo = self.root / "alpha-app"
        baseline = self._scan(repo, eng.log_opts_full())
        self.assertTrue(baseline)
        marker = Path(self._tmp.name) / "DRIVER_RAN"
        (repo / ".git" / "info").mkdir(exist_ok=True)
        (repo / ".git" / "info" / "attributes").write_text("* diff=evil\n")
        _git(repo, "config", "diff.evil.textconv", f"sh -c 'touch {marker}; true' --")
        _git(repo, "config", "diff.external", f"sh -c 'touch {marker}; true' --")
        rows = self._scan(repo, eng.log_opts_full())
        self.assertFalse(marker.exists(), "a repository diff driver ran")
        self.assertEqual(len(rows), len(baseline))

    def test_real_gitleaks_vanished_tip_is_failure_not_clean(self):
        with self.assertRaises(EngineError) as ctx:
            self._scan(self.root / "alpha-app", eng.log_opts_since(["0" * 40]))
        self.assertIn("[git] fatal", ctx.exception.detail)
        self.assertEqual(list(self.raw_dir.iterdir()), [])

    def test_real_gitleaks_incremental_range_scans_only_new_commit(self):
        repo = self.root / "beta-api"
        full = self._scan(repo, eng.log_opts_full())
        tips = _git(repo, "for-each-ref", "--format=%(objectname)").split()
        self.assertTrue(tips)

        key = "github-pat"
        (repo / "ci" / "later.env").write_text(fx.LINES[key].format(v=PLANTED[key].value))
        _git(repo, "add", "ci/later.env")
        _git(repo, "commit", "-q", "-m", "add later token")
        new_sha = _git(repo, "rev-parse", "HEAD").strip()

        rows = self._scan(repo, eng.log_opts_since(tips))
        self.assertGreaterEqual(len(rows), 1)
        self.assertLess(len(rows), len(full))
        self.assertEqual({row["Commit"] for row in rows}, {new_sha})
        hit = any(row["File"] == "ci/later.env" and row["Secret"] == PLANTED[key].value for row in rows)
        self.assertTrue(hit, f"secret mismatch for {key}")
        self.assertEqual(list(self.raw_dir.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
