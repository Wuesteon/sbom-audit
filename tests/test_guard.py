"""Pre-commit guard: config-dir sync, framework detection, installer, the installed guard script, setup flags.

The installed guard (`templates/guard/guard.py`) is run as a real subprocess against a staged planted
secret. Assertions use fixed messages: a failure must never print guard output that could hold a value.
"""
from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import __version__, cli, config, pipeline, setup
from sbomaudit.secrets import classify, guard
from sbomaudit.secrets.findings import assert_redacted
from tests import secrets_fixture as fx
from tests.helpers import _git, make_repo

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
GUARD_TEMPLATE = PLUGIN_ROOT / "templates" / "guard" / "guard.py"
PLANTED = list(fx.PLANTED.values())
ALL_PRESENT = lambda tool: f"/usr/local/bin/{tool}"  # noqa: E731


def load_guard_module():
    spec = importlib.util.spec_from_file_location("installed_guard", GUARD_TEMPLATE)
    assert spec and spec.loader, "templates/guard/guard.py not found"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stage(repo: Path, keys: list[str]) -> None:
    for key in keys:
        item = fx.PLANTED[key]
        path = repo / item.file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(fx.LINES[key].format(v=item.value))
        _git(repo, "add", item.file)


class GuardTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name).resolve()
        empty = self.tmp / "gitconfig-global"
        empty.write_text("")
        self.global_config = empty
        env = mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(empty), "GIT_CONFIG_NOSYSTEM": "1",
                                           "XDG_CONFIG_HOME": str(self.tmp / "config")})
        env.start()
        self.addCleanup(env.stop)
        self.cfg_dir = self.tmp / "config" / "sbom-audit"

    def run_guard(self, repo: Path, path_env: str | None = None, python: str = sys.executable):
        tmpdir = self.tmp / "guard-tmp"
        tmpdir.mkdir(exist_ok=True)
        env = dict(os.environ, TMPDIR=str(tmpdir))
        if path_env is not None:
            env["PATH"] = path_env
        started = time.monotonic()
        proc = subprocess.run([python, str(self.cfg_dir / "guard.py")], cwd=repo, env=env,
                              capture_output=True, text=True, timeout=60)
        return proc, time.monotonic() - started, tmpdir


def yaml_single_quoted(line: str, key: str) -> str:
    """The value of `<key>: '<value>'` on one line, unquoted (YAML single-quoted scalar)."""
    value = line.split(f"{key}: ", 1)[1].rstrip("\n")
    assert value.startswith("'") and value.endswith("'"), "not a single-quoted YAML scalar"
    inner = value[1:-1]
    assert "'" not in inner.replace("''", ""), "unescaped quote inside a single-quoted YAML scalar"
    return inner.replace("''", "'")


class SyncTests(GuardTestCase):
    def test_sync_config_dir_writes_header_and_refreshes_on_version_change(self):
        written = guard.sync_config_dir(self.cfg_dir, PLUGIN_ROOT)
        self.assertEqual(sorted(p.name for p in written), ["classes.toml", "gitleaks.toml", "guard.py"])
        header = f"# sbom-audit {__version__}"
        guard_lines = (self.cfg_dir / "guard.py").read_text().splitlines()
        self.assertTrue(guard_lines[0].startswith("#!"), "shebang must stay the first line")
        self.assertEqual(guard_lines[1], header)
        self.assertEqual((self.cfg_dir / "classes.toml").read_text().splitlines()[0], header)
        self.assertEqual(guard.sync_config_dir(self.cfg_dir, PLUGIN_ROOT), [])
        stale = self.cfg_dir / "gitleaks.toml"
        stale.write_text("# sbom-audit 0.0.1\nold\n")
        self.assertEqual(guard.sync_config_dir(self.cfg_dir, PLUGIN_ROOT), [stale])
        self.assertEqual(stale.read_text().splitlines()[0], header)
        self.assertIn("[[rules]]", stale.read_text())


    def test_refresh_installed_only_touches_an_existing_guard(self):
        self.assertEqual(guard.refresh_installed(self.cfg_dir, PLUGIN_ROOT), [])
        self.assertFalse(self.cfg_dir.exists(), "run must not create the config dir")
        guard.sync_config_dir(self.cfg_dir, PLUGIN_ROOT)
        stale = self.cfg_dir / "guard.py"
        stale.write_text("#!/usr/bin/env python3\n# sbom-audit 0.0.1\n")
        self.assertEqual(guard.refresh_installed(self.cfg_dir, PLUGIN_ROOT), [stale])

    def test_pipeline_guard_refresh_step_honours_secrets_enabled(self):
        guard.sync_config_dir(self.cfg_dir, PLUGIN_ROOT)
        stale = self.cfg_dir / "classes.toml"
        stale.write_text("# sbom-audit 0.0.1\n")
        cfg = config.Config(out=self.tmp / "security", root=self.tmp, mode="portfolio")
        said = []
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.tmp / "config")}):
            cfg.secrets.enabled = False
            pipeline.guard_refresh_step(cfg, said.append)
            self.assertEqual(stale.read_text(), "# sbom-audit 0.0.1\n")
            cfg.secrets.enabled = True
            pipeline.guard_refresh_step(cfg, said.append)
        self.assertEqual(stale.read_text().splitlines()[0], f"# sbom-audit {__version__}")
        self.assertEqual(said, [f"guard: refreshed classes.toml in {self.cfg_dir}"])


class DetectTests(GuardTestCase):
    def test_detect_kinds(self):
        plain = make_repo(self.tmp, "plain", {"README.md": "x\n"})
        hooks = make_repo(self.tmp, "hooks", {"README.md": "x\n"})
        _git(hooks, "config", "core.hooksPath", ".git/custom-hooks")
        husky = make_repo(self.tmp, "husky", {".husky/pre-commit": "npm test\n"})
        _git(husky, "config", "core.hooksPath", ".husky/_")
        husky_files = make_repo(self.tmp, "husky-files", {".husky/pre-commit": "npm test\n"})
        lefthook = make_repo(self.tmp, "lefthook", {"lefthook.yml": "pre-commit:\n  commands: {}\n"})
        dot_lefthook = make_repo(self.tmp, "dot-lefthook", {".lefthook.yml": "pre-push:\n"})
        framework = make_repo(self.tmp, "framework", {".pre-commit-config.yaml": "repos: []\n"})
        shared = make_repo(self.tmp, "shared", {"githooks/pre-commit": "#!/bin/sh\n"})
        _git(shared, "config", "core.hooksPath", "githooks")

        got = {name: guard.detect(repo) for name, repo in (
            ("plain", plain), ("hooks", hooks), ("husky", husky), ("husky-files", husky_files),
            ("lefthook", lefthook), ("dot-lefthook", dot_lefthook), ("framework", framework),
            ("shared", shared))}
        self.assertEqual({k: d.kind for k, d in got.items()}, {
            "plain": "plain", "hooks": "hookspath", "husky": "husky", "husky-files": "husky",
            "lefthook": "lefthook", "dot-lefthook": "lefthook", "framework": "pre-commit-framework",
            "shared": "hookspath"})
        self.assertEqual(got["plain"].hook_path, plain / ".git" / "hooks" / "pre-commit")
        self.assertEqual(got["hooks"].hook_path, hooks / ".git" / "custom-hooks" / "pre-commit")
        self.assertEqual(got["husky"].hook_path, husky / ".husky" / "pre-commit")
        self.assertEqual(got["lefthook"].hook_path, lefthook / "lefthook.yml")
        self.assertEqual(got["dot-lefthook"].hook_path, dot_lefthook / ".lefthook.yml")
        self.assertEqual(got["framework"].hook_path, framework / ".pre-commit-config.yaml")
        self.assertEqual(got["shared"].hook_path, shared / "githooks" / "pre-commit")
        self.assertFalse(got["plain"].tracked or got["hooks"].tracked, "hooks inside .git are untracked")
        self.assertTrue(got["shared"].tracked and got["husky"].tracked, "hooks outside .git need --tracked-ok")


    def test_global_hookspath_is_reported_never_edited(self):
        shared = self.tmp / "global-hooks"
        self.global_config.write_text(f"[core]\n\thooksPath = {shared}\n")
        repo = make_repo(self.tmp, "app", {"README.md": "x\n"})
        det = guard.detect(repo)
        self.assertEqual((det.kind, det.origin), ("hookspath", "global"))
        expected = f"global core.hooksPath {shared}: install by hand"
        self.assertEqual(guard.install(repo, self.cfg_dir, tracked_ok=True), expected)
        self.assertEqual(guard.install(repo, self.cfg_dir, tracked_ok=False), expected)
        self.assertFalse(shared.exists(), "a global hooks dir must never be written")
        local = make_repo(self.tmp, "local-wins", {"README.md": "x\n"})
        _git(local, "config", "core.hooksPath", ".git/own-hooks")
        self.assertEqual((guard.detect(local).kind, guard.detect(local).origin), ("hookspath", "local"))


class InstallTests(GuardTestCase):
    def test_install_plain_chains_existing_hook_and_is_idempotent(self):
        repo = make_repo(self.tmp, "app", {"README.md": "x\n"})
        hook = repo / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\necho mine\n")
        hook.chmod(0o755)
        line = guard.install(repo, self.cfg_dir, tracked_ok=False)
        self.assertIn("installed", line)
        local = hook.with_name("pre-commit.local")
        self.assertEqual(local.read_text(), "#!/bin/sh\necho mine\n")
        text = hook.read_text()
        self.assertIn(guard.MARKER, text)
        self.assertIn("pre-commit.local", text)
        self.assertIn(str(self.cfg_dir / "guard.py"), text)
        self.assertEqual(hook.stat().st_mode & 0o777, 0o755)
        self.assertIn("unchanged", guard.install(repo, self.cfg_dir, tracked_ok=False))
        self.assertEqual(hook.read_text(), text)
        self.assertEqual(local.read_text(), "#!/bin/sh\necho mine\n")
        self.assertEqual(_git(repo, "status", "--porcelain"), "", "the working tree must stay clean")

    def test_install_plain_hook_runs_guard_then_local_hook(self):
        repo = make_repo(self.tmp, "app", {"README.md": "x\n"})
        hook = repo / ".git" / "hooks" / "pre-commit"
        marker = self.tmp / "local-ran"
        hook.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
        hook.chmod(0o755)
        guard.sync_config_dir(self.cfg_dir, PLUGIN_ROOT)
        guard.install(repo, self.cfg_dir, tracked_ok=False)
        (repo / "notes.txt").write_text("hello\n")
        _git(repo, "add", "notes.txt")
        _git(repo, "commit", "-q", "-m", "clean commit")
        self.assertTrue(marker.exists(), "the chained pre-commit.local did not run")

    def test_install_framework_requires_tracked_ok(self):
        repo = make_repo(self.tmp, "web", {".husky/pre-commit": "npm test\n"})
        before = (repo / ".husky" / "pre-commit").read_text()
        line = guard.install(repo, self.cfg_dir, tracked_ok=False)
        self.assertEqual(line, f"needs confirmation (husky): add  {guard.TRACKED_LINE}  to .husky/pre-commit; "
                               f"{guard.HUSKY_INACTIVE}")
        self.assertEqual((repo / ".husky" / "pre-commit").read_text(), before)
        guard.install(repo, self.cfg_dir, tracked_ok=True)
        guard.install(repo, self.cfg_dir, tracked_ok=True)
        after = (repo / ".husky" / "pre-commit").read_text()
        self.assertEqual(after, before + guard.TRACKED_LINE + "\n")
        self.assertNotIn(str(self.tmp), after, "a tracked file must never hold a machine-specific path")
        _git(repo, "config", "core.hooksPath", ".husky/_")
        other = make_repo(self.tmp, "web2", {".husky/pre-commit": "npm test\n"})
        _git(other, "config", "core.hooksPath", ".husky/_")
        self.assertEqual(guard.install(other, self.cfg_dir, tracked_ok=True), "guard line added to .husky/pre-commit")

    def test_husky_line_goes_before_a_trailing_exit_or_is_refused(self):
        trailing = make_repo(self.tmp, "trailing", {".husky/pre-commit": "#!/bin/sh\nnpm test\nexec lint-staged\n"})
        guard.install(trailing, self.cfg_dir, tracked_ok=True)
        self.assertEqual((trailing / ".husky" / "pre-commit").read_text(),
                         f"#!/bin/sh\nnpm test\n{guard.TRACKED_LINE}\nexec lint-staged\n")
        nested = "if [ -n \"$CI\" ]; then\n  exit 0\nfi\nnpm test\n"
        unsafe = make_repo(self.tmp, "unsafe", {".husky/pre-commit": nested})
        line = guard.install(unsafe, self.cfg_dir, tracked_ok=True)
        self.assertTrue(line.startswith("not changed: .husky/pre-commit"), line)
        self.assertIn("by hand", line)
        self.assertEqual((unsafe / ".husky" / "pre-commit").read_text(), nested)

    def test_invalid_utf8_tracked_hook_is_refused_not_crashed(self):
        repo = make_repo(self.tmp, "binary", {"README.md": "x\n"})
        hook = repo / ".husky" / "pre-commit"
        hook.parent.mkdir()
        hook.write_bytes(b"npm test \xff\xfe\n")
        line = guard.install(repo, self.cfg_dir, tracked_ok=True)
        self.assertTrue(line.startswith("not changed: .husky/pre-commit is not valid UTF-8"), line)
        self.assertEqual(hook.read_bytes(), b"npm test \xff\xfe\n")

    def test_tracked_lines_allow_without_guard_and_block_with_failing_guard(self):
        husky = make_repo(self.tmp, "husky", {".husky/pre-commit": "true\n"})
        lefthook = make_repo(self.tmp, "lh", {"lefthook.yml": "pre-push:\n  commands: {}\n"})
        framework = make_repo(self.tmp, "fw", {".pre-commit-config.yaml": "repos:\n"})
        for repo in (husky, lefthook, framework):
            guard.install(repo, self.cfg_dir, tracked_ok=True)
        with (husky / ".husky" / "pre-commit").open("a") as fh:
            fh.write("echo after-guard\n")    # the guard line is no longer the last statement
        run_line = next(l for l in (lefthook / "lefthook.yml").read_text().splitlines() if "run: " in l)
        entry = next(l for l in (framework / ".pre-commit-config.yaml").read_text().splitlines() if "entry: " in l)
        commands = {"husky": ["sh", str(husky / ".husky" / "pre-commit")],
                    "lefthook": ["sh", "-c", yaml_single_quoted(run_line, "run")],
                    "pre-commit": shlex.split(yaml_single_quoted(entry, "entry"))}
        self.assertEqual(commands["pre-commit"][:2], ["sh", "-c"])
        absent = self.tmp / "absent-config"
        failing = self.tmp / "failing-config"
        (failing / "sbom-audit").mkdir(parents=True)
        (failing / "sbom-audit" / "guard.py").write_text("import sys\nprint('BLOCKED A x f:1')\nsys.exit(1)\n")
        for name, argv in commands.items():
            proc = subprocess.run(argv, env=dict(os.environ, XDG_CONFIG_HOME=str(absent)), capture_output=True,
                                  text=True)
            self.assertEqual(proc.returncode, 0, name)
            notice = [l for l in proc.stdout.splitlines() if "sbom-audit guard" in l]
            self.assertEqual(len(notice), 1, name)
            self.assertIn("sbom-audit guard: not installed on this machine", notice[0])
            self.assertIn("commit allowed", notice[0])
            proc = subprocess.run(argv, env=dict(os.environ, XDG_CONFIG_HOME=str(failing)), capture_output=True,
                                  text=True)
            self.assertEqual(proc.returncode, 1, name)
            self.assertNotIn("after-guard", proc.stdout, name)

    def test_tracked_line_without_python3_allows_commit(self):
        present = self.tmp / "present-config"
        (present / "sbom-audit").mkdir(parents=True)
        (present / "sbom-audit" / "guard.py").write_text("import sys\nsys.exit(1)\n")   # would block if it ran
        bin_dir = self.tmp / "no-python-bin"
        bin_dir.mkdir()
        for tool in ("sh", "echo"):
            os.symlink(shutil.which(tool), bin_dir / tool)
        env = {"PATH": str(bin_dir), "XDG_CONFIG_HOME": str(present), "HOME": str(self.tmp)}
        proc = subprocess.run(["/bin/sh", "-c", guard.TRACKED_LINE], env=env, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, "sbom-audit guard: python3 not found; commit allowed\n")
        self.assertNotIn("'", guard.TRACKED_LINE, "the pre-commit framework wraps the line in single quotes")

    def test_untracked_hook_uses_home_relative_guard_path(self):
        home = self.tmp / "home"
        cfg_dir = home / ".config" / "sbom-audit"
        repo = make_repo(self.tmp, "app", {"README.md": "x\n"})
        with mock.patch.dict(os.environ, {"HOME": str(home)}):
            guard.install(repo, cfg_dir, tracked_ok=False)
        text = (repo / ".git" / "hooks" / "pre-commit").read_text()
        self.assertIn('python3 "$HOME/.config/sbom-audit/guard.py"', text)
        self.assertNotIn(str(home), text)

    def test_install_uses_the_given_plugin_root_template(self):
        root = self.tmp / "plugin"
        (root / "templates" / "guard").mkdir(parents=True)
        (root / "templates" / "guard" / "pre-commit.sh").write_text(f"#!/bin/sh\n{guard.MARKER}\n# @GUARD@\n")
        repo = make_repo(self.tmp, "app", {"README.md": "x\n"})
        guard.install(repo, self.cfg_dir, tracked_ok=False, plugin_root=root)
        self.assertEqual((repo / ".git" / "hooks" / "pre-commit").read_text(),
                         f"#!/bin/sh\n{guard.MARKER}\n# {self.cfg_dir / 'guard.py'}\n")

    def test_install_lefthook_and_pre_commit_framework_insert_once(self):
        lefthook = make_repo(self.tmp, "lh", {"lefthook.yml": "pre-commit:\n  parallel: true\n  commands:\n"
                                                             "    lint:\n      run: npm run lint\n"
                                                             "pre-push:\n  commands: {}\n"})
        framework = make_repo(self.tmp, "fw", {".pre-commit-config.yaml":
                                               "repos:\n-   repo: https://github.com/psf/black\n"
                                               "    rev: 24.1.0\n    hooks:\n    -   id: black\n"
                                               "default_stages: [pre-commit]\n"})
        for repo in (lefthook, framework):
            self.assertIn("needs confirmation", guard.install(repo, self.cfg_dir, tracked_ok=False))
            guard.install(repo, self.cfg_dir, tracked_ok=True)
            self.assertIn("unchanged", guard.install(repo, self.cfg_dir, tracked_ok=True))
        lh = (lefthook / "lefthook.yml").read_text()
        self.assertEqual(lh.count("sbom-audit-guard"), 1)
        self.assertIn(f"  commands:\n    sbom-audit-guard:\n      run: '{guard.TRACKED_LINE}'\n", lh)
        self.assertTrue(lh.endswith("pre-push:\n  commands: {}\n"), "pre-push must stay untouched")
        fw = (framework / ".pre-commit-config.yaml").read_text()
        self.assertEqual(fw.count("id: sbom-audit-guard"), 1)
        self.assertIn("- repo: local\n  hooks:\n  - id: sbom-audit-guard\n", fw)
        self.assertIn("    stages: [pre-commit]\n", fw)
        self.assertLess(fw.index("repo: local"), fw.index("default_stages"))
        self.assertNotIn(str(self.tmp), lh + fw, "a tracked file must never hold a machine-specific path")

    def test_framework_confirmation_shows_a_pasteable_yaml_block(self):
        framework = make_repo(self.tmp, "fw", {".pre-commit-config.yaml": "repos:\n"})
        lines = guard.install(framework, self.cfg_dir, tracked_ok=False).splitlines()
        self.assertEqual(lines[0], "needs confirmation (pre-commit-framework): add this block to "
                                   ".pre-commit-config.yaml under repos:")
        self.assertEqual(lines[1:4], ["- repo: local", "  hooks:", "  - id: sbom-audit-guard"])
        entry = next(l for l in lines if l.lstrip().startswith("entry: "))
        self.assertEqual(yaml_single_quoted(entry, "entry"), f"sh -c '{guard.TRACKED_LINE}'")
        lefthook = make_repo(self.tmp, "lh", {"lefthook.yml": "pre-push:\n"})
        lines = guard.install(lefthook, self.cfg_dir, tracked_ok=False).splitlines()
        self.assertEqual(lines[1:4], ["pre-commit:", "  commands:", "    sbom-audit-guard:"])

    def test_uninstall_restores_local_hook(self):
        repo = make_repo(self.tmp, "app", {"README.md": "x\n"})
        hook = repo / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\necho mine\n")
        hook.chmod(0o755)
        guard.install(repo, self.cfg_dir, tracked_ok=False)
        self.assertIn("restored", guard.uninstall(repo))
        self.assertEqual(hook.read_text(), "#!/bin/sh\necho mine\n")
        self.assertFalse(hook.with_name("pre-commit.local").exists())
        self.assertIn("not installed", guard.uninstall(repo))
        bare = make_repo(self.tmp, "bare-hooks", {"README.md": "x\n"})
        guard.install(bare, self.cfg_dir, tracked_ok=False)
        self.assertIn("removed", guard.uninstall(bare))
        self.assertFalse((bare / ".git" / "hooks" / "pre-commit").exists())


class InstalledGuardTests(GuardTestCase):
    def setUp(self):
        super().setUp()
        guard.sync_config_dir(self.cfg_dir, PLUGIN_ROOT)

    @unittest.skipUnless(shutil.which("gitleaks"), "gitleaks not installed")
    def test_guard_blocks_class_a_and_b_prints_no_value(self):
        repo = make_repo(self.tmp, "app", {"README.md": "x\n"})
        stage(repo, ["jwt-service-role", "jwt-other"])
        proc, elapsed, tmpdir = self.run_guard(repo)
        printed = proc.stdout + proc.stderr
        self.assertEqual(assert_redacted(printed, PLANTED), [], "the guard printed a planted value or window")
        self.assertEqual(proc.returncode, 1)
        self.assertLess(elapsed, 2.0)
        self.assertTrue("BLOCKED A jwt server/supabase-admin.env:1" in proc.stdout, "missing: BLOCKED A jwt")
        self.assertTrue("BLOCKED B jwt server/session.env:1" in proc.stdout, "missing: BLOCKED B jwt")
        self.assertTrue("--no-verify" in proc.stdout and "gitleaks:allow" in proc.stdout, "missing: escapes")
        self.assertEqual(sorted(p.name for p in tmpdir.iterdir()), [], "a temp report was left behind")

    @unittest.skipUnless(shutil.which("gitleaks"), "gitleaks not installed")
    def test_guard_lets_class_c_through(self):
        repo = make_repo(self.tmp, "app", {"README.md": "x\n"})
        stage(repo, ["jwt-anon"])
        proc, _, tmpdir = self.run_guard(repo)
        self.assertEqual(assert_redacted(proc.stdout + proc.stderr, PLANTED), [], "planted value printed")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(sorted(p.name for p in tmpdir.iterdir()), [], "a temp report was left behind")

    @unittest.skipUnless(shutil.which("gitleaks") and shutil.which("python3.8"), "gitleaks or python3.8 missing")
    def test_guard_runs_under_python38_without_tomllib(self):
        repo = make_repo(self.tmp, "app", {"README.md": "x\n"})
        stage(repo, ["jwt-service-role", "jwt-anon"])
        proc, _, tmpdir = self.run_guard(repo, python=shutil.which("python3.8"))
        self.assertEqual(assert_redacted(proc.stdout + proc.stderr, PLANTED), [], "planted value printed")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout.splitlines()[0], "BLOCKED A jwt server/supabase-admin.env:1")
        self.assertFalse("web/supabase-public.env" in proc.stdout, "class C must not be listed")
        self.assertEqual(sorted(p.name for p in tmpdir.iterdir()), [], "a temp report was left behind")

    @unittest.skipUnless(shutil.which("gitleaks"), "gitleaks not installed")
    def test_installed_hook_blocks_a_real_commit(self):
        repo = make_repo(self.tmp, "app", {"README.md": "x\n"})
        guard.install(repo, self.cfg_dir, tracked_ok=False)
        stage(repo, ["stripe-live"])
        proc = subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "add key"],
                              capture_output=True, text=True)
        self.assertEqual(assert_redacted(proc.stdout + proc.stderr, PLANTED), [], "planted value printed")
        self.assertNotEqual(proc.returncode, 0)
        self.assertTrue("BLOCKED A stripe-access-token" in proc.stdout + proc.stderr, "missing: BLOCKED line")
        self.assertEqual(_git(repo, "rev-list", "--count", "HEAD").strip(), "1")

    def test_guard_without_engine_allows_commit_with_install_line(self):
        repo = make_repo(self.tmp, "app", {"README.md": "x\n"})
        stage(repo, ["jwt-service-role"])
        empty_path = self.tmp / "empty-bin"
        empty_path.mkdir()
        proc, _, _ = self.run_guard(repo, path_env=str(empty_path))
        self.assertEqual(proc.returncode, 0)
        self.assertIn("brew install gitleaks", proc.stdout)
        self.assertIn("commit allowed", proc.stdout)

    def test_guard_engine_error_allows_commit_with_error_line(self):
        repo = make_repo(self.tmp, "app", {"README.md": "x\n"})
        fake_bin = self.tmp / "fake-bin"
        fake_bin.mkdir()
        fake = fake_bin / "gitleaks"
        for rc, expected in ((2, "gitleaks exit 2: FTL failed to load config"),
                             (1, "gitleaks exit 1 without a parsable report: FTL failed to load config")):
            fake.write_text("#!/bin/sh\nif [ \"$1\" = version ]; then echo 8.30.1; exit 0; fi\n"
                            f"echo 'FTL failed to load config' >&2\nexit {rc}\n")
            fake.chmod(0o755)
            proc, _, tmpdir = self.run_guard(repo, path_env=f"{fake_bin}{os.pathsep}/usr/bin{os.pathsep}/bin")
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stdout, f"sbom-audit guard: {expected}; commit allowed\n")
            self.assertEqual(sorted(p.name for p in tmpdir.iterdir()), [], "a temp report was left behind")

    def test_guard_unexpected_error_never_blocks(self):
        installed = load_guard_module()
        buf = io.StringIO()
        with mock.patch.object(installed, "find_engine", side_effect=RuntimeError("quoted-match-text")), \
             contextlib.redirect_stdout(buf):
            self.assertEqual(installed.main(), 0)
        self.assertEqual(buf.getvalue(), "sbom-audit guard: RuntimeError; commit allowed\n")

    def test_guard_classification_matches_package(self):
        installed = load_guard_module()
        package_classes = classify.load_classes()
        text = classify.CLASSES_PATH.read_text()
        self.assertEqual(installed.parse_toml_subset(text), tomllib.loads(text))
        for guard_classes in (installed.load_classes(classify.CLASSES_PATH),
                              installed.Classes.from_dict(installed.parse_toml_subset(text))):
            for item in PLANTED:
                self.assertEqual(installed.classify(item.rule_id, item.value, guard_classes, item.file),
                                 classify.classify(item.rule_id, item.value, package_classes, item.file),
                                 f"classification differs for {item.rule_id} in {item.file}")
            for rule_id, secret, file in (("gcp-api-key", "AIza-fixture", "web/firebase.json"),
                                          ("jwt-base64", "not base64!", ""), ("unknown-rule", "x", ""),
                                          ("stripe-access-token", "rk_test_fixture", "")):
                self.assertEqual(installed.classify(rule_id, secret, guard_classes, file),
                                 classify.classify(rule_id, secret, package_classes, file), rule_id)

    def test_guard_source_is_python38_compatible_and_self_contained(self):
        source = GUARD_TEMPLATE.read_text()
        tree = ast.parse(source, feature_version=(3, 8))
        imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
                    for alias in node.names}
        imported |= {node.module.split(".")[0] for node in ast.walk(tree)
                     if isinstance(node, ast.ImportFrom) and node.module}
        self.assertNotIn("sbomaudit", imported)
        self.assertTrue(imported <= set(sys.stdlib_module_names), sorted(imported - set(sys.stdlib_module_names)))
        self.assertNotIn("removeprefix", source)
        self.assertNotIn("umask=", source)


class SetupGuardTests(GuardTestCase):
    def setup_run(self, out, root, **kwargs):
        buf = io.StringIO()
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.tmp / "config")}), \
             contextlib.redirect_stdout(buf):
            rc = setup.run(out, root, gh=lambda *a, **k: subprocess.CompletedProcess(a, 1, "", ""),
                           which=ALL_PRESENT, **kwargs)
        return rc, buf.getvalue()

    def test_setup_install_guard_prints_per_repo_and_confirmation_block(self):
        root = self.tmp / "PROJECTS"
        make_repo(root, "alpha", {"README.md": "x\n"})
        make_repo(root, "beta", {".husky/pre-commit": "npm test\n"})
        out = root / "security"
        rc, text = self.setup_run(out, root, install_guard=True)
        self.assertEqual(rc, 0, text)
        self.assertTrue((self.cfg_dir / "guard.py").exists())
        self.assertRegex(text, r"\n  alpha: installed")
        block = text.split("Tracked hook files (confirm per repo, then rerun with --tracked-ok <name>):\n")
        self.assertEqual(len(block), 2, text)
        self.assertTrue(block[1].startswith("  beta: needs confirmation (husky): add  G="), text)
        self.assertLess(text.index("Tracked hook files"), text.index("Next: /sbom-audit:run"))
        self.assertTrue((root / "alpha" / ".git" / "hooks" / "pre-commit").exists())
        self.assertNotIn("guard.py", (root / "beta" / ".husky" / "pre-commit").read_text())

        rc, text = self.setup_run(out, root, install_guard=True, tracked_ok=["beta", "nope"])
        self.assertEqual(rc, 0, text)
        self.assertIn("  alpha: unchanged", text)
        self.assertIn("  beta: guard line added to .husky/pre-commit", text)
        self.assertIn("--tracked-ok nope: no repository with that name", text)
        self.assertNotIn("Tracked hook files", text)

        rc, text = self.setup_run(out, root, tracked_ok=["beta"])
        self.assertIn("--tracked-ok is used only with --install-guard; ignored", text)
        self.assertNotIn("Pre-commit guard:", text)

        gamma = make_repo(root, "gamma", {".pre-commit-config.yaml": "repos:\n"})
        rc, text = self.setup_run(out, root, install_guard=True)
        block = text.split("Tracked hook files (confirm per repo, then rerun with --tracked-ok <name>):\n")[1]
        self.assertIn("  gamma: needs confirmation (pre-commit-framework): add this block to", block)
        self.assertIn("\n      - repo: local\n        hooks:\n", block)
        shutil.rmtree(gamma)

        rc, text = self.setup_run(out, root, uninstall_guard=True)
        self.assertEqual(rc, 0, text)
        self.assertIn("  alpha: removed", text)
        self.assertFalse((root / "alpha" / ".git" / "hooks" / "pre-commit").exists())
        rc, text = self.setup_run(out, root, uninstall_guard=True, tracked_ok=["beta"])
        self.assertEqual(rc, 0, text)
        self.assertIn("--tracked-ok is used only with --install-guard; ignored", text)
        self.assertIn("Pre-commit guard:", text)
        self.assertNotIn("--tracked-ok beta", text)

    def test_cli_parses_guard_flags(self):
        args = cli.build_parser().parse_args(["setup", "--install-guard", "--tracked-ok", "a", "b"])
        self.assertEqual((args.install_guard, args.uninstall_guard, args.tracked_ok), (True, False, ["a", "b"]))
        args = cli.build_parser().parse_args(["setup"])
        self.assertEqual((args.install_guard, args.uninstall_guard, args.tracked_ok), (False, False, []))
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["setup", "--install-guard", "--uninstall-guard"])
        captured = {}
        with mock.patch.object(setup, "run", side_effect=lambda *a, **k: captured.update(k) or 0):
            self.assertEqual(cli.main(["setup", "--out", str(self.tmp / "security"), "--install-guard",
                                       "--tracked-ok", "beta"]), 0)
        self.assertEqual((captured["install_guard"], captured["tracked_ok"]), (True, ["beta"]))


if __name__ == "__main__":
    unittest.main()
