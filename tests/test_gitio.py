import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import gitio
from tests.helpers import make_repo


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, text=True,
                          capture_output=True).stdout


class GitioTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()

    def tearDown(self):
        self._tmp.cleanup()

    def test_pick_branches_skips_missing(self):
        repo = make_repo(self.tmp, "r", {"a": "1"}, branches=["main", "dev"])
        self.assertEqual(gitio.pick_branches(repo, ["main", "dev", "release"]), ["main", "dev"])
        self.assertEqual(gitio.pick_branches(repo, ["dev", "main"]), ["dev", "main"])

    def test_pick_branches_includes_origin_only(self):
        origin = make_repo(self.tmp, "origin", {"a": "1"}, branches=["main", "dev"])
        clone = self.tmp / "clone"
        _git(self.tmp, "clone", "-q", "--branch", "main", str(origin), str(clone))
        self.assertEqual(gitio.pick_branches(clone, ["main", "dev"]), ["main", "dev"])
        ref, sha, behind = gitio.branch_ref(clone, "dev")
        self.assertEqual(ref, "refs/remotes/origin/dev")
        self.assertEqual(len(sha), 40)
        self.assertEqual(behind, 0)

    def test_branch_ref_prefers_origin_when_behind(self):
        origin = make_repo(self.tmp, "origin", {"a": "1"})
        clone = self.tmp / "clone"
        _git(self.tmp, "clone", "-q", str(origin), str(clone))
        (origin / "b").write_text("2")
        _git(origin, "add", "b")
        _git(origin, "-c", "user.email=t@e", "-c", "user.name=t", "commit", "-q", "-m", "second")
        self.assertIsNone(gitio.fetch_origin(clone))
        ref, sha, behind = gitio.branch_ref(clone, "main")
        self.assertEqual(ref, "refs/remotes/origin/main")
        self.assertEqual(behind, 1)
        self.assertEqual(sha, _git(origin, "rev-parse", "main").strip())
        ref2, _, behind2 = gitio.branch_ref(origin, "main")
        self.assertEqual((ref2, behind2), ("refs/heads/main", 0))

    def test_tag_named_like_the_branch_does_not_shadow_it(self):
        repo = make_repo(self.tmp, "r", {"a": "1"}, branches=["main", "dev"])
        old = _git(repo, "rev-parse", "refs/heads/main").strip()
        _git(repo, "tag", "dev", old)                     # refs/tags/dev at an older commit than the branch
        _git(repo, "tag", "-a", "-m", "x", "main", old)   # annotated tag on the branch's own commit
        (repo / "b").write_text("2")
        _git(repo, "add", "b")
        _git(repo, "commit", "-q", "-m", "second")
        dev_tip = _git(repo, "rev-parse", "refs/heads/dev").strip()
        main_tip = _git(repo, "rev-parse", "refs/heads/main").strip()
        self.assertEqual(gitio.pick_branches(repo, ["main", "dev"]), ["main", "dev"])
        self.assertEqual(gitio.branch_ref(repo, "dev"), ("refs/heads/dev", dev_tip, 0))
        self.assertEqual(gitio.branch_ref(repo, "main"), ("refs/heads/main", main_tip, 0))
        self.assertTrue(gitio.tag_shadows_branch(repo, "dev"))
        self.assertTrue(gitio.tag_shadows_branch(repo, "main"))
        dest = self.tmp / "export"
        gitio.export_ref(repo, "refs/heads/main", dest)
        self.assertTrue((dest / "b").exists())            # the branch, not the tag
        self.assertFalse(gitio.tag_shadows_branch(make_repo(self.tmp, "clean", {"a": "1"}), "main"))

    def test_tag_does_not_shadow_an_origin_only_branch(self):
        origin = make_repo(self.tmp, "origin", {"a": "1"}, branches=["main", "dev"])
        clone = self.tmp / "clone"
        _git(self.tmp, "clone", "-q", "--branch", "main", str(origin), str(clone))
        _git(clone, "tag", "dev", "refs/heads/main")
        ref, sha, _ = gitio.branch_ref(clone, "dev")
        self.assertEqual(ref, "refs/remotes/origin/dev")
        self.assertEqual(sha, _git(origin, "rev-parse", "refs/heads/dev").strip())

    def test_git_timeout_is_a_git_error(self):
        repo = make_repo(self.tmp, "r", {"a": "1"})

        def run(args, **kwargs):
            raise subprocess.TimeoutExpired(args, kwargs.get("timeout"))

        with mock.patch.object(gitio.subprocess, "run", run):
            with self.assertRaises(gitio.GitError) as ctx:
                gitio.git(repo, "log")
            self.assertIn("timed out", str(ctx.exception))
            with self.assertRaises(gitio.GitError):
                gitio.git_bytes(repo, "log")

    def test_export_timeout_is_a_git_error(self):
        repo = make_repo(self.tmp, "r", {"a": "1"})
        with mock.patch.object(gitio, "EXPORT_TIMEOUT", 0.001), \
                mock.patch.object(gitio, "_tar_argv", lambda dest: ["sh", "-c", "sleep 5"]):
            with self.assertRaises(gitio.GitError) as ctx:
                gitio.export_ref(repo, "main", self.tmp / "export")
        self.assertIn("timed out", str(ctx.exception))

    def test_every_git_call_has_a_timeout(self):
        seen = []

        def run(args, **kwargs):
            seen.append(kwargs.get("timeout"))
            return subprocess.CompletedProcess(args, 0, "" if kwargs.get("text") else b"", "")

        with mock.patch.object(gitio.subprocess, "run", run):
            gitio.git(self.tmp, "status")
            gitio.git_bytes(self.tmp, "status")
            gitio.fetch_origin(self.tmp)
        self.assertEqual(seen, [gitio.GIT_TIMEOUT] * 3)

    def test_fetch_origin_reports_error_without_remote(self):
        repo = make_repo(self.tmp, "r", {"a": "1"})
        err = gitio.fetch_origin(repo)
        self.assertIsInstance(err, str)
        self.assertTrue(err)

    def test_net_env_never_prompts(self):
        env = gitio.net_env({"PATH": "/bin"})
        self.assertEqual(env, {"PATH": "/bin", "GIT_TERMINAL_PROMPT": "0", "GIT_SSH_COMMAND": "ssh -oBatchMode=yes"})
        env = gitio.net_env({"GIT_SSH_COMMAND": "ssh -i ~/.ssh/audit -oBatchMode=yes", "GIT_TERMINAL_PROMPT": "1"})
        self.assertEqual(env["GIT_SSH_COMMAND"], "ssh -i ~/.ssh/audit -oBatchMode=yes")   # kept verbatim
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
        env = gitio.net_env({"GIT_SSH": "/usr/local/bin/myssh"})
        self.assertNotIn("GIT_SSH_COMMAND", env)                                           # GIT_SSH wins
        self.assertEqual(env["GIT_SSH"], "/usr/local/bin/myssh")
        self.assertNotIn("StrictHostKeyChecking", " ".join(gitio.net_env({}).values()))
        self.assertIsNot(gitio.net_env(), None)                                            # os.environ default

    def test_fetch_origin_runs_with_net_env(self):
        repo = make_repo(self.tmp, "r", {"a": "1"})
        seen = {}

        def run(args, **kwargs):
            seen.update(kwargs)
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        with mock.patch.object(gitio.subprocess, "run", run):
            self.assertIsNone(gitio.fetch_origin(repo))
        self.assertEqual(seen["env"]["GIT_TERMINAL_PROMPT"], "0")
        self.assertIn("GIT_SSH_COMMAND", seen["env"])

    def test_fetch_origin_error_is_scrubbed(self):
        repo = make_repo(self.tmp, "r", {"a": "1"})
        stderr = "fatal: unable to access 'https://user:tok3n_EXAMPLE@example.invalid/x.git/': no\nmore\n"

        def run(args, **kwargs):
            return subprocess.CompletedProcess(args, 128, stdout="", stderr=stderr)

        with mock.patch.object(gitio.subprocess, "run", run):
            err = gitio.fetch_origin(repo)
        self.assertEqual(err, "fatal: unable to access 'https://***@example.invalid/x.git/': no")

    def test_scrub_credentials(self):
        self.assertEqual(gitio.scrub_credentials("x https://u:p@h/r.git y ssh://git@h/r.git"),
                         "x https://***@h/r.git y ssh://***@h/r.git")
        self.assertEqual(gitio.scrub_credentials("git@github.com:o/r.git"), "git@github.com:o/r.git")
        self.assertEqual(gitio.scrub_credentials(""), "")

    def test_export_excludes_security_dir(self):
        repo = make_repo(self.tmp, "r", {
            "package.json": "{}",
            "src/app.js": "x",
            "security/sbom/r/main.cdx.json": "{}",
            "security/AUDIT.md": "old",
        })
        dest = self.tmp / "export"
        dest.mkdir()
        gitio.export_ref(repo, "main", dest)
        self.assertTrue((dest / "package.json").exists())
        self.assertTrue((dest / "src/app.js").exists())
        self.assertFalse((dest / "security").exists())

    def test_export_does_not_touch_worktree(self):
        repo = make_repo(self.tmp, "r", {"a": "1"}, branches=["main", "dev"])
        (repo / "untracked.txt").write_text("dirty")
        before = _git(repo, "status", "--porcelain")
        head_before = _git(repo, "rev-parse", "HEAD")
        dest = self.tmp / "export"
        dest.mkdir()
        gitio.export_ref(repo, "dev", dest)
        self.assertTrue((dest / "DEV").exists())
        self.assertEqual(_git(repo, "status", "--porcelain"), before)
        self.assertEqual(_git(repo, "rev-parse", "HEAD"), head_before)
        self.assertEqual(_git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip(), "main")

    def test_git_env_carries_hardening_config(self):
        env = gitio.git_env({"PATH": "/bin"})
        count = int(env["GIT_CONFIG_COUNT"])
        pairs = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(count)}
        self.assertEqual(pairs["core.fsmonitor"], "false")
        self.assertEqual(pairs["core.hooksPath"], "/dev/null")
        self.assertEqual(pairs["diff.external"], "")
        self.assertEqual(pairs["log.showSignature"], "false")
        self.assertEqual(env["PATH"], "/bin")
        # an existing GIT_CONFIG_COUNT from the caller is kept and appended to
        env = gitio.git_env({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "user.name",
                             "GIT_CONFIG_VALUE_0": "x"})
        self.assertEqual(env["GIT_CONFIG_KEY_0"], "user.name")
        self.assertEqual(env["GIT_CONFIG_KEY_1"], "core.fsmonitor")
        # net_env composes with it
        self.assertIn("GIT_CONFIG_COUNT", gitio.git_env(gitio.net_env({})))

    def test_every_git_call_gets_the_hardening_env(self):
        repo = make_repo(self.tmp, "r", {"a": "1"})
        seen = []

        def run(args, **kwargs):
            seen.append(kwargs)
            return subprocess.CompletedProcess(args, 0, stdout="" if kwargs.get("text") else b"", stderr="")

        with mock.patch.object(gitio.subprocess, "run", run):
            gitio.git(repo, "status")
            gitio.git_bytes(repo, "status")
            gitio.fetch_origin(repo)
        self.assertEqual(len(seen), 3)
        for kwargs in seen:
            self.assertEqual(kwargs["env"].get("GIT_CONFIG_KEY_1"), "core.hooksPath")

    def test_export_runs_no_filter_driver_from_repository_config(self):
        repo = make_repo(self.tmp, "r", {".gitattributes": "a.txt filter=evil\n", "a.txt": "plain\n"})
        marker = self.tmp / "SMUDGED"
        for key in ("smudge", "clean"):
            _git(repo, "config", f"filter.evil.{key}", f"sh -c 'touch {marker}; echo replaced'")
        _git(repo, "config", "filter.evil.required", "true")
        dest = self.tmp / "export"
        gitio.export_ref(repo, "main", dest)
        self.assertFalse(marker.exists())
        self.assertEqual((dest / "a.txt").read_text(), "plain\n")
        _git(repo, "config", "--unset-all", "filter.evil.smudge")
        _git(repo, "config", "filter.evil.process", f"sh -c 'touch {marker}; exit 1'")
        dest2 = self.tmp / "export2"
        gitio.export_ref(repo, "main", dest2)
        self.assertFalse(marker.exists())
        self.assertEqual((dest2 / "a.txt").read_text(), "plain\n")

    def test_git_raises_on_failure(self):
        repo = make_repo(self.tmp, "r", {"a": "1"})
        with self.assertRaises(gitio.GitError):
            gitio.git(repo, "rev-parse", "--verify", "nope")


class RealGitBehindAppleShim(unittest.TestCase):
    """Apple's /usr/bin/git asks xcrun, which a sandbox can block; the real binary is used directly."""

    def _fake_tools(self, tmp):
        tools = Path(tmp) / "Developer"
        (tools / "usr" / "bin").mkdir(parents=True)
        binary = tools / "usr" / "bin" / "git"
        binary.write_text("#!/bin/sh\necho real-git\n")
        binary.chmod(0o755)
        (tools / "usr" / "bin" / "python3").write_text("#!/bin/sh\n")
        (tools / "usr" / "bin" / "python3").chmod(0o755)
        return tools

    def _no_developer_dir(self):
        patcher = mock.patch.dict(os.environ, {"PATH": "/usr/bin:/bin"})
        env = patcher.start()
        self.addCleanup(patcher.stop)
        env.pop("DEVELOPER_DIR", None)

    def test_shim_resolves_to_the_selected_developer_directory(self):
        self._no_developer_dir()
        with tempfile.TemporaryDirectory() as tmp:
            tools = self._fake_tools(tmp)
            with mock.patch.object(gitio, "_first_git", return_value=gitio.APPLE_GIT_SHIM), \
                    mock.patch.object(gitio, "_XCODE_SELECT_LINK", str(tools)):
                self.assertEqual(gitio.real_git(platform="darwin"), str(tools.resolve() / "usr" / "bin" / "git"))

    def test_path_gains_a_folder_holding_only_git(self):
        self._no_developer_dir()
        with tempfile.TemporaryDirectory() as tmp:
            tools = self._fake_tools(tmp)
            with mock.patch.object(gitio, "real_git", return_value=str(tools / "usr" / "bin" / "git")):
                folder = gitio.use_real_git()
            self.addCleanup(shutil.rmtree, folder, True)
            self.assertEqual(os.listdir(folder), ["git"])          # the developer folder's python3 does not come along
            self.assertEqual(os.environ["PATH"], folder + os.pathsep + "/usr/bin:/bin")
            out = subprocess.run(["git"], capture_output=True, text=True).stdout
            self.assertEqual(out, "real-git\n")

    def test_another_git_or_another_platform_is_left_alone(self):
        with mock.patch.object(gitio, "_first_git", return_value="/opt/homebrew/bin/git"):
            self.assertIsNone(gitio.real_git(platform="darwin"))
        with mock.patch.object(gitio, "_first_git", return_value=gitio.APPLE_GIT_SHIM):
            self.assertIsNone(gitio.real_git(platform="linux"))

    def test_no_real_binary_or_no_temp_folder_keeps_the_path(self):
        self._no_developer_dir()
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(gitio, "_first_git", return_value=gitio.APPLE_GIT_SHIM), \
                mock.patch.object(gitio, "_XCODE_SELECT_LINK", str(Path(tmp) / "missing")), \
                mock.patch.object(gitio, "_COMMAND_LINE_TOOLS", str(Path(tmp) / "none")), \
                mock.patch.object(gitio.sys, "platform", "darwin"):
            self.assertIsNone(gitio.real_git(platform="darwin"))
        with mock.patch.object(gitio, "real_git", return_value="/somewhere/git"), \
                mock.patch.object(gitio.tempfile, "mkdtemp", side_effect=PermissionError("sandbox")):
            self.assertIsNone(gitio.use_real_git())
        self.assertEqual(os.environ["PATH"], "/usr/bin:/bin")

    def test_first_git_walks_the_path_in_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            tools = self._fake_tools(tmp)
            found = gitio._first_git(os.pathsep.join([str(Path(tmp) / "empty"), str(tools / "usr" / "bin"), "/usr/bin"]))
            self.assertEqual(found, str(tools / "usr" / "bin" / "git"))

if __name__ == "__main__":
    unittest.main()
