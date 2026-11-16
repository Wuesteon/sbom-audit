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
        self.assertEqual(ref, "origin/dev")
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
        self.assertEqual(ref, "origin/main")
        self.assertEqual(behind, 1)
        self.assertEqual(sha, _git(origin, "rev-parse", "main").strip())
        ref2, _, behind2 = gitio.branch_ref(origin, "main")
        self.assertEqual((ref2, behind2), ("main", 0))

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

    def test_git_raises_on_failure(self):
        repo = make_repo(self.tmp, "r", {"a": "1"})
        with self.assertRaises(gitio.GitError):
            gitio.git(repo, "rev-parse", "--verify", "nope")


if __name__ == "__main__":
    unittest.main()
