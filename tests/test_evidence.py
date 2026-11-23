"""Evidence folder: docs, pruning, run commit, guarded push, visibility (real git repos)."""
from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sbomaudit import evidence
from tests.helpers import make_repo

MARKER = "<!-- sbom-audit-template v{} -->"


def git(repo: Path, *args: str, env: dict | None = None) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, text=True,
                          capture_output=True, env=env).stdout


class FolderDocsTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_folder_docs_written_once_and_refreshed_on_marker_bump(self):
        out = self.tmp / "security"
        out.mkdir()
        written = evidence.write_folder_docs(out)
        self.assertEqual(sorted(p.name for p in written), ["CLAUDE.md", "README.md"])
        for name in ("CLAUDE.md", "README.md"):
            self.assertEqual((out / name).read_text().splitlines()[0], MARKER.format(7))
        # same version again: nothing is rewritten, but both stay owned (returned for the run commit)
        (out / "CLAUDE.md").write_text(MARKER.format(7) + "\nlocal tweak below the marker\n")
        owned = evidence.write_folder_docs(out)
        self.assertEqual(sorted(p.name for p in owned), ["CLAUDE.md", "README.md"])
        self.assertIn("local tweak", (out / "CLAUDE.md").read_text())
        # a hand-written file (no marker) is never touched and not returned
        (out / "README.md").write_text("my own readme\n")
        self.assertEqual([p.name for p in evidence.write_folder_docs(out)], ["CLAUDE.md"])
        self.assertEqual((out / "README.md").read_text(), "my own readme\n")
        # an older marker is refreshed; the template here is v3, so fake a v0 file
        (out / "CLAUDE.md").write_text(MARKER.format(0) + "\nold text\n")
        again = evidence.write_folder_docs(out)
        self.assertEqual([p.name for p in again], ["CLAUDE.md"])
        self.assertEqual((out / "CLAUDE.md").read_text().splitlines()[0], MARKER.format(7))
        self.assertNotIn("old text", (out / "CLAUDE.md").read_text())

    def test_templates_state_the_rules(self):
        claude = (evidence.TEMPLATE_DIR / "CLAUDE.md").read_text()
        readme = (evidence.TEMPLATE_DIR / "README.md").read_text()
        self.assertEqual(claude.splitlines()[0], MARKER.format(7))
        self.assertEqual(readme.splitlines()[0], MARKER.format(7))
        for needle in ("## Assessment", "status.json", "issues.json", "secrets.json", "SECRETS.md", "sbom/",
                       "/sbom-audit:vex", "/sbom-audit:secrets resolve", "private", "HOSTS.md", "hosts.json",
                       "hosts/", "hosts-decisions.toml", "--confirm"):
            self.assertIn(needle, claude)
        for needle in ("status.json", "STATUS.md", "issues.json", "secrets.json", "SECRETS.md", "osv.dev",
                       "api.github.com", "private", "HOSTS.md", "hosts-decisions.toml"):
            self.assertIn(needle, readme)

    def test_prune_removes_only_unconfigured_sbom_dirs_never_reports(self):
        out = self.tmp / "security"
        (out / "sbom" / "old").mkdir(parents=True)
        (out / "sbom" / "old" / "main.cdx.json").write_text("{}")
        (out / "sbom" / "keep").mkdir(parents=True)
        (out / "reports").mkdir()
        (out / "reports" / "x").write_text("x")
        removed = evidence.prune_sbom_dirs(out, {"keep"})
        self.assertEqual(removed, ["old"])
        self.assertFalse((out / "sbom" / "old").exists())
        self.assertTrue((out / "sbom" / "keep").is_dir())
        self.assertTrue((out / "reports" / "x").exists())
        self.assertEqual(evidence.prune_sbom_dirs(self.tmp / "nowhere", set()), [])

    def test_prune_keeps_a_dir_with_anything_but_sboms(self):
        out = self.tmp / "security"
        (out / "sbom" / "old" / "nested").mkdir(parents=True)
        (out / "sbom" / "old" / "main.cdx.json").write_text("{}")
        (out / "sbom" / "stray").mkdir(parents=True)
        (out / "sbom" / "stray" / "main.cdx.json").write_text("{}")
        (out / "sbom" / "stray" / "notes.txt").write_text("mine\n")
        (out / "sbom" / "clean").mkdir(parents=True)
        (out / "sbom" / "clean" / "dev.cdx.json").write_text("{}")
        self.assertFalse(evidence.holds_only_sboms(out / "sbom" / "old"))
        self.assertFalse(evidence.holds_only_sboms(out / "sbom" / "stray"))
        self.assertTrue(evidence.holds_only_sboms(out / "sbom" / "clean"))
        self.assertEqual(evidence.prune_sbom_dirs(out, set()), ["clean"])
        self.assertTrue((out / "sbom" / "stray" / "notes.txt").exists())
        self.assertTrue((out / "sbom" / "old" / "nested").is_dir())

    def test_is_own_repo(self):
        outer = make_repo(self.tmp, "outer", {"a": "1\n"})
        inner = outer / "PROJECTS" / "security"
        inner.mkdir(parents=True)
        self.assertTrue(evidence.is_own_repo(outer))
        self.assertFalse(evidence.is_own_repo(inner))
        self.assertFalse(evidence.is_own_repo(self.tmp / "missing"))
        plain = self.tmp / "plain"
        plain.mkdir()
        self.assertFalse(evidence.is_own_repo(plain))
        with mock.patch.object(evidence.subprocess, "run", side_effect=FileNotFoundError("git")):
            self.assertFalse(evidence.is_own_repo(outer, git=evidence.subprocess.run))

    def test_prune_ignores_a_symlinked_sbom_dir(self):
        outside = self.tmp / "outside"
        (outside / "victim").mkdir(parents=True)
        out = self.tmp / "security"
        out.mkdir()
        (out / "sbom").symlink_to(outside, target_is_directory=True)
        self.assertEqual(evidence.prune_sbom_dirs(out, set()), [])
        self.assertTrue((outside / "victim").is_dir())

    def test_relative_out_gives_absolute_paths_and_commits(self):
        repo = make_repo(self.tmp, "ev", {"seed": "1\n"})
        with contextlib.chdir(self.tmp):
            written = evidence.write_folder_docs(Path("ev"))
            self.assertTrue(all(p.is_absolute() for p in written))
            self.assertEqual(sorted(p.name for p in written), ["CLAUDE.md", "README.md"])
            res = evidence.commit_run(Path("ev"), written, "s", "b")
            self.assertEqual(res.status, "committed", res.detail)
            self.assertEqual(evidence.pending_hand_edits(Path("ev"), set(written)), [])
        self.assertEqual(sorted(git(repo, "show", "--name-only", "--format=", "HEAD").split()),
                         ["CLAUDE.md", "README.md"])

    def test_subject_line_format(self):
        status = {"counts": {"vulnerable": 169, "kev": 3, "secrets": {"A": 2, "B": 1, "C": 0}},
                  "generated_at": "2026-11-07T09:30:00+01:00", "plugin_version": "1.0.0",
                  "exit_code": 1, "run_host": "mbp"}
        self.assertEqual(evidence.subject_line(status),
                         "audit 2026-11-07: 169 vulnerable, 3 KEV, 2 class A secrets")
        self.assertEqual(evidence.body_line(status), "sbom-audit 1.0.0, exit 1, run host mbp")
        status["exit_code"] = None
        self.assertEqual(evidence.body_line(status), "sbom-audit 1.0.0, exit none, run host mbp")
        status["counts"]["secrets"] = None
        self.assertEqual(evidence.subject_line(status), "audit 2026-11-07: 169 vulnerable, 3 KEV, secrets skipped")
        del status["counts"]["secrets"]
        self.assertEqual(evidence.subject_line(status), "audit 2026-11-07: 169 vulnerable, 3 KEV, secrets skipped")


class CommitTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_commit_only_written_files_lists_hand_edits(self):
        out = make_repo(self.tmp, "security", {"sbom-audit.toml": "a = 1\n", "AUDIT.md": "v1\n"})
        (out / "sbom-audit.toml").write_text("a = 2\n")      # hand edit, not written by the run
        git(out, "add", "sbom-audit.toml")                   # pre-staged by the user
        (out / "AUDIT.md").write_text("v2\n")
        (out / "sbom" / "p").mkdir(parents=True)
        (out / "sbom" / "p" / "main.cdx.json").write_text("{}")
        written = [out / "AUDIT.md", Path("sbom/p/main.cdx.json")]   # absolute and relative
        res = evidence.commit_run(out, written, "audit 2026-11-07: 1 vulnerable, 0 KEV, 0 class A secrets",
                                  "sbom-audit 1.0.0, exit 1, run host h")
        self.assertEqual(res.status, "committed")
        self.assertEqual(res.sha, git(out, "rev-parse", "--short", "HEAD").strip())
        files = git(out, "show", "--name-only", "--format=", "HEAD").split()
        self.assertEqual(sorted(files), ["AUDIT.md", "sbom/p/main.cdx.json"])
        self.assertIn("exit 1", git(out, "log", "-1", "--format=%B"))
        self.assertNotIn("sbom-audit.toml", files)
        self.assertIn("M  sbom-audit.toml", git(out, "status", "--porcelain").splitlines())
        self.assertEqual(evidence.pending_hand_edits(out, {Path("AUDIT.md"), out / "sbom/p/main.cdx.json"}),
                         ["sbom-audit.toml"])
        # nothing changed since: second commit is a no-op
        again = evidence.commit_run(out, written, "s", "b")
        self.assertEqual(again.status, "nothing")

    def test_commit_records_deleted_tracked_paths_and_ignores_untracked_ghosts(self):
        out = make_repo(self.tmp, "security", {"sbom/gone/x.cdx.json": "{}\n", "AUDIT.md": "v1\n"})
        shutil.rmtree(out / "sbom" / "gone")
        (out / "AUDIT.md").write_text("v2\n")
        written = [out / "AUDIT.md", Path("sbom/gone"), Path("sbom/never-tracked")]
        res = evidence.commit_run(out, written, "s", "b")
        self.assertEqual(res.status, "committed", res.detail)
        changes = sorted(git(out, "show", "--name-status", "--format=", "HEAD").splitlines())
        self.assertEqual(changes, ["D\tsbom/gone/x.cdx.json", "M\tAUDIT.md"])
        # only ghosts and nothing else: no failure, nothing to commit
        res = evidence.commit_run(out, [Path("sbom/never-tracked"), Path("sbom/gone")], "s", "b")
        self.assertEqual(res.status, "nothing")

    def test_pending_hand_edits_for_a_subfolder_of_a_repo(self):
        repo = make_repo(self.tmp, "proj", {"app.txt": "1\n"})
        out = repo / "security"
        (out / "sbom").mkdir(parents=True)
        (out / "AUDIT.md").write_text("a\n")
        (out / "sbom-audit.toml").write_text("t\n")
        (out / "sbom" / "x.json").write_text("{}")
        (repo / "app.txt").write_text("2\n")                  # outside `out`: not reported
        self.assertEqual(evidence.pending_hand_edits(out, {out / "AUDIT.md"}),
                         ["sbom-audit.toml", "sbom/x.json"])
        res = evidence.commit_run(out, [Path("AUDIT.md")], "s", "b")
        self.assertEqual(res.status, "committed", res.detail)
        self.assertEqual(git(repo, "show", "--name-only", "--format=", "HEAD").split(), ["security/AUDIT.md"])

    def test_commit_without_identity_reports_failure_keeps_files(self):
        out = make_repo(self.tmp, "security", {"AUDIT.md": "v1\n"})
        git(out, "config", "--unset", "user.name")
        git(out, "config", "--unset", "user.email")
        (out / "AUDIT.md").write_text("v2\n")
        empty_home = self.tmp / "home"
        empty_home.mkdir()
        drop = {"GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL", "EMAIL"}
        env = {k: v for k, v in os.environ.items() if k not in drop}
        env.update({"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(empty_home),
                    # no guessing an identity from the host name
                    "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "user.useConfigOnly",
                    "GIT_CONFIG_VALUE_0": "true"})
        before = git(out, "rev-parse", "HEAD")

        def run(args, **kw):
            return subprocess.run(args, env=env, **kw)

        res = evidence.commit_run(out, [Path("AUDIT.md")], "s", "b", git=run)
        self.assertEqual(res.status, "failed")
        self.assertIn("identity", res.detail.lower())
        self.assertEqual((out / "AUDIT.md").read_text(), "v2\n")
        self.assertEqual(git(out, "rev-parse", "HEAD"), before)

    def test_commit_outside_git_repo_is_skipped(self):
        out = self.tmp / "plain"
        out.mkdir()
        (out / "AUDIT.md").write_text("x\n")
        res = evidence.commit_run(out, [Path("AUDIT.md")], "s", "b")
        self.assertEqual((res.status, res.detail), ("skipped", "not a git repository"))
        self.assertIsNone(res.sha)


class PushTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_push_refused_for_public_visibility(self):
        stub = mock.Mock()
        res = evidence.push_run(self.tmp, "public", git=stub)
        self.assertEqual(res["status"], "refused_public")
        self.assertEqual(res["detail"], "remote is public; keep the evidence repository private")
        stub.assert_not_called()

    def test_push_guard_is_case_and_whitespace_insensitive(self):
        for value in ("PUBLIC", " Public ", "public\n"):
            stub = mock.Mock()
            res = evidence.push_run(self.tmp, value, git=stub)
            self.assertEqual(res["status"], "refused_public", value)
            stub.assert_not_called()

    def test_push_goes_to_the_branch_upstream_remote(self):
        origin = self.tmp / "origin.git"
        mirror = self.tmp / "mirror.git"
        for bare in (origin, mirror):
            subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(bare)], check=True)
        out = make_repo(self.tmp, "security", {"AUDIT.md": "v1\n"}, remote=str(origin))
        git(out, "remote", "add", "mirror", str(mirror))
        git(out, "push", "-q", "-u", "mirror", "main")
        (out / "AUDIT.md").write_text("v2\n")
        git(out, "commit", "-q", "-am", "local")
        calls = []

        def spy(args, **kw):
            calls.append(args[4:])
            return subprocess.run(args, **kw)

        res = evidence.push_run(out, "private", git=spy)
        self.assertEqual(res["status"], "pushed", res)
        self.assertIn(["fetch", "mirror"], calls)
        self.assertIn(["push", "mirror", "HEAD:refs/heads/main"], calls)
        self.assertFalse([c for c in calls if "origin" in c])
        self.assertEqual(git(mirror, "rev-parse", "main"), git(out, "rev-parse", "HEAD"))
        self.assertNotIn("main", git(origin, "branch", "--list"))
        # visibility reads the same remote
        git(out, "remote", "set-url", "mirror", "https://github.com/me/mirror.git")
        git(out, "remote", "set-url", "origin", "https://github.com/me/other.git")
        gh = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout="private\n", stderr=""))
        self.assertEqual(evidence.remote_visibility(out, gh=gh, which=lambda n: "gh"), "private")
        self.assertEqual(gh.call_args[0][0][2], "repos/me/mirror")
        # a pushurl that is public is what counts
        git(out, "remote", "set-url", "--push", "mirror", "git@github.com:me/pub.git")
        evidence.remote_visibility(out, gh=gh, which=lambda n: "gh")
        self.assertEqual(gh.call_args[0][0][2], "repos/me/pub")

    def test_push_timeout_is_reported_without_hanging(self):
        bare = self.tmp / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(bare)], check=True)
        out = make_repo(self.tmp, "security", {"AUDIT.md": "v1\n"}, remote=str(bare))
        git(out, "push", "-q", "-u", "origin", "main")
        seen = {}

        def stub(args, **kw):
            if args[4] == "fetch":
                seen.update(kw)
                raise subprocess.TimeoutExpired(args, kw.get("timeout"))
            return subprocess.run(args, **kw)

        res = evidence.push_run(out, "private", git=stub)
        self.assertEqual(res, {"status": "failed", "detail": "timed out"})
        self.assertEqual(seen["timeout"], 120)
        self.assertEqual(seen["env"]["GIT_TERMINAL_PROMPT"], "0")
        self.assertIn("GIT_SSH_COMMAND", seen["env"])
        self.assertIn("BatchMode=yes", seen["env"]["GIT_SSH_COMMAND"])

    def test_push_with_remote_ahead_and_clean_tree_fast_forwards(self):
        bare = self.tmp / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(bare)], check=True)
        out = make_repo(self.tmp, "security", {"AUDIT.md": "v1\n"}, remote=str(bare))
        git(out, "push", "-q", "-u", "origin", "main")
        clone = self.tmp / "clone"
        subprocess.run(["git", "clone", "-q", str(bare), str(clone)], check=True)
        git(clone, "config", "user.email", "o@example.invalid")
        git(clone, "config", "user.name", "Other")
        (clone / "other.txt").write_text("x\n")
        git(clone, "add", "other.txt")
        git(clone, "commit", "-q", "-m", "remote one")
        git(clone, "push", "-q", "origin", "main")
        res = evidence.push_run(out, "private")
        self.assertEqual(res["status"], "pushed", res)
        self.assertTrue((out / "other.txt").exists())
        self.assertEqual(git(out, "rev-parse", "HEAD"), git(bare, "rev-parse", "main"))

    def test_push_without_upstream_is_skipped(self):
        out = make_repo(self.tmp, "security", {"a": "1\n"})
        res = evidence.push_run(out, "private")
        self.assertEqual((res["status"], res["detail"]), ("skipped", "no upstream"))

    def test_push_failure_detail_never_carries_the_remote_url(self):
        out = make_repo(self.tmp, "security", {"a": "1\n"})
        git(out, "remote", "add", "origin", "https://nobody:tok3n@nonexistent.invalid/o/r.git")
        git(out, "config", "branch.main.remote", "origin")
        git(out, "config", "branch.main.merge", "refs/heads/main")
        res = evidence.push_run(out, "private")
        self.assertEqual(res["status"], "failed")
        for needle in ("nonexistent", "invalid", "o/r.git", "nobody", "tok3n", "://"):
            self.assertNotIn(needle, res["detail"])
        self.assertLessEqual(len(res["detail"]), 200)

    def test_scrub_replaces_url_tokens_and_known_parts(self):
        line = ("fatal: unable to access 'https://u:secret@host.example/o/r.git/': Could not resolve host: "
                "host.example; also git@github.com:o/r.git")
        text = evidence._scrub(line, ["host.example", "o/r.git", "u:secret", "secret"])
        self.assertNotIn("host.example", text)
        self.assertNotIn("secret", text)
        self.assertNotIn("github.com", text)
        self.assertIn("<remote>", text)
        self.assertEqual(len(evidence._scrub("x" * 500)), 200)

    def test_has_upstream(self):
        self.assertFalse(evidence.has_upstream(self.tmp / "missing"))
        out = make_repo(self.tmp, "security", {"a": "1\n"})
        self.assertFalse(evidence.has_upstream(out))
        git(out, "config", "branch.main.remote", "origin")
        git(out, "config", "branch.main.merge", "refs/heads/main")
        self.assertTrue(evidence.has_upstream(out))

    def test_push_fast_forward_then_push_and_conflict(self):
        bare = self.tmp / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(bare)], check=True)
        out = make_repo(self.tmp, "security", {"AUDIT.md": "v1\n"}, remote=str(bare))
        git(out, "push", "-q", "-u", "origin", "main")
        # a new local commit goes out
        (out / "AUDIT.md").write_text("v2\n")
        git(out, "commit", "-q", "-am", "local one")
        res = evidence.push_run(out, "private")
        self.assertEqual(res["status"], "pushed", res)
        self.assertEqual(res["detail"], git(out, "rev-parse", "--short", "HEAD").strip())
        self.assertEqual(git(bare, "rev-parse", "main"), git(out, "rev-parse", "HEAD"))
        # someone else pushes; local has a new commit too -> diverged
        clone = self.tmp / "clone"
        subprocess.run(["git", "clone", "-q", str(bare), str(clone)], check=True)
        git(clone, "config", "user.email", "o@example.invalid")
        git(clone, "config", "user.name", "Other")
        (clone / "other.txt").write_text("x\n")
        git(clone, "add", "other.txt")
        git(clone, "commit", "-q", "-m", "remote one")
        git(clone, "push", "-q", "origin", "main")
        (out / "AUDIT.md").write_text("v3\n")
        git(out, "commit", "-q", "-am", "local two")
        local_head = git(out, "rev-parse", "HEAD")
        res = evidence.push_run(out, "unknown")
        self.assertEqual(res["status"], "conflict", res)
        self.assertEqual(git(out, "rev-parse", "HEAD"), local_head)       # local commit kept
        self.assertNotEqual(git(bare, "rev-parse", "main"), local_head)   # nothing forced


class VisibilityTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_remote_visibility_unknown_without_gh_or_github(self):
        gh = mock.Mock()
        out = make_repo(self.tmp, "a", {"f": "1\n"}, remote="https://github.com/o/r.git")
        self.assertEqual(evidence.remote_visibility(out, gh=gh, which=lambda name: None), "unknown")
        gh.assert_not_called()
        other = make_repo(self.tmp, "b", {"f": "1\n"}, remote="https://gitlab.com/o/r.git")
        self.assertEqual(evidence.remote_visibility(other, gh=gh, which=lambda name: "/usr/bin/gh"), "unknown")
        noremote = make_repo(self.tmp, "c", {"f": "1\n"})
        self.assertEqual(evidence.remote_visibility(noremote, gh=gh, which=lambda name: "/usr/bin/gh"), "unknown")
        gh.assert_not_called()

    def test_remote_visibility_reads_gh_for_the_three_url_forms(self):
        for i, url in enumerate(("https://github.com/o/r.git", "git@github.com:o/r",
                                 "ssh://git@github.com/o/r.git")):
            out = make_repo(self.tmp, f"r{i}", {"f": "1\n"}, remote=url)
            gh = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout="private\n", stderr=""))
            self.assertEqual(evidence.remote_visibility(out, gh=gh, which=lambda n: "/usr/bin/gh"), "private")
            args, kwargs = gh.call_args
            self.assertEqual(args[0], ["gh", "api", "repos/o/r", "--jq", ".visibility"])
            self.assertEqual(kwargs, {"capture_output": True, "text": True, "timeout": 10})
        out = make_repo(self.tmp, "bad", {"f": "1\n"}, remote="https://github.com/o/r")
        for stdout, rc in (("weird\n", 0), ("public\n", 1)):
            gh = mock.Mock(return_value=SimpleNamespace(returncode=rc, stdout=stdout, stderr="e"))
            self.assertEqual(evidence.remote_visibility(out, gh=gh, which=lambda n: "gh"), "unknown")
        gh = mock.Mock(side_effect=subprocess.TimeoutExpired("gh", 10))
        self.assertEqual(evidence.remote_visibility(out, gh=gh, which=lambda n: "gh"), "unknown")

    def test_remote_visibility_runs_the_injected_git_with_literal_pathspecs(self):
        out = make_repo(self.tmp, "r-git", {"f": "1\n"}, remote="https://github.com/o/r.git")
        calls = []

        def spy(args, **kw):
            calls.append(list(args))
            return subprocess.run(args, **kw)

        gh = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout="private\n", stderr=""))
        self.assertEqual(evidence.remote_visibility(out, gh=gh, which=lambda n: "gh", git=spy), "private")
        self.assertTrue(calls)
        for args in calls:
            self.assertEqual(args[:4], ["git", "--literal-pathspecs", "-C", str(Path(out).resolve())])
        self.assertIn(["remote", "get-url", "--push", "--", "origin"], [a[4:] for a in calls])
        calls.clear()
        evidence.remote_visibility(out, gh=gh, which=lambda n: "gh", remote="origin", git=spy)
        self.assertEqual([a[4:] for a in calls], [["remote", "get-url", "--push", "--", "origin"]])

    def test_remote_parts_skips_the_ssh_git_user_and_keeps_https_userinfo(self):
        out = make_repo(self.tmp, "parts", {"f": "1\n"}, remote="ssh://git@github.com/o/r.git")
        parts = evidence._remote_parts(subprocess.run, out, "origin")
        self.assertIn("github.com", parts)
        self.assertIn("o/r.git", parts)
        self.assertNotIn("git", parts)
        git(out, "remote", "add", "cred", "https://user:tok3n_EXAMPLE@github.com/o/r.git")
        parts = evidence._remote_parts(subprocess.run, out, "cred")
        for piece in ("user:tok3n_EXAMPLE", "user", "tok3n_EXAMPLE", "github.com", "o/r.git"):
            self.assertIn(piece, parts)


if __name__ == "__main__":
    unittest.main()
