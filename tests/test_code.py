"""`code grep|show|files`: read-only access to a project's committed code on an audited branch."""
from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import assess, cli, code
from tests.helpers import _git, make_repo


def call(out: Path, *argv: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        rc = cli.main(["--out", str(out), "code", *argv])
    return rc, stdout.getvalue(), stderr.getvalue()


class CodeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.repo = make_repo(self.root, "app", {
            "src/server.js": "const yaml = require('js-yaml');\nyaml.load(input);\n",
            "README.md": "app\n",
            "security/.cache/key": "fingerprint-key\n",
        }, branches=["main", "dev"])
        (self.repo / "src" / "server.js").write_text("// working tree edit: yaml.load\n")  # never read
        self.out = self.root / "security"
        self.out.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def test_grep_reads_the_branch_not_the_working_tree(self):
        rc, out, _ = call(self.out, "grep", "app", "main", r"yaml\.load")
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "src/server.js:2:yaml.load(input);")

    def test_grep_without_match_exits_1(self):
        rc, out, _ = call(self.out, "grep", "app", "main", "nothing-here")
        self.assertEqual(rc, 1)
        self.assertIn("no match", out)

    def test_grep_never_searches_the_cache(self):
        rc, out, _ = call(self.out, "grep", "app", "main", "fingerprint")
        self.assertEqual(rc, 1, out)

    def test_show_numbers_lines_and_takes_a_range(self):
        rc, out, _ = call(self.out, "show", "app", "main", "src/server.js", "--lines", "2-2")
        self.assertEqual((rc, out.strip()), (0, "2: yaml.load(input);"))

    def test_files_lists_the_tree(self):
        rc, out, _ = call(self.out, "files", "app", "dev")
        self.assertEqual(rc, 0)
        self.assertIn("DEV", out.split())
        self.assertIn("src/server.js", out.split())

    def test_refuses_unknown_project_branch_and_paths(self):
        cases = [("show", "nope", "main", "README.md"), ("show", "app", "nope", "README.md"),
                 ("show", "app", "main", "../etc/passwd"), ("show", "app", "main", "/etc/passwd"),
                 ("show", "app", "main", "security/.cache/key"), ("grep", "app", "main", "x", "--path", ":(top)")]
        for argv in cases:
            rc, out, err = call(self.out, *argv)
            self.assertEqual(rc, 2, argv)
            self.assertEqual(out, "", argv)
            self.assertTrue(err.startswith("code: "), argv)

    def test_is_read_only_and_allowed_headless(self):
        self.assertIn("code", assess.READ_ONLY_SUBCOMMANDS)
        args = cli.build_parser().parse_args(["code", "files", "app", "main"])
        self.assertFalse(cli._writes(args))

    def test_repository_textconv_never_runs(self):
        marker = self.root / "ran"
        _git(self.repo, "config", "diff.evil.textconv", f"touch {marker}; cat")
        (self.repo / ".gitattributes").write_text("*.js diff=evil\n")
        _git(self.repo, "add", ".gitattributes")
        _git(self.repo, "commit", "-q", "-m", "attrs")
        call(self.out, "grep", "app", "main", "yaml")
        call(self.out, "show", "app", "main", "src/server.js")
        self.assertFalse(marker.exists())


XCRUN_STDERR = ("xcode-select: Failed to locate 'git', requesting installation of command line developer tools.\n"
                "couldn't create cache file '/var/folders/x/xcrun_db': Operation not permitted\n")


class GitNotUsableTests(unittest.TestCase):
    """`code` says when git itself could not run, apart from "no match" and from an unreadable repository."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.repo = make_repo(self.root, "app", {"src/server.js": "yaml.load(input);\n"}, branches=["main"])
        self.out = self.root / "security"
        self.out.mkdir()
        self.bin = self.root / "fakebin"
        self.bin.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def _stub(self, body: str) -> None:
        stub = self.bin / "git"
        stub.write_text("#!/bin/sh\n" + body)
        stub.chmod(0o755)

    def _call_with_path(self, path: str, *argv: str):
        with mock.patch.dict(os.environ, {"PATH": path}):
            return call(self.out, *argv)

    def test_failing_git_stub_is_git_not_usable_not_no_match(self):
        self._stub(f"printf '%s' \"{XCRUN_STDERR}\" >&2\nexit 1\n")
        for argv in (("grep", "app", "main", "yaml"), ("show", "app", "main", "src/server.js"),
                     ("files", "app", "main")):
            rc, out, err = self._call_with_path(str(self.bin), *argv)
            self.assertEqual(rc, code.EXIT_GIT_UNUSABLE, argv)
            self.assertEqual(out, "", argv)
            self.assertNotIn("no match in", out + err)
            self.assertIn("git could not run: xcode-select: Failed to locate 'git'", err)
            self.assertNotIn("Operation not permitted", err)          # only the first line of git's stderr
            self.assertIn(code.GIT_HINT, err)

    def test_empty_path_is_git_not_found(self):
        rc, out, err = self._call_with_path("", "grep", "app", "main", "yaml")
        self.assertEqual((rc, out), (code.EXIT_GIT_UNUSABLE, ""))
        self.assertIn("git could not run: git not found on PATH", err)
        self.assertIn(code.GIT_HINT, err)

    def test_not_executable_git_is_git_not_usable(self):
        (self.bin / "git").write_text("#!/bin/sh\nexit 0\n")      # no execute bit
        rc, _, err = self._call_with_path(str(self.bin), "grep", "app", "main", "yaml")
        self.assertEqual(rc, code.EXIT_GIT_UNUSABLE)
        self.assertIn(code.GIT_HINT, err)

    def test_unreadable_ref_is_exit_2_without_the_git_hint(self):
        (self.repo / ".git" / "objects").rename(self.repo / ".git" / "objects-gone")
        rc, out, err = call(self.out, "grep", "app", "main", "yaml")
        self.assertEqual((rc, out), (code.EXIT_UNREADABLE, ""))
        self.assertIn("code: ", err)
        self.assertNotIn(code.GIT_HINT, err)
        self.assertNotIn("no match in", out + err)

    def test_working_git_still_separates_match_and_no_match(self):
        self.assertIsNone(code.git_unusable_reason())
        self.assertEqual(call(self.out, "grep", "app", "main", "yaml")[0], 0)
        self.assertEqual(call(self.out, "grep", "app", "main", "absent-pattern")[0], code.EXIT_NO_MATCH)


if __name__ == "__main__":
    unittest.main()
