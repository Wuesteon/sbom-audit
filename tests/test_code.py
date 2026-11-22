"""`code grep|show|files`: read-only access to a project's committed code on an audited branch."""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import assess, cli, code, gitio, sensitive
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


FAKE = "FAKE-not-a-real-token-0000"          # obviously fake; must never be printed


class WithheldTests(unittest.TestCase):
    """Secret-bearing paths (one list with the headless deny rules) and recorded secrets findings stay out."""

    FILES = {
        "src/app.js": "const a = 1;\nconst token = 'FAKE-not-a-real-token-0000';\nconst b = 2;\n",
        "src/moved.js": "const token = 'FAKE-not-a-real-token-0000';\n",
        ".env": f"TOKEN={FAKE}\n",
        "deploy/.ENV.production": f"TOKEN={FAKE}\n",
        "certs/server.pem": f"{FAKE}\n",
        "home/.ssh/config": f"Host {FAKE}\n",
        "ops/.docker/config.json": f"{{\"auth\": \"{FAKE}\"}}\n",
        "credentials.json": f"{FAKE}\n",
        "README.md": "hello\n",
        "security/.cache/key": "fingerprint-key\n",
    }

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.repo = make_repo(self.root, "app", self.FILES)
        self.out = self.root / "security"
        self.out.mkdir()
        first = _git(self.repo, "rev-parse", "HEAD").strip()
        # moved.js: the secret moves one line down in a later commit; the finding points at the old commit.
        (self.repo / "src" / "moved.js").write_text("// header\n" + self.FILES["src/moved.js"])
        _git(self.repo, "commit", "-q", "-am", "move")
        findings = [{"repo": "app", "file": "src/app.js", "line": 2, "commit": first, "live_in_tree": True},
                    {"repo": "app", "file": "src/moved.js", "line": 1, "commit": first, "live_in_tree": True},
                    {"repo": "other", "file": "README.md", "line": 1, "commit": first, "live_in_tree": True}]
        (self.out / "secrets.json").write_text(json.dumps({"findings": findings}))

    def tearDown(self):
        self._tmp.cleanup()

    def test_shared_list_with_the_headless_deny_rules(self):
        for rule in sensitive.deny_rules():
            self.assertIn(rule, assess.DENY_RULES)
        for path in (".env", "a/.env.local", "x/server.PEM", "k.key", "id_ed25519", "c.p12", "c.pfx", ".npmrc",
                     ".pypirc", ".netrc", ".git-credentials", "credentials.json", "h/.ssh/known_hosts",
                     ".aws/config", "ops/.docker/config.json"):
            self.assertTrue(sensitive.is_sensitive(path), path)
        for path in ("src/env.js", "README.md", "docker/config.json", "ssh/config", "keys.js"):
            self.assertFalse(sensitive.is_sensitive(path), path)

    def test_show_refuses_secret_bearing_paths(self):
        for path in (".env", "deploy/.ENV.production", "certs/server.pem", "home/.ssh/config",
                     "ops/.docker/config.json", "credentials.json"):
            rc, out, err = call(self.out, "show", "app", "main", path)
            self.assertEqual((rc, out), (code.EXIT_UNREADABLE, ""), path)
            self.assertIn("withheld", err)
            self.assertNotIn(FAKE, out + err)

    def test_grep_never_searches_them_and_says_so(self):
        rc, out, err = call(self.out, "grep", "app", "main", "FAKE-not")
        self.assertNotIn(FAKE, out + err)
        for path in (".env", ".ENV", "server.pem", ".ssh", ".docker", "credentials"):
            self.assertNotIn(path, out + err)
        self.assertIn("withheld, not searched: 7 files", out)
        # the masked lines are not searched either, so the exit code does not reveal a match on them
        self.assertEqual(rc, code.EXIT_NO_MATCH, out)
        self.assertIn("no match", out)

    def test_grep_withholds_a_recorded_finding_line_without_revealing_a_match(self):
        rc, out, _ = call(self.out, "grep", "app", "main", "const")
        self.assertEqual(rc, 0)
        lines = out.splitlines()
        self.assertIn("src/app.js:1:const a = 1;", lines)
        self.assertIn("src/app.js:3:const b = 2;", lines)
        self.assertFalse(any(line.startswith("src/app.js:2:") for line in lines), out)
        self.assertNotIn("src/moved.js", "\n".join(l for l in lines if not l.startswith("…")))
        self.assertIn("withheld, not searched: 7 files, 1 line", out)

    def test_show_masks_a_recorded_finding_line(self):
        rc, out, _ = call(self.out, "show", "app", "main", "src/app.js")
        self.assertEqual(rc, 0)
        self.assertNotIn(FAKE, out)
        lines = out.splitlines()
        self.assertEqual(lines[0], "1: const a = 1;")
        self.assertTrue(lines[1].startswith("2: [withheld"), out)
        self.assertEqual(lines[2], "3: const b = 2;")
        self.assertIn("withheld: 1 line", lines[-1])

    def test_show_withholds_a_changed_file_that_still_holds_a_live_finding(self):
        rc, out, err = call(self.out, "show", "app", "main", "src/moved.js")
        self.assertEqual((rc, out), (code.EXIT_UNREADABLE, ""))
        self.assertIn("withheld", err)
        self.assertNotIn(FAKE, err)

    def test_files_omits_secret_bearing_paths_and_the_cache(self):
        rc, out, _ = call(self.out, "files", "app", "main")
        self.assertEqual(rc, 0)
        names = out.splitlines()
        self.assertIn("README.md", names)
        self.assertIn("src/app.js", names)
        for name in names:
            self.assertFalse(sensitive.is_sensitive(name), name)
            self.assertFalse(name.startswith("security/.cache"), name)
        self.assertIn("withheld: 6 names", out)

    def test_findings_of_another_project_change_nothing(self):
        rc, out, _ = call(self.out, "show", "app", "main", "README.md")
        self.assertEqual((rc, out), (0, "1: hello\n"))


class PathspecTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.repo = make_repo(self.root, "app", {"src/a.js": "needle\n", "lib/b.js": "needle\n",
                                                 "security/.cache/raw": "needle\n"})
        self.out = self.root / "security"
        self.out.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def test_leading_whitespace_does_not_hide_pathspec_magic(self):
        for path in (" :!src", "\t:(top)", " :/"):
            rc, out, err = call(self.out, "grep", "app", "main", "needle", "--path", path)
            self.assertEqual((rc, out), (code.EXIT_UNREADABLE, ""), path)
            self.assertIn("not a repository-relative path", err)

    def test_paths_are_literal_not_globs(self):
        rc, out, _ = call(self.out, "grep", "app", "main", "needle", "--path", "*.js")
        self.assertEqual(rc, code.EXIT_NO_MATCH, out)
        rc, out, _ = call(self.out, "grep", "app", "main", "needle", "--path", "src")
        self.assertEqual((rc, out.strip()), (0, "src/a.js:1:needle"))
        rc, out, _ = call(self.out, "files", "app", "main", "*.js")
        self.assertEqual(out.strip(), "")

    def test_files_never_lists_the_cache(self):
        rc, out, _ = call(self.out, "files", "app", "main")
        self.assertEqual(rc, 0)
        self.assertNotIn("security/.cache", out)
        rc, out, err = call(self.out, "files", "app", "main", "security")
        self.assertNotIn("raw", out + err)

    def test_grep_timeout_is_unreadable_not_no_match(self):
        real = subprocess.run

        def slow(cmd, *a, **kw):
            if "grep" in cmd:
                self.assertEqual(kw.get("timeout"), gitio.GIT_TIMEOUT)
                raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
            return real(cmd, *a, **kw)

        with mock.patch.object(code.subprocess, "run", side_effect=slow):
            rc, out, err = call(self.out, "grep", "app", "main", "needle")
        self.assertEqual((rc, out), (code.EXIT_UNREADABLE, ""))
        self.assertIn("repository or ref unreadable", err)
        self.assertIn("timed out", err)
        self.assertNotIn("no match", out + err)


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
