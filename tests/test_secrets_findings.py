"""Redacted findings: keyed value_id, key handling, branches, liveness, age.

Assertions never print a planted or generated secret value: they compare field names, class letters,
branch lists, ints and booleans, or use fixed messages.
"""
from __future__ import annotations

import json
import os
import random
import stat
import string
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from sbomaudit.secrets import classify as cl
from sbomaudit.secrets import findings as fi
from tests import secrets_fixture as fx
from tests.helpers import make_repo

CLASSES = cl.load_classes()


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, text=True,
                          capture_output=True).stdout


def _row(repo: Path, rule_id: str, file: str, secret: str, line: int, commit: str) -> dict:
    """A gitleaks-shaped row, with the keys redact must never copy."""
    return {"RuleID": rule_id, "Description": "d", "StartLine": line, "EndLine": line,
            "Match": f"x={secret}", "Secret": secret, "File": file, "Commit": commit,
            "Entropy": 4.5, "Author": "Test", "Email": "test@example.invalid",
            "Date": datetime.fromtimestamp(int(_git(repo, "log", "-1", "--format=%ct", commit)),
                                           timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "Message": f"msg {secret}", "Tags": [],
            "Fingerprint": f"{commit}:{file}:{rule_id}:{line}"}


class FindingsTest(unittest.TestCase):
    def test_value_id_is_keyed_and_short(self):
        a, b = b"a" * 32, b"b" * 32
        self.assertEqual(len(fi.value_id(a, "value-one")), 16)
        self.assertEqual(fi.value_id(a, "value-one"), fi.value_id(a, "value-one"))
        self.assertNotEqual(fi.value_id(a, "value-one"), fi.value_id(b, "value-one"))
        self.assertNotEqual(fi.value_id(a, "value-one"), fi.value_id(a, "value-two"))

    def test_load_key_env_hex_wins_then_file_then_generated_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "security"
            self.assertTrue(fi.load_key(out, env={fi.KEY_ENV: "ab" * 32}) == bytes.fromhex("ab" * 32),
                            "env key mismatch")
            self.assertFalse((out / fi.KEY_FILE).exists())
            with self.assertRaises(ValueError) as ctx:
                fi.load_key(out, env={fi.KEY_ENV: "zz"})
            self.assertNotIn("zz", str(ctx.exception))
            key = fi.load_key(out, env={})
            self.assertEqual(len(key), 32)
            path = out / fi.KEY_FILE
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertTrue(path.read_bytes() == key, "key file mismatch")
            self.assertTrue(fi.load_key(out, env={}) == key, "key not reloaded from file")
            self.assertTrue(fi.load_key(out, env={fi.KEY_ENV: "cd" * 32}) == bytes.fromhex("cd" * 32),
                            "env key mismatch")

    def test_load_key_rejects_short_key_material_without_echoing_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "security"
            with self.assertRaises(ValueError) as ctx:
                fi.load_key(out, env={fi.KEY_ENV: "ab12"})
            self.assertEqual(str(ctx.exception), f"{fi.KEY_ENV} is too short")
            path = out / fi.KEY_FILE
            path.parent.mkdir(parents=True)
            path.write_bytes(b"")
            with self.assertRaises(ValueError) as ctx:
                fi.load_key(out, env={})
            self.assertTrue(str(ctx.exception).endswith("is too short"), "short key file accepted")

    def test_redact_has_exactly_fields_and_no_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = fx.write_fixture_portfolio(Path(tmp))
            repo = root / "alpha-app"
            key = next(k for k in fx.REPOS["alpha-app"]
                       if k not in (fx.HISTORY_ONLY, "database-url-password"))
            planted = fx.PLANTED[key]
            commit = _git(repo, "log", "--format=%H", "--", planted.file).splitlines()[0]
            lines = (repo / planted.file).read_text().splitlines()
            line = next(i for i, text in enumerate(lines, 1) if planted.value in text)
            row = _row(repo, planted.rule_id, planted.file, planted.value, line, commit)
            now = datetime.now(timezone.utc)
            finding = fi.redact(row, repo_name="alpha-app", repo=repo, key=b"k" * 32,
                                classes=CLASSES, now=now)
            self.assertEqual(set(finding), set(fi.FIELDS))
            offending = fi.assert_redacted(json.dumps(finding), fx.PLANTED.values())
            self.assertEqual(len(offending), 0, "output not redacted")
            self.assertEqual(finding["class"], planted.expected_class)
            self.assertIs(finding["live_in_tree"], True)
            self.assertIn("main", finding["branches"])
            self.assertEqual(finding["status"], "open")
            self.assertEqual(finding["line"], line)
            self.assertEqual(finding["value_id"], fi.value_id(b"k" * 32, planted.value))

    def test_assert_redacted_flags_value_and_any_window(self):
        planted = fx.PLANTED["fal-key"]
        self.assertGreater(len(fi.assert_redacted(f"x {planted.value} y", [planted])), 0,
                           "full value not flagged")
        self.assertGreater(len(fi.assert_redacted(planted.core[7:12], [planted])), 0,
                           "window not flagged")
        self.assertEqual(len(fi.assert_redacted(planted.core[7:11], [planted])), 0, "4 chars flagged")
        hex_core = fx.PLANTED["inngest-signing-key"]
        self.assertGreater(len(fi.assert_redacted("x" + hex_core.core[20:28] + "x", [hex_core])), 0,
                           "8-char hex window not flagged")
        self.assertEqual(len(fi.assert_redacted("x" + hex_core.core[20:27] + "x", [hex_core])), 0,
                         "a 7-char hex run (commit-hash noise) flagged")
        short = fx.Planted(value="abcd", core="abcd", expected_class="B", file="f", rule_id="r")
        with self.assertRaises(ValueError) as ctx:
            fi.assert_redacted("text", [short])
        self.assertEqual(str(ctx.exception), "planted core too short")

    def test_branches_live_in_tree_and_age(self):
        value = "ghp_" + "".join(random.Random(1).choices(string.ascii_letters + string.digits, k=36))
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp), "r", {"app.env": f"TOKEN={value}\n"})
            commit = _git(repo, "rev-parse", "HEAD").strip()
            _git(repo, "branch", "feature")
            (repo / "app.env").write_text("TOKEN=\n")
            _git(repo, "commit", "-q", "-am", "drop on main")
            row = _row(repo, "github-pat", "app.env", value, 1, commit)
            now = datetime.now(timezone.utc)

            def run():
                return fi.redact(row, repo_name="r", repo=repo, key=b"k" * 32, classes=CLASSES, now=now)

            finding = run()
            self.assertEqual(finding["branches"], ["feature", "main"])
            self.assertIs(finding["live_in_tree"], True)
            self.assertEqual(finding["age_days"], 0)
            _git(repo, "checkout", "-q", "feature")
            (repo / "app.env").write_text("TOKEN=\n")
            _git(repo, "commit", "-q", "-am", "drop on feature")
            _git(repo, "checkout", "-q", "main")
            finding = run()
            self.assertEqual(finding["branches"], ["feature", "main"])
            self.assertIs(finding["live_in_tree"], False)
            row["Date"] = "not a date"
            self.assertIsNone(run()["age_days"])

    def test_value_only_on_remote_branch_is_live(self):
        value = "ghp_" + "".join(random.Random(2).choices(string.ascii_letters + string.digits, k=36))
        with tempfile.TemporaryDirectory() as tmp:
            origin = make_repo(Path(tmp), "origin", {"README.md": "x\n"})
            _git(origin, "checkout", "-q", "-b", "feature")
            (origin / "app.env").write_text(f"TOKEN={value}\n")
            _git(origin, "add", "-A")
            _git(origin, "commit", "-q", "-m", "plant")
            commit = _git(origin, "rev-parse", "HEAD").strip()
            _git(origin, "checkout", "-q", "main")
            clone = Path(tmp) / "clone"
            subprocess.run(["git", "clone", "-q", str(origin), str(clone)], check=True,
                           capture_output=True)
            self.assertNotIn("feature", _git(clone, "branch", "--format=%(refname:short)").split())
            row = _row(clone, "github-pat", "app.env", value, 1, commit)
            finding = fi.redact(row, repo_name="clone", repo=clone, key=b"k" * 32, classes=CLASSES,
                                now=datetime.now(timezone.utc))
            self.assertEqual(finding["branches"], ["feature"])
            self.assertIs(finding["live_in_tree"], True)
            self.assertNotIn("HEAD", finding["branches"])
            self.assertNotIn("origin/HEAD", finding["branches"])

    def test_non_utf8_file_does_not_crash_and_is_live(self):
        value = "ghp_" + "".join(random.Random(3).choices(string.ascii_letters + string.digits, k=36))
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp), "r", {"README.md": "x\n"})
            (repo / "legacy.properties").write_bytes(b"name=caf\xe9\ntoken=" + value.encode() + b"\n")
            _git(repo, "add", "-A")
            _git(repo, "commit", "-q", "-m", "latin-1 file")
            commit = _git(repo, "rev-parse", "HEAD").strip()
            row = _row(repo, "github-pat", "legacy.properties", value, 2, commit)
            finding = fi.redact(row, repo_name="r", repo=repo, key=b"k" * 32, classes=CLASSES,
                                now=datetime.now(timezone.utc))
            self.assertIs(finding["live_in_tree"], True)
            row["Secret"] = ""
            empty = fi.redact(row, repo_name="r", repo=repo, key=b"k" * 32, classes=CLASSES,
                              now=datetime.now(timezone.utc))
            self.assertIs(empty["live_in_tree"], False)

    def test_history_only_value_is_not_live(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = fx.write_fixture_portfolio(Path(tmp)) / "alpha-app"
            planted = fx.PLANTED[fx.HISTORY_ONLY]
            commit = _git(repo, "log", "--format=%H", "--diff-filter=A", "--", planted.file).split()[0]
            row = _row(repo, planted.rule_id, planted.file, planted.value, 1, commit)
            finding = fi.redact(row, repo_name="alpha-app", repo=repo, key=b"k" * 32, classes=CLASSES,
                                now=datetime.now(timezone.utc))
            self.assertIs(finding["live_in_tree"], False)
            self.assertIn("main", finding["branches"])


if __name__ == "__main__":
    unittest.main()
