"""Release surface: CI workflow, changelog entries and README sections for 1.1.0 (and the 1.0.0 entry it keeps)."""
from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from tests.secrets_fixture import EVAL_GRADER, PLANTED, eval_windows, write_eval_graders

ROOT = Path(__file__).resolve().parents[1]
# every committed text output a planted value could leak into (the redaction rule covers them all)
PUBLIC_TEXT = ("README.md", "CONTRIBUTING.md", "CHANGELOG.md", "docs", "evals")
VERSION = json.loads((ROOT / "plugin" / ".claude-plugin" / "plugin.json").read_text())["version"]


class ReleaseTests(unittest.TestCase):
    def test_ci_workflow_mentions_required_steps(self):
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        for needle in ("unittest discover", "plugin validate --strict", "gitleaks", "sbom-audit--v",
                       "3.11", "3.12", "contents: write"):
            self.assertIn(needle, ci, needle)
        self.assertNotIn("plugin eval", ci, "evals are run by hand before a release, not in CI")
        self.assertNotIn("secrets.", ci.replace("secrets.GITHUB_TOKEN", ""), "CI needs no secrets")

    def test_changelog_has_1_1_0_section(self):
        text = (ROOT / "CHANGELOG.md").read_text()
        self.assertRegex(text, r"\n## 1\.1\.0 — 2026-11-10\n")
        self.assertLess(text.find("## 1.1.0"), text.find("## 1.0.0"), "newest entry first")
        section = text.split("## 1.1.0", 1)[1].split("\n## ", 1)[0]
        for needle in ("full secrets rescan", "setup --schedule weekly", "new", "/sbom-audit:hosts"):
            self.assertIn(needle, section, needle)

    def test_changelog_has_1_1_1_section(self):
        text = (ROOT / "CHANGELOG.md").read_text()
        self.assertRegex(text, r"\n## 1\.1\.1 — 2026-11-10\n")
        self.assertLess(text.find("## 1.1.1"), text.find("## 1.1.0"), "newest entry first")
        section = text.split("## 1.1.1", 1)[1].split("\n## ", 1)[0]
        for needle in ("rootless", "section-failed:containers", "Collector version 2", "hosts bootstrap"):
            self.assertIn(needle, section, needle)

    def test_changelog_has_1_2_0_section(self):
        text = (ROOT / "CHANGELOG.md").read_text()
        self.assertRegex(text, r"\n## 1\.2\.0 — 2026-11-16\n")
        self.assertNotIn("## Unreleased", text)
        self.assertLess(text.find("## 1.2.0"), text.find("## 1.1.1"), "newest entry first")
        section = text.split("## 1.2.0", 1)[1].split("\n## ", 1)[0]
        for needle in ("issues.json", "--max-priority", "secrets resolve", "adversarial verification", "`assess` case"):
            self.assertIn(needle, section, needle)

    def test_changelog_has_1_2_1_section(self):
        text = (ROOT / "CHANGELOG.md").read_text()
        self.assertRegex(text, r"^# Changelog\n\n## 1\.2\.1 — 2026-11-16\n")
        section = text.split("## 1.2.1", 1)[1].split("\n## ", 1)[0]
        for needle in ("/sbom-audit:settings", "autonomous", "code grep", "plugin/", "hook on"):
            self.assertIn(needle, section, needle)
        self.assertEqual(VERSION, "1.2.1")

    def test_changelog_has_1_0_0_section(self):
        text = (ROOT / "CHANGELOG.md").read_text()
        self.assertRegex(text, r"\n## 1\.0\.0 — \d{4}-\d{2}-\d{2}\n")
        self.assertLess(text.find("## 1.0.0"), text.find("## 0.1.0 — 2026-11-06"), "newest entry first")
        section = text.split("## 1.0.0", 1)[1].split("\n## ", 1)[0]
        self.assertGreaterEqual(section.count("\n- "), 17, "one bullet per plan task")

    def test_readme_sections(self):
        readme = (ROOT / "README.md").read_text()
        for skill in ("setup", "run", "status", "assess", "lookup", "incident", "vex", "secrets", "schedule", "hosts"):
            self.assertIn(f"/sbom-audit:{skill}", readme, skill)
        self.assertIn("sbom-audit@wuesteon-plugins", readme)
        self.assertIn("docs/reference.md", readme)
        # the README is the landing page; the manual lives in docs/reference.md
        text = readme + (ROOT / "docs" / "reference.md").read_text()
        for needle in ("## Scheduler", "## Secrets", "STATUS.md", "status.json", "SECRETS.md", "secrets.json",
                       "secrets-decisions.toml", "## Hosts", "HOSTS.md", "hosts-decisions.toml", "api.github.com", "sbom-audit@wuesteon-plugins",
                       "Art. 13(1)", "Annex I Part II", "Art. 14", "assess_budget_usd", "proposal waiting:"):
            self.assertIn(needle, text, needle)
        for skill in ("setup", "run", "status", "assess", "lookup", "incident", "vex", "secrets", "schedule", "hosts"):
            self.assertIn(f"/sbom-audit:{skill}", text, skill)
        self.assertNotIn("commands/", text, "commands/ is gone; skills/ replaced it")
        self.assertNotRegex(text, r"\*\*Status:\*\* 0\.1\.0")


    def test_actions_template_is_pinned_and_verifies_downloads(self):
        text = (ROOT / "plugin" / "templates" / "github-actions" / "sbom-audit.yml").read_text()
        self.assertIn("sha256", text)
        self.assertIn("--ignore-missing", text)
        uses = [line.strip() for line in text.splitlines() if line.strip().startswith("- uses:")]
        self.assertTrue(uses)
        for line in uses:
            self.assertRegex(line, r"@[0-9a-f]{40}( +# v\d+\.\d+\.\d+)?$", line)
            self.assertNotRegex(line, r"@v\d+\s*$", line)
        self.assertIn("gh auth setup-git", text)
        self.assertIn("SBOM_AUDIT_GIT_PROTOCOL: https", text)


class EvalLeakGraderTests(unittest.TestCase):
    def test_leak_grader_is_current_and_covers_every_leak(self):
        committed = EVAL_GRADER.read_text()
        with tempfile.TemporaryDirectory() as tmp:
            fresh = write_eval_graders(Path(tmp) / "no-leak.md").read_text()
        self.assertEqual(committed, fresh, "evals/secrets/graders/no-leak.md is stale: rerun write_eval_graders()")
        pattern = re.compile(committed.split("\n---\n", 1)[1].strip())
        for key in sorted(PLANTED):
            value, core = PLANTED[key].value, PLANTED[key].core
            self.assertTrue(pattern.search(value), f"{key}: full value not caught")
            windows = eval_windows(core)
            self.assertTrue(windows, f"{key}: no windows")
            span = 2 * max(len(w) for w in windows) - 1
            uncovered = [i for i in range(len(core) - span + 1) if not pattern.search(core[i:i + span])]
            self.assertEqual(uncovered, [], f"{key}: a leaked run of {span} characters would go unnoticed")
            short_hex = [w for w in windows if len(w) < 8 and set(w) <= set("0123456789abcdef")]
            self.assertEqual(short_hex, [], f"{key}: a short all-hex window would match commit hashes")

    def test_no_planted_window_in_committed_text(self):
        files = []
        for entry in PUBLIC_TEXT:
            path = ROOT / entry
            files += [p for p in sorted(path.rglob("*")) if p.is_file() and "results" not in p.parts] \
                if path.is_dir() else [path]
        self.assertIn(EVAL_GRADER, files)
        for path in files:
            text = path.read_bytes().decode("utf-8", errors="ignore")
            for key in sorted(PLANTED):
                core = PLANTED[key].core
                hit = any(core[i:i + 5] in text for i in range(len(core) - 4))
                self.assertFalse(hit, f"{key}: a 5-character window is in {path.relative_to(ROOT)}")


if __name__ == "__main__":
    unittest.main()
