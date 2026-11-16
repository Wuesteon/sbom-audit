"""`settings`: opt-in autonomous mode and session hook in ~/.claude/settings.json (a scratch home here)."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sbomaudit import integration

CLI = Path("/home/u/.claude/plugins/cache/m/sbom-audit/1.2.1/scripts/sbom_audit_cli.py")
NEWER = Path("/home/u/.claude/plugins/cache/m/sbom-audit/1.2.2/scripts/sbom_audit_cli.py")


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        self.settings = self.home / ".claude" / "settings.json"
        self.settings.parent.mkdir(parents=True)
        self.user = {"permissions": {"allow": ["Bash(ls *)", "WebFetch(domain:osv.dev)"]},
                     "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "echo mine"}]}]},
                     "theme": "dark"}
        self.settings.write_text(json.dumps(self.user))

    def tearDown(self):
        self._tmp.cleanup()

    def load(self):
        return json.loads(self.settings.read_text())

    def test_rules_cover_exactly_the_local_subcommands(self):
        rules = integration.autonomy_rules(CLI)
        bash = [r for r in rules if r.startswith("Bash(")]
        self.assertEqual(len(bash), 2 * len(integration.AUTONOMOUS_SUBCOMMANDS))
        for rule in bash:
            self.assertTrue(rule.startswith(f"Bash(python3 {CLI} ") or rule.startswith(f'Bash(python3 "{CLI}" '), rule)
            self.assertNotIn("*", rule[:-3], rule)                       # no wildcard but the trailing one
        for never in integration.NEVER_AUTONOMOUS:
            self.assertFalse(any(f" {never} *)" in r for r in rules), never)
        self.assertIn("WebSearch", rules)
        self.assertNotIn("WebFetch", rules)                              # never unscoped

    def test_on_then_off_restores_the_users_settings(self):
        integration.set_autonomy(True, self.home, CLI)
        allow = self.load()["permissions"]["allow"]
        self.assertEqual(allow[:2], self.user["permissions"]["allow"])
        self.assertIn(f'Bash(python3 "{CLI}" run *)', allow)
        self.assertEqual(allow.count("WebFetch(domain:osv.dev)"), 1)
        self.assertTrue((self.home / ".claude" / "settings.json.sbom-audit.bak").exists())
        integration.set_autonomy(False, self.home, CLI)
        self.assertEqual(self.load(), self.user)                         # the user's own osv.dev rule stays

    def test_refresh_moves_rules_to_the_new_path_only(self):
        integration.set_autonomy(True, self.home, CLI)
        lines = integration.refresh(self.home, NEWER)
        allow = self.load()["permissions"]["allow"]
        self.assertTrue(lines)
        self.assertFalse(any(str(CLI) in r for r in allow))
        self.assertIn(f'Bash(python3 "{NEWER}" status *)', allow)
        self.assertEqual(integration.refresh(self.home, NEWER), [])

    def test_refresh_adds_nothing_without_opt_in(self):
        self.assertEqual(integration.refresh(self.home, NEWER), [])
        self.assertEqual(self.load(), self.user)

    def test_session_hook_on_runs_and_off_removes(self):
        integration.set_session_hook(True, self.home)
        integration.set_session_hook(True, self.home)                    # idempotent
        entries = self.load()["hooks"]["SessionStart"]
        self.assertEqual(len(entries), 2)
        ours = entries[1]
        self.assertEqual(ours["matcher"], "startup|resume|clear")
        script = self.home / ".claude" / "sbom-audit" / "session-start.py"
        self.assertEqual(ours["hooks"][0]["command"], f'python3 "{script}"')
        self.assertIn(f"VERSION = {integration.plugin_version()!r}", script.read_text())
        proc = subprocess.run([sys.executable, str(script)], input="{}", capture_output=True, text=True,
                              cwd=self.home, timeout=10)
        self.assertEqual(proc.returncode, 0)
        integration.set_session_hook(False, self.home)
        self.assertEqual(self.load(), self.user)
        self.assertFalse(script.exists())

    def test_invalid_settings_change_nothing(self):
        self.settings.write_text("{not json")
        with self.assertRaises(integration.SettingsError):
            integration.set_autonomy(True, self.home, CLI)
        self.assertEqual(self.settings.read_text(), "{not json")

    def test_status_lines(self):
        self.assertIn("off", integration.status_lines(self.home, CLI)[0])
        integration.set_autonomy(True, self.home, CLI)
        self.assertIn("on (", integration.status_lines(self.home, CLI)[0])
        self.assertIn("older plugin path", integration.status_lines(self.home, NEWER)[0])


if __name__ == "__main__":
    unittest.main()
