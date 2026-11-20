"""Headless assessment: read-only `claude -p` run that writes only a proposal file."""
from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sbomaudit import assess, scheduler
from sbomaudit.config import Config

NOW = datetime(2026, 11, 8, 3, 0, tzinfo=timezone.utc)
HEADER = "<!-- proposal written by headless assessment, not applied; review with /sbom-audit:assess -->"
SKILL = "---\nname: assess\ndescription: x\n---\nAssess the audit.\nStep two.\n"


def make_cfg_in(tmp: Path, **schedule) -> Config:
    cfg = Config(out=tmp / "security", root=tmp, mode="portfolio", fetch=False)
    cfg.out.mkdir(parents=True)
    for key, value in schedule.items():
        setattr(cfg.schedule, key, value)
    return cfg


def make_plugin(tmp: Path, body: str | None = SKILL) -> Path:
    root = tmp / "plugin"
    if body is not None:
        (root / "skills" / "assess").mkdir(parents=True)
        (root / "skills" / "assess" / "SKILL.md").write_text(body, encoding="utf-8")
    return root


def reply(result="PROPOSAL TEXT", cost=0.42, code=0, stdout=None):
    text = stdout if stdout is not None else json.dumps({"result": result, "total_cost_usd": cost})
    return SimpleNamespace(returncode=code, stdout=text, stderr="")


def which_claude(tool):
    return f"/stub/bin/{tool}"


class FakeRun:
    """Stub for subprocess.run: the probe call answers `probe`, every other call answers `main`."""
    def __init__(self, main=None, probe="sbom-audit status"):
        self.calls = []
        self.main = main if main is not None else reply()
        self.probe = probe

    def __call__(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        if cmd[2] == "/sbom-audit:status":
            if isinstance(self.probe, Exception):
                raise self.probe
            return reply(self.probe)
        if isinstance(self.main, Exception):
            raise self.main
        return self.main

    def main_calls(self):
        return [c for c in self.calls if c[0][2] != "/sbom-audit:status"]


class AssessTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_command_has_read_only_tools_and_no_max_turns(self):
        cfg = make_cfg_in(self.tmp, assess_budget_usd=2.5)
        cli_path = Path("/abs/plugin/scripts/sbom_audit_cli.py")
        cmd = assess.command(cfg, cli_path, "PROMPT")
        self.assertEqual(cmd[:3], ["claude", "-p", "PROMPT"])
        tools = cmd[cmd.index("--allowedTools") + 1]
        out = cfg.out.resolve().as_posix()
        self.assertNotIn("Read,", tools)
        self.assertNotIn("WebFetch,", tools)
        self.assertNotIn("WebSearch", tools)
        self.assertEqual(tools.split(","), [
            f"Read(/{out}/**)",                       # the evidence folder only, never the portfolio root
            "WebFetch(domain:osv.dev)", "WebFetch(domain:api.osv.dev)", "WebFetch(domain:api.github.com)",
            "WebFetch(domain:nvd.nist.gov)", "WebFetch(domain:services.nvd.nist.gov)",
            "WebFetch(domain:www.cisa.gov)", "WebFetch(domain:endoflife.date)",
            "WebFetch(domain:security-tracker.debian.org)", "WebFetch(domain:ubuntu.com)",
            "Bash(python3 /abs/plugin/scripts/sbom_audit_cli.py lookup:*)",
            'Bash(python3 "/abs/plugin/scripts/sbom_audit_cli.py" lookup:*)',
            "Bash(python3 /abs/plugin/scripts/sbom_audit_cli.py incident:*)",
            'Bash(python3 "/abs/plugin/scripts/sbom_audit_cli.py" incident:*)',
            "Bash(python3 /abs/plugin/scripts/sbom_audit_cli.py status:*)",
            'Bash(python3 "/abs/plugin/scripts/sbom_audit_cli.py" status:*)',
            "Bash(python3 /abs/plugin/scripts/sbom_audit_cli.py code:*)",
            'Bash(python3 "/abs/plugin/scripts/sbom_audit_cli.py" code:*)'])
        self.assertNotIn(f"Read(/{cfg.root.resolve().as_posix()}/**)", tools)
        self.assertEqual(cmd[cmd.index("--max-budget-usd") + 1], "2.5")
        self.assertEqual(cmd[cmd.index("--output-format") + 1], "json")
        self.assertNotIn("--max-turns", cmd)
        self.assert_hard_limits(cmd)
        self.assertEqual(cmd.count("--disallowedTools"), 1)
        self.assertEqual(cmd[cmd.index("--disallowedTools") + 1].split(","), [
            "Read(./.cache/**)", "Read(//**/.cache/**)", "Read(//**/.env*)", "Read(//**/*.pem)",
            "Read(//**/*.key)", "Read(//**/id_*)", "Read(//**/*.p12)", "Read(//**/*.pfx)", "Read(//**/.npmrc)",
            "Read(//**/.pypirc)", "Read(//**/.netrc)", "Read(//**/.git-credentials)", "Read(//**/credentials*)",
            "Read(//**/.ssh/**)", "Read(//**/.aws/**)", "Read(//**/.docker/config.json)"])

    def test_documented_permissions_match_the_code(self):
        """The skill text and docs/reference.md name exactly the hosts and deny rules the child gets."""
        repo = Path(__file__).resolve().parent.parent
        skill = (repo / "plugin" / "skills" / "assess" / "SKILL.md").read_text(encoding="utf-8")
        reference = (repo / "docs" / "reference.md").read_text(encoding="utf-8")
        for text in (skill, reference):
            for host in assess.HEADLESS_FETCH_DOMAINS:
                self.assertIn(f"`{host}`", text, host)
        for rule in assess.DENY_RULES:
            self.assertIn(f"`{rule}`", reference, rule)
        self.assertIn("no WebSearch", skill)

    def assert_hard_limits(self, cmd):
        tools = cmd[cmd.index("--tools") + 1].split(",")
        self.assertEqual(tools, ["Read", "Grep", "Glob", "WebFetch", "Bash"])
        for banned in ("Write", "Edit", "NotebookEdit"):
            self.assertNotIn(banned, tools)
        self.assertEqual(cmd[cmd.index("--permission-mode") + 1], "dontAsk")
        self.assertEqual(cmd[cmd.index("--permission-prompts") + 1], "none")
        self.assertIn("--strict-mcp-config", cmd)
        self.assertNotIn("--restricted", cmd)

    def test_proposal_written_with_header_and_logged(self):
        cfg = make_cfg_in(self.tmp)
        run = FakeRun()
        res = assess.run_headless(cfg, cfg.out, make_plugin(self.tmp), run=run, which=which_claude, now=NOW)
        self.assertEqual(res, {"status": "written", "path": "reports/2026-11-08-assessment-proposal.md",
                               "reason": None, "cost_usd": 0.42})
        text = (cfg.out / res["path"]).read_text(encoding="utf-8")
        self.assertEqual(text.splitlines()[0], HEADER)
        self.assertIn("PROPOSAL TEXT", text)
        cmd, kwargs = run.main_calls()[0]
        self.assertEqual(kwargs["timeout"], 900)
        self.assertEqual(list(cfg.out.rglob("*.md")), [cfg.out / res["path"]])   # nothing else written
        self.assertEqual(list((cfg.out / "reports").iterdir()), [cfg.out / res["path"]])   # no tmp left over

    def test_second_run_same_day_overwrites(self):
        cfg = make_cfg_in(self.tmp)
        plugin = make_plugin(self.tmp)
        assess.run_headless(cfg, cfg.out, plugin, run=FakeRun(main=reply("first")), which=which_claude, now=NOW)
        res = assess.run_headless(cfg, cfg.out, plugin, run=FakeRun(main=reply("second")),
                                  which=which_claude, now=NOW)
        text = (cfg.out / res["path"]).read_text(encoding="utf-8")
        self.assertIn("second", text)
        self.assertNotIn("first", text)

    def test_skipped_without_claude_binary(self):
        cfg = make_cfg_in(self.tmp)
        run = FakeRun()
        res = assess.run_headless(cfg, cfg.out, make_plugin(self.tmp), run=run, which=lambda t: None, now=NOW)
        self.assertEqual(res, {"status": "skipped", "path": None, "reason": "claude not on PATH",
                               "cost_usd": None})
        self.assertEqual(run.calls, [])
        self.assertFalse((cfg.out / "reports").exists())

    def test_env_read_only_set_for_child(self):
        cfg = make_cfg_in(self.tmp)
        run = FakeRun()
        assess.run_headless(cfg, cfg.out, make_plugin(self.tmp), run=run, which=which_claude, now=NOW)
        env = run.main_calls()[0][1]["env"]
        self.assertEqual(env["SBOM_AUDIT_READ_ONLY"], "1")
        self.assertIn("PATH", env)
        probe = [c for c in run.calls if c[0][2] == "/sbom-audit:status"]
        self.assertEqual(len(probe), 1)
        self.assertEqual(probe[0][1]["env"]["SBOM_AUDIT_READ_ONLY"], "1")
        root = (self.tmp / "plugin").resolve().as_posix()   # skill bodies call "${CLAUDE_PLUGIN_ROOT}/…"
        self.assertEqual(env["CLAUDE_PLUGIN_ROOT"], root)
        self.assertEqual(probe[0][1]["env"]["CLAUDE_PLUGIN_ROOT"], root)
        for _, kwargs in run.calls:                       # both children run inside the evidence repo
            self.assertEqual(kwargs["cwd"], cfg.out)

    def test_prompt_falls_back_to_skill_body_when_print_mode_lacks_skills(self):
        plugin = make_plugin(self.tmp)
        tail = " Never read, search or list anything under .cache/."
        self.assertEqual(assess.prompt(plugin, skills_work=False), "Assess the audit.\nStep two. --headless" + tail)
        self.assertEqual(assess.prompt(plugin, skills_work=True), "/sbom-audit:assess --headless" + tail)
        cfg = make_cfg_in(self.tmp)
        run = FakeRun(probe="Unknown command")
        assess.run_headless(cfg, cfg.out, plugin, run=run, which=which_claude, now=NOW)
        self.assertEqual(run.main_calls()[0][0][2], "Assess the audit.\nStep two. --headless" + tail)

    def test_fallback_prompt_substitutes_the_absolute_cli_path(self):
        body = ('---\nname: assess\n---\nRun:\npython3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" status\n'
                'python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" lookup x\n'
                'Templates live in ${CLAUDE_PLUGIN_ROOT}/templates.\n')
        plugin = make_plugin(self.tmp, body)
        root = plugin.resolve().as_posix()
        cli = f"{root}/scripts/sbom_audit_cli.py"
        text = assess.prompt(plugin, skills_work=False)
        self.assertNotIn("${CLAUDE_PLUGIN_ROOT}", text)
        self.assertIn(f"python3 {cli} status\n", text)          # unquoted: matches the child's allow rule
        self.assertIn(f"python3 {cli} lookup x\n", text)
        self.assertNotIn(f'"{cli}"', text)
        self.assertIn(f"Templates live in {root}/templates.", text)
        self.assertTrue(text.endswith(" --headless " + assess.CACHE_SENTENCE))
        self.assertEqual(assess.prompt(plugin, skills_work=True), "/sbom-audit:assess --headless " + assess.CACHE_SENTENCE)

    def test_prompt_uses_skill_when_probe_works(self):
        cfg = make_cfg_in(self.tmp)
        run = FakeRun(probe="sbom-audit: nothing yet")
        assess.run_headless(cfg, cfg.out, make_plugin(self.tmp, None), run=run, which=which_claude, now=NOW)
        self.assertEqual(run.main_calls()[0][0][2], "/sbom-audit:assess --headless " + assess.CACHE_SENTENCE)

    def test_missing_skill_file_without_print_mode_skills_is_skipped(self):
        cfg = make_cfg_in(self.tmp)
        run = FakeRun(probe="nope")
        res = assess.run_headless(cfg, cfg.out, make_plugin(self.tmp, None), run=run, which=which_claude, now=NOW)
        self.assertEqual(res, {"status": "skipped", "path": None, "reason": "skills/assess/SKILL.md missing",
                               "cost_usd": None})
        self.assertEqual(run.main_calls(), [])

    def test_probe_result_is_cached_and_preserves_other_state_keys(self):
        cfg = make_cfg_in(self.tmp)
        scheduler.write_state(cfg.out, {"installed": True, "last_fired": "2026-11-01"})
        run = FakeRun()
        env = {"SBOM_AUDIT_READ_ONLY": "1"}
        self.assertTrue(assess.skill_expansion_works(run, cfg.out, env))
        self.assertEqual(scheduler.read_state(cfg.out),
                         {"installed": True, "last_fired": "2026-11-01", "print_mode_skills": True})
        calls = len(run.calls)
        self.assertTrue(assess.skill_expansion_works(run, cfg.out))
        self.assertEqual(len(run.calls), calls)            # cached bool: no second probe
        self.assertEqual(run.calls[0][1]["timeout"], 120)
        probe = run.calls[0][0]
        self.assert_hard_limits(probe)
        self.assertEqual(probe[probe.index("--max-budget-usd") + 1], "0.50")
        self.assertEqual(run.calls[0][1]["cwd"], cfg.out)
        self.assertEqual(run.calls[0][1]["env"]["SBOM_AUDIT_READ_ONLY"], "1")

    def test_cached_false_skips_probe(self):
        cfg = make_cfg_in(self.tmp)
        scheduler.write_state(cfg.out, {"print_mode_skills": False})
        run = FakeRun()
        self.assertFalse(assess.skill_expansion_works(run, cfg.out))
        self.assertEqual(run.calls, [])

    def test_probe_failures_are_false(self):
        runs = {"OSError": FakeRun(probe=OSError("x")),
                "Timeout": FakeRun(probe=subprocess.TimeoutExpired("claude", 120)),
                "nonjson": lambda cmd, **kw: reply(stdout="not json"),
                "exit1": lambda cmd, **kw: reply(code=1, stdout=json.dumps({"result": "sbom-audit"}))}
        for name, run in runs.items():
            with self.subTest(probe=name):
                out = self.tmp / name
                self.assertFalse(assess.skill_expansion_works(run, out))
                self.assertNotIn("print_mode_skills", scheduler.read_state(out) or {})   # retried next run

    def test_probe_with_is_error_is_false_and_not_cached(self):
        out = self.tmp / "errored"
        errored = json.dumps({"result": "sbom-audit", "is_error": True})
        self.assertFalse(assess.skill_expansion_works(lambda cmd, **kw: reply(stdout=errored), out))
        self.assertNotIn("print_mode_skills", scheduler.read_state(out) or {})   # retried next run

    def test_probe_with_clean_exit_but_no_match_is_cached_false(self):
        out = self.tmp / "nomatch"
        self.assertFalse(assess.skill_expansion_works(FakeRun(probe="Unknown command"), out))
        self.assertIs(scheduler.read_state(out)["print_mode_skills"], False)

    def test_result_carrying_the_fingerprint_key_is_discarded(self):
        cfg = make_cfg_in(self.tmp)
        plugin = make_plugin(self.tmp)
        key_file = cfg.out / ".cache" / "secrets-id.key"
        key_file.parent.mkdir(parents=True)
        raw = bytes(range(32))
        key_file.write_bytes(raw)
        cases = {"hex": raw.hex(), "hex-upper": raw.hex().upper(),
                 "base64": __import__("base64").b64encode(raw).decode("ascii")}
        for name, material in cases.items():
            with self.subTest(form=name):
                run = FakeRun(main=reply(result=f"Findings.\n\nKey: {material}\n"))
                res = assess.run_headless(cfg, cfg.out, plugin, run=run, which=which_claude, now=NOW)
                self.assertEqual(res["status"], "failed")
                self.assertEqual(res["reason"], "proposal contained cache material")
                self.assertEqual(res["cost_usd"], 0.42)
                self.assertFalse((cfg.out / "reports").exists())
        # a text key is matched as written
        key_file.write_text("textkey-EXAMPLE-0123456789abcdef\n", encoding="utf-8")
        run = FakeRun(main=reply(result="see textkey-EXAMPLE-0123456789abcdef here"))
        res = assess.run_headless(cfg, cfg.out, plugin, run=run, which=which_claude, now=NOW)
        self.assertEqual(res["reason"], "proposal contained cache material")
        self.assertFalse((cfg.out / "reports").exists())
        # a clean result is still written
        run = FakeRun(main=reply(result="nothing of the kind"))
        res = assess.run_headless(cfg, cfg.out, plugin, run=run, which=which_claude, now=NOW)
        self.assertEqual(res["status"], "written")
        self.assertTrue((cfg.out / res["path"]).exists())

    def test_short_or_missing_key_file_never_blocks_a_proposal(self):
        cfg = make_cfg_in(self.tmp)
        self.assertFalse(assess.contains_cache_material(cfg.out, "anything"))
        (cfg.out / ".cache").mkdir()
        (cfg.out / ".cache" / "secrets-id.key").write_text("short\n")
        self.assertFalse(assess.contains_cache_material(cfg.out, "short"))

    def test_write_failure_leaves_no_file_and_reports_oserror(self):
        cfg = make_cfg_in(self.tmp)
        with mock.patch("sbomaudit.assess.os.replace", side_effect=OSError("disk")):
            res = assess.run_headless(cfg, cfg.out, make_plugin(self.tmp), run=FakeRun(),
                                      which=which_claude, now=NOW)
        self.assertEqual(res, {"status": "failed", "path": None, "reason": "OSError", "cost_usd": None})
        self.assertEqual(list((cfg.out / "reports").iterdir()), [])

    def test_failures_report_short_reasons_and_leak_nothing(self):
        cfg = make_cfg_in(self.tmp)
        plugin = make_plugin(self.tmp)
        cases = [
            (subprocess.TimeoutExpired("claude", 900), "timed out"),
            (FileNotFoundError("SECRET-PATH"), "FileNotFoundError"),
            (reply(code=3, stdout="SECRET-OUT"), "exit 3"),
            (reply(stdout="SECRET-NOT-JSON"), "no result"),
            (reply(stdout=json.dumps({"result": 5})), "no result"),
            (reply(stdout=json.dumps([1])), "no result"),
        ]
        for main, reason in cases:
            with self.subTest(reason=reason):
                res = assess.run_headless(cfg, cfg.out, plugin, run=FakeRun(main=main),
                                          which=which_claude, now=NOW)
                self.assertEqual(res, {"status": "failed", "path": None, "reason": reason, "cost_usd": None})
                self.assertNotIn("SECRET", json.dumps(res))
        self.assertFalse((cfg.out / "reports").exists())

    def test_missing_cost_is_none(self):
        cfg = make_cfg_in(self.tmp)
        res = assess.run_headless(cfg, cfg.out, make_plugin(self.tmp),
                                  run=FakeRun(main=reply(stdout=json.dumps({"result": "x"}))),
                                  which=which_claude, now=NOW)
        self.assertEqual((res["status"], res["cost_usd"]), ("written", None))


if __name__ == "__main__":
    unittest.main()
