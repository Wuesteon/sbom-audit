"""Optional headless assessment: `claude -p` in read-only mode, writing only a proposal file.

`run_headless` runs when `[schedule] assess = true`. The child gets read-only tools plus prefix rules for the
read-only CLI subcommands, and `SBOM_AUDIT_READ_ONLY=1` so every writing subcommand exits 5 without writing.
The only file written is `reports/<date>-assessment-proposal.md`, which the user reviews with
/sbom-audit:assess. The proposal text, stdout and stderr of the child are never printed or logged; failures
are reported as a short reason (an exception class name or an exit code).
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from . import scheduler
from .config import Config
from .secrets.findings import KEY_FILE

PROPOSAL_NAME = "{date}-assessment-proposal.md"
HEADER = "<!-- proposal written by headless assessment, not applied; review with /sbom-audit:assess -->"
SKILL_PROMPT = "/sbom-audit:assess --headless"
# `.cache/` holds the fingerprint key (KEY_FILE) and raw caches: denied as a tool rule, said in the prompt, and
# a proposal that still carries key material is dropped (three layers, R95).
CACHE_DENY_RULE = "Read(./.cache/**)"
CACHE_SENTENCE = "Never read, search or list anything under .cache/."
CACHE_MATERIAL_REASON = "proposal contained cache material"
_MIN_MATERIAL_CHARS = 16
SKILL_FILE = Path("skills") / "assess" / "SKILL.md"
RUN_TIMEOUT = 900
PROBE_TIMEOUT = 120
PROBE_BUDGET_USD = "0.50"
# Hard limits for every child (R75): `--allowedTools` only adds allow rules, so the tool set, the permission
# mode, the prompts and the user's MCP servers are pinned too. Never `--restricted` (it drops plugin skills).
CHILD_TOOLS = "Read,Grep,Glob,WebSearch,WebFetch,Bash"
LIMIT_FLAGS = ["--tools", CHILD_TOOLS, "--permission-mode", "dontAsk", "--permission-prompts", "none",
               "--strict-mcp-config"]
# Reads and fetches are scoped (R75): `Read(//<abs>/**)` also covers Grep and Glob, and anything outside the
# portfolio root and the evidence folder is denied, so injected report or page text can't make the child read
# `~/.ssh` and send it on. WebFetch reaches only the advisory sources below; WebSearch stays unscoped.
FETCH_DOMAINS = ("osv.dev", "api.osv.dev", "github.com", "nvd.nist.gov", "www.cisa.gov", "endoflife.date",
                 "security-tracker.debian.org", "ubuntu.com", "www.npmjs.com", "pypi.org", "jsr.io")
STATE_KEY = "print_mode_skills"
READ_ONLY_SUBCOMMANDS = ("lookup", "incident", "status")
PLUGIN_ROOT_VAR = "${CLAUDE_PLUGIN_ROOT}"
QUOTED_CLI = f'"{PLUGIN_ROOT_VAR}/scripts/sbom_audit_cli.py"'
_FRONTMATTER = re.compile(r"\A---[ \t]*\n.*?\n---[ \t]*(?:\n|\Z)", re.DOTALL)


def command(cfg: Config, cli_path: Path, prompt: str) -> list[str]:
    """The child's argv. Reads are limited to the portfolio root and the evidence folder, fetches to
    FETCH_DOMAINS. Each read-only subcommand is allowed with the CLI path unquoted (the fallback prompt's
    form) and double-quoted (the form a skill body expands to when `${CLAUDE_PLUGIN_ROOT}` is substituted)."""
    cli = Path(cli_path).as_posix()
    rules = [f"Bash(python3 {path} {sub}:*)" for sub in READ_ONLY_SUBCOMMANDS for path in (cli, f'"{cli}"')]
    reads = [f"Read(/{p.as_posix()}/**)" for p in dict.fromkeys(Path(d).resolve() for d in (cfg.root, cfg.out))]
    fetches = [f"WebFetch(domain:{d})" for d in FETCH_DOMAINS]
    tools = ",".join([*reads, "WebSearch", *fetches, *rules])
    return ["claude", "-p", prompt, "--allowedTools", tools, "--disallowedTools", CACHE_DENY_RULE,
            "--max-budget-usd", str(cfg.schedule.assess_budget_usd), "--output-format", "json", *LIMIT_FLAGS]


def skill_expansion_works(run=subprocess.run, out: Path | None = None, env: dict | None = None) -> bool:
    """Whether `claude -p` expands plugin skills (a `/sbom-audit:status` call mentions sbom-audit).

    The probe has the same hard limits as the main run, a small budget and `cwd=out`. A clean answer (exit 0,
    JSON) is cached under `print_mode_skills` in `.cache/scheduler.json` (other keys kept) and a cached bool
    skips the probe; a failed probe (timeout, OSError, non-zero exit, bad JSON, `is_error`) is False and not cached.
    """
    state = scheduler.read_state(out) if out is not None else None
    if state is not None and isinstance(state.get(STATE_KEY), bool):
        return state[STATE_KEY]
    cmd = ["claude", "-p", "/sbom-audit:status", "--output-format", "json",
           "--max-budget-usd", PROBE_BUDGET_USD, *LIMIT_FLAGS]
    kwargs = {"text": True, "capture_output": True, "timeout": PROBE_TIMEOUT}
    if env is not None:
        kwargs["env"] = env
    if out is not None:
        kwargs["cwd"] = Path(out)
    try:
        proc = run(cmd, **kwargs)
        if proc.returncode != 0:
            return False
        data = json.loads(proc.stdout)
    except Exception:                       # timeout, missing binary, bad JSON: the probe is just "no"
        return False
    errored = not isinstance(data, dict) or bool(data.get("is_error"))
    works = not errored and isinstance(data.get("result"), str) and "sbom-audit" in data["result"]
    if out is not None and not errored:          # an errored probe answer is "no" for now and retried next run
        try:
            scheduler.write_state(out, {**(state or {}), STATE_KEY: works})
        except OSError:
            pass
    return works


def prompt(plugin_root: Path, skills_work: bool = False) -> str:
    """`/sbom-audit:assess --headless`, or (print mode without skills) the body of skills/assess/SKILL.md
    with the frontmatter stripped and ` --headless` appended; both end with CACHE_SENTENCE. FileNotFoundError
    when that file is missing.

    Nothing substitutes `${CLAUDE_PLUGIN_ROOT}` in the fallback body, so the quoted CLI path becomes the
    unquoted absolute path (the form the child's allow rules and the skill's headless paragraph use) and any
    other `${CLAUDE_PLUGIN_ROOT}` becomes the resolved plugin root."""
    if skills_work:
        return f"{SKILL_PROMPT} {CACHE_SENTENCE}"
    root = Path(plugin_root).resolve()
    text = (Path(plugin_root) / SKILL_FILE).read_text(encoding="utf-8")
    text = text.replace(QUOTED_CLI, (root / "scripts" / "sbom_audit_cli.py").as_posix())
    text = text.replace(PLUGIN_ROOT_VAR, root.as_posix())
    return _FRONTMATTER.sub("", text, count=1).strip() + f" --headless {CACHE_SENTENCE}"


def _result(status: str, path: str | None = None, reason: str | None = None, cost: float | None = None) -> dict:
    return {"status": status, "path": path, "reason": reason, "cost_usd": cost}


def _cache_material(out: Path) -> list[str]:
    """Forms of the fingerprint key that must not appear in a child's answer: the file as text, as hex and as
    base64 (what `xxd`, `base64` or a tool that shows a binary file would print). Empty when there is no key."""
    try:
        raw = (Path(out) / KEY_FILE).read_bytes()
    except OSError:
        return []
    forms = [raw.decode("utf-8", errors="ignore").strip(), raw.hex(), base64.b64encode(raw).decode("ascii")]
    return [form for form in forms if len(form) >= _MIN_MATERIAL_CHARS]


def contains_cache_material(out: Path, text: str) -> bool:
    lowered = text.lower()
    return any(form in text or form.lower() in lowered for form in _cache_material(out))


def run_headless(cfg: Config, out: Path, plugin_root: Path, run=subprocess.run, which=shutil.which,
                 now: datetime | None = None) -> dict:
    """Run the assessment and write the proposal. Returns
    `{"status": "written"|"skipped"|"failed", "path": "reports/..." | None, "reason": str | None,
    "cost_usd": float | None}`. Never raises for a failing child; never writes anything else."""
    out = Path(out)
    if which("claude") is None:
        return _result("skipped", reason="claude not on PATH")
    env = {**os.environ, "SBOM_AUDIT_READ_ONLY": "1", "CLAUDE_PLUGIN_ROOT": Path(plugin_root).resolve().as_posix()}
    try:
        text = prompt(plugin_root, skill_expansion_works(run, out, env))
    except OSError:
        return _result("skipped", reason=f"{SKILL_FILE.as_posix()} missing")
    cli_path = Path(plugin_root).resolve() / "scripts" / "sbom_audit_cli.py"
    try:
        proc = run(command(cfg, cli_path, text), text=True, capture_output=True, timeout=RUN_TIMEOUT, env=env,
                   cwd=out)
    except subprocess.TimeoutExpired:
        return _result("failed", reason="timed out")
    except OSError as exc:
        return _result("failed", reason=type(exc).__name__)
    if proc.returncode != 0:
        return _result("failed", reason=f"exit {proc.returncode}")
    try:
        data = json.loads(proc.stdout)
    except (TypeError, ValueError):
        return _result("failed", reason="no result")
    if not isinstance(data, dict) or not isinstance(data.get("result"), str):
        return _result("failed", reason="no result")
    cost = data.get("total_cost_usd")
    cost = float(cost) if isinstance(cost, (int, float)) and not isinstance(cost, bool) else None
    if contains_cache_material(out, data["result"]):     # the child got at the key file after all
        return _result("failed", reason=CACHE_MATERIAL_REASON, cost=cost)
    now = now or datetime.now(timezone.utc)
    rel = f"reports/{PROPOSAL_NAME.format(date=now.strftime('%Y-%m-%d'))}"
    target = out / rel
    tmp = target.with_name(target.name + ".tmp")
    try:                                        # atomic: a partial proposal never appears under reports/
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(f"{HEADER}\n{data['result'].rstrip()}\n", encoding="utf-8")
        os.replace(tmp, target)
    except OSError as exc:
        tmp.unlink(missing_ok=True)
        return _result("failed", reason=type(exc).__name__)
    return _result("written", path=rel, cost=cost)
