"""The CLI form next to a `/sbom-audit:` slash command, for users without Claude Code.

Terminal messages name the real script path (as `setup` does); text written into the evidence folder
(`STATUS.md`, `cra.json`, ...) names only `sbom_audit_cli.py`, so no local path lands in a shared report.
"""
from __future__ import annotations

import shlex
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "sbom_audit_cli.py"


def command(sub: str, full: bool = True) -> str:
    """`python3 '<path>/sbom_audit_cli.py' <sub>`; `sbom_audit_cli.py <sub>` when not `full`."""
    return f"python3 {shlex.quote(SCRIPT.as_posix())} {sub}" if full else f"sbom_audit_cli.py {sub}"


def slash(sub: str, full: bool = True, skill: str | None = None) -> str:
    """`/sbom-audit:<skill> (CLI: <command>)`; the skill name defaults to the subcommand."""
    return f"/sbom-audit:{skill or sub} (CLI: {command(sub, full)})"
