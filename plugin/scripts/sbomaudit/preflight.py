"""Check that the external tools the pipeline shells out to are installed."""
from __future__ import annotations

import shutil
from collections.abc import Callable, Sequence

TOOLS = ["syft", "osv-scanner", "git", "gh"]          # everything `setup` wants; gh only for --enable-dependabot
RUN_TOOLS = ("syft", "osv-scanner", "git")
SCAN_TOOLS = ("syft", "git")
AUDIT_TOOLS = ("osv-scanner",)
BREW_LINE = "brew install syft osv-scanner gh"
SECRETS_TOOLS = ("gitleaks",)                         # optional: never part of RUN_TOOLS
SECRETS_INSTALL = "brew install gitleaks"


def check(which: Callable[[str], str | None] | None = None, tools: Sequence[str] = TOOLS) -> list[str]:
    """Return the names of required tools that are not on PATH, in `tools` order."""
    which = which or shutil.which
    return [tool for tool in tools if not which(tool)]


def message(missing: Sequence[str]) -> str:
    return f"missing tools: {', '.join(missing)}\n{BREW_LINE}\noptional, for the secrets scan: {SECRETS_INSTALL}"
