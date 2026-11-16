"""Exceptions shared across modules."""
from __future__ import annotations


class ToolError(RuntimeError):
    """An external tool (syft, osv-scanner) failed or produced unusable output."""

    def __init__(self, tool: str, returncode: int | None, detail: str):
        self.tool, self.returncode, self.detail = tool, returncode, detail
        super().__init__(f"{tool} failed (exit {returncode}): {detail}")


class ConfigError(ValueError):
    """`sbom-audit.toml` (or an overriding environment variable) holds a value of the wrong kind."""


class VexError(ValueError):
    """An OpenVEX document could not be read; the run aborts rather than ignore it."""

    def __init__(self, path, reason: str):
        self.path, self.reason = path, reason
        super().__init__(f"{path}: {reason}")


class EngineError(RuntimeError):
    """The secrets engine (gitleaks) failed; `detail` never carries a finding or a secret value."""

    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)
