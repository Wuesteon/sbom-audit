"""Test package: makes `sbomaudit` importable from the scripts directory, and isolates the config dir.

Every test runs with `XDG_CONFIG_HOME` pointing at a fresh temporary directory, so nothing in the suite
(`pipeline.run` / `pipeline.finish` refresh an installed guard there) can ever touch `~/.config/sbom-audit`.
The previous value is restored and the directory removed when the interpreter exits.
"""
import atexit
import os
import shutil
import sys
import tempfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "plugin" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

_PREVIOUS_XDG = os.environ.get("XDG_CONFIG_HOME")
CONFIG_HOME = tempfile.mkdtemp(prefix="sbom-audit-tests-xdg-")
os.environ["XDG_CONFIG_HOME"] = CONFIG_HOME
# `settings` and its refresh write ~/.claude/settings.json; tests point them at a scratch home instead.
os.environ["SBOM_AUDIT_HOME"] = tempfile.mkdtemp(prefix="sbom-audit-tests-home-")


def _restore_config_home() -> None:
    if _PREVIOUS_XDG is None:
        os.environ.pop("XDG_CONFIG_HOME", None)
    else:
        os.environ["XDG_CONFIG_HOME"] = _PREVIOUS_XDG
    shutil.rmtree(CONFIG_HOME, ignore_errors=True)
    shutil.rmtree(os.environ.pop("SBOM_AUDIT_HOME", ""), ignore_errors=True)


atexit.register(_restore_config_home)
