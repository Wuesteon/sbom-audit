#!/usr/bin/env python3
"""Launcher so the plugin can run the package without installing it."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sbomaudit.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
