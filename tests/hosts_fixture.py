"""Collector documents for host-mode tests, built from the section texts in `fixtures/hosts/clean/`.

The clean host is a made-up Ubuntu 24.04 box (`box-a`, addresses from 203.0.113.0/24). Every value is
example data: nothing here describes a real server or person.
"""
from __future__ import annotations

from pathlib import Path

from sbomaudit.hosts import parse

CLEAN_DIR = Path(__file__).resolve().parent / "fixtures" / "hosts" / "clean"
STARTED = 1794211200  # 2026-11-09T08:00:00Z
DEFAULT_RC = {"reboot": 1, "owners": 1}  # no reboot pending; dpkg -S exits 1 for the /lib aliases


def section_text(name: str) -> str:
    return (CLEAN_DIR / f"{name}.txt").read_text()


def collector_doc(**sections: str | tuple[int, str]) -> dict:
    """A collector document: the clean defaults, with `name=out` or `name=(rc, out)` overrides."""
    out = {}
    for name in parse.SECTIONS:
        out[name] = {"rc": DEFAULT_RC.get(name, 0), "out": section_text(name)}
    for name, value in sections.items():
        rc, text = value if isinstance(value, tuple) else (0, value)
        out[name] = {"rc": rc, "out": text}
    return {"collector": parse.SHIPPED_VERSION, "started": STARTED, "sections": out}
