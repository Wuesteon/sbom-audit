#!/usr/bin/env python3
"""Compare two audit.json files: which vulnerable (project, branch, package, version, id)
tuples of the OLD audit are missing in the NEW one, and vice versa.

    python3 scripts/parity.py OLD_AUDIT_JSON NEW_AUDIT_JSON

A tuple matches when project, branch, ecosystem, normalised name and version agree and
any id or alias of the vulnerability overlaps. Exit 0 when nothing from OLD is missing.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

Tuple = tuple[str, str, str, str, str, str]     # project, branch, ecosystem, name, version, id


def norm_name(ecosystem: str, name: str) -> str:
    if ecosystem == "PyPI":
        return name.lower().replace("_", "-").replace(".", "-")
    return name


def _ids(vuln: dict) -> frozenset[str]:
    return frozenset({vuln.get("id", "")} | set(vuln.get("aliases") or [])) - {""}


def tuples(rep: dict) -> dict[tuple, list[frozenset[str]]]:
    """(project, branch, ecosystem, name, version) -> list of id-sets, one per vulnerability."""
    out: dict[tuple, list[frozenset[str]]] = {}
    for entry in rep.get("vulnerabilities", []):
        key_base = (entry["ecosystem"], norm_name(entry["ecosystem"], entry["name"]), entry["version"])
        for loc in entry.get("locations", []):
            key = (loc["project"], loc["branch"]) + key_base
            out.setdefault(key, []).extend(_ids(v) for v in entry.get("vulns", []))
    return out


def _one_sided(a: dict, b: dict) -> set[Tuple]:
    missing: set[Tuple] = set()
    for key, id_sets in a.items():
        other = b.get(key, [])
        for ids in id_sets:
            if not any(ids & o for o in other):
                missing.add(key + (sorted(ids)[0],))
    return missing


def diff(old: dict, new: dict) -> tuple[set[Tuple], set[Tuple]]:
    """-> (in old but missing in new, in new but not in old)."""
    return _one_sided(old, new), _one_sided(new, old)


def counts(rep: dict) -> dict:
    return {"kev": sum(1 for e in rep.get("vulnerabilities", []) if e.get("kev")),
            "eol": sum(1 for r in rep.get("runtimes", []) if r.get("status") == "EOL"),
            "floating": len(rep.get("unpinned_images", []))}


def _print(title: str, rows: set[Tuple]) -> None:
    print(f"## {title}: {len(rows)}")
    for r in sorted(rows):
        print("  " + " | ".join(r))
    print()


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    old = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    new = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    missing, added = diff(tuples(old), tuples(new))
    _print("In OLD, missing in NEW", missing)
    _print("In NEW, not in OLD", added)
    co, cn = counts(old), counts(new)
    print("## Counts (old -> new)")
    for k, label in (("kev", "KEV package versions"), ("eol", "EOL runtimes/images"), ("floating", "floating images")):
        print(f"  {label}: {co[k]} -> {cn[k]}")
    return 0 if not missing else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
