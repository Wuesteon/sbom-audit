"""What the repository scan cannot see in C/C++ and firmware code: a coverage gap, never a clean result.

Syft and the plugin's readers inventory package managers (npm, PyPI, Go, Maven, Cargo, Conan `conanfile.txt`
and `conan.lock`, ...). C/C++ and firmware projects mostly bring their third-party code in other ways, which
this module only *detects* in the exported tree of one branch, so the reports can say what was not inventoried:

- git submodules (`.gitmodules`): `git archive` leaves them out, so their code is not in the scanned tree;
- manifests no reader understands: Zephyr `west.yml`, ESP-IDF `idf_component.yml`, PlatformIO `platformio.ini`
  and `library.json`, Conan `conanfile.py`, the `dependencies` of `vcpkg.json` (Syft reads only its name and
  version), CMake `FetchContent_Declare` / `ExternalProject_Add`;
- C/C++ source files: vendored libraries (mbedTLS, FreeRTOS, lwIP, zlib ...) copied into the tree carry no
  manifest at all.

The cure is a build SBOM (CLI `import`). Nothing here reads a version or matches advisories.
"""
from __future__ import annotations

import configparser
import os
import re
from pathlib import Path

C_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".s", ".S"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build", ".pio"}
MANIFESTS = {
    "west.yml": "Zephyr west manifest",
    "idf_component.yml": "ESP-IDF component manifest",
    "platformio.ini": "PlatformIO project",
    "library.json": "PlatformIO library manifest",
    "conanfile.py": "Conan recipe (Python)",
}
CMAKE_FETCH = re.compile(r"\b(FetchContent_Declare|ExternalProject_Add)\s*\(\s*([A-Za-z0-9_.+-]+)")
MAX_LISTED = 50                    # entries kept per list in inventory.json; the counts stay exact
MAX_FILE_BYTES = 1_000_000


def _read(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def submodules(text: str) -> list[dict]:
    """`.gitmodules` -> [{"path", "url"}]; an unreadable file gives []."""
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(text)
    except configparser.Error:
        return []
    out = []
    for section in parser.sections():
        if not section.startswith("submodule"):
            continue
        path = parser.get(section, "path", fallback="").strip()
        if path:
            out.append({"path": path, "url": parser.get(section, "url", fallback="").strip()})
    return out


def _vcpkg_dependencies(text: str) -> int:
    import json
    try:
        doc = json.loads(text)
    except ValueError:
        return 0
    if not isinstance(doc, dict):
        return 0
    lists = [doc.get("dependencies")]                       # plus each feature's own (libsndfile: all of them)
    features = doc.get("features")
    if isinstance(features, dict):
        lists += [f.get("dependencies") for f in features.values() if isinstance(f, dict)]
    return sum(len(deps) for deps in lists if isinstance(deps, list))


def detect(src: Path) -> dict | None:
    """The coverage gap of one exported tree, or None when there is none.

    {"submodules": [{"path", "url"}], "submodule_count": n,
     "manifests": [{"file", "kind"}], "manifest_count": n, "c_sources": n}"""
    src = Path(src)
    subs = submodules(_read(src / ".gitmodules")) if (src / ".gitmodules").is_file() else []
    manifests: list[dict] = []
    c_sources = 0
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        here = Path(dirpath)
        for name in sorted(filenames):
            rel = (here / name).relative_to(src).as_posix()
            suffix = os.path.splitext(name)[1]
            if suffix in C_SUFFIXES:
                c_sources += 1
            if name in MANIFESTS:
                manifests.append({"file": rel, "kind": MANIFESTS[name]})
            elif name == "vcpkg.json":
                n = _vcpkg_dependencies(_read(here / name))
                if n:
                    manifests.append({"file": rel, "kind": f"vcpkg manifest, {n} dependencies not read"})
            elif name == "CMakeLists.txt" or name.endswith(".cmake"):
                found = sorted({m.group(2) for m in CMAKE_FETCH.finditer(_read(here / name))})
                if found:
                    manifests.append({"file": rel, "kind": "CMake FetchContent/ExternalProject: "
                                      + ", ".join(found[:10]) + (" …" if len(found) > 10 else "")})
    if not subs and not manifests and not c_sources:
        return None
    return {"submodules": subs[:MAX_LISTED], "submodule_count": len(subs),
            "manifests": manifests[:MAX_LISTED], "manifest_count": len(manifests), "c_sources": c_sources}


def describe(gap: dict, imported: bool = False) -> str:
    """One line for AUDIT.md and CRA.md: what is not in the SBOM and what closes the gap."""
    parts = []
    if gap.get("submodule_count"):
        shown = ", ".join(f"`{s['path']}`" for s in gap["submodules"][:8])
        more = " …" if gap["submodule_count"] > 8 else ""
        parts.append(f"{gap['submodule_count']} git submodule(s) not scanned ({shown}{more})")
    if gap.get("manifest_count"):
        shown = ", ".join(f"`{m['file']}` ({m['kind']})" for m in gap["manifests"][:5])
        more = " …" if gap["manifest_count"] > 5 else ""
        parts.append(f"{gap['manifest_count']} dependency manifest(s) no reader understands: {shown}{more}")
    if gap.get("c_sources"):
        parts.append(f"{gap['c_sources']} C/C++ source files, whose vendored or compiled-in libraries are not "
                     "inventoried")
    cure = ("a build SBOM is imported for this branch: check that it covers these" if imported else
            "import a build SBOM (`import`) to cover them")
    return "coverage gap: " + "; ".join(parts) + f". Not in the SBOM and not checked for vulnerabilities; {cure}."
