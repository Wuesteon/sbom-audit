"""Go modules that only tests or tools import.

go.mod and go.sum do not say which required modules only the tests need. This reader finds out from the
code: it reads the `import` declarations of every `.go` file of each Go module in the exported tree (a
directory with its own `go.mod` is a different module) and maps each import path to the required module
with the longest matching path. A directly required module is dev-only when every import of it is in a
`_test.go` file or in a file constrained to the `tools` build tag (`//go:build tools`, the tools.go
convention), or when go.mod lists it only through a `tool` directive (Go 1.24) and no other file imports it.
A module no file imports stays unknown, not dev-only.

Only the header of a file is read (build constraints, package clause, imports), by a small tokenizer that
skips comments and handles single and block imports, aliases, dot and blank imports. Directories Go itself
ignores are skipped: `vendor/`, `testdata/` and names starting with `.` or `_`. Only regular files inside the
tree (no symlinks), each at most MAX_FILE_BYTES, at most MAX_GO_FILES per scan; a module where a file was
skipped for size or the cap was reached makes no dev-only claim.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

MAX_FILE_BYTES = 1 << 20
MAX_GO_FILES = 20_000
SKIP_DIRS = {"vendor", "testdata", "node_modules"}
TOOLS_TAG = re.compile(r"(?<![!\w])tools(?!\w)")

TEST, TOOL, PROD = "test", "tool", "prod"


def _strip_comment(line: str) -> str:
    return line.split("//", 1)[0].strip()


def parse_go_mod_tools(text: str) -> list[str]:
    """Package paths of the `tool` directives (single-line and block) in a go.mod."""
    out, in_block = [], False
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if in_block:
            if line.startswith(")"):
                in_block = False
            elif line:
                out.append(line.split()[0].strip('"'))
            continue
        m = re.match(r"^tool\s*(.*)$", line)
        if m:
            rest = m.group(1).strip()
            if rest.startswith("("):
                in_block = True
            elif rest:
                out.append(rest.split()[0].strip('"'))
    return out


def _tokens(text: str):
    """(kind, value) tokens of Go source until the caller stops: kind is 'comment', 'ident', 'string' or
    'punct'. Newlines are not tokens (automatic semicolons do not matter for the header)."""
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in " \t\r\n﻿":
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            yield "comment", text[i:end]
            i = end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            yield "comment", text[i:end]
            i = end
        elif ch == '"':
            j = i + 1
            while j < n and text[j] != '"' and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            yield "string", text[i + 1:min(j, n)]
            i = j + 1
        elif ch == "`":
            end = text.find("`", i + 1)
            end = n if end < 0 else end
            yield "string", text[i + 1:end]
            i = end + 1
        elif ch.isalpha() or ch == "_" or ord(ch) > 127:
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] == "_" or ord(text[j]) > 127):
                j += 1
            yield "ident", text[i:j]
            i = j
        else:
            yield "punct", ch
            i += 1


def parse_header(text: str) -> tuple[list[str], bool]:
    """(import paths, constrained to the `tools` build tag) of one Go file. Malformed input gives what was
    read up to the problem."""
    imports: list[str] = []
    tools = False
    toks = _tokens(text)
    seen_package = False
    for kind, value in toks:
        if kind == "comment":
            line = value[2:].strip() if value.startswith("//") else ""
            if (line.startswith("go:build") or line.startswith("+build")) and TOOLS_TAG.search(line):
                tools = True
            continue
        seen_package = kind == "ident" and value == "package"
        break
    if not seen_package:
        return imports, tools
    # after `package`: the package name, then import declarations
    state = "name"
    for kind, value in toks:
        if kind == "comment":
            continue
        if state == "name":
            state = "decl"
            continue
        if state == "decl":
            if kind == "punct" and value == ";":
                continue
            if kind == "ident" and value == "import":
                state = "import"
                continue
            break
        if state == "import":
            if kind == "punct" and value == "(":
                state = "block"
            elif kind == "string":
                imports.append(value)
                state = "decl"
            elif not (kind == "ident" or (kind == "punct" and value == ".")):
                break
            continue
        if state == "block":
            if kind == "punct" and value == ")":
                state = "decl"
            elif kind == "string":
                imports.append(value)
            elif not (kind == "ident" or (kind == "punct" and value in ".;")):
                break
    return imports, tools


def _walk(root: Path, ignore: list[str]):
    prefixes = [p.strip().lstrip("./").rstrip("/") + "/" for p in ignore if p.strip().strip("./")]
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = [d for d in sorted(dirnames)
                       if d not in SKIP_DIRS and not d.startswith((".", "_"))
                       and not any(f"{rel_dir}/{d}/".lstrip("/").startswith(p) for p in prefixes)]
        for name in sorted(filenames):
            if name == "go.mod" or name.endswith(".go"):
                yield Path(dirpath) / name


def _regular_inside(root: Path, path: Path) -> bool:
    try:
        return not path.is_symlink() and path.is_file() and path.resolve().is_relative_to(root)
    except (OSError, RuntimeError):
        return False


def _owner(module_paths: list[str], imp: str) -> str | None:
    best = None
    for m in module_paths:
        if (imp == m or imp.startswith(m + "/")) and (best is None or len(m) > len(best)):
            best = m
    return best


def usage(src: Path, ignore: list[str], parse_go_mod) -> dict[str, dict[str, set[str] | None]]:
    """go.mod path -> {directly required module -> kinds of use ({test, tool, prod}), or None when the module
    could not be read completely}. `parse_go_mod` is readers.parse_go_mod (passed in to avoid an import
    cycle)."""
    root = src.resolve()
    mods: dict[Path, dict] = {}
    files: list[Path] = []
    for path in _walk(root, ignore):
        if not _regular_inside(root, path):
            continue
        if path.name == "go.mod":
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            parsed = parse_go_mod(text)
            mods[path.parent] = {"rel": path.relative_to(root).as_posix(),
                                 "direct": [m for m, indirect in parsed["require"] if not indirect],
                                 "tools": parse_go_mod_tools(text),
                                 "uses": {}, "complete": True}
        else:
            files.append(path)
    out: dict[str, dict] = {}
    if not mods:
        return out
    for i, path in enumerate(files):
        owner_dir = next((d for d in [path.parent, *path.parent.parents] if d in mods), None)
        if owner_dir is None:
            continue
        mod = mods[owner_dir]
        if i >= MAX_GO_FILES:
            mod["complete"] = False
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                mod["complete"] = False
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            mod["complete"] = False
            continue
        imports, tools = parse_header(text)
        kind = TEST if path.name.endswith("_test.go") else TOOL if tools else PROD
        for imp in imports:
            target = _owner(mod["direct"], imp)
            if target is not None:
                mod["uses"].setdefault(target, set()).add(kind)
    for mod in mods.values():
        for pkg in mod["tools"]:
            target = _owner(mod["direct"], pkg)
            if target is not None:
                mod["uses"].setdefault(target, set()).add(TOOL)
        out[mod["rel"]] = {m: (mod["uses"].get(m, set()) if mod["complete"] else None) for m in mod["direct"]}
    return out


def dev_only(src: Path, ignore: list[str], parse_go_mod) -> set[str]:
    """Module paths that every go.mod requiring them directly uses only from tests or tools."""
    verdict: dict[str, bool] = {}
    for per_mod in usage(src, ignore, parse_go_mod).values():
        for module, kinds in per_mod.items():
            dev = bool(kinds) and PROD not in kinds        # None (incomplete) or empty (no import): unknown
            verdict[module] = verdict.get(module, True) and dev
    return {m for m, dev in verdict.items() if dev}
