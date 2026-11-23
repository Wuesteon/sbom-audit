"""The run manifest (`manifest.json`) and `verify`: which inputs, tool versions and data a run used, and a
SHA-256 for every evidence file it wrote, so a reader can check that the reports are what the run produced.

Three parts:

- `provenance` (built during the audit, stored in `audit.json` and shown in `AUDIT.md` and `REPORT.html`):
  sbom-audit and Python versions, the platform, the configuration digest, the version of each external tool
  as the tool itself reports it (`unknown` when it does not answer, `not installed` when it is not on PATH),
  and the status and freshness of every data source (OSV, CISA KEV, endoflife.date, registries).
- `write` (the end of `run`, before the commit): the provenance plus run start and end, the exit code, the
  audited commit of every project branch and release tag, and `{sha256, bytes}` of every file the run wrote
  or read as a decision (VEX, decisions files, imported SBOMs). A file cannot hold its own hash: the manifest
  lists the others and the run's git commit covers the manifest.
- `refresh_changed` (after every other writing command, called from `cli.main`): a command that rewrites
  evidence after the run (`issues`, `secrets resolve`, `hosts check`, `vex add`, `cra check`, `import`, …)
  updates exactly the entries of the files it changed, each marked `refreshed: {at, command}`, and appends one
  line to `refreshed`. Files the command did not touch keep the run's hash, so an edit by hand still shows.

`log.md` and `AUDIT.md` are append-only (`append_only: true`): a hand-written `## Assessment` section or log
line after the run reads `appended`, not `changed`; an edit inside the recorded bytes reads `changed`.

Never recorded: anything under `.cache/` (the fingerprint key lives there), `.git/`, `cra/` (the user's own
documents), `sbom-audit.toml` (its digest is recorded instead: a hand edit of the config is not tampering), a
secret value (no input of the manifest holds one; secrets.json has fingerprints only), tool paths.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath

from . import __version__
from .cache import atomic_write

SCHEMA = "sbom-audit-manifest/1"
MANIFEST_FILE = "manifest.json"
CONFIG_FILE = "sbom-audit.toml"
APPEND_ONLY = ("log.md", "AUDIT.md")
EXCLUDED_DIRS = (".git", ".cache", "cra")
EXCLUDED_FILES = (MANIFEST_FILE, CONFIG_FILE)
# where a file the manifest does not list is worth naming: the reports at the top, SBOMs, VEX, imports
UNLISTED_SCOPE_DIRS = ("sbom", "vex", "imports")
TOP_LEVEL_SKIP = ("CLAUDE.md", "README.md", ".gitignore")
EXIT_OK, EXIT_MISMATCH, EXIT_NO_MANIFEST = 0, 1, 2
UNKNOWN, NOT_INSTALLED = "unknown", "not installed"
VERSION_TIMEOUT = 15
TOOL_ARGS = {"syft": ["version"], "osv-scanner": ["--version"], "git": ["--version"], "gh": ["--version"]}
RUN_TOOLS = ("syft", "osv-scanner", "git")
_VERSION = re.compile(r"(?<![\w.])v?(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z][0-9A-Za-z.+-]*)?)")
_VERSION_LINE = re.compile(r"^\s*version\s*:?\s*v?(\S+)", re.I | re.M)
_versions_seen: dict[str, str] = {}       # per process: a tool does not change version during one run
# bound at import: a test that replaces subprocess.run for a scanner never feeds the version probe
_RUN, _WHICH = subprocess.run, shutil.which


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    try:
        return dt.datetime.fromtimestamp(float(ts), dt.timezone.utc).replace(microsecond=0).isoformat()
    except (ValueError, OverflowError, OSError, TypeError):
        return None


def utc_iso(value) -> str | None:
    """An ISO 8601 time with an offset, as UTC (`…+00:00`); a time without an offset is returned as it is
    (its zone is not known, so it is not called UTC), anything unparsable as None."""
    if not isinstance(value, str) or not value:
        return None
    try:
        at = dt.datetime.fromisoformat(value.replace("Z", "+00:00") if value.endswith("Z") else value)
    except ValueError:
        return None
    if at.tzinfo is None or at.utcoffset() is None:
        return value
    return at.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat()


# --------------------------------------------------------------------------- tool versions

def parse_version(text: str) -> str | None:
    """The version a tool printed: a `Version:` line first (syft), else the first dotted number."""
    text = text or ""
    m = _VERSION_LINE.search(text)
    if m and _VERSION.match(m.group(1)):
        return _VERSION.match(m.group(1)).group(1)
    m = _VERSION.search(text)
    return m.group(1) if m else None


def tool_version(name: str, run=None, which=None) -> str:
    """`<tool> version` (or `--version`) as the tool reports it; `not installed` when it is not on PATH and
    `unknown` when it does not answer. Never raises, never guesses."""
    which = which or _WHICH
    run = run or _RUN
    binary = which(name)
    if not binary:
        return NOT_INSTALLED
    env = {**os.environ, "SYFT_CHECK_FOR_APP_UPDATE": "false", "GH_NO_UPDATE_NOTIFIER": "1"}
    try:
        proc = run([binary, *TOOL_ARGS.get(name, ["--version"])], capture_output=True, text=True,
                   errors="replace", timeout=VERSION_TIMEOUT, env=env)
    except Exception:                               # OSError, timeout, anything: the run goes on
        return UNKNOWN
    if getattr(proc, "returncode", 1) != 0:
        return UNKNOWN
    return parse_version(f"{proc.stdout or ''}\n{proc.stderr or ''}") or UNKNOWN


def tool_versions(names=RUN_TOOLS, run=None, which=None) -> dict[str, str]:
    """{tool: version} for `names`. Without injected `run`/`which`, each tool is asked once per process."""
    if run is not None or which is not None:
        return {n: tool_version(n, run, which) for n in names}
    out = {}
    for n in names:
        if n not in _versions_seen:
            _versions_seen[n] = tool_version(n)
        out[n] = _versions_seen[n]
    return out


# --------------------------------------------------------------------------- provenance (audit time)

def _source_status(info) -> str:
    if not isinstance(info, dict):
        return "not run"
    if info.get("skipped"):
        return "skipped"
    if info.get("error"):
        return "failed"
    if info.get("failed"):
        return "partial"
    return "ok"


def _answers(cache, keys, since: float) -> dict:
    """How fresh the cached database answers behind `keys` are: live (fetched during this audit), from the
    local cache (fetched earlier), or none (a failed lookup is not cached)."""
    stamps = [cache.stored_at(k) for k in sorted(keys)]
    have = [s for s in stamps if s is not None]
    return {"answers": len(keys), "live": sum(1 for s in have if s >= since),
            "cached": sum(1 for s in have if s < since), "without_answer": len(stamps) - len(have),
            "oldest_fetch": _iso(min(have)) if have else None, "newest_fetch": _iso(max(have)) if have else None}


def data_sources(sources: dict, cache, since: float, *, eol_keys=(), latest_keys=(),
                 generated_at: str | None = None) -> dict:
    """Status and freshness of each database the audit used, from what the run already holds."""
    osv = sources.get("osv-scanner")
    kev = sources.get("cisa_kev")
    fetched = cache.stored_at("kev-catalog")
    meta = cache.get("kev-catalog-meta") or {}
    meta = meta if isinstance(meta, dict) else {}
    kev_doc = {"status": _source_status(kev), "entries": (kev or {}).get("loaded"),
               "origin": None if fetched is None or _source_status(kev) == "failed"
               else ("live" if fetched >= since else "cache"),
               "fetched_at": _iso(fetched), "catalog_version": meta.get("catalogVersion") or UNKNOWN,
               "catalog_date": meta.get("dateReleased") or UNKNOWN}
    eol = sources.get("endoflife")
    reg = sources.get("registries")
    vex = sources.get("openvex")
    return {
        "osv": {"status": _source_status(osv), "origin": "live", "queried_at": utc_iso(generated_at),
                "via": "osv-scanner (OSV.dev, queried during the audit)",
                "branches_scanned": (osv or {}).get("scanned"), "branches_failed": len((osv or {}).get("failed") or [])},
        "cisa_kev": kev_doc,
        **({"epss": _epss_doc(sources["epss"])} if "epss" in sources else {}),   # only when the EPSS step ran
        "endoflife": {"status": _source_status(eol), **_answers(cache, eol_keys, since)},
        "registries": {"status": _source_status(reg), **_answers(cache, latest_keys, since)},
        "openvex": {"status": _source_status(vex), "statements": (vex or {}).get("statements")},
    }


def _epss_doc(src) -> dict:
    """The EPSS entry from sources["epss"] (epss.source): `stale` when an older cached file was used."""
    src = src if isinstance(src, dict) else {}
    status = "failed" if src.get("error") else ("stale" if src.get("origin") == "stale" or src.get("warning")
                                                 else "ok")
    return {"status": status, "entries": src.get("loaded"), "origin": src.get("origin"),
            "fetched_at": src.get("fetched_at"), "score_date": src.get("score_date"),
            "model_version": src.get("model_version")}


EPSS_ORIGIN = {"live": "downloaded during this audit", "cache": "from the local cache",
               "stale": "download failed, older file used"}


def provenance(cfg, cache, since: float, *, sources: dict, eol_rows=(), latest_keys=(),
               generated_at: str | None = None, tools: dict | None = None) -> dict:
    """What `audit.json` and `AUDIT.md` say about how the audit was produced."""
    eol_keys = {f"eol:{r['product']}/{r['cycle']}" for r in eol_rows if r.get("cycle")}
    reg_keys = {f"latest:{eco}:{name}" for eco, name in latest_keys}
    return {"sbom_audit": __version__, "python": platform.python_version(), "platform": platform.platform(),
            "config_sha256": getattr(cfg, "digest", None),
            "tools": tools if tools is not None else tool_versions(),
            "data_sources": data_sources(sources, cache, since, eol_keys=eol_keys, latest_keys=reg_keys,
                                         generated_at=generated_at)}


def try_provenance(*args, **kwargs) -> dict:
    """`provenance` that never breaks the audit; a failure is recorded by its type only."""
    try:
        return provenance(*args, **kwargs)
    except Exception as exc:
        return {"sbom_audit": __version__, "error": type(exc).__name__}


# --------------------------------------------------------------------------- AUDIT.md section

def _md(value) -> str:
    return str(value if value is not None else UNKNOWN).replace("|", "\\|").replace("\n", " ")


def _freshness(name: str, info: dict) -> str:
    if name == "osv":
        return f"queried live during this audit ({_md(info.get('queried_at'))})"
    if name == "cisa_kev":
        if not info.get("fetched_at"):
            return "not loaded"
        origin = "downloaded during this audit" if info.get("origin") == "live" else "from the local cache"
        return (f"catalogue {_md(info.get('catalog_date'))} (version {_md(info.get('catalog_version'))}), "
                f"fetched {_md(info.get('fetched_at'))}, {origin}")
    if name in ("endoflife", "registries"):
        if not info.get("answers"):
            return "nothing to look up"
        text = (f"{info['answers']} lookups: {info.get('live', 0)} fetched during this audit, "
                f"{info.get('cached', 0)} from the local cache (24 h)")
        if info.get("without_answer"):
            text += f", {info['without_answer']} without an answer"
        if info.get("oldest_fetch"):
            text += f"; oldest answer fetched {_md(info['oldest_fetch'])}"
        return text
    if name == "openvex":
        return f"{_md(info.get('statements'))} statements in `vex/`"
    if name == "epss":
        if info.get("status") == "failed":
            return "not loaded"
        return (f"scores of {_md(info.get('score_date'))} (model {_md(info.get('model_version'))}), "
                f"fetched {_md(info.get('fetched_at'))}, {EPSS_ORIGIN.get(info.get('origin'), _md(info.get('origin')))}")
    return ""


SOURCE_NAMES = {"osv": "OSV (osv-scanner)", "cisa_kev": "CISA KEV", "endoflife": "endoflife.date",
                "registries": "npm/PyPI/JSR registries", "openvex": "OpenVEX",
                "epss": "EPSS (FIRST)"}


def audit_md_section(prov: dict | None) -> list[str]:
    """`## How this report was produced` for AUDIT.md, or a one-line note when the audit recorded nothing."""
    L = ["## How this report was produced", ""]
    if not isinstance(prov, dict) or prov.get("error") or not isinstance(prov.get("tools"), dict):
        why = f" ({_md(prov['error'])})" if isinstance(prov, dict) and prov.get("error") else ""
        return L + [f"Not recorded for this audit{why}.", ""]
    digest = prov.get("config_sha256")
    L += [f"sbom-audit {_md(prov.get('sbom_audit'))} on Python {_md(prov.get('python'))} "
          f"({_md(prov.get('platform'))}). Configuration: `sbom-audit.toml` "
          + (f"SHA-256 `{_md(digest)}`." if digest else "not read (defaults)."), "",
          "| Tool | Version |", "|---|---|"]
    L += [f"| {_md(name)} | {_md(version)} |" for name, version in prov["tools"].items()]
    L += ["", "| Data source | Status | Freshness |", "|---|---|---|"]
    for key, info in (prov.get("data_sources") or {}).items():
        if isinstance(info, dict):
            L.append(f"| {SOURCE_NAMES.get(key, _md(key))} | {_md(info.get('status'))} | {_freshness(key, info)} |")
    L += ["", "The secrets scan's own results are in `SECRETS.md`. `manifest.json` records the run's start and "
          "end, the audited commits and the SHA-256 and size of every file the run wrote; "
          "`sbom_audit_cli.py verify` recomputes them.", ""]
    return L


# --------------------------------------------------------------------------- files

def sha256_of(path: Path, limit: int | None = None) -> str:
    """SHA-256 of the file, or of its first `limit` bytes."""
    h = hashlib.sha256()
    left = limit
    with open(path, "rb") as fh:
        while left is None or left > 0:
            chunk = fh.read(1 << 20 if left is None else min(1 << 20, left))
            if not chunk:
                break
            h.update(chunk)
            if left is not None:
                left -= len(chunk)
    return h.hexdigest()


def _rel(out: Path, path: Path) -> str | None:
    """`path` relative to `out` as POSIX text, or None when it is outside `out` or must not be recorded."""
    try:
        rel = Path(path).resolve().relative_to(out)
    except (ValueError, OSError):
        try:
            rel = Path(os.path.abspath(path)).relative_to(out)
        except ValueError:
            return None
    parts = rel.parts
    if not parts or parts[0] in EXCLUDED_DIRS or rel.as_posix() in EXCLUDED_FILES:
        return None
    if parts[-1].endswith(".tmp"):
        return None
    return rel.as_posix()


def _safe_rel(rel) -> bool:
    """A manifest path is relative, inside the folder, never `..`, never under an excluded folder."""
    if not isinstance(rel, str) or not rel or "\\" in rel or "\x00" in rel:
        return False
    p = PurePosixPath(rel)
    return (not p.is_absolute() and ".." not in p.parts and p.parts[0] not in EXCLUDED_DIRS
            and rel not in EXCLUDED_FILES)


def file_entry(out: Path, rel: str) -> dict:
    path = out / rel
    entry = {"sha256": sha256_of(path), "bytes": path.stat().st_size}
    if rel in APPEND_ONLY:
        entry["append_only"] = True
    return entry


def evidence_inputs(out: Path) -> list[Path]:
    """Decision files and imported SBOMs the run read: VEX documents, decisions files, imports/."""
    paths = sorted((out / "vex").glob("*.openvex.json")) if (out / "vex").is_dir() else []
    paths += [out / n for n in ("secrets-decisions.toml", "hosts-decisions.toml") if (out / n).is_file()]
    if (out / "imports").is_dir():
        paths += sorted(p for p in (out / "imports").rglob("*") if p.is_file())
    return paths


def files_of(out: Path, paths) -> dict[str, dict]:
    files: dict[str, dict] = {}
    for p in paths:
        rel = _rel(out, Path(p))
        if rel is None or rel in files:
            continue
        path = out / rel
        if path.is_symlink() or not path.is_file():
            continue
        files[rel] = file_entry(out, rel)
    return dict(sorted(files.items()))


# --------------------------------------------------------------------------- the manifest (end of run)

def _audited(inventories) -> list[dict]:
    rows = []
    for inv in inventories:
        row = {"project": inv.project, "branch": inv.branch, "commit": inv.commit or None,
               "complete": not inv.errors}
        if inv.release:
            row["release_tag"] = inv.release.get("tag")
        src = inv.package_source or {}
        if src.get("kind") == "import":
            row["imported_sbom"] = {k: src.get(k) for k in ("file", "in", "sha256", "commit", "stale")}
        rows.append(row)
    return sorted(rows, key=lambda r: (r["project"], r["branch"]))


def _secrets_source(doc, rep_source) -> tuple[dict, dict]:
    """(data source entry, {engine: version}) for the secrets scan of this run."""
    if not isinstance(doc, dict):
        status = "failed" if isinstance(rep_source, dict) else "not run"
        return {"status": status}, {}
    scan = doc.get("scan") if isinstance(doc.get("scan"), dict) else {}
    engine = doc.get("engine") if isinstance(doc.get("engine"), dict) else {}
    if scan.get("mode") == "skipped":
        return {"status": "skipped", "reason": scan.get("skipped_reason"), "scanned_at": doc.get("generated_at")}, {}
    status = "partial" if scan.get("failed") else "failed" if scan.get("error") else "ok"
    tools = {str(engine["name"]): str(engine.get("version") or UNKNOWN)} if engine.get("name") else {}
    return {"status": status, "mode": scan.get("mode"), "repositories": scan.get("repos"),
            "scanned_at": doc.get("generated_at")}, tools


def _hosts_source(doc) -> dict | None:
    if not isinstance(doc, dict):
        return None
    if doc.get("skipped"):
        return {"status": "skipped", "reason": str(doc["skipped"]), "last_checked": doc.get("last_checked")}
    hosts = doc.get("hosts") if isinstance(doc.get("hosts"), dict) else {}
    failed = sum(1 for h in hosts.values() if isinstance(h, dict) and h.get("status") == "failed")
    return {"status": "partial" if failed else "ok", "hosts": len(hosts), "failed": failed,
            "last_checked": doc.get("last_checked")}


def build(out: Path, rep: dict, inventories, written, *, exit_code: int, started_at: dt.datetime,
          finished_at: dt.datetime | None = None, secrets=None, hosts=None, gh_used: bool = False,
          command: str = "run", run=None, which=None) -> dict:
    out = Path(out).resolve()
    prov = rep.get("provenance") if isinstance(rep.get("provenance"), dict) else {}
    tools = dict(prov.get("tools") or {}) or tool_versions(run=run, which=which)
    if gh_used and "gh" not in tools:
        tools.update(tool_versions(("gh",), run=run, which=which) if (run or which) else tool_versions(("gh",)))
    sources = dict(prov.get("data_sources") or {})
    secrets_src, engine = _secrets_source(secrets, (rep.get("sources") or {}).get("secrets"))
    tools.update(engine)
    sources["secrets"] = secrets_src
    hosts_src = _hosts_source(hosts)
    if hosts_src is not None:
        sources["hosts"] = hosts_src
    paths = list(written) + evidence_inputs(out)
    return {"schema": SCHEMA, "sbom_audit": __version__,
            "python": prov.get("python") or platform.python_version(),
            "platform": prov.get("platform") or platform.platform(),
            "run": {"command": command, "started_at": started_at.replace(microsecond=0).isoformat(),
                    "finished_at": (finished_at or _utc_now()).replace(microsecond=0).isoformat(),
                    "exit_code": exit_code},
            "config": {"file": CONFIG_FILE, "sha256": prov.get("config_sha256")},
            "tools": tools, "data_sources": sources, "audited": _audited(inventories),
            "files": files_of(out, paths), "refreshed": []}


def write(out: Path, doc: dict) -> Path:
    return atomic_write(Path(out) / MANIFEST_FILE, json.dumps(doc, indent=2, ensure_ascii=False) + "\n")


def try_write(out: Path, rep: dict, inventories, written, say=print, **kwargs) -> list[Path]:
    """Build and write the manifest; never breaks the run (a failure is logged by its type and nothing is
    written, so `verify` then reports the previous run's manifest or none)."""
    try:
        return [write(out, build(out, rep, inventories, written, **kwargs))]
    except Exception as exc:
        say(f"manifest: not written ({type(exc).__name__})")
        return []


def read(out: Path) -> dict | None:
    """The manifest, or None when absent; ValueError when it is not a manifest this version reads."""
    path = Path(out) / MANIFEST_FILE
    if not path.is_file():
        return None
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA or not isinstance(doc.get("files"), dict):
        raise ValueError("not a sbom-audit manifest")
    return doc


# --------------------------------------------------------------------------- refresh after the run

def _walk(out: Path) -> dict[str, tuple]:
    """{relative path: (inode, mtime_ns, size)} for every file that may be evidence."""
    seen: dict[str, tuple] = {}
    for root, dirs, names in os.walk(out):
        here = Path(root)
        if here == out:
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        dirs[:] = [d for d in dirs if not (here / d).is_symlink()]
        for name in names:
            path = here / name
            rel = path.relative_to(out).as_posix()
            if rel in EXCLUDED_FILES or name.endswith(".tmp") or path.is_symlink():
                continue
            try:
                st = path.stat()
            except OSError:
                continue
            seen[rel] = (st.st_ino, st.st_mtime_ns, st.st_size)
    return seen


def snapshot(out: Path) -> dict | None:
    """The state before a writing command, or None when there is no manifest to keep current."""
    try:
        out = Path(out).resolve()
        if not (out / MANIFEST_FILE).is_file():
            return None
        return _walk(out)
    except Exception:
        return None


def refresh_changed(out: Path, before: dict | None, command: str, now: dt.datetime | None = None) -> list[str]:
    """Update the manifest entries of the files `command` wrote or removed since `before`; returns their paths.

    Only a file whose (inode, mtime, size) changed during the command is touched, so a file edited by hand
    before the command keeps the run's hash. A new file is added, a removed listed file is dropped; each one
    is named in a `refreshed` line with the time and the command. Never raises."""
    if before is None:
        return []
    try:
        out = Path(out).resolve()
        doc = read(out)
        if doc is None:
            return []
        after = _walk(out)
        files = doc["files"]
        at = (now or _utc_now()).replace(microsecond=0).isoformat()
        changed, removed = [], []
        for rel, stat in sorted(after.items()):
            if before.get(rel) == stat:
                continue
            entry = file_entry(out, rel)
            old = files.get(rel)
            if isinstance(old, dict) and old.get("sha256") == entry["sha256"] and old.get("bytes") == entry["bytes"]:
                continue                            # rewritten with the same bytes: the run's entry stands
            files[rel] = {**entry, "refreshed": {"at": at, "command": command}}
            changed.append(rel)
        for rel in sorted(set(before) - set(after)):
            if rel in files:
                del files[rel]
                removed.append(rel)
        if not changed and not removed:
            return []
        doc["files"] = dict(sorted(files.items()))
        line = {"at": at, "command": command, "files": changed}
        if removed:
            line["removed"] = removed
        doc.setdefault("refreshed", []).append(line)
        write(out, doc)
        return changed + removed
    except Exception:
        return []


def refresh_paths(out: Path, paths, command: str, now: dt.datetime | None = None) -> list[str]:
    """Update the entries of `paths` (the run's own status files after the commit outcome is known)."""
    try:
        out = Path(out).resolve()
        doc = read(out)
        if doc is None:
            return []
        at = (now or _utc_now()).replace(microsecond=0).isoformat()
        changed = []
        for p in paths:
            rel = _rel(out, Path(p))
            if rel is None or not (out / rel).is_file():
                continue
            entry = file_entry(out, rel)
            old = doc["files"].get(rel)
            if isinstance(old, dict) and old.get("sha256") == entry["sha256"]:
                continue
            doc["files"][rel] = {**entry, "refreshed": {"at": at, "command": command}}
            changed.append(rel)
        if changed:
            doc["files"] = dict(sorted(doc["files"].items()))
            doc.setdefault("refreshed", []).append({"at": at, "command": command, "files": changed})
            write(out, doc)
        return changed
    except Exception:
        return []


def command_label(args) -> str:
    """`issues`, `secrets resolve`, `hosts check`, `vex add`, `cra check`, `incident --vex`, …"""
    parts = [str(args.command)]
    for attr in ("secrets_command", "hosts_command", "vex_command", "cra_command", "assess_command",
                 "code_command"):
        sub = getattr(args, attr, None)
        if sub:
            parts.append(str(sub))
    if args.command == "incident":
        parts.append("--vex")
    return " ".join(parts)


# --------------------------------------------------------------------------- verify

def _check(out: Path, rel, entry) -> dict:
    row = {"path": rel if isinstance(rel, str) else repr(rel)}
    if not _safe_rel(rel) or not isinstance(entry, dict) or not isinstance(entry.get("sha256"), str) \
            or not isinstance(entry.get("bytes"), int):
        return {**row, "status": "invalid", "detail": "entry is not a file inside the folder"}
    if isinstance(entry.get("refreshed"), dict):
        row["refreshed"] = entry["refreshed"]
    path = out / rel
    try:
        inside = path.resolve().is_relative_to(out)
    except OSError:
        inside = False
    if path.is_symlink() or (path.exists() and not inside):
        return {**row, "status": "changed", "detail": "is a symbolic link"}
    if not path.is_file():
        return {**row, "status": "missing"}
    size = path.stat().st_size
    expected = entry["bytes"]
    if size == expected and sha256_of(path) == entry["sha256"]:
        return {**row, "status": "ok"}
    if entry.get("append_only") and size > expected and sha256_of(path, expected) == entry["sha256"]:
        return {**row, "status": "appended", "detail": f"{size - expected} bytes added after the recorded end"}
    return {**row, "status": "changed", "detail": f"{expected} bytes recorded, {size} now"}


def _unlisted(out: Path, files: dict) -> list[str]:
    found = []
    for rel in _walk(out):
        top = rel.split("/", 1)[0]
        if "/" not in rel:
            if rel in TOP_LEVEL_SKIP or rel.startswith("."):
                continue
        elif top not in UNLISTED_SCOPE_DIRS:
            continue
        if rel not in files:
            found.append(rel)
    return sorted(found)


def _config_state(out: Path, doc: dict) -> str:
    recorded = (doc.get("config") or {}).get("sha256")
    path = out / CONFIG_FILE
    if not path.is_file():
        return "absent"
    if not recorded:
        return "not recorded"
    return "matches" if sha256_of(path) == recorded else "differs"


def verify(out: Path) -> dict:
    """Recompute every hash in the manifest. Reads only; `exit_code` 0 all match, 1 a mismatch, 2 no manifest."""
    out = Path(out).resolve()
    try:
        doc = read(out)
    except (OSError, ValueError) as exc:
        return {"exit_code": EXIT_NO_MANIFEST, "error": f"{MANIFEST_FILE} unreadable ({type(exc).__name__})"}
    if doc is None:
        return {"exit_code": EXIT_NO_MANIFEST, "error": f"no {MANIFEST_FILE} in {out}: run `run` first"}
    rows = [_check(out, rel, entry) for rel, entry in sorted(doc["files"].items(), key=lambda kv: str(kv[0]))]
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    bad = any(r["status"] in ("changed", "missing", "invalid") for r in rows)
    run = doc.get("run") if isinstance(doc.get("run"), dict) else {}
    return {"exit_code": EXIT_MISMATCH if bad else EXIT_OK, "manifest": MANIFEST_FILE,
            "sbom_audit": doc.get("sbom_audit"), "run": run, "files": rows, "counts": counts,
            "unlisted": _unlisted(out, doc["files"]), "config": _config_state(out, doc),
            "refreshed": [r for r in doc.get("refreshed") or [] if isinstance(r, dict)]}


CONFIG_TEXT = {"matches": "matches the digest the run read",
               "differs": "differs from the digest the run read (edited since; informational)",
               "absent": "not present", "not recorded": "the run read no configuration file"}


def render(result: dict) -> str:
    if result.get("error"):
        return result["error"] + "\n"
    run = result.get("run") or {}
    L = [f"{MANIFEST_FILE}: run {run.get('started_at', UNKNOWN)} to {run.get('finished_at', UNKNOWN)}, "
         f"exit {run.get('exit_code', UNKNOWN)}, sbom-audit {result.get('sbom_audit') or UNKNOWN}"]
    for r in result["files"]:
        extra = []
        if r.get("detail"):
            extra.append(r["detail"])
        if r.get("refreshed"):
            extra.append(f"refreshed by `{r['refreshed'].get('command')}` at {r['refreshed'].get('at')}")
        L.append(f"{r['status']:<8} {r['path']}" + (f" ({'; '.join(extra)})" if extra else ""))
    if result["unlisted"]:
        L.append("not in the manifest (not covered by this run): " + ", ".join(result["unlisted"]))
    L.append(f"{CONFIG_FILE}: {CONFIG_TEXT.get(result['config'], result['config'])}")
    counts = result["counts"]
    L.append(", ".join(f"{counts.get(s, 0)} {s}" for s in ("ok", "appended", "changed", "missing", "invalid")
                       if counts.get(s) or s in ("ok", "changed", "missing"))
             + ("" if result["exit_code"] == EXIT_OK else " — the folder differs from what the manifest records"))
    return "\n".join(L) + "\n"


def cli_verify(args) -> int:
    result = verify(Path(args.out))
    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        sys.stdout.write(render(result))
    return result["exit_code"]
