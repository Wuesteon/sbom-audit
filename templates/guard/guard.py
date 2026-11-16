#!/usr/bin/env python3
"""sbom-audit pre-commit guard: refuse a commit that stages a class A or B secret.

The installed copy lives in the sbom-audit config dir (`$XDG_CONFIG_HOME/sbom-audit` or
`~/.config/sbom-audit`) beside `gitleaks.toml` and `classes.toml`, copied there by
`sbom-audit setup --install-guard` and refreshed by every `sbom-audit run`. It is self-contained: standard
library only, imports nothing from the plugin, runs under any python3 >= 3.8.

classes.toml is read with `tomllib` when it exists (3.11+); on 3.8-3.10 `parse_toml_subset` reads exactly
the shape classes.toml uses (`[section]`, `[a.b]`, `key = "string"`, `key = ["list", ...]` across lines,
`#` comments) and raises ValueError on anything else. The classification below duplicates
`sbomaudit.secrets.classify`; a test pins both (and both parsers) to the same result on every planted
fixture secret, so change them together.

Output is only `BLOCKED <class> <rule_id> <file>:<line>` lines plus one hint line, never a matched value.
gitleaks' report is a 0600 file in a private (0700) temp directory, parsed in memory and removed in a
`finally`. Exit 1 blocks the commit; a missing engine or an engine error prints one line and exits 0: the
guard never blocks on a tool error, and is never silently "clean".
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

CANDIDATES = (("gitleaks", "8."), ("betterleaks", "1."), ("betterleaks-v1", "1."))
BETTERLEAKS_ENV = {"BETTERLEAKS_VALIDATE": "false", "BETTERLEAKS_ANALYZE": "false"}
VERSION_TIMEOUT = 10
SCAN_TIMEOUT = 60
PREFIX = "sbom-audit guard: "
INSTALL_LINE = PREFIX + "gitleaks not installed (brew install gitleaks); commit allowed"
HINT = (PREFIX + "commit blocked. A false positive: add `# gitleaks:allow` to that line. Commit anyway: "
        "git commit --no-verify (the weekly rescan still reports it).")
BLOCKING = ("A", "B")

DEFAULT_CLASS = "B"
DEFAULT_PROVIDER = "generic"
JWT_RULES = ("jwt", "jwt-base64")
_STRIPE_TEST = re.compile(r"(?:sk|rk)_test_")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
TIMESTAMP = re.compile(r"^(?:\d{1,2}:\d{2}(?::\d{2})?\s?[AP]M|\d{4}-\d{2}-\d{2}T\S+)\s+")


class GuardError(Exception):
    """An engine problem; its message names the tool and exit code or an ERR/FTL line, never a value."""


# --- classes.toml -----------------------------------------------------------------------------------------

_TOKEN = re.compile(r'''(?P<ws>[ \t\r]+)|(?P<comment>\#[^\n]*)|(?P<nl>\n)|(?P<str>"(?:[^"\\\n]|\\.)*"|'[^'\n]*')'''
                    r'''|(?P<punct>[\[\]=,])|(?P<bare>[A-Za-z0-9_.-]+)''')


def _tokens(text: str) -> list:
    out, pos = [], 0
    while pos < len(text):
        match = _TOKEN.match(text, pos)
        if not match:
            raise ValueError("unsupported TOML at offset %d" % pos)
        pos = match.end()
        kind = match.lastgroup
        if kind in ("ws", "comment"):
            continue
        value = match.group()
        if kind == "str":
            value = json.loads(value) if value[0] == '"' else value[1:-1]
        out.append((kind, value))
    out.append(("nl", "\n"))
    return out


def parse_toml_subset(text: str) -> dict:
    """The classes.toml shape: tables (dotted names) of string or string-list values."""
    data: dict = {}
    table = data
    toks = _tokens(text)
    i = 0

    def expect(kind, value=None):
        nonlocal i
        tok_kind, tok_value = toks[i]
        if tok_kind != kind or (value is not None and tok_value != value):
            raise ValueError("unsupported TOML near token %d" % i)
        i += 1
        return tok_value

    while i < len(toks):
        kind, value = toks[i]
        if kind == "nl":
            i += 1
        elif kind == "punct" and value == "[":
            i += 1
            table = data
            for part in expect("bare").split("."):
                table = table.setdefault(part, {})
            expect("punct", "]")
            expect("nl")
        elif kind == "bare":
            i += 1
            expect("punct", "=")
            if toks[i] == ("punct", "["):
                i += 1
                items = []
                while True:
                    while toks[i][0] == "nl":
                        i += 1
                    if toks[i] == ("punct", "]"):
                        i += 1
                        break
                    items.append(expect("str"))
                    while toks[i][0] == "nl":
                        i += 1
                    if toks[i] == ("punct", ","):
                        i += 1
                table[value] = items
            else:
                table[value] = expect("str")
            expect("nl")
        else:
            raise ValueError("unsupported TOML near token %d" % i)
    return data


class Classes:
    def __init__(self, rule_to_class: dict, rule_providers: dict):
        self.rule_to_class = rule_to_class
        self.rule_providers = rule_providers

    @classmethod
    def from_dict(cls, data: dict) -> "Classes":
        rule_to_class: dict = {}
        for klass, rule_ids in (data.get("classes") or {}).items():
            for rule_id in rule_ids:
                if rule_to_class.setdefault(rule_id, klass) != klass:
                    raise ValueError("rule %s is listed in two classes" % rule_id)
        return cls(rule_to_class, dict(data.get("rule_providers") or {}))


def load_classes(path) -> Classes:
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        import tomllib
    except ImportError:  # python 3.8-3.10
        return Classes.from_dict(parse_toml_subset(raw.decode("utf-8")))
    return Classes.from_dict(tomllib.loads(raw.decode("utf-8")))


# --- classification (duplicate of sbomaudit.secrets.classify) -----------------------------------------------

def _b64url(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def jwt_claims(token: str):
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        claims = json.loads(_b64url(parts[1]))
    except Exception:  # never raise on untrusted input; no value in any message
        return None
    return claims if isinstance(claims, dict) else None


def _classify_jwt(rule_id: str, secret: str):
    token = secret
    if rule_id == "jwt-base64":
        try:
            token = base64.b64decode(secret + "=" * (-len(secret) % 4)).decode()
        except (ValueError, binascii.Error):
            return DEFAULT_CLASS, DEFAULT_PROVIDER
    claims = jwt_claims(token) or {}
    role = claims.get("role")
    if role == "service_role":
        return "A", "supabase"
    if role == "anon":
        return "C", "supabase"
    iss = claims.get("iss")
    if isinstance(iss, str) and "supabase" in iss.lower():
        return "B", "supabase"
    return DEFAULT_CLASS, DEFAULT_PROVIDER


def classify(rule_id: str, secret: str, classes: Classes, file: str = ""):
    """`(class, provider)` for one finding. Unknown rules are class B, provider `generic`."""
    if rule_id in JWT_RULES:
        return _classify_jwt(rule_id, secret)
    provider = classes.rule_providers.get(rule_id, DEFAULT_PROVIDER)
    cls = classes.rule_to_class.get(rule_id, DEFAULT_CLASS)
    if rule_id == "stripe-access-token":
        cls = "C" if _STRIPE_TEST.match(secret) else "A"
    elif rule_id == "gcp-api-key" and "firebase" in file.lower():
        cls = "C"
    return cls, provider


# --- engine ---------------------------------------------------------------------------------------------

def _version(binary: str):
    try:
        proc = subprocess.run([binary, "version"], capture_output=True, text=True, errors="replace",
                              timeout=VERSION_TIMEOUT)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    version = (proc.stdout or "").strip()
    return (version[1:] if version.startswith("v") else version) or None


def find_engine():
    """`(binary, name, env)` for gitleaks 8.x or betterleaks 1.x; None when missing or unsupported."""
    for name, major in CANDIDATES:
        binary = shutil.which(name)
        if not binary:
            continue
        version = _version(binary)
        if version and version.startswith(major):
            return binary, name, ({} if name == "gitleaks" else dict(BETTERLEAKS_ENV))
    return None


def _error_line(stderr: str):
    for line in (stderr or "").splitlines():
        line = TIMESTAMP.sub("", ANSI.sub("", line)).strip()
        if line.startswith(("ERR ", "FTL ")) or "[git] fatal" in line:
            return line
    return None


def scan_staged(binary: str, name: str, env: dict, rules_path: str) -> list:
    """gitleaks' report rows for the staged changes of the repository in the current directory."""
    tmpdir = tempfile.mkdtemp(prefix="sbom-audit-guard-")  # 0700
    report = os.path.join(tmpdir, "report.json")
    old_umask = os.umask(0o077)  # gitleaks replaces the report file; keep its replacement 0600
    try:
        os.close(os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        argv = [binary, "git", "--pre-commit", "--staged", "--no-banner", "--no-color", "-c", rules_path,
                "-f", "json", "-r", report, "--exit-code", "1", "."]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, errors="replace",
                                  env=dict(os.environ, **env), timeout=SCAN_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise GuardError("%s timed out" % name) from None
        except OSError as exc:
            raise GuardError("%s could not start (%s)" % (name, exc.strerror or type(exc).__name__)) from None
        if proc.returncode == 0:
            error = _error_line(proc.stderr)
            if error is not None:
                raise GuardError(error)
            return []
        if proc.returncode == 1:
            try:
                with open(report, encoding="utf-8") as fh:
                    rows = json.load(fh)
            except (OSError, ValueError):
                rows = None
            if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
                raise GuardError("%s exit 1 without a parsable report: %s" % (name, _error_line(proc.stderr) or "no error line"))
            return rows
        first = _error_line(proc.stderr)
        detail = "%s exit %d" % (name, proc.returncode)
        raise GuardError("%s: %s" % (detail, first) if first else detail)
    finally:
        os.umask(old_umask)
        shutil.rmtree(tmpdir, ignore_errors=True)


def main() -> int:
    """Exit 1 means "blocked" and nothing else: any unexpected error allows the commit, naming only its type."""
    try:
        return _main()
    except Exception as exc:
        print(PREFIX + "%s; commit allowed" % type(exc).__name__)
        return 0


def _main() -> int:
    cfg_dir = os.path.dirname(os.path.abspath(__file__))
    engine = find_engine()
    if engine is None:
        print(INSTALL_LINE)
        return 0
    binary, name, env = engine
    try:
        classes = load_classes(os.path.join(cfg_dir, "classes.toml"))
    except Exception as exc:  # a broken config never blocks, and never passes silently
        print(PREFIX + "cannot read classes.toml in %s (%s); commit allowed" % (cfg_dir, type(exc).__name__))
        return 0
    try:
        rows = scan_staged(binary, name, env, os.path.join(cfg_dir, "gitleaks.toml"))
    except GuardError as exc:
        print(PREFIX + "%s; commit allowed" % exc)
        return 0
    blocked = []
    for row in rows:
        rule_id = str(row.get("RuleID") or "")
        cls, _ = classify(rule_id, str(row.get("Secret") or ""), classes, str(row.get("File") or ""))
        if cls in BLOCKING:
            blocked.append("BLOCKED %s %s %s:%s" % (cls, rule_id, row.get("File"), row.get("StartLine")))
    del rows
    if not blocked:
        return 0
    for line in blocked:
        print(line)
    print(HINT)
    return 1


if __name__ == "__main__":
    sys.exit(main())
