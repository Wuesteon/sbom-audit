"""Redacted secret findings: a raw engine row becomes a finding that holds no secret.

The raw `Secret` and `Match` are used in memory only (keyed `value_id`, classification, liveness check)
and never copied into the finding. The finding is built from `FIELDS`, so no other key can leak in.
"""
from __future__ import annotations

import datetime as dt
import hmac
import os
import secrets
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from .. import gitio
from .classify import Classes, classify, value_context

if TYPE_CHECKING:  # the fixture lives in the tests package; never imported at runtime
    from tests.secrets_fixture import Planted

KEY_FILE = ".cache/secrets-id.key"
KEY_ENV = "SBOM_AUDIT_SECRETS_KEY"
FIELDS = ("fingerprint", "value_id", "repo", "branches", "commit", "author", "date", "file", "line",
          "rule_id", "provider", "class", "entropy", "live_in_tree", "age_days", "status",
          "first_seen", "last_seen", "reopened_from", "rotated_on", "base_class", "context")
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_WINDOW = 5
_HEX_WINDOW = 8       # a window starting with 5 lowercase hex characters: see assert_redacted
_HEX = frozenset("0123456789abcdef")
_MIN_KEY_BYTES = 16


def _checked(key: bytes, source: str) -> bytes:
    if len(key) < _MIN_KEY_BYTES:
        raise ValueError(f"{source} is too short")
    return key


def load_key(out: Path, env=os.environ) -> bytes:
    """Key for `value_id`: env hex wins, else the key file, else a fresh 32-byte key written 0600."""
    value = env.get(KEY_ENV)
    if value:
        try:
            key = bytes.fromhex(value)
        except ValueError:
            raise ValueError(f"{KEY_ENV} is not hex") from None
        return _checked(key, KEY_ENV)
    path = Path(out) / KEY_FILE
    if path.exists():
        return _checked(path.read_bytes(), str(path))
    key = secrets.token_bytes(32)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:  # another process won the race: use its key
        return _checked(path.read_bytes(), str(path))
    with os.fdopen(fd, "wb") as handle:
        handle.write(key)
    return key


def value_id(key: bytes, value: str) -> str:
    return hmac.new(key, value.encode(), "sha256").hexdigest()[:16]


def _display_name(ref: str) -> str | None:
    """`refs/heads/x` -> `x`, `refs/remotes/<remote>/x` -> `x`; None for HEAD and anything else."""
    if ref.startswith("refs/heads/"):
        name = ref[len("refs/heads/"):]
    elif ref.startswith("refs/remotes/"):
        _, _, name = ref[len("refs/remotes/"):].partition("/")
    else:  # detached HEAD, tags, ...
        return None
    return None if not name or name == "HEAD" else name


def _branch_refs(repo: Path, commit: str, git) -> dict[str, list[str]]:
    """Display branch name -> every full ref (local and remote-tracking) that contains `commit`."""
    try:
        out = git(repo, "branch", "-a", "--contains", commit, "--format=%(refname)")
    except gitio.GitError:
        return {}
    refs: dict[str, list[str]] = {}
    for line in out.splitlines():
        ref = line.strip()
        name = _display_name(ref)
        if name is not None and ref not in refs.setdefault(name, []):
            refs[name].append(ref)
    return refs


def _live(repo: Path, refs: dict[str, list[str]], file: str, secret: str, git_bytes) -> bool:
    """Is the raw value in `file` at the tip of any ref behind any listed branch? Compared in memory."""
    needle = secret.encode()
    if not needle:
        return False
    for full_refs in refs.values():
        for ref in full_refs:
            try:
                content = git_bytes(repo, "show", f"{ref}:{file}")
            except gitio.GitError:  # file gone on this ref
                continue
            if needle in content:
                return True
    return False


def age_days(date: str | None, now: dt.datetime) -> int | None:
    """Whole days from a finding's commit `date` (`%Y-%m-%dT%H:%M:%SZ`, UTC) to `now`; None when unparsable."""
    try:
        commit_date = dt.datetime.strptime(date or "", _DATE_FORMAT)
    except ValueError:
        return None
    return (now.date() - commit_date.date()).days


def refresh_ages(items: list[dict], now: dt.datetime) -> list[dict]:
    """Recompute `age_days` of every finding from its `date` against `now`, in place (a carried finding's
    age would otherwise stay at the value of the scan that first found it)."""
    for f in items:
        if isinstance(f, dict):
            f["age_days"] = age_days(f.get("date"), now)
    return items


def redact(row: dict, *, repo_name: str, repo: Path, key: bytes, classes: Classes,
           now: dt.datetime, git=gitio.git, git_bytes=gitio.git_bytes) -> dict:
    """Finding with exactly FIELDS. `date` is the row's raw `Date` string (UTC, `%Y-%m-%dT%H:%M:%SZ`) or
    None when the row has none; `age_days` is None when it is missing or unparsable."""
    secret = row["Secret"]
    cls, provider = classify(row["RuleID"], secret, classes, file=row["File"])
    refs = _branch_refs(repo, row["Commit"], git)
    branches = sorted(refs)
    today = now.date().isoformat()
    values = {
        "fingerprint": row["Fingerprint"],
        "value_id": value_id(key, secret),
        "repo": repo_name,
        "branches": branches,
        "commit": row["Commit"],
        "author": row["Author"],
        "date": row.get("Date"),
        "file": row["File"],
        "line": row["StartLine"],
        "rule_id": row["RuleID"],
        "provider": provider,
        "class": cls,
        "entropy": row.get("Entropy"),
        "live_in_tree": _live(repo, refs, row["File"], secret, git_bytes),
        "age_days": age_days(row.get("Date"), now),
        "status": "open",
        "first_seen": today,
        "last_seen": today,
        "reopened_from": None,
        "rotated_on": None,
        "base_class": cls,                           # class of rule and value; `class` adds the path context
        "context": value_context(row["RuleID"], secret),  # a value-shape label; the path label is set later
    }
    return {name: values[name] for name in FIELDS}


def assert_redacted(text: str, planted: Iterable[Planted]) -> list[str]:
    """Offending strings in `text`: a planted value, or any window of its random core. A window is 5 characters,
    or 8 where its first 5 are all lowercase hex (as `tests.secrets_fixture.eval_windows`): a 5-character hex run
    matches a per-run commit hash, blob id or HMAC in the output by chance, an 8-character one practically never,
    so the check is deterministic while any leak of 8 or more characters is still caught."""
    offending: list[str] = []
    for item in planted:
        if item.value in text:
            offending.append(item.value)
        core = item.core
        if len(core) < _WINDOW:
            raise ValueError("planted core too short")
        for i in range(len(core) - _WINDOW + 1):
            n = _HEX_WINDOW if set(core[i:i + _WINDOW]) <= _HEX else _WINDOW
            if i + n <= len(core) and core[i:i + n] in text:
                offending.append(core[i:i + n])
    return offending
