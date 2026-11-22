"""Paths that typically hold a secret: dotenv files, private keys and credential stores.

One list for two guards: the headless assessment denies them to its Read, Grep and Glob tools
(`assess.DENY_RULES`), and `code grep|show|files` never searches, prints or lists them. Matching here is
case-insensitive, so `code` withholds at least what the deny rules deny.
"""
from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import PurePosixPath

# A file whose name matches one of these, in any directory.
NAME_PATTERNS = (".env*", "*.pem", "*.key", "id_*", "*.p12", "*.pfx", ".npmrc", ".pypirc", ".netrc",
                 ".git-credentials", "credentials*")
# Everything below a directory of this name, in any directory.
DIRECTORIES = (".ssh", ".aws")
# A file at this path tail, in any directory.
TAILS = (".docker/config.json",)
# The `code` message when something was withheld; never names a withheld path or line.
DESCRIPTION = "dotenv, key and credential files"


def deny_rules() -> tuple[str, ...]:
    """The same list as Claude Code `Read` deny rules (absolute patterns, every directory)."""
    rules = [f"Read(//**/{pattern})" for pattern in NAME_PATTERNS]
    rules +=[f"Read(//**/{d}/**)" for d in DIRECTORIES]
    rules += [f"Read(//**/{tail})" for tail in TAILS]
    return tuple(rules)


def git_excludes() -> list[str]:
    """The same list as git exclude pathspecs (glob, case-insensitive), for `git grep`."""
    out = [f":(exclude,glob,icase)**/{pattern}" for pattern in NAME_PATTERNS]
    out += [f":(exclude,glob,icase)**/{d}/**" for d in DIRECTORIES]
    out += [f":(exclude,glob,icase)**/{tail}" for tail in TAILS]
    return out


def is_sensitive(path: str) -> bool:
    """Whether a repository-relative path is one of the paths above (case-insensitive)."""
    parts = PurePosixPath(path.lower()).parts
    if not parts:
        return False
    if any(fnmatchcase(parts[-1], pattern) for pattern in NAME_PATTERNS):
        return True
    if any(part in DIRECTORIES for part in parts[:-1]):
        return True
    return any(parts[-len(PurePosixPath(t).parts):] == PurePosixPath(t).parts for t in TAILS)
