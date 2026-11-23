"""Shared test helpers: real git repositories in temp folders, canned HTTP errors, EPSS files."""
from __future__ import annotations

import gzip
import io
import subprocess
import urllib.error
from pathlib import Path


def not_found(url: str) -> urllib.error.HTTPError:
    """A 404 the way urlopen raises it: with a (here empty) response body.

    HTTPError is file-like; an open one warns with ResourceWarning when collected (Python 3.13+),
    and the code under test only reads `.code`, so the body is closed before the error is raised.
    """
    err = urllib.error.HTTPError(url, 404, "Not Found", {}, io.BytesIO())  # type: ignore[arg-type]
    err.close()
    return err


def epss_gz(rows: dict[str, tuple[float, float]] | None = None,
            score_date: str = "2026-11-23T12:00:23Z", model: str = "v2026.06.15") -> bytes:
    """A valid EPSS score file as FIRST publishes it: gzip, a comment line, a header, one row per CVE."""
    rows = {"CVE-2021-23337": (0.0123, 0.79)} if rows is None else rows
    lines = [f"#model_version:{model},score_date:{score_date}", "cve,epss,percentile"]
    lines += [f"{cve},{score!r},{percentile!r}" for cve, (score, percentile) in rows.items()]
    return gzip.compress(("\n".join(lines) + "\n").encode("utf-8"), mtime=0)


def epss_fetch(raw: bytes | Exception):
    """fetch(url) that returns `raw` or raises it, and records every URL in `.calls`."""
    calls = []

    def fetch(url):
        calls.append(url)
        if isinstance(raw, Exception):
            raise raw
        return raw

    fetch.calls = calls
    return fetch


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, text=True,
                          capture_output=True).stdout


def make_repo(tmp: Path, name: str, files: dict[str, str],
              branches: list[str] | None = None, remote: str | None = None) -> Path:
    """Create a git repo `tmp/name` with `files` committed on `main`.

    Every extra branch is cut from main with one more commit touching `DEV`.
    """
    branches = branches or ["main"]
    repo = tmp / name
    repo.mkdir(parents=True)
    for rel, content in files.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "commit.gpgsign", "false")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "initial")
    for branch in branches:
        if branch == "main":
            continue
        _git(repo, "checkout", "-q", "-b", branch)
        (repo / "DEV").write_text(f"on {branch}\n")
        _git(repo, "add", "DEV")
        _git(repo, "commit", "-q", "-m", f"extra commit on {branch}")
    _git(repo, "checkout", "-q", "main")
    if remote:
        _git(repo, "remote", "add", "origin", remote)
    return repo
