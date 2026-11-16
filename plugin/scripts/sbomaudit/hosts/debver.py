"""Debian version comparison, the algorithm of `dpkg --compare-versions` (deb-version(7)).

A version is `[epoch:]upstream[-revision]`. The epoch compares as an integer (absent = 0). The upstream
version and the revision (absent = "", which equals "0") compare part by part: alternately a run of
non-digits, compared character by character with `~` before everything (even the end of the string),
then letters, then every other character; and a run of digits, compared as an integer.
"""
from __future__ import annotations

_DIGITS = "0123456789"


def _split(v: str) -> tuple[int, str, str]:
    v = v.strip()
    epoch = 0
    head, sep, rest = v.partition(":")
    if sep and head.isdigit():
        epoch, v = int(head), rest
    upstream, sep, revision = v.rpartition("-")
    if not sep:
        upstream, revision = v, ""
    return epoch, upstream, revision


def _order(c: str) -> int:
    if c in _DIGITS:
        return 0
    if c.isascii() and c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _cmp_part(a: str, b: str) -> int:
    """dpkg's verrevcmp: a negative, zero or positive number."""
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and a[i] not in _DIGITS) or (j < len(b) and b[j] not in _DIGITS):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first_diff = 0
        while i < len(a) and a[i] in _DIGITS and j < len(b) and b[j] in _DIGITS:
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i] in _DIGITS:
            return 1
        if j < len(b) and b[j] in _DIGITS:
            return -1
        if first_diff:
            return first_diff
    return 0


def compare(a: str, b: str) -> int:
    """-1, 0 or 1 as Debian version `a` sorts before, equal to or after `b`."""
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    r = (ea > eb) - (ea < eb) or _cmp_part(ua, ub) or _cmp_part(ra, rb)
    return (r > 0) - (r < 0)
