"""Lenient version helpers shared by readers, enrichment and reports."""
from __future__ import annotations

import re


def ver_key(v: str) -> tuple:
    """Sort key: numeric components first, then the raw string."""
    nums = [int(x) for x in re.findall(r"\d+", v or "")[:6]]
    return (tuple(nums), v or "")


def ver_major(v: str | None) -> int | None:
    if not v:
        return None
    m = re.match(r"\D*(\d+)", v)
    return int(m.group(1)) if m else None


def ver_minor_tuple(v: str | None) -> tuple[int, int] | None:
    if not v:
        return None
    m = re.match(r"\D*(\d+)\.(\d+)", v)
    return (int(m.group(1)), int(m.group(2))) if m else None


def min_version_from_range(spec: str | None) -> str | None:
    """'>=18.0.0', '^20', '~22.1', '>=3.10,<3.14', '20' -> lowest allowed version."""
    if not spec:
        return None
    lowers = []
    for clause in re.split(r"[,|\s]+", spec):
        m = re.match(r"^(>=|\^|~|==|=|>)?v?(\d+(?:\.\d+)*)", clause.strip())
        if m:
            lowers.append(m.group(2))
    if not lowers:
        found = re.findall(r"v?(\d+(?:\.\d+)*)", spec)
        return found[0] if found else None
    return sorted(lowers, key=ver_key)[0]


# Products whose endoflife.date cycles are major.minor (checked against the API 2026-11-06).
MINOR_CYCLE_PRODUCTS = {"python", "alpine", "ubuntu", "deno", "nginx", "redis", "mongodb", "mysql",
                        "mariadb", "go", "php", "ruby", "traefik", "rabbitmq", "elasticsearch",
                        "haproxy", "memcached"}


def runtime_cycle(product: str, version: str | None) -> str:
    """endoflife.date cycle for a runtime version: '20.11.1' -> '20', python '3.12.4' -> '3.12'."""
    if not version:
        return ""
    if product in MINOR_CYCLE_PRODUCTS:
        t = ver_minor_tuple(version)
        if t:
            return f"{t[0]}.{t[1]}"
    major = ver_major(version)
    return str(major) if major is not None else ""


def norm_py(name: str) -> str:
    """PEP 503 normalisation."""
    return re.sub(r"[-_.]+", "-", name).lower()
