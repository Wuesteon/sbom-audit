"""Tiny JSON file cache with a TTL in hours, used for every outbound lookup, and the atomic file write
every status, state and secrets file goes through."""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path


def atomic_write(path: Path, text: str) -> Path:
    """Write `<name>.<pid>.tmp` next to `path`, then replace; a failure never leaves a half file or a stray
    tmp. The pid keeps two writers apart (a timer run next to a manual run) so neither renames the other's
    half-written tmp into place."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return path


class Cache:
    def __init__(self, dir: Path, ttl_hours: int = 24):
        self.dir = Path(dir)
        self.ttl_hours = ttl_hours

    def _path(self, key: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_.@-]+", "_", key)
        return self.dir / f"{safe}.json"

    def get(self, key: str):
        """Cached object, or None when missing, expired (TTL 0 = never) or unreadable."""
        p = self._path(key)
        try:
            entry = json.loads(p.read_text(encoding="utf-8"))
            stored = float(entry["stored_at"])
            value = entry["value"]
        except (OSError, ValueError, KeyError, TypeError):
            return None
        if self.ttl_hours and time.time() - stored > self.ttl_hours * 3600:
            return None
        return value

    def put(self, key: str, obj) -> None:
        p = self._path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"stored_at": time.time(), "value": obj}), encoding="utf-8")
