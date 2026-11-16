#!/usr/bin/env python3
"""Write `.claude-plugin/icon.png`: a 512x512 RGBA shield with a check mark (stdlib only).

Run from anywhere: `python3 scripts/make_icon.py`. The PNG is deterministic, so rerunning it
leaves the file unchanged unless this script changed.
"""
from __future__ import annotations

import struct
import zlib
from pathlib import Path

SIZE = 512
SAMPLES = 4                       # 4x4 supersampling per pixel for smooth edges
BACKGROUND = (17, 24, 39)         # slate tile behind the shield
SHIELD = (16, 185, 129)           # emerald shield
CHECK = (255, 255, 255)           # white check mark
OUT = Path(__file__).resolve().parents[1] / ".claude-plugin" / "icon.png"


def in_tile(x: float, y: float) -> bool:
    """Rounded square covering the canvas with a 96 px corner radius."""
    r, lo, hi = 96.0, 0.0, float(SIZE)
    cx = min(max(x, lo + r), hi - r)
    cy = min(max(y, lo + r), hi - r)
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def in_shield(x: float, y: float) -> bool:
    """Flat top with rounded shoulders, straight sides, then two arcs meeting in a point."""
    left, right, top, mid, bottom = 112.0, 400.0, 88.0, 270.0, 448.0
    if y < top or y > bottom or x < left or x > right:
        return False
    shoulder = 40.0
    if y < top + shoulder:
        cx = min(max(x, left + shoulder), right - shoulder)
        return (x - cx) ** 2 + (y - (top + shoulder)) ** 2 <= shoulder ** 2
    if y <= mid:
        return True
    t = (y - mid) / (bottom - mid)              # 0 at the waist, 1 at the point
    half = (right - left) / 2 * (1 - t ** 1.6) ** 0.85
    return abs(x - SIZE / 2) <= half


def in_check(x: float, y: float) -> bool:
    """Two thick strokes: (180,262)->(236,318) and (236,318)->(338,198)."""
    def near(ax, ay, bx, by, width=26.0):
        dx, dy = bx - ax, by - ay
        t = max(0.0, min(1.0, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)))
        px, py = ax + t * dx, ay + t * dy
        return (x - px) ** 2 + (y - py) ** 2 <= width * width
    return near(180, 262, 236, 318) or near(236, 318, 338, 198)


def pixel(px: int, py: int) -> tuple[int, int, int, int]:
    acc = [0.0, 0.0, 0.0, 0.0]
    n = SAMPLES * SAMPLES
    for sy in range(SAMPLES):
        for sx in range(SAMPLES):
            x, y = px + (sx + 0.5) / SAMPLES, py + (sy + 0.5) / SAMPLES
            if not in_tile(x, y):
                continue
            colour = CHECK if in_check(x, y) and in_shield(x, y) else SHIELD if in_shield(x, y) else BACKGROUND
            acc[0] += colour[0]
            acc[1] += colour[1]
            acc[2] += colour[2]
            acc[3] += 255
    if acc[3] == 0:
        return 0, 0, 0, 0
    covered = acc[3] / 255
    return (round(acc[0] / covered), round(acc[1] / covered), round(acc[2] / covered), round(acc[3] / n))


def chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


def png() -> bytes:
    rows = bytearray()
    for y in range(SIZE):
        rows.append(0)                           # filter type 0 (None) for every scanline
        for x in range(SIZE):
            rows.extend(pixel(x, y))
    ihdr = struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0)   # 8-bit RGBA, no interlace
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(bytes(rows), 9)) + chunk(b"IEND", b""))


def main() -> None:
    data = png()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(data)
    print(f"{OUT.name}: {SIZE}x{SIZE} RGBA, {len(data)} bytes")


if __name__ == "__main__":
    main()
