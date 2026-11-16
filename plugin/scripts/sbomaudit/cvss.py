"""CVSS 3.1 base score, severity labels and a CVSS 4.0 → 3.1 vector approximation."""
from __future__ import annotations

import math

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "MODERATE": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}


def score31(vector: str) -> float | None:
    """CVSS 3.x base score from a vector string; None when the vector is not parseable."""
    try:
        parts = dict(p.split(":") for p in vector.split("/")[1:])
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[parts["AV"]]
        ac = {"L": 0.77, "H": 0.44}[parts["AC"]]
        ui = {"N": 0.85, "R": 0.62}[parts["UI"]]
        changed = parts["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[parts["PR"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        iss = 1 - (1 - cia[parts["C"]]) * (1 - cia[parts["I"]]) * (1 - cia[parts["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * av * ac * pr * ui
        if impact <= 0:
            return 0.0
        base = min(1.08 * (impact + expl), 10) if changed else min(impact + expl, 10)
        return math.ceil(base * 10 - 1e-9) / 10
    except (KeyError, ValueError, AttributeError):
        return None


def label(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score == 0:
        return "NONE"
    if score < 4:
        return "LOW"
    if score < 7:
        return "MEDIUM"
    if score < 9:
        return "HIGH"
    return "CRITICAL"


def base_label(severity: str) -> str:
    """'HIGH(~v4)' -> 'HIGH'."""
    return severity.split("(")[0]


def v4_to_31(vector: str) -> str | None:
    """Approximate a CVSS:4.0 vector as CVSS:3.1 (same AV/AC/PR/UI, VC/VI/VA → C/I/A,
    any subsequent-system impact → S:C). Callers label the result as approximate."""
    if not vector.startswith("CVSS:4.0/"):
        return None
    m = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    try:
        scope = "C" if any(m.get(k, "N") != "N" for k in ("SC", "SI", "SA")) else "U"
        ac = "L" if m.get("AC", "L") == "L" and m.get("AT", "N") == "N" else "H"
        return (f"CVSS:3.1/AV:{m['AV']}/AC:{ac}/PR:{m['PR']}/UI:{'N' if m['UI'] == 'N' else 'R'}"
                f"/S:{scope}/C:{m['VC']}/I:{m['VI']}/A:{m['VA']}")
    except KeyError:
        return None
