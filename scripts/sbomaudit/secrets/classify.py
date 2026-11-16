"""Blast-radius classification of a secret finding: rule id (plus decoded JWT claims, Stripe prefix,
file path) to class A/B/C and provider. Pure functions; the secret itself is never returned or logged."""
from __future__ import annotations

import base64
import binascii
import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CLASSES_PATH = Path(__file__).resolve().parents[3] / "secrets" / "classes.toml"
DEFAULT_CLASS = "B"
DEFAULT_PROVIDER = "generic"
JWT_RULES = ("jwt", "jwt-base64")
_STRIPE_TEST = re.compile(r"(?:sk|rk)_test_")


@dataclass(frozen=True)
class Provider:
    name: str
    hint: str
    packages: tuple[str, ...] = ()


@dataclass
class Classes:
    rule_to_class: dict[str, str] = field(default_factory=dict)
    providers: dict[str, Provider] = field(default_factory=dict)
    rule_providers: dict[str, str] = field(default_factory=dict)


def load_classes(path: Path | None = None) -> Classes:
    with (path or CLASSES_PATH).open("rb") as fh:
        data = tomllib.load(fh)
    rule_to_class: dict[str, str] = {}
    for cls, rule_ids in (data.get("classes") or {}).items():
        for rule_id in rule_ids:
            if rule_to_class.setdefault(rule_id, cls) != cls:
                raise ValueError(f"rule {rule_id} is listed in two classes")
    providers = {
        key: Provider(name=p["name"], hint=p["hint"], packages=tuple(p.get("packages", [])))
        for key, p in (data.get("providers") or {}).items()
    }
    return Classes(rule_to_class, providers, dict(data.get("rule_providers") or {}))


def _b64url(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def jwt_claims(token: str) -> dict | None:
    """Payload claims of a JWT, decoded without verification; None when it is not a JWT."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        claims = json.loads(_b64url(parts[1]))
    except Exception:  # never raise on untrusted input (ValueError, RecursionError, ...); no value in the message
        return None
    return claims if isinstance(claims, dict) else None


def _classify_jwt(rule_id: str, secret: str) -> tuple[str, str]:
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
    if isinstance(iss, str) and "supabase" in iss.lower():  # also https://<ref>.supabase.co/auth/v1
        return "B", "supabase"
    return DEFAULT_CLASS, DEFAULT_PROVIDER


def classify(rule_id: str, secret: str, classes: Classes, file: str = "") -> tuple[str, str]:
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
