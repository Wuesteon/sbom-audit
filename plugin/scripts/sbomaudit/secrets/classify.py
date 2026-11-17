"""Blast-radius classification of a secret finding: rule id (plus decoded JWT claims, Stripe prefix,
file path, value shape) to class A/B/C and provider, and the path context (test, docs, vendored, ...)
that ranks a finding one class lower. Pure functions; the secret itself is never returned or logged."""
from __future__ import annotations

import base64
import binascii
import fnmatch
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
    context: dict[str, tuple[str, ...]] = field(default_factory=dict)  # label -> path patterns, in order


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
    context = {str(label): tuple(patterns) for label, patterns in (data.get("context") or {}).items()}
    return Classes(rule_to_class, providers, dict(data.get("rule_providers") or {}), context)


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
    """`(class, provider)` for one finding, from the rule and the value (never the path context, see
    `apply_context`). Unknown rules are class B, provider `generic`; a value `value_context` names as no
    credential is class C."""
    if rule_id in JWT_RULES:
        return _classify_jwt(rule_id, secret)
    provider = classes.rule_providers.get(rule_id, DEFAULT_PROVIDER)
    cls = classes.rule_to_class.get(rule_id, DEFAULT_CLASS)
    if rule_id == "stripe-access-token":
        cls = "C" if _STRIPE_TEST.match(secret) else "A"
    elif rule_id == "gcp-api-key" and "firebase" in file.lower():
        cls = "C"
    elif value_context(rule_id, secret):
        cls = "C"
    return cls, provider


# --------------------------------------------------------------------------- value shape

VALUE_CONTEXTS = ("no-key-body", "placeholder", "not-a-credential")
PLACEHOLDER_RULES = ("generic-api-key", "curl-auth-header", "curl-auth-user")
_PEM_HEADER = re.compile(r"-----BEGIN[ A-Z0-9_-]{0,100}-----")
_PEM_FOOTER = re.compile(r"-----END[ A-Z0-9_-]{0,100}-----")
_KEY_RUN = re.compile(r"[A-Za-z0-9+/=]{40,}")
_KEY_MARK = re.compile(r"[0-9+/]")
# A value that only refers to a variable: ${VAR}, $VAR, {{ var }}, %VAR%, with an optional trailing ":"
# (curl -u "${KEY}:"). It holds no secret, whatever it points to.
_VARREF = re.compile(r"(?:\$\{[A-Za-z_][A-Za-z0-9_.-]*\}|\$[A-Z_][A-Z0-9_]*|\{\{[^{}]{1,80}\}\}|%[A-Z_][A-Z0-9_]*%):?")
# Shapes of generic-api-key values that are names, not keys. Each shape excludes what a generated key
# looks like: words without any digit; a dotted path whose parts are lower-case or CamelCase words (so the
# mixed-case base64url parts of a JWT never match); a semantic or Go pseudo-version; an advisory or ticket id.
_WORDS = re.compile(r"[A-Za-z]+(?:[._-][A-Za-z]+)*")
_DOTTED = re.compile(r"(?:[a-z][a-z0-9_-]*|[A-Z][A-Za-z]*)(?:\.(?:[a-z][a-z0-9_-]*|[A-Z][A-Za-z]*)){2,}=?")
_VERSION = re.compile(r"v?\d{1,4}\.\d{1,4}\.\d{1,6}(?:-[0-9A-Za-z.]+)*(?:\+[0-9A-Za-z.]+)?")
_ADVISORY = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*-\d+(?:-\d+)*")


def has_key_body(secret: str) -> bool:
    """A private-key match holds key material: between the BEGIN and END lines there is at least one run
    of 40 or more base64 characters (a PEM line is 64) holding a digit, `+` or `/`, after `\\n` escapes
    of a key in a string literal are turned into line breaks. Header lines that are only mentioned (prose,
    an assertion, a long method name between two of them) have none."""
    body = secret.replace("\\n", "\n").replace("\\r", "\n")
    head = _PEM_HEADER.search(body)
    if head is not None:
        body = body[head.end():]
    foot = _PEM_FOOTER.search(body)
    if foot is not None:
        body = body[:foot.start()]
    return any(_KEY_MARK.search(run) for run in _KEY_RUN.findall(body))


def value_context(rule_id: str, secret: str) -> str | None:
    """A label when the matched value itself is no credential, else None. Decided by the value's shape
    alone, never by its file, and only for three rules:

    - `private-key` without a key body (`has_key_body`): `no-key-body`;
    - `generic-api-key`, `curl-auth-header`, `curl-auth-user` whose value only names a variable
      (`${API_KEY}`, `$TOKEN`, `{{ key }}`): `placeholder`;
    - `generic-api-key` whose value is letter words without a digit, a dotted name (`org.example.Type`,
      `a.b.key=`), a version (`v1.2.3`, a Go pseudo-version) or an advisory/ticket id (`ABC-JS-FOO-123`):
      `not-a-credential`.

    A value with any other shape keeps its rule's class: hex strings, UUIDs and mixed-case strings look
    the same whether they are a key or a hash, so they are never guessed away."""
    if rule_id == "private-key":
        return None if has_key_body(secret) else "no-key-body"
    if rule_id not in PLACEHOLDER_RULES:
        return None
    value = secret.strip().strip("\"'`").strip()
    if _VARREF.fullmatch(value):
        return "placeholder"
    if rule_id == "generic-api-key" and any(p.fullmatch(value) for p in (_WORDS, _DOTTED, _VERSION, _ADVISORY)):
        return "not-a-credential"
    return None


# --------------------------------------------------------------------------- path context

CONTEXT_TEXT = {
    "test": "test code", "fixture": "test fixture", "example": "example or sample", "docs": "documentation",
    "vendored": "vendored or third-party code", "data": "data file", "dev": "local development setup",
    "no-key-body": "key header text only, no key material", "placeholder": "a variable reference, no value",
    "not-a-credential": "a name, version or id, not a key",
}
SKIP_LABEL = "deployable"   # sbom-audit.toml [secrets.context] deployable = [...]: never context
_LOWER = {"A": "B", "B": "C", "C": "C"}


def _matches(path: str, pattern: str) -> bool:
    """"dir/" (or "a/b/"): that directory sequence anywhere in the path, case-insensitive; a pattern with
    another "/": the whole path (glob); else the file name (glob, case-sensitive)."""
    if pattern.endswith("/"):
        return ("/" + pattern.strip("/").lower() + "/") in ("/" + path.lower())
    if "/" in pattern:
        return fnmatch.fnmatchcase(path, pattern.lstrip("/"))
    return fnmatch.fnmatchcase(path.rsplit("/", 1)[-1], pattern)


def context_rules(classes: Classes, extra: dict[str, tuple[str, ...]] | None = None) -> dict[str, tuple[str, ...]]:
    """The labels and patterns in force: classes.toml's `[context]` plus sbom-audit.toml's
    `[secrets.context]` (added per label; a new label goes last; `deployable` is kept as is)."""
    rules = {label: tuple(patterns) for label, patterns in classes.context.items()}
    for label, patterns in (extra or {}).items():
        rules[label] = rules.get(label, ()) + tuple(patterns)
    return rules


def path_context(path: str, rules: dict[str, tuple[str, ...]]) -> str | None:
    """The first label whose patterns match the file path, None for deployable code and config."""
    path = (path or "").replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    if not path or any(_matches(path, p) for p in rules.get(SKIP_LABEL, ())):
        return None
    for label, patterns in rules.items():
        if label != SKIP_LABEL and any(_matches(path, p) for p in patterns):
            return label
    return None


def apply_context(items: list[dict], classes: Classes, *, enabled: bool = True,
                  extra: dict[str, tuple[str, ...]] | None = None) -> list[dict]:
    """Set `class` and `context` of every finding from its `base_class` (the class of rule and value,
    see `classify`) and its file path; in place, and returned. Nothing is removed, so per-class totals
    still add up to the number of findings.

    - A value-shape label (`VALUE_CONTEXTS`, set at redaction) is kept as is.
    - A path label ranks the finding one class lower (A to B, B to C), unless the same value (`value_id`)
      is also found in a file without context: then the class stays, the label is kept.
    - `enabled` False (`rank_by_context = false`): every class is its base class again; labels are kept.

    A document written before `base_class` existed uses its `class` as the base class."""
    rules = context_rules(classes, extra)
    labels: dict[int, str | None] = {}
    plain_values: set[str] = set()
    for f in items:
        if not f.get("base_class"):
            f["base_class"] = f.get("class")
        label = f.get("context")
        if label not in VALUE_CONTEXTS:
            label = path_context(str(f.get("file") or ""), rules)
        labels[id(f)] = label
        if label is None and f.get("value_id"):
            plain_values.add(f["value_id"])
    for f in items:
        label = labels[id(f)]
        f["context"] = label
        base = f["base_class"]
        if not enabled or label is None or label in VALUE_CONTEXTS or f.get("value_id") in plain_values:
            f["class"] = base
        else:
            f["class"] = _LOWER.get(base, base)
    return items


def ranked_lower(f: dict) -> bool:
    """The finding's class is lower than its base class because of its path context."""
    return bool(f.get("context")) and f.get("context") not in VALUE_CONTEXTS and \
        f.get("base_class") not in (None, f.get("class"))


def context_text(label) -> str:
    """Plain words for a context label; a label from sbom-audit.toml is shown as is."""
    return CONTEXT_TEXT.get(str(label), str(label))
