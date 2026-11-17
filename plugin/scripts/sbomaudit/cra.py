"""Cyber Resilience Act readiness: which evidence exists per product, which is missing or stale.

Regulation (EU) 2024/2847. Evidence tooling, not legal advice: this module never decides whether a product is
in scope or meets the Regulation. It looks for evidence and says where it found it, what is missing, what is
older than the configured review interval, and what only the manufacturer can answer.

Only projects listed under `[cra.products]` in sbom-audit.toml are products; nothing is assumed in scope.
The product repositories are read from git objects of one branch (nothing is checked out, nothing is written
there). Starter documents and proposals are written only into `<security>/cra/<product>/`.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from .cache import atomic_write
from .errors import ConfigError

CRA_FILE = "CRA.md"
CRA_JSON = "cra.json"
CRA_DIR = "cra"
RELEASES_JSON = "releases.json"
SCHEMA = 1
DEFAULT_REVIEW_DAYS = 365
DEFAULT_AUDIT_MAX_AGE_DAYS = 8                 # a weekly schedule plus a day
WELL_KNOWN_TIMEOUT = 10
WELL_KNOWN_MAX_BYTES = 64 * 1024
TEMPLATE_DIR = Path(__file__).resolve().parents[2] / "templates" / "cra"
LANGUAGES = ("en", "de")
# First line of every starter document; while it is there, the document counts as not filled in.
STARTER_MARK = "sbom-audit cra starter"
CAVEAT = ("Evidence tooling, not legal advice: this overview shows which evidence exists. It does not decide "
          "whether a product is in scope of Regulation (EU) 2024/2847 or whether it meets it.")

STATUSES = ("present", "missing", "stale", "manufacturer")
STATUS_TEXT = {"present": "evidence present", "missing": "evidence missing", "stale": "stale",
               "manufacturer": "manufacturer's responsibility"}

# id -> (reference in Regulation (EU) 2024/2847, title). Read from the Official Journal text (EN and DE,
# EUR-Lex OJ:L_202402847); see docs/reference.md for the source list.
OBLIGATIONS: dict[str, tuple[str, str]] = {
    "risk_assessment": ("Art. 13(2), 13(3), 13(7); Annex I Part I; Annex VII point 3",
                        "Cybersecurity risk assessment, documented and updated during the support period"),
    "contact": ("Art. 13(17); Annex I Part II (6); Annex II point 2",
                "Single point of contact and a contact address for reporting vulnerabilities"),
    "security_txt": ("Annex I Part II (6); Annex II point 2 (RFC 9116 is one common way, not a CRA requirement)",
                     "Machine-readable contact (security.txt) with a valid Expires date"),
    "cvd_policy": ("Annex I Part II (5); Art. 13(8); Annex VII point 2(b)",
                   "Coordinated vulnerability disclosure policy"),
    "reporting": ("Art. 14(1)-(8); Art. 16; Art. 69(3); Art. 71(2)",
                  "Procedure for reporting actively exploited vulnerabilities and severe incidents"),
    "sbom": ("Annex I Part II (1); Annex VII point 2(b)",
             "Software bill of materials, machine-readable, at least top-level dependencies"),
    "vulnerability_handling": ("Annex I Part II (2), (3); Art. 13(8)",
                               "Vulnerabilities identified and addressed without delay, regular tests and reviews"),
    "decisions_trail": ("Art. 13(7); Annex VII point 2(b)",
                        "Documented vulnerability decisions and an evidence trail"),
    "support_period": ("Art. 13(8), 13(19); Annex II point 7; Annex VII point 4",
                       "Support period determined, end date stated"),
    "released_versions": ("Annex I Part II (2), (8); Art. 13(9)",
                          "Released versions under audit during the support period"),
}
MANUFACTURER: dict[str, tuple[str, str]] = {
    "scope": ("Art. 2, 3, 7; Annex III, IV",
              "Whether the product is in scope, and its category (default, important, critical)"),
    "essential_requirements": ("Annex I Part I (1), (2)(a)-(m)",
                               "Implementing the product properties of Annex I Part I"),
    "advisories": ("Annex I Part II (4), (7), (8)",
                   "Publishing fixed vulnerabilities, secure update distribution, advisory messages"),
    "components": ("Art. 13(6)", "Reporting vulnerabilities found in components to their maintainers"),
    "user_information": ("Art. 13(16), 13(18); Annex II", "Information and instructions to the user"),
    "technical_documentation": ("Art. 13(13), 31; Annex VII", "Technical documentation, kept for 10 years"),
    "conformity": ("Art. 28, 30, 32; Annex V", "Conformity assessment, EU declaration of conformity, CE marking"),
}
ORDER = (*OBLIGATIONS, *MANUFACTURER)

# Where a product's repository may hold the files the checks look for (the first one found is reported).
SECURITY_MD_PATHS = ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")
SECURITY_TXT_PATHS = (".well-known/security.txt", "public/.well-known/security.txt",
                      "static/.well-known/security.txt", "security.txt")
_REVIEWED_RE = re.compile(r"^\s*[-*]?\s*\**(?:Last reviewed|Zuletzt geprüft)\**\s*:\s*\**\s*(\d{4}-\d{2}-\d{2})",
                          re.I | re.M)

# Starter documents for `cra init`: template name -> path under cra/<product>/ (proposals for the product
# repository go to proposed-for-repo/, never into the repository itself).
STARTERS = (
    ("risk-assessment.md", "risk-assessment.md"),
    ("art14-procedure.md", "art14-procedure.md"),
    ("cvd-policy.md", "cvd-policy.md"),
    ("art14-early-warning.md", "art14/early-warning.md"),
    ("art14-notification.md", "art14/notification.md"),
    ("art14-final.md", "art14/final.md"),
    ("SECURITY.md", "proposed-for-repo/SECURITY.md"),
    ("security.txt", "proposed-for-repo/security.txt"),
)
REPO_TARGETS = {
    "proposed-for-repo/SECURITY.md": "SECURITY.md at the root of the repository (or .github/SECURITY.md)",
    "proposed-for-repo/security.txt": "/.well-known/security.txt on the product's web host, served over HTTPS "
                                      "(for many frameworks: public/.well-known/security.txt)",
}


# --------------------------------------------------------------------------- config

@dataclass
class Product:
    key: str                       # the project name (folder) in the portfolio
    name: str
    branch: str | None = None
    url: str | None = None


@dataclass
class CraConfig:
    products: list[Product] = field(default_factory=list)
    review_interval_days: int = DEFAULT_REVIEW_DAYS
    audit_max_age_days: int = DEFAULT_AUDIT_MAX_AGE_DAYS
    check_well_known: bool = False


def _origin(url: str, where: str) -> str:
    """An https:// origin (scheme, host, optional port) without path, query or credentials."""
    try:
        p = urllib.parse.urlsplit(url)
        p.port                                           # noqa: B018 - raises on a malformed port
    except ValueError:
        raise ConfigError(f"{where} is not a valid URL") from None
    if p.scheme != "https" or not p.hostname:
        raise ConfigError(f"{where} must be an https:// URL such as https://shop.example")
    if p.username or p.password or p.query or p.fragment or p.path not in ("", "/"):
        raise ConfigError(f"{where} must be the site's origin only, such as https://shop.example")
    return f"https://{p.netloc}"


def load_config(out: Path) -> CraConfig:
    """`[cra]` of `<out>/sbom-audit.toml`; an absent table means no product (nothing is assumed in scope)."""
    from .config import CONFIG_NAME, _bool, _int, _str
    path = Path(out) / CONFIG_NAME
    if not path.exists():
        return CraConfig()
    with path.open("rb") as fh:
        raw = tomllib.load(fh).get("cra")
    if raw is None:
        return CraConfig()
    if not isinstance(raw, dict):
        raise ConfigError("[cra] must be a table")
    cfg = CraConfig(
        review_interval_days=_int(raw.get("review_interval_days", DEFAULT_REVIEW_DAYS), "[cra] review_interval_days", 1),
        audit_max_age_days=_int(raw.get("audit_max_age_days", DEFAULT_AUDIT_MAX_AGE_DAYS), "[cra] audit_max_age_days", 1),
        check_well_known=_bool(raw.get("check_well_known", False), "[cra] check_well_known"))
    products = raw.get("products", {})
    if not isinstance(products, dict):
        raise ConfigError("[cra.products] must be a table")
    for key, opts in products.items():
        where = f'[cra.products."{key}"]'
        if not isinstance(opts, dict):
            raise ConfigError(f"{where} must be a table")
        name = _str(opts["name"], f"{where} name") if "name" in opts else key
        branch = _str(opts["branch"], f"{where} branch") if "branch" in opts else None
        url = _origin(_str(opts["url"], f"{where} url"), f"{where} url") if "url" in opts else None
        cfg.products.append(Product(key=key, name=name, branch=branch, url=url))
    return cfg


# --------------------------------------------------------------------------- reading evidence

def _today() -> dt.date:
    return dt.datetime.now().astimezone().date()


def _parse_time(value) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        when = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return when if when.tzinfo else when.replace(tzinfo=dt.timezone.utc)


def _read_json(path: Path):
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def is_starter(text: str) -> bool:
    """True while the starter line of `cra init` is still in the document (blanks not filled in)."""
    return STARTER_MARK in "\n".join(text.splitlines()[:3])


def reviewed_on(text: str) -> dt.date | None:
    """The `Last reviewed: YYYY-MM-DD` (German: `Zuletzt geprüft:`) date of a document, or None."""
    m = _REVIEWED_RE.search(text)
    if not m:
        return None
    try:
        return dt.date.fromisoformat(m.group(1))
    except ValueError:
        return None


def parse_security_txt(text: str) -> dict:
    """The RFC 9116 fields this check needs: contacts, expires (raw), policy. Comments and signatures ignored."""
    fields: dict = {"contact": [], "expires": [], "policy": []}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().lower()
        if key in fields:
            fields[key].append(value.strip())
    return fields


def security_txt_state(text: str, today: dt.date) -> tuple[str, str]:
    """(status, note) for one security.txt: Contact and exactly one Expires are required (RFC 9116 2.5.3, 2.5.5)."""
    if is_starter(text):
        return "missing", "starter file, blanks not filled in"
    f = parse_security_txt(text)
    if not f["contact"]:
        return "missing", "no Contact field (required by RFC 9116)"
    if not f["expires"]:
        return "missing", "no Expires field (required by RFC 9116)"
    if len(f["expires"]) > 1:
        return "missing", "more than one Expires field (RFC 9116 allows one)"
    when = _parse_time(f["expires"][0])
    if when is None:
        return "missing", f"Expires is not an RFC 3339 date-time: {f['expires'][0][:40]}"
    day = when.date()
    if day < today:
        return "stale", f"Expires {day.isoformat()} has passed"
    note = f"Expires {day.isoformat()}"
    if day > today + dt.timedelta(days=366):
        note += " (RFC 9116 recommends less than a year ahead)"
    return "present", note


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - urllib hook
        return None                                     # a redirect is reported, never followed


def fetch_well_known(origin: str, timeout: int = WELL_KNOWN_TIMEOUT) -> tuple[int | None, str]:
    """GET <origin>/.well-known/security.txt over HTTPS, no redirects, no cookies, at most 64 KiB.
    Returns (HTTP status or None, body text); the body is empty for anything but 200."""
    url = origin.rstrip("/") + "/.well-known/security.txt"
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "sbom-audit", "Accept": "text/plain"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read(WELL_KNOWN_MAX_BYTES).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        exc.close()
        return exc.code, ""
    except (urllib.error.URLError, OSError, ValueError):
        return None, ""


def _git_file(repo: Path, ref: str, path: str) -> str | None:
    from .code import SAFE
    from .gitio import GitError, git_bytes
    try:
        return git_bytes(repo, *SAFE, "cat-file", "blob", f"{ref}:{path}").decode("utf-8", errors="replace")
    except GitError:
        return None


def _first_file(repo: Path, ref: str, paths) -> tuple[str | None, str | None]:
    for path in paths:
        text = _git_file(repo, ref, path)
        if text is not None:
            return path, text
    return None, None


def _evidence_doc(out: Path, product: Product, name: str, today: dt.date, review_days: int | None = None
                  ) -> tuple[str, list[str], str]:
    """(status, evidence, note) for a document in cra/<product>/; `review_days` adds the review-date check."""
    rel = f"{CRA_DIR}/{product.key}/{name}"
    path = out / rel
    if not path.is_file():
        return "missing", [], f"no {rel} (`cra init {product.key}` writes a starter)"
    text = path.read_text(encoding="utf-8", errors="replace")
    if is_starter(text):
        return "missing", [rel], "starter document, blanks not filled in yet"
    if review_days is None:
        return "present", [rel], ""
    day = reviewed_on(text)
    if day is None:
        return "missing", [rel], "no `Last reviewed: YYYY-MM-DD` line"
    age = (today - day).days
    if age > review_days:
        return "stale", [rel], f"last reviewed {day.isoformat()}, {age} days ago (interval {review_days} days)"
    return "present", [rel], f"last reviewed {day.isoformat()}"


def _product_kev(audit: dict | None, project: str, branch: str | None) -> int:
    """Open KEV findings of the product's project on its branch (any branch when the branch is unknown)."""
    if not audit:
        return 0
    n = 0
    for v in audit.get("vulnerabilities") or []:
        if not (isinstance(v, dict) and v.get("kev")):
            continue
        locs = [loc for loc in v.get("locations") or [] if isinstance(loc, dict) and loc.get("project") == project]
        if any(branch is None or loc.get("branch") == branch for loc in locs):
            n += 1
    return n


def _releases_for(releases: dict | None, project: str) -> dict | None:
    projects = (releases or {}).get("projects")
    entry = projects.get(project) if isinstance(projects, dict) else None
    return entry if isinstance(entry, dict) else None


# --------------------------------------------------------------------------- the check

def _ob(oid: str, status: str, evidence=None, note: str = "") -> dict:
    ref, title = OBLIGATIONS.get(oid) or MANUFACTURER[oid]
    return {"id": oid, "ref": ref, "title": title, "status": status, "evidence": list(evidence or []), "note": note}


def check_product(cfg, ccfg: CraConfig, product: Product, out: Path, *, audit: dict | None,
                  releases: dict | None, today: dt.date, fetch=fetch_well_known) -> dict:
    """One product's readiness: every obligation with one status, the evidence named by path."""
    from . import config
    from .gitio import GitError, branch_ref, pick_branches
    projects = {p.name: p for p in config.discover(cfg)}
    project = projects.get(product.key)
    res: dict = {"name": product.name, "project": product.key, "branch": None, "commit": None, "error": None,
                 "url": product.url, "kev_open": 0, "obligations": []}
    obs = res["obligations"]
    ref = None
    if project is None:
        res["error"] = f"no project {product.key!r} in the portfolio"
    else:
        wanted = [product.branch] if product.branch else list(cfg.branches)
        try:
            found = pick_branches(project.path, wanted)
            if found:
                ref, sha, _behind = branch_ref(project.path, found[0])
                res["branch"], res["commit"] = found[0], sha
            else:
                res["error"] = f"no branch {' or '.join(wanted)} in {product.key}"
        except GitError as exc:
            res["error"] = f"git: {type(exc).__name__}"
    on = f"{product.key}@{res['branch']}" if res["branch"] else product.key

    # risk assessment
    obs.append(_ob("risk_assessment", *_evidence_doc(out, product, "risk-assessment.md", today,
                                                     ccfg.review_interval_days)))
    # single point of contact: SECURITY.md in the product repository
    proposal = f"{CRA_DIR}/{product.key}/proposed-for-repo/SECURITY.md"
    if ref is None:
        obs.append(_ob("contact", "missing", [], "repository not read: " + (res["error"] or "unknown")))
    else:
        path, text = _first_file(project.path, ref, SECURITY_MD_PATHS)
        if path is None:
            hint = f"; a proposal is in {proposal}" if (out / proposal).is_file() else \
                f"; `cra init {product.key}` writes a proposal"
            obs.append(_ob("contact", "missing", [], f"no SECURITY.md on {on}{hint}"))
        elif is_starter(text):
            obs.append(_ob("contact", "missing", [f"{on}:{path}"], "starter file, blanks not filled in"))
        else:
            obs.append(_ob("contact", "present", [f"{on}:{path}"],
                           "the text is the manufacturer's; check it names a way to report that is not only automated "
                           "(Art. 13(17))"))
    # security.txt: in the repository, and over HTTPS when enabled
    states: list[tuple[str, str, str]] = []
    if ref is not None:
        path, text = _first_file(project.path, ref, SECURITY_TXT_PATHS)
        if path is not None:
            states.append((f"{on}:{path}", *security_txt_state(text, today)))
    if ccfg.check_well_known and product.url:
        url = product.url + "/.well-known/security.txt"
        code, body = fetch(product.url)
        if code == 200 and body:
            states.append((url, *security_txt_state(body, today)))
        else:
            states.append((url, "missing", f"HTTP {code}" if code else "not reachable"))
    if not states:
        obs.append(_ob("security_txt", "missing", [], "no security.txt in the repository"
                       + ("" if ccfg.check_well_known and product.url else
                          "; the HTTPS check is off ([cra] check_well_known)")))
    else:
        rank = {"present": 0, "stale": 1, "missing": 2}
        best = min(states, key=lambda s: rank[s[1]])
        notes = "; ".join(f"{where}: {note}" for where, _st, note in states if note)
        obs.append(_ob("security_txt", best[1], [s[0] for s in states if s[1] != "missing" or s[0] == best[0]],
                       notes))
    # CVD policy and the reporting procedure
    obs.append(_ob("cvd_policy", *_evidence_doc(out, product, "cvd-policy.md", today)))
    status, evidence, note = _evidence_doc(out, product, "art14-procedure.md", today)
    kev = _product_kev(audit, product.key, res["branch"])
    res["kev_open"] = kev
    if kev:
        note = (note + "; " if note else "") + (
            f"{kev} open KEV finding(s) in this product: decide whether it is an actively exploited vulnerability "
            f"in the product (Art. 3(42)); if so the 24-hour early warning of Art. 14(2)(a) applies, see "
            f"{CRA_DIR}/{product.key}/art14-procedure.md")
    obs.append(_ob("reporting", status, evidence, note))
    # SBOM and the audit
    sbom = f"sbom/{product.key}/{res['branch']}.cdx.json" if res["branch"] else None
    if sbom and (out / sbom).is_file():
        obs.append(_ob("sbom", "present", [sbom]))
    else:
        obs.append(_ob("sbom", "missing", [], f"no {sbom or f'sbom/{product.key}/'} (run /sbom-audit:run)"))
    generated = _parse_time((audit or {}).get("generated_at"))
    if audit is None or generated is None:
        obs.append(_ob("vulnerability_handling", "missing", [], "no readable audit.json (run /sbom-audit:run)"))
    else:
        age = (today - generated.astimezone().date()).days
        st = "stale" if age > ccfg.audit_max_age_days else "present"
        obs.append(_ob("vulnerability_handling", st, ["audit.json", "AUDIT.md"],
                       f"last audit {generated.date().isoformat()}, {age} days ago (limit {ccfg.audit_max_age_days})"))
    trail = [n for n in ("log.md", "reports") if (out / n).exists()]
    vex = f"vex/{product.key}.openvex.json"
    if (out / vex).is_file():
        trail.append(vex)
    obs.append(_ob("decisions_trail", "present" if "log.md" in trail else "missing", trail,
                   "" if (out / vex).is_file() else "no OpenVEX decision recorded for this project yet"))
    # support period and released versions (releases.json is written by the release audit, never here)
    entry = _releases_for(releases, product.key)
    support = (entry or {}).get("support") if isinstance((entry or {}).get("support"), dict) else {}
    if support.get("period_months") or support.get("until"):
        bits = [f"{support['period_months']} months" if support.get("period_months") else "",
                f"until {support['until']}" if support.get("until") else ""]
        obs.append(_ob("support_period", "present", [RELEASES_JSON], ", ".join(b for b in bits if b)
                       + "; Art. 13(8): at least five years unless the expected use is shorter"))
    else:
        obs.append(_ob("support_period", "missing", [],
                       "no support period in releases.json" if entry else "no released versions under audit"))
    rels = [r for r in (entry or {}).get("releases") or [] if isinstance(r, dict)]
    if not rels:
        obs.append(_ob("released_versions", "missing", [], "no released versions under audit"))
    else:
        supported = [r for r in rels if r.get("supported")]
        notes = [f"{len(rels)} release(s), {len(supported)} supported"]
        for r in supported:
            o = r.get("open") if isinstance(r.get("open"), dict) else {}
            if o.get("kev"):
                notes.append(f"{r.get('tag')}: {o['kev']} open KEV, see the reporting procedure")
            if r.get("eol_before_support_end"):
                notes.append(f"{r.get('tag')}: end of life before support ends: "
                             + ", ".join(str(x) for x in r["eol_before_support_end"][:5]))
            if r.get("eol_unknown"):
                notes.append(f"{r.get('tag')}: end of life unknown: "
                             + ", ".join(str(x) for x in r["eol_unknown"][:5]))
        obs.append(_ob("released_versions", "present", [RELEASES_JSON], "; ".join(notes)))
    for oid in MANUFACTURER:
        obs.append(_ob(oid, "manufacturer"))
    return res


def check(cfg, out: Path, *, today: dt.date | None = None, fetch=fetch_well_known) -> dict:
    out = Path(out)
    ccfg = load_config(out)
    today = today or _today()
    audit = _read_json(out / "audit.json")
    releases = _read_json(out / RELEASES_JSON)
    products = {p.key: check_product(cfg, ccfg, p, out, audit=audit, releases=releases, today=today, fetch=fetch)
                for p in ccfg.products}
    return {"schema": SCHEMA, "generated_at": dt.datetime.now().astimezone().replace(microsecond=0).isoformat(),
            "caveat": CAVEAT, "review_interval_days": ccfg.review_interval_days,
            "audit_max_age_days": ccfg.audit_max_age_days, "check_well_known": ccfg.check_well_known,
            "releases_json": (out / RELEASES_JSON).exists(), "products": products}


def _md(text) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_md(doc: dict) -> str:
    L = [f"# CRA readiness {doc['generated_at'][:10]}", "",
         f"> {CAVEAT}", "",
         "Regulation (EU) 2024/2847. Art. 14 (reporting) applies from 11 September 2026, also to products placed "
         "on the market before 11 December 2027 (Art. 69(3)); the rest of the Regulation applies from "
         "11 December 2027 (Art. 71(2)).", "",
         f"Statuses: **evidence present** (the file is named), **evidence missing**, **stale** (older than the "
         f"review interval of {doc['review_interval_days']} days, or an audit older than "
         f"{doc['audit_max_age_days']} days, or a passed Expires date), **manufacturer's responsibility** "
         f"(no file can show it; only you can).", ""]
    if not doc["products"]:
        L += ["No product is configured. Add the projects that are products under `[cra.products]` in "
              "sbom-audit.toml; nothing is assumed to be in scope.", ""]
    for key, p in doc["products"].items():
        where = f"`{key}`" + (f", branch `{p['branch']}`" if p["branch"] else "")
        L += [f"## {_md(p['name'])} ({where})", ""]
        if p["error"]:
            L += [f"Repository not read: {_md(p['error'])}.", ""]
        if p["kev_open"]:
            L += [f"**{p['kev_open']} open KEV finding(s).** Check `{CRA_DIR}/{key}/art14-procedure.md`: an "
                  "actively exploited vulnerability in the product starts the 24-hour clock of Art. 14(2)(a).", ""]
        counts = {s: sum(1 for o in p["obligations"] if o["status"] == s) for s in STATUSES}
        L += [", ".join(f"{STATUS_TEXT[s]}: {counts[s]}" for s in STATUSES), "",
              "| Obligation | Reference | Status | Evidence | Note |", "|---|---|---|---|---|"]
        for o in p["obligations"]:
            ev = ", ".join(f"`{_md(x)}`" for x in o["evidence"]) or "-"
            L.append(f"| {_md(o['title'])} | {_md(o['ref'])} | {STATUS_TEXT[o['status']]} | {ev} | "
                     f"{_md(o['note']) or ''} |")
        L.append("")
    L += ["## What this overview does not check", "",
          "- Whether a product is in scope, its category, and whether it meets Annex I: that is the manufacturer's "
          "assessment.",
          "- The content of the documents: a filled-in risk assessment is evidence that one exists, not that it "
          "is complete or right.",
          "- Submissions to the ENISA single reporting platform: they are not visible from this folder.",
          "- Released versions and the support period come from `releases.json` when it exists; without it they are "
          "reported as missing evidence.", ""]
    return "\n".join(L)


def write(out: Path, doc: dict) -> list[Path]:
    out = Path(out)
    return [atomic_write(out / CRA_JSON, json.dumps(doc, indent=2, ensure_ascii=False) + "\n"),
            atomic_write(out / CRA_FILE, render_md(doc))]


def try_check(cfg, out: Path, say=print) -> list[Path]:
    """The `run` step: only with at least one configured product; never raises, never changes the exit code."""
    try:
        if not load_config(out).products:
            return []
        doc = check(cfg, out)
        paths = write(out, doc)
        n = sum(1 for p in doc["products"].values() for o in p["obligations"] if o["status"] in ("missing", "stale"))
        say(f"cra: readiness for {len(doc['products'])} product(s) in {CRA_FILE}, {n} item(s) missing or stale")
        return paths
    except ConfigError as exc:
        say(f"cra: skipped, sbom-audit.toml: {exc}")
    except Exception as exc:                          # the type only, as everywhere
        say(f"cra: skipped ({type(exc).__name__})")
    return []


# --------------------------------------------------------------------------- init

def _fill(text: str, product: Product, today: dt.date) -> str:
    return (text.replace("{{product}}", product.name).replace("{{project}}", product.key)
            .replace("{{today}}", today.isoformat()))


def init_plan(out: Path, product: Product, lang: str) -> list[tuple[str, str, str]]:
    """[(template file, path under out, "new" | "exists, kept")]: existing files are never overwritten."""
    plan = []
    for tmpl, rel in STARTERS:
        dest = f"{CRA_DIR}/{product.key}/{rel}"
        plan.append((str(TEMPLATE_DIR / lang / tmpl), dest, "exists, kept" if (out / dest).exists() else "new"))
    return plan


def init(out: Path, product: Product, lang: str, today: dt.date | None = None) -> list[Path]:
    today = today or _today()
    written = []
    for tmpl, dest, state in init_plan(out, product, lang):
        if state != "new":
            continue
        written.append(atomic_write(out / dest, _fill(Path(tmpl).read_text(encoding="utf-8"), product, today)))
    return written


# --------------------------------------------------------------------------- CLI

def _product(out: Path, key: str) -> Product:
    for p in load_config(out).products:
        if p.key == key:
            return p
    raise ConfigError(f'{key!r} is not a configured product; add [cra.products."{key}"] first '
                      "(only listed projects are treated as products)")


def cli(args) -> int:
    import sys
    from . import config
    out = Path(args.out)
    if args.cra_command == "init":
        product = _product(out, args.product)
        lang = args.lang or config.load(out).report.language
        if lang not in LANGUAGES:
            lang = "en"
        plan = init_plan(out, product, lang)
        print(f"cra init {product.key} ({lang}): starter documents in {out / CRA_DIR / product.key}; nothing is "
              "written into the product repository")
        for _tmpl, dest, state in plan:
            target = REPO_TARGETS.get(dest.split("/", 2)[2])
            print(f"  {state:<13} {dest}" + (f"  -> belongs in the product as {target}" if target else ""))
        if not args.yes:
            print("plan only: nothing written. Run again with --yes after the user confirmed.")
            return 0
        for path in init(out, product, lang):
            print(f"written {path.relative_to(out)}")
        print("The documents ask questions and leave blanks; the answers are yours. "
              "Delete the first line of a document once its blanks are filled in.")
        return 0
    cfg = config.load(out)
    if not load_config(out).products:
        print('no product configured: add [cra.products."<project>"] to sbom-audit.toml '
              "(nothing is assumed to be in scope)", file=sys.stderr)
        return 2
    doc = check(cfg, out)
    for path in write(out, doc):
        print(path.relative_to(out))
    for key, p in doc["products"].items():
        counts = {s: sum(1 for o in p["obligations"] if o["status"] == s) for s in STATUSES}
        print(f"{key}: " + ", ".join(f"{STATUS_TEXT[s]} {counts[s]}" for s in STATUSES)
              + (f"; {p['kev_open']} open KEV: see the reporting procedure" if p["kev_open"] else ""))
    return 0
