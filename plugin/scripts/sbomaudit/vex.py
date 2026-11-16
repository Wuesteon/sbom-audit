"""OpenVEX 0.2.0 documents: one file per project under <out>/vex/, applied to findings.

Product = the project purl (`pkg:github/<owner>/<repo>` or `pkg:generic/<name>`), optionally
`@<branch>`; subcomponent = the package purl with or without version.
"""
from __future__ import annotations

import datetime as dt
import json
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__
from .errors import VexError
from .model import Finding

CONTEXT = "https://openvex.dev/ns/v0.2.0"
ID_PREFIX = "https://github.com/Wuesteon/sbom-audit/vex"
STATUSES = ("not_affected", "affected", "fixed", "under_investigation")
JUSTIFICATIONS = ("component_not_present", "vulnerable_code_not_present",
                  "vulnerable_code_not_in_execute_path",
                  "vulnerable_code_cannot_be_controlled_by_adversary",
                  "inline_mitigations_already_exist")
SUPPRESSING = ("not_affected", "fixed")


@dataclass
class Statement:
    vuln: str
    product: str
    subcomponents: list[str] = field(default_factory=list)
    status: str = "under_investigation"
    justification: str | None = None
    impact: str | None = None
    timestamp: str = ""
    project: str = ""          # file stem: <out>/vex/<project>.openvex.json
    path: str = ""

    def to_dict(self) -> dict:
        return {"vuln": self.vuln, "product": self.product, "subcomponents": list(self.subcomponents),
                "status": self.status, "justification": self.justification, "impact": self.impact,
                "timestamp": self.timestamp, "project": self.project, "path": self.path}


@dataclass
class Suppressed:
    finding: Finding
    statement: Statement

    def to_dict(self) -> dict:
        return {"finding": self.finding.to_dict(), "statement": self.statement.to_dict()}


def path(out: Path, project: str) -> Path:
    return Path(out) / "vex" / f"{project}.openvex.json"


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


# --------------------------------------------------------------------------- read

def _statement_from(raw: dict, project: str, file: Path, doc_products: list) -> list[Statement]:
    if not isinstance(raw, dict):
        raise VexError(file, "statement is not an object")
    vuln = raw.get("vulnerability")
    name = vuln.get("name") if isinstance(vuln, dict) else vuln
    if not isinstance(name, str) or not name:
        raise VexError(file, "statement without vulnerability name")
    status = raw.get("status")
    if status not in STATUSES:
        raise VexError(file, f"{name}: invalid status {status!r}")
    justification = raw.get("justification")
    impact = raw.get("impact_statement")
    if status == "not_affected" and not justification and not impact:
        raise VexError(file, f"{name}: not_affected needs a justification or impact_statement")
    if justification is not None and justification not in JUSTIFICATIONS:
        raise VexError(file, f"{name}: unknown justification {justification!r}")
    products = raw.get("products", doc_products)
    if not isinstance(products, list) or not products:
        raise VexError(file, f"{name}: statement without products")
    out = []
    for prod in products:
        pid = prod.get("@id") if isinstance(prod, dict) else prod
        if not isinstance(pid, str) or not pid:
            raise VexError(file, f"{name}: product without @id")
        subs = []
        for sub in (prod.get("subcomponents") or []) if isinstance(prod, dict) else []:
            sid = sub.get("@id") if isinstance(sub, dict) else sub
            if isinstance(sid, str) and sid:
                subs.append(sid)
        out.append(Statement(vuln=name, product=pid, subcomponents=subs, status=status,
                             justification=justification, impact=impact,
                             timestamp=str(raw.get("timestamp") or ""), project=project, path=str(file)))
    return out


def _read_doc(file: Path) -> dict:
    try:
        doc = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise VexError(file, f"not valid JSON ({exc})") from exc
    if not isinstance(doc, dict):
        raise VexError(file, "document is not a JSON object")
    if not str(doc.get("@context", "")).startswith("https://openvex.dev/ns"):
        raise VexError(file, "missing or foreign @context")
    if not isinstance(doc.get("statements"), list):
        raise VexError(file, "missing statements list")
    return doc


def load(file: Path) -> list[Statement]:
    file = Path(file)
    doc = _read_doc(file)
    project = file.name[: -len(".openvex.json")] if file.name.endswith(".openvex.json") else file.stem
    statements: list[Statement] = []
    for raw in doc["statements"]:
        statements.extend(_statement_from(raw, project, file, doc.get("products") or []))
    return statements


def load_all(out: Path) -> list[Statement]:
    folder = Path(out) / "vex"
    if not folder.is_dir():
        return []
    statements: list[Statement] = []
    for file in sorted(folder.glob("*.openvex.json")):
        statements.extend(load(file))
    return statements


# --------------------------------------------------------------------------- write

def default_author() -> str:
    for key in ("user.email", "user.name"):
        try:
            value = subprocess.run(["git", "config", "--get", key], capture_output=True, text=True).stdout.strip()
        except OSError:
            value = ""
        if value:
            return value
    return "sbom-audit"


def add(out: Path, project: str, project_purl: str, vuln: str, status: str,
        justification: str | None = None, impact: str | None = None,
        subcomponent: str | None = None, author: str | None = None) -> Path:
    """Append a statement to <out>/vex/<project>.openvex.json, creating the document if needed."""
    if status not in STATUSES:
        raise ValueError(f"status must be one of {', '.join(STATUSES)}; got {status!r}")
    if justification is not None and justification not in JUSTIFICATIONS:
        raise ValueError(f"justification must be one of {', '.join(JUSTIFICATIONS)}; got {justification!r}")
    if status == "not_affected" and not justification:
        raise ValueError("not_affected requires --justification (one of: " + ", ".join(JUSTIFICATIONS) + ")")
    file = path(out, project)
    now = _now()
    if file.exists():
        doc = _read_doc(file)
        doc["version"] = int(doc.get("version") or 0) + 1
        doc["last_updated"] = now
    else:
        doc = {"@context": CONTEXT, "@id": f"{ID_PREFIX}/{project}/{uuid.uuid4()}",
               "author": author or default_author(), "timestamp": now, "last_updated": now,
               "version": 1, "tooling": f"sbom-audit/{__version__}", "statements": []}
    product: dict = {"@id": project_purl}
    if subcomponent:
        product["subcomponents"] = [{"@id": subcomponent}]
    statement: dict = {"vulnerability": {"name": vuln}, "products": [product], "status": status,
                       "timestamp": now}
    if justification:
        statement["justification"] = justification
    if impact:
        statement["impact_statement"] = impact
    doc["statements"].append(statement)
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return file


# --------------------------------------------------------------------------- apply

def bare_purl(purl: str) -> str:
    """purl without qualifiers and subpath."""
    return purl.split("?", 1)[0].split("#", 1)[0]


def versionless(purl: str) -> str:
    base = bare_purl(purl)
    head, sep, tail = base.rpartition("@")
    return head if sep and "/" not in tail else base


def split_product(product: str) -> tuple[str, str | None]:
    """'pkg:github/o/r@dev' -> ('pkg:github/o/r', 'dev'); no suffix -> (purl, None)."""
    head, sep, tail = product.rpartition("@")
    if sep and "/" not in tail:
        return head, tail
    return product, None


def _matches(st: Statement, f: Finding, vuln: dict, purl_of: dict[str, str] | None) -> bool:
    ids = {vuln.get("id", "")} | set(vuln.get("aliases") or [])
    if st.vuln not in ids:
        return False
    base, branch = split_product(st.product)
    if purl_of is not None:
        if base != purl_of.get(f.project):
            return False
    elif st.project != f.project:
        return False
    if branch is not None and branch != f.branch:
        return False
    if st.subcomponents:
        purl = bare_purl(f.component.purl)
        if not any(bare_purl(s) == purl or (versionless(s) == s and s == versionless(purl))
                   for s in st.subcomponents):
            return False
    return True


def apply(findings: list[Finding], statements: list[Statement],
          purl_of: dict[str, str] | None = None) -> tuple[list[Finding], list[Suppressed]]:
    """Split findings into kept and suppressed by VEX; affected/under_investigation annotate only.

    `purl_of` maps project name -> project purl; without it the statement file's name is the project.
    """
    kept: list[Finding] = []
    suppressed: list[Suppressed] = []
    for f in findings:
        remaining = []
        for vuln in f.vulns:
            hit = next((s for s in statements if _matches(s, f, vuln, purl_of)), None)
            if hit is None:
                remaining.append(vuln)
            elif hit.status in SUPPRESSING:
                suppressed.append(Suppressed(Finding(f.project, f.branch, f.component, [vuln]), hit))
            else:
                vuln["vex"] = hit.status
                remaining.append(vuln)
        if remaining:
            kept.append(Finding(f.project, f.branch, f.component, remaining))
    return kept, suppressed


# --------------------------------------------------------------------------- CLI

def cli(args) -> int:
    from . import config
    cfg = config.load(args.out)
    project = next((p for p in config.discover(cfg) if p.name == args.project), None)
    if project is None:
        print(f"vex add: project {args.project!r} not found under {cfg.root}")
        return 2
    try:
        file = add(args.out, project.name, config.project_purl(project), args.vuln, args.status,
                   justification=args.justification, impact=args.impact,
                   subcomponent=args.subcomponent, author=args.author)
    except (ValueError, VexError) as exc:
        print(f"vex add: {exc}")
        return 2
    print(f"recorded {args.status} for {args.vuln} on {config.project_purl(project)} -> {file}")
    return 0
