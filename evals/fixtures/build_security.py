"""Regenerate `evals/fixtures/security/`: the last-scan state the lookup and incident evals read.

Synthetic and deterministic: three fixture projects (see `projects/`), fixed timestamps, one
real advisory (lodash 4.17.20, GHSA-35jh-r3h4-6jhm / CVE-2021-23337) so `incident` gets a `hit`
from the live OSV record. No credentials, no host names, no absolute paths.

    PYTHONPATH=plugin/scripts python3 evals/fixtures/build_security.py
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "plugin" / "scripts"))

from sbomaudit import management, report, scan, status  # noqa: E402
from sbomaudit.config import Config, ProjectOpts, write_default  # noqa: E402
from sbomaudit.model import BranchInventory, Component, Finding  # noqa: E402
from sbomaudit.readers import image_component, runtime_component  # noqa: E402

INVENTORY_AT = "2026-11-07T02:58:00Z"
AUDIT_AT = "2026-11-07T03:00:00Z"


def pkg(name, version, ecosystem="npm", manifest="package-lock.json", direct=True):
    purl_type = {"npm": "npm", "PyPI": "pypi"}[ecosystem]
    return Component(kind="package", ecosystem=ecosystem, name=name, version=version,
                     purl=f"pkg:{purl_type}/{name.lower()}@{version}", scope="required",
                     locations=[manifest], direct=direct)


def inv(project, components):
    return BranchInventory(project=project, branch="main", ref="main", commit="0000000000000000000000000000000000000001",
                           components=components, sbom_path=f"sbom/{project}/main.cdx.json")


LODASH_OLD = pkg("lodash", "4.17.20")
INVS = [
    inv("shop-web", [LODASH_OLD, image_component("node:18-alpine", "Dockerfile"),
                     runtime_component("nodejs", "18", "package.json", "engines.node >=18")]),
    inv("billing-api", [pkg("requests", "2.31.0", "PyPI", "requirements.txt"),
                        image_component("python:3.12-slim", "Dockerfile")]),
    inv("docs-site", [pkg("lodash", "4.17.21")]),
]
LODASH_VULN = {"id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"], "cves": ["CVE-2021-23337"],
               "summary": "Command Injection in lodash", "severity": "HIGH", "cvss": 7.2,
               "fixed": ["4.17.21"], "published": "2021-05-06", "modified": "2024-02-01", "withdrawn": False}


def main() -> None:
    out = HERE / "security"
    shutil.rmtree(out, ignore_errors=True)
    cfg = Config(out=out, root=Path("."), mode="portfolio", fetch=False, commit=False,
                 projects={"shop-web": ProjectOpts(production=True)})
    write_default(out, cfg)
    with (out / "sbom-audit.toml").open("a") as fh:
        fh.write('"shop-web" = { production = true }\n')
    report._now = lambda: INVENTORY_AT  # fixed timestamps keep the checked-in files reproducible
    scan.write_inventory(cfg, scan.ScanResult(inventories=INVS, generated_at=INVENTORY_AT))
    report.write_inventory_md(cfg, INVS, out)
    rep = report.build(cfg, INVS, [Finding("shop-web", "main", LODASH_OLD, [LODASH_VULN])], [], [], [],
                       {"osv-scanner": {"scanned": 3, "failed": []}})
    rep["generated_at"] = AUDIT_AT
    rep["provenance"] = {  # fixed values: what manifest.provenance records on a real run
        "sbom_audit": "fixture", "python": "3.12.0", "platform": "fixture", "config_sha256": None,
        "tools": {"syft": "1.18.1", "osv-scanner": "2.0.2", "git": "2.47.1"},
        "data_sources": {
            "osv": {"status": "ok", "origin": "live", "queried_at": AUDIT_AT, "branches_scanned": 3,
                    "branches_failed": 0},
            "cisa_kev": {"status": "ok", "entries": 1400, "origin": "live", "fetched_at": "2026-11-07T02:59:00+00:00",
                         "catalog_version": "2026.11.06", "catalog_date": "2026-11-06T15:00:00.000Z"},
            "endoflife": {"status": "ok", "answers": 0, "live": 0, "cached": 0, "without_answer": 0,
                          "oldest_fetch": None, "newest_fetch": None},
            "registries": {"status": "ok", "answers": 0, "live": 0, "cached": 0, "without_answer": 0,
                           "oldest_fetch": None, "newest_fetch": None},
            "openvex": {"status": "ok", "statements": 0}}}
    report.write_json(rep, out)
    report.write_audit_md(rep, out)
    doc = status.build(rep, secrets=None, previous=None, duration_s=12.0, exit_code=1,
                       run_host="eval-fixture", mode="portfolio")
    doc["generated_at"] = AUDIT_AT
    status.write(out, doc)
    status.write_md(out, doc, scheduler={})
    management.write(out, dated=False)  # REPORT.html, the sample the README links
    for path in sorted(out.rglob("*")):
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace(str(HERE), "."), encoding="utf-8")
        print(path.relative_to(HERE))


if __name__ == "__main__":
    main()
