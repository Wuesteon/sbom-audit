# Dependency Audit — 2026-11-07

Generated 2026-11-07T03:00:00Z by sbom-audit 1.4.1. Sources: Syft SBOMs per project and branch (committed tree, not the working copy), osv-scanner against OSV.dev, CISA KEV (actively exploited), endoflife.date (runtimes and base images), npm/PyPI/JSR registries (latest versions), OpenVEX statements in `vex/`. Full data: `audit.json`; what is installed where: `INVENTORY.md`.

EPSS (FIRST's exploit probability scores) never lowers a rank: it only ranks up a package version that is not KEV, CRITICAL or HIGH, in production or a supported release, whose score is at or above 10.0% (`[epss] promote_at`).

## Source status

A failed source means its section below is empty, not clean.

| Source | Status | Detail |
|---|---|---|
| osv-scanner | ok | scanned=3 |
| epss | ok | loaded=300000, scored=1, score_date=2026-11-06T00:00:00Z, model_version=v2025.03.14, origin=live, fetched_at=2026-11-07T02:59:00Z |

## Summary

| Metric | Count |
|---|---|
| Projects / branches scanned | 3 / 3 |
| Distinct package versions (ecosystem, name, version) | 3 |
| Vulnerable package versions | 1 |
| … in CISA KEV (actively exploited) | 0 |
| … max severity HIGH | 1 |
| CRITICAL/HIGH in production projects (excluding dev-only) | 1 |
| Severity not rated in production (excluding dev-only, KEV) | 0 |
| Promoted by EPSS (at or above 10.0%, in production or a supported release) | 0 |
| Packages with version not resolved, not checked for vulnerabilities | 0 |
| Dev-only vulnerable package versions | 0 |
| Vulnerable direct dependencies | 1 |
| Runtimes / images past end-of-life | 0 |
| Runtimes / images reaching EOL within 90 days | 0 |
| Allowed but unsupported: declared minimum allows an end-of-life version (not counted as EOL) | 0 |
| Floating container images (unique) | 0 |
| Direct deps ≥1 major behind latest | 0 |
| Suppressed by VEX | 0 |

MEDIUM and LOW advisories are not listed below, nor not-rated ones outside production; they are in `audit.json` under `vulnerabilities`.

## 🔴 Actively exploited (CISA KEV)

None of the vulnerable package versions is in the CISA Known Exploited Vulnerabilities catalog.

## Likely to be exploited (EPSS)

EPSS is FIRST's daily estimate of the probability that a CVE is exploited in the next 30 days (scores of 2026-11-06). It is a forecast and exists only for CVEs: a low or missing score does not mean safe. None of the vulnerable package versions has an EPSS score at or above 10.0%.

## Critical and high severity by project

KEV, CRITICAL and HIGH package versions with runtime scope; dev-only occurrences are listed further down. Production projects come first. `Fix target` is the lowest version that closes every listed advisory (`–` = no fix released). Direct `yes` = the manifest declares the package itself; `no` = it is transitive and the fix is a lockfile refresh of the parent; `unknown` = the scan could not tell whether the manifest declares it, which is not the same as transitive: check the manifest first.

### shop-web (production)

**`main`** — 1 vulnerable package version

| Sev | EPSS | Package | Version | Advisories | Fix target | Direct | Manifest | Worst advisory |
|---|---|---|---|---|---|---|---|---|
| HIGH 7.2 | 1.2% | lodash | 4.17.20 | 1 | 4.17.21 | yes | `package-lock.json` | GHSA-35jh-r3h4-6jhm (CVE-2021-23337): Command Injection in lodash |

## Runtimes and base images

No runtime or base-image cycles were checked (none found, or endoflife.date was skipped).

## Floating image tags

None: every container image is pinned to at least a major version.

## Outdated direct dependencies (≥1 major version behind)

None (or registry lookups were skipped).

## Dev-only findings

KEV, CRITICAL and HIGH package versions that occur here only as a devDependency or build-time tool (SBOM scope `optional`, labelled dev-only). Fix them, but they are not a production exposure.

None.

## Suppressed by VEX

Findings removed from the sections above by an OpenVEX statement in `vex/`. Re-check them when the package version or the code path changes.

None.

## Notes

None.

## How this report was produced

sbom-audit fixture on Python 3.12.0 (fixture). Configuration: `sbom-audit.toml` not read (defaults).

| Tool | Version |
|---|---|
| syft | 1.18.1 |
| osv-scanner | 2.0.2 |
| git | 2.47.1 |

| Data source | Status | Freshness |
|---|---|---|
| OSV (osv-scanner) | ok | queried live during this audit (2026-11-07T03:00:00Z) |
| CISA KEV | ok | catalogue 2026-11-06T15:00:00.000Z (version 2026.11.06), fetched 2026-11-07T02:59:00+00:00, downloaded during this audit |
| EPSS (FIRST) | ok | scores of 2026-11-06T00:00:00Z (model v2025.03.14), fetched 2026-11-07T02:59:00Z, downloaded during this audit |
| endoflife.date | ok | nothing to look up |
| npm/PyPI/JSR registries | ok | nothing to look up |
| OpenVEX | ok | 0 statements in `vex/` |

The secrets scan's own results are in `SECRETS.md`. `manifest.json` records the run's start and end, the audited commits and the SHA-256 and size of every file the run wrote; `sbom_audit_cli.py verify` recomputes them.

