# Dependency Audit — 2026-11-07

Generated 2026-11-07T03:00:00Z by sbom-audit 1.0.0. Sources: Syft SBOMs per project and branch (committed tree, not the working copy), osv-scanner against OSV.dev, CISA KEV (actively exploited), endoflife.date (runtimes and base images), npm/PyPI/JSR registries (latest versions), OpenVEX statements in `vex/`. Full data: `audit.json`; what is installed where: `INVENTORY.md`.

## Source status

A failed source means its section below is empty, not clean.

| Source | Status | Detail |
|---|---|---|
| osv-scanner | ok | scanned=3 |

## Summary

| Metric | Count |
|---|---|
| Projects / branches scanned | 3 / 3 |
| Unique package versions checked | 3 |
| Vulnerable package versions | 1 |
| … in CISA KEV (actively exploited) | 0 |
| … max severity HIGH | 1 |
| CRITICAL/HIGH in production projects (excluding dev-only) | 1 |
| Dev-only vulnerable package versions | 0 |
| Vulnerable direct dependencies | 1 |
| Runtimes / images past end-of-life | 0 |
| Runtimes / images reaching EOL within 90 days | 0 |
| Floating container images (unique) | 0 |
| Direct deps ≥1 major behind latest | 0 |
| Suppressed by VEX | 0 |

MEDIUM, LOW and UNKNOWN advisories are not listed below; they are in `audit.json` under `vulnerabilities`.

## 🔴 Actively exploited (CISA KEV)

None of the vulnerable package versions is in the CISA Known Exploited Vulnerabilities catalog.

## Critical and high severity by project

KEV, CRITICAL and HIGH package versions with runtime scope; dev-only occurrences are listed further down. Production projects come first. `Fix target` is the lowest version that closes every listed advisory (`–` = no fix released). `direct` = the manifest declares the package itself; otherwise it is transitive and the fix is a lockfile refresh of the parent.

### shop-web (production)

**`main`** — 1 vulnerable package version

| Sev | Package | Version | Advisories | Fix target | Direct | Manifest | Worst advisory |
|---|---|---|---|---|---|---|---|
| HIGH 7.2 | lodash | 4.17.20 | 1 | 4.17.21 | yes | `package-lock.json` | GHSA-35jh-r3h4-6jhm (CVE-2021-23337): Command Injection in lodash |

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

