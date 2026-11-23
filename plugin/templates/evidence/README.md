<!-- sbom-audit-template v6 -->
# Security evidence

SBOMs, a vulnerability audit, secrets scan results and VEX decisions for the projects in this
portfolio, written by the [sbom-audit](https://github.com/Wuesteon/sbom-audit) Claude Code plugin.
This folder is the output; the plugin is the tool. Start with `STATUS.md`, then `AUDIT.md`.

Keep this repository private: it lists your dependencies, open vulnerabilities and secrets
fingerprints, and `HOSTS.md` holds the IP addresses, open ports and user names of your servers. The plugin refuses to push to a public remote, and reports an `unknown` visibility in
`STATUS.md` instead of assuming it is private.

## The folder

```
security/
├── sbom-audit.toml          # configuration, committed with the evidence
├── AUDIT.md / audit.json    # the audit, triage order fixed; assessments carried over
├── INVENTORY.md / inventory.json
├── status.json / STATUS.md  # summary of the last run: counts, exit code, host, visibility
├── issues.json / ISSUES.md  # work list: every open issue and where it occurs, most urgent first
├── releases.json / RELEASES.md  # releases under audit (only with [releases]): support, open counts, fixed
├── secrets.json / SECRETS.md  # secrets scan results, counts and fingerprints only, never values
├── HOSTS.md / hosts.json    # server audit (only with [hosts]); IPs, ports and user names inside
├── CRA.md / cra.json        # CRA readiness per product (only with [cra.products]); evidence, not a verdict
├── cra/<product>/           # starter documents you fill in; proposed-for-repo/ files you copy yourself
├── secrets-decisions.toml   # decisions per secrets finding
├── hosts-decisions.toml     # accepted host findings
├── hosts/                   # baseline/<host>.json, known_hosts, bootstrap/<host>.json
├── sbom/<project>/<branch>.cdx.json   # CycloneDX, one per project and branch
├── sbom/<project>/tags__<tag>.cdx.json  # one per release tag under audit (only with [releases])
├── vex/<project>.openvex.json         # OpenVEX 0.2.0 decisions
├── reports/<date>-audit.md  # dated copy of every run
├── log.md                   # append-only: one line per run, secrets scan and host action
└── .cache/                  # KEV, EPSS, endoflife.date and registry answers, 24 h; gitignored
```

Only the `## Assessment` sections of `AUDIT.md` are edited by hand. Record decisions with
`/sbom-audit:vex`, `/sbom-audit:secrets resolve` and `/sbom-audit:hosts accept` (without Claude Code:
`python3 <plugin root>/scripts/sbom_audit_cli.py vex add …`, `secrets resolve …`, `hosts accept …`); do not edit
`status.json`, `issues.json`, `ISSUES.md`, `releases.json`, `RELEASES.md`, `secrets.json`, `SECRETS.md`, `HOSTS.md`, `hosts/` or `sbom/`.

## What leaves the machine

No source code, no SBOM file and no secret value is sent anywhere. The outbound hosts, all public
databases except your own git remotes, are:

| Host | When | What is sent |
|---|---|---|
| your git remotes | `git fetch --prune origin` before every scan (`fetch = false` disables); the push of this folder when `push = true` | the usual fetch and push |
| osv.dev | osv-scanner during every run; `api.osv.dev/v1/vulns/<id>` during `incident` | package names and versions; the advisory id |
| www.cisa.gov | once per 24 h | nothing; the KEV catalogue is downloaded |
| epss.empiricalsecurity.com | once per 24 h | nothing; the complete daily EPSS file is downloaded |
| endoflife.date | once per runtime cycle per 24 h; with `[hosts]`, once per server OS release | product and cycle, e.g. `nodejs/20` |
| registry.npmjs.org, pypi.org, jsr.io | once per direct dependency per 24 h | the package name |
| api.github.com | Dependabot and secret-scanning status reads, the visibility check of this repository's remote, `[discovery]` clones, `setup --enable-dependabot` after confirmation; with `[hosts]`, the releases endpoint for the binaries in the vendor table | the repository name |
| your product websites | only with `[cra] check_well_known = true`, during `cra check` and the `run` that includes it | one HTTPS GET of `/.well-known/security.txt` per configured `url`, no redirects followed |
| your configured servers | `hosts check` and the `run` that includes it, `bootstrap`, `unbootstrap`, `patch`; SSH only | the SSH session; the collector makes no outbound calls of its own, but `bootstrap` makes the host download Lynis and its apt packages and `patch` runs `apt-get update` on the host |

The secrets scan runs locally: no verification calls, no telemetry. During the assessment the plugin
performs web searches through Claude for incidents of the last 30 days; the queries name the
runtimes and frameworks in your inventory, not your projects.

This file is refreshed by the plugin when its template version changes. Delete the first line to take
it over and stop the refresh.
