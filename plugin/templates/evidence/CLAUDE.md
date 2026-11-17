<!-- sbom-audit-template v5 -->
# Evidence folder (written by sbom-audit)

This folder is the output of the [sbom-audit](https://github.com/Wuesteon/sbom-audit) plugin: the
SBOMs, vulnerability audit, secrets scan results and decisions for the projects next to it. It is
meant to be committed and kept as evidence. Read this file before you change anything here.

## What each file is

| Path | What it is | Who writes it |
|---|---|---|
| `sbom-audit.toml` | Configuration: branches, `production` flag per project, ignored projects, push | you |
| `AUDIT.md` / `audit.json` | The audit, in triage order (secrets, KEV, critical/high in production, EOL, the rest) | the plugin |
| `INVENTORY.md` / `inventory.json` | Every package, image and runtime on the audited branches | the plugin |
| `status.json` / `STATUS.md` | Machine- and human-readable summary of the last run | the plugin |
| `issues.json` / `ISSUES.md` | The work list: every open issue with a stable id, priority, where it occurs (project or host, branches, file, line) and the fix target. Derived from the reports; nothing suppressed, decided or accepted is in it | the plugin |
| `releases.json` / `RELEASES.md` | Releases under audit (only with `[releases]`): support period, open KEV/critical/high, runtimes reaching EOL inside the support period, advisories no longer present compared with the previous release. Read it with `releases --project <name> [--fixed <tag>]` | the plugin |
| `secrets.json` / `SECRETS.md` | Secrets scan results: counts and fingerprints only, never values | the plugin |
| `HOSTS.md` / `hosts.json` | Server audit (only with `[hosts]`): critical findings, KEV, patch automation, logins, fingerprint changes, Lynis. Contains IP addresses, ports and user names | the plugin |
| `hosts/` | `baseline/<host>.json` (the accepted state), `known_hosts` (pinned host keys), `bootstrap/<host>.json` (bootstrap records) | the plugin |
| `CRA.md` / `cra.json` | CRA readiness per configured product (only with `[cra.products]`): one status per obligation with its article reference. Evidence, not a verdict | the plugin |
| `cra/<product>/` | Starter documents (risk assessment, reporting procedure, disclosure policy, Art. 14 drafts) and `proposed-for-repo/` files to copy into the product repository yourself | `/sbom-audit:cra init`, then you |
| `secrets-decisions.toml` | Decisions per secrets finding (revoked, false positive, accepted) | `/sbom-audit:secrets resolve` |
| `hosts-decisions.toml` | Accepted host findings with date, note and review date | `/sbom-audit:hosts accept` |
| `sbom/<project>/<branch>.cdx.json` | CycloneDX SBOM per project and branch; `tags__<tag>.cdx.json` per release tag under audit | the plugin |
| `vex/<project>.openvex.json` | OpenVEX decisions (why a finding does not affect the product) | `/sbom-audit:vex` |
| `reports/<date>-audit.md` | Dated copy of every run | the plugin |
| `log.md` | Append-only: one line per run, secrets scan and host action | the plugin |
| `.cache/` | Short-lived answers from public databases; gitignored | the plugin |

## Rules

- The only hand-edited parts of `AUDIT.md` are the `## Assessment` sections. They are carried over
  from run to run. Everything else in the file is regenerated.
- Never edit `status.json`, `issues.json`, `ISSUES.md`, `releases.json`, `RELEASES.md`, `secrets.json`, `SECRETS.md`, `hosts.json`, `HOSTS.md`, anything under `hosts/` or anything under `sbom/` by hand. The next run
  overwrites them, and an edited SBOM is no longer evidence.
- To fix things, read `issues.json`: it lists only what is open, most urgent first, one issue per line.
  For one project: `python3 <plugin root>/scripts/sbom_audit_cli.py issues --project <name> --json`
  (writes nothing; inside the plugin's skills the plugin root is `${CLAUDE_PLUGIN_ROOT}`). An entry disappears
  when the next run no longer finds the issue or a decision closes it; never delete entries. A non-empty
  `incomplete` means a source failed and the list may be missing issues.
- Decisions go through the plugin's skills, not through the files: use `/sbom-audit:vex` for vulnerability
  decisions and `/sbom-audit:secrets resolve` for secrets decisions. Never write a decision without the
  user confirming the list first.
- Never run `hosts patch`, `hosts bootstrap` or `hosts unbootstrap` with `--confirm` until the user has
  named that host in the conversation and confirmed the plan printed for it (run without `--confirm` first).
  `hosts accept` is written only after the user confirms the whole list. Never paste IP addresses,
  `authorized_keys` comments or sudoers content from `HOSTS.md` into issues or messages.
- Under `cra/`, never fill in a blank (`____`) with an answer the user did not give, and never remove
  the `sbom-audit cra starter` line for them: while it is there the document counts as missing.
- Keep this repository private. It describes your dependencies and unfixed vulnerabilities. If the
  remote is public, the plugin refuses to push.
- A secret value must never appear in any file, log line or commit message here. Reports carry counts
  and fingerprints only.
- Never answer "are we affected by X" from memory. Run `/sbom-audit:incident <CVE|GHSA|package>`.

## Skills

- `/sbom-audit:status` prints `STATUS.md` from the last run; it writes nothing.
- `/sbom-audit:run` runs the scan and audit (a few minutes; run it in the background).
- `/sbom-audit:assess` writes the `## Assessment` section and drafts decisions for you to confirm.
- `/sbom-audit:lookup <package>` answers "which project uses X".
- `/sbom-audit:incident <CVE|GHSA|package>` answers "are we affected".
- `/sbom-audit:vex` records a vulnerability decision.
- `/sbom-audit:secrets resolve` records a secrets decision.
- `/sbom-audit:schedule weekly|off` installs or removes the weekly run.
- `/sbom-audit:hosts` checks the servers (`check`), records accepted findings (`accept`) and patches or bootstraps one named host after confirmation.
- `/sbom-audit:cra` shows the CRA readiness per product (`check`) and writes starter documents after confirmation (`init`).
- `/sbom-audit:setup` configures a new portfolio.

This file is refreshed by the plugin when its template version changes. Delete the first line to take
it over and stop the refresh.
