# sbom-audit

[![ci](https://github.com/Wuesteon/sbom-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/Wuesteon/sbom-audit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Portfolio-wide SBOMs, vulnerability audit and secrets scan for every repository you own, as a
Claude Code plugin.**

Point it at a folder of git repositories. It builds one CycloneDX SBOM per project and branch,
audits them all at once against OSV, CISA KEV and endoflife.date, scans every repository's history
for leaked credentials, optionally checks your Linux servers, and then helps Claude write an
assessment of the result in your session. Decisions are recorded as OpenVEX and kept in a private
`security/` git repository, so the next run and the next incident start from what you already know.

Most scanners answer per repository and per concern. sbom-audit answers the questions an incident
raises, across the whole portfolio:

- *Which of our projects run this package, on which branch, directly or transitively?*
- *Is it on CISA's actively-exploited list?*
- *Which runtimes and base images are past end of life? Which images float on `latest`?*
- *Did a credential ever land in git history?*
- *What did we decide about this finding last time?*

It only reads git objects (`git archive`, never your working tree) and writes into `security/`.
Opt-in features write elsewhere only after you confirm them: a weekly launchd/systemd timer, a
pre-commit guard in each repository's `.git/hooks`, an SSH audit key `~/.ssh/sbom-audit_ed25519`
and, in host mode, changes to the servers you name. It never fixes code or opens pull requests; it
hands you a prioritised work list instead.

## Quickstart

Requirements: Claude Code (or see [Without Claude Code](#without-claude-code)), Python 3.11+
(standard library only), macOS or Linux, and these tools:

```bash
brew install syft osv-scanner gitleaks gh   # git is assumed
```

Install the plugin:

```bash
claude plugin marketplace add Wuesteon/sbom-audit
claude plugin install sbom-audit@wuesteon-plugins
```

Then, in Claude Code, from the folder that holds your repositories (or from inside one repository):

```text
/sbom-audit:setup     # discover repositories, write security/sbom-audit.toml
/sbom-audit:run       # SBOMs, audit, secrets scan, reports, then an assessment
```

A portfolio of about ten repositories takes a few minutes. Without gitleaks the secrets scan reports
`skipped`, never "clean"; everything else works. Update with
`claude plugin update sbom-audit@wuesteon-plugins`.

## What you get

The run writes a `security/` folder next to your repositories:

| File | Contents |
|---|---|
| `STATUS.md` / `status.json` | One-screen summary of the last run, with deltas since the previous one |
| `AUDIT.md` / `audit.json` | The audit: KEV first, then CRITICAL/HIGH per project (production first), EOL runtimes, floating tags, outdated direct dependencies |
| `ISSUES.md` / `issues.json` | Work list for a person or an agent: every open issue, most urgent first, with a fix target |
| `REPORT.html` | Management report: one self-contained page that prints to A4/PDF, with the overall state, what needs action now, decisions on record, coverage, the CRA evidence mapping and, for configured products, the CRA readiness per product (English or German; [sample](evals/fixtures/security/REPORT.html)) |
| `INVENTORY.md` / `inventory.json` | Every package, image and runtime per project and branch |
| `SECRETS.md` / `secrets.json` | Leaked-credential findings by fingerprint, file and line, never the value |
| `HOSTS.md` / `hosts.json` | Server audit, when enabled |
| `RELEASES.md` / `releases.json` | Releases under audit (with `[releases]`): support period, open KEV/critical/high, runtimes reaching end of life inside the support period, advisories no longer present compared with the previous release |
| `sbom/<project>/<branch>.cdx.json` | CycloneDX SBOMs |
| `sbom/<project>/tags__<tag>.cdx.json` | CycloneDX SBOM per release tag under audit (with `[releases]`) |
| `vex/<project>.openvex.json` | Your OpenVEX decisions |
| `CRA.md` / `cra.json`, `cra/<product>/` | EU Cyber Resilience Act readiness for the projects you list as products under `[cra.products]`: per obligation, with its article reference, evidence present, missing, stale or the manufacturer's responsibility; starter documents you fill in. Evidence tooling, not legal advice |

Sample from the committed demo fixture [`evals/fixtures/security/AUDIT.md`](evals/fixtures/security/AUDIT.md):

```
### shop-web (production)

**`main`** — 1 vulnerable package version

| Sev | Package | Version | Advisories | Fix target | Direct | Manifest | Worst advisory |
|---|---|---|---|---|---|---|---|
| HIGH 7.2 | lodash | 4.17.20 | 1 | 4.17.21 | yes | `package-lock.json` | GHSA-35jh-r3h4-6jhm (CVE-2021-23337): Command Injection in lodash |
```

### Released versions (opt-in)

Branches show what you build; for the versions you shipped, add a `[releases]` table to
`security/sbom-audit.toml`. Each run then also audits the newest matching release tags, each with its
own SBOM, through the same pipeline as a branch:

```toml
[releases]
tags = "v*"                 # glob over local tags; version order when every tag is a version, else tag date
keep = 3                    # the newest N tags
support_months = 60         # support period from each tag's date ...
support_until = 2031-12-31  # ... and/or an end date (with both, the later one counts)

[projects."docs-site"]
releases = false            # per project: false, or a table that overrides key by key
```

Findings in a supported release rank like production; releases past their support period are listed
but are not open work. `sbom_audit_cli.py releases --project shop-web --fixed v2.4.0` lists the advisories
no longer present in the SBOM of `v2.4.0` compared with the previous release, with the release that
first held each one and the days in between. That is exactly what it proves: absence from the SBOM,
checked against today's OSV data. In the EU Cyber Resilience Act mapping this is the row
**SBOM per released version** (Annex I Part II (1), Annex VII points 2(b) and 8, Art. 13(8) and (13)
of Regulation (EU) 2024/2847); details and the `releases.json` format:
[Releases](docs/reference.md#releases-an-sbom-per-released-version). Evidence tooling, not legal
advice.

### Build SBOMs (opt-in)

The repository scan reads manifests and lockfiles. When versions come from outside the repository (a
Maven parent or BOM it does not hold, Gradle), it lists them as "version not resolved". A CycloneDX JSON
SBOM from the build fills that gap: `sbom_audit_cli.py import --project shop-api --branch main bom.json`
(or `--tag v2.3.0`) stores it in `security/imports/`, and every later run uses its packages for the
ecosystems it covers, with direct and transitive dependencies from its graph; packages only the
repository scan found stay in the inventory, marked as not in the build SBOM. Every coverage statement
names the imported file and says when it was not built from the scanned commit. Details:
[Imported build SBOMs](docs/reference.md#imported-build-sboms).

## Skills

| Skill | What it does |
|---|---|
| `/sbom-audit:setup` | Checks the tools, discovers repositories, writes the config; optional evidence repo, Dependabot, weekly schedule, pre-commit guard |
| `/sbom-audit:run` | The full pipeline, then prints `STATUS.md` and assesses the result |
| `/sbom-audit:status` | Prints the summary of the last run; writes nothing |
| `/sbom-audit:assess` | Incident sweep, triage and a written assessment; every drafted "not affected" decision is first challenged by a second agent |
| `/sbom-audit:lookup` | "Who uses X?": a package, glob, image or runtime |
| `/sbom-audit:incident` | "Are we affected?": a verdict per project and branch for a CVE, GHSA or PYSEC id (a bare package name falls back to `lookup`) |
| `/sbom-audit:vex` | Records an OpenVEX decision after you confirm it |
| `/sbom-audit:secrets` | `scan`, `report` and `resolve` secrets findings |
| `/sbom-audit:schedule` | Installs or removes a weekly run (launchd on macOS, systemd on Linux) |
| `/sbom-audit:hosts` | Audits Debian/Ubuntu servers over a forced-command SSH key, installing nothing; `accept` writes after you confirm the list, `patch`, `bootstrap` and `unbootstrap` act only after you confirm the host by name |
| `/sbom-audit:cra` | CRA readiness per configured product (`check`); starter documents for the risk assessment, reporting procedure and disclosure policy after you confirm the plan (`init`); never writes into your product repositories |
| `/sbom-audit:settings` | Switches between ask-first and autonomous mode, and turns the session status line on or off |

Skills that write anything show the whole list first and wait for one confirmation. Every skill calls
`plugin/scripts/sbom_audit_cli.py`, which you can also run by hand.

## Two modes

**Ask-first (default).** The plugin installs no hooks and pre-approves nothing but reading files, so
Claude Code asks before every command it runs. Nothing changes in your Claude Code settings.

**Autonomous (opt-in).** `/sbom-audit:settings autonomous` adds allow rules to your
`~/.claude/settings.json` for exactly this plugin's CLI, and only for what reads or writes the local
`security/` folder (`run`, `status`, `lookup`, `incident`, `code`, `issues`, `vex add`, `secrets`,
`hosts check`, `hosts accept`, …), plus web search and fetches from the advisory sources (osv.dev,
GitHub, NVD, CISA, endoflife.date, distro trackers, registries). The audit, the assessment and its
verifier agents then run without interruptions. Never covered, always asked: `setup` (it can change
GitHub settings), `hosts patch|bootstrap|unbootstrap` (they change servers), `gh`, `git` and any other
command. `/sbom-audit:settings ask` removes exactly the rules it added; a backup of your settings is
kept on the first change.

**Session status line (opt-in).** `/sbom-audit:settings hook on` registers a small stdlib script that
prints one line when a session starts (overdue run, class A secrets, new KEV or CRITICAL/HIGH findings),
with no network call.

## Privacy

No source code, SBOM or secret value leaves your machine. Outbound requests go only to public
databases (osv.dev, CISA, endoflife.date, the npm/PyPI/JSR registries, api.github.com) and carry
package names, versions or advisory ids, plus your own git remotes and, if you enable host mode, your
own servers. gitleaks runs locally. The evidence repository lists your open vulnerabilities, so the
plugin refuses to push it to a public remote. In host mode your servers' installed package names and
versions also go to osv.dev, and with `[schedule] assess = true` the weekly run starts a headless
`claude -p` session that sends the audit results to Anthropic like any Claude Code session. Only if
you configure `[assess]`, `assess draft` (and the scheduled assessment) sends report excerpts to the
endpoint you name instead: the source status, summary and VEX-suppressed sections of `AUDIT.md`, the
inventory overview and the open work list (projects, branches, packages, versions, advisories, file
paths and lines, secret fingerprints but never secret values, no host issues unless you include them).
`assess draft --dry-run` prints the exact request. With `[cra] check_well_known = true` (off by
default), `cra check` fetches `/.well-known/security.txt` from each product `url` you configured. Full table:
[Privacy](docs/reference.md#privacy-what-leaves-your-machine).

## Without Claude Code

Everything the skills do runs through one stdlib Python CLI; other coding agents and plain shells can
call it directly. Install syft, osv-scanner and gitleaks as above, clone this repository, and run from
the folder that holds your repositories (or pass `--out <path>/security`):

```bash
CLI=/path/to/sbom-audit/plugin/scripts/sbom_audit_cli.py
python3 $CLI setup                         # discover repositories, write security/sbom-audit.toml
python3 $CLI run                           # SBOMs, audit, secrets scan, reports (exit 1: findings present)
python3 $CLI status                        # the one-screen summary; writes nothing
python3 $CLI issues --max-priority 3       # the most urgent open issues
python3 $CLI lookup lodash                 # who uses a package, image or runtime
python3 $CLI incident CVE-2021-23337       # are we affected, per project and branch
python3 $CLI vex add shop-web GHSA-35jh-r3h4-6jhm under_investigation --impact "checking the call sites"
```

For a written assessment without Claude, point `[assess]` at any OpenAI-compatible endpoint
(OpenRouter, OpenAI, Gemini's OpenAI-compatible endpoint, Moonshot/Kimi or a local Ollama) and run
`python3 $CLI assess draft`. It writes `reports/<date>-assessment-proposal.md` and records nothing: every
decision in it is an unverified proposal for you to check and then record with `vex add` or
`secrets resolve`. Setup and providers: [Assessment drafts](docs/reference.md#assessment-drafts-without-claude-code-assess-draft).
Instructions for coding agents: [AGENTS.md](AGENTS.md). The full tested command sequence, and which
features need a model: [Using sbom-audit without Claude Code](docs/without-claude-code.md).

## Documentation

- **[Reference](docs/reference.md)**: configuration, the full pipeline, `issues.json`, scheduler,
  secrets, hosts, the `security/` folder, the EU Cyber Resilience Act (what is covered, what is checked, what stays
  with the manufacturer), limitations.
- **[Limitations](docs/limitations.md)**: what the scan does not see (C/C++ and firmware, submodules,
  vendored code), what is not tested yet (scheduler on a Linux server, CI other than GitHub Actions)
  and what data leaves the machine in each mode. Read it before trusting a clean report.
- **[Without Claude Code](docs/without-claude-code.md)**: the plain-CLI command sequence.
- **[CHANGELOG](CHANGELOG.md)**: release notes.
- **[CONTRIBUTING](CONTRIBUTING.md)**: layout, tests, plugin validation, evals and the release steps.

## Development

```bash
python3 -m unittest discover -s tests -t .      # synthetic fixtures; tool-dependent tests skip when a tool is missing
claude plugin validate --strict --profile directory plugin
claude --plugin-dir plugin                       # try the plugin from a checkout
```

## License

MIT, see [LICENSE](LICENSE).
