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

Requirements: Claude Code, Python 3.11+ (standard library only), macOS or Linux, and these tools:

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
| `REPORT.html` | Management report: one self-contained page that prints to A4/PDF, with the overall state, what needs action now, decisions on record, coverage and the CRA evidence mapping (English or German; [sample](evals/fixtures/security/REPORT.html)) |
| `INVENTORY.md` / `inventory.json` | Every package, image and runtime per project and branch |
| `SECRETS.md` / `secrets.json` | Leaked-credential findings by fingerprint, file and line, never the value |
| `HOSTS.md` / `hosts.json` | Server audit, when enabled |
| `sbom/<project>/<branch>.cdx.json` | CycloneDX SBOMs |
| `vex/<project>.openvex.json` | Your OpenVEX decisions |

Sample from the committed demo fixture [`evals/fixtures/security/AUDIT.md`](evals/fixtures/security/AUDIT.md):

```
### shop-web (production)

**`main`** — 1 vulnerable package version

| Sev | Package | Version | Advisories | Fix target | Direct | Manifest | Worst advisory |
|---|---|---|---|---|---|---|---|
| HIGH 7.2 | lodash | 4.17.20 | 1 | 4.17.21 | yes | `package-lock.json` | GHSA-35jh-r3h4-6jhm (CVE-2021-23337): Command Injection in lodash |
```

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
`claude -p` session that sends the audit results to Anthropic like any Claude Code session. Full table:
[Privacy](docs/reference.md#privacy-what-leaves-your-machine).

## Documentation

- **[Reference](docs/reference.md)**: configuration, the full pipeline, `issues.json`, scheduler,
  secrets, hosts, the `security/` folder, the EU Cyber Resilience Act mapping, limitations.
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
