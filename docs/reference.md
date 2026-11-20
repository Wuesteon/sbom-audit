# sbom-audit reference

The full manual: configuration, every artefact, the secrets and host audits, the Cyber Resilience Act
mapping, what leaves your machine and the known limitations. For installation and a first run see the
[README](../README.md).

## Contents

- [The loop: setup → run → incident → vex](#the-loop-setup--run--incident--vex)
- [The work list: `issues.json`](#the-work-list-issuesjson)
- [Releases: an SBOM per released version](#releases-an-sbom-per-released-version)
- [Scheduler](#scheduler)
- [Assessment drafts without Claude Code: `assess draft`](#assessment-drafts-without-claude-code-assess-draft)
- [Secrets](#secrets)
- [Hosts](#hosts)
- [Modes, the session line and reading code](#modes-the-session-line-and-reading-code)
- [The `security/` folder](#the-security-folder)
- [Cyber Resilience Act](#cyber-resilience-act)
- [Privacy: what leaves your machine](#privacy-what-leaves-your-machine)
- [What is read per ecosystem](#what-is-read-per-ecosystem)
- [Imported build SBOMs](#imported-build-sboms)
- [SBOM quality: `sbom check`](#sbom-quality-sbom-check)
- [Limitations](#limitations)

## The loop: setup → run → incident → vex

**1. Setup, once per folder.** `cd` into the folder that holds your repositories (or into
one repository) and run `/sbom-audit:setup`. It checks the tools, discovers every
subfolder with a `.git` (and, with `[discovery] github_owner`, the owner's GitHub
repositories; cloning uses SSH by default, so an SSH key for GitHub must be present, or set
`protocol = "https"` under `[discovery]` or `SBOM_AUDIT_GIT_PROTOCOL=https` after
`gh auth setup-git` to clone over HTTPS), writes `security/sbom-audit.toml`, creates `security/` with its own
`CLAUDE.md`, `README.md` and a `.gitignore` for the cache, and prints visibility, secret
scanning and push protection per GitHub repository. In portfolio mode `--init-git` makes
`security/` its own git repository so the evidence has its own history.

`--enable-dependabot` enables Dependabot alerts only; `--enable-dependabot fixes` also
enables security updates. Both first print the target repositories and change nothing; the
change happens only when you rerun with `--yes` after seeing the list.

```toml
# security/sbom-audit.toml
branches = ["main", "dev"]            # skipped per project when absent
ignore_projects = ["sbom-audit"]      # folders discovery must skip
fetch = true                          # git fetch --prune origin before reading
commit = true                         # commit the evidence repository after each run
push = false                          # push only to a remote that is not public

[discovery]                           # optional: GitHub repositories besides local folders
github_owner = "your-github-user"
protocol = "ssh"                      # or "https" after `gh auth setup-git`
include_forks = false

[schedule]
assess = false                        # true: headless assessment proposal after the weekly run
assess_budget_usd = 5.0

[secrets]
enabled = true

[assess]                              # optional: assessment drafts by an OpenAI-compatible endpoint
base_url = "https://openrouter.ai/api/v1"
model = "openai/gpt-5.2"
api_key_env = "OPENROUTER_API_KEY"    # the NAME of the variable that holds the key, never the key

[report]                              # optional: REPORT.html, the management report
organisation = "Example AG"           # shown in the title; omitted when absent
language = "en"                       # or "de": REPORT.html and the cra init templates only

[projects."shop-web"]
production = true                     # moves the project up the triage order
github = "owner/repo"                 # when the remote does not name the GitHub repository
[projects."docs-site"]
ignore = ["build/"]
```

Release scanning (`[releases]`, off by default) is described in
[Releases](#releases-an-sbom-per-released-version).

**2. Run.** `/sbom-audit:run` builds one CycloneDX SBOM per project and branch with Syft,
runs osv-scanner against them, marks CISA KEV entries, queries endoflife.date for every
runtime and base image, compares direct dependencies with their registries, applies the
VEX statements, scans new commits for secrets, writes `AUDIT.md`, `audit.json`,
`INVENTORY.md`, `inventory.json`, `STATUS.md`, `status.json`, `SECRETS.md`,
`secrets.json` and the work list `issues.json`, appends a line to `log.md`, commits the evidence (`commit = true`) and then
opens the assessment: an incident sweep of the last 30 days across every runtime and
framework in the inventory, triage in the fixed order open class A secrets → KEV →
CRITICAL/HIGH in production and open class B secrets → EOL → floating tags → dev-only
tooling, and a written `## Assessment YYYY-MM-DD` section with actions per project. A portfolio of about ten
repositories takes a few minutes; run it in the background.

**3. Incident.** When a CVE, advisory or package is in the news, `/sbom-audit:incident
CVE-2021-23337` (or a GHSA or PYSEC id) fetches the affected
versions from OSV, checks every project and branch from the last scan and prints a
verdict per project: `hit` with the vulnerable version and manifest, `present_not_affected`
when the package exists in a version outside the affected range, `absent`, or `unknown`
when that branch's last audit was incomplete (osv-scanner failed on it, or the scan reported
errors), in which case the command exits 2 and asks for a re-run. `unknown` is also the verdict
for a package whose version is not resolved (evidence "version not resolved, not checked for
vulnerabilities"), and `incident --vex` records nothing for it. A finding `audit.json` lists for the
advisory is always a `hit` (evidence suffixed "(from audit.json)" when the inventory names the package
differently), never `absent`. Verdicts are per version,
so a branch holding two versions of one package shows both. Given a bare package name instead of an id, it prints where that package is used, like
`lookup`, without a verdict.

*Unknown instead of absent.* Advisory ecosystems are compared in OSV spelling: the inventory's purl
types map to `SwiftURL` (purl `swift`, matched on the repository path such as
`github.com/apple/swift-nio`), `GitHub Actions` (`github`), `crates.io` (`cargo`), `RubyGems` (`gem`),
`Packagist` (`composer`), `ConanCenter` (`conan`), `Go` (`golang`); `cocoapods`, `deno` and `jsr` have no
OSV ecosystem. For each affected package that is not in a branch's inventory, the verdict for that
branch is `unknown` (with the reason as evidence), never `absent`, when one of these holds:

1. the branch's last audit was incomplete (above);
2. the advisory is against the Go runtime (`Go` package `stdlib` or `toolchain`) and the branch has a Go
   runtime row (a Dockerfile `golang` image, a `.go-version`, a go.mod `go`/`toolchain` line, which is
   only a build minimum), a Go package or a `go.mod`: osv-scanner does not check the Go toolchain, so
   compare the version shown with the advisory's fixed versions by hand;
3. the advisory's ecosystem is one the scan does not inventory, i.e. anything other than `npm`, `PyPI`,
   `Go`, `RubyGems`, `crates.io`, `Maven`, `NuGet`, `Hex`, `Pub`, `Packagist`, `SwiftURL`,
   `GitHub Actions`, `ConanCenter` and `Hackage` (for example `CRAN`, `Linux`, `Android`); an
   operating-system ecosystem (`Debian`, `Ubuntu`, `Alpine`, `Red Hat`, `Wolfi`, …) is `unknown` only
   on a branch that uses a container image, whose contents the scan does not list, and `absent` on one
   without;
4. the branch's inventory holds no package at all although manifests or lockfiles are present, or the
   inventory was written before manifests were recorded (`manifests` missing in `inventory.json`) and
   holds no package;
5. the branch has a manifest or lockfile of the advisory's ecosystem (`manifests` in `inventory.json`,
   e.g. `poetry.lock` for PyPI) but not one package of that ecosystem was inventoried.

Otherwise the branch is `absent`, once per branch and only when it has no other verdict. Each branch
inventory records `manifests` (OSV ecosystem → manifest and lockfile paths, at most 20 per ecosystem,
walked like the readers, without `node_modules`, vendored and ignored folders).

`incident --vex` writes `not_affected` / `component_not_present` only for a project whose every verdict
is `absent`, only for affected packages of an inventoried ecosystem (never for `Go` `stdlib`/`toolchain`),
and one statement per examined branch: the product is `<project purl>@<branch>` (a `/` in the branch or
release label written `%2F`) and the impact statement names the branch and the commit, so the statement
does not cover branches or commits the scan did not examine. Everything it leaves out it prints as
`not recorded: <reason>`.
`/sbom-audit:lookup <name>` answers the plain "who uses X" without an advisory; names
may be globs (`expo-*`), images (`nginx:alpine`) or runtimes (`nodejs`). A Maven package answers to
its OSV name `group:artifact` (`org.postgresql:postgresql`, as listed) and to the bare artifact
(`postgresql`); Go modules and npm scopes are matched by their full name. The purl `incident --vex`
writes for a Maven package is `pkg:maven/<group>/<artifact>`.

**What the audit could not judge.** Two coverage gaps are reported as gaps, never as findings and
never as clean:

- *Version not resolved.* A package whose version is empty, `UNKNOWN` or an unexpanded `${property}`
  (Syft writes `UNKNOWN` when a Maven version comes from a BOM or parent outside the repository; a
  `package.json` without a lockfile gives no version) is kept in the inventory and SBOM but not
  matched: osv-scanner would treat it as affected by every advisory ever published for the package.
  `AUDIT.md` lists it under "Version not resolved" per project and branch, `audit.json` under
  `unresolved_versions` (`[{project, branch, count, packages: [{ecosystem, name, version, purl,
  manifests, direct, scope, requirement?}], release?}]`, present only when not empty) and
  `stats.unresolved_versions`; `STATUS.md` and the run summary give the count ("packages with version
  not resolved, not checked for vulnerabilities"). A reusable workflow of the same repository
  (`uses: ./.github/workflows/…`) is versionless by design and not counted. Before matching, a Maven
  version that `<dependencyManagement>` of a pom in the same repository sets (directly, through an
  in-repo parent found by groupId:artifactId, or through an in-repo imported BOM, with `${…}`
  properties expanded along the parent chain) is filled in offline, without Maven or network; the SBOM
  entry then carries the property `sbom-audit:version_source` naming that pom, the inventory
  component `props.version_source`. A version from an external BOM or parent stays unresolved.
- *Severity not rated.* An advisory without a CVSS v3 score, database severity or CVSS v4 vector takes
  the severity of an aliased record in the same osv-scanner result (a GHSA for a GO- or CVE-only
  record), else the numeric `max_severity` of its osv-scanner group; the advisory then carries
  `severity_source` (`alias <ID>` or `osv-scanner group score`) in `audit.json`. No score is invented
  (`cvss` stays null). One still without a severity keeps `severity: "UNKNOWN"`, shown everywhere as
  "not rated". In runtime scope of a production project or supported release it is not ranked under
  LOW: `AUDIT.md` lists it under "Severity not rated", the summary and `STATUS.md` count it
  (`status.json` `counts.unrated_production`), and `issues.json` gives it priority 3 with reason
  `unrated_production`, next to CRITICAL/HIGH, until someone has read it.

Each `audit.json` vulnerability row also carries `package` (the OSV name: `group:artifact` for Maven,
otherwise the name) and `purl` (without qualifiers); `issues.json` `details.package` uses the same name.
Every name a reader sees uses it: the `AUDIT.md` tables (KEV, by project, dev-only, not rated, suppressed
by VEX), the `INVENTORY.md` direct dependencies, the issue titles in `ISSUES.md`/`issues.json`, the
management report, `RELEASES.md`/`releases.json` (`fixed_since_previous[].package`) and `lookup`. Two
Maven artifacts with the same name in different groups are two packages. Only the `name` field of an
`audit.json` row (the bare artifact, as Syft writes it) and the identifiers built from it keep the short
name: issue ids (`vuln:<project>:<manifest>:Maven:<artifact>@<version>`) and the `status` identities stay
as they were, so an id does not change between versions.

**4. VEX.** `/sbom-audit:vex` records why a finding does or does not apply, in OpenVEX
0.2.0, one document per project under `security/vex/`. `incident --vex` records
`not_affected` / `component_not_present` for every project that does not hold the
component. Every later run applies the statements, lists what they suppressed and keeps
the counts honest.

In `/sbom-audit:assess` (and the assessment after `run`), a drafted decision that closes a finding
on a judgement (`not_affected` because the code is not present, not reached, not controllable or
mitigated; a secret marked `false_positive`, `test_fixture` or `accepted`) first goes to a fresh
agent that sees only the claim and tries to disprove it against the advisory and the audited branch.
The list you confirm shows each verdict: `holds` (the evidence is stored in the statement),
`disproved` (the finding stays open and becomes an action) or `unresolved` (recorded as
`under_investigation`, which suppresses nothing). You can still overrule a verdict; the statement
then says the verifier disagreed. A headless proposal has no second agent and marks these entries
`unverified`; they are verified when you apply it.

```bash
python3 plugin/scripts/sbom_audit_cli.py vex add billing-api GHSA-xxxx-yyyy-zzzz not_affected \
  --justification vulnerable_code_not_in_execute_path \
  --impact "The parser is only used on trusted config files."
```

Exit codes of `run`: 0 clean, 1 findings present, 2 a source failed (its section is empty,
not clean; the report says so), 3 a VEX file is malformed (the run aborts naming the
file), 4 a required tool is missing (checked before anything is written; `scan` needs
`syft` and `git`, `audit` needs `osv-scanner`, `gh` only for GitHub reads and
`setup --enable-dependabot`). `lookup` exits 1 on no match; `incident` exits 1 on a hit, 2
when it cannot answer. 5 means read-only mode (`SBOM_AUDIT_READ_ONLY=1`): nothing was written.
`status` prints `STATUS.md` and writes nothing.

**What a run commits.** With `commit = true` and `security/` as its own repository, a run commits
exactly the files it wrote plus `sbom-audit.toml`, the configuration it read, so the evidence commit
names the settings it was produced with. The configuration stays out of the commit, and `STATUS.md`
says why under Commit, when it changed while the run was going (the next run commits it) or when a
key name or value looks like a credential (`token`, `password`, `user:password@` in a URL, a known
token prefix): the configuration holds names and paths (`api_key_env`, `api_key_file`, `[hosts] key`),
never a key value. Everything else that changed by hand, such as `vex/`, `secrets-decisions.toml`,
`hosts-decisions.toml` or your own notes, is left uncommitted and listed under Pending hand edits.

**Deltas between runs.** `STATUS.md`, the session line and `REPORT.html` compare each open set with
the previous run only when both were counted by the same rule (`open_rules` in `status.json`). After
an upgrade that changed a rule, that set reads "not comparable with the previous run" for one run
instead of new and resolved numbers (from 1.1.x, CRITICAL/HIGH in production: 1.1.x put every
advisory of an affected package into it, 1.2.0 and later only its KEV and CRITICAL/HIGH ones). An
advisory that left the KEV or CRITICAL/HIGH set while `AUDIT.md` still reports it (its severity or
KEV flag or the production scope changed, or a VEX decision covers only some projects) is listed as
"no longer counted", never as resolved.

## The work list: `issues.json`

The plugin reports and never fixes. What it hands to whoever does fix, a person or an agent, is
`issues.json` (readable copy: `ISSUES.md`): one entry per open issue, most urgent first.

```json
{"id": "vuln:shop:backend/uv.lock:PyPI:litellm@1.74.9", "kind": "vulnerability",
 "priority": 2, "reason": "kev", "severity": "CRITICAL", "production": true,
 "title": "litellm 1.74.9: 45 advisories, worst CRITICAL (KEV, actively exploited)",
 "where": {"project": "shop", "branches": ["main"], "path": "backend/uv.lock", "line": null},
 "details": {"package": "litellm", "version": "1.74.9", "direct": false,
             "worst": {"id": "GHSA-…", "severity": "CRITICAL", "summary": "…"}, "advisories": ["…"]},
 "fix": {"action": "upgrade", "target": "1.84.0", "unfixed_advisories": 0, "hint": "…"},
 "first_seen": "2026-11-10"}
```

- `kind`: `vulnerability` (one per project, manifest and package version), `secret` (file, line and
  fingerprint, never the value), `eol`, `floating_tag`, `host`.
- `priority`: 1 class A secret · 2 KEV and critical host findings · 3 CRITICAL/HIGH in a production
  project or a supported release (reason `critical_high_production`), an advisory there that is not
  rated (`unrated_production`), and class B secrets · 4 end of life, and secrets ranked lower by their
  path context (`secret_context`, see [Secrets](#secrets)) · 5 floating tag · 6 everything else,
  among them a declared minimum (`engines.node`, `requires-python`) that allows an end-of-life
  version (`eol_minimum`, see [What is read per ecosystem](#what-is-read-per-ecosystem); what
  runs is not stated or has its own row).
- `fix.action`: `upgrade`, `no_fix_released`, `rotate`, `upgrade_runtime`, `raise_minimum`, `pin`,
  `apt_upgrade`, `reboot`, `no_fix_installable`, `review`.
- Only open issues: findings suppressed by a VEX statement, decided secrets, accepted host findings and
  informational host output are not in it. An id is stable from run to run and the entry disappears
  when the issue does.
- `incomplete` lists failed sources. When it is not empty, a short list is not a clean one.
- `details.direct` says whether the package is a direct dependency of that manifest (`true`), a
  transitive one (`false`) or that the scan could not tell (`null`: unknown, never counted as
  transitive), `details.dev_only` whether only dev-only scopes hold it. The list is ordered by
  priority, production first, then direct dependencies, then unknown, then transitive ones, then
  severity, place and id: a direct dependency's fix lands in your own
  manifest; a transitive one is fixed through the parent that pulls it in or a lockfile refresh; for an
  unknown one check the manifest first. The priority never depends on it. `ISSUES.md` and
  `REPORT.html` say how many vulnerabilities at priority 2 and 3 are direct, how many transitive and,
  when there are any, how many unknown, and mark each row. Transitive does not mean
  harmless: the package is installed and can run like a direct one, and there is no reachability
  analysis (see [Limitations](#limitations)), so it stays a finding until it is fixed or a VEX
  decision says otherwise.

It is a view of `audit.json`, `secrets.json` and `hosts.json`, never a second source of truth.
The file holds one issue per line, so `grep '"priority": 1' issues.json` returns whole entries. An
agent that fixes one project should not load the whole list; it asks for its part, which writes
nothing and works in read-only mode:

```bash
python3 plugin/scripts/sbom_audit_cli.py issues --project shop --max-priority 3 --json   # what to fix first in shop
python3 plugin/scripts/sbom_audit_cli.py issues --kind secret                           # one line per open secret
python3 plugin/scripts/sbom_audit_cli.py issues --host web-1                            # one server
```

`--project` also selects the findings of the hosts that run the project. Each advisory entry carries
its id, CVEs, severity and fix version; `details.worst` names the advisory to read first with its
summary, and the full texts stay in `audit.json`.

`issues` without a filter rebuilds both files from the reports. `secrets resolve`, `hosts check` and
`hosts accept` do the same, and `secrets resolve` also updates the secrets counts in `status.json`, so
the session line stops counting a finding the moment it is decided. A `vex` decision takes effect
with the next `run` or `audit`, like in `AUDIT.md`.

## Releases: an SBOM per released version

Branches show what you are building; a manufacturer also answers for what it shipped. With
`[releases]`, every run also scans the newest release tags of a project, each through the same
pipeline as a branch: its own SBOM, OSV, CISA KEV, endoflife.date and VEX.

```toml
[releases]                    # portfolio default; absent = off, nothing changes
tags = "v*"                   # glob over local tag names (required)
keep = 3                      # the newest N matching tags are audited
support_months = 60           # support period: months from each release's tag date ...
support_until = 2031-12-31    # ... and/or an end date; with both, the later one counts
prereleases = false           # default; true also audits pre-release tags (-rc.1, -beta, -SNAPSHOT)

[projects."shop-web"]
releases = { tags = "shop-v*", keep = 5 }   # overrides key by key
[projects."docs-site"]
releases = false                            # off for this project
```

`releases = true` on a project needs a `[releases]` table; a project table without `tags` inherits it
from `[releases]`. Unknown keys are refused.

- **Which tags.** Local tags only, read from git objects (`git for-each-ref refs/tags`); the normal
  `git fetch` brings tags along, nothing extra is fetched or checked out. A tag that points at a tree
  or a blob is skipped. When every matching tag, with the pattern's literal prefix removed, reads as a
  version (`1.2.3`, `2.0.0-rc.1`), they are ordered by version with semver precedence: numeric parts
  compare as numbers (`rc.10` after `rc.9`, `1.10.0` after `1.9.0`), a pre-release ranks below its own
  release (`2.0.0-rc.10` before `2.0.0`), and build metadata after `+` only breaks ties. Otherwise
  they are ordered by tag date (the tagger date of an annotated tag, else the commit date). The run
  log names the order used, and so do `releases.json` (`order`) and `RELEASES.md`.
- **Pre-releases.** `prereleases = false` (the default) leaves pre-release tags out before the newest
  `keep` are chosen: the releases a manufacturer supports are its final releases, and a release
  candidate would otherwise take one of the `keep` slots and its findings would rank like production.
  A tag counts as a pre-release when its version carries a suffix after the numbers (`-rc.1`, `-beta`,
  `-SNAPSHOT`, `alpha1`, `.M1`); `.RELEASE`, `.Final`, `-ga` and build metadata (`+build.5`) do not
  make a pre-release. Set `prereleases = true` in `[releases]` or on one project when you ship and
  support pre-releases. Configs without the key keep working; a project that used to audit an
  `-rc` tag among its newest `keep` now audits the next final release instead.
- **Where the results go.** The SBOM is `sbom/<project>/tags__<tag>.cdx.json` (its version is the
  tag). In `inventory.json`, `audit.json` and `issues.json` a release appears with branch
  `tags/<tag>`; an `audit.json` location in a release carries `release: <tag>` and an issue lists its
  tags under `where.releases`. `INVENTORY.md` lists releases in their own table, `AUDIT.md` has a
  "Releases under audit" section, `STATUS.md` counts them and `REPORT.html` (en, de) shows them under
  coverage. The outdated-dependency and floating-tag checks run on branches only.
- **Support period.** A release is supported until `support_months` after its tag date or
  `support_until`, whichever is later; with neither, it counts as supported and `support_until` is
  null. Findings in a supported release rank like production (priority 3 for CRITICAL/HIGH). A
  release past its support period is listed in `releases.json`, `RELEASES.md` and `AUDIT.md`, but its
  findings are not in `audit.json`, `issues.json` or the exit code. A runtime or base image whose
  endoflife.date end of life falls before the end of the support period is listed under
  `eol_before_support_end`. One whose end of life cannot be compared is listed apart under
  `eol_unknown`, with the reason: `(no endoflife.date data)` (the product or cycle is not on
  endoflife.date, or the lookup failed), `(no end-of-life date published)` (a cycle without an
  announced end) or `(version unknown)` (no version to look up). An empty `eol_before_support_end`
  therefore never hides a runtime without a date; `RELEASES.md` has an "EOL unknown" column, and
  `REPORT.html` and `CRA.md` name them per release. Both lists are empty when the release has no
  support period to compare with. A build minimum (status `minimum`: a go.mod line, `engines.node` or
  `requires-python`, see "The Go runtime is a minimum" below) is in neither list.
- **Remediation evidence.** For each release, `fixed_since_previous` lists the advisories that matched
  a package in the SBOM of the previous kept release and match none in the SBOM of this one, with
  `first_seen` (the earliest kept release of the unbroken run that held it;
  `first_seen_is_oldest_kept` means it may be older) and `days` between the two tag dates. Both SBOMs
  are matched against today's OSV data, before VEX. This proves "no longer present in the SBOM of
  release X" and nothing more: not that the code path was reachable, not when the advisory was
  published. When either scan was incomplete, `fixed_since_previous_unknown` is true and the list is
  empty.
- **What happened to the package.** "No longer present" is not the same as "upgraded". Each entry
  says what the two SBOMs show: `removed_versions` (the versions the advisory matched in the previous
  release, gone now), `remaining_versions` (versions in this release that were already in the
  previous one, where the advisory did not match them), `new_versions` (versions new in this release)
  and `change`: `upgraded` (a new version, higher than every removed one), `replaced` (a new version
  that is not higher), `affected_removed` (only the affected copy went, for example with a deleted
  second lockfile, and the other versions were already there), `package_gone` (no version of the
  package left in the SBOM) or `no_longer_matched` (the affected version is still in the SBOM and
  today's OSV data no longer matches it). It is read from the SBOMs alone and says nothing about
  which manifest or line changed. `versions_before` (the affected versions) and `versions_after`
  (every version of the package in this release) stay for compatibility; read `change` rather than
  putting the two side by side. `RELEASES.md`, `releases --fixed` and `REPORT.html` word it the same
  way, for example `4.17.23 removed; 4.17.21 remains (already in v1.0, not matched by this
  advisory); no new version of the package`.

```bash
python3 plugin/scripts/sbom_audit_cli.py releases                                          # every project
python3 plugin/scripts/sbom_audit_cli.py releases --project shop-web --fixed shop-v2.4.0   # fixed vs the previous release
python3 plugin/scripts/sbom_audit_cli.py releases --project shop-web --json
```

`releases` reads `releases.json` and writes nothing. Exit 1: the project or tag is not under audit;
2: no `releases.json` yet, or `--fixed` cannot compare because a scan was incomplete.

**`releases.json`** is written by every `run` and `audit`, also without `[releases]` (then `projects`
is empty). A project without release scanning is absent from `projects`. The shape is stable: fields
may be added, never renamed or removed. Releases are listed newest first.

```json
{"schema": 1, "generated": "2026-11-18T09:00:00+01:00", "plugin_version": "…",
 "projects": {"shop-web": {
   "support": {"period_months": 60, "until": null},
   "tags": "shop-v*", "keep": 3, "order": "version", "prereleases": false,
   "releases": [
     {"tag": "shop-v2.4.0", "commit": "<sha>", "date": "2026-10-01T12:00:00+02:00",
      "supported": true, "support_until": "2031-10-01",
      "sbom": "sbom/shop-web/tags__shop-v2.4.0.cdx.json",
      "open": {"kev": 0, "critical": 1, "high": 2},
      "eol_before_support_end": ["nodejs 20 (EOL 2026-04-30)"],
      "eol_unknown": ["caddy 2 (no endoflife.date data)"],
      "fixed_since_previous": [{"id": "GHSA-…", "package": "lodash", "ecosystem": "npm",
                                "versions_before": ["4.17.20"], "versions_after": ["4.17.21"],
                                "removed_versions": ["4.17.20"], "remaining_versions": [],
                                "new_versions": ["4.17.21"], "change": "upgraded",
                                "first_seen": "shop-v2.2.0", "first_seen_date": "…",
                                "first_seen_is_oldest_kept": false, "days": 184}],
      "previous": "shop-v2.3.0", "branch": "tags/shop-v2.4.0", "complete": true}]}}}
```

`open` counts package versions with an open (not VEX-suppressed) advisory, runtime scope only, by
their worst advisory; `kev` counts those with an actively exploited one.

## Scheduler

`/sbom-audit:schedule weekly` (or `setup --schedule weekly`) runs the pipeline every
Saturday 03:00 local time: a per-user launchd agent in `~/Library/LaunchAgents/` on macOS, a
systemd user service and timer in `~/.config/systemd/user/` on Linux. The timer calls a
small wrapper that resolves the installed plugin path at run time, so it survives plugin
updates. `schedule off` removes both. Other platforms get the GitHub Actions template
`plugin/templates/github-actions/sbom-audit.yml` instead; it downloads pinned, checksum-verified syft,
osv-scanner and gitleaks release binaries from github.com in your CI. It clones the plugin at the
release tag in `SBOM_AUDIT_REF`. A tag can be moved; to run a fixed version, point the clone at your own
fork.

- **One writer.** Only one machine runs the schedule and pushes to the evidence repository.
  When setup sees that the last run happened on another host, it says so; turn the timer
  off on one of them.
- A missed week (the machine was asleep or off) shows in the session status line (when turned on) and in
  `STATUS.md` as `scheduler did not run since …`.
- Unattended runs never prompt for a password or passphrase; when GitHub's host key is not
  yet in `~/.ssh/known_hosts`, the fetch fails with `Host key verification failed`, which
  one `ssh -T git@github.com` on that machine fixes.
- The weekly run is the plain CLI `run`, with no model involved, unless
  `[schedule] assess = true`. Then the run also starts a headless, read-only assessment
  (`claude -p` with `SBOM_AUDIT_READ_ONLY=1`, a fixed tool list and
  `--max-budget-usd assess_budget_usd`, default 5.0) that can only write
  `reports/<date>-assessment-proposal.md`. Its permissions (`assess.command`):
  - tools `Read`, `Grep`, `Glob`, `WebFetch`, `Bash` (`--tools`), `--permission-mode dontAsk`,
    `--strict-mcp-config`; no Write, Edit, Agent or MCP, and no WebSearch;
  - Read (which also governs Grep and Glob) only inside `security/`; project code only through the
    read-only `code` subcommand, besides `status`, `lookup` and `incident` (`Bash(python3 <cli>
    <subcommand>:*)`);
  - WebFetch only to `osv.dev`, `api.osv.dev`, `api.github.com`, `nvd.nist.gov`, `services.nvd.nist.gov`,
    `www.cisa.gov`, `endoflife.date`, `security-tracker.debian.org` and `ubuntu.com`; not `github.com`
    (repository pages anyone can write to) and no package registries;
  - denied everywhere (`--disallowedTools`): `Read(./.cache/**)`, `Read(//**/.cache/**)`,
    `Read(//**/.env*)`, `Read(//**/*.pem)`, `Read(//**/*.key)`, `Read(//**/id_*)`, `Read(//**/*.p12)`,
    `Read(//**/*.pfx)`, `Read(//**/.npmrc)`, `Read(//**/.pypirc)`, `Read(//**/.netrc)`,
    `Read(//**/.git-credentials)`, `Read(//**/credentials*)`, `Read(//**/.ssh/**)`, `Read(//**/.aws/**)`,
    `Read(//**/.docker/config.json)`.

  WebSearch is left out because nobody watches the headless run: a search result can lead to any page
  and the query itself can carry text out, while the advisory databases above answer every id the
  steps need. The 30-day web sweep for new advisories (assess step 2) therefore happens only in an
  interactive `/sbom-audit:assess`; the headless proposal lists it as still to do. The proposal is never applied automatically:
  `STATUS.md` lists it as `proposal waiting: reports/<date>-assessment-proposal.md`, and you
  review and apply it with `/sbom-audit:assess`. `log.md` records it as
  `<time> | assess-proposal | cost <usd> | reports/<date>-assessment-proposal.md`.
- When `[assess]` names a `base_url` and a `model`, `[schedule] assess = true` uses that endpoint
  instead of `claude -p` (see the next section); `claude` is then not needed. The cost is not
  known to the plugin and is logged as `cost unknown`. The launchd/systemd job does not see the
  variables of your shell, so for a scheduled draft put the key in `api_key_file` (below).

## Assessment drafts without Claude Code: `assess draft`

`assess draft` asks any OpenAI-compatible chat completions endpoint for an assessment proposal of
the last run. It is off until `[assess]` sets `base_url` and `model`, and it is the only command
that sends report content to a model provider.

```bash
export OPENROUTER_API_KEY=...                    # the key stays in the environment
python3 plugin/scripts/sbom_audit_cli.py assess draft --dry-run   # print the exact request; sends nothing
python3 plugin/scripts/sbom_audit_cli.py assess draft             # send it, write the proposal
```

| Key in `[assess]` | Environment override | Meaning |
|---|---|---|
| `base_url` | `SBOM_AUDIT_ASSESS_BASE_URL` | the endpoint up to `/v1` (or the provider's equivalent); `/chat/completions` is appended. https only; plain http only for `localhost`/`127.0.0.1`/`::1` |
| `model` | `SBOM_AUDIT_ASSESS_MODEL` | the provider's model id |
| `api_key_env` | `SBOM_AUDIT_ASSESS_API_KEY_ENV` | the name of the environment variable that holds the key; sent as `Authorization: Bearer <key>`. Leave it out for a local server without a key |
| `api_key_file` | – | a file outside `security/` that holds only the key, mode 600 (group/other access is refused); read when the variable is not set. For scheduled runs |
| `timeout_seconds` | – | default 600 |
| `max_tokens` | – | sent only when set; a cut-off answer is discarded |
| `include_hosts` | – | default false: host issues (server names, users, ports) are not sent |

A key written into the config (`api_key = ...`), a `base_url` with `user:password@`, a query or a
fragment, and a value of `api_key_env` that is not a variable name are refused. Errors name the
key or variable, never its value. Base URLs per provider (check the provider's documentation for
current model ids):

| Provider | `base_url` | `model`, for example |
|---|---|---|
| OpenRouter | `https://openrouter.ai/api/v1` | `openai/gpt-5.2`, `anthropic/claude-sonnet-4.6` |
| OpenAI | `https://api.openai.com/v1` | `gpt-5.5` |
| Google Gemini (OpenAI compatibility) | `https://generativelanguage.googleapis.com/v1beta/openai` | a Gemini model id from Google's model list |
| Moonshot / Kimi | `https://api.moonshot.ai/v1` | `kimi-k3` |
| Ollama on this machine | `http://localhost:11434/v1` | a pulled model, e.g. `gpt-oss:20b`; no key |

**What happens.** One request, with no tools: the model cannot read code, search the web or run
commands. It receives a fixed instruction text and the documents listed under
[Privacy](#privacy-what-leaves-your-machine), and answers with the same three parts as the headless
proposal: `## Assessment <date>` (with the incident sweep as a to-do list of `incident` commands,
since the model has no web access), `## Proposed decisions (unverified)` and `## GitHub issue drafts`.
The answer is written atomically to `reports/<date>-assessment-proposal.md` under a header that names
the model, the endpoint and the time and says that nothing was applied. The run records
`assess-proposal | cost unknown` in `log.md` and, when `status.json` exists, lists the file as
`proposal waiting` in `STATUS.md`. The command prints the path and the token counts, never the
proposal text.

**What it never does.** It writes no VEX statement, no secrets decision and nothing into `AUDIT.md`;
every decision in the draft is marked `unverified` and is a command for you to run after checking it.
The instructions forbid presenting a code-based `not_affected` (code not present, not reached, not
controllable, mitigated) as settled and the secrets status `rotated`; a draft that names such a
justification anyway gets a warning line in its header. An answer that contains the fingerprint key
from `.cache/`, or the API key, is discarded. HTTP errors are reported as the status code only (the
response body is never read or printed), redirects are not followed, so the key is sent only to
`base_url`. Exit codes: 0 written, 2 not configured or failed, 5 in read-only mode (`--dry-run` is
allowed there).

In Claude Code, review a draft with `/sbom-audit:assess`, which verifies each decision before
recording it. Without Claude Code, check each entry against the advisory and the audited branch
(`code grep`, `code show`) and run the commands you confirm yourself.

## Secrets

`/sbom-audit:secrets scan` runs gitleaks 8.x (betterleaks 1.x is accepted too) over the
history of every local repository, ignored projects and worktrees included (each counted
once), plus the GitHub repositories found through `[discovery]`, cloned read-only into the
cache. The plugin adds rules for providers the defaults miss (Supabase, RevenueCat, fal.ai,
AssemblyAI, DataForSEO, Expo, Hetzner, Contabo, Inngest, database URLs, Docker) and ranks
every finding in one of three classes:

- **A** owns the platform (cloud, database or payment admin keys): rotate before anything
  else; ranks above KEV.
- **B** costs money or data (paid API keys, write tokens).
- **C** is public by design (publishable keys) or a test value.

**Context.** The class comes from the rule, refined by the value and by where it is. Nothing is
dropped: every finding keeps a class, a `context` label and its `base_class` (the class before
the path context), and the totals per class still add up to every finding.

- *Value shape* (also in the pre-commit guard). A `private-key` match is class C
  (`no-key-body`) unless there is key material between the BEGIN and END lines: a run of 40 or
  more base64 characters holding a digit, `+` or `/` (`\n` escapes in a string literal count
  as line breaks). Header text in a comment or an assertion is not a key. A `generic-api-key`,
  `curl-auth-header` or `curl-auth-user` value that only names a variable (`${API_KEY}`,
  `$TOKEN`, `{{ key }}`) is class C (`placeholder`), and a `generic-api-key` value that is
  words without a digit, a dotted name (`org.example.Type`), a version (`v1.2.3`, a Go
  pseudo-version) or an advisory id (`ABC-JS-FOO-123`) is class C (`not-a-credential`). Every
  other shape keeps its class: a hex string, a UUID or a mixed-case string can be a key.
- *Path context* (`[context]` in `classes.toml`). A finding in a test, a fixture, an example,
  docs, vendored code, a data file or a dev setup is ranked one class lower (A to B, B to C)
  and labelled `test`, `fixture`, `example`, `docs`, `vendored`, `data` or `dev`, unless the
  same value is also found in a file without context. Defaults include `src/test/`, `test/`,
  `tests/`, `__tests__/`, `spec/`, `*_test.go`, `test_*.py`, `*.test.*`, `*Test.java`,
  `testdata/`, `fixtures/`, `examples/`, `*.example`, `docs/`, `vendor/`, `_vendor/`,
  `node_modules/`, `*.min.js`, `license-list-data/`, `*.csv`, `dev/`, `.devcontainer/` and
  `docker-compose.dev.yml`; the full list is in `classes.toml`. A pattern ending in `/` matches
  that directory anywhere in the path, one with another `/` the whole path, anything else the
  file name. Markdown files, `README.md`, `.env*` files, `build/`, `dist/` and CI files are
  never context: a key in a manual or a bundle is still a leak.

```toml
[secrets]
rank_by_context = true             # false: every finding keeps its base class (labels stay)
[secrets.context]                  # added to the defaults per label; new labels are allowed
test = ["qa/"]
deployable = ["deploy/examples/"]  # never context, whatever else matches
```

A changed `classes.toml` triggers a full rescan; a changed `[secrets.context]` applies on the
next `run`. In `SECRETS.md` a ranked finding says its context and "if the value is real,
rotate", a count line sums them by label, and open class C findings with a context are listed
under *Ranked lower by context*. In `issues.json` a class B finding ranked lower by its path
is priority 4 (`secret_context`), never production, with the fix `review`: check whether the
value is real, then rotate it or record `test_fixture` or `false_positive`. Fingerprints do not
change, so existing decisions keep matching. History is scanned as before: a value removed
from the working tree is still a finding.

No value is ever stored, printed, logged or committed: findings carry a fingerprint, file,
line, branches, whether the value is still in the working tree, its age and a keyed
`value_id`. The raw engine report is a `0600` file deleted after reading. The results are
`secrets.json` and `SECRETS.md` (with rotation hints per provider and the other projects
that use the same credential); decisions live in `secrets-decisions.toml` with the statuses
`open`, `rotated`, `false_positive`, `test_fixture` and `accepted`. Each `run` scans new
commits only; a rules or plugin minor change triggers a full rescan, and a decided finding
that reappears in a new commit is reopened.

**Resolve.** `/sbom-audit:secrets resolve` drafts one decision per open finding, shows the
whole list and records it only after you confirm. For a real leak the sequence is: rotate
the credential at the provider → redeploy everything that uses it → verify by hand that the
old value no longer works → `secrets resolve <fingerprint> rotated "<note>"` → only then
decide about rewriting history (that does not un-leak a pushed secret; rotation is the fix).

**Pre-commit guard.** `setup --install-guard` installs an untracked `.git/hooks/pre-commit`
in every local repository that blocks new class A/B secrets and prints
`BLOCKED <class> <rule_id> <file>:<line>`. Repositories that manage hooks in tracked files
(husky, lefthook, the pre-commit framework) are changed only after
`--tracked-ok <name>`; the block printed for the pre-commit framework uses
`stages: [pre-commit]`, which needs pre-commit 3.2 or newer. The guard is per machine:
install it on every machine that commits.
`--uninstall-guard` removes it.

**Keep the evidence repository private.** It lists dependencies, open vulnerabilities and
secrets fingerprints. The plugin checks the remote's visibility before every push, refuses
to push to a public remote, and reports an `unknown` visibility in `STATUS.md` instead of
assuming it is private.

## Hosts

Optional. `/sbom-audit:hosts` audits the Debian and Ubuntu servers you list in
`sbom-audit.toml`, installing nothing on them, and `run` includes the check when `[hosts]` is enabled:

```toml
[hosts]
enabled = true
concurrency = 4                      # hosts collected in parallel
timeout_minutes = 10                 # per host; a hung host becomes a failed source
key = "~/.ssh/sbom-audit_ed25519"

[hosts.servers."web-1"]
address = "203.0.113.10"             # or an ~/.ssh/config alias
admin = "root@203.0.113.10"          # used by bootstrap, unbootstrap and patch only
production = true                    # sorts first
projects = ["shop-web"]              # optional: named in the report
```

**What is checked.**

- Installed packages against OSV, joined to CISA KEV, with whether a fix is installable by apt. When the KEV list cannot be loaded (and is not cached), every checked host gets the critical `section-failed:kev` and keeps its earlier KEV findings: an outage never reads as resolved.
- Packages from third-party apt repositories, and known binaries outside apt against their latest GitHub release. The collector runs a binary (`caddy`, `node`, `docker-compose`) for its version only when root alone can change it: the file and every directory above it, through each symlink hop, owned by root and not group- or other-writable. Any other binary is not run and is the critical `permissive:binary-untrusted:<path>`, because whoever can change it gets root the next time root runs it. The check covers the file that is executed, not what it loads: a root-owned wrapper script that execs a binary in a user's home, or a pip-installed `docker-compose` v1 importing from a writable `dist-packages`, still passes.
- A fingerprint of the host (users, sudoers, `authorized_keys`, listening sockets, units, timers, cron, effective sshd config, firewall, apt sources, container names and ports) against the baseline you accepted. Kernel and reboot flag, loopback sockets and a renamed process on a known socket are informational. A unit, timer or cron file that a package owns and that changes during that package's upgrade is shown as an explained change, not a new finding.
- Permissive defaults: AppArmor off or in complain mode, a firewall whose default incoming policy is allow or accept (deny, drop and reject are fine), sshd `PasswordAuthentication yes`, `PermitRootLogin yes` or `KbdInteractiveAuthentication yes`.
- SSH logins since the last check (at most 8 days), one finding per host, user and key: `login:<user>/<fingerprint>` (or `login:<user>/password`, `login:<user>/keyboard-interactive` for a login without a key), with the number of logins, the first and last time and the source addresses. The id does not contain a time or an address, so it stays the same from run to run. Such a finding is critical when the key is not in the baseline's `authorized_keys` (of any user), the login used a password or keyboard-interactive, the user is not a login user in the baseline's `users`, or the user is root while the baseline's `PermitRootLogin` is `no`. A known key of a known user from a new address is not critical; it is listed under Logins. A successful login after at least 10 failures from its own address in the 24 hours before is critical on its own as well, with the per-login id `login:<user>@<time>/<fingerprint>`, and still counts in its user-and-key finding. An open critical login finding is carried to later checks until it is accepted, and later logins with that key are added to it.
- Accepting a login finding is only recorded (it changes no baseline) and does not expire: `hosts accept <host> login:<user>/<fingerprint> "<note>"` covers that user's later logins with that key, also from new addresses; a new key, another user with the same key or a password login is a new finding. A key that is in the host's current `authorized_keys` can be accepted this way before it has logged in (a new CI deploy key). Accepting the `change:authorized_keys:+<user>/<fingerprint>` finding puts the key into the baseline, so later logins with it are no longer critical, but the logins already seen with it stay open until their `login:` finding is accepted too.
- Migration from per-login findings (plugin versions before this change wrote one `login:<user>@<time>/<fingerprint>` finding per login): a decision recorded for such an id keeps matching that one login and nothing more; it is never rewritten. Open per-login findings carried in `hosts.json` are folded into their `login:<user>/<fingerprint>` finding on the next check (the per-login ids accepted one by one are left out of the count), except those raised for failures before the login, which stay as they are. The critical count drops on that check because many ids become one; baselines are unchanged.
- The patch automation itself: unattended-upgrades disabled, no `-security` origin, `apt-daily-upgrade.timer` inactive, or no run for more than 3 days.
- The OS release's own end of life, from endoflife.date (Ubuntu by `VERSION_ID`, e.g. `22.04`; Debian by major version): `os:eol` is critical once the release's free security support has ended (paid Ubuntu Pro or Extended LTS support is named, not assumed) and informational within 90 days of that date. A failed lookup is the informational `info:os-eol-unavailable`, never "supported". It cannot be accepted, only fixed by upgrading the release.
- The Lynis hardening index, its drop since the last run, warnings and suggestions.

The result is `security/HOSTS.md` (a summary table, then one section per host with, in this order: critical, failed checks, host key, KEV, patch automation, logins, fingerprint changes, permissive defaults, Lynis warnings, vulnerabilities, third-party updates, collapsed Lynis suggestions, informational) and `hosts.json`; accepted state lives in `hosts/baseline/<host>.json` and `hosts-decisions.toml`, pinned host keys in `hosts/known_hosts`. `status.json` and the session status line gain the open key `hosts_critical`. The first successful check becomes the baseline; after that every difference stays open until you `accept` it.

**How a server is reached.** Each server gets a user `sbom-audit` with its own ed25519 key. Its `authorized_keys` line is `restrict,command="sudo -n /usr/local/lib/sbom-audit/collect"` and the sudoers drop-in allows exactly that path, with no arguments. The collector is a single POSIX `sh` script, owned by root and not writable by that user; it never reads `.env` files, application directories or private keys, and reports fingerprints and hashes instead of key or sudoers content. The private key `~/.ssh/sbom-audit_ed25519` has no passphrase, because the weekly run is unattended. That is acceptable only because of the forced command: the key can run the collector and nothing else. Host keys are pinned in `security/hosts/known_hosts` and checked with `StrictHostKeyChecking=yes`; a changed key aborts that host and is critical. `patch` and `bootstrap` use your own admin SSH access, never the audit key.

**Setup order.**

1. Add the `[hosts]` table and servers to `sbom-audit.toml`.
2. Pick one non-production server and run `/sbom-audit:hosts bootstrap <host>`. It shows the plan and the host key fingerprint, and acts only after you confirm that host by name.
3. Test the forced command: `ssh -i ~/.ssh/sbom-audit_ed25519 sbom-audit@<host> id` must print the collector's JSON document, not the output of `id`.
4. Bootstrap the remaining servers one at a time the same way, then run `/sbom-audit:hosts check`.
5. Review each host's first baseline with Claude and accept the expected state (`/sbom-audit:hosts accept`, one confirmed list).
6. Only then install the weekly scheduler (`/sbom-audit:schedule weekly`); host mode runs unattended only after this step.

GitHub Actions does not support host mode: the template has no audit key, so the step reports `skipped: no audit key on this machine` (not a failure, the exit code is unchanged). When the last check is more than 8 days old, `STATUS.md` and the session line say `hosts not checked since <date>`. A host that cannot be reached, or whose collector fails, is a failed source (exit 2), never clean. The session line names failed hosts (`<n> host(s) failed the last check`) until a check reaches them, also after a manual `hosts check`. An outdated collector is reported as `collector outdated: run hosts bootstrap <host>`; it is never updated silently.

**Changing a server.** The three commands that write to a server print their plan when run without `--confirm`; Claude runs them with `--confirm <host>` only after you have named that host in the conversation and confirmed the plan. `--confirm` must equal the host name exactly and is refused under the scheduler and in headless assessments.

- `hosts bootstrap <host>` creates the user, installs the collector, the sudoers drop-in, the forced-command key and Lynis, and pins the host keys. If `AllowUsers` or `AllowGroups` would lock the audit user out, it adds the user, after backing up the file, running `sshd -t`, reloading (never restarting) sshd, proving a fresh admin login and an audit login, and restoring the backup if either fails. Re-running it overwrites the `*.sbom-audit.bak` backup next to `sshd_config`, so that file holds only the latest pre-bootstrap config; `unbootstrap` does not restore a backup (it removes only the `AllowUsers` token that bootstrap added), and an old `.bak` must never be copied back over a live config. If the admin account has neither root nor passwordless sudo, the CLI changes nothing on the host, prints the commands for you to run by hand (with `!` in Claude Code) and exits 2: that is expected, not a failure. The host keys are already pinned by then, and the CLI's own hint is to run the same `--confirm` command again afterwards, which verifies the audit login. This manual path writes no bootstrap record, so also run `hosts check <host>`.
- `hosts unbootstrap <host>` removes the user, collector, sudoers drop-in and any `AllowUsers` entry bootstrap added; Lynis stays installed.
- `hosts patch <host>` runs the host's own `unattended-upgrade`, once: a dry run (preceded by `apt-get update` to refresh the package lists) shows the package list and whether `reboot-required` is already pending, and a confirmed run installs exactly that list. The plan does not predict whether the upgrade will need a reboot: the reboot state afterwards and the services on old libraries are reported once the upgrade has run. The saved plan is valid for 24 hours, `--include-docker` must match the plan's, and the list is checked again before anything is installed; otherwise the plan has to be run again. Without passwordless sudo, the command printed for you to run by hand is pinned to the saved plan's packages and is printed only while that plan is under 24 hours old and has the same `--include-docker`; otherwise you get the plan command. It never reboots and never restarts services or containers (`NEEDRESTART_SUSPEND=1`). Docker packages are held back unless you add `--include-docker`; a Docker-related package missing from the hold-back list blocks patching. unattended-upgrades runs with a strict Package-Whitelist and with the kernel and dependency autoremovals off for that run, so an upgrade that needs a new package, typically a new kernel image, may be refused: install those by hand with apt in a maintenance window. Packages' own maintainer scripts may restart their own services (ssh, for example); sbom-audit itself restarts nothing. If an `apt.conf.d` file on the host sets an unattended-upgrades `Remove-*` option to `"true"`, patch stops with "not in force": the host's file overrides the run's own setting (autoremovals off), so the run could remove packages nobody confirmed. Change that setting on the host by hand for patch to work there.

Hosts reached only through ProxyJump or ProxyCommand are not supported: the host-key scan finds no keys.

## Modes, the session line and reading code

The plugin ships no hooks, and its skills pre-approve only Read, Grep and Glob, so by default Claude Code
asks before each command. `/sbom-audit:settings` (CLI: `settings`) manages two opt-ins in the user's
`~/.claude/settings.json`:

```bash
python3 plugin/scripts/sbom_audit_cli.py settings                      # what is on
python3 plugin/scripts/sbom_audit_cli.py settings --autonomy on        # autonomous mode
python3 plugin/scripts/sbom_audit_cli.py settings --session-hook on    # status line at session start
python3 plugin/scripts/sbom_audit_cli.py settings --autonomy off --session-hook off
```

- **Autonomous mode** adds `Bash(python3 "<installed CLI path>" <subcommand> *)` (quoted and unquoted) for
  `status`, `lookup`, `incident`, `code`, `issues`, `run`, `scan`, `audit`, `vex add`, `secrets`,
  `hosts check` and `hosts accept`, plus `WebSearch` and `WebFetch(domain:…)` for the advisory sources.
  The path is absolute, with no wildcard, so a repository you scan cannot ship a script that matches.
  `setup`, `hosts patch|bootstrap|unbootstrap` and `settings` itself are never covered.
- **Session hook** copies `templates/session-hook/session-start.py` to `~/.claude/sbom-audit/` and
  registers it for `startup|resume|clear` with a 5-second timeout. It reads `security/status.json` from
  the working directory upwards, treats every string in it as untrusted, makes no network call and
  always exits 0.
- What was added is recorded in `~/.claude/sbom-audit/integration.json`; `off` removes exactly that and
  leaves your own rules and hooks alone. `settings.json` is backed up to `settings.json.sbom-audit.bak`
  on the first change, and a file that is not valid JSON is never touched.
- A plugin update changes the installed path. `run` and `setup` move recorded rules to the new path and
  refresh the hook script; they never add anything that was not turned on.

**Reading code on an audited branch.** `code` reads committed code without a shell and without checking
anything out, for the assessment's verifier agents and for you:

```bash
python3 plugin/scripts/sbom_audit_cli.py code grep shop main 'template\(' --path src   # extended regex
python3 plugin/scripts/sbom_audit_cli.py code show shop main src/server.js --lines 10-40
python3 plugin/scripts/sbom_audit_cli.py code files shop main src
```

Only configured projects and existing branches (local or `origin/`, chosen like the scan does); paths
must be repository-relative, `security/.cache/` is never read, repository textconv drivers and hooks
never run, and output is capped at 400 lines. It writes nothing, so the headless assessment may call it
too. Three outcomes, never confused:

| Exit | Meaning | Message |
|---|---|---|
| 0 / 1 | output (for `grep`: a match) / no match | `no match in <project>@<branch>` |
| 2 | refused request, or the repository or ref could not be read | `code: repository or ref unreadable: <project>@<branch>: <first line of git's error>` |
| 4 | git itself could not run: not found, not executable, or failing before it reads any repository | `code: git could not run: <first line of git's stderr or the OS error>; hint: git not usable (macOS xcrun shim or sandbox?)` |

After a failed git call, `code` runs `git --version` once to tell 2 from 4; it does not look for another
git binary. Exit 2 and 4 read nothing and say nothing about the code. The assessment's verifiers record
them in the finding as `code not read: <message line>` instead of a bare "under investigation".

## The `security/` folder

```
security/
├── CLAUDE.md / README.md    # how to work in this folder; refreshed by the plugin
├── sbom-audit.toml          # configuration, committed with each run's evidence
├── STATUS.md / status.json  # one-screen summary of the last run: counts, deltas, scheduler, proposal
├── ISSUES.md / issues.json  # work list: every open issue and where it occurs, most urgent first
├── REPORT.html              # management report: one printable page (A4), built from the JSON above
├── AUDIT.md / audit.json    # the audit, triage order fixed; assessments carried over
├── INVENTORY.md / inventory.json
├── SECRETS.md / secrets.json          # secrets findings: fingerprints and counts, never values
├── secrets-decisions.toml             # decisions per secrets finding
├── HOSTS.md / hosts.json              # server audit (when [hosts] is enabled); contains IPs, ports, user names
├── hosts-decisions.toml               # accepted host findings
├── hosts/                             # baseline/<host>.json, known_hosts, bootstrap/<host>.json
├── CRA.md / cra.json                  # CRA readiness per product (only with [cra.products])
├── cra/<product>/                     # starter documents; proposed-for-repo/ files you copy yourself
├── RELEASES.md / releases.json        # releases under audit (with [releases]): support, open counts, fixed
├── sbom/<project>/<branch>.cdx.json   # CycloneDX, one per project and branch
├── sbom/<project>/tags__<tag>.cdx.json  # CycloneDX, one per release tag under audit
├── vex/<project>.openvex.json         # OpenVEX 0.2.0 decisions
├── reports/<date>-audit.md            # dated copy of every run (and assessment proposals)
├── reports/<date>-report.html         # dated copy of REPORT.html
├── log.md                   # append-only: one line per run, secrets scan and host action
├── manifest.json            # the last run: tool versions, data source dates, SHA-256 of every file it wrote
└── .cache/                  # KEV, endoflife.date and registry answers, 24 h; gitignored
```

| Artefact | Written by | Edit by hand? |
|---|---|---|
| `STATUS.md`, `status.json` | every `run`, `setup` | no; `/sbom-audit:status` prints it |
| `ISSUES.md`, `issues.json` | every `run`, `issues`, and after `secrets resolve`, `hosts check`, `hosts accept` | no; derived from the reports |
| `REPORT.html`, `reports/<date>-report.html` | every `run`, `report` | no; derived from the JSON |
| `AUDIT.md`, `audit.json`, `INVENTORY.md`, `inventory.json` | `run` | only the `## Assessment` sections of `AUDIT.md` |
| `RELEASES.md`, `releases.json` | `run`, `audit` | no; read with `releases` |
| `SECRETS.md`, `secrets.json` | `run`, `secrets scan` | no |
| `secrets-decisions.toml` | `secrets resolve` | through `/sbom-audit:secrets resolve` |
| `HOSTS.md`, `hosts.json`, `hosts/` | `run`, `hosts check`, `hosts bootstrap` | no |
| `hosts-decisions.toml` | `hosts accept` | through `/sbom-audit:hosts accept` |
| `vex/*.openvex.json` | `vex add`, `incident --vex` | through `/sbom-audit:vex` |
| `CRA.md`, `cra.json` | `run` (with `[cra.products]`), `cra check` | no; derived from the files it names |
| `cra/<product>/` | `cra init <product> --yes` (new files only, never overwrites) | yes: these are your documents |
| `reports/`, `log.md` | every run, secrets scan and host action | no |
| `manifest.json` | every `run`; entries refreshed by every later writing command | no; checked with `verify` |

**Management report.** `REPORT.html` is a single self-contained page (inline CSS, no script, no
external request) for people who do not read the Markdown: overall state with the change since the
previous run, the priority 1 to 3 issues with their fix, the decisions on record (VEX, secrets,
accepted host findings), coverage and limits with the data timestamps, the Cyber Resilience Act
mapping below and, with `[cra.products]`, the readiness table per product from `cra.json`. It prints to A4 from any browser (Print, Save as PDF). A number the run did not
produce reads "not available", never 0, and a skipped secrets scan reads as skipped, never as
clean. Secret values are never part of it. `sbom_audit_cli.py report [--lang en|de]` rebuilds it
from the JSON already in the folder without scanning; `[report] language` and `organisation` set the
defaults. By design, `language` applies only to `REPORT.html` and the `cra init` templates:
`AUDIT.md`, `INVENTORY.md`, `RELEASES.md`, `ISSUES.md`, `CRA.md`, `STATUS.md`, `SECRETS.md` and the JSON
files stay in English, so agents, diffs and tools read one vocabulary (the German report says so under
its limits). Times in the report are shown in the run's time zone (the offset of `audit.json`
`generated_at`, which also names `reports/<date>-…`): a timestamp another file records in UTC, such as
`secrets.json` or the KEV cache, is converted, so every day in the report is the run's day; a value
recorded as a day only (an issue's or a secret's `first_seen`, a decision date) is shown as recorded,
and `secrets.json` records UTC days. The report states the zone above its timestamp table.
Sample: [`evals/fixtures/security/REPORT.html`](../evals/fixtures/security/REPORT.html).

### Run manifest and `verify`

Every `run` writes `manifest.json` just before its commit (written atomically, committed with the run). It
records how the reports were produced and what they were when the run finished:

| Field | Content |
|---|---|
| `schema`, `sbom_audit`, `python`, `platform` | manifest format (`sbom-audit-manifest/1`), plugin version, Python version, platform |
| `run` | `command`, `started_at`, `finished_at` (UTC), `exit_code` |
| `config` | SHA-256 of the `sbom-audit.toml` the run read (`null` when it read none) |
| `tools` | version of syft, osv-scanner and git as each tool reports it (`syft version`, `osv-scanner --version`, `git --version`), gh when the run uses it, and the secrets engine actually used (gitleaks or betterleaks); `unknown` when a tool does not answer, `not installed` when it is not on PATH |
| `data_sources` | per source (`osv`, `cisa_kev`, `endoflife`, `registries`, `openvex`, `secrets`, `hosts`): `status` (ok, partial, failed, skipped, not run) and freshness: OSV is queried live by osv-scanner (`queried_at`, the audit's time in UTC); CISA KEV gives catalogue version and date, fetch time and whether it came live or from the 24 h cache; endoflife.date and the registries give the number of lookups answered live and from the cache and the oldest and newest fetch time |
| `audited` | per project and branch or release tag: the audited commit, `release_tag`, `complete` (no error on that branch), and for an imported build SBOM its file, SHA-256, commit and staleness |
| `files` | `{path: {sha256, bytes}}` for every file the run wrote (reports, JSON, dated copies, `sbom/**/*.cdx.json`, imported SBOMs) and every decision file it read (`vex/*.openvex.json`, `secrets-decisions.toml`, `hosts-decisions.toml`); `append_only: true` on `AUDIT.md` and `log.md` |
| `refreshed` | one line per later command that rewrote evidence: `at`, `command`, `files`, `removed` |

Never in it: anything under `.cache/` (the fingerprint key lives there), `.git/`, your own documents in
`cra/`, the configuration file itself (its digest instead), a secret value or a tool path. A file cannot
contain its own hash: the manifest lists every other file and the run's git commit covers the manifest.

`sbom_audit_cli.py verify [--json]` recomputes every hash and prints one line per file: `ok`, `changed`
(other bytes or size, or replaced by a symbolic link), `missing`, `appended` or `invalid` (an entry that
points outside the folder or into `.cache/`, never read). It also names evidence files present in the
folder but not in the manifest (top-level reports, `sbom/`, `vex/`, `imports/`) and says whether
`sbom-audit.toml` still matches the digest the run read; both are information, not failures. It writes
nothing and works with `SBOM_AUDIT_READ_ONLY=1`. Exit 0 every file matches, 1 a file changed, is missing or
an entry is invalid, 2 no `manifest.json` or one that cannot be read.

**Append-only files.** `AUDIT.md` takes hand-written `## Assessment` sections and `log.md` takes a line per
later action. For both, `verify` checks the bytes the run wrote: text added after them reads `appended`
(exit 0); a change inside them reads `changed`.

**Commands after the run.** `issues`, `secrets resolve`, `secrets scan`, `hosts check`, `hosts accept`,
`vex add`, `incident --vex`, `cra check`, `cra init --yes`, `report`, `import`, `scan` and `audit` rewrite
evidence after the run. Each of them, on its way out, updates the manifest entries of exactly the files it
wrote or removed during that command (a stat comparison before and after), marks each one
`refreshed: {at, command}` and appends a line to `refreshed`. A file the command did not touch keeps the
run's hash, so an edit by hand still reads `changed`, even when a later command ran. This keeps `verify`
honest without re-running the audit: the manifest says which file a later command changed and when, and
the next commit of the folder covers it. When `run` rewrites `status.json` and `STATUS.md` after a failed
commit or push, it refreshes those two entries the same way (`command`: `run (commit and push outcome)`);
the next run commits them.

The same facts appear in plain words in a "How this report was produced" section at the end of `AUDIT.md`
(before carried-over assessments) and as section 6 of `REPORT.html`, both from `audit.json` `provenance`.
Its tool table lists every tool the manifest records: `run` writes `AUDIT.md` before the secrets scan, so
it asks the secrets engine and gh for their versions up front (`audit` on its own, which runs neither,
lists syft, osv-scanner and git only). The OSV query time there is UTC like the manifest's; `audit.json`
`generated_at` keeps the run's own offset.

**Inventory overview.** The Overview table of `INVENTORY.md` always has the columns Node, Python,
Deno, Expo/React Native, SvelteKit, NestJS, Astro, Vite, FastAPI and Postgres. Java/JDK (`java`,
`openjdk`, `eclipse-temurin`, `amazon-corretto` and other JDK distributions), Go and .NET appear
when some branch has a value there, and any other runtime pinned in a manifest gets a column
named by its endoflife.date product; runtimes read from a base image are in the Images column.

**One package in two manifests.** When a pom.xml and a build.gradle (or any two manifests) declare the
same coordinate (ecosystem, name, and the same version or none resolved in either), `inventory.json`
keeps one row per manifest as evidence. Counts of packages count the coordinate once: the branch line
of `INVENTORY.md` reads "N distinct packages", adding "in M manifest rows" when the two differ; the
Direct dependencies table shows one line, "same coordinate, 2 manifests: `pom.xml`, `build.gradle`";
the releases table counts distinct packages; `audit.json` `stats.unique_package_versions` and
`stats.direct_dependencies` (per project and branch) count coordinates, and `stats.occurrences` counts
the rows (declarations) on purpose. Different resolved versions stay separate lines. Manifests are
named by path; the inventory does not keep line numbers.

Portfolio mode: the parent of `security/` is a plain folder whose direct subfolders with a
`.git` are the projects; `security/` is outside every audited repository. Single-repo
mode: the parent is itself a git repository; `security/` lives inside it and is excluded
from the export (`git archive <ref> -- . ':!security'`) so Syft never catalogues
committed SBOMs.

## Cyber Resilience Act

Regulation (EU) 2024/2847 (the CRA) sets cybersecurity requirements for products with digital elements
made available in the EU. **The plugin is evidence tooling, not legal advice.** It shows which evidence
exists for the products you name; it does not decide whether a product is in scope, which category it
belongs to, or whether it meets the regulation. No output of the plugin says a product is compliant.

**Dates, as Art. 71(2) states them.** The regulation applies from 11 December 2027. Art. 14 (reporting)
applies from 11 September 2026, and by Art. 69(3) also to products placed on the market before
11 December 2027. Chapter IV (notification of conformity assessment bodies) applies from 11 June 2026.

### What the plugin covers

Only the projects you list as products. Nothing is assumed to be in scope:

```toml
[cra]
review_interval_days = 365   # risk assessment older than this reads "stale"
audit_max_age_days = 8       # last audit older than this reads "stale"
check_well_known = false     # true: one HTTPS GET of <url>/.well-known/security.txt per product

[cra.products."shop-api"]    # key = a project name as in INVENTORY.md
name = "Shop API"            # optional display name
branch = "main"              # optional; default: the first configured branch the repository has
url = "https://shop.example" # optional, https origin only; used only with check_well_known
```

| Command | Writes |
|---|---|
| `cra check` | `CRA.md`, `cra.json`; also runs at the end of every `run` when a product is configured (it never changes the run's exit code) |
| `cra init <product> [--lang en\|de]` | nothing: prints the plan |
| `cra init <product> --yes` | new files in `cra/<product>/`, never overwrites; nothing in the product repository |

`/sbom-audit:cra` wraps both and can walk you through the risk assessment question by question; it
writes only your answers and leaves unanswered questions blank. `SBOM_AUDIT_READ_ONLY=1` makes `cra
check` and `cra init --yes` exit 5.

### What is checked, per product

Each obligation gets one status: **evidence present** (the file is named), **evidence missing**,
**stale**, or **manufacturer's responsibility**. "Present" means the document exists and its starter
line is gone, not that its content is complete or right. Repository files are read from git objects of
the configured branch (`git cat-file`), never from the working tree; the plugin writes nothing there.

| Obligation | Reference | Evidence the check looks for |
|---|---|---|
| Risk assessment, documented and updated | Art. 13(2), 13(3), 13(7); Annex I Part I; Annex VII point 3 | `cra/<product>/risk-assessment.md` without the starter line, with `Last reviewed: YYYY-MM-DD` (de: `Zuletzt geprüft:`); older than `review_interval_days` reads stale |
| Single point of contact, contact address | Art. 13(17); Annex I Part II (6); Annex II point 2 | `SECURITY.md`, `.github/SECURITY.md` or `docs/SECURITY.md` on the branch |
| security.txt | Annex I Part II (6); Annex II point 2 | `.well-known/security.txt` (also under `public/`, `static/`, or `security.txt`) on the branch, and with `check_well_known` the served file: RFC 9116 needs `Contact` and exactly one `Expires`; a past `Expires` reads stale. RFC 9116 is one common way to publish the contact, not a CRA requirement |
| Coordinated vulnerability disclosure policy | Annex I Part II (5); Art. 13(8); Annex VII point 2(b) | `cra/<product>/cvd-policy.md` without the starter line |
| Reporting procedure | Art. 14(1)-(8); Art. 16; Art. 69(3); Art. 71(2) | `cra/<product>/art14-procedure.md` without the starter line; an open KEV finding in the product adds a note pointing to it |
| SBOM | Annex I Part II (1); Annex VII point 2(b) | `sbom/<project>/<branch>.cdx.json` (a `/` in the branch reads `__`). A file with structural errors ([SBOM quality](#sbom-quality-sbom-check)) reads missing, with the path and the error codes in the note; the note of a usable file gives its data-field coverage. Neither says whether the content is complete |
| Vulnerabilities addressed, regular reviews | Annex I Part II (2), (3); Art. 13(8) | `audit.json`; older than `audit_max_age_days` reads stale |
| Decisions and evidence trail | Art. 13(7); Annex VII point 2(b) | `log.md`, `reports/`, `vex/<project>.openvex.json` |
| Support period and end date | Art. 13(8), 13(19); Annex II point 7; Annex VII point 4 | `support` of the product in `releases.json` |
| Released versions under audit | Annex I Part II (2), (8); Art. 13(9) | `releases` of the product in `releases.json`; open KEV and end-of-life components per supported release. Without `releases.json`: "no released versions under audit" |

### What stays with the manufacturer

These rows always read "manufacturer's responsibility"; no file can show them.

| Obligation | Reference |
|---|---|
| Whether the product is in scope, and its category (default, important, critical) | Art. 2, 3, 7; Annex III, IV |
| The product properties of Annex I Part I (secure by default, access control, confidentiality, integrity, minimisation, availability, attack surface, logging, data removal, ...) | Annex I Part I (1), (2)(a)-(m) |
| Publishing fixed vulnerabilities, secure update distribution, advisories | Annex I Part II (4), (7), (8) |
| Reporting vulnerabilities in components to their maintainers | Art. 13(6) |
| Information and instructions to the user | Art. 13(16), 13(18); Annex II |
| Technical documentation, kept for 10 years | Art. 13(13), 31; Annex VII |
| Conformity assessment, EU declaration of conformity, CE marking | Art. 28, 30, 32; Annex V |

### Starter documents

`cra init` copies these templates (English or German, `plugin/templates/cra/<lang>/`) into
`cra/<product>/`. They ask questions and leave blanks (`____`); none states that a product is secure or
meets a requirement. Each begins with a `sbom-audit cra starter` line: until you delete it, the document
counts as missing.

| File | Content |
|---|---|
| `risk-assessment.md` | questions along Annex I Part I (1), (2)(a)-(m) and Part II (1)-(8), Art. 13(3) |
| `art14-procedure.md` | who reports, the deadlines below, the ENISA single reporting platform (Art. 16), the coordinator CSIRT, informing users (Art. 14(8)) |
| `cvd-policy.md` | coordinated vulnerability disclosure policy (Annex I Part II (5)) |
| `art14/early-warning.md`, `art14/notification.md`, `art14/final.md` | drafts with the content items of Art. 14(2) and (4) |
| `proposed-for-repo/SECURITY.md`, `proposed-for-repo/security.txt` | proposals you copy into the product repository yourself (repository root or `.github/`; `/.well-known/security.txt` on your website) |

Art. 14 deadlines as the text gives them: an early warning within 24 hours of becoming aware
(Art. 14(2)(a), (4)(a)); a notification within 72 hours (Art. 14(2)(b), (4)(b)); a final report no later
than 14 days after a corrective or mitigating measure is available for an actively exploited
vulnerability (Art. 14(2)(c)), and within one month after the incident notification for a severe incident
(Art. 14(4)(c)).

### The other artefacts

| Artefact | What it serves |
|---|---|
| `sbom/<project>/<branch>.cdx.json` (CycloneDX) | Annex I Part II (1): identify and document components and vulnerabilities, including an SBOM in a commonly used machine-readable format covering at least top-level dependencies |
| `AUDIT.md`, `audit.json`, `STATUS.md`, the weekly schedule | Annex I Part II (2) and (3): address vulnerabilities without delay, regular tests and reviews |
| The KEV section, class A secrets in `SECRETS.md` | Art. 14: the trigger to run the reporting procedure; whether a finding is reportable is the manufacturer's decision |
| `vex/<project>.openvex.json`, `secrets-decisions.toml` | Art. 13(7) and Annex I Part II: documented vulnerability handling decisions: which finding was assessed, by whom, with which justification |
| `log.md`, `reports/`, the git history of `security/` | Art. 13(7), Annex VII point 2(b): the evidence trail for the technical documentation |
| `INVENTORY.md`, endoflife.date section, `releases.json` | Support period (Art. 13(8)): runtimes and images past or near end of life, released versions |
| SBOM per released version: `sbom/<project>/tags__<tag>.cdx.json`, `releases.json` (with `[releases]`) | Annex I Part II (1) for each version you placed on the market; Annex VII point 2(b) (the SBOM as part of the vulnerability handling described in the technical documentation) and point 8 (the SBOM to a market surveillance authority on reasoned request); Art. 13(8) (vulnerabilities handled for the support period: `support_until`, open counts, `eol_before_support_end`); Art. 13(13) (technical documentation kept at least 10 years after placing on the market or for the support period, whichever is longer: the history of `security/` keeps each release's SBOM, retention itself is yours to organise) |

### Sources

Read for this section (consolidated text as published; the Art. 13(4) replacement by Regulation
(EU) 2025/327 from 26 March 2027 was not read):

- Regulation (EU) 2024/2847, OJ L, 20.11.2024, English and German:
  <https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202402847>,
  <https://eur-lex.europa.eu/legal-content/DE/TXT/HTML/?uri=OJ:L_202402847>
- Its corrigenda (none changes a provision above): <https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX:32024R2847>
- Delegated Regulation (EU) 2026/881: <https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32026R0881>
- ENISA, single reporting platform: <https://portal.cra-srp.enisa.europa.eu/>
- RFC 9116 (security.txt): <https://www.rfc-editor.org/rfc/rfc9116>
- For the data-field table under [SBOM quality](#sbom-quality-sbom-check), read 2026-11-18:
  NTIA, "The Minimum Elements For a Software Bill of Materials (SBOM)", 12 July 2021,
  <https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf>; BSI TR-03183-2
  "Software Bill of Materials (SBOM)", version 2.1.0 of 20 August 2025, the version the BSI page lists as
  current, <https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.pdf?__blob=publicationFile&v=6>
  (page: <https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03183/TR-03183_node.html>).
  Neither is a CRA implementing act; see the note below.

No implementing act under Art. 13(24) (SBOM format) or Art. 14(10) (reporting format) had been found
when this section was written. The Commission's guidance C(2026) 6013 is non-binding and its annex was
not read.

## Privacy: what leaves your machine

The plugin's own scripts send no source code, no SBOM file and no secret value anywhere. The
outbound hosts, all public databases except your own git remotes, servers, Anthropic and the
`[assess]` endpoint you configure, are:

| Host | When | What is sent |
|---|---|---|
| your git remotes | `git fetch --prune origin` before every scan (`fetch = false` disables); the push of `security/` when `push = true` | the usual fetch and push |
| osv.dev | osv-scanner during every run; `api.osv.dev/v1/vulns/<id>` during `incident` | package names and versions; the advisory id; with `[hosts]`, `api.osv.dev/v1/querybatch` receives each server's Debian/Ubuntu source package names and versions |
| www.cisa.gov | once per 24 h | nothing; the KEV catalogue is downloaded |
| endoflife.date | once per runtime cycle per 24 h; with `[hosts]`, once per server OS release and vendor-table binary per 24 h | product and cycle, e.g. `nodejs/20`, `ubuntu/22.04` |
| registry.npmjs.org, pypi.org, jsr.io | once per direct dependency per 24 h | the package name |
| api.github.com | Dependabot and secret-scanning status reads, the visibility check of the evidence repository's remote, `[discovery]` listing and clones, `setup --enable-dependabot` after confirmation; with `[hosts]`, the releases endpoint for the binaries in the vendor table | the repository name |
| your product websites | only with `[cra] check_well_known = true`: `cra check` and the `run` that includes it | one HTTPS GET of `<url>/.well-known/security.txt` per configured product `url`; no redirects followed, at most 64 KiB read, User-Agent `sbom-audit` |
| your configured servers | `hosts check` (and the `run` that includes it), `bootstrap`, `unbootstrap` and `patch`, over SSH only | the SSH session; the collector makes no outbound calls of its own, but `bootstrap` makes the host download Lynis and its apt packages and `patch` runs `apt-get update` on the host |
| Anthropic, through Claude Code | the interactive skills, like any Claude Code session; with `[schedule] assess = true`, a headless `claude -p` after the weekly run | what Claude reads: reports, inventory and the code excerpts the verifier opens; the headless run is capped by `--max-budget-usd` |
| the `[assess]` `base_url`, only when configured | `assess draft`; with `[schedule] assess = true`, after the weekly run | one POST to `<base_url>/chat/completions` with the model id, a fixed instruction text and, as documents: from `AUDIT.md` the sections Source status, Summary and Suppressed by VEX and the latest `## Assessment` section; the Overview table of `INVENTORY.md` (project, branch, runtime versions, base images); the open work list as `issues.json` would hold it (project names, branches, manifest paths, package names and versions, advisory ids, severities and summaries, fix targets; for secrets the fingerprint, rule, provider, class, commit, file and line, never the value; host issues only with `include_hosts = true`), at most 300 issues and 20,000 characters per section. The key goes in the `Authorization` header. No source code, SBOM file or secret value. `--dry-run` prints the whole body |

`HOSTS.md` and `hosts.json` contain IP addresses, open ports and user names of your servers, so the private evidence repository rule applies to them in particular.

gitleaks runs locally and makes no network calls: no verification of found credentials, no
telemetry. During an interactive assessment Claude performs web searches for incidents of the last 30
days; the queries name the runtimes and frameworks in your inventory, not your projects. The headless
assessment makes no web search and fetches only from the hosts listed under [Scheduler](#scheduler).
When Claude runs `assess`, `incident` or `lookup` it may also use its own WebSearch/WebFetch
for advisory pages; those requests go through Claude Code, not the plugin, and carry only
advisory ids and package names.

## What is read per ecosystem

Syft lists the packages. The plugin's own readers add three facts it cannot get from Syft: whether a
package is a **direct** dependency (`direct` in `inventory.json`, `sbom-audit:direct` in the SBOM),
whether it is **dev-only** (scope `optional`) and which **runtimes** the manifests ask for. Every manifest
is read from the scanned git ref, never from the working tree. A package of the project itself is dropped:
it is not a dependency.

| Ecosystem | direct | dev-only (`optional`) | own packages dropped | runtime |
|---|---|---|---|---|
| npm | `dependencies`, `devDependencies`, `optionalDependencies` of every `package.json` | `devDependencies` (from Syft's second run) | `package.json` `name` | `engines.node`, `.nvmrc`, `.node-version` |
| PyPI | `pyproject.toml` (PEP 621, Poetry), `requirements*.txt` | not determined | `pyproject.toml` name | `requires-python`, `.python-version` |
| Go | every `require` in every `go.mod` without `// indirect` (single-line and block) | a directly required module that only `_test.go` files, files with the `tools` build tag or a go.mod `tool` directive use, in every go.mod that requires it (see [Go test-only modules](#go-test-only-modules)) | the `module` of every `go.mod` | `toolchain`, else `go` line of each `go.mod`, labelled as the minimum Go for the build |
| Maven | `<dependencies>` (and profile dependencies) of every `pom.xml`; not `<dependencyManagement>`, not plugin dependencies | a dependency whose every declaration has `<scope>test</scope>`, its own or one a `<dependencyManagement>` entry in the repository sets | `groupId:artifactId` of every `pom.xml` (the reactor modules) | Java language level: `maven-compiler-plugin` `<release>`/`<target>`/`<source>`, then `maven.compiler.release`/`target`/`source`, then `java.version`; checked against Eclipse Temurin's support dates |
| Gradle (Maven purls) | `dependencies { }` of every `build.gradle` and `build.gradle.kts` (projects in `settings.gradle(.kts)` included; not `buildscript`, not `plugins { }`, not `project(...)`) | every declaration in a test, debug or build-tool configuration, every Maven declaration `test` too; a package only in `gradle.lockfile` when all its lock configurations are test ones and every module is locked (see [Gradle](#gradle)) | none (`project(...)` dependencies are skipped) | none |
| .NET | none (no NuGet reader) | none | none | `global.json` `sdk.version` and `<TargetFramework(s)>` in `*.csproj`, `*.fsproj`, `*.vbproj`, `Directory.Build.props` (`net5.0`+ and `netcoreappX.Y`; .NET Framework and .NET Standard skipped) |
| others (Cargo, RubyGems, Composer, Swift, CocoaPods, GitHub Actions, …) | none | none | none | images in Dockerfiles and Compose files only |

- **Unknown is not transitive.** For an ecosystem without a reader, `direct` is left out of
  `inventory.json` and the SBOM (null), instead of claiming `false`; the same holds for an imported
  build SBOM without a dependency graph. It stays null downstream: `audit.json` location `direct` and
  the coverage `direct` value, `issues.json` `details.direct`, and `lookup` print `unknown` (never
  `transitive`); `AUDIT.md` shows `unknown` in the Direct column, `ISSUES.md` "dependency type unknown",
  the management report "dependency type unknown" / "Abhängigkeitsart unbekannt". Several places of one
  package merge to `true` when any is direct, `false` only when every one is known transitive, else
  null.
- **Maven `provided`, `runtime` and `system` count as production.** `provided` code is on the
  production classpath, supplied by the container or the JDK; a finding there is still yours to judge.
  A dependency declared as `test` in one module and without scope in another is production.
- **Maven `${…}` in coordinates** resolves from the pom's own properties and coordinates, then from
  any pom in the repository; a property defined only in a parent outside the repository stays
  unresolved and the dependency is neither direct nor dropped.
- **The Java runtime is a language level**, the release the code is compiled for, not the JDK in
  production. The JDK in a `FROM eclipse-temurin:…` image is listed separately. A level below 9
  (`1.8`) is read as `8`.
- **The Go runtime is a minimum.** The Go version in a binary is the toolchain that built it; the
  `golang` build image, when there is one, says more. A go.mod `go` or `toolchain` line is therefore
  never reported as an end-of-life runtime: when every source of a Go cycle on a branch is a go.mod
  line, its `audit.json` `runtimes` row (and the `eol` row behind it) has status `minimum`, `basis`
  `"go.mod"` and the cycle's own endoflife.date status in `cycle_status`; `eol_date` and `latest`
  stay. `AUDIT.md` lists it last as `build minimum (cycle EOL)` with a footnote. It is not counted in
  the summary, the log or the exit code, is not an `eol` issue in `issues.json`, is not in
  `STATUS.md` or `MANAGEMENT.md`, and is in neither release list. A `golang` image of the same cycle
  on the same branch is what builds or runs the code, so that cycle stays a normal runtime row with
  its real status. The rule lives in `enrich.build_minimum` and `enrich.eol`.
- **`engines.node` and `requires-python` are minimums too.** They say which versions the code
  allows, not which one runs. When every source of a Node.js or Python cycle on a branch is such a
  declaration (the lowest version the range allows), the row has status `minimum`, `basis`
  `"engines.node"` or `"requires-python"`, the cycle's own status in `cycle_status` (with `eol_date`),
  `declared` (the declarations, e.g. `"requires-python >=3.8"`) and `pinned`: the real runtime sources
  of the same product on the same project and branch (`.nvmrc`, `.node-version`, `.python-version`,
  an image), each as `{"cycle", "source"}`. It is not counted as end of life, not in the exit code and
  in neither release list; the pinned runtime has its own row and decides the end-of-life status. When
  `cycle_status` is `EOL`, the row is counted apart as **allowed but unsupported**: `audit.json`
  `stats.allowed_unsupported`, `status.json` `counts.allowed_unsupported`, a row in the `AUDIT.md`
  summary, the `STATUS.md` counts line and a note next to the end-of-life figure in `REPORT.html`.
  `AUDIT.md` lists the row as `build minimum (cycle EOL)` and explains each location, e.g. "build
  minimum: `requires-python >=3.8` allows Python 3.8, which reached end of life on 2024-10-07. The
  runtime actually used is not stated in this repository. Add `.python-version`, a Dockerfile image or
  a build SBOM to confirm it." With a pin, the last two sentences become "Pinned runtime: Node.js 22
  (Dockerfile); its own row gives the end-of-life status." In `issues.json` it is an `eol` issue with
  priority 6, reason `eol_minimum` and fix `raise_minimum` (raise the floor to a supported cycle).
  Go minimums keep the behaviour above and are not counted here.
- **.NET** runtime detection is unit-tested only; it has not been checked against a real .NET
  repository yet.

### Go test-only modules

go.mod and go.sum do not say which modules only the tests need, so the plugin reads the code
(`goread.py`). For each `go.mod` it reads the import declarations of every `.go` file of that module (a
subdirectory with its own `go.mod` is another module) and maps each import path to the required module
with the longest matching path. A module required without `// indirect` is dev-only (`optional`) when
every import of it is in a `_test.go` file or in a file with a `tools` build constraint
(`//go:build tools`, the tools.go convention), or when go.mod names it only in a `tool` directive, and
that holds in every go.mod of the repository that requires it. A module no file imports stays production
(unknown, not dev-only); `// indirect` modules are handled as before.

- Only the file header is read (build constraints, `package`, imports) by a small tokenizer: single and
  block imports, aliases, dot and blank imports, comments and raw strings.
- `vendor/`, `testdata/` and directories starting with `.` or `_` are skipped, as the Go tool does.
- Build tags other than `tools` are not evaluated: a file under `//go:build integration` that is not a
  `_test.go` counts as production, and so does a test helper package (`internal/testutil/x.go`) that
  only tests import. Generated code is read like any other file; cgo's `import "C"` is not a module.
- Hostile input: regular files inside the tree only, no symlinks, at most 1 MiB per file and 20,000 Go
  files per scan; a module where a file was skipped makes no dev-only claim.

### Gradle

Syft (checked with 1.56.0) reads only files named exactly `gradle.lockfile`: every
`group:artifact:version` in it, all configurations flattened, so no scope and no direct/transitive
split. It reads nothing from `build.gradle(.kts)`, `settings.gradle(.kts)`, `gradle/libs.versions.toml`,
`gradle.properties`, `buildscript-gradle.lockfile` or the legacy `gradle/dependency-locks/*.lockfile`.
Gradle is never run; the plugin's reader (`gradleread.py`) adds, statically:

- **Declarations** in `dependencies { }` blocks (also inside `if`/`forEach`, and Kotlin Multiplatform
  source sets): string notation `"g:a:v"` (`@aar`, classifier, `!!` accepted), map notation
  (`group: …, name: …, version: …` and the Kotlin `=` form), `kotlin("x")`, `platform(…)` and
  `enforcedPlatform(…)` (the BOM itself is listed, `platform: true`), version catalogs (`libs.x.y`,
  `libs.bundles.x`, `version.ref`, `strictly`/`require`/`prefer`, other catalogs created in
  `settings.gradle` with `from(files(…))`), and a local `val x = platform(libs.y)`. A `constraints { }`
  block only supplies a version to a declaration of the same file. `project(…)`, `files(…)`,
  `fileTree(…)`, `buildscript { }` and `plugins { }` are not dependencies.
- **Versions.** Literal versions, and `$x`/`${x}` when `x` has exactly one literal value across
  `def`/`val`, `ext.x =`, `ext { }`, `extra["x"]`, `val x by extra(…)`, Groovy maps in `ext`
  (`versions.kotlin`), `buildSrc` `object X { const val y = "…" }` and every `gradle.properties` in the
  repository. Two different values for the same name, a computed value, a dynamic version (`1.+`,
  `latest.release`, a range) and a version that comes from a platform/BOM, the Spring
  dependency-management plugin or the Kotlin plugin stay **unresolved**: the package is listed with an
  empty version, `requirement` and `reason`, and counted under "version not resolved". A declaration
  whose coordinates are unknown (an alias missing from the catalog, `Deps.x`, a helper function) is
  listed under its expression with no purl, also unresolved; nothing is dropped.
- **Which version counts.** A module with a `gradle.lockfile` gets its versions from Syft's reading of
  it; the reader adds only declarations missing from the lock file. A module without one gets its
  declared versions, which are a lower bound: Gradle's conflict resolution may pick a higher one, and
  transitive packages are not known at all. Legacy `gradle/dependency-locks/<configuration>.lockfile`
  files are read by the plugin (Syft does not).
- **Next to a `pom.xml` (or a legacy lock file).** A repository that builds with both Maven and Gradle
  (spring-petclinic) declares most packages twice. A Gradle declaration with the same name and version as
  a package Syft lists adds no second entry; its build file joins that entry's locations. A Gradle
  declaration without a resolved version whose `group:artifact` another reader on the branch resolves
  (Syft from a `pom.xml`, a legacy lock file) adds no unresolved duplicate either: its build file joins
  every resolved entry of that coordinate and is named in `gradle_unversioned` there, because the Gradle
  build may still pick another version. In the `sbom/` document these build files are
  `sbom-audit:location:<i>` properties next to Syft's `syft:location:*`, plus `sbom-audit:gradle_unversioned`.
  A coordinate only Gradle declares, or that nothing resolves, stays as described above.
- **Scope.** A configuration is dev-only when one of its camel-case words is `test`
  (`testImplementation`, `androidTestImplementation`, `kspTest`, `testFixturesApi`,
  `integrationTestImplementation`, `debugUnitTestRuntimeClasspath`), when it starts with `debug`
  (`debugImplementation`, `debugRuntimeClasspath`), when it is an annotation processor (`kapt*`, `ksp*`,
  `*annotationProcessor`) or a build tool (`developmentOnly`, `checkstyle`, `detektPlugins`,
  `lintChecks`, `kotlinCompilerClasspath`, …). Everything else counts as production, including
  `compileOnly`, unknown custom configurations and flavor/release variants. A package is dev-only only
  when every declaration (Gradle and Maven) says so. A package found only in `gradle.lockfile` is
  dev-only when all its lock configurations are dev ones, but only if every module that declares
  dependencies is locked and there is no `pom.xml` in the repository; otherwise it might reach a
  production classpath another way and stays production.
- **Direct.** A declared `group:artifact` is direct. Lock file packages of a module that declares
  something the reader could not identify get `direct` unknown (null) instead of `false`.
- **Hostile input.** Only regular files inside the exported tree, no symlinks, at most 1 MiB per file and
  2,000 build files; a `settings.gradle` path that leaves the tree is ignored; `build/`, `node_modules/`,
  hidden folders and the configured `ignore` paths are skipped (`android/` is read: it is where React
  Native and Flutter keep the Gradle build).

For exact versions, scopes and the transitive tree, commit a lock file (`./gradlew dependencies
--write-locks` with `dependencyLocking { lockAllConfigurations() }`) or import a build SBOM made with
the CycloneDX Gradle plugin (`org.cyclonedx.bom`; see [Imported build SBOMs](#imported-build-sboms) for
the task and the file it writes, which differ between plugin 2.x and 3.x).

## Imported build SBOMs

The repository scan sees what the manifests declare. Where versions come from outside the repository
(a Maven parent or BOM that is not in it, Gradle) or where you ship more than the manifests show, the
build knows better. A CycloneDX JSON SBOM from the build supplements the scan's package list of a
project branch or release tag: where both name a package, the build's entry counts.

```bash
# in the build, for Maven (official plugin, checked with 2.9.1; writes target/bom.json)
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom -DoutputFormat=json
# for Gradle (official plugin 3.x, Gradle 8.4+: plugins { id("org.cyclonedx.bom") version "3.6.1" })
./gradlew cyclonedxBom        # whole build, aggregated: build/reports/cyclonedx/bom.json
./gradlew cyclonedxDirectBom  # one per project: build/reports/cyclonedx-direct/bom.json
# (plugin 2.x, e.g. 2.4.1: ./gradlew cyclonedxBom writes build/reports/bom.json)
# then, on the machine that holds security/
python3 scripts/sbom_audit_cli.py import --project shop-api --branch main target/bom.json
python3 scripts/sbom_audit_cli.py import --project shop-api --tag v2.3.0 bom.json
python3 scripts/sbom_audit_cli.py import --project shop-api --branch main --from-artifact app.jar
```

- **Where it is read from.** `import` validates the file and copies it to
  `imports/<project>/<label>.cdx.json` (`<label>` as under `sbom/`: `main`, `release__1`, `tags__v2.3.0`)
  with `<label>.import.json` next to it: sha256, generating tool, the document's timestamp, the commit it
  was built from (`--commit`, default the current commit of the branch or tag) and the import time.
  Alternatively `sbom = "target/bom.json"` under `[projects."<name>"]` takes a file committed in the
  repository, read from the scanned commit, never from the working tree. When both exist, the
  `imports/` file wins. `--from-artifact` runs Syft on a built JAR, WAR, folder or image instead.
- **What it replaces, what it keeps.** Syft and the readers still run. For each ecosystem (purl type) in
  the imported SBOM, a package that both the SBOM and the scan name (same ecosystem and package name,
  Maven `groupId:artifactId`) is taken from the SBOM: version, scope and direct. A scan package of that
  ecosystem the SBOM does not name is kept and marked `not_in_build_sbom` (in `inventory.json`, and as
  `sbom-audit:not_in_build_sbom` in the `sbom/` document); if its version is not resolved it stays in
  "Coverage: unresolved versions" like any other, so nothing leaves the inventory silently. Other
  ecosystems, images and runtime pins stay as the scan found them. The project's own modules are dropped
  (the SBOM's `metadata.component` and its sub-components, the components the root depends on that the
  repository defines). There is no switch: a package the build does not list (a test-only or optional
  dependency, a module the SBOM of one artefact does not cover) is still checked as the scan found it.
- **Counts per branch.** The branch line in `INVENTORY.md` and the Notes of `AUDIT.md` say how many
  packages came from the import, how many were kept from the repository scan (not in the build SBOM, with
  the number whose version is not resolved, and up to 20 of them by name and version) and how many
  repository entries the import replaced, and how many of those had no version in the repository (a
  Gradle declaration that leaves it to a platform, a Maven version managed outside the repository) and
  got one from the import. `package_source` carries `packages`, `kept_from_scan`, `kept_unresolved`,
  `kept` (the names), `replaced_entries` and `resolved_by_import`; `replaced` stays the list of
  ecosystems the SBOM covers. A Gradle declaration counts like any other scan entry: the import's entry
  takes its build file as a location (and `gradle_unversioned` when it left the version open); one the
  import does not name is kept and marked `not_in_build_sbom`.
- **Direct and transitive** come from the SBOM's `dependencies` graph: a package is direct when the root
  or one of the project's own modules depends on it. Without a usable graph (Syft on a fat JAR has none)
  the manifests decide as for a scan, and an ecosystem without a manifest reader stays unknown.
- **Dev-only** (`optional`) only on evidence: the CycloneDX scope `excluded`, the cyclonedx-npm property
  `cdx:npm:package:development`, or a Maven dependency the build lists directly that every pom declares
  `<scope>test</scope>`. CycloneDX `optional` is not read as dev-only: the Maven plugin uses it for
  `<optional>true</optional>` and cyclonedx-npm for `optionalDependencies`, which both ship. The Maven
  plugin leaves test-scope dependencies out unless `includeTestScope` is set.
- **Locations.** A package the scan also found keeps its manifests; one only the SBOM lists points at the
  imported file, and its work-list hint says so instead of naming a manifest line.
- **Fields carried through.** An imported package is written into the `sbom/` document with the
  build SBOM's `group`, `publisher`, `hashes`, `licenses`, `supplier`, `manufacturer`, `cpe` and
  `externalReferences`, unchanged, so `sbom check` counts what the build stated. Each value is checked
  and bounded (known hash algorithms with hex content of a CycloneDX length; licence id, name, URL and
  `acknowledgement`, or one SPDX expression; organisation name, URLs and contacts; external references
  of a CycloneDX type with a URL; at most 32 entries per list, no control characters, no nested
  bom-refs, licence texts or other fields); a value that fails a check is left out, never repaired. A
  `sbom/` document older than CycloneDX 1.6 gets no `manufacturer`, no `acknowledgement` and only the
  external reference types of 1.4. Two import entries for the same package version merge, the first
  value of each field wins. These fields are in the `sbom/` document only, not in `inventory.json`.
- **Dependency graph carried through.** The import's `dependencies` are written in the bom-refs of the
  `sbom/` document: the project's own modules become the subject (`metadata.component`), an edge
  through a component that was not written (no purl, malformed) is followed through it, so no path is
  lost, and edges between own modules are left out. At most 2,000,000 edges; `package_source`
  records `graph_edges` (and `graph_truncated` when the limit cut it), and the branch line says "its
  dependency graph kept (N edges)".
- **Not this commit's.** When the recorded commit differs from the scanned one, the import is still used
  and every coverage statement says so: the branch line in `INVENTORY.md`, the coverage line and Notes in
  `AUDIT.md`, the gaps in `STATUS.md` and the limits in `REPORT.html`. For a file committed in the
  repository (config `sbom`) the commit is the last commit on the audited branch that changed the file,
  read from git history (`git log -1 <scanned commit> -- <path>`, no hooks, fsmonitor or diff drivers;
  `commit_from: "git history"`). When that is the scanned commit the line reads "committed in <sha> (the
  scanned commit)"; when it is older, "file last changed in commit <sha>, not the scanned one": the
  dependencies may have changed since. If git cannot name it, and for an `imports/` file changed after
  `import`, the import reads "commit not recorded".
- **Where it shows.** `package_source` on the inventory entry (`inventory.json`) and in
  `audit.json` `imported_sboms` (tool, timestamp, sha256, commit, `commit_from` (`provenance` or
  `git history`), stale, covered ecosystems as `replaced`, how direct was decided, the counts above), the
  `sbom-audit:package_source:*` properties of the `sbom/` document, and
  `"imported": true` on a vulnerability location from it. `cra check` counts the `sbom/` document as
  before; an imported package list is part of it.
- **Untrusted input.** CycloneDX JSON spec 1.4 to 1.7, at most 64 MiB and 200,000 components. XML and
  SPDX are refused with the generator's JSON option. Components without a purl are skipped and counted;
  unknown purl types are kept. A file that cannot be used is an error on the branch (`errors` in
  `inventory.json`) and the repository scan stands.

## SBOM quality: `sbom check`

Every SBOM the plugin writes, and any CycloneDX JSON file you point it at, gets a structural check and a
count of which data fields its components carry. The command reads and prints, and writes nothing (it
runs under `SBOM_AUDIT_READ_ONLY=1` and in the autonomous allow list).

```bash
python3 scripts/sbom_audit_cli.py sbom check                                  # every sbom/*/*.cdx.json
python3 scripts/sbom_audit_cli.py sbom check --project shop --branch release/1  # sbom/shop/release__1.cdx.json
python3 scripts/sbom_audit_cli.py sbom check target/bom.json --json           # a build SBOM before import
```

Exit code 0: no structural errors; 1: at least one file has structural errors; 2: a file is missing,
too large or not JSON (also for conflicting arguments).

**Structural findings.** Each finding has a level, a stable code, a message, a count and up to three
examples. "Valid" means none of the checks below found an error; it is not a full JSON Schema
validation, and it says nothing about whether the components are the right ones.

| Level | Codes |
|---|---|
| error | `not-object`, `bom-format`, `spec-version` (1.4 to 1.7), `serial-number-format` (`urn:uuid:`), `version-invalid`; `metadata-type`, `timestamp-format` (ISO 8601 date-time with zone), `tools-type`, `subject-type`, `subject-type-invalid`, `subject-name-missing`; `component-not-object`, `component-type-missing`, `component-type-invalid`, `component-name-missing`, `component-components`, `purl-syntax`, `version-type`; `bom-ref-type`, `bom-ref-too-long`, `bom-ref-duplicate`; `dependencies-type`, `dependency-not-object`, `dependency-ref-type`, `dependency-ref-dangling`, `depends-on-type`, `depends-on-dangling`; `too-many-components`, `too-many-dependencies`. Unreadable: `missing`, `too-large`, `unreadable`, `not-json` |
| warning | `serial-number-missing`, `version-missing`, `metadata-missing`, `timestamp-missing`, `tools-missing`, `subject-missing` (all optional in CycloneDX), `dependency-ref-repeated`, `nesting-too-deep` |

**Coverage.** For each field, how many component entries carry it, and the share. The count is of entries
in the document, not of distinct packages: a package declared in two manifests (a `pom.xml` and a
`build.gradle`) with versions spelled differently is two entries. Components of type `file`
(Syft lists the manifests it read) are counted apart and left out of the shares. A value counts only
when it is there and non-empty; nothing is inferred and nothing is filled in. The plugin never adds a
supplier, licence or hash a source does not state, so a low share is the honest result for most
repository scans: lockfiles carry versions and purls, rarely licences or suppliers.

| Column | Counts a component when it has |
|---|---|
| Version | a non-empty `version` |
| purl | a syntactically valid `purl` |
| Identifier | a valid purl, a `cpe`, `swid.tagId`, `omniborId` or `swhid` |
| Licence | a `licenses` entry with an id, a name or an expression |
| Hash | a `hashes` entry with algorithm and content, also under `externalReferences[].hashes`; SHA-512 separately |
| Supplier | `supplier` or `manufacturer` with a name, URL or contact |
| In graph | a `dependencies` row naming it, as `ref` or in `dependsOn` |

Document-level flags: dependency graph present, `compositions` present, timestamp, tool named,
author or tool (tools, `metadata.authors`, `manufacturer`, `manufacture` or `supplier`), subject named
with a version (`metadata.component`).

**Where it shows.** `sbom_quality` on each inventory entry in `inventory.json` (the counts above), the
"SBOM quality" table in `INVENTORY.md`, and the SBOM row of `cra check` (see the table under Cyber
Resilience Act).

**What the columns correspond to.** The table names the data fields of two documents that describe what
an SBOM should hold; the numbers show how many components carry something in that field. They do not
show that a document conforms to either, and neither document is a CRA implementing act: the CRA itself
asks for an SBOM in a commonly used, machine-readable format covering at least the top-level
dependencies (Annex I Part II (1)), and the Commission may set format and elements by an
implementing act (Art. 13(24)), which had not been found when this section was written. Sources and the
dates read are under [Sources](#sources).

| Column | NTIA minimum elements (2021) | BSI TR-03183-2 2.1.0 (2025) | What the count does not check |
|---|---|---|---|
| (structural: component name) | Component Name | Component name (5.2.2, required) | |
| Version | Version of the Component | Component version (5.2.2, required) | whether the version follows a well-recognised scheme, as the TR recommends (8.1.9) |
| purl, Identifier | Other Unique Identifiers | Other unique identifiers, CPE or purl (5.2.4, additional) | |
| Supplier | Supplier Name | not the same field: the TR's "Component creator" (5.2.2, required) is the manufacturer, with an email or URL, and the TR keeps creator and supplier apart | whether the party is the creator; whether an email or URL is given |
| Licence | not a minimum element ("License Information" is listed as a recommended field) | Distribution licences (5.2.2, required) | the SPDX expression rules and the "concluded" acknowledgement the TR asks for |
| Hash, SHA-512 | not a minimum element ("Hash of the Component" is recommended) | Hash value of the deployable component, SHA-512 (5.2.2, required) | whether the hash is of the deployable form, and where it sits (the TR names the distribution external reference) |
| In graph, dependency graph, compositions | Dependency Relationship; NTIA asks at least for all top-level dependencies and for gaps to be stated ("known unknowns") | Dependencies on other components, with completeness indicated (5.2.2, required); recursive resolution as set out in 5.1 | whether the graph is complete or deep enough; `compositions` is only noted as present |
| Author or tool | Author of SBOM Data | Creator of the SBOM, with an email or URL (5.2.1, required) | whether a contact is given |
| Timestamp | Timestamp | Timestamp (5.2.1, required) | |

Not counted at all: the TR's filename and executable, archive and structured properties of a component
(5.2.2), the SBOM-URI (5.2.3), source code and deployable-form URIs (5.2.4), and the TR's format floor
(CycloneDX 1.6 or SPDX 3.0.1 or higher, section 4; the plugin writes the CycloneDX version Syft writes, 1.7 when Syft fails).
NTIA's practices (frequency, delivery, access control) are outside a file check.

## Limitations

The overview, with C/C++ and firmware coverage, untested platforms and the data that leaves the
machine per mode, is [Limitations](limitations.md); the plain-CLI sequence is
[Using sbom-audit without Claude Code](without-claude-code.md). The details:

- C/C++ and firmware: git submodules, vendored C/C++ code, Zephyr `west.yml`, ESP-IDF
  `idf_component.yml`, PlatformIO `platformio.ini`/`library.json`, Conan `conanfile.py`, the
  dependencies of `vcpkg.json` and CMake `FetchContent`/`ExternalProject` are not inventoried. They
  are detected per branch (`coverage_gaps` in `inventory.json`) and reported, never as clean:
  `AUDIT.md` summary row "Branches with submodules, C/C++ code or firmware manifests not inventoried"
  and a Note per branch, `stats.coverage_gaps` in `audit.json`, the counts in `STATUS.md`, the limits of
  `REPORT.html` and `INCOMPLETE` in the CRA SBOM row. Import a build SBOM to cover them.
- Packages with a purl type OSV has no advisories for (`generic`, `github` outside workflows, `conan`,
  `vcpkg`, `bitbucket`, `gitlab`), typically from an imported C/C++ build SBOM, are inventoried but not
  checked: `stats.packages_unmatched`, the `AUDIT.md` summary row "Packages OSV cannot match" and a Note
  per branch. CPEs are not used for matching.
- A project with none of the configured branches is not scanned: `setup` warns, the run lists it in
  `AUDIT.md` Notes, `skipped_projects` and `stats.projects_not_scanned` in `audit.json`, and `STATUS.md`
  Sources and Counts. The exit code does not change.
- Ecosystems OSV does not cover (CocoaPods, Swift packages, system packages) are listed
  in the inventory but not matched against vulnerabilities.
- GitHub Actions used in workflows (`pkg:github/<owner>/<repo>@<ref>`) are inventoried but not
  checked for vulnerabilities. OSV's "GitHub Actions" advisories carry only ECOSYSTEM ranges, and a
  query with a version returns nothing even for an affected one (tried with `tj-actions/changed-files`
  35.0.0 against GHSA-mrrh-fwg8-r2c3 and `actions/download-artifact` 4.1.2 against GHSA-cxww-7g56-2vh6,
  with and without the `v`); workflows also mostly pin a floating major tag (`v4`) or a commit SHA,
  which no range comparison resolves. `AUDIT.md` counts them in the summary ("GitHub Actions
  inventoried, not checked for vulnerabilities") and names them per branch under Notes,
  `audit.json` has the count as `stats.github_actions_unchecked`, and `REPORT.html` states it under
  limits.
- Dependencies are read from the configured branches (and the release tags under audit); the secrets
  scan reads the whole git history of every branch of each repository, so a secret on an
  unconfigured branch is found while that branch's dependencies are not audited.
- `requirements.txt` with ranges is read best effort; a `package.json` without a lockfile
  lists its direct dependencies with their range and marks them unresolved.
- A package without a resolved version (Maven `UNKNOWN` from an external BOM or parent, a manifest
  without a lockfile) is not checked for vulnerabilities; it is counted and listed as "version not
  resolved", neither vulnerable nor clean. In-repo Maven poms are resolved offline; external BOMs are
  not downloaded, and Maven profiles, `<version>` ranges and properties set on the command line or in
  `settings.xml` are not evaluated.
- Gradle build files are read, not run: plugins that add dependencies (Spring Boot, Android Gradle
  plugin, Kotlin), `allprojects`/`subprojects` blocks applied to other modules, convention plugins,
  catalogs published as artifacts, version catalogs' `rejectAll`/rich versions beyond
  `strictly`/`require`/`prefer` and anything computed are not evaluated. Without `gradle.lockfile` a
  Gradle project has no transitive packages and its declared versions are lower bounds (see
  [Gradle](#gradle)); use lock files or the CycloneDX Gradle plugin's SBOM.
- An advisory that no source rates reads "not rated"; it ranks with CRITICAL/HIGH in production
  (issues priority 3) rather than below LOW, and someone has to read it to know how bad it is.
- No reachability analysis: a vulnerable package in the lockfile counts as a finding until
  a VEX statement says otherwise. The verifier in `assess` reads code; it runs nothing, and a
  `holds` verdict is a second opinion, not a proof.
- `deno.lock` packages pulled through a CDN (esm.sh, unpkg, jsDelivr, Skypack) are listed;
  `deno.land` modules are not, because OSV has no ecosystem for them.
- `run --only <project>` replaces the inventory and report with those projects only; run
  without it for the portfolio. Merging partial scans into the portfolio is not implemented.
- The secrets scan finds what gitleaks rules match; it does not verify whether a credential
  still works, and it cannot see secrets that never reached git.
- `git archive` honours `export-ignore` in a scanned repository's `.gitattributes`: a manifest
  or lockfile marked that way is missing from the SBOM. The secrets scan reads the history
  directly and is not affected.
- Host mode covers Debian and Ubuntu servers with apt only; other distributions are reported as unsupported. A Lynis run takes several minutes per host, so a check of many servers takes a while (hosts run in parallel, 4 by default). Hosts reached only through ProxyJump or ProxyCommand are not supported. `patch` installs only the confirmed list and may refuse an upgrade that needs a new package (see [Hosts](#hosts)).
- The scheduler covers macOS and Linux; elsewhere use the GitHub Actions template.
- Release scanning reads local tags only, and only the newest `keep` of them; a release outside that
  window is no longer audited. "Fixed since previous" compares two SBOMs with today's OSV data, so it
  is evidence of absence from the SBOM, not of a code fix or of the date a vulnerability was handled;
  `days` runs between tag dates. The support period is what you configure; the plugin does not
  determine it.
- Findings never inflate the counts: dev-only occurrences are labelled and listed apart,
  a failed source leaves its section empty and is named under **Source status**.
