# Changelog

## 1.4.1 — 2026-11-24

Display and wording fixes after the first 1.4.0 run on a real portfolio. No priority, order, count or
exit code changes, and `audit.json` and `issues.json` are unchanged.

### Changed
- `HOSTS.md`: a package line shows its highest EPSS score only from 10% up, and names the CVE that has
  it: ` - highest EPSS 83.2% (<cve>)`. In 1.4.0 every package line carried the figure (about 1,100 lines
  on five hosts, almost all below 1%), and a high figure on a package with thousands of open CVEs could
  not be checked, because the CVE was not named. A lower score is not shown. A package none of whose open
  CVEs has a score still reads ` - no EPSS`, so a missing score is never left out; the line under the
  table states both. The 10% is fixed and does not read `[epss] promote_at`: no host rule depends on a
  score.
- `hosts.json`: `vuln` findings carry `max_epss_cve` next to `max_epss` (`null` without a score). A
  `hosts.json` written by 1.4.0 has no such field, so its high scores are shown without a CVE until the
  next `hosts check`.

### Fixed
- `REPORT.html` (EN, DE): with `promote_at = 0` the sentence above the action list no longer says
  ", or likely to be exploited by EPSS".
- `ISSUES.md`: with `promote_at = 0` the sentence on the order inside a priority no longer names an EPSS
  threshold. It reads "production comes first, then direct dependencies before transitive ones, then the
  higher EPSS score", which is the order such a run uses.
- `AUDIT.md`, section "Likely to be exploited (EPSS)": when none of the listed rows is promoted, the
  intro says so. Before, it said "Rows marked promoted are the ones the summary counts" above a list
  with no marked row.

### Documentation
- Evals, 2026-11-24 (three runs per arm): every case at or above 0.8 with the plugin (`assess`, `hosts`,
  `incident`, `lookup`, `run`, `setup` 1.00, `secrets` 0.96); no eval exception is recorded for 1.4.1.
  Details in `CONTRIBUTING.md`.

## 1.4.0 — 2026-11-24

EPSS scores: FIRST's daily estimate of the probability that a CVE is exploited in the next 30 days. They
rank up likely targets among the MEDIUM and LOW findings in production and order the work inside each
priority. EPSS never lowers a priority. No new commands.

**Upgrade note.** After the first 1.4.0 run, some MEDIUM or LOW findings in a production project or a
supported release move from priority 6 to 3 in `issues.json` (reason `epss_production`, default
threshold 10%), the order inside a priority changes (likely ones first, then the higher score), and
there is a new outbound host, `epss.empiricalsecurity.com`. To keep the scores but stop the promotion,
set `promote_at = 0` under `[epss]` in `sbom-audit.toml`; to stop the download and every EPSS field,
column and rule, set `enabled = false`. If `epss.empiricalsecurity.com` cannot be reached and no earlier
file is cached (allow-listed egress in CI, an air-gapped machine), the EPSS source is `failed` and the run
exits 2, as for KEV. Allow the host, or set `[epss] enabled = false`. `promote_at = 0` turns only the
promotion off; issues are still ordered by score inside a priority. Only `enabled = false` restores the
1.3.1 order. Scores change daily, so `audit.json`, `issues.json` and the reports can differ from one day
to the next with no change in your dependencies.

### Added
- EPSS step in `audit` and `run`: one GET of the complete daily file
  `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (no query string, nothing about your
  packages is sent), kept for 24 h as `.cache/enrich/epss-scores.csv.gz` and shared with the host check.
- Config `[epss]`: `enabled = true` and `promote_at = 0.10` (a fraction; `0` turns promotion off). A
  value outside 0 to 1, or a bool, is a config error that shows `0.10 for 10%`. An unknown key in
  `[epss]` (a typo such as `promote_att`) is a config error that names the key, as in `[releases]`. The
  default `sbom-audit.toml` carries the block commented out.
- Priority rule `epss_production` (priority 3): a package version that is not KEV, not CRITICAL/HIGH and
  not unrated, in runtime scope of a production project or supported release, with an EPSS score at or
  above `promote_at`. The issue title names the threshold, not the score, so it does not change daily.
- Order inside a priority: production first, then issues at or above the threshold, then direct,
  unknown and transitive dependencies, then the higher score (none counts as the threshold), then
  severity, place and id. Host issues are never moved by a score.
- `audit.json`: top-level `epss`, per advisory `epss` and `epss_percentile`, per row `max_epss`,
  `sources.epss`. `issues.json`: top-level `epss`, `details.max_epss`, `details.epss_likely` and the
  scores per advisory; `SCHEMA` stays 1. `status.json`: `counts.epss_promoted` (`null` when no score
  file was available). `manifest.json`:
  `data_sources.epss`.
- `AUDIT.md`: a method sentence, the summary row "Promoted by EPSS" (`off` at `promote_at = 0`, `not
  available` when no score file was available), the section "Likely to be exploited (EPSS)" (its rows
  that the summary counts end with `; promoted to priority 3`) and an EPSS column in the by-project and
  dev-only tables. `ISSUES.md` and `REPORT.html` (EN, DE): an EPSS column and the reason "Likely to be
  exploited (EPSS)". `STATUS.md` and the run summary count the promoted ones (`STATUS.md` reads `EPSS
  not available` when no score file was available); `incident` shows the score in its evidence, the
  `issues` query line at its end (`no EPSS` without a score).
- Hosts: KEV findings carry the CVE's score, `vuln` findings the highest one, in `hosts.json` and
  `HOSTS.md` (`(KEV, no EPSS)` and ` - no EPSS` without a score). Information only: no host priority depends on it, and finding ids and texts never contain
  a score.

### Changed
- A missing score reads `no EPSS`, never 0%; a score that rounds to 0.0% reads `<0.1%`.
- A failed download with an older cached file uses that file: the source status is `stale` with the
  reason and the score date, and the exit code does not change. Without any file the source is failed
  (exit 2, as for KEV) and nothing is promoted.
- An `audit.json` without the top-level `epss` key (written by 1.3.x, or with `enabled = false`) gives
  the same `AUDIT.md`, `issues.json`, `ISSUES.md`, `STATUS.md` and `REPORT.html` as 1.3.1.
- The assessment triage order (skills and `assess draft`) names `epss_production` after CRITICAL/HIGH
  in production.

### Documentation
- `docs/reference.md`: EPSS section, the new rule and order, the fields, the outbound host, outage
  behaviour and limitations (a forecast, CVEs only, a missing score is not a low score, the 10% default
  is a judgement, scores change daily). `README.md`, `docs/limitations.md`, `docs/index.html` and the
  evidence folder templates name the new source and host.
- Evidence folder templates v7: the next run rewrites the plugin-owned `README.md` and `CLAUDE.md` in an
  existing evidence folder once, so its table of outbound hosts names the EPSS host; hand-written files
  without the marker are left alone.
- The eval fixture carries a synthetic EPSS score on its lodash advisory.
- Evals, 2026-11-24 (three runs per arm): every case at or above 0.8 with the plugin (`assess`, `lookup`,
  `run`, `setup` 1.00, `incident` and `secrets` 0.92, `hosts` 0.83); no eval exception is recorded for
  1.4.0. Details in `CONTRIBUTING.md`.

## 1.3.1 — 2026-11-23

Hardening after an independent review and field tests on C/C++, firmware and Maven repositories. No
new commands; several reports now say plainly what was not checked.

### Security
- A scanned repository's own config no longer runs anything during a scan: every git process (including
  the git that gitleaks starts) gets command-line config that disables fsmonitor, hooks, the external
  diff command and signature checks, and blocks the `ext::` transport. gitleaks reads history with
  `--no-textconv --no-ext-diff`, and the tree export empties all repository filter drivers. Before, a
  textconv driver could run a program and hide the history from the secrets scan. `git fetch` still
  uses the repository's transport config; see "Hostile repositories" in `docs/reference.md`.
- The clear-text gitleaks report is read from a pipe and never written to disk. gitleaks runs in its own
  process group with its own timeout; a timeout, an error or SIGTERM kills it and the git processes it
  started. Files an older version left in `.cache/secrets/raw/` are deleted.
- Branches are read by full ref (`refs/heads/…`, `refs/remotes/origin/…`). A tag with a branch's name
  can no longer swap in another tree; the run prints a warning when such a tag exists.
- Maven pom resolution reads only regular files inside the exported tree: no symlink out of it, no FIFO.
- Incremental secrets scans accept only full 40- or 64-hex commit ids from `secrets.json`.
- git, the tree export, syft and osv-scanner have timeouts; a timeout is a failed source, never a clean
  one.
- `code grep`/`show`/`files` withhold dotenv, key and credential files (one list shared with the
  assessment's deny rules) and lines recorded in `secrets.json`, and say how many were withheld without
  showing content. User paths are literal, and `files` no longer lists `security/.cache`.
- Headless assessment: reads only the evidence folder, denies secret and cache paths everywhere, fetches
  only from a fixed list of advisory hosts, and has no web search.

### Fixed
- git on macOS inside a sandbox: when `git` on `PATH` is Apple's `/usr/bin/git` shim, every command now
  puts the real git (selected Xcode, else the Command Line Tools) first on `PATH`, through a temporary
  folder that holds only a `git` symlink, so nothing else is shadowed. The shim asks `xcrun`,
  which writes a cache file under `/var/folders`; Claude Code's sandbox and the eval sandbox forbid that
  write, so every git call failed (`couldn't create cache file ... xcrun_db`) and `code grep`, `scan` and
  the verifier could read nothing. The `assess` eval case, 0.33 for 1.3.0 for this reason, scores 1.00
  again (3 of 3 runs, 2026-11-23); no eval exception is recorded for 1.3.1.
- `incident` and `lookup` answer "unknown" instead of "absent" when the inventory cannot support
  "absent": ecosystems the scan does not resolve, Swift and other purl types mapped to their OSV names,
  Go `stdlib` and `toolchain` advisories. The rules are in `docs/reference.md`.
- `incident --vex` records "not affected" per examined branch (`<purl>@<branch>`), no longer for the
  whole project, and prints `not recorded: …` for what it refused.
- A minimum such as `requires-python >=3.8` or `engines.node` is reported as "allows a version that is
  end of life" (status `minimum`, count `allowed_unsupported`, issue reason `eol_minimum`, priority 6),
  no longer as an end-of-life runtime. A pinned runtime in the same project takes precedence.
- The same package declared in two manifests is one line in `INVENTORY.md` naming both files; counts in
  reports are distinct packages (`stats.unique_package_versions`, `direct_dependencies`).
- `code` separates three outcomes: no match (exit 1), repository or ref unreadable (exit 2), git could
  not run (exit 4, with a hint for the macOS git shim). `grep` has a timeout.
- C/C++ and firmware: submodules, west, ESP-IDF, PlatformIO, `conanfile.py`, vcpkg and CMake
  FetchContent are detected and reported as coverage gaps (`coverage_gaps` in `inventory.json`; counts
  in AUDIT.md, STATUS.md and REPORT.html; the CRA SBOM row reads INCOMPLETE). The tool does not
  inventory or check these dependencies; see `docs/limitations.md`.
- Packages no vulnerability source covers are counted as not checked (`packages_unmatched`,
  `stats.unique_package_versions_unchecked`); REPORT.html qualifies "No finding requires immediate
  action" (EN/DE) when projects were skipped, gaps exist or packages were not checked.
- Skipped projects (none of the configured branches exist) end `run`, `scan` and `audit` with a WARNING
  line (`projects_not_scanned`); the exit code is unchanged. `setup` warns about them.
- An imported `pkg:github` component is no longer treated as a GitHub Action; the project's own
  `vcpkg.json` is no longer its own dependency.
- `vex add` and `incident --vex` refuse without `--author` or a git identity.
- Messages that name a `/sbom-audit:` command also give the CLI form; evidence folder templates v6.
- `inventory.json` stores full refs in `ref` (`refs/heads/main`); reports show the short form.
- Scheduler status: `last fired` is shown in local time (the raw UTC stamp made a Saturday 03:00 fire
  east of UTC read as Friday) and `next fire` is computed, no longer frozen at its install-time value.
  A missed weekly fire is reported as `scheduler did not run since <day> (weekly run N days overdue)`;
  new lines report a scheduled run that failed or did not finish, and STATUS.md shows the last exit
  code, last error and plugin used. The weekly wrapper falls back to the newest cached plugin version
  when its recorded install directory is gone.

### Added
- Opt-in systemd container test for the Linux timer (`SBOM_AUDIT_DOCKER_TESTS=1`) and
  `docs/testing-linux-timer.md`. The test has not yet been run on a Linux machine.

### Documentation
- New `docs/limitations.md` and `docs/without-claude-code.md`.
- `CONTRIBUTING.md`: how to run the evals from a checkout, the rule for shipping with a case below 0.8
  and the list of recorded exceptions, a 14-day rule for tool pins. README install line corrected.

## 1.3.0 — 2026-11-21

Evidence you can hand to an auditor: every run records how it was produced and can be verified later,
each SBOM is checked for validity and data-field coverage, released versions and CRA readiness get
their own reports, and a build SBOM fills what a repository scan cannot resolve.

- Run manifest and `verify`: every run writes `manifest.json` with the plugin and tool versions (syft,
  osv-scanner, git, the secrets engine, gh), the data sources and their dates in UTC, a digest of the
  config, the audited commit per project and branch, and the SHA-256 and size of every evidence file.
  `verify [--json]` compares the folder with it and names each file as ok, appended, changed, missing or
  invalid (exit 0, 1 or 2; read-only). Later writing commands refresh only the entries they wrote.
  `AUDIT.md` and `REPORT.html` gain a "How this report was produced" block.
- SBOM quality: `sbom check [<path> | --project <p> [--branch <b>]] [--json]` checks a CycloneDX file
  structurally and reports the share of components with a version, a package URL, a unique identifier,
  a licence, a hash and a supplier, and whether a dependency graph is present. `INVENTORY.md` and
  `inventory.json` carry the same numbers per SBOM. `docs/reference.md` maps the columns to the NTIA
  minimum elements (2021) and BSI TR-03183-2 v2.1.0; the tool reports coverage and never states
  compliance. Every SBOM the tool writes has a serial number and a timestamp.
- Imported build SBOMs: `import --project <p> (--branch <b> | --tag <t>) bom.json` stores a CycloneDX
  JSON SBOM from your build under `imports/`; later runs use its packages for the ecosystems it covers,
  with direct and transitive dependencies from its graph. It supplements the repository scan: packages
  only the scan found stay in the inventory, marked `sbom-audit:not_in_build_sbom`. Hashes, licences,
  supplier, manufacturer, CPE, external references and the dependency graph of the imported file are
  carried into the written SBOM. Coverage statements name the imported file and say when it was not
  built from the scanned commit; a checked-in SBOM gets its commit from git history.
- Releases (opt-in, `[releases]`): an SBOM and audit per release tag, support periods, `RELEASES.md` and
  `releases.json`, and `releases --project <p> --fixed <tag>` for the advisories no longer present
  compared with the previous release. Version order is semver with pre-releases opt-in.
- CRA readiness (opt-in, `[cra.products]`): `cra check` writes `CRA.md` and `cra.json` per product and
  obligation with its article reference (evidence present, missing, stale, or the manufacturer's
  responsibility); `cra init` writes starter documents in English and German after you confirm the
  plan. An SBOM with structural errors counts as missing. Evidence tooling, not legal advice.
- Management report: `REPORT.html`, one self-contained page that prints to A4/PDF, in English or
  German, built from the run's JSON.
- Without Claude Code: `assess draft` sends the report excerpts to an endpoint you configure under
  `[assess]` and writes a draft assessment; `--dry-run` prints the exact request. The README documents
  the CLI for other agents and plain shells.
- Gradle: build files and version catalogues are read statically for direct dependencies, scope and
  declared versions. A version the files do not state is listed as "version not resolved". Next to a
  `pom.xml` that resolves the same coordinate, the Gradle declaration adds its location to that entry
  instead of a second row. Convention plugins and published catalogues are not read; a build SBOM
  covers them.
- Maven and Go: manifests are read for direct, test-only and own packages; Java, Go and .NET runtimes
  are detected. Go modules that only tests or tools import count as dev-only. A Maven package is named
  `group:artifact` everywhere (issue ids are unchanged).
- Accuracy: an unknown dependency type reads "unknown" and is `null` in `audit.json`, `issues.json`
  and coverage entries, never "transitive". The Go version in `go.mod` is a build minimum (runtime
  status `minimum`), not an end-of-life runtime. Packages without a version and advisories without a
  rating are reported as coverage gaps. End of life "unknown" is its own state. Unchecked GitHub
  Actions are listed.
- Secrets: findings are ranked by context (key body evidence, path labels, value shape).
- Hosts: login findings are aggregated per user and key.
- Status: a delta never reports a rule change as progress; a count that follows other rules than the
  previous run reads "not comparable with the previous run". A run commits the config it read.
- Fix: the GitHub Actions template runs the CLI at `plugin/scripts/sbom_audit_cli.py`; in 1.2.1 it
  called a path that does not exist in the tag.
- Fix: `sbom check --project` and `--branch` cannot name a path outside the `sbom/` folder.

Eval exception (recorded afterwards, see `CONTRIBUTING.md`): the `assess` case scored 0.33 with the
plugin because the eval sandbox on macOS blocks Apple's git shim, so `code grep` could not read the
fixture repository. The same command works outside the sandbox.

## 1.2.1 — 2026-11-16

- Upgrading from 1.2.0: the SessionStart hook is no longer installed with the plugin. Run
  `/sbom-audit:settings hook on` to keep the status line. Claude Code now asks before each plugin
  command; `/sbom-audit:settings autonomous` lets the local and read-only ones run without asking.
- Safety: the plugin ships no hooks, and every skill pre-approves only Read, Grep and Glob (before:
  unrestricted Bash, WebFetch and WebSearch in ten skills). Two opt-ins replace that, managed by the
  new `/sbom-audit:settings` skill and `settings` subcommand in the user's `~/.claude/settings.json`:
  autonomous mode (allow rules for this plugin's CLI at its absolute installed path, only for
  subcommands that read or write the local `security/` folder, plus WebFetch on the advisory domains;
  never `setup` or a host change) and the session status line. `off` removes exactly what `on` added;
  a backup of `settings.json` is kept; after a plugin update `run` and `setup` move the recorded rules
  to the new path and add nothing else.
- New: `code grep|show|files <project> <branch>` reads committed code on an audited branch without a
  shell or a checkout (configured projects only, repository-relative paths, `security/.cache/` never
  read, no textconv or hooks, output capped). The assessment's verifier agents use it instead of raw
  `git`, and the headless assessment may call it.
- Layout: the installable plugin moved to `plugin/`. Tests, evals, docs, CI and the icon and parity
  helpers (`tools/`) stay in the repository and are no longer shipped to users. The marketplace entry
  points at `./plugin`.

## 1.2.0 — 2026-11-16

- Upgrading from 1.1.x: nothing to migrate. The minor version bump triggers one full secrets
  rescan; rerun `hosts bootstrap <host>` (plan, then `--confirm <host>`) per server to get
  collector 3. The README is now a short landing page; the full manual moved to
  `docs/reference.md`.
- Security: the headless assessment child (`[schedule] assess = true`) could read any file and fetch
  any URL. Its reads are now limited to the portfolio and `security/` (`Read(//<path>/**)`), and
  WebFetch to advisory sources (osv.dev, GitHub, NVD, CISA, endoflife.date, distro trackers, package
  registries). The assess skill treats report text, scanned code and fetched pages as data, never as
  instructions.
- Security: the SessionStart hook printed strings from `security/status.json` into Claude's context
  verbatim, and a cloned repository can ship its own. Every string is now one printable line without
  backticks, capped in length; delta items are quoted, prose-like items are replaced, and at most 20
  are listed per key. Report cells (`md()`) also drop control characters and bidi overrides.
- Fix: STATUS.md and the session line counted a MEDIUM advisory of a package that also had a HIGH
  one as a new CRITICAL/HIGH finding. AUDIT.md and `issues.json` now name the same worst advisory.
- Fix: `run` and `setup` in a folder without git repositories exited 0 and reported a clean
  portfolio; both now exit 2 with a hint. Right after `setup`, status says "set up, no run yet"
  instead of "nothing new". Hints name `/sbom-audit:*` commands instead of a nonexistent
  `sbom-audit` executable, the missing-tool hint mentions gitleaks, `incident` without an inventory
  says so plainly, and `issues --project`/`--host` with an unknown name lists the known ones.
- Security: the host collector (now collector 3; run `hosts bootstrap <host>` to update) ran
  `caddy`, `node` and `docker-compose` as root after only an executable-file test that followed
  symlinks, so a user who could write one of those paths or a symlink target (an nvm install linked
  into `/usr/local/bin`) got root on the next `hosts check`. It now runs a binary only when the file
  and every directory above it, through each symlink hop, are owned by root and writable by no group
  or other user. Any other binary is not run and is reported as the critical
  `permissive:binary-untrusted:<path>`.
- Security: a scanned repository could make the plugin's own readers read files outside the export.
  A Dockerfile `RUN pip install -r <path>` was resolved and read before the path was checked (a
  symlink, `../` or an absolute path reached outside; the absolute path ended up in an error property
  of the SBOM and the Dockerfile's images were dropped), and a committed symlink named `.nvmrc`,
  `.python-version`, `package.json`, `pyproject.toml`, `Dockerfile` and so on was read through,
  putting the first line of any file the scanning user can read into the SBOM. Files are now read
  only when they resolve to a regular file inside the tree; anything else is skipped unread.
- Work list: `issues.json` and `ISSUES.md`. Every `run` writes one flat list of what is open and
  where: a stable id, kind (`vulnerability`, `secret`, `eol`, `floating_tag`, `host`), priority in
  triage order, place (project or host, branches, file, line), fix target and first-seen date. It is
  for whoever fixes, a person or an agent; the plugin still fixes nothing. Suppressed, decided,
  accepted and informational findings are left out, secrets appear by fingerprint only, and failed
  sources are named under `incomplete`. Refreshed after `secrets resolve`, `hosts check` and
  `hosts accept`; the new CLI command `issues` rebuilds it from the reports. With `--project`,
  `--host`, `--kind`, `--max-priority` or `--json` the command prints the selection instead and writes
  nothing (allowed in read-only mode). One issue per line in the file. Evidence templates v3.
- Fix: `secrets resolve` now updates the secrets part of `status.json` and `STATUS.md` (counts, open
  set, oldest open finding; a decided finding moves from `new` to `resolved`). Before, the session
  line kept counting decided findings until the next run.
- Evals: new `assess` case. The user's claim that would close a finding is false in the fixture code;
  the case grades that a verifier agent runs, the claim is reported as disproved and nothing is recorded.
- Assess: adversarial verification. Before the one confirmation, every drafted decision that closes a
  finding on a judgement (VEX `not_affected` with `vulnerable_code_not_present`,
  `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary` or
  `inline_mitigations_already_exist`; secrets `false_positive`, `test_fixture`, `accepted`) goes to a
  fresh agent that sees only the claim and tries to disprove it. `holds` stores the evidence in the
  statement, `disproved` keeps the finding open as an action, `unresolved` becomes
  `under_investigation`. The user can overrule a verdict; the statement then records
  `verifier disagreed`. `component_not_present` and `fixed` are checked with `lookup`. Headless
  proposals mark these entries `unverified`. The `assess` and `run` skills gain the `Agent` tool.

## 1.1.1 — 2026-11-10

- Hosts check: the `containers` section now lists rootless Docker daemons (Docker run by a user) through
  `/run/user/<uid>/docker.sock`, their containers named `uid<uid>/<name>`, next to the system daemon. A
  host where Docker is installed but no `dockerd` runs reports no containers instead of the critical
  `section-failed:containers`, also when a stale `/var/run/docker.sock` is left behind. Without `pgrep`
  the collector asks the system socket, as before.
- A rootless daemon is asked only through a socket owned by its own uid (no symlinks), and every line it
  returns carries the `uid<uid>/` prefix, so a user's daemon cannot stand in for root's containers. A
  `dockerd` in another PID namespace (inside a container or an LXC guest) is skipped.
- Collector version 2: `hosts check` reports hosts that still run collector 1 as `info:collector-outdated`
  until you rerun `hosts bootstrap <host>` (plan) and `--confirm <host>`. On a host with a baseline,
  rootless containers then show once as baseline changes to accept; on a host that had none, they join
  its first baseline.

## 1.1.0 — 2026-11-10

Host mode: an audit of your Debian and Ubuntu servers that installs nothing on them, plus confirmed patching and
bootstrapping, in the same evidence folder.

- Hosts check: `hosts check` collects each configured server over SSH with a forced-command audit login and writes `HOSTS.md` and `hosts.json`: installed packages against OSV and CISA KEV, third-party apt sources and known binaries, permissive defaults, SSH logins keyed on the key fingerprint, the patch automation itself, the OS release's own end of life from endoflife.date (`os:eol`: critical once free security support has ended, informational within 90 days; a failed lookup is informational, never "supported"), and the Lynis hardening index. A CISA KEV list that cannot be loaded is the critical `section-failed:kev` on every checked host, which keeps the earlier KEV findings open; an osv.dev outage does the same with the critical `section-failed:osv`. An empty `admin = ""` is rejected at config load.
- Baseline: the first successful check becomes the accepted fingerprint (users, sudoers, `authorized_keys`, sockets, units, timers, cron, sshd, firewall, apt sources, containers); later differences stay open until accepted. A unit, timer or cron file owned by a package that changes during that package's upgrade is shown as an explained change, not a new finding.
- Accept: `hosts accept <host> <change-id> "<note>" [--review-by YYYY-MM-DD]` records a decision in `hosts-decisions.toml`; a KEV finding needs a review date at most 30 days ahead.
- Bootstrap: `hosts bootstrap` and `hosts unbootstrap` install and remove the audit user, collector, sudoers drop-in, forced-command key and Lynis, pin the host keys, and guard `AllowUsers` edits with a backup, `sshd -t`, a reload and a proven second login. Re-running bootstrap overwrites the `*.sbom-audit.bak` backup, so it holds only the latest pre-bootstrap `sshd_config`; unbootstrap does not restore a backup, and an old `.bak` must not be copied back over a live config. The manual path (admin without passwordless sudo) changes nothing on the host, prints the commands and exits 2; it writes no bootstrap record, so also run `hosts check`.
- Patch: `hosts patch` runs the host's own unattended-upgrades once (its plan runs `apt-get update` and installs nothing; the saved plan is valid for 24 hours and `--include-docker` must match it, also for the command printed on the manual path), with Docker packages held back unless `--include-docker`, and installs exactly the confirmed list (strict Package-Whitelist, kernel and dependency autoremovals off for that run). An upgrade that needs a new package, typically a new kernel image, may be refused: install it by hand in a maintenance window. Maintainer scripts may restart their own services; sbom-audit restarts nothing, suppresses needrestart and never reboots. If a host's `apt.conf.d` sets a `Remove-*` option to `"true"`, patch stops with "not in force".
- Confirmation: `patch`, `bootstrap` and `unbootstrap` print a plan first; `--confirm <host>` must equal the host name and is refused under the scheduler marker and in headless assessments.
- Status: `status.json`, `STATUS.md` and the SessionStart line gain the open key `hosts_critical`, a line naming the hosts that failed the last check, and "hosts not checked since <date>" after 8 days; a machine without the audit key reports `skipped: no audit key on this machine` (exit code unchanged). Hosts reached only through ProxyJump or ProxyCommand are not supported.
- Skill: `/sbom-audit:hosts` (`check`, `accept`, `patch`, `bootstrap`, `unbootstrap`) with a `hosts` eval case; the evidence folder's `CLAUDE.md` and `README.md` templates (now v2) describe `HOSTS.md`, `hosts.json`, `hosts/` and `hosts-decisions.toml`.
- Upgrading from 1.0.0: nothing to migrate; `[hosts]` is optional and off by default. The first run after you enable `[hosts]` reports the existing host findings once as "new", because there is no earlier host state to compare with. The minor version bump triggers one full secrets rescan. `setup --schedule weekly` must be rerun to get the scheduler marker that makes the scheduled run refuse `--confirm`.

## 1.0.0 — 2026-11-08

First public-ready release: secrets scanning, a status screen, a weekly schedule, skills instead of
commands, and the evidence folder as its own private repository.

- Configuration: `sbom-audit.toml` gains `commit`/`push` for the evidence repository, `[discovery]` (GitHub owner, forks, clone `protocol`), `[schedule]` (`assess`, `assess_budget_usd`), `[secrets]` (`enabled`) and a per-project `github = "owner/repo"`; existing files keep working.
- Status: every run writes `status.json` and a one-screen `STATUS.md` (open class A/B secrets, KEV, CRITICAL/HIGH in production, EOL, deltas since the last run, scheduler state, `proposal waiting:`); `sbom-audit status` prints it and writes nothing.
- SessionStart hook: one severity line per session (failed or overdue run, missed schedule, class A secrets, new KEV, new CRITICAL/HIGH, unassessed findings) from `status.json`, under one second, no network.
- Evidence folder: `security/` gets its own `CLAUDE.md` and `README.md`, stale `sbom/<project>/` folders are pruned, each run commits the evidence (`commit = true`) and pushes only to a remote that is not public (`push = true`); an `unknown` visibility is reported, never assumed private.
- Pipeline: `run` ends with the status screen, refreshes the evidence docs, and reports hand edits it did not write instead of committing them; `status` is a new subcommand.
- Failure handling: a project whose git repository is broken or half-cloned becomes a failed source for each requested branch (exit 2, listed under Source status) instead of a crash, and any unexpected error before the audit still writes `STATUS.md` and `status.json` with a failed outcome.
- Scheduler: `setup --schedule weekly|off` installs a per-user launchd agent (macOS) or systemd user timer (Linux) for Saturday 03:00 through a wrapper that survives plugin updates; missed weeks show in the status line; a GitHub Actions template covers other platforms.
- Secrets rules: gitleaks rules for the providers the defaults miss (Supabase, RevenueCat, fal.ai, AssemblyAI, DataForSEO, Expo, Hetzner, Contabo, Inngest, database URLs, Docker) and three classes: A owns the platform, B costs money or data, C is public by design or a test value.
- Secrets engine: gitleaks 8.x (`brew install gitleaks`; betterleaks 1.x accepted); without an engine the scan says `skipped`, never "clean"; nothing leaves the machine, and the raw engine report is a `0600` file deleted after reading.
- Secrets findings: no value is ever stored or printed (fingerprint, file, line, a keyed `value_id`); each finding shows its branches, whether it is still in the working tree, and its age.
- Secrets scope: every local repository including ignored projects and worktrees (counted once), plus GitHub repositories listed through `[discovery]` and cloned read-only into the cache.
- Secrets store: `secrets.json`, decisions in `secrets-decisions.toml` (`open`, `rotated`, `false_positive`, `test_fixture`, `accepted`), incremental scans of new commits with a full rescan when the rules or the plugin minor change, and a decided finding that reappears in a new commit is reopened.
- Secrets scan: `sbom-audit secrets scan|resolve|report`, `SECRETS.md` with rotation hints per provider and "also uses" projects, an incremental scan in every `run`, and a test that checks no output, file, log or commit contains a planted value or any 5-character window of it.
- Pre-commit guard: `setup --install-guard` blocks new class A/B secrets at commit time in every local repository (an untracked `.git/hooks/pre-commit`; husky, lefthook and pre-commit framework repositories only after `--tracked-ok <name>`); `--uninstall-guard` removes it.
- GitHub: `setup` prints visibility, secret scanning and push protection per repository; `--enable-dependabot` now enables alerts only (`fixes` adds security updates) and changes nothing until it is rerun with `--yes` after the target list was shown; discovered but unaudited repositories are listed.
- Headless assessment: with `[schedule] assess = true` the weekly run asks Claude for an assessment in a read-only child (`SBOM_AUDIT_READ_ONLY=1`, a fixed tool list, a budget cap) that can only write `reports/<date>-assessment-proposal.md`; the proposal is never applied by itself.
- Skills replace commands: `/sbom-audit:setup`, `run`, `status`, `assess`, `lookup`, `incident`, `vex`, `secrets` and `schedule`, plus the `sbom-audit` knowledge skill; skills that write ask for one confirmation of the whole list first.
- Release: plugin icon, CI (tests on Python 3.11 and 3.12 with a checksum-verified gitleaks, a pinned Claude Code, SHA-pinned actions, `claude plugin validate --strict`, GitHub releases from `sbom-audit--v*` tags), five eval cases under `evals/`, `CONTRIBUTING.md`, README and docs page for the new features.
- Upgrading from 0.1.0: nothing to migrate; the existing `security/` folder and `sbom-audit.toml` are read as they are and every new key is optional. 0.1.0 wrote no `status.json`, so the first 1.0.0 run is a first run: it reports every open finding as new once, and the deltas are real from the second run on. The same happens when a `status.json` with another schema is found.

## 0.1.0 — 2026-11-06

First release, private repository.

- `setup`: preflight for `syft`, `osv-scanner`, `git`, `gh`; project discovery; `security/sbom-audit.toml`; `--init-git`; `--enable-dependabot` (asks first).
- `scan`: one CycloneDX SBOM per project and branch from `git archive` (no checkout, no writes into audited repositories); own readers for what Syft cannot catalogue: runtimes from `engines`, `requires-python`, `.python-version`, Dockerfiles, compose files, Supabase `config.toml`, `deno.json`; container images and floating tags; `package.json` without lockfile (unresolved); `deno.lock` packages served by esm.sh, unpkg, jsDelivr and Skypack.
- `audit`: osv-scanner against OSV.dev, CISA KEV marking, endoflife.date for runtimes and base images, registry drift for direct npm/PyPI/JSR dependencies, OpenVEX 0.2.0 statements applied with alias matching, `AUDIT.md`/`audit.json`/`INVENTORY.md`/`inventory.json`, dated copies under `reports/`, `log.md`; hand-written `## Assessment` sections carried over; fixed triage order; dev-only findings labelled; failed sources reported, never shown as clean.
- `run`: scan + audit with exit codes 0/1/2/3/4; `run`, `scan` and `audit` check for their tools before writing anything (exit 4 with the install line). endoflife.date and registry failures are reported in **Source status** and `log.md` and retried next run (only HTTP 404 is cached).
- `lookup`: who uses a package, glob, image or runtime, from the last inventory.
- `incident`: verdict per project, branch and version for a CVE/GHSA/PYSEC id or a package name (`hit`, `unknown` when that branch's last audit was incomplete, `present_not_affected`, `absent`); warns when the OSV record or the inventory is newer than the audit; exit 1 on a hit, 2 when it cannot answer; `--vex` records `component_not_present` for the absent projects.
- `vex add`: append an OpenVEX statement; `not_affected` requires a justification.
- Plugin: skill `sbom-audit`, commands `/sbom-audit:setup|run|lookup|incident|vex`, SessionStart hook (7-day staleness), marketplace `wuesteon-plugins`.
- `scripts/parity.py` to compare two audits.
