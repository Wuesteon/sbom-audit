# Changelog

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
