---
name: sbom-audit
description: Use when asked which package, image or runtime versions repos use, whether a CVE or security incident in the news affects them, whether credentials leaked into git, when an audit is due (security/AUDIT.md older than a week), or before planning dependency upgrades
---

# sbom-audit

## Overview

Syft writes a CycloneDX SBOM per project and branch from the committed tree (`main`, `dev`; never the working tree). osv-scanner matches it against OSV.dev; the plugin adds CISA KEV (actively exploited), endoflife.date (runtimes and base images), registry "majors behind" and your OpenVEX decisions, then writes `security/AUDIT.md`, `INVENTORY.md`, `audit.json`, `inventory.json`, a dated copy under `reports/` and one line in `log.md`. You are the layer on top: interpret, sweep for incidents too fresh for the databases, turn findings into per-project actions.

**Never answer "are we affected by X" from memory.** The knowledge cutoff predates the question. Run the command, search the web.

## Run

```
/sbom-audit:setup                      once per folder; --init-git, --enable-dependabot, --schedule weekly, --install-guard on request
/sbom-audit:run                        scan + audit + secrets + commit, minutes; --only <project>, --no-fetch
/sbom-audit:status                     STATUS.md from the last run; writes nothing
/sbom-audit:assess                     the assessment below as one workflow; verified decisions after one confirmation
/sbom-audit:lookup astro 'expo-*' caddy   who uses what, from the last scan, in a second
/sbom-audit:incident CVE-2026-…        verdict per project@branch: hit / unknown / present_not_affected / absent
/sbom-audit:vex <project> <id> <status>   record a decision; applied by every run
/sbom-audit:secrets scan|report|resolve   leaked credentials in git history; decisions per fingerprint
/sbom-audit:schedule weekly|off        per-user timer (launchd / systemd); one machine writes
```

Direct: `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" <command> --help`. If `AUDIT.md` was generated today, reuse it instead of re-running.

**Status.** The session-start line names the most urgent condition (failed run, stale run, open class A secrets, new KEV, new production CRITICAL/HIGH, unassessed findings) and offers `/sbom-audit:assess` when something needs assessing. `STATUS.md` holds the counts, deltas, source failures, commit/push state, scheduler and `last assessment`; `proposal waiting:` with a path (not `none`) is an unapplied headless draft: review it, apply it with an interactive `/sbom-audit:assess`; it stays listed until the next run after an `## Assessment YYYY-MM-DD` dated on or after the proposal is in `AUDIT.md`.

## Then: the assessment

1. Read `security/AUDIT.md`. **Source status** first: a failed source means that section is empty, not clean.
2. **Incident sweep.** Web search (extended) for advisories from the last 30 days for every runtime and framework in the `INVENTORY.md` overview, plus anything the user named. For each: affected versions, then `/sbom-audit:incident <id>` or `lookup <package>`; record hit or no hit with the version as evidence. For a transitive hit name the parent (`npm ls`, `pnpm why`, `uv tree --package`, read-only) so the fix lands on the right manifest.
3. **Triage order:** open class A secrets → KEV → CRITICAL/HIGH in production projects (`production = true` in `sbom-audit.toml`) and open class B secrets → EOL runtimes and base images → floating image tags → dev-only tooling. Mark dev-only (devDependencies, build stages) explicitly.
4. **Write it down.** Append `## Assessment YYYY-MM-DD` to `security/AUDIT.md`: incident-sweep table, prioritized actions per project (manifest, package, current → target). Append one line to `security/log.md`. Draft VEX statements and secrets decisions as one list; record them (`vex add`, `secrets resolve`) only after the user confirms it.
5. **The plugin fixes nothing.** `security/issues.json` (readable: `ISSUES.md`) is the work list for whoever does: every open issue with id, priority, place and fix target; `issues --project <p> --max-priority 3 --json` selects. Fix per project, per PR, with that project's tests. No `npm audit fix --force`, no bulk upgrades.

## Secrets

`secrets scan` runs gitleaks over every repository's history, locally; nothing leaves the machine and no output contains a secret value. Class A owns the platform (service-role keys, live payment keys, PATs, private keys), class B costs money or data (LLM and SaaS API keys), class C is public by design or a test value. An open class A ranks above KEV in triage.

Rotation sequence: rotate at the provider → redeploy → verify by hand that the old value fails → `secrets resolve <fingerprint> rotated` → decide about history (rewriting it does not un-leak a pushed secret). Decisions live in `secrets-decisions.toml`, never in prose only. The pre-commit guard (`setup --install-guard`, per machine) blocks new class A/B commits; `--no-verify` skips it, and that is a choice the log must show.

## CRA

The Cyber Resilience Act's Art. 14 reporting obligations apply since 2026-09-11, and the reporting runbook arrives in a later release. Evidence tooling, not legal advice.

## Common mistakes

| Mistake | Why it matters |
|---|---|
| Auditing only the checked-out branch | HEAD is often a feature branch; `main` and `dev` ship. |
| `npm audit` per project | Skips Python, Deno, Docker; leaves nothing persistent. |
| Trusting `uv.lock` when the Dockerfile installs `requirements.txt` with `>=` | Deployed versions are unknown; AUDIT.md's Notes flag these. |
| Accepting floating tags (`caddy:2-alpine`, `qdrant:latest`) | Every rebuild silently changes the runtime. |
| Looking only at packages | Runtime bugs and EOL base images are findings too. |
| Reporting a transitive devDependency as a production risk | Fix it, but say what it is. |
| Trusting `present_not_affected` after the OSV record changed | Re-run; the verdict is as fresh as the last osv-scanner run. |
| Reading `unknown` as "no hit" | That branch's last audit was incomplete; re-run before answering. |

Dependabot alerts are the continuous complement: `/sbom-audit:setup --enable-dependabot`.
