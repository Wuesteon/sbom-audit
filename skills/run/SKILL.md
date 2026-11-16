---
name: run
description: Run the full pipeline (SBOMs, vulnerability audit against OSV, CISA KEV and endoflife.date, incremental secrets scan, reports, evidence commit), then print STATUS.md and assess the result.
argument-hint: "[--only <project>…] [--no-fetch] [--root <folder>]"
allowed-tools: Bash, Read, Grep, WebSearch, WebFetch, Agent
disable-model-invocation: true
---

Build the SBOMs, the vulnerability audit and the secrets scan, then do the assessment the sbom-audit skill describes.

1. Start the run **in the background** (Bash with `run_in_background`; it takes minutes for a large portfolio). Wait for the completion notice; do not poll.

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" run $ARGUMENTS
```

Flags: `--only <project>…` limits the scan (the inventory and report then cover only those projects; run without it for the portfolio), `--no-fetch` skips `git fetch`, `--root <folder>` overrides the project folder. Exit 0 = clean, 1 = findings, 2 = a source failed (that section is empty, not clean), 3 = a broken VEX file, 4 = tool missing, 5 = read-only mode (`SBOM_AUDIT_READ_ONLY=1`, nothing written).

2. Print the status screen and show it to the user as is:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" status
```

3. Read `security/AUDIT.md`, **Source status** first, and `security/SECRETS.md` when the status lists open class A or B secrets.
4. Assess, as `/sbom-audit:assess` describes: incident sweep for the runtimes and frameworks in the `INVENTORY.md` overview; triage open class A secrets → KEV → production CRITICAL/HIGH and open class B secrets → EOL → floating tags → dev-only; append `## Assessment YYYY-MM-DD` to `AUDIT.md` and one line to `security/log.md`; draft VEX statements and secrets decisions as one list, have every decision that closes a finding on a judgement checked by a fresh verifier agent as step 6 there describes, and write them only after the user confirms the list.
5. Report hits with the version as evidence; mark dev-only findings as such. Remediation is per project, per PR. The plugin fixes nothing: the run leaves `security/issues.json` (readable: `ISSUES.md`), every open issue with its place and fix target, for whoever fixes. Point the user to it.

With `[schedule] assess = true` in `sbom-audit.toml`, the run adds a headless proposal step: it writes `reports/<date>-assessment-proposal.md` and `STATUS.md` shows `proposal waiting: <path>`. The run never applies that proposal; open it, review it, and apply it with `/sbom-audit:assess`.
