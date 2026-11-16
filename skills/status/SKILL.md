---
name: status
description: Print STATUS.md, the one-screen summary of the last sbom-audit run, without running or writing anything.
argument-hint: "[]"
allowed-tools: Bash, Read
---

Show where the evidence repository stands, from the last run. This reads `status.json` and writes nothing. It takes no arguments: ignore `$ARGUMENTS` and run exactly:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" status
```

Print the output as is. Then read its first line, the status line (`🛡️ sbom-audit <version>: …`), most urgent condition first:

- `no status.json yet: run /sbom-audit:setup, then /sbom-audit:run` → nothing has run here; offer `/sbom-audit:setup`.
- `last run FAILED (exit …)` → show the failed sources from `STATUS.md`; a failed source is empty, not clean. Suggest `/sbom-audit:run` after the cause is fixed.
- `last run N days ago` or `scheduler did not run since …` → the evidence is stale; suggest `/sbom-audit:run` (and `/sbom-audit:schedule` if no timer is installed).
- `N class A, M B secrets open` → point at `security/SECRETS.md` and `/sbom-audit:secrets`; class A is rotated before anything else.
- `N new KEV since last run` or `N new CRITICAL/HIGH in production since last run`, or `findings not assessed yet; run /sbom-audit:assess` → offer `/sbom-audit:assess`.
- `nothing new since <date>` → say so; nothing to do.

`proposal waiting:` with a path (not `none`) in `STATUS.md` means the weekly headless assessment left a proposal it did not apply. Tell the user to open that file, review it, then run `/sbom-audit:assess` interactively to apply it; it stays listed until the next run after an `## Assessment YYYY-MM-DD` dated on or after the proposal is in `AUDIT.md`.

Do not start a run or an assessment yourself; offer them.
