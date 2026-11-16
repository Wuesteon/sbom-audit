---
name: secrets
description: Scan every repository's git history for leaked credentials with gitleaks, print SECRETS.md, and record confirmed decisions per finding.
argument-hint: "scan [--full] | resolve <fingerprint> <status> <note> | report"
allowed-tools: Bash, Read
disable-model-invocation: true
---

Find credentials that ever landed in git history, rank them by blast radius, and keep the decisions in `security/secrets-decisions.toml`. Nothing leaves the machine: no verification calls, and no output ever contains a secret value. Never print, echo or copy a secret value yourself either; refer to findings by fingerprint, file and line.

**Route the arguments (`$ARGUMENTS`) first:**

- They start with `resolve`: do not call the CLI with them. They are a draft of one decision for the **Resolve** flow below, which confirms before it writes.
- No arguments, or `report`: `secrets report`.
- They start with `scan`: `secrets scan` with the rest of them (`scan --full` → `secrets scan --full`).
- Anything else (for example `--full`): `secrets scan $ARGUMENTS`.

## Scan and report

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" secrets report
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" secrets scan [--root R] [--full]
```

- `secrets scan [--root R] [--full]`: scans new commits since the last scan (`--full`: all history), writes `secrets.json` and `SECRETS.md`. `run` already does the incremental scan.
- `secrets report`: prints `SECRETS.md` from `secrets.json`; writes nothing.

Exit 0 = nothing open in class A or B, 1 = open class A or B, 2 = failed, 4 = no engine (`brew install gitleaks`; the scan is `skipped`, never "clean"), 5 = read-only mode. Classes: A owns the platform (rotate before anything else, ranks above KEV), B costs money or data, C is public by design or a test value.

## Resolve: confirm one list, then write

Claude never records a secrets decision on its own.

1. Read `SECRETS.md`. For each open finding, draft a decision: fingerprint, status (`open|rotated|false_positive|test_fixture|accepted`), and a note saying why (what was rotated, why it is a false positive or accepted). Use `rotated` only when the user says the credential was rotated.
2. Show the whole list and wait for the user to confirm it once. Edits are fine; show the edited list again.
3. After the confirmation, call the CLI once per entry, as `secrets resolve <fingerprint> <status> "<note>" [--rotated-on YYYY-MM-DD]`:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" secrets resolve <fingerprint> <status> "<note>"
```

Rotation sequence for a real leak: rotate the credential at the provider → redeploy everything that uses it → verify by hand that the old value no longer works → `secrets resolve <fingerprint> rotated "<note>"` → then decide about history (rewriting history does not un-leak a pushed secret; rotation is the fix). Decisions live in `secrets-decisions.toml`, never in prose only.

## Pre-commit guard

`/sbom-audit:setup --install-guard` installs a guard that blocks new class A/B secrets at commit time and prints `BLOCKED <class> <rule_id> <file>:<line>`. It is per machine: run it on every machine that commits. `setup --uninstall-guard` removes it. `git commit --no-verify` skips it; that is a choice the log must show.
