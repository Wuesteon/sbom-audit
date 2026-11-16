---
name: vex
description: Record an OpenVEX decision (not_affected, affected, fixed, under_investigation) for a project after the user confirms it.
argument-hint: "<project> <vuln-id> <status> [--justification …] [--impact …] [--subcomponent <purl>]"
allowed-tools: Read
disable-model-invocation: true
---

Record why a finding does or does not apply, so the next audit stops repeating it. Statements live in `security/vex/<project>.openvex.json` (OpenVEX 0.2.0) and are applied by every `run`. Claude never writes a statement the user has not confirmed.

1. Map the user's reason to the OpenVEX justification before writing anything:

| Reason given | status / justification |
|---|---|
| the package is not in our SBOM | `not_affected` / `component_not_present` |
| the vulnerable function or module is not in the package build we ship | `not_affected` / `vulnerable_code_not_present` |
| we never call the vulnerable code path | `not_affected` / `vulnerable_code_not_in_execute_path` |
| an attacker cannot reach the input | `not_affected` / `vulnerable_code_cannot_be_controlled_by_adversary` |
| a mitigation (WAF, config, sandbox) already blocks it | `not_affected` / `inline_mitigations_already_exist` |
| we are affected and will fix it | `affected` (add `--impact` with the plan) |
| already upgraded past the fix | `fixed` |
| not sure yet | `under_investigation` |

2. Draft the statements as one list (per entry: project, vulnerability id, status, justification, impact text, subcomponent purl), show it, and wait for the user to confirm the list once. Edits are fine; show the edited list again. Nothing is written before that confirmation.
3. Then call the CLI once per confirmed entry (`$ARGUMENTS` when the user gave exactly one statement and confirmed it as shown; otherwise each entry's own values):

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" vex add $ARGUMENTS
```

(`vex add <project> <vuln-id> <status> [--justification …] [--impact …] [--subcomponent pkg:npm/name] [--author …]`). Exit 5 means read-only mode (`SBOM_AUDIT_READ_ONLY=1`): nothing was written; say so. Then suggest `/sbom-audit:run` (or `audit`) to see the finding move to the suppressed section.
