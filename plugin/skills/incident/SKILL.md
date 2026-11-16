---
name: incident
description: Use when the user asks whether a CVE, GHSA or PYSEC id or a vulnerability in the news affects them ("are we affected by CVE-…?", "does GHSA-… hit us?"); checks the advisory against every project and branch and gives a verdict (hit, not affected, unknown) per project.
argument-hint: "<CVE|GHSA|package> [--vex]"
allowed-tools: Read, Grep, Glob
---

Never answer "are we affected" from memory; the knowledge cutoff predates the incident.

1. Run with the id (`CVE-…`, `GHSA-…`, `PYSEC-…`) or a package name, **without** `--vex` (strip it from the arguments for this first call; it writes):

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" incident $ARGUMENTS
```

Exit 1 = hits, 0 = no hits, 2 = no answer: OSV does not know the id, the record names no packages, there is no inventory/audit yet, or a branch's last audit was incomplete (`unknown` verdicts) and nothing hit.

2. If OSV does not know the id, or the user only has a news headline: web search (extended) for the advisory, note the affected packages and version ranges, then `/sbom-audit:lookup <package>` and compare versions yourself. Say which source the ranges came from.
3. Present the verdict table. `hit` = the advisory is in that branch's osv-scanner findings; `unknown` = that branch's last audit was incomplete (osv-scanner failed on it, or its checkout/readers reported errors), so a missing finding proves nothing: re-run and repeat; `present_not_affected` = the package is there but outside the affected range per the last audit (heed the warning when the OSV record or the inventory is newer than the audit: re-run first); `absent` = not in the SBOM.
4. For hits: fixed version, manifest, and whether it is dev-only; remediation per project, per PR.
5. Offer `--vex` to record `not_affected` / `component_not_present` for the projects without the component. Show the list of projects it would write, wait for the user to confirm, and only then rerun the same call with `--vex`. Never pass `--vex` unasked.
