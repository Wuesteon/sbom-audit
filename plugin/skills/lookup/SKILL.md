---
name: lookup
description: Use when the user asks which projects use a package, image or runtime ("who uses lodash?") and in which version, from the last scan; takes package names, globs, images or runtimes.
argument-hint: "<package|image|runtime> [more…]"
allowed-tools: Read
---

Answer "who uses X" from `security/inventory.json` without rescanning. Names may be globs (`expo-*`), images (`nginx:alpine`) or runtimes (`nodejs`).

**Advisory questions go to the incident flow.** If the question contains an advisory id (`CVE-`, `GHSA-`, `PYSEC-`) or asks whether we are affected, do not answer from the inventory. Run

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" incident <id>
```

and follow the incident skill's flow: a verdict per project and branch; if OSV was unreachable or does not know the id, say so and say where the affected range came from; never pass `--vex` unasked.

Otherwise:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" lookup $ARGUMENTS
```

Exit 2 means there is no inventory yet: run `/sbom-audit:run` first. Exit 1 means no match: say so, do not guess from memory.

Show the table as is. For a `transitive` row the fix lands on the parent: find it with `npm ls <pkg>`, `pnpm why <pkg>` or `uv tree --package <pkg>` inside that project (read-only) when the user wants to remediate.
