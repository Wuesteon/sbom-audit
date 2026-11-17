---
name: cra
description: Check the EU Cyber Resilience Act readiness of the configured products and write starter documents (risk assessment, reporting procedure, disclosure policy) after the user confirms them.
argument-hint: "check | init <project> [--lang en|de]"
allowed-tools: Read
disable-model-invocation: true
---

A readiness overview for the products the user listed under `[cra.products]` in `security/sbom-audit.toml`, built from Regulation (EU) 2024/2847. It shows evidence, never a verdict: never say a product is "compliant", "certified" or "CRA-conform", and keep the caveat that this is evidence tooling, not legal advice. Each obligation gets one status: evidence present (naming the file), missing, stale, or the manufacturer's responsibility.

Route the arguments first. Arguments that start with `init` go to step 2, everything else (empty or `check`) to step 1. Never pass `$ARGUMENTS` to the CLI unrouted.

## 1. Check

If `[cra.products]` is missing, say that no product is configured and nothing is assumed to be in scope. Ask which projects are products placed on the EU market; the user edits the config (example: `[cra.products."<project>"]` with optional `name`, `branch`, `url`). Do not decide that for them. Then:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" cra check
```

It reads git objects of the configured branch (never the working tree) and writes `CRA.md` and `cra.json` into the evidence folder; it writes nothing into the product repositories. Read `security/CRA.md` and summarise per product: what is missing, what is stale, and which rows are the manufacturer's responsibility. A product with open KEV findings: point to its reporting procedure (`cra/<project>/art14-procedure.md`) and the Art. 14(2)(a) early warning within 24 hours; do not judge whether the finding is reportable, that is the manufacturer's decision. Exit 2 means no product is configured or the config is invalid.

## 2. Init (starter documents)

With `init <project>` from `$ARGUMENTS`, show the plan first; it writes nothing:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" cra init <project>
```

Show the printed plan and wait for the user to confirm it once. Existing files are kept, never overwritten. Files listed as "belongs in the product" (`SECURITY.md`, `security.txt`) are proposals under `cra/<project>/proposed-for-repo/`; the user copies them into the product repository. Never copy them yourself and never edit a product repository. Only after the user confirmed:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" cra init <project> --yes
```

Add `--lang de` or `--lang en` when the user asked for a language (default: `[report] language`). Exit 5 means read-only mode (`SBOM_AUDIT_READ_ONLY=1`): nothing was written; say so.

## 3. Filling in the risk assessment (optional, only on request)

The documents ask questions and leave blanks (`____`). You may walk the user through `cra/<project>/risk-assessment.md` one question at a time, Annex I Part I (2)(a) to (m), then Part II.

- Ask; never answer for them. Write only what the user said, in their words. A question they cannot answer stays `____`.
- Never write that the product is secure, meets a requirement or is compliant. Do not infer answers from the code, the SBOM or the audit; you may point to evidence ("AUDIT.md lists 2 open high findings") and let the user decide what to write.
- Show each edited section before saving it and save only after the user confirms it. Edit only files under `security/cra/`.
- Leave the first line (`sbom-audit cra starter`) in place; tell the user to delete it once every blank is filled in. Until then the document counts as missing. The `Last reviewed:` date is the user's to set.

Afterwards suggest `cra check` again to see the status change.
