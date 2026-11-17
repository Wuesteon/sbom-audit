# AGENTS.md

Instructions for any coding agent (Codex, Gemini CLI, Cursor, Aider, Claude Code without the plugin, …)
that drives sbom-audit directly. The Claude Code skills in `plugin/skills/` are thin wrappers around one
CLI; this file gives you the same commands and the same rules.

## The CLI

```bash
CLI=<this repository>/plugin/scripts/sbom_audit_cli.py   # Python 3.11+, standard library only
python3 $CLI --help
python3 $CLI <command> --help
```

Run it from the folder that holds the user's repositories, or pass `--out <path>/security`. It writes only
into `security/` unless a command below says otherwise. Required tools: `git`, `syft`, `osv-scanner`;
`gitleaks` for the secrets scan (without it the scan reports `skipped`, never clean); `gh` for GitHub reads.

| Task | Command | Writes |
|---|---|---|
| Set up a folder, once | `setup` (`--init-git` makes `security/` its own git repository) | `security/sbom-audit.toml`, `security/` skeleton |
| Full run | `run` (`--only <project>`, `--no-fetch`); takes minutes, run it in the background | reports in `security/`, a commit there when `commit = true` |
| Summary of the last run | `status` | nothing |
| Open work list | `issues --project <p> --max-priority 3 --json` | nothing with a filter or `--json` |
| Who uses X | `lookup <name>` (globs `'expo-*'`, images `nginx:alpine`, runtimes `nodejs`) | nothing |
| Are we affected | `incident <CVE-…\|GHSA-…\|PYSEC-…>` | nothing (`--vex` writes, see rules) |
| Record a decision | `vex add <project> <vuln-id> <status> [--justification …] --impact "…"` | `security/vex/<project>.openvex.json` |
| Secrets | `secrets report`; `secrets resolve <fingerprint> <status> "<note>"` | `resolve` writes `secrets-decisions.toml` |
| Read audited code | `code grep\|show\|files <project> <branch> …` | nothing |
| CRA readiness per product | `cra check` (only products under `[cra.products]`; also part of `run`) | `security/CRA.md`, `security/cra.json` |
| CRA starter documents | `cra init <project>` (plan), then `cra init <project> --yes` after confirmation | new files in `security/cra/<project>/`, never overwrites |
| Assessment draft by a model | `assess draft --dry-run`, then `assess draft` (needs `[assess]`, see below) | `reports/<date>-assessment-proposal.md` |

Exit codes: `run` 0 clean, 1 findings, 2 a source failed (that section is empty, not clean), 3 malformed
VEX file, 4 missing tool; `lookup` 1 no match; `incident` 1 hit, 2 cannot answer; 5 read-only mode
(`SBOM_AUDIT_READ_ONLY=1` makes every writing command exit 5 without writing).

Not for agents without the user present: `setup --enable-dependabot … --yes`, `setup --schedule`,
`setup --install-guard`, `hosts bootstrap|unbootstrap|patch --confirm <host>` and `settings`. They change
GitHub settings, the user's machine or servers; run them only on the user's explicit request.

## Rules

1. **Never answer "are we affected" from memory.** Run `incident` (or `lookup`) and say how fresh the
   data is (the date in `STATUS.md`). `unknown` means that branch's last audit was incomplete: re-run,
   do not read it as "no hit".
2. **Read Source status first.** A failed source in `AUDIT.md` means its section is empty, not clean.
3. **Show before writing, confirm once.** Before any command that writes a decision (`vex add`,
   `incident --vex`, `secrets resolve`, `hosts accept`), show the user the full list of what you will
   record and wait for one explicit confirmation. Never record a decision the user has not seen.
4. **Judgement decisions need evidence.** A `not_affected` with `vulnerable_code_not_present`,
   `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary` or
   `inline_mitigations_already_exist`, and a secret marked `false_positive`, `test_fixture` or
   `accepted`, must name the code you checked (`code grep`, `code show` on the audited branch, not the
   working tree). If you cannot establish it, record `under_investigation` instead. Only the person who
   rotated a credential may mark it `rotated`.
5. **Triage order:** open class A secrets, then KEV, then CRITICAL/HIGH in production projects and open
   class B secrets, then end-of-life runtimes and base images, then floating image tags, then dev-only
   tooling. Mark dev-only findings as such; do not inflate counts.
6. **Never fix code as part of the audit.** sbom-audit and the agent driving it report; they do not edit
   the audited repositories, open pull requests or push. `issues.json` is the work list for whoever fixes:
   per project, per pull request, with that project's tests. No `npm audit fix --force`, no bulk upgrades.
7. **Never print a secret value.** Refer to secrets by fingerprint, file and line. Never read or show
   anything under `security/.cache/` (it holds the fingerprint key).
8. **Keep `security/` private.** It lists open vulnerabilities; the CLI refuses to push it to a public
   remote. Do not copy its contents into issues, chats or services the user has not chosen.

## The assessment

After a run, write the assessment the way the `/sbom-audit:assess` skill does
(`plugin/skills/assess/SKILL.md` is the full workflow):

1. `status`, then `AUDIT.md` (Source status first) and the `INVENTORY.md` overview.
2. Incident sweep: search for advisories from the last 30 days for every runtime and framework in the
   overview; check each with `incident <id>`.
3. Triage in the order above; append `## Assessment YYYY-MM-DD` to `security/AUDIT.md` with the sweep
   table and actions per project (manifest, package, current → target) and one line to `security/log.md`.
4. Draft the VEX statements and secrets decisions as one list, check each (rule 4), show it, and record
   only what the user confirms (rule 3).

An agent without web access, or a scheduled job, can instead ask a model for a draft:
`assess draft` sends report excerpts (never code, SBOMs or secret values) to the OpenAI-compatible
endpoint in `[assess]` and writes `reports/<date>-assessment-proposal.md`. It records nothing; every
decision in it is `unverified` and goes through steps 2 to 4 before anything is recorded. Configuration,
providers and exactly what is sent: [docs/reference.md](docs/reference.md#assessment-drafts-without-claude-code-assess-draft).

## CRA readiness

The same flow as the `/sbom-audit:cra` skill (`plugin/skills/cra/SKILL.md`). It is a readiness overview
from Regulation (EU) 2024/2847: evidence present, missing, stale, or the manufacturer's responsibility.
Never call a product "compliant", "certified" or "CRA-conform"; this is evidence tooling, not legal advice.

1. Only projects the user listed under `[cra.products]` are covered. Do not decide which projects are
   products; ask.
2. `cra check`, then read `security/CRA.md` and summarise what is missing or stale per product. An open KEV
   finding in a product points to `cra/<project>/art14-procedure.md`; whether it is reportable is the
   manufacturer's decision.
3. `cra init <project>` prints the plan; show it, wait for one confirmation, then run it with `--yes`.
   `SECURITY.md` and `security.txt` land in `cra/<project>/proposed-for-repo/`: the user copies them into
   the product repository (rule 6).
4. Filling in `risk-assessment.md`: ask the questions one at a time and write only the user's answers.
   An unanswered question stays `____`; never infer answers from the code or the audit, never write that a
   requirement is met. Show each section before saving it. The `sbom-audit cra starter` first line stays
   until the user removes it; until then the document counts as missing.

## Working on this repository

Tests: `python3 -m unittest discover -s tests -t .` (no network). Layout, the redaction rule and the
release steps are in [CONTRIBUTING.md](CONTRIBUTING.md).
