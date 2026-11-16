---
name: setup
description: Set up sbom-audit for this folder by checking tools, discovering repos and writing security/sbom-audit.toml, with optional git, Dependabot, weekly schedule and pre-commit guard.
argument-hint: "[--init-git] [--enable-dependabot [alerts|fixes]] [--schedule weekly|off] [--install-guard|--uninstall-guard]"
allowed-tools: Bash, Read
disable-model-invocation: true
---

Set up sbom-audit for the current folder (a folder of git repos = portfolio mode, one repo = single mode). Setup is idempotent: rerunning it keeps the config and refreshes `security/CLAUDE.md`, `README.md`, `.gitignore` and `status.json`.

1. Four flags change things outside `security/`. If the user did not pass them, ask **once** whether they want any of them before running; never add them on your own:
   - `--init-git`: makes `security/` its own git repository (portfolio mode only).
   - `--enable-dependabot [alerts|fixes]`: Dependabot alerts (bare flag) or alerts + security updates (`fixes`) on every GitHub repository, through `gh api`.
   - `--schedule weekly`: a per-user timer that runs `run` every Saturday 03:00 (see `/sbom-audit:schedule`).
   - `--install-guard`: the pre-commit secrets guard in every local repository (untracked `.git/hooks/pre-commit`).
2. Run:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" setup $ARGUMENTS
```

3. Exit 4 means a tool is missing: show the `brew install` line and stop.
4. **Dependabot needs a second, confirmed call.** Without `--yes` setup changes nothing on GitHub; it prints `Dependabot alerts will be enabled on:` (or `Dependabot alerts + security updates will be enabled on:`), one `owner/repo` per line, then `run again with --yes to enable (no changes made)`. Show that list to the user and ask for one confirmation of the whole list. Only after they confirm, rerun with the same flags plus `--yes`. Never pass `--yes` unasked. Each repo then prints `<slug>: alerts: on` or `alerts: failed (<reason>)`; tell the user about every `failed (…)` line and do not retry on your own. `(no GitHub repositories)` or `discovery: skipped (<reason>)` means there was nothing to enable.
5. **GitHub status.** Show the `GitHub status:` block as is (visibility, secret scanning, push protection per repo). Private repositories need GitHub Advanced Security (paid) for secret scanning; the plugin does not enable it.
6. **Pre-commit guard.** The `Pre-commit guard:` block has one line per repo (`installed`, `unchanged`, `updated`, `needs confirmation (<husky|lefthook|hookspath|pre-commit-framework>)`, `not installed: … both exist (merge them by hand, then rerun)`, `global core.hooksPath <path>: install by hand`, `failed (<ExcName>)`). Repos that commit through husky, lefthook or the pre-commit framework need a line in a **tracked** file; setup prints `Tracked hook files (confirm per repo, then rerun with --tracked-ok <name>):` with the exact line or YAML block per repo. Show each, ask the user per repo, and rerun with `--install-guard --tracked-ok <name>…` only for the repos they confirmed. Never pass `--tracked-ok` unasked. The guard is per machine: tell the user to run `setup --install-guard` on every machine that commits.
7. Show the discovered projects and `security/sbom-audit.toml`. Ask which projects run in production (servers, bots holding keys, anything on a VPS) and set `production = true` for them; add folders that should never be audited to `ignore_projects`. Discovered-but-not-audited GitHub repos (with `[discovery]` set) are listed under `Discovered but not audited`; add them to `[projects]` only on request.
8. Next step is `/sbom-audit:run`.
