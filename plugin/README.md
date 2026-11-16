# sbom-audit (plugin folder)

This folder is the installable Claude Code plugin: skills, the stdlib Python CLI, gitleaks rules and
templates. Documentation, tests and evals live in the repository root:
<https://github.com/Wuesteon/sbom-audit>.

- Start with `/sbom-audit:setup`, then `/sbom-audit:run`.
- The plugin installs no hooks and pre-approves only reading files; Claude Code asks before each
  command. `/sbom-audit:settings autonomous` and `/sbom-audit:settings hook on` are opt-ins.
- License: MIT (see `LICENSE`).
