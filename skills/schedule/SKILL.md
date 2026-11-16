---
name: schedule
description: Schedule the weekly sbom-audit run on this machine (launchd on macOS, a systemd user timer on Linux) or remove it.
argument-hint: "weekly|off"
allowed-tools: Bash, Read
disable-model-invocation: true
---

Install or remove the per-user timer that runs the pipeline every Saturday 03:00 local time. `$ARGUMENTS` is `weekly` or `off`; ask if it is neither.

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" setup --schedule $ARGUMENTS
```

This reruns setup (idempotent: preflight, config and status refresh, `GitHub status:` reads, possibly a setup commit); show the user only the `Scheduler:` block unless something else changed.

- macOS: a launchd agent in `~/Library/LaunchAgents/`. Linux: a systemd user service and timer in `~/.config/systemd/user/`. Other platforms print `scheduling not supported on …` with a GitHub Actions template instead.
- Show the `Scheduler:` lines as is: the wrapper, the timer files and `scheduler: installed, weekly Saturday 03:00 local, next fire …`, or `scheduler install failed: …` (tell the user; do not retry on your own).
- **One writer.** Only one machine may run the schedule and push to the evidence repository. If setup prints `warning: the last run happened on <host>, this timer runs on <host>`, ask the user which machine should audit and run `off` on the other.
- The weekly run is the same CLI `run`, with no model involved, unless `[schedule] assess = true` in `sbom-audit.toml`: then it also writes a headless assessment proposal (budget `assess_budget_usd`, default 5.0) that `STATUS.md` lists as `proposal waiting:`. It is never applied automatically; review it and apply it with `/sbom-audit:assess`.
- A missed week shows in the status line as `scheduler did not run since …` (the machine was asleep or off).
