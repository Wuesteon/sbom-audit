---
name: settings
description: Switch sbom-audit between ask-first and autonomous mode, and turn the session status line on or off, in the user's Claude Code settings.
argument-hint: "[autonomous|ask] [hook on|off]"
allowed-tools: Read
disable-model-invocation: true
---

sbom-audit has two modes. **Ask-first** (the default): Claude Code asks before every command the plugin runs. **Autonomous**: the plugin's own CLI runs without asking for subcommands that only read or write the local `security/` folder (`status`, `lookup`, `incident`, `code`, `issues`, `run`, `scan`, `audit`, `vex add`, `secrets`, `hosts check`, `hosts accept`), plus WebSearch and WebFetch on the advisory sources. Autonomous mode never covers `setup` (it can change GitHub settings), `hosts patch|bootstrap|unbootstrap` (they change servers), `gh`, `git` or any other command; those always ask. The optional **session hook** prints one status line from `security/status.json` when a session starts (no network, exit 0 always).

Arguments: `$ARGUMENTS`.

1. Show the current state first:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" settings
```

2. Work out what the user asked for: `autonomous` → `--autonomy on`, `ask` → `--autonomy off`, `hook on|off` → `--session-hook on|off`. With no arguments, explain the two modes and the hook in three short lines and ask which they want; change nothing without an answer.
3. Both opt-ins write to the user's `~/.claude/settings.json` (a backup is kept at `~/.claude/settings.json.sbom-audit.bak`; `off` removes exactly what `on` added). Before running, tell the user that file will change and what will be allowed, and wait for a clear yes. Then run, for example:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" settings --autonomy on --session-hook on
```

4. Show the printed lines. New rules and hooks apply to the next Claude Code session. After a plugin update, `run` and `setup` point the recorded rules at the new plugin path on their own; nothing new is added.
5. Exit 2 means `settings.json` could not be read as JSON or has an unexpected shape: show the message; never edit the file by hand on the user's behalf.
