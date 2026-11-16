---
name: hosts
description: Check the configured servers without installing anything, record accepted host findings, and patch, bootstrap or unbootstrap one named host after you confirm its plan.
argument-hint: "[check|accept|patch|bootstrap|unbootstrap] [host]"
allowed-tools: Bash, Read
disable-model-invocation: true
---

Audit the servers listed under `[hosts.servers]` in `security/sbom-audit.toml`: patch state, open updates against OSV and CISA KEV, the OS release's own end of life (`os:eol`, critical once free security support has ended; fixed only by a release upgrade, never accepted), a state fingerprint against the accepted baseline, SSH logins, and a Lynis hardening index. `check` installs and changes nothing on the servers (Lynis writes only its own log files in `/var/log`). `accept`, `patch`, `bootstrap` and `unbootstrap` write, so each one waits for the user's confirmation as described below. Never paste `authorized_keys` comments, sudoers content or IP addresses into issues, pull requests or chat messages meant for others; refer to hosts by their configured name and to keys by SHA256 fingerprint.

**Route the arguments (`$ARGUMENTS`) first.** Never forward them as one string to the CLI; call exactly the subcommand named here.

- No arguments, or they start with `check`: **Check** (the rest are host names).
- They start with `accept`: do not call the CLI with them. They are a draft for the **Accept** flow, which confirms before it writes.
- They start with `patch`, `bootstrap` or `unbootstrap`: the **Admin actions** flow, for the one host named after the subcommand. If no host is named, ask which one; do not guess.
- Anything else: ask what the user wants (check, accept, patch, bootstrap or unbootstrap).

## Check

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" hosts check [host ...]
```

Run it freely: it collects over SSH with the audit login (a forced command that can run the collector and nothing else), installs and changes nothing on the servers apart from Lynis's own log files in `/var/log`, and takes several minutes per host (Lynis). Then read `security/HOSTS.md` and show the user the critical section of each host first (critical, KEV, patch automation, logins, fingerprint changes), then a short summary of the rest.

Exit 0 = clean, or skipped because there is no audit key on this machine (never a failure); 1 = a host has an open critical finding; 2 = a host failed (unreachable host or failed collector counts as a failed source, never as clean) or the configuration is wrong; 5 = read-only mode. A host whose collector is outdated, or that was never bootstrapped, is fixed with `bootstrap`, not by hand.

## Accept: confirm one list, then write

Claude never records a host decision on its own.

1. Read `HOSTS.md`. For each finding the user wants to accept, draft one entry: host, change-id (the id printed in `HOSTS.md`), and a note saying why the state is expected. A KEV finding needs `--review-by YYYY-MM-DD`, at most 30 days ahead; propose a date and say why.
2. Show the whole list and wait for the user to confirm it once. Edits are fine; show the edited list again.
3. After the confirmation, call the CLI once per entry:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" hosts accept <host> <change-id> "<note>" [--review-by YYYY-MM-DD]
```

Accepting moves the state into the baseline (for a KEV finding: until the `--review-by` date; login and origin decisions are only recorded and do not expire). Do not accept a login from an unknown key, a new `authorized_keys` entry or a new listening port just to make the report quiet: ask whether the user recognises it.

## Admin actions: patch, bootstrap, unbootstrap

These change a server. Claude does not run any of them with `--confirm` until **both** hold: the user has named that host in this conversation, and the user has confirmed the plan shown for it. One host at a time; a confirmation for `box-a` is never a confirmation for `web-1`.

1. **Plan.** Run the subcommand without `--confirm`. It prints the plan and exits; nothing is installed, restarted or rebooted (the `patch` plan does run `apt-get update` on the host to refresh its package lists):

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" hosts patch <host> [--include-docker]
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" hosts bootstrap <host>
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" hosts unbootstrap <host>
```

2. **Show it.** Show the plan as printed: for `patch` the package list, whether `reboot-required` is already pending (the plan does not predict whether the upgrade will need a reboot: never say it does; that state is reported only after the upgrade has run), and which Docker packages are held back (`--include-docker` lifts the hold; add it only when the user asks for it); for `bootstrap` the host key fingerprint and the steps, including any `AllowUsers` edit; for `unbootstrap` what is removed. Then ask: "Run this on `<host>`? Reply with the host name to confirm."
3. **Confirm.** Only a reply that names the host and agrees counts. If the user names a different host, or only says "yes" while several hosts were discussed, ask again. Silence, an earlier "go ahead" for another action, or the scheduler or a headless run never counts.
4. **Apply.** Rerun the same command with `--confirm <host>` (the CLI refuses a value that differs from the host name, and refuses `--confirm` under the scheduler marker `SBOM_AUDIT_SCHEDULED=1`). For `patch`, the saved plan is valid for 24 hours, `--include-docker` must be given exactly as it was in the plan, and the package list is checked again. If the plan is older, the flag differs or the list changed, the CLI refuses and says why: run the plan again, show it, and get a new confirmation instead of working around it:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" hosts patch <host> --confirm <host> [--include-docker]
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" hosts bootstrap <host> --confirm <host>
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/sbom_audit_cli.py" hosts unbootstrap <host> --confirm <host>
```

5. **Report.** Say what happened in the CLI's words. After `bootstrap`, run `hosts check <host>` and show the first baseline for review (then **Accept**). After `patch`, report `reboot-required` and the services on old libraries; never reboot, restart services or touch containers yourself, and never run `docker compose down`. If the CLI says "state unknown", stop and tell the user what it says to check.

Things the plan or the result can say, and what to do:

- **Admin login without root or passwordless sudo.** The CLI changes nothing on the host, prints the commands to run by hand and exits 2 (`bootstrap` with `--confirm` has by then pinned the host keys and created the audit key on this machine). Exit 2 here is expected, not a failure: say so. Show the commands and tell the user to run them with `!` in Claude Code or in their own terminal (sudo may ask for a password); do not try another way to escalate. The CLI's own hint is to run the same `--confirm` command again afterwards: for `bootstrap` that verifies the audit login, for `unbootstrap` it removes the pinned keys here. The manual path writes no bootstrap record, so also run `hosts check <host>`.
- **`patch` installs exactly the confirmed list.** unattended-upgrades runs with a strict Package-Whitelist, so an upgrade that needs a new package (typically a new kernel image) can be refused; those are installed by hand with apt in a maintenance window. The packages' own maintainer scripts may restart their own services (ssh, for example); sbom-audit restarts nothing, suppresses needrestart's automatic restarts, and never reboots.
- **`patch` stops with "not in force"** when an `apt.conf.d` file on the host sets an unattended-upgrades `Remove-*` option to `"true"`. Tell the user the host's setting has to be changed by hand before patch can work there.
- **A Docker-related package missing from the hold-back list** blocks patching ("add it to DOCKER_PACKAGES"); do not pass `--include-docker` to get around it unless the user asks for that.
- **Re-running `bootstrap`** overwrites the `*.sbom-audit.bak` backup next to `sshd_config`, so that file holds only the latest pre-bootstrap config. `unbootstrap` does not restore a backup (it removes only the `AllowUsers` token bootstrap added); never copy an old `.bak` back over a live sshd config.
- **Hosts reached only through ProxyJump or ProxyCommand** are not supported: the host-key scan finds no keys.
- **A changed host key** aborts that host and is critical. Do not re-pin it with `bootstrap` until the user has confirmed out of band why the key changed.
