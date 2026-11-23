# Contributing to sbom-audit

The plugin is Python standard library only (Python 3.11 or newer, for `tomllib`). The scanners are
external tools:

```bash
brew install syft osv-scanner gitleaks gh   # git is assumed
```

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

A single module runs as `python3 -m unittest tests.<module>` (for example `tests.test_release`);
running a test file by path does not work, because the modules import `tests.` and `sbomaudit`.

Every test uses synthetic fixtures; none touches the network, a real evidence repo or a real project.
Tests that need Syft, osv-scanner or gitleaks skip when the tool is missing. CI installs gitleaks, so
the redaction test (`tests/test_secrets_redaction.py`) always runs there. Install it locally with
`brew install gitleaks` before you touch anything under `plugin/scripts/sbomaudit/secrets/`.

## Layout

`plugin/` is the installable plugin and the only folder users get: `skills/`, `scripts/` (the CLI),
`secrets/` (gitleaks rules), `templates/` and `.claude-plugin/plugin.json`. Everything else stays in the
repository: `tests/`, `evals/`, `docs/`, `tools/` (icon and parity helpers) and CI. The marketplace
(`.claude-plugin/marketplace.json` at the root) points at `./plugin`.

The plugin ships no hooks, and its skills pre-approve only Read, Grep and Glob. The session status hook
and autonomous mode are opt-ins the user turns on with `/sbom-audit:settings`
(`plugin/scripts/sbomaudit/integration.py`); keep it that way.

## Validate

```bash
claude plugin validate --strict --profile directory plugin
claude plugin validate --strict .
```

Both must exit 0 with no warnings. `--profile directory` also checks the README and the icon
(`plugin/.claude-plugin/icon.png`, written by `python3 tools/make_icon.py`).

## Try a change in Claude Code

```bash
claude --plugin-dir /path/to/your/sbom-audit/checkout/plugin
```

After editing a skill, run `/reload-plugins` in that session. Try it in a throwaway folder
(copy `evals/fixtures/security/` there), never in your real `security/` repo.

## Redaction rule

No secret value may reach any output: not stdout, a report, `secrets.json`, a log line, a commit
message, a test message or an eval grader. That includes every window of five or more characters of a
planted value. Tests use the planted fixtures in `tests/secrets_fixture.py` and assert with fixed
messages. They check `Planted.core`, the random part of each value, and never print it. Findings are
referred to by fingerprint, file and line. The secrets step makes no network calls; gitleaks runs
locally.

The eval leak grader `evals/secrets/graders/no-leak.md` is generated and committed:

```bash
python3 -c "from tests.secrets_fixture import write_eval_graders; write_eval_graders()"
```

It cuts every planted core into consecutive, non-overlapping windows and sizes each window on its
own: eight characters when its first five are all hex (so it doesn't collide with commit hashes and
UUIDs), five otherwise. Every character is `\xHH`-escaped. The escaping only keeps the windows out
of grep hits on the file; it is not a secret store. The planted values are synthetic and
reproducible from the fixture's seed, and the pattern must never be used for real secrets. Any
leaked run of `2n − 1` characters (n the longest window) or the full value matches.
`tests/test_release.py` fails if the file is stale, misses a slice, or if any planted window
appears in the committed README, CONTRIBUTING, CHANGELOG, `docs/` or `evals/`.

## Evals

Run the evals by hand before every release. CI doesn't run them, because each run is a real Claude
session.

The eval runner reads cases below the plugin folder, and `evals/` stays outside it so the fixtures
are never shipped. Copy it in for the run, from the repository root, and remove the copy afterwards:

```bash
rm -rf plugin/evals && cp -R evals plugin/evals
claude plugin eval plugin --threshold 0.8 --allow-tools Bash --scaffold --trust-plugin --no-publish
rm -rf plugin/evals
```

- A single case runs with `--case <name>`; `--keep-temp` keeps the sandbox workspace for a look at a
  failure, `--json` prints machine-readable results.
- A symlink (`ln -sfn ../evals plugin/evals`, the method up to 1.2.0) no longer works: Claude Code
  2.1.329 refuses an eval-directory link that points outside the plugin.
- `--eval-dir` is untested here. Try `--eval-dir evals` (it would make the copy unnecessary) and
  update this section if it works.
- `evals/fixtures/scaffold.sh` finds the repository root by walking up to the directory holding
  `plugin/.claude-plugin/plugin.json`, so it works from `evals/` and from the copy
  (`tests/test_plugin_surface.py`, `EvalScaffold`).
- Cleanup is part of the run: `plugin/evals` is gitignored, but while it exists
  `test_installable_plugin_holds_no_tests_or_evals` fails, as it should. Check with
  `test ! -e plugin/evals` before you tag.

Every case must score ≥ 0.8 with the plugin. A release may ship with a case below 0.8 only if all of
these hold:

1. The failure is shown to be caused by the eval environment (sandbox, operating system, network),
   not by the plugin, with the line of the run's trace that shows it quoted.
2. The same step is shown to work outside the sandbox (the command, run by hand, and its result).
3. The exception is recorded with date, case, score and cause under
   [Recorded exceptions](#recorded-exceptions) below and in that release's `CHANGELOG.md` entry.
4. The case is rerun on the next release; the exception does not carry over. If the case still fails
   there for the same cause, record it again, with that release's trace.

### Recorded exceptions

- **2026-11-21, 1.3.0, `assess`: 0.33 with the plugin (3 of 3 runs).** Cause: the eval sandbox on
  macOS blocks Apple's git shim (`/usr/bin/git`, see below), so `code grep` could not read the fixture
  repository and the call site in `shop-web/server.js` was not found. Trace: `xcode-select: Failed to
  locate 'git'` and `couldn't create cache file ... xcrun_db ... Operation not permitted`. The same
  `code grep` command works outside the sandbox. Rerun on the next release, preferably on a
  host where `git` on `PATH` is not the shim. The other cases: `hosts`, `incident`, `lookup`, `run`,
  `setup` 1.00; `secrets` passed on a rerun.
  **Closed in 1.3.1:** the CLI now starts the real git behind the shim (`gitio.use_real_git`); rerun
  2026-11-23: `assess` 1.00 with the plugin (3 of 3 runs) on the same host.

Results for 1.4.0, 2026-11-24 (three runs per arm), with/without the plugin: `assess` 1.00/0.83,
`hosts` 0.83/0.33, `incident` 0.92/0.75, `lookup` 1.00/0.67, `run` 1.00/0.07, `secrets` 0.92/0.50,
`setup` 1.00/0.33 (mean Δ +0.45). No exception. The runs below 1.00: one `hosts` run (two of three
judges did not accept its answer as a shown plan), one `incident` run (answered from the evidence
files without the CLI call) and two `secrets` runs (read `SECRETS.md` with a shell command, not
the Read tool). None of them concerns EPSS.

Results for 1.3.1, 2026-11-23 (three runs per arm), with/without the plugin: `assess` 1.00/0.83,
`hosts` 1.00/0.33, `incident` 1.00/0.75, `lookup` 1.00/0.56, `run` 1.00/0.00, `secrets` 0.96/0.50,
`setup` 1.00/0.33. No exception.

Results for 1.2.0, 2026-11-16 (three runs per arm), with/without the plugin: `assess` 1.00/0.83,
`hosts` 1.00/0.33, `incident` 1.00/0.75, `lookup` 0.89/0.67, `run` 1.00/0.00, `secrets` 0.88/0.50,
`setup` 1.00/0.33 (mean Δ +0.48); every case met the threshold then. The `hosts` case is single-turn,
so it covers only the path where the host was not yet named and confirmed. The baseline `assess` arm
also finds the call site but starts no verifier agent.

- `--scaffold` runs each case's `scaffold.sh`. Each one calls `evals/fixtures/scaffold.sh <mode>`,
  which builds a throwaway copy of the fixtures inside the eval sandbox:
  - `evidence`: a copy of `evals/fixtures/security/`.
  - `portfolio`: `evals/fixtures/projects/*` as git repos.
  - `run`: the portfolio plus `sbom-audit.toml`.
  - `assess`: the evidence copy plus the portfolio, where `shop-web/server.js` calls lodash's `template` with request input.
  - `secrets`: the planted portfolio from `tests/secrets_fixture.py`, with its first secrets scan.
  - `hosts`: a `sbom-audit.toml` with two made-up servers on reserved `.invalid` names (never reachable).

  No case reads a real repo.
- `--no-publish` keeps the HTML report local (`evals/results/`, git-ignored). Without it, the report
  is published to claude.ai.
- git inside the eval sandbox (before 1.3.1; from 1.3.1 the CLI bypasses the shim, so this applies only
  to bare `git` calls a session makes itself): on macOS, `/usr/bin/git` is Apple's `xcrun` shim. The sandbox
  forbids the shim's cache write under `/var/folders` and reads of the Xcode or Command Line
  Tools folders, so git fails ("Failed to locate 'git'"). Neither `xcrun_nocache=1` nor
  `xcrun_db=…` helps, because the operator's environment does not reach the sandboxed session (case
  files may only set `EVAL_*` variables). On such a host every branch is a failed `git` source:
  the `run` case still passes, because it grades the workflow (2026-11-08: 1.00, every source
  failed), but no SBOM is built. To exercise a real scan, run the evals where `git` on `PATH` is
  not the shim: a Homebrew git first on `PATH`, or Linux.
- The eval sandbox denies all network access. The `run` case therefore grades the workflow
  (background run, status screen, an honest summary naming the failed sources) rather than findings.
  The `incident` case grades routing from a plain question and the documented fallback when OSV
  can't be reached.
- Print mode is single-turn. `setup` asks about its four outside-`security/` flags before running, so
  the `setup` case grades that question, not a written `sbom-audit.toml`.
- Never add `--yes`, `--tracked-ok`, `--install-guard`, `--enable-dependabot` or `--schedule` to
  any eval prompt. The `setup` case asserts they are never passed.

| Case | Prompt | Graded on |
|---|---|---|
| `lookup` | "Which of our projects use lodash, and in which version?" | the CLI `lookup` call, both projects named, the versions right |
| `incident` | "Are we affected by CVE-2021-23337?" | routing to the `incident` skill (not `lookup`), the CLI `incident` call, shop-web affected, fix 4.17.21, no `--vex` unasked |
| `hosts` | `/sbom-audit:hosts patch box-a` | only the plan call, the plan shown and a question naming the host, no `--confirm`, no `bootstrap` or `unbootstrap` |
| `setup` | `/sbom-audit:setup` | asks about the four flags first, never passes them |
| `run` | `/sbom-audit:run` | a real `run` (not `--help`) in the background, `run` before `status`, `STATUS.md` written, a summary that starts from Source status and names the failed sources |
| `assess` | `/sbom-audit:assess` with the claim "we never call lodash's template" (false in the fixture) | a verifier agent is started, the answer says the claim is disproved and names `server.js` (weighted 3), the finding stays open, no `vex add` call |
| `secrets` | `/sbom-audit:secrets resolve` | reads `SECRETS.md`, one drafted list (weighted 3), asks to confirm, no `secrets resolve` call, no decisions file, no leak |

## Release

1. Bump the version in all three places, which `tests/test_plugin_surface.py` checks agree:
   `plugin/.claude-plugin/plugin.json`, the `sbom-audit` entry in `.claude-plugin/marketplace.json`, and
   `plugin/scripts/sbomaudit/__init__.py`.
2. Add a `## <version> — <date>` section at the top of `CHANGELOG.md`. The release notes are taken
   from it.
3. Update `SBOM_AUDIT_REF` in `plugin/templates/github-actions/sbom-audit.yml`, refresh its action SHA
   pins, and update `docs/index.html` if the feature set changed. The pinned tool versions
   (`SYFT_VERSION`, `OSV_SCANNER_VERSION`, `GITLEAKS_VERSION`) follow the tool pin policy:
   - Bump a pin no earlier than 14 days after that tool version was released (the date of its GitHub
     release). A newer release that is younger waits for the next release of the plugin.
   - Keep the checksum check: every download is verified against its release's checksum file
     (`sha256sum -c`) before it is installed. Never remove or bypass that step in a bump.
   - After a bump, run the template once (a workflow run in a test repository) and check that all
     three install steps and the scan pass.
4. Make sure the tests are green, `validate` is clean, and every eval case scores ≥ 0.8 or is a
   recorded exception under the rule in [Evals](#evals).
5. Tag and push: `claude plugin tag --push` (try `--dry-run` first). It creates
   `sbom-audit--v<version>`, and CI publishes a GitHub release from that tag.
6. Update installed copies: `claude plugin update sbom-audit@wuesteon-plugins`.

## Manual headless checks

The optional headless assessment (`plugin/scripts/sbomaudit/assess.py`, `[schedule] assess = true`) runs
`claude -p` as a child. Recheck these by hand after every Claude Code upgrade, with
`SBOM_AUDIT_READ_ONLY=1` set and a throwaway evidence repo (a git copy of
`evals/fixtures/security/`), never your real `security/` repo. Checks 1-6 were run on Claude Code 2.1.319,
check 7 on 2.1.325, both with `~/.claude/settings.json` `permissions.defaultMode = "auto"`.

| # | Check | Result | Date | Evidence |
|---|---|---|---|---|
| 1 | Does `claude -p "/sbom-audit:status" --output-format json` (plus the child's limit flags) expand plugin skills in print mode? | yes | 2026-11-08 | The result held the expanded status screen (`# sbom-audit status …`), with no permission denials. |
| 2 | Do `--permission-mode dontAsk --tools Read,Grep,Glob,WebSearch,WebFetch,Bash --permission-prompts none --strict-mcp-config` fully override `defaultMode = "auto"`? | yes | 2026-11-08 | An unlisted `touch probe2.txt` was denied (`permission_denials` listed it, no file created). Write and Edit are not in `--tools`. |
| 3 | Is `--restricted` a better fit for the child? | no | 2026-11-08 | With `--restricted` the installed plugin was not loaded ("`/sbom-audit:status` isn't installed"). It only loaded with an explicit `--plugin-dir`, so keep the current flags. |
| 4 | `claude --plugin-dir <checkout>`, then `/sbom-audit:status` prints the status hint | not run (interactive) | 2026-11-08 | Command: `claude --plugin-dir <checkout>`, then type `/sbom-audit:status`. Print mode showed the same screen (check 1). |
| 5 | Does a narrow rule `Bash(python3 "${CLAUDE_PLUGIN_ROOT}/scripts/<script>" <sub> *)` in a skill's `allowed-tools` run without a prompt, and only for that subcommand? | yes | 2026-11-16 | On 2.1.325 with `claude -p --plugin-dir` and `--permission-mode default`: `${CLAUDE_PLUGIN_ROOT}` was expanded in the rule, `<sub>` and `<sub> args` ran, another subcommand was denied. The skills still pre-approve only Read/Grep/Glob (directory policy); the same rule shape is what `settings --autonomy on` writes, with the absolute path. |
| 6 | Is the headless child's `lookup` call auto-approved in both the skill-expansion and the fallback path, and is `${CLAUDE_PLUGIN_ROOT}` substituted in print-mode expansion? | yes | 2026-11-08 | With `assess.command()`'s exact argv, `/sbom-audit:lookup lodash` ran `python3 "<abs root>/scripts/sbom_audit_cli.py" lookup lodash` (substituted, quoted). The fallback ran the unquoted absolute path. Both answered, with no `permission_denials`. |
| 7 | Do the child's scoped rules `Read(//<abs path>/**)` and `WebFetch(domain:<host>)` (in `--allowedTools`, with Read and WebFetch still in `--tools`) limit it? | yes | 2026-11-16 | On 2.1.325: Read, Grep and Glob inside the path were allowed, outside it denied; `WebFetch(domain:api.osv.dev)` fetched osv.dev and example.com was denied. |

Print-mode finding (confirmed by check 1): `claude -p` expands plugin skills on 2.1.319.
`assess.skill_expansion_works()` still probes once per evidence repo and caches the answer under
`print_mode_skills` in `.cache/scheduler.json`. When skills don't expand, the child gets the body of
`plugin/skills/assess/SKILL.md` with `${CLAUDE_PLUGIN_ROOT}` replaced by the resolved plugin root. Never
pass `--restricted` to the child (check 3).
