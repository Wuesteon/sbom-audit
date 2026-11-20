# Using sbom-audit without Claude Code

Everything that writes evidence (SBOMs, audit, secrets scan, VEX, reports, `verify`) is one Python
CLI that uses only the standard library. Claude Code is not needed for any of it. This page is a
command sequence you can copy, tested in a clean shell: no `claude` on `PATH`, no `CLAUDE_*`
variables, a new empty `HOME`.

What needs a model: the written assessment (`/sbom-audit:assess`, the verifier that reads code, the
web search for recent incidents). Without Claude Code you can get a draft from any
OpenAI-compatible endpoint with `assess draft`, or do the assessment yourself. The rest runs without
a model.

## 1. Install

Requirements: Python 3.11 or newer, git, macOS or Linux.

```bash
brew install syft osv-scanner gitleaks        # or the release binaries from each project's GitHub page
# gh is optional: only for GitHub status reads, the evidence repository visibility check and [discovery]
git clone https://github.com/Wuesteon/sbom-audit.git ~/sbom-audit
CLI=~/sbom-audit/plugin/scripts/sbom_audit_cli.py
python3 $CLI --version
```

To pin a version, check out a release tag (`git -C ~/sbom-audit checkout sbom-audit--v<version>`).

## 2. Set up

Run from the folder that holds your repositories. `setup` writes `security/` next to them (or pass
`--out <path>/security` before the command).

```bash
cd ~/code                                    # the folder with your git repositories
python3 $CLI setup
```

Read what it prints:

- `warning: <project> has none of the branches [...]`: that project would be skipped. Open
  `security/sbom-audit.toml` and add its branch (for example `master`) to `branches`.
- GitHub status lines read `unknown` when `gh` is missing or not logged in. That is harmless.
- `setup` writes `security/CLAUDE.md` and `security/README.md`. They describe the folder for a coding
  agent and use slash commands; each slash command has the CLI command of the same name
  (`/sbom-audit:incident X` is `python3 $CLI incident X`).

## 3. Run

```bash
python3 $CLI run          # SBOMs, audit, secrets scan, reports; prints STATUS.md at the end
echo "exit $?"            # 0 clean, 1 findings, 2 a source failed, 3 bad VEX file, 4 tool missing
python3 $CLI status       # the summary again; writes nothing
```

Then read `security/STATUS.md` and `security/AUDIT.md`. Check the **Notes** section of `AUDIT.md`
before you trust a low number: projects that were not scanned, packages that were not checked and
C/C++ code that was not inventoried are listed there (see [Limitations](limitations.md)).

## 4. Daily questions

```bash
python3 $CLI lookup lodash                   # which project and branch uses a package (exit 1: no match)
python3 $CLI incident CVE-2021-23337         # are we affected (exit 1: a hit, 2: incomplete)
python3 $CLI incident CVE-2021-23337 --vex   # also records not_affected for the projects without it
python3 $CLI issues --max-priority 3         # the most urgent open issues
python3 $CLI code grep shop-web main 'parseQuery\('   # read committed code on an audited branch
```

## 5. Record a decision (VEX)

```bash
python3 $CLI vex add shop-web GHSA-35jh-r3h4-6jhm not_affected \
  --justification vulnerable_code_not_in_execute_path \
  --subcomponent pkg:npm/lodash \
  --impact "template() is never called with user input" \
  --author you@example.com
python3 $CLI audit        # re-apply VEX to the existing SBOMs, no rescan
```

`not_affected` needs a `--justification`. Without `--author` the author is your `git config user.email`
(or `user.name`); when neither is set, `vex add` and `incident --vex` refuse and ask for `--author`.

## 6. Secrets

```bash
python3 $CLI secrets report                  # SECRETS.md from secrets.json (never prints a value)
python3 $CLI secrets resolve --help          # record a decision for one finding
```

`run` already includes the scan. Without gitleaks the scan reports `skipped`, never clean.

## 7. Reports and evidence

```bash
python3 $CLI report       # REPORT.html, the printable management report
python3 $CLI sbom check   # SBOM quality of every file under sbom/
python3 $CLI verify       # checks every file against the SHA-256 in manifest.json
```

## 8. C/C++ and firmware: import a build SBOM

The repository scan does not see submodules, vendored C code or firmware manifests. If you have an
SBOM from your build, import it:

```bash
python3 $CLI sbom check build/firmware.cdx.json
python3 $CLI import --project firmware --branch main build/firmware.cdx.json
python3 $CLI audit
```

Read [Limitations](limitations.md) first: an imported C library is only checked for
vulnerabilities when its purl type is one OSV knows.

## 9. Optional

- **CRA readiness:** add `[cra.products."<project>"]` to `sbom-audit.toml`, then `python3 $CLI cra check`.
  Without a product it exits 2 with "no product configured".
- **Weekly schedule:** `python3 $CLI setup --schedule weekly` installs a launchd agent (macOS) or a
  systemd user timer (Linux) that runs the plain CLI `run`. See [Limitations](limitations.md) for what
  has not been tested.
- **CI:** `plugin/templates/github-actions/sbom-audit.yml`.
- **Assessment draft:** configure `[assess]` (any OpenAI-compatible endpoint), check the request with
  `python3 $CLI assess draft --dry-run`, then `python3 $CLI assess draft`. It writes a proposal and
  records nothing.

## Commands that are Claude Code only

| Command | Without Claude Code |
|---|---|
| `/sbom-audit:assess` (verifier, incident search) | `assess draft` with your own endpoint, or by hand |
| `settings` (autonomous mode, session hook) | not needed; it edits `~/.claude/settings.json` only |
| `[schedule] assess = true` | needs `claude` on `PATH`; otherwise the step is reported as skipped |

Messages that name a slash command add the CLI form, for example
`run /sbom-audit:run (CLI: python3 /path/to/sbom_audit_cli.py run)`. Terminal messages give the real
path; text written into the evidence folder (`STATUS.md`, `CRA.md`) names only `sbom_audit_cli.py`, so
no local path ends up in a shared report. `/sbom-audit:assess` maps to `assess draft`.
