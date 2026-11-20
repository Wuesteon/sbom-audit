# Limitations

This page lists what sbom-audit does not see and what has not been tested, in plain terms. Read it
before you rely on a report that shows few or no findings. The full list of smaller limits per
ecosystem is in [reference.md, Limitations](reference.md#limitations).

## C, C++ and firmware

**Short version: for C and C++ code the repository scan sees almost nothing. You need an SBOM from
your build.**

The scan reads package manager files. Most C/C++ and firmware projects do not use a package manager
the scan understands. Their third-party code arrives in other ways:

| How the code arrives | What the scan does |
|---|---|
| Copied into the tree (vendored mbedTLS, FreeRTOS, lwIP, zlib, FatFs ...) | Not seen. There is no manifest to read. |
| git submodules | Not seen. `git archive` leaves submodules out. |
| Zephyr `west.yml`, ESP-IDF `idf_component.yml`, PlatformIO `platformio.ini` / `library.json` | Not read. |
| Conan `conanfile.py` | Not read. `conanfile.txt` and `conan.lock` are read. |
| vcpkg `vcpkg.json` | Only the project's own name and version are read, not its dependencies. The project itself is then listed as a package. |
| CMake `FetchContent_Declare`, `ExternalProject_Add` | Not read. |
| System libraries linked at build time (OpenSSL from the distribution) | Not seen. |

What the reports say about this: for each branch with submodules, unread firmware manifests or C/C++
source files, `AUDIT.md` has a row "Branches with submodules, C/C++ code or firmware manifests not
inventoried" and a Note naming the submodules, manifests and the number of C/C++ files. `STATUS.md`
repeats the count, `REPORT.html` names it under limits, and the CRA SBOM row is marked
`INCOMPLETE`. The plugin detects these gaps; it does not close them.

### Field test (2026-11-20, public repositories, nothing built or run)

| Repository | Found by the scan | Missed |
|---|---|---|
| libsndfile (C, CMake, vcpkg) | 1 package: libsndfile itself, from `vcpkg.json` | its 7 vcpkg feature dependencies (libvorbis, libflac, opus, mpg123, mp3lame, sqlite3, speex), 210 C/C++ files |
| meshtastic-firmware (PlatformIO) | 104 GitHub Actions, 5 PyPI packages, 4 container images | 2 submodules, every `lib_deps` in 204 `platformio.ini` files, 1,571 C/C++ files |
| micropython | 45 GitHub Actions, 2 PyPI packages, 1 image | 35 submodules (mbedTLS, lwIP, TinyUSB, BTstack ...), `idf_component.yml`, 2,398 C/C++ files including vendored libraries |
| zephyr-example (west) | 10 GitHub Actions | the Zephyr tree and modules in `west.yml`, 7 C files |

None of the firmware dependencies were in an SBOM, and so none were checked for vulnerabilities.
Before the coverage-gap notes were added, the reports for these repositories read like a clean result.

### A build SBOM closes the inventory gap, not always the matching gap

`import` replaces a branch's package list with a CycloneDX SBOM from your build. In the field test a
hand-made build SBOM for micropython added mbedTLS 2.28.0, zlib 1.2.11 (Conan), lwIP, FreeRTOS
9.0.0, littlefs and FatFs to the inventory. All of these versions have known CVEs, and the audit
still reported **0 vulnerable**. The reason: osv-scanner matches by package URL, and OSV has no
advisories for `pkg:github/...`, `pkg:generic/...`, `pkg:conan/...` or `pkg:vcpkg/...` purls. CPE
identifiers in the SBOM are not used for matching.

So an imported C/C++ SBOM is inventoried, but its components are **listed, not checked**. `AUDIT.md`
counts them as "Packages OSV cannot match (generic, GitHub, Conan, vcpkg), not checked for
vulnerabilities" and names them per branch under Notes. Checking them needs CPE/NVD matching, which
the plugin does not do. Until it does, check C libraries against the NVD or your vendor's
advisories yourself, and record the result with `vex add`.

## Vendored code and submodules (any language)

- Submodules are never scanned. If a submodule is your own repository, add it to the portfolio as a
  project of its own.
- Code copied into the tree (a `vendor/` folder, a minified library in `static/`) is seen only when it
  carries a manifest Syft understands (for example Go `vendor/modules.txt` or a `package.json`).
- The secrets scan reads the history of the repository itself, not the history of submodules.

## Projects that are not scanned

A project is skipped when none of the configured `branches` exist in it (a repository on `master`
with the default `["main", "dev"]`). `setup` warns about each such project. The run names skipped
projects in `STATUS.md` (Sources and Counts) and in the Notes of `AUDIT.md`. The run's exit code does
not change: a skipped project does not make the run fail.

## Scheduler

The weekly schedule installs a launchd agent on macOS and a systemd user timer on Linux.

- The generated launchd and systemd files, install and removal are covered by unit tests.
- **Not yet validated on a Linux server through a reboot.** A systemd *user* timer runs only while
  that user's systemd instance runs. On a server where nobody logs in, that usually needs
  `loginctl enable-linger <user>`; the plugin does not set it and does not check it. `Persistent=true`
  should catch up a missed run after a reboot, but this has not been tested. Check with
  `systemctl --user list-timers` after a reboot, and watch `STATUS.md` for
  `scheduler did not run since ...`.
- Other platforms (Windows) have no scheduler; use CI.

## CI

The CI template `plugin/templates/github-actions/sbom-audit.yml` is written for and validated on
GitHub Actions only. GitLab CI, Jenkins, Azure DevOps and others are not tested and have no template.
The commands are the same CLI calls, so porting is possible, but the tool downloads, checksums,
credentials and the push of `security/` would have to be rebuilt by you. Host mode does not run in
CI.

## Use without Claude Code

Tested in a clean shell (no `claude`, no `CLAUDE_*` variables, an empty `HOME`) with python3, syft,
osv-scanner and gitleaks: `setup`, `run`, `status`, `lookup`, `incident` (also `--vex`), `vex add`,
`audit`, `issues`, `report`, `secrets report`, `sbom check`, `import` and `verify` all work. Command
sequence: [Using sbom-audit without Claude Code](without-claude-code.md).

What you lose without Claude Code:

- the assessment: the verifier that reads code to back a VEX decision and the web search for
  incidents of the last 30 days. `assess draft` with your own OpenAI-compatible endpoint writes an
  unverified proposal instead;
- `[schedule] assess = true` (needs `claude` on `PATH`; the step is reported as skipped);
- `settings`, which only edits `~/.claude/settings.json`.

Things that are confusing without Claude Code:

- `security/CLAUDE.md`, `security/README.md` and several messages name slash commands
  (`run /sbom-audit:run first`). The CLI command has the same name.
- `setup` calls `gh` for GitHub status when it is installed. Without a login every line reads
  `unknown`; `gh` may create its own files under `~/.local/state/gh/`.
- `run` prints `STATUS.md` to the terminal at the end, so the output is long.

## What data leaves the machine

No source code, SBOM file or secret value is sent by the plugin's own code in any mode. gitleaks
runs locally. Syft is run with its update check turned off. The table lists each mode and what it
adds.

| Mode | Hosts contacted | What is sent | Code |
|---|---|---|---|
| Every `run` / `scan` | your git remotes | `git fetch --prune origin` (turn off with `fetch = false`) | `gitio.py` |
| Every `run` / `audit` | api.osv.dev (by osv-scanner) | package names, versions and ecosystems from the SBOMs | `matching.py` |
| Every `run` / `audit` | www.cisa.gov | nothing; the KEV catalogue is downloaded (once per 24 h) | `enrich.py` |
| Every `run` / `audit` | endoflife.date | product and cycle, e.g. `nodejs/20` (once per 24 h) | `enrich.py` |
| Every `run` / `audit` | registry.npmjs.org, pypi.org, jsr.io | the name of each direct dependency (once per 24 h) | `enrich.py` |
| `incident` | api.osv.dev | the advisory id | `lookup.py` |
| `setup`, `run` with a `gh` login | api.github.com (through `gh`) | repository names: Dependabot and secret-scanning status, visibility of the evidence repository's remote | `setup.py`, `evidence.py` |
| `setup --enable-dependabot` (after you confirm) | api.github.com | PUT requests that turn on Dependabot for the named repositories | `setup.py` |
| `push = true` | the evidence repository's remote | the `security/` folder (refused for a public remote) | `evidence.py` |
| `[discovery]` | api.github.com, github.com | the owner name (`gh repo list`), then clones | `secrets/discovery.py` |
| Host mode (`[hosts]`) | your servers over SSH; api.osv.dev; endoflife.date; api.github.com | the SSH session; each server's Debian/Ubuntu package names and versions; OS release; vendor binary names | `hosts/` |
| `[cra] check_well_known = true` | your product websites | one GET of `/.well-known/security.txt` per product | `cra.py` |
| `assess draft`, only with `[assess]` | the endpoint you configure | excerpts of `AUDIT.md`, the inventory overview and the open work list (package names, versions, advisories, file paths; secret fingerprints, never values). `--dry-run` prints the request | `draft.py` |
| Claude Code skills | Anthropic, through Claude Code | what Claude reads: reports, inventory, code excerpts the verifier opens | the skills |
| `[schedule] assess = true` | Anthropic, through `claude -p` | as for the skills, capped by `--max-budget-usd` | `assess.py` |
| CI template | github.com (tool downloads), the hosts of a normal run | as above | `plugin/templates/github-actions/` |

The details per host are in [reference.md, Privacy](reference.md#privacy-what-leaves-your-machine).
