"""`setup`: preflight, discovery, config + .gitignore, optional git init and Dependabot hand-off."""
from __future__ import annotations

import contextlib
import io
import datetime as dt
import json
import subprocess
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from sbomaudit import cli, config, preflight, setup, status

ALL_PRESENT = lambda tool: f"/usr/local/bin/{tool}"  # noqa: E731


def make_root(tmp: Path) -> Path:
    root = tmp / "PROJECTS"
    for name, remote in (("alpha", "git@github.com:Example-Org/Alpha.git"),
                         ("beta", "https://gitlab.com/someone/beta.git"),
                         ("gamma", None)):
        repo = root / name
        repo.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        if remote:
            subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", remote], check=True)
    (root / "not-a-repo").mkdir()
    return root


def gh_stub(fail_for: tuple[str, ...] = ()):
    calls: list[list[str]] = []

    def gh(cmd, **kwargs):
        calls.append(list(cmd))
        rc = 1 if any(part in cmd[-1] for part in fail_for) else 0
        return subprocess.CompletedProcess(cmd, rc, "", "HTTP 403: forbidden\n" if rc else "")

    gh.calls = calls
    return gh


SA_ENABLED = {"visibility": "private", "sa": {"secret_scanning": {"status": "enabled"},
                                              "secret_scanning_push_protection": {"status": "disabled"}}}


def gh_json_stub(status=None, repos=None, repo_list_rc=0, fail_for=()):
    """Records argv; `--jq` reads answer with `status` JSON, `gh repo list` with `repos`, PUTs succeed."""
    calls: list[list[str]] = []

    def gh(cmd, **kwargs):
        calls.append(list(cmd))
        if cmd[:3] == ["gh", "repo", "list"]:
            if repo_list_rc:
                return subprocess.CompletedProcess(cmd, repo_list_rc, "", "HTTP 401: bad credentials\nsecond line\n")
            return subprocess.CompletedProcess(cmd, 0, json.dumps(repos or []), "")
        if "--jq" in cmd:
            return subprocess.CompletedProcess(cmd, 0, json.dumps(status if status is not None else SA_ENABLED), "")
        rc = 1 if any(part in cmd[-1] for part in fail_for) else 0
        return subprocess.CompletedProcess(cmd, rc, "", "HTTP 403: forbidden\nsecond line\n" if rc else "")

    gh.calls = calls
    return gh


def puts(gh):
    return [c for c in gh.calls if c[:4] == ["gh", "api", "-X", "PUT"]]


def run(out, root, init_git=False, enable_dependabot=None, gh=None, which=ALL_PRESENT, yes=False):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = setup.run(out, root, init_git=init_git, enable_dependabot=enable_dependabot,
                       gh=gh or gh_stub(), which=which, yes=yes)
    return rc, buf.getvalue()


class SetupTests(unittest.TestCase):
    def test_setup_writes_config_and_gitignore_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(Path(tmp))
            out = root / "security"
            rc, text = run(out, root)
            self.assertEqual(rc, 0, text)
            toml = out / config.CONFIG_NAME
            self.assertIn('# "alpha" = { production = false }', toml.read_text())
            self.assertIn('# "gamma" = { production = false }', toml.read_text())
            self.assertIn(".cache/", (out / ".gitignore").read_text())
            self.assertIn("alpha", text)
            self.assertIn("portfolio", text)
            self.assertIn("/sbom-audit:run", text)
            self.assertNotIn("<plugin root>", text)                 # a runnable path for use without Claude Code
            self.assertIn("scripts/sbom_audit_cli.py run", text)
            self.assertFalse((out / ".git").exists())
            before = {p.name: p.read_text() for p in out.iterdir() if p.is_file()}
            (toml).write_text(toml.read_text() + '"alpha" = { production = true }\n')
            before[toml.name] = toml.read_text()
            rc, text = run(out, root)
            self.assertEqual(rc, 0)
            self.assertEqual({p.name: p.read_text() for p in out.iterdir() if p.is_file()}, before)
            self.assertIn("unchanged", text)

    def test_setup_portfolio_init_git_only_when_asked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(Path(tmp))
            out = root / "security"
            rc, _ = run(out, root)
            self.assertFalse((out / ".git").exists())
            rc, text = run(out, root, init_git=True)
            self.assertEqual(rc, 0, text)
            self.assertTrue((out / ".git").is_dir())
            self.assertIn("git init", text)
            rc, text = run(out, root, init_git=True)
            self.assertEqual(rc, 0)
            self.assertIn("already", text)
            # single mode: security/ inside a repo is tracked by that repo, never its own
            repo = root / "alpha"
            rc, text = run(repo / "security", repo, init_git=True)
            self.assertEqual(rc, 0, text)
            self.assertFalse((repo / "security" / ".git").exists())
            self.assertIn("single", text)
            self.assertIn("evidence repo visibility: not checked (single-repo mode", text)
            self.assertNotIn("committed", text)

    def test_dependabot_alerts_only_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(Path(tmp))
            out = root / "security"
            gh = gh_stub(fail_for=("automated-security-fixes",))
            rc, text = run(out, root, enable_dependabot="alerts", gh=gh, yes=True)
            self.assertEqual(rc, 0, text)
            self.assertEqual([c[-1] for c in puts(gh)], ["repos/Example-Org/Alpha/vulnerability-alerts"])
            self.assertIn("Example-Org/Alpha: alerts: on", text)
            self.assertNotIn("fixes", text)
            self.assertNotIn("automated-security-fixes", " ".join(" ".join(c) for c in gh.calls))
            before = len(puts(gh))
            run(out, root, gh=gh)
            self.assertEqual(len(puts(gh)), before)     # no --enable-dependabot: no PUT

    def test_dependabot_fixes_puts_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(Path(tmp))
            out = root / "security"
            gh = gh_stub(fail_for=("automated-security-fixes",))
            rc, text = run(out, root, enable_dependabot="fixes", gh=gh, yes=True)
            self.assertEqual(rc, 0, text)
            self.assertEqual([c[-1] for c in puts(gh)], ["repos/Example-Org/Alpha/vulnerability-alerts",
                                                         "repos/Example-Org/Alpha/automated-security-fixes"])
            self.assertIn("Dependabot alerts + security updates will be enabled on:", text)
            self.assertIn("Example-Org/Alpha: alerts: on, fixes: failed (HTTP 403: forbidden)", text)
            self.assertNotIn("second line", text)

    def test_dependabot_requires_yes_and_lists_targets_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(Path(tmp))
            out = root / "security"
            out.mkdir()
            (out / config.CONFIG_NAME).write_text('[discovery]\ngithub_owner = "Example-Org"\n')
            repos = [{"nameWithOwner": "example-org/alpha", "isArchived": False, "isFork": False},
                     {"nameWithOwner": "Example-Org/other", "isArchived": False, "isFork": False},
                     {"nameWithOwner": "Example-Org/old", "isArchived": True, "isFork": False}]
            gh = gh_json_stub(repos=repos)
            rc, text = run(out, root, enable_dependabot="alerts", gh=gh)
            self.assertEqual(rc, 0, text)
            self.assertEqual(puts(gh), [])
            self.assertIn("Dependabot alerts will be enabled on:\n  Example-Org/Alpha\n  Example-Org/other\n", text)
            block = text.split("Dependabot alerts will be enabled on:")[1].split("run again")[0]
            self.assertNotIn("Example-Org/old", block)
            self.assertIn("run again with --yes to enable (no changes made)", text)
            self.assertEqual(len([c for c in gh.calls if c[:3] == ["gh", "repo", "list"]]), 1)
            gh = gh_json_stub(repos=repos)
            rc, text = run(out, root, enable_dependabot="fixes", gh=gh)
            self.assertEqual(puts(gh), [])
            self.assertIn("Dependabot alerts + security updates will be enabled on:\n  Example-Org/Alpha\n", text)
            self.assertIn("run again with --yes to enable (no changes made)", text)
            gh = gh_json_stub(repos=repos)
            rc, text = run(out, root, enable_dependabot="alerts", gh=gh, yes=True)
            self.assertEqual([c[-1] for c in puts(gh)], ["repos/Example-Org/Alpha/vulnerability-alerts",
                                                         "repos/Example-Org/other/vulnerability-alerts"])
            self.assertLess(text.index("will be enabled on:"), text.index("Example-Org/other: alerts: on"))
            self.assertNotIn("run again", text)

    def test_dependabot_empty_target_list_and_discovery_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "PROJECTS"
            (root / "gamma").mkdir(parents=True)
            subprocess.run(["git", "init", "-q", str(root / "gamma")], check=True)
            out = root / "security"
            gh = gh_stub()
            rc, text = run(out, root, enable_dependabot="alerts", gh=gh, yes=True)
            self.assertEqual(rc, 0, text)
            self.assertIn("(no GitHub repositories)", text)
            self.assertEqual(gh.calls, [])
            root2 = make_root(Path(tmp) / "two")
            out2 = root2 / "security"
            out2.mkdir()
            (out2 / config.CONFIG_NAME).write_text('[discovery]\ngithub_owner = "Example-Org"\n')
            gh = gh_json_stub(repo_list_rc=1)
            rc, text = run(out2, root2, enable_dependabot="alerts", gh=gh, yes=True)
            self.assertEqual(rc, 0, text)
            self.assertIn("discovery: skipped (HTTP 401: bad credentials)", text)
            self.assertNotIn("second line", text)
            self.assertEqual([c[-1] for c in puts(gh)], ["repos/Example-Org/Alpha/vulnerability-alerts"])
            self.assertNotIn("Discovered but not audited", text)

    def test_dependabot_put_has_timeout_and_survives_errors_per_slug(self):
        seen = []

        def gh(cmd, **kwargs):
            seen.append((list(cmd), kwargs))
            if "Bad/Timeout" in cmd[-1]:
                raise subprocess.TimeoutExpired(cmd, 30)
            if "Bad/Missing" in cmd[-1]:
                raise FileNotFoundError("gh\nsecond line with token ghp_secret")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        lines = setup.turn_on_dependabot(["Bad/Timeout", "Bad/Missing", "Good/Repo"], gh=gh, fixes=True)
        self.assertEqual(lines, ["  Bad/Timeout: alerts: failed (timed out), fixes: failed (timed out)",
                                 "  Bad/Missing: alerts: failed (FileNotFoundError), "
                                 "fixes: failed (FileNotFoundError)",
                                 "  Good/Repo: alerts: on, fixes: on"])
        self.assertTrue(all(kw.get("timeout") == 30 for _, kw in seen))
        self.assertNotIn("ghp_", "\n".join(lines))

    def test_yes_without_enable_dependabot_is_noted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(Path(tmp))
            gh = gh_stub()
            rc, text = run(root / "security", root, gh=gh, yes=True)
            self.assertEqual(rc, 0, text)
            self.assertIn("--yes is used only with --enable-dependabot; ignored", text)
            self.assertEqual(puts(gh), [])
            rc, text = run(root / "security", root, gh=gh)
            self.assertNotIn("--yes is used only", text)

    def test_github_status_lines_handle_null_security_block(self):
        gh = gh_json_stub(status={"visibility": "public", "sa": None})
        lines = setup.github_status(["Example-Org/Alpha"], gh=gh)
        self.assertEqual(lines[0], "  Example-Org/Alpha: public, secret scanning: unknown, push protection: unknown")
        self.assertEqual(lines[1], "  private repositories need GitHub Advanced Security (paid) for secret "
                                   "scanning; the plugin does not enable it")
        self.assertEqual(gh.calls[0], ["gh", "api", "repos/Example-Org/Alpha", "--jq",
                                       "{visibility, sa: .security_and_analysis}"])
        lines = setup.github_status(["a/b"], gh=gh_json_stub())
        self.assertEqual(lines[0], "  a/b: private, secret scanning: enabled, push protection: disabled")
        for bad in (gh_stub(), gh_stub(fail_for=("a/b",))):     # empty stdout / non-zero exit
            self.assertEqual(setup.github_status(["a/b"], gh=bad)[0],
                             "  a/b: unknown, secret scanning: unknown, push protection: unknown")

        def not_json(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 0, "not json", "")
        self.assertEqual(setup.github_status(["a/b"], gh=not_json)[0],
                         "  a/b: unknown, secret scanning: unknown, push protection: unknown")
        odd = gh_json_stub(status={"visibility": "weird\nvalue", "sa": SA_ENABLED["sa"]})
        self.assertEqual(setup.github_status(["a/b"], gh=odd)[0],
                         "  a/b: unknown, secret scanning: enabled, push protection: disabled")
        internal = gh_json_stub(status={"visibility": "internal", "sa": None})
        self.assertIn("a/b: internal,", setup.github_status(["a/b"], gh=internal)[0])

        def boom(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, 10)
        self.assertIn("a/b: unknown", setup.github_status(["a/b"], gh=boom)[0])

        def garbage(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 0, '{"sa": {"secret_scanning": 3}}', "")
        self.assertEqual(setup.github_status(["a/b"], gh=garbage)[0],
                         "  a/b: unknown, secret scanning: unknown, push protection: unknown")

    def test_setup_prints_github_status_for_configured_github_projects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(Path(tmp))
            out = root / "security"
            rc, text = run(out, root, gh=gh_json_stub())
            self.assertEqual(rc, 0, text)
            self.assertIn("GitHub status:\n  Example-Org/Alpha: private, secret scanning: enabled, "
                          "push protection: disabled\n", text)
            self.assertLess(text.index("evidence repo visibility"), text.index("GitHub status:"))
            rc, text = run(out, root, gh=gh_stub())     # stub answers nothing: unknown, no crash
            self.assertIn("Example-Org/Alpha: unknown, secret scanning: unknown", text)

    def test_setup_lists_discovered_not_audited(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(Path(tmp))
            out = root / "security"
            out.mkdir()
            (out / config.CONFIG_NAME).write_text('[discovery]\ngithub_owner = "Example-Org"\n')
            repos = [{"nameWithOwner": "Example-Org/ALPHA", "isArchived": False, "isFork": False},
                     {"nameWithOwner": "Example-Org/newrepo", "isArchived": False, "isFork": False},
                     {"nameWithOwner": "Example-Org/old", "isArchived": True, "isFork": False}]
            gh = gh_json_stub(repos=repos)
            rc, text = run(out, root, gh=gh)
            self.assertEqual(rc, 0, text)
            self.assertIn("Discovered but not audited (add to [projects] to audit):\n  Example-Org/newrepo\n", text)
            tail = text.split("Discovered but not audited")[1]
            self.assertNotIn("ALPHA", tail)
            self.assertNotIn("Example-Org/old", tail)
            self.assertEqual(len([c for c in gh.calls if c[:3] == ["gh", "repo", "list"]]), 1)
            rc, text = run(out, root, gh=gh_json_stub(repos=repos[:1]))
            self.assertNotIn("Discovered but not audited", text)
            (out / config.CONFIG_NAME).write_text("commit = true\n")
            gh = gh_json_stub(repos=repos)
            rc, text = run(out, root, gh=gh)
            self.assertNotIn("Discovered but not audited", text)
            self.assertEqual([c for c in gh.calls if c[:3] == ["gh", "repo", "list"]], [])

    def test_setup_writes_folder_docs_and_initial_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(Path(tmp))
            out = root / "security"
            rc, text = run(out, root)
            self.assertEqual(rc, 0, text)
            for name in ("CLAUDE.md", "README.md"):
                self.assertTrue((out / name).read_text().startswith("<!-- sbom-audit-template v"), name)
            doc = status.read(out)
            self.assertEqual(doc["schema"], status.SCHEMA)
            self.assertIsNone(doc["exit_code"])
            self.assertTrue(doc["first_run"])
            self.assertEqual(doc["mode"], "portfolio")
            counts = dict(doc["counts"])
            self.assertEqual(counts.pop("secrets"), {"A": 0, "B": 0, "C": 0})
            self.assertIsNone(counts.pop("hosts"))              # [hosts] not active: no host counts
            self.assertEqual(set(counts.values()), {0})
            self.assertTrue((out / status.STATUS_FILE).exists())
            line = status.severity_line(doc, None, dt.datetime.now().astimezone())
            self.assertIn("no run yet; run /sbom-audit:run", line)
            # a status.json from a real run is never replaced by setup
            doc["exit_code"] = 1
            status.write(out, doc)
            rc, text = run(out, root)
            self.assertEqual(rc, 0, text)
            self.assertEqual(status.read(out)["exit_code"], 1)

    def test_setup_in_a_folder_without_repositories_fails_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "empty"
            root.mkdir()
            out = root / "security"
            rc, text = run(out, root)
            self.assertEqual(rc, 2, text)
            self.assertIn("no git repository found", text)
            self.assertFalse((out / config.CONFIG_NAME).exists())

    def test_setup_prints_visibility_and_public_push_warning(self):
        def visibility_gh(answer, rc=0):
            calls = []

            def gh(cmd, **kwargs):
                calls.append(list(cmd))
                return subprocess.CompletedProcess(cmd, rc, answer, "" if rc == 0 else "HTTP 404\n")
            gh.calls = calls
            return gh

        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(Path(tmp))
            out = root / "security"
            out.mkdir()
            (out / config.CONFIG_NAME).write_text("push = true\n")
            subprocess.run(["git", "init", "-q", str(out)], check=True)
            subprocess.run(["git", "-C", str(out), "remote", "add", "origin",
                            "git@github.com:Example-Org/security.git"], check=True)
            gh = visibility_gh("public\n")
            rc, text = run(out, root, gh=gh)
            self.assertEqual(rc, 0, text)
            self.assertIn(["gh", "api", "repos/Example-Org/security", "--jq", ".visibility"], gh.calls)
            self.assertIn("evidence repo visibility: public", text)
            self.assertIn("push = true will be refused", text)

            rc, text = run(out, root, gh=visibility_gh("private\n"))
            self.assertIn("evidence repo visibility: private", text)
            self.assertNotIn("will be refused", text)
            self.assertNotIn("keep this repository private", text)

            rc, text = run(out, root, gh=visibility_gh("", rc=1))
            self.assertIn("evidence repo visibility: unknown", text)
            self.assertIn("keep this repository private", text)

    def test_setup_commits_what_it_wrote_in_its_own_repo(self):
        def git(*args):
            return subprocess.run(["git", "-C", str(out), *args], check=True, text=True,
                                  capture_output=True).stdout
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(Path(tmp))
            out = root / "security"
            out.mkdir()
            git("init", "-q", "-b", "main")
            git("config", "user.email", "test@example.invalid")
            git("config", "user.name", "Test")
            git("config", "commit.gpgsign", "false")
            rc, text = run(out, root)
            self.assertEqual(rc, 0, text)
            self.assertEqual(git("log", "--format=%s").splitlines(), [setup.SETUP_SUBJECT])
            self.assertIn(f"committed {git('rev-parse', '--short', 'HEAD').strip()}", text)
            self.assertEqual(set(git("show", "--name-only", "--format=", "HEAD").split()),
                             {config.CONFIG_NAME, ".gitignore", "CLAUDE.md", "README.md",
                              status.STATUS_JSON,
                              status.STATUS_FILE})
            self.assertEqual(git("status", "--porcelain"), "")
            rc, text = run(out, root)                 # nothing new: no second commit
            self.assertEqual(rc, 0, text)
            self.assertEqual(len(git("log", "--format=%s").splitlines()), 1)
            self.assertEqual(git("status", "--porcelain"), "")

    def test_setup_does_not_commit_with_commit_false_or_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(Path(tmp))
            out = root / "security"
            out.mkdir()
            subprocess.run(["git", "init", "-q", str(out)], check=True)
            (out / config.CONFIG_NAME).write_text("commit = false\n")
            rc, text = run(out, root)
            self.assertEqual(rc, 0, text)
            self.assertNotEqual(subprocess.run(["git", "-C", str(out), "rev-parse", "HEAD"],
                                               capture_output=True).returncode, 0)
            with unittest.mock.patch.dict("os.environ", {"SBOM_AUDIT_READ_ONLY": "1"}):
                buf, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
                    rc = cli.main(["--out", str(out), "setup", "--root", str(root)])
            self.assertEqual(rc, 5)
            self.assertIn("read-only mode: setup writes nothing", err.getvalue())

    def test_setup_stops_when_tool_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(Path(tmp))
            out = root / "security"
            rc, text = run(out, root, which=lambda t: None if t == "osv-scanner" else f"/bin/{t}")
            self.assertEqual(rc, 4)
            self.assertIn("osv-scanner", text)
            self.assertIn(preflight.BREW_LINE, text)
            self.assertFalse(out.exists())

    def test_setup_cli_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(Path(tmp))
            out = root / "security"
            gh = gh_stub()
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                 unittest.mock.patch.object(setup, "gh_run", gh), \
                 unittest.mock.patch.object(setup, "which", ALL_PRESENT):
                rc = cli.main(["--out", str(out), "setup", "--root", str(root), "--init-git",
                               "--enable-dependabot"])
                self.assertEqual(rc, 0, buf.getvalue())
                self.assertTrue((out / ".git").is_dir())
                self.assertEqual(puts(gh), [])          # bare flag lists, --yes acts
                self.assertIn("Dependabot alerts will be enabled on:", buf.getvalue())
                rc = cli.main(["--out", str(out), "setup", "--root", str(root), "--enable-dependabot", "--yes"])
                self.assertEqual([c[-1] for c in puts(gh)], ["repos/Example-Org/Alpha/vulnerability-alerts"])
                rc = cli.main(["--out", str(out), "setup", "--root", str(root), "--enable-dependabot", "fixes",
                               "--yes"])
                self.assertEqual(len(puts(gh)), 3)
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    cli.main(["--out", str(out), "setup", "--enable-dependabot", "bogus"])

    def test_setup_schedule_flag_installs_or_removes_the_timer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(Path(tmp))
            out = root / "security"
            for flag, target in (("weekly", "install_weekly"), ("off", "remove")):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf), \
                     unittest.mock.patch.object(setup, "which", ALL_PRESENT), \
                     unittest.mock.patch.object(setup.scheduler, target, return_value=[f"{target} done"]) as fake:
                    rc = cli.main(["--out", str(out), "setup", "--root", str(root), "--schedule", flag])
                self.assertEqual(rc, 0, buf.getvalue())
                fake.assert_called_once()
                self.assertEqual(fake.call_args.args[0], out.resolve())
                self.assertIn(f"{target} done", buf.getvalue())
            with unittest.mock.patch.object(setup.scheduler, "install_weekly") as fake:
                rc, text = run(out, root)                       # no flag: the scheduler is not touched
            fake.assert_not_called()
            self.assertNotIn("Scheduler:", text)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                cli.build_parser().parse_args(["setup", "--schedule", "daily"])


class BranchWarningTests(unittest.TestCase):
    def test_project_without_a_configured_branch_is_named(self):
        from tests.helpers import make_repo
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "PROJECTS"
            make_repo(root, "shop", {"README.md": "x\n"})
            make_repo(root, "fw", {"README.md": "x\n"}, branches=["main", "develop"])
            subprocess.run(["git", "-C", str(root / "fw"), "branch", "-q", "-m", "main", "master"], check=True)
            cfg = config.load(root / "security", root=root)
            lines = setup.branch_warnings(cfg, config.discover(cfg))
        self.assertEqual(len(lines), 1)
        self.assertIn("warning: fw has none of the branches ['main', 'dev'] and will not be scanned", lines[0])
        self.assertIn("it has develop, master.", lines[0])


if __name__ == "__main__":
    unittest.main()
