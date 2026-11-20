import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import config, gitio
from sbomaudit.errors import ToolError
from sbomaudit.secrets import discovery, scope
from tests.helpers import make_repo

REFSPEC = "+refs/heads/*:refs/heads/*"
GH_ARGV = ["gh", "repo", "list", "owner", "--limit", "1000",
           "--json", "nameWithOwner,isArchived,isFork,isPrivate,sshUrl,url"]


def _gh_entry(slug: str, url: str, fork: bool = False, archived: bool = False,
              https_url: str | None = None) -> dict:
    return {"nameWithOwner": slug, "isArchived": archived, "isFork": fork,
            "isPrivate": True, "sshUrl": url, "url": https_url if https_url is not None else url}


def _gh_stub(entries: list[dict], calls: list | None = None):
    def run(args, **kwargs):
        if calls is not None:
            calls.append(list(args))
        return subprocess.CompletedProcess(args, 0, stdout=json.dumps(entries), stderr="")
    return run


def _recording_git(calls: list, envs: list | None = None):
    def run(args, **kwargs):
        calls.append(list(args))
        if envs is not None:
            envs.append((list(args), kwargs.get("env")))
        return subprocess.run(args, **kwargs)
    return run


class SecretsScopeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()
        self.out = self.tmp / "security"
        self.out.mkdir()
        self.remotes = self.tmp / "remotes"  # no .git: never a portfolio project

    def tearDown(self):
        self._tmp.cleanup()

    def _cfg(self, toml: str = "") -> config.Config:
        (self.out / config.CONFIG_NAME).write_text(toml)
        return config.load(self.out)

    def _branches(self, bare: Path) -> list[str]:
        return gitio.git(bare, "branch", "--format=%(refname:short)").split()

    def test_local_repos_include_ignored_and_skip_backup_and_security(self):
        make_repo(self.tmp, "beta", {"a": "1"})
        make_repo(self.tmp, "alpha", {"a": "1"}, remote="git@github.com:Owner/Alpha.git")
        make_repo(self.tmp, "sbom-audit", {"a": "1"})
        make_repo(self.tmp, "alpha-local-backup-2026", {"a": "1"})
        (self.tmp / "notes").mkdir()
        subprocess.run(["git", "-C", str(self.out), "init", "-q"], check=True)
        cfg = self._cfg('ignore_projects = ["sbom-audit"]\n')
        repos = scope.local_repos(cfg)
        self.assertEqual([(r.name, r.source) for r in repos],
                         [("alpha", "project"), ("beta", "project"), ("sbom-audit", "ignored")])
        self.assertEqual(repos[0].path, self.tmp / "alpha")
        self.assertEqual(repos[0].github, "Owner/Alpha")
        self.assertIsNone(repos[1].github)
        # the SBOM side keeps skipping the ignored project
        self.assertEqual([p.name for p in config.discover(cfg)], ["alpha", "beta"])

    def test_local_repos_single_mode(self):
        repo = make_repo(self.tmp, "solo", {"a": "1"}, remote="https://github.com/Owner/solo")
        cfg = config.load(repo / "security")
        self.assertEqual(scope.local_repos(cfg),
                         [scope.Repo(name="solo", path=repo, github="Owner/solo", source="project")])

    def test_worktrees_counted_once(self):
        alpha = make_repo(self.tmp, "alpha", {"a": "1"})
        subprocess.run(["git", "-C", str(alpha), "worktree", "add", "-q",
                        str(self.tmp / "alpha-wt"), "-b", "wt"], check=True, capture_output=True)
        self.assertTrue((self.tmp / "alpha-wt" / ".git").is_file())
        repos = scope.local_repos(self._cfg())
        self.assertEqual([r.name for r in repos], ["alpha"])

    def test_list_repos_filters_forks_keeps_archived(self):
        entries = [_gh_entry("owner/a", "git@github.com:owner/a.git"),
                   _gh_entry("owner/f", "git@github.com:owner/f.git", fork=True),
                   _gh_entry("owner/old", "git@github.com:owner/old.git", archived=True)]
        calls: list = []
        got = discovery.list_repos("owner", False, gh=_gh_stub(entries, calls))
        self.assertEqual([r["nameWithOwner"] for r in got], ["owner/a", "owner/old"])
        self.assertEqual(calls, [GH_ARGV])
        got = discovery.list_repos("owner", True, gh=_gh_stub(entries))
        self.assertEqual([r["nameWithOwner"] for r in got], ["owner/a", "owner/f", "owner/old"])

    def test_list_repos_without_gh_is_a_tool_error(self):
        def missing(args, **kwargs):
            raise FileNotFoundError(2, "No such file or directory", "gh")

        with self.assertRaises(ToolError) as ctx:
            discovery.list_repos("owner", False, gh=missing)
        self.assertEqual(ctx.exception.tool, "gh")
        self.assertEqual(ctx.exception.detail, "gh not installed")

        def failing(args, **kwargs):
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="\nHTTP 401: Bad credentials\n")

        with self.assertRaises(ToolError) as ctx:
            discovery.list_repos("owner", False, gh=failing)
        self.assertEqual((ctx.exception.returncode, ctx.exception.detail), (1, "HTTP 401: Bad credentials"))

        def garbage(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, stdout="not json", stderr="")

        with self.assertRaises(ToolError) as ctx:
            discovery.list_repos("owner", False, gh=garbage)
        self.assertEqual(ctx.exception.detail, "gh returned invalid JSON")

        make_repo(self.tmp, "alpha", {"a": "1"})
        cfg = self._cfg('[discovery]\ngithub_owner = "owner"\n')
        repos, failures = scope.all_repos(cfg, self.out, gh=missing)
        self.assertEqual([r.name for r in repos], ["alpha"])
        self.assertEqual(failures, [{"repo": "owner/*", "error": "gh not installed"}])

    def test_sync_bare_clones_then_fetches_prune(self):
        src = make_repo(self.remotes, "a", {"app.py": "print(1)\n"})
        calls: list = []
        lines: list = []
        entries = [_gh_entry("owner/a", str(src))]
        repos, failures = discovery.sync(self.out, entries, git=_recording_git(calls), log=lines.append)
        bare = self.out / ".cache" / "repos" / "owner__a.git"
        self.assertEqual(failures, [])
        self.assertEqual(repos, [discovery.Repo(name="owner/a", path=bare, github="owner/a",
                                                source="discovered")])
        self.assertEqual(calls, [["git", "clone", "--bare", "--quiet", "--", str(src), str(bare)],
                                 ["git", "-C", str(bare), "config", "remote.origin.fetch", REFSPEC]])
        self.assertEqual(self._branches(bare), ["main"])

        subprocess.run(["git", "-C", str(src), "branch", "feature"], check=True)
        calls.clear()
        repos, failures = discovery.sync(self.out, entries, git=_recording_git(calls), log=lines.append)
        self.assertEqual((len(repos), failures), (1, []))
        self.assertEqual(calls, [["git", "-C", str(bare), "rev-parse", "--is-bare-repository"],
                                 ["git", "-C", str(bare), "fetch", "--prune", "--quiet", "origin", REFSPEC]])
        self.assertEqual(self._branches(bare), ["feature", "main"])
        self.assertEqual(lines, ["cloned owner/a", "fetched owner/a"])

        subprocess.run(["git", "-C", str(src), "branch", "-D", "feature"], check=True, capture_output=True)
        discovery.sync(self.out, entries)
        self.assertEqual(self._branches(bare), ["main"])  # pruned

    def test_clone_failure_is_reported_and_others_continue(self):
        good = make_repo(self.remotes, "good", {"a": "1"})
        entries = [_gh_entry("owner/bad", str(self.remotes / "missing")),
                   _gh_entry("owner/good", str(good))]
        repos, failures = discovery.sync(self.out, entries)
        self.assertEqual([r.name for r in repos], ["owner/good"])
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["repo"], "owner/bad")
        self.assertTrue(failures[0]["error"])
        self.assertFalse((self.out / ".cache" / "repos" / "owner__bad.git").exists())
        self.assertTrue((self.out / ".cache" / "repos" / "owner__good.git").is_dir())

    def test_existing_clone_survives_failed_fetch(self):
        src = make_repo(self.remotes, "a", {"a": "1"})
        entries = [_gh_entry("owner/a", str(src))]
        discovery.sync(self.out, entries)
        bare = config.bare_clone_path(self.out, "owner/a")
        shutil.rmtree(src)
        repos, failures = discovery.sync(self.out, entries)
        self.assertEqual(repos, [])
        self.assertEqual([f["repo"] for f in failures], ["owner/a"])
        self.assertTrue(failures[0]["error"])
        self.assertEqual(self._branches(bare), ["main"])

    def test_sync_timeout_is_a_failure(self):
        def slow(args, **kwargs):
            raise subprocess.TimeoutExpired(args, kwargs.get("timeout"))

        repos, failures = discovery.sync(self.out, [_gh_entry("owner/a", str(self.remotes / "a"))], git=slow)
        self.assertEqual((repos, failures), ([], [{"repo": "owner/a", "error": "timed out"}]))
        self.assertFalse(config.bare_clone_path(self.out, "owner/a").exists())

    def test_failure_errors_carry_no_credentials(self):
        stderr = "\nfatal: unable to access 'https://user:tok3n@example.invalid/x.git/': Could not resolve host\n"

        def failing(args, **kwargs):
            return subprocess.CompletedProcess(args, 128, stdout="", stderr=stderr)

        _, failures = discovery.sync(self.out, [_gh_entry("owner/x", "https://example.invalid/x.git")],
                                     git=failing)
        self.assertEqual(len(failures), 1)
        self.assertTrue("tok3n" not in failures[0]["error"], "clone failure carries a credential")
        self.assertTrue("//***@example.invalid" in failures[0]["error"], "clone failure not scrubbed")
        with self.assertRaises(ToolError) as ctx:
            discovery.list_repos("owner", False, gh=failing)
        self.assertTrue("tok3n" not in ctx.exception.detail, "gh failure carries a credential")

    def test_scrub_drops_token_userinfo_from_https_url(self):
        url = "https://x-access-token:ghs_EXAMPLE_not_a_real_token@github.com/o/r.git"
        text = discovery._scrub(f"fatal: unable to access '{url}/': Could not resolve host")
        self.assertTrue("x-access-token:" not in text, "scrubbed text still names the credential user")
        self.assertTrue("EXAMPLE_not_a_real_token" not in text, "scrubbed text still carries the token")
        self.assertIn("https://***@github.com/o/r.git", text)

    def test_sync_clones_the_url_of_the_chosen_protocol(self):
        src = make_repo(self.remotes, "a", {"a": "1"})
        entry = _gh_entry("owner/a", "git@github.invalid:owner/a.git", https_url=str(src))
        calls: list = []
        repos, failures = discovery.sync(self.out, [entry], git=_recording_git(calls), protocol="https")
        self.assertEqual(failures, [])
        self.assertEqual([r.name for r in repos], ["owner/a"])
        self.assertEqual([c[-2] for c in calls if c[1] == "clone"], [str(src)])

        calls.clear()
        entry = _gh_entry("owner/b", str(src), https_url="https://github.invalid/owner/b.git")
        repos, failures = discovery.sync(self.out, [entry], git=_recording_git(calls), protocol="ssh")
        self.assertEqual(failures, [])
        self.assertEqual([c[-2] for c in calls if c[1] == "clone"], [str(src)])

    def test_sync_without_clone_url_is_a_failure(self):
        entry = {"nameWithOwner": "owner/a", "sshUrl": "git@github.invalid:owner/a.git"}
        repos, failures = discovery.sync(self.out, [entry], git=_recording_git([]), protocol="https")
        self.assertEqual((repos, failures), ([], [{"repo": "owner/a", "error": "no clone url"}]))
        self.assertFalse(config.bare_clone_path(self.out, "owner/a").exists())

    def test_sync_network_commands_never_prompt(self):
        src = make_repo(self.remotes, "a", {"a": "1"})
        entries = [_gh_entry("owner/a", str(src))]
        envs: list = []
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GIT_SSH_COMMAND", None)
            os.environ.pop("GIT_SSH", None)
            discovery.sync(self.out, entries, git=_recording_git([], envs))
            discovery.sync(self.out, entries, git=_recording_git([], envs))
        net = {tuple(args): env for args, env in envs if args[1] == "clone" or "fetch" in args}
        self.assertEqual(len(net), 2, "one clone and one fetch")
        for env in net.values():
            self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
            self.assertEqual(env["GIT_SSH_COMMAND"], "ssh -oBatchMode=yes")

    def test_sync_every_git_command_gets_the_hardening_config(self):
        entries = [{"nameWithOwner": "acme/one", "sshUrl": "git@example.invalid:acme/one.git"}]
        envs: list = []
        discovery.sync(self.out, entries, git=_recording_git([], envs))
        discovery.sync(self.out, entries, git=_recording_git([], envs))
        self.assertTrue(envs)
        for args, env in envs:
            self.assertIsNotNone(env, args)
            self.assertEqual(env.get("GIT_CONFIG_KEY_1"), "core.hooksPath", args)

    def test_sync_with_fetch_false_keeps_existing_clones_and_clones_missing_ones(self):
        a = make_repo(self.remotes, "a", {"a": "1"})
        b = make_repo(self.remotes, "b", {"b": "1"})
        discovery.sync(self.out, [_gh_entry("owner/a", str(a))])
        subprocess.run(["git", "-C", str(a), "branch", "feature"], check=True)
        calls: list = []
        lines: list = []
        repos, failures = discovery.sync(self.out, [_gh_entry("owner/a", str(a)), _gh_entry("owner/b", str(b))],
                                         git=_recording_git(calls), log=lines.append, fetch=False)
        self.assertEqual(failures, [])
        self.assertEqual([r.name for r in repos], ["owner/a", "owner/b"])
        self.assertEqual(lines, ["kept owner/a", "cloned owner/b"])
        self.assertFalse([c for c in calls if "fetch" in c and c[1] == "-C"], "fetch = false still fetched")
        self.assertEqual(self._branches(config.bare_clone_path(self.out, "owner/a")), ["main"])

    def test_stale_clone_dir_is_recloned(self):
        src = make_repo(self.remotes, "x", {"a": "1"})
        subprocess.run(["git", "-C", str(self.out), "init", "-q"], check=True)  # like `setup --init-git`
        stale = config.bare_clone_path(self.out, "owner/x")
        stale.mkdir(parents=True)
        lines: list = []
        repos, failures = discovery.sync(self.out, [_gh_entry("owner/x", str(src))], log=lines.append)
        self.assertEqual((len(repos), failures), (1, []))
        self.assertEqual(lines, ["recloned owner/x"])
        self.assertEqual(gitio.git(stale, "rev-parse", "--is-bare-repository").strip(), "true")
        self.assertEqual(self._branches(stale), ["main"])

    def test_unwritable_cache_is_a_failure(self):
        (self.out / ".cache").mkdir()
        (self.out / ".cache" / "repos").write_text("not a folder")
        repos, failures = discovery.sync(self.out, [_gh_entry("owner/a", str(self.remotes / "a"))])
        self.assertEqual(repos, [])
        self.assertEqual([f["repo"] for f in failures], ["owner/a"])
        self.assertTrue(failures[0]["error"])

    def test_clone_sets_fetch_refspec(self):
        src = make_repo(self.remotes, "a", {"a": "1"})
        discovery.sync(self.out, [_gh_entry("owner/a", str(src))])
        bare = config.bare_clone_path(self.out, "owner/a")
        self.assertEqual(gitio.git(bare, "config", "--get", "remote.origin.fetch").strip(), REFSPEC)
        subprocess.run(["git", "-C", str(src), "branch", "feature"], check=True)
        gitio.git(bare, "fetch", "--quiet", "--prune", "origin")  # what scan's fetch_origin runs
        self.assertEqual(self._branches(bare), ["feature", "main"])

    def test_sync_rejects_unsafe_slug_without_crashing(self):
        good = make_repo(self.remotes, "good", {"a": "1"})
        entries = [_gh_entry("owner/../../escape", str(good)), _gh_entry("owner/good", str(good))]
        repos, failures = discovery.sync(self.out, entries)
        self.assertEqual([r.name for r in repos], ["owner/good"])
        self.assertEqual([f["repo"] for f in failures], ["owner/../../escape"])
        self.assertFalse((self.tmp / "escape").exists())

    def test_bare_clone_path_validates_slug(self):
        self.assertEqual(config.bare_clone_path(self.out, "Owner/repo.js"),
                         self.out / ".cache" / "repos" / "owner__repo.js.git")
        self.assertEqual(config.bare_clone_path(self.out, "OWNER/Lib"), config.bare_clone_path(self.out, "owner/lib"))
        for bad in ("owner", "owner/a/b", "/repo", "owner/", "owner/..", "../repo", "owner/a b",
                    "owner/a\\b", "owner/a\tb", ""):
            with self.subTest(slug=bad), self.assertRaises(ValueError) as ctx:
                config.bare_clone_path(self.out, bad)
            self.assertNotEqual(str(ctx.exception), bad)

    def test_all_repos_dedups_by_slug_local_wins(self):
        make_repo(self.tmp, "alpha", {"a": "1"}, remote="git@github.com:Owner/Alpha.git")
        src = make_repo(self.remotes, "alpha", {"a": "1"})
        other = make_repo(self.remotes, "beta", {"b": "1"})
        cfg = self._cfg('[discovery]\ngithub_owner = "owner"\n')
        calls: list = []
        gh = _gh_stub([_gh_entry("owner/alpha", str(src)), _gh_entry("owner/beta", str(other))])
        repos, failures = scope.all_repos(cfg, self.out, gh=gh, git=_recording_git(calls))
        self.assertEqual(failures, [])
        self.assertEqual([(r.name, r.source) for r in repos],
                         [("alpha", "project"), ("owner/beta", "discovered")])
        self.assertEqual(repos[0].path, self.tmp / "alpha")
        self.assertEqual([c[-1] for c in calls if c[1] == "clone"],  # only beta is cloned
                         [str(config.bare_clone_path(self.out, "owner/beta"))])
        self.assertFalse((self.out / ".cache" / "repos" / "owner__alpha.git").exists())

    def test_github_only_project_is_scannable_by_export_ref(self):
        make_repo(self.tmp, "alpha", {"a": "1"})
        source_repo = make_repo(self.remotes, "lib", {"lib.py": "VALUE = 1\n"})
        cfg = self._cfg('[projects."lib"]\ngithub = "owner/lib"\nproduction = true\n')
        self.assertEqual([p.name for p in config.discover(cfg)], ["alpha"])

        lines: list = []
        repos, failures = scope.all_repos(cfg, self.out, gh=_gh_stub([]), log=lines.append,
                                          clone_url=lambda slug: str(source_repo))
        bare = config.bare_clone_path(self.out, "owner/lib")
        self.assertEqual(failures, [])
        self.assertEqual(repos, [scope.Repo("alpha", self.tmp / "alpha", None, "project"),
                                 scope.Repo("lib", bare, "owner/lib", "github")])
        self.assertEqual(lines, ["cloned owner/lib"])

        projects = config.discover(cfg)
        self.assertEqual([(p.name, p.path) for p in projects], [("alpha", self.tmp / "alpha"), ("lib", bare)])
        self.assertTrue(projects[1].production)
        self.assertEqual(projects[1].remote, str(source_repo))
        dest = self.tmp / "export"
        gitio.export_ref(projects[1].path, "main", dest)
        self.assertEqual((dest / "lib.py").read_text(), "VALUE = 1\n")

    def test_github_only_project_uses_discovered_ssh_url(self):
        source_repo = make_repo(self.remotes, "lib", {"lib.py": "VALUE = 1\n"})
        cfg = self._cfg('[discovery]\ngithub_owner = "owner"\n[projects."lib"]\ngithub = "Owner/Lib"\n')
        gh = _gh_stub([_gh_entry("owner/lib", str(source_repo))])
        # a clone made earlier as a discovered repo is the same folder: fetched, not cloned again
        discovery.sync(self.out, [_gh_entry("owner/lib", str(source_repo))])
        lines: list = []
        repos, failures = scope.all_repos(cfg, self.out, gh=gh, log=lines.append,
                                          clone_url=lambda slug: str(self.remotes / "nowhere"))
        self.assertEqual(failures, [])
        self.assertEqual([(r.name, r.github, r.source) for r in repos], [("lib", "Owner/Lib", "github")])
        self.assertEqual(repos[0].path, self.out / ".cache" / "repos" / "owner__lib.git")
        self.assertEqual(lines, ["fetched Owner/Lib"])
        self.assertEqual(sorted(p.name for p in (self.out / ".cache" / "repos").iterdir()), ["owner__lib.git"])
        self.assertEqual([p.path for p in config.discover(cfg)], [repos[0].path])

    def test_all_repos_honours_fetch_false(self):
        src = make_repo(self.remotes, "a", {"a": "1"})
        discovery.sync(self.out, [_gh_entry("owner/a", str(src))])
        cfg = self._cfg('fetch = false\n[discovery]\ngithub_owner = "owner"\n')
        calls: list = []
        lines: list = []
        repos, failures = scope.all_repos(cfg, self.out, gh=_gh_stub([_gh_entry("owner/a", str(src))]),
                                          git=_recording_git(calls), log=lines.append)
        self.assertEqual(failures, [])
        self.assertEqual([r.name for r in repos], ["owner/a"])
        self.assertEqual(lines, ["kept owner/a"])
        self.assertFalse([c for c in calls if "fetch" in c], "fetch = false still fetched")

    def test_all_repos_clones_over_https_when_configured(self):
        src = make_repo(self.remotes, "lib", {"a": "1"})
        cfg = self._cfg('[discovery]\ngithub_owner = "owner"\nprotocol = "https"\n'
                        '[projects."lib"]\ngithub = "owner/lib"\n')
        listed = [_gh_entry("owner/lib", "git@github.invalid:owner/lib.git", https_url=str(src)),
                  _gh_entry("owner/other", "git@github.invalid:owner/other.git", https_url=str(src))]
        calls: list = []
        repos, failures = scope.all_repos(cfg, self.out, gh=_gh_stub(listed), git=_recording_git(calls))
        self.assertEqual(failures, [])
        self.assertEqual([(r.name, r.source) for r in repos], [("lib", "github"), ("owner/other", "discovered")])
        self.assertEqual([c[-2] for c in calls if c[1] == "clone"], [str(src), str(src)])

    def test_default_clone_url_per_protocol(self):
        self.assertEqual(scope._default_clone_url("o/r"), "git@github.com:o/r.git")
        self.assertEqual(scope._default_clone_url("o/r", "ssh"), "git@github.com:o/r.git")
        self.assertEqual(scope._default_clone_url("o/r", "https"), "https://github.com/o/r.git")

    def test_github_only_project_default_url_follows_protocol(self):
        cfg = self._cfg('[discovery]\nprotocol = "https"\n[projects."lib"]\ngithub = "owner/lib"\n')
        seen: list = []

        def failing(args, **kwargs):
            seen.append(list(args))
            return subprocess.CompletedProcess(args, 128, stdout="", stderr="fatal: no\n")

        repos, failures = scope.all_repos(cfg, self.out, gh=_gh_stub([]), git=failing)
        self.assertEqual([r.name for r in repos], [])
        self.assertEqual([f["repo"] for f in failures], ["owner/lib"])
        self.assertEqual([c[-2] for c in seen if c[1] == "clone"], ["https://github.com/owner/lib.git"])

    def test_scope_reexports_repo(self):
        self.assertIs(scope.Repo, discovery.Repo)


if __name__ == "__main__":
    unittest.main()
