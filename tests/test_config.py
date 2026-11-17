import contextlib
import hashlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sbomaudit import cli, config
from sbomaudit.errors import ConfigError
from tests.helpers import make_repo


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()

    def tearDown(self):
        self._tmp.cleanup()

    def test_detect_single_vs_portfolio(self):
        repo = make_repo(self.tmp, "one", {"README.md": "x"})
        self.assertEqual(config.detect_mode(repo / "security"), "single")
        self.assertEqual(config.detect_mode(self.tmp / "security"), "portfolio")

    def test_defaults_when_config_missing(self):
        cfg = config.load(self.tmp / "security")
        self.assertEqual(cfg.branches, ["main", "dev"])
        self.assertTrue(cfg.fetch)
        self.assertEqual(cfg.ignore_projects, [])
        self.assertEqual(cfg.root, self.tmp)
        self.assertEqual(cfg.mode, "portfolio")

    def test_load_reads_toml(self):
        out = self.tmp / "security"
        out.mkdir()
        (out / "sbom-audit.toml").write_text(
            'branches = ["main"]\nignore_projects = ["sbom-audit"]\nfetch = false\n'
            '[projects]\n"scanner-api" = { production = true }\n'
            '"mobile-app" = { ignore = ["targets/"] }\n'
        )
        cfg = config.load(out)
        self.assertEqual(cfg.branches, ["main"])
        self.assertFalse(cfg.fetch)
        self.assertEqual(cfg.ignore_projects, ["sbom-audit"])
        self.assertTrue(cfg.projects["scanner-api"].production)
        self.assertEqual(cfg.projects["mobile-app"].ignore, ["targets/"])

    def test_discover_skips_ignored_and_backups(self):
        make_repo(self.tmp, "beta", {"a": "1"})
        make_repo(self.tmp, "alpha", {"a": "1"}, remote="git@github.com:Example-Org/alpha.git")
        make_repo(self.tmp, "sbom-audit", {"a": "1"})
        make_repo(self.tmp, "alpha-local-backup-2026", {"a": "1"})
        (self.tmp / "notes").mkdir()  # plain folder, no .git
        out = self.tmp / "security"
        out.mkdir()
        (out / "sbom-audit.toml").write_text(
            'ignore_projects = ["sbom-audit"]\n[projects]\n"beta" = { production = true }\n'
        )
        cfg = config.load(out)
        projects = config.discover(cfg)
        self.assertEqual([p.name for p in projects], ["alpha", "beta"])
        self.assertEqual(projects[0].remote, "git@github.com:Example-Org/alpha.git")
        self.assertIsNone(projects[1].remote)
        self.assertTrue(projects[1].production)
        self.assertFalse(projects[0].production)

    def test_discover_skips_the_output_folder(self):
        """After `setup --init-git` the security folder is itself a git repo; it is never a project."""
        make_repo(self.tmp, "alpha", {"a": "1"})
        out = make_repo(self.tmp, "security", {"AUDIT.md": "# audit\n"})
        (out / "sbom-audit.toml").write_text("")
        cfg = config.load(out)
        self.assertEqual([p.name for p in config.discover(cfg)], ["alpha"])

    def test_discover_single_mode(self):
        repo = make_repo(self.tmp, "solo", {"a": "1"})
        cfg = config.load(repo / "security")
        projects = config.discover(cfg)
        self.assertEqual([(p.name, p.path) for p in projects], [("solo", repo)])

    def test_project_purl_github_and_generic(self):
        gh = config.Project(name="alpha", path=self.tmp, remote="git@github.com:Example-Org/alpha.git")
        https = config.Project(name="alpha", path=self.tmp, remote="https://github.com/Example-Org/Alpha-Repo.git")
        plain = config.Project(name="Client Portal Web", path=self.tmp, remote=None)
        self.assertEqual(config.project_purl(gh), "pkg:github/example-org/alpha")
        self.assertEqual(config.project_purl(https), "pkg:github/example-org/alpha-repo")
        self.assertEqual(config.project_purl(plain), "pkg:generic/Client%20Portal%20Web")

    def test_write_default_is_idempotent(self):
        out = self.tmp / "security"
        cfg = config.load(out)
        path = config.write_default(out, cfg)
        self.assertTrue(path.exists())
        first = path.read_text()
        self.assertIn('branches = ["main", "dev"]', first)
        path.write_text(first + "\n# edited\n")
        config.write_default(out, cfg)
        self.assertIn("# edited", path.read_text())

    def _write_toml(self, text):
        out = self.tmp / "security"
        out.mkdir(exist_ok=True)
        (out / "sbom-audit.toml").write_text(text)
        return out

    def test_load_release1_keys(self):
        out = self._write_toml(
            'commit = false\npush = true\n[discovery]\ngithub_owner = "Example-Org"\n'
            'include_forks = true\n[schedule]\nassess = true\nassess_budget_usd = 2.5\n'
            '[secrets]\nenabled = false\n[projects."alpha"]\ngithub = "Example-Org/alpha"\n')
        cfg = config.load(out)
        self.assertFalse(cfg.commit)
        self.assertTrue(cfg.push)
        self.assertEqual(cfg.discovery, config.Discovery("Example-Org", True))
        self.assertEqual(cfg.schedule, config.Schedule(True, 2.5))
        self.assertFalse(cfg.secrets.enabled)
        self.assertEqual(cfg.projects["alpha"].github, "Example-Org/alpha")

    def test_defaults_when_keys_absent(self):
        cfg = config.load(self._write_toml("branches = ['main']\n"))
        self.assertTrue(cfg.commit)
        self.assertFalse(cfg.push)
        self.assertEqual(cfg.discovery, config.Discovery())
        self.assertFalse(cfg.schedule.assess)
        self.assertEqual(cfg.schedule.assess_budget_usd, 5.0)
        self.assertTrue(cfg.secrets.enabled)

    def test_write_default_mentions_new_tables_commented(self):
        out = self.tmp / "security"
        cfg = config.load(out)
        text = config.write_default(out, cfg, []).read_text()
        for needle in ("commit = true", "push = false", "# [discovery]", "# github_owner",
                       "# [schedule]", "# assess = false", "# [secrets]", "# enabled = true"):
            self.assertIn(needle, text)

    def test_discovery_protocol_default_toml_and_env(self):
        out = self._write_toml('[discovery]\ngithub_owner = "o"\n')
        self.assertEqual(config.load(out).discovery.protocol, "ssh")
        self.assertEqual(config.load(out, env={}).discovery.protocol, "ssh")
        self.assertEqual(config.load(out, env={"SBOM_AUDIT_GIT_PROTOCOL": "https"}).discovery.protocol, "https")
        self.assertEqual(config.load(out, env={"SBOM_AUDIT_GIT_PROTOCOL": ""}).discovery.protocol, "ssh")
        with patch.dict(os.environ, {"SBOM_AUDIT_GIT_PROTOCOL": "https"}):
            self.assertEqual(config.load(out).discovery.protocol, "https")
        out = self._write_toml('[discovery]\nprotocol = "https"\n')
        self.assertEqual(config.load(out, env={}).discovery.protocol, "https")
        self.assertEqual(config.load(out, env={"SBOM_AUDIT_GIT_PROTOCOL": "ssh"}).discovery.protocol, "ssh")

    def test_discovery_protocol_rejects_other_values(self):
        out = self._write_toml('[discovery]\nprotocol = "git"\n')
        with self.assertRaises(ConfigError) as ctx:
            config.load(out, env={})
        self.assertEqual(str(ctx.exception), '[discovery] protocol must be "ssh" or "https"')
        out = self._write_toml("")
        with self.assertRaises(ConfigError) as ctx:
            config.load(out, env={"SBOM_AUDIT_GIT_PROTOCOL": "HTTPS"})
        self.assertEqual(str(ctx.exception), 'SBOM_AUDIT_GIT_PROTOCOL must be "ssh" or "https"')

    def test_wrong_value_kinds_are_config_errors(self):
        cases = {
            'fetch = "yes"\n': "fetch must be true or false",
            "commit = 1\n": "commit must be true or false",
            'push = "false"\n': "push must be true or false",
            "[discovery]\ninclude_forks = 1\n": "[discovery] include_forks must be true or false",
            '[schedule]\nassess = "on"\n': "[schedule] assess must be true or false",
            '[schedule]\nassess_budget_usd = "5"\n': "[schedule] assess_budget_usd must be a number",
            "[schedule]\nassess_budget_usd = true\n": "[schedule] assess_budget_usd must be a number",
            "[schedule]\nassess_budget_usd = 0\n": "[schedule] assess_budget_usd must be a number greater than 0",
            "[secrets]\nenabled = 0\n": "[secrets] enabled must be true or false",
            '[projects."alpha"]\nproduction = "true"\n': '[projects."alpha"] production must be true or false',
        }
        for toml, message in cases.items():
            with self.subTest(toml=toml):
                out = self._write_toml(toml)
                with self.assertRaises(ConfigError) as ctx:
                    config.load(out, env={})
                self.assertEqual(str(ctx.exception), message)
        self.assertEqual(config.load(self._write_toml("[schedule]\nassess_budget_usd = 3\n"),
                                     env={}).schedule.assess_budget_usd, 3.0)

    def test_cli_reports_config_error_without_traceback(self):
        out = self._write_toml('fetch = "yes"\n')
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(["scan", "--out", str(out), "--root", str(self.tmp)])
        self.assertEqual(code, 2)
        self.assertEqual(err.getvalue().strip(), "sbom-audit.toml: fetch must be true or false")

    def test_read_only_env_blocks_writing_commands(self):
        out = self.tmp / "security"
        err = io.StringIO()
        with patch.dict(os.environ, {"SBOM_AUDIT_READ_ONLY": "1"}), contextlib.redirect_stderr(err), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(config.read_only())
            self.assertEqual(cli.main(["vex", "add", "p", "CVE-1", "fixed", "--out", str(out)]), 5)
            self.assertEqual(cli.main(["incident", "CVE-1", "--vex", "--out", str(out)]), 5)
            self.assertNotEqual(cli.main(["lookup", "x", "--out", str(out)]), 5)
        self.assertIn("read-only mode: vex writes nothing", err.getvalue())
        self.assertIn("read-only mode: incident writes nothing", err.getvalue())
        self.assertFalse(out.exists())
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SBOM_AUDIT_READ_ONLY", None)
            self.assertFalse(config.read_only())

    def _load_hosts(self, toml: str):
        out = self.tmp / "security"
        out.mkdir(exist_ok=True)
        (out / "sbom-audit.toml").write_text(toml)
        return config.load(out)

    def test_hosts_absent_is_inactive(self):
        cfg = self._load_hosts("")
        self.assertFalse(cfg.hosts.active)
        self.assertEqual(cfg.hosts.servers, {})

    def test_hosts_parsed(self):
        cfg = self._load_hosts(
            '[hosts]\nenabled = true\n\n'
            '[hosts.servers."box-a"]\n'
            'address = "203.0.113.10"\nadmin = "root@203.0.113.10"\n'
            'production = true\nprojects = ["Example Project"]\n\n'
            '[hosts.servers."box-b"]\naddress = "203.0.113.11"\n'
        )
        hosts = cfg.hosts
        self.assertTrue(hosts.active)
        self.assertEqual(hosts.concurrency, 4)
        self.assertEqual(hosts.timeout_minutes, 10)
        self.assertEqual(hosts.key, Path.home() / ".ssh/sbom-audit_ed25519")
        a = hosts.servers["box-a"]
        self.assertEqual(a.address, "203.0.113.10")
        self.assertEqual(a.admin, "root@203.0.113.10")
        self.assertTrue(a.production)
        self.assertEqual(a.projects, ["Example Project"])
        b = hosts.servers["box-b"]
        self.assertIsNone(b.admin)
        self.assertFalse(b.production)
        self.assertEqual(b.projects, [])

    def test_hosts_options_and_key_expansion(self):
        cfg = self._load_hosts(
            '[hosts]\nenabled = true\nconcurrency = 2\ntimeout_minutes = 5\n'
            'key = "~/.ssh/other_key"\n'
            '[hosts.servers."box-a"]\naddress = "203.0.113.10"\n'
        )
        self.assertEqual(cfg.hosts.concurrency, 2)
        self.assertEqual(cfg.hosts.timeout_minutes, 5)
        self.assertEqual(cfg.hosts.key, Path.home() / ".ssh/other_key")

    def test_hosts_bad_values(self):
        server = '[hosts.servers."box-a"]\naddress = "203.0.113.10"\n'
        cases = [
            ("[hosts] concurrency must be", '[hosts]\nconcurrency = 0\n' + server),
            ("[hosts] timeout_minutes must be", '[hosts]\ntimeout_minutes = "x"\n' + server),
            ("address is required", '[hosts.servers."box-a"]\nadmin = "root@203.0.113.10"\n'),
            ("address must be a non-empty string", '[hosts.servers."box-a"]\naddress = ""\n'),
            ("host name must match", '[hosts.servers."bad/name"]\naddress = "203.0.113.10"\n'),
            ("host name must match", '[hosts.servers."-x"]\naddress = "203.0.113.10"\n'),
            ("host name must match", '[hosts.servers.".x"]\naddress = "203.0.113.10"\n'),
            ("host name must match", '[hosts.servers.".."]\naddress = "203.0.113.10"\n'),
            ("admin must be a login", server + 'admin = "-oProxyCommand=x"\n'),
            ("admin must be a login", server + 'admin = "root @203.0.113.10"\n'),
            ("admin must be a login", server + 'admin = "root@203.0.113.10\\t"\n'),
            ("admin must be a login", server + 'admin = "root@203.0.113.10\\u0001"\n'),
            ("admin must be a non-empty string", server + 'admin = 5\n'),
            ("[hosts] enabled must be true or false", '[hosts]\nenabled = "yes"\n' + server),
            ("projects must be a list", '[hosts.servers."box-a"]\naddress = "203.0.113.10"\nprojects = "x"\n'),
            ("production must be true or false", '[hosts.servers."box-a"]\naddress = "203.0.113.10"\nproduction = "yes"\n'),
            ("[hosts] key must be a non-empty string", '[hosts]\nkey = 5\n' + server),
            ("[hosts] must be a table", 'hosts = []\n'),
            ("[hosts] must be a table", 'hosts = false\n'),
            ("[hosts.servers] must be a table", '[hosts]\nservers = []\n'),
        ]
        for phrase, toml in cases:
            with self.subTest(phrase=phrase), self.assertRaises(ConfigError) as ctx:
                self._load_hosts(toml)
            self.assertIn(phrase, str(ctx.exception))

    def test_host_name_rule_matches_the_store_and_admin_rule_matches_transport(self):
        from sbomaudit.hosts import store, transport
        for name in ["web-1", "a", "A.b_c-9", "-x", ".x", "..", "_x", "a/b", "a b"]:
            toml = f'[hosts.servers."{name}"]\naddress = "203.0.113.10"\n'
            with self.subTest(name=name):
                try:
                    store.check_host(name)
                    store_ok = True
                except ValueError:
                    store_ok = False
                try:
                    self._load_hosts(toml)
                    config_ok = True
                except ConfigError:
                    config_ok = False
                self.assertEqual(config_ok, store_ok)
        for admin in ["root@203.0.113.10", "web-1-admin", "-oProxyCommand=x", "a b"]:
            toml = f'[hosts.servers."box-a"]\naddress = "203.0.113.10"\nadmin = "{admin}"\n'
            with self.subTest(admin=admin):
                try:
                    transport.admin_argv(admin)
                    argv_ok = True
                except ValueError:
                    argv_ok = False
                try:
                    self._load_hosts(toml)
                    config_ok = True
                except ConfigError:
                    config_ok = False
                self.assertEqual(config_ok, argv_ok)

    def test_hosts_enabled_false_is_inactive_even_with_servers(self):
        cfg = self._load_hosts(
            '[hosts]\nenabled = false\n[hosts.servers."box-a"]\naddress = "203.0.113.10"\n'
        )
        self.assertEqual(list(cfg.hosts.servers), ["box-a"])
        self.assertFalse(cfg.hosts.active)

    def test_hosts_enabled_without_servers_is_inactive(self):
        self.assertFalse(self._load_hosts("[hosts]\nenabled = true\n").hosts.active)


class CommitRefusalTests(unittest.TestCase):
    """Whether a run may commit the sbom-audit.toml it read: never one that could hold a credential."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.out = Path(self._tmp.name).resolve() / "security"
        self.out.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, text: str) -> str:
        (self.out / config.CONFIG_NAME).write_text(text)
        return hashlib.sha256(text.encode()).hexdigest()

    def test_the_config_read_by_the_run_may_be_committed(self):
        self.write('branches = ["main"]\n[assess]\napi_key_env = "MY_KEY"\n')
        cfg = config.load(self.out)
        self.assertRegex(cfg.digest or "", r"^[0-9a-f]{64}$")
        self.assertIsNone(config.commit_refusal(self.out, cfg.digest))

    def test_not_read_changed_or_linked(self):
        self.assertEqual(config.commit_refusal(self.out, None), "not read by this run")
        digest = self.write('branches = ["main"]\n')
        self.write('branches = ["dev"]\n')
        self.assertIn("changed during the run", config.commit_refusal(self.out, digest))
        real = self.out.parent / "elsewhere.toml"
        real.write_text('branches = ["main"]\n')
        (self.out / config.CONFIG_NAME).unlink()
        (self.out / config.CONFIG_NAME).symlink_to(real)
        self.assertEqual(config.commit_refusal(self.out, digest), "not read by this run")

    def test_credential_like_keys_and_values_are_refused_by_name_only(self):
        token = "gh" + "p_" + "x" * 36                      # built at runtime: no token-like literal in the repo
        cases = {
            f'[discovery]\ngithub_owner = "me"\n[extra]\ntoken = "{token}"\n': "extra.token",
            '[extra]\ndb_password = "hunter"\n': "extra.db_password",
            f'[extra]\nnote = "{token}"\n': "extra.note",
            '[extra]\nmirror = "https://user:pa55@example.invalid/x"\n': "extra.mirror",
        }
        for text, key in cases.items():
            reason = config.commit_refusal(self.out, self.write(text))
            self.assertIsNotNone(reason, key)
            self.assertIn(key, reason)
            self.assertIn("credential", reason)
            for secret in (token, "hunter", "pa55"):
                self.assertNotIn(secret, reason)

    def test_documented_names_are_not_mistaken_for_credentials(self):
        data = {"branches": ["main"], "commit": True, "push": False,
                "assess": {"api_key_env": "X", "api_key_file": "~/.config/key",
                           "base_url": "https://api.example.invalid"},
                "hosts": {"key": "~/.ssh/id_audit"}, "discovery": {"github_owner": "me", "protocol": "ssh"},
                "projects": {"author": {"production": True}, "auth-service": {"production": True},
                             "token-api": {"ignore": ["x"]}}}
        self.assertEqual(config._secret_like(data), [])


if __name__ == "__main__":
    unittest.main()
