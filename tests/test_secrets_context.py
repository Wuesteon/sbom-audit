"""Context of a secret finding: value shape (a key header without a key, a placeholder, a name) and path
context (tests, fixtures, examples, docs, vendored code, data files, dev setups), and what both do to the
class, the totals, SECRETS.md and the work list.

Values here are synthetic and built at run time (none is a planted fixture value); assertions use fixed
messages and never print a value.
"""
from __future__ import annotations

import base64
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

from sbomaudit import config, issues
from sbomaudit.errors import ConfigError
from sbomaudit.secrets import classify as cl
from sbomaudit.secrets import report as secrets_report
from sbomaudit.secrets import findings
from tests.secrets_fixture import PLANTED

CLASSES = cl.load_classes()
RULES = cl.context_rules(CLASSES)
GUARD = Path(__file__).resolve().parent.parent / "plugin" / "templates" / "guard" / "guard.py"


def pem(lines: int = 6, escaped: bool = False) -> str:
    """A synthetic PEM block with a random body (not a key anyone holds)."""
    raw = base64.b64encode(os.urandom(48 * lines)).decode()
    body = [raw[i:i + 64] for i in range(0, len(raw), 64)]
    sep = "\\n" if escaped else "\n"
    return sep.join(["-----BEGIN RSA PRIVATE KEY-----", *body, "-----END RSA PRIVATE KEY-----"])


def token(n: int = 32) -> str:
    return base64.b16encode(os.urandom(n // 2)).decode().lower()


def finding(fp, base, file, value_id=None, context=None, status="open", **kw):
    f = {"fingerprint": fp, "value_id": value_id or "v-" + fp, "repo": "prod", "branches": ["main"],
         "commit": "abc1234", "file": file, "line": 1, "rule_id": "private-key", "provider": "private-key",
         "class": base, "base_class": base, "context": context, "live_in_tree": True, "age_days": 3,
         "status": status, "first_seen": "2026-11-01", "date": "2026-11-01T00:00:00Z"}
    f.update(kw)
    return f


class ValueShapeTests(unittest.TestCase):
    def test_private_key_needs_a_key_body(self):
        header_only = [
            "-----BEGIN PRIVATE KEY-----}),\n     * which the JDK reads natively. A key delivered as\n"
            "     * -----BEGIN RSA PRIVATE KEY-----",
            '-----BEGIN RSA PRIVATE KEY-----");\n    }\n\n    @Test\n'
            "    void validateShouldRejectBothMethodsConfiguredAtTheSameTime() {\n"
            '        config.setKey("-----BEGIN RSA PRIVATE KEY-----',
        ]
        for text in header_only:
            self.assertEqual(cl.value_context("private-key", text), "no-key-body", "header text only")
            self.assertEqual(cl.classify("private-key", text, CLASSES)[0], "C", "header text only is class C")
        for text in (pem(), pem(escaped=True), pem(lines=2)):
            self.assertIsNone(cl.value_context("private-key", text), "a key body is evidence")
            self.assertEqual(cl.classify("private-key", text, CLASSES)[0], "A", "a key with a body is class A")

    def test_planted_private_key_stays_class_a(self):
        item = PLANTED["private-key"]
        self.assertEqual(cl.classify(item.rule_id, item.value, CLASSES, item.file)[0], "A")
        self.assertIsNone(cl.value_context(item.rule_id, item.value))

    def test_generic_api_key_names_versions_and_ids_are_not_credentials(self):
        for value in ("changeit-please", "property_name", "org.example.model.Project", "app.policy.s3.secret.key=",
                      "v0.0.0-20231016165738-49dd2c1f3d0b", "1.24.3", "ABC-JS-LIBRARY-2944238"):
            self.assertEqual(cl.value_context("generic-api-key", value), "not-a-credential", "a name or id")
            self.assertEqual(cl.classify("generic-api-key", value, CLASSES)[0], "C")

    def test_generic_api_key_keeps_every_key_like_value(self):
        uuid = "-".join(token(n) for n in (8, 4, 4, 4, 12))
        mixed = base64.b64encode(os.urandom(24)).decode().replace("+", "x").replace("/", "y")
        jwt_like = ".".join(base64.urlsafe_b64encode(os.urandom(n)).decode().rstrip("=") for n in (27, 60, 32))
        for value in (token(32), token(40), uuid, mixed, "prefix_" + mixed, jwt_like):
            self.assertIsNone(cl.value_context("generic-api-key", value), "a key-like value is kept")
            self.assertEqual(cl.classify("generic-api-key", value, CLASSES)[0], "B", "a key-like value stays B")

    def test_variable_references_are_placeholders_for_curl_and_generic_rules_only(self):
        for rule in ("generic-api-key", "curl-auth-header", "curl-auth-user"):
            for value in ('"${API_KEY}:"', "$SERVICE_TOKEN", "{{ .Site.Params.key }}", "%API_KEY%"):
                self.assertEqual(cl.value_context(rule, value), "placeholder", "a variable reference")
        self.assertIsNone(cl.value_context("database-url-password", "${DB_PASSWORD}"), "other rules unchanged")
        self.assertIsNone(cl.value_context("curl-auth-user", token(24) + ":"), "a value is kept")

    def test_guard_value_checks_match_the_package(self):
        spec = importlib.util.spec_from_file_location("guard_ctx", GUARD)
        guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guard)
        guard_classes = guard.load_classes(str(cl.CLASSES_PATH))
        samples = [("private-key", pem()), ("private-key", "-----BEGIN PRIVATE KEY----- text -----END PRIVATE KEY-----"),
                   ("generic-api-key", "org.example.Thing"), ("generic-api-key", token()),
                   ("curl-auth-user", "${KEY}:"), ("generic-api-key", "v1.2.3")]
        for rule, value in samples:
            self.assertEqual(guard.value_context(rule, value), cl.value_context(rule, value), f"parity {rule}")
            self.assertEqual(guard.classify(rule, value, guard_classes)[0], cl.classify(rule, value, CLASSES)[0],
                             f"class parity {rule}")


class PathContextTests(unittest.TestCase):
    def test_default_rules_by_ecosystem(self):
        cases = {
            "src/test/java/org/example/FooTest.java": "test",
            "src/test/resources/keys/app-key.pem": "test",
            "pkg/server/handler_test.go": "test",
            "internal/testdata/key.pem": "fixture",
            "web/__tests__/api.ts": "test",
            "tests/unit/client.test.ts": "test",
            "spec/models/user_spec.rb": "test",
            "app/fixtures/users.json": "fixture",
            "examples/basic/config.yaml": "example",
            "server/database.example.env": "example",
            "docs/_docs/usage/cicd.md": "docs",
            "_vendor/github.com/x/theme/app.js": "vendored",
            "web/node_modules/pkg/index.js": "vendored",
            "src/main/resources/license-list-data/json/licenses.json": "data",
            "dev/docker-compose.postgres.yml": "dev",
            "docker-compose.dev.yml": "dev",
            ".devcontainer/devcontainer.json": "dev",
        }
        for path, label in cases.items():
            self.assertEqual(cl.path_context(path, RULES), label, path)

    def test_deployable_code_and_config_has_no_context(self):
        for path in (".env", ".env.prod", ".env.local", "MANUAL.md", "README.md", ".github/workflows/deploy.yml",
                     "ci/release.sh", "build/assets/index-abc.js", "dist/app.js", "infra/deploy_key.pem",
                     "src/main/resources/application.properties", "supabase/functions/api/index.ts",
                     "docker-compose.yml", "contest/entry.py", "latest/config.json", "attestation/key.pem"):
            self.assertIsNone(cl.path_context(path, RULES), path)

    def test_config_adds_patterns_and_deployable_wins(self):
        rules = cl.context_rules(CLASSES, {"test": ("qa/",), "deployable": ("deploy/examples/",),
                                           "generated": ("_gen/",)})
        self.assertEqual(cl.path_context("qa/smoke.py", rules), "test")
        self.assertEqual(cl.path_context("resources/_gen/app.js", rules), "generated")
        self.assertIsNone(cl.path_context("deploy/examples/prod.env", rules), "deployable is never context")
        self.assertEqual(cl.path_context("examples/prod.env", rules), "example")


class ApplyContextTests(unittest.TestCase):
    def test_one_class_lower_never_dropped_and_totals_add_up(self):
        items = [finding("a1", "A", "infra/deploy_key.pem"),
                 finding("a2", "A", "src/test/resources/app-key.pem"),
                 finding("b1", "B", "docs/usage.md", rule_id="generic-api-key"),
                 finding("b2", "B", "web/src/client.ts", rule_id="generic-api-key"),
                 finding("c1", "C", "src/Thing.java", context="no-key-body"),
                 finding("c2", "C", "examples/app.ts", rule_id="supabase-publishable-key"),
                 finding("r1", "A", "tests/old.pem", status="rotated")]
        before = len(items)
        cl.apply_context(items, CLASSES)
        got = {f["fingerprint"]: (f["class"], f["context"]) for f in items}
        self.assertEqual(got, {"a1": ("A", None), "a2": ("B", "test"), "b1": ("C", "docs"), "b2": ("B", None),
                               "c1": ("C", "no-key-body"), "c2": ("C", "example"), "r1": ("B", "test")})
        self.assertEqual(len(items), before, "nothing is removed")
        self.assertEqual(sum(1 for f in items if f["class"] in "ABC"), before, "every finding has a class")
        self.assertTrue(all(f["base_class"] for f in items), "base class kept")
        self.assertEqual([cl.ranked_lower(f) for f in items], [False, True, True, False, False, False, True])

    def test_real_looking_key_in_deployable_config_stays_class_a(self):
        value = pem()
        cls, _ = cl.classify("private-key", value, CLASSES, "config/prod/deploy_key.pem")
        items = [finding("k", cls, "config/prod/deploy_key.pem", context=cl.value_context("private-key", value))]
        cl.apply_context(items, CLASSES)
        self.assertEqual((items[0]["class"], items[0]["context"]), ("A", None))

    def test_same_value_outside_context_keeps_the_class(self):
        items = [finding("t", "B", "scripts/test_upload.py", value_id="same", rule_id="gcp-api-key"),
                 finding("p", "B", "scripts/upload.py", value_id="same", rule_id="gcp-api-key"),
                 finding("o", "B", "tests/test_other.py", value_id="other", rule_id="gcp-api-key")]
        cl.apply_context(items, CLASSES)
        got = {f["fingerprint"]: (f["class"], f["context"], cl.ranked_lower(f)) for f in items}
        self.assertEqual(got, {"t": ("B", "test", False), "p": ("B", None, False), "o": ("C", "test", True)})

    def test_switch_off_and_old_documents(self):
        items = [finding("a", "A", "tests/key.pem")]
        cl.apply_context(items, CLASSES)
        self.assertEqual(items[0]["class"], "B")
        cl.apply_context(items, CLASSES, enabled=False)
        self.assertEqual((items[0]["class"], items[0]["context"]), ("A", "test"), "off: base class, label kept")
        old = {k: v for k, v in finding("o", "A", "tests/key.pem").items() if k not in ("base_class", "context")}
        cl.apply_context([old], CLASSES)
        self.assertEqual((old["base_class"], old["class"]), ("A", "B"), "a document without base_class")
        cl.apply_context([old], CLASSES)
        self.assertEqual(old["class"], "B", "applying twice never ranks twice")

    def test_history_only_finding_is_still_a_finding(self):
        items = [finding("h", "A", ".env.prod", live_in_tree=False)]
        cl.apply_context(items, CLASSES)
        self.assertEqual((items[0]["class"], items[0]["status"]), ("A", "open"), "removed from HEAD, still open")

    def test_fields_and_fingerprints_unchanged(self):
        self.assertEqual(findings.FIELDS[-2:], ("base_class", "context"))
        items = [finding("fp-1", "A", "tests/key.pem")]
        cl.apply_context(items, CLASSES)
        self.assertEqual(items[0]["fingerprint"], "fp-1", "the decision key never changes")


class OutputTests(unittest.TestCase):
    def test_issues_rank_context_secrets_below_production_vulnerabilities(self):
        rep = {"generated_at": "2026-11-10T10:00:00+00:00", "production_projects": ["prod"], "runtimes": [],
               "unpinned_images": [], "suppressed": [],
               "vulnerabilities": [{"ecosystem": "npm", "name": "lib", "version": "1.0.0", "scope": "required",
                                    "direct_anywhere": True, "max_severity": "HIGH", "kev": False,
                                    "locations": [{"project": "prod", "branch": "main", "manifest": "p.json",
                                                   "direct": True, "scope": "required"}],
                                    "vulns": [{"id": "GHSA-x", "cves": [], "summary": "s", "severity": "HIGH",
                                               "kev": False, "fixed_in": "1.2.0"}]}]}
        items = [finding("ctx", "A", "src/test/resources/app-key.pem"), finding("real", "A", "infra/key.pem"),
                 finding("doc", "B", "docs/api.md", rule_id="generic-api-key")]
        cl.apply_context(items, CLASSES)
        doc = issues.build(rep, {"findings": items}, None, now="2026-11-12T00:00:00+00:00")
        ids = [i["id"] for i in doc["issues"]]
        self.assertEqual(ids[:2], ["secret:real", "vuln:prod:p.json:npm:lib@1.0.0"])
        by = {i["id"]: i for i in doc["issues"]}
        ctx = by["secret:ctx"]
        self.assertEqual((ctx["priority"], ctx["reason"], ctx["production"], ctx["fix"]["action"]),
                         (4, "secret_context", False, "review"))
        self.assertIn("test code", ctx["title"])
        self.assertIn("check whether the value is a real credential", ctx["fix"]["hint"])
        self.assertEqual((ctx["details"]["context"], ctx["details"]["base_class"]), ("test", "A"))
        real = by["secret:real"]
        self.assertEqual((real["priority"], real["production"], real["fix"]["action"]), (1, True, "rotate"))
        self.assertEqual(by["secret:doc"]["priority"], 6, "a class C finding stays at the bottom")
        self.assertIn("secret_context", issues.PRIORITY_REASONS[4])

    def test_secrets_md_labels_counts_and_lists_ranked_findings(self):
        items = [finding("ctx", "A", "src/test/resources/app-key.pem"),
                 finding("hdr", "C", "src/Thing.java", context="no-key-body"),
                 finding("doc", "B", "docs/api.md", rule_id="generic-api-key"),
                 finding("real", "A", "infra/key.pem")]
        cl.apply_context(items, CLASSES)
        doc = {"generated_at": "2026-11-12T00:00:00+00:00", "scan": {"mode": "full", "repos": 1},
               "engine": {"name": "gitleaks", "version": "8.30.1"}, "findings": items}
        with tempfile.TemporaryDirectory() as tmp:
            text = secrets_report.render(Path(tmp), doc, CLASSES)
        self.assertIn("Ranked lower by context: 3 open", text)
        self.assertIn("- context: test code, ranked lower from class A", text)
        self.assertIn("- if the value is real, rotate:", text)
        self.assertIn("## Ranked lower by context", text)
        self.assertIn("`hdr` prod `src/Thing.java:1` (private-key): key header text only", text)
        self.assertIn("`doc` prod `docs/api.md:1` (generic-api-key): documentation, ranked lower from class B", text)
        real = text[text.index("`infra/key.pem:1`"):]
        self.assertIn("- rotate:", real.split("###")[0], "a deployable finding keeps the plain rotate hint")

    def test_secrets_md_says_why_a_labelled_finding_kept_its_class(self):
        items = [finding("t", "A", "tests/key.pem", value_id="same"), finding("p", "A", "infra/key.pem", value_id="same")]
        cl.apply_context(items, CLASSES)
        doc = {"generated_at": "2026-11-12T00:00:00+00:00", "scan": {"mode": "full", "repos": 1},
               "engine": {"name": "gitleaks", "version": "8.30.1"}, "findings": items}
        with tempfile.TemporaryDirectory() as tmp:
            text = secrets_report.render(Path(tmp), doc, CLASSES)
        self.assertIn("- context: test code; not ranked lower", text)
        self.assertNotIn("Ranked lower by context: ", text, "nothing was ranked lower")
        self.assertNotIn("if the value is real", text)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.out = Path(self._tmp.name) / "security"
        self.out.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def load(self, text: str):
        (self.out / "sbom-audit.toml").write_text(text, encoding="utf-8")
        return config.load(self.out)

    def test_defaults_and_overrides(self):
        cfg = self.load("")
        self.assertTrue(cfg.secrets.rank_by_context)
        self.assertEqual(cfg.secrets.context, {})
        cfg = self.load('[secrets]\nrank_by_context = false\n[secrets.context]\ntest = ["qa/"]\n'
                        'deployable = ["deploy/examples/"]\n')
        self.assertFalse(cfg.secrets.rank_by_context)
        self.assertEqual(cfg.secrets.context, {"test": ("qa/",), "deployable": ("deploy/examples/",)})

    def test_bad_values_are_named(self):
        cases = {'[secrets]\nrank_by_context = "no"\n': "[secrets] rank_by_context must be true or false",
                 '[secrets]\ncontext = "tests/"\n': "[secrets.context] must be a table",
                 '[secrets.context]\ntest = "qa/"\n': "[secrets.context] test must be a list",
                 '[secrets.context]\nTest = ["qa/"]\n': "[secrets.context] Test: a label is"}
        for text, message in cases.items():
            with self.subTest(text=text):
                with self.assertRaises(ConfigError) as ctx:
                    self.load(text)
                self.assertIn(message, str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
