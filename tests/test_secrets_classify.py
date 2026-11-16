"""Secrets rules and classification: gitleaks.toml, classes.toml, classify.py, planted values.

Assertions never print a planted value; they compare classes and provider names or use fixed messages.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

from sbomaudit.secrets import classify as cl
from sbomaudit import config
from tests import secrets_fixture as fx
from tests.secrets_fixture import PLANTED

ROOT = Path(__file__).resolve().parent.parent
RULES = tomllib.loads((ROOT / "secrets" / "gitleaks.toml").read_text())
CUSTOM = {rule["id"]: rule for rule in RULES["rules"]}
CLASSES = cl.load_classes()


class RulesTests(unittest.TestCase):
    def test_every_planted_rule_matches_its_regex(self):
        for rule_id, rule in CUSTOM.items():
            planted = [p for p in PLANTED.values() if p.rule_id == rule_id]
            self.assertTrue(planted, f"no planted value for custom rule {rule_id}")
            for item in planted:
                # the file content as planted: keyword-bound rules need their assignment context
                text = fx.LINES[next(k for k, v in PLANTED.items() if v is item)].format(v=item.value)
                self.assertTrue(bool(re.search(rule["regex"], text)),
                                f"regex of rule {rule_id} did not match its planted value")
        allow = RULES["allowlist"]["regexes"]
        for item in PLANTED.values():
            for rx in allow:
                self.assertFalse(bool(re.search(rx, item.value)),
                                 "an allowlist regex matched a planted value")

    def test_gitleaks_toml_extends_default(self):
        self.assertIs(RULES["extend"]["useDefault"], True)

    def test_classes_toml_covers_every_rule_in_gitleaks_toml(self):
        for rule_id in CUSTOM:
            self.assertIn(rule_id, CLASSES.rule_to_class)
            self.assertIn(CLASSES.rule_providers[rule_id], CLASSES.providers)
        for provider in CLASSES.providers.values():
            self.assertTrue(provider.hint)
        self.assertEqual(set(CLASSES.rule_to_class.values()), {"A", "B", "C"})
        self.assertIn("generic", CLASSES.providers)

    def test_every_planted_value_classifies_as_expected(self):
        for key, item in PLANTED.items():
            got, _ = cl.classify(item.rule_id, item.value, CLASSES, item.file)
            self.assertEqual((key, got), (key, item.expected_class))


# The six rules without a distinctive prefix: keyword bound to an assignment, value in secretGroup 1.
CONTEXT_RULES = {
    "supabase-jwt-secret": "SUPABASE_JWT_SECRET",
    "hetzner-api-token": "HCLOUD_TOKEN",
    "contabo-client-secret": "CONTABO_CLIENT_SECRET",
    "expo-access-token": "EXPO_TOKEN",
    "assemblyai-api-key": "ASSEMBLYAI_API_KEY",
    "dataforseo-credentials": "DATAFORSEO_AUTH",
}
SHAPES = (
    ("env", "{k}={v}\n"),
    ("json", '{{\n  "{k}": "{v}"\n}}\n'),
    ("yaml", "{k}: {v}\n"),
    ("toml", '{k} = "{v}"\n'),
    ("quoted env", "export {k}='{v}'\n"),
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()  # 64 hex characters built at runtime


def _custom_hits(text: str, rule_ids) -> set[str]:
    return {r for r in rule_ids if re.search(CUSTOM[r]["regex"], text)}


class ContextTests(unittest.TestCase):
    def test_unprefixed_rules_match_all_assignment_shapes_and_capture_the_value(self):
        for rule_id, key in CONTEXT_RULES.items():
            value = PLANTED[rule_id].value
            self.assertEqual(CUSTOM[rule_id].get("secretGroup"), 1)
            for shape, template in SHAPES:
                text = template.format(k=key, v=value)
                m = re.search(CUSTOM[rule_id]["regex"], text)
                self.assertTrue(bool(m) and m.group(1) == value,
                                f"rule {rule_id} did not capture its planted value in the {shape} shape")

    def test_anon_jwt_next_to_an_empty_jwt_secret_line_is_not_a_jwt_secret(self):
        text = "SUPABASE_JWT_SECRET=\nSUPABASE_ANON_KEY=" + PLANTED["jwt-anon"].value + "\n"
        self.assertFalse(bool(re.search(CUSTOM["supabase-jwt-secret"]["regex"], text)),
                         "supabase-jwt-secret matched an anon key beside an empty secret line")

    def test_lockfile_hash_in_a_file_mentioning_hcloud_is_not_a_hetzner_token(self):
        text = ('provider "registry.terraform.io/hetznercloud/hcloud" {\n  version = "1.50.0"\n'
                f'  hashes = [\n    "zh:{_digest("lock")}",\n  ]\n}}\n')
        self.assertFalse(bool(re.search(CUSTOM["hetzner-api-token"]["regex"], text)),
                         "hetzner-api-token matched a lockfile hash")

    def test_image_digest_in_a_file_mentioning_contabo_is_not_a_contabo_secret(self):
        text = f"# deployed to contabo\nservices:\n  app:\n    image: registry.local/app@sha256:{_digest('img')}\n"
        self.assertFalse(bool(re.search(CUSTOM["contabo-client-secret"]["regex"], text)),
                         "contabo-client-secret matched an image digest")

    @unittest.skipUnless(shutil.which("gitleaks"), "gitleaks not installed")
    def test_engine_captures_planted_values_and_ignores_the_decoys(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan = Path(tmp) / "scan"
            scan.mkdir()
            for i, (rule_id, key) in enumerate(CONTEXT_RULES.items()):
                template = SHAPES[i % len(SHAPES)][1]
                (scan / f"{rule_id}.cfg").write_text(template.format(k=key, v=PLANTED[rule_id].value))
            (scan / "anon.env").write_text(
                "SUPABASE_JWT_SECRET=\nSUPABASE_ANON_KEY=" + PLANTED["jwt-anon"].value + "\n")
            (scan / "lock.hcl").write_text(f'# hcloud\nhashes = [\n  "zh:{_digest("lock")}",\n]\n')
            (scan / "compose.yml").write_text(f"# contabo\nimage: app@sha256:{_digest('img')}\n")
            report = Path(tmp) / "report.json"
            proc = subprocess.run(
                ["gitleaks", "dir", "--no-banner", "--no-color", "-c", str(ROOT / "secrets" / "gitleaks.toml"),
                 "-f", "json", "-r", str(report), "--exit-code", "1", str(scan)],
                capture_output=True, text=True)
            self.assertEqual(proc.returncode, 1)
            rows = json.loads(report.read_text())
        for rule_id in CONTEXT_RULES:
            mine = [r for r in rows if r["RuleID"] == rule_id]
            self.assertTrue(len(mine) == 1 and mine[0]["File"].endswith(f"{rule_id}.cfg")
                            and mine[0]["Secret"] == PLANTED[rule_id].value,
                            f"engine did not report exactly the planted value for {rule_id}")
        decoys = {Path(r["File"]).name for r in rows if r["RuleID"] in CONTEXT_RULES
                  and not r["File"].endswith(".cfg")}
        self.assertEqual(decoys, set())


class ClassifyTests(unittest.TestCase):
    def test_jwt_role_classification(self):
        for key, want in (("jwt-service-role", "A"), ("jwt-anon", "C"),
                          ("jwt-supabase-other", "B"), ("jwt-other", "B")):
            self.assertEqual(cl.classify("jwt", PLANTED[key].value, CLASSES)[0], want, key)
        self.assertEqual(cl.classify("jwt", PLANTED["jwt-service-role"].value, CLASSES)[1], "supabase")
        self.assertEqual(cl.classify("jwt", PLANTED["jwt-other"].value, CLASSES)[1], "generic")
        self.assertIsNone(cl.jwt_claims("not-a-token"))
        self.assertIsNone(cl.jwt_claims("a.b"))
        self.assertIsNone(cl.jwt_claims("eyJhbGciOiJIUzI1NiJ9.bm90IGpzb24.sig"))
        self.assertEqual(cl.classify("jwt", "garbage", CLASSES), ("B", "generic"))

    def test_jwt_base64_is_decoded_first(self):
        import base64
        wrapped = base64.b64encode(PLANTED["jwt-service-role"].value.encode()).decode()
        self.assertEqual(cl.classify("jwt-base64", wrapped, CLASSES)[0], "A")

    def test_stripe_live_vs_test(self):
        self.assertEqual(cl.classify("stripe-access-token", PLANTED["stripe-live"].value, CLASSES),
                         ("A", "stripe"))
        self.assertEqual(cl.classify("stripe-access-token", PLANTED["stripe-test"].value, CLASSES),
                         ("C", "stripe"))
        self.assertEqual(cl.classify("stripe-access-token", "rk_live_" + "a1B2" * 6, CLASSES)[0], "A")
        self.assertEqual(cl.classify("stripe-access-token", "rk_test_" + "a1B2" * 6, CLASSES)[0], "C")

    def test_gcp_key_in_firebase_file_is_C(self):
        value = PLANTED["gcp-api-key"].value
        self.assertEqual(cl.classify("gcp-api-key", value, CLASSES, "src/firebaseConfig.ts"), ("C", "gcp"))
        self.assertEqual(cl.classify("gcp-api-key", value, CLASSES, "src/gemini.ts"), ("B", "gcp"))
        self.assertEqual(cl.classify("gcp-api-key", value, CLASSES), ("B", "gcp"))

    def test_supabase_issuer_url_and_nonsense_claims(self):
        token, _ = fx._jwt({"iss": "https://abcdefgh.supabase.co/auth/v1", "sub": "u1"})
        self.assertEqual(cl.classify("jwt", token, CLASSES), ("B", "supabase"))
        token, _ = fx._jwt({"iss": ["supabase"], "role": 7})
        self.assertEqual(cl.classify("jwt", token, CLASSES), ("B", "generic"))

    def test_jwt_claims_never_raises(self):
        import base64
        deep = "[" * 100000
        payload = base64.urlsafe_b64encode(deep.encode()).decode().rstrip("=")
        self.assertIsNone(cl.jwt_claims(f"aaa.{payload}.ccc"))

    def test_providers_for_anthropic_openai_and_slack(self):
        for rule_id, provider in (("anthropic-api-key", "anthropic"), ("openai-api-key", "openai"),
                                  ("slack-webhook-url", "slack"), ("slack-bot-token", "slack"),
                                  ("slack-user-token", "slack")):
            self.assertEqual(CLASSES.rule_providers[rule_id], provider)
            self.assertTrue(CLASSES.providers[provider].hint)
            self.assertTrue(CLASSES.providers[provider].packages)
        for key, provider in (("anthropic-api-key", "anthropic"), ("slack-webhook-url", "slack")):
            item = PLANTED[key]
            self.assertEqual(cl.classify(item.rule_id, item.value, CLASSES, item.file),
                             ("B", provider))

    def test_unknown_rule_defaults_to_B_generic(self):
        self.assertEqual(cl.classify("some-new-rule", "x" * 20, CLASSES), ("B", "generic"))

    def test_load_classes_rejects_a_rule_in_two_classes(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "classes.toml"
            bad.write_text('[classes]\nA = ["x"]\nB = ["x"]\nC = []\n')
            with self.assertRaises(ValueError):
                cl.load_classes(bad)


class FixtureTests(unittest.TestCase):
    def test_fixture_portfolio_layout(self):
        import subprocess
        import tempfile

        def git(repo, *args):
            return subprocess.run(["git", "-C", str(repo), *args], check=True, text=True,
                                  capture_output=True).stdout

        with tempfile.TemporaryDirectory() as tmp:
            root = fx.write_fixture_portfolio(Path(tmp))
            alpha, beta = root / "alpha-app", root / "beta-api"
            history = PLANTED[fx.HISTORY_ONLY].file
            self.assertFalse((alpha / history).exists())
            self.assertTrue(git(alpha, "log", "--oneline", "--", history).strip())
            self.assertTrue((root / fx.WORKTREE / ".git").exists())
            self.assertIn("wt-branch", git(alpha, "branch", "--list"))
            branch_file = PLANTED[fx.BRANCH_ONLY].file
            self.assertFalse((beta / branch_file).exists())
            self.assertTrue(git(beta, "ls-tree", "-r", "--name-only", "dev").count(branch_file))
            cfg = config.load(root / "security", root)
            self.assertEqual(cfg.ignore_projects, ["ignored-archive"])
            placed = {k for keys in fx.REPOS.values() for k in keys}
            self.assertEqual(placed, set(PLANTED))


if __name__ == "__main__":
    unittest.main()
