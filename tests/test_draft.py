"""`assess draft`: an assessment proposal from an OpenAI-compatible endpoint (a local stub server, no network)."""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from sbomaudit import cli, config, draft
from sbomaudit.errors import ConfigError
from sbomaudit.secrets.findings import KEY_FILE

FIXTURE = Path(__file__).resolve().parent.parent / "evals" / "fixtures" / "security"
NOW = datetime(2026, 11, 8, 3, 0, tzinfo=timezone.utc)
KEY = "sk-test-0123456789abcdefSECRETKEY"
ANSWER = ("## Assessment 2026-11-08\nSummary.\n\n## Proposed decisions (unverified)\nnone\n\n"
          "## GitHub issue drafts\nnone\n")


class Stub:
    """A chat completions server on 127.0.0.1 that records requests and replies as told."""

    def __init__(self, status=200, body=None, location=None):
        self.requests: list[dict] = []
        self.status, self.location = status, location
        self.body = body if body is not None else completion(ANSWER)
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                stub.requests.append({"path": self.path, "headers": dict(self.headers),
                                      "body": json.loads(self.rfile.read(length) or b"{}")})
                payload = stub.body if isinstance(stub.body, bytes) else json.dumps(stub.body).encode()
                self.send_response(stub.status)
                if stub.location:
                    self.send_header("Location", stub.location)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def completion(content, finish="stop"):
    return {"choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": finish}],
            "usage": {"prompt_tokens": 1200, "completion_tokens": 300}}


class DraftBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.out = self.tmp / "security"
        shutil.copytree(FIXTURE, self.out)
        self.env = mock.patch.dict(os.environ, {"SBOM_AUDIT_READ_ONLY": "", "TEST_ASSESS_KEY": KEY})
        self.env.start()
        for var in config.ASSESS_ENV.values():
            os.environ.pop(var, None)

    def tearDown(self):
        self.env.stop()
        self._tmp.cleanup()

    def configure(self, url, extra=""):
        toml = (self.out / "sbom-audit.toml").read_text(encoding="utf-8")
        block = f'\n[assess]\nbase_url = "{url}"\nmodel = "test-model"\napi_key_env = "TEST_ASSESS_KEY"\n{extra}'
        (self.out / "sbom-audit.toml").write_text(toml + block, encoding="utf-8")
        return config.load(self.out)

    def cli(self, *argv):
        so, se = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(so), contextlib.redirect_stderr(se):
            rc = cli.main([*argv, "--out", str(self.out)])
        return rc, so.getvalue(), se.getvalue()


class ConfigTests(DraftBase):
    def test_off_by_default(self):
        cfg = config.load(self.out)
        self.assertFalse(cfg.assess.configured)
        self.assertIsNone(cfg.assess.base_url)

    def test_keys_and_env_overrides(self):
        cfg = self.configure("https://openrouter.ai/api/v1/", "timeout_seconds = 30\nmax_tokens = 4000\n")
        self.assertTrue(cfg.assess.configured)
        self.assertEqual(cfg.assess.base_url, "https://openrouter.ai/api/v1")
        self.assertEqual((cfg.assess.timeout_seconds, cfg.assess.max_tokens), (30, 4000))
        self.assertFalse(cfg.assess.include_hosts)
        env = {"SBOM_AUDIT_ASSESS_BASE_URL": "http://localhost:11434/v1", "SBOM_AUDIT_ASSESS_MODEL": "other",
               "SBOM_AUDIT_ASSESS_API_KEY_ENV": "OTHER_KEY"}
        cfg = config.load(self.out, env=env)
        self.assertEqual((cfg.assess.base_url, cfg.assess.model, cfg.assess.api_key_env),
                         ("http://localhost:11434/v1", "other", "OTHER_KEY"))

    def test_env_alone_turns_it_on(self):
        cfg = config.load(self.out, env={"SBOM_AUDIT_ASSESS_BASE_URL": "https://api.example.com/v1",
                                         "SBOM_AUDIT_ASSESS_MODEL": "m"})
        self.assertTrue(cfg.assess.configured)
        self.assertIsNone(cfg.assess.api_key_env)

    def assert_refused(self, block, *needles, absent=()):
        (self.out / "sbom-audit.toml").write_text(
            (FIXTURE / "sbom-audit.toml").read_text(encoding="utf-8") + "\n[assess]\n" + block, encoding="utf-8")
        with self.assertRaises(ConfigError) as ctx:
            config.load(self.out)
        for needle in needles:
            self.assertIn(needle, str(ctx.exception))
        for text in absent:
            self.assertNotIn(text, str(ctx.exception))

    def test_refusals(self):
        self.assert_refused('base_url = "https://a.example/v1"\n', "set together")
        self.assert_refused(f'base_url = "https://a.example/v1"\nmodel = "m"\napi_key = "{KEY}"\n',
                            "never put the key", absent=(KEY,))
        self.assert_refused(f'base_url = "https://a.example/v1"\nmodel = "m"\napi_key_env = "{KEY}"\n',
                            "NAME of an environment variable", absent=(KEY,))
        self.assert_refused('base_url = "http://api.example.com/v1"\nmodel = "m"\n', "only for localhost")
        self.assert_refused('base_url = "ftp://api.example.com/v1"\nmodel = "m"\n', "https://")
        self.assert_refused(f'base_url = "https://user:{KEY}@api.example.com/v1"\nmodel = "m"\n',
                            "user:password", absent=(KEY,))
        self.assert_refused(f'base_url = "https://api.example.com/v1?key={KEY}"\nmodel = "m"\n',
                            "query", absent=(KEY,))
        key_file = self.out / "key.txt"
        self.assert_refused(f'base_url = "https://a.example/v1"\nmodel = "m"\napi_key_file = "{key_file}"\n',
                            "outside the security/ folder")

    def test_loopback_http_is_allowed(self):
        for url in ("http://localhost:11434/v1", "http://127.0.0.1:8080/v1", "http://[::1]:8080/v1"):
            self.assertEqual(config.assess_url(url, "x"), url)

    def test_default_config_documents_the_block_commented_out(self):
        fresh = config.Config(out=self.tmp / "fresh", root=self.tmp, mode="portfolio", fetch=False)
        fresh.out.mkdir()
        config.write_default(fresh.out, fresh)
        text = (self.tmp / "fresh" / "sbom-audit.toml").read_text(encoding="utf-8")
        self.assertIn("# [assess]", text)
        self.assertFalse(config.load(self.tmp / "fresh").assess.configured)


class DraftTests(DraftBase):
    def test_not_configured_exits_2_and_sends_nothing(self):
        rc, out, err = self.cli("assess", "draft")
        self.assertEqual(rc, 2)
        self.assertIn("not configured", err)
        self.assertFalse((self.out / "reports").exists() and list((self.out / "reports").glob("*proposal*")))

    def test_dry_run_prints_body_without_key_and_sends_nothing(self):
        with Stub() as stub:
            self.configure(stub.url)
            rc, out, err = self.cli("assess", "draft", "--dry-run")
        self.assertEqual(rc, 0)
        self.assertEqual(stub.requests, [])
        self.assertIn(f"POST {stub.url}/chat/completions", out)
        self.assertNotIn(KEY, out + err)
        body = json.loads(out.split("\n", 1)[1])
        self.assertEqual(set(body), {"model", "messages", "stream"})
        self.assertIn("## Summary", body["messages"][1]["content"])
        self.assertFalse(list(self.out.glob("reports/*proposal*")))

    def test_dry_run_is_allowed_in_read_only_mode_but_a_draft_is_not(self):
        with Stub() as stub:
            self.configure(stub.url)
            os.environ["SBOM_AUDIT_READ_ONLY"] = "1"
            self.assertEqual(self.cli("assess", "draft", "--dry-run")[0], 0)
            self.assertEqual(self.cli("assess", "draft")[0], 5)
        self.assertEqual(stub.requests, [])

    def test_writes_labelled_proposal_and_marks_it_waiting(self):
        with Stub() as stub:
            self.configure(stub.url, "max_tokens = 9000\n")
            rc, out, err = self.cli("assess", "draft")
        self.assertEqual(rc, 0, err)
        req = stub.requests[0]
        self.assertEqual(req["path"], "/v1/chat/completions")
        self.assertEqual(req["headers"]["Authorization"], f"Bearer {KEY}")
        self.assertTrue(req["headers"]["User-Agent"].startswith("sbom-audit/"))
        self.assertEqual(req["body"]["model"], "test-model")
        self.assertEqual(req["body"]["max_tokens"], 9000)
        self.assertFalse(req["body"]["stream"])
        system, user = req["body"]["messages"]
        self.assertIn("unverified", system["content"])
        self.assertIn('<document name="AUDIT.md § Source status">', user["content"])
        self.assertIn('<document name="open work list', user["content"])
        rel = f"reports/{datetime.now(timezone.utc):%Y-%m-%d}-assessment-proposal.md"
        text = (self.out / rel).read_text(encoding="utf-8")
        self.assertTrue(text.startswith("<!-- proposal written by `assess draft` (model test-model at "))
        self.assertIn("by model `test-model`", text)
        self.assertIn(ANSWER.strip(), text)
        self.assertIn(rel, out)
        self.assertIn("1200 input, 300 output tokens", out)
        self.assertNotIn("Summary.", out + err)               # the proposal text is never printed
        self.assertIn("| assess-proposal | cost unknown | " + rel, (self.out / "log.md").read_text())
        self.assertEqual(json.loads((self.out / "status.json").read_text())["assessment_proposal"], rel)
        self.assertIn(rel, (self.out / "STATUS.md").read_text())
        for path in self.out.rglob("*"):
            if path.is_file():
                self.assertNotIn(KEY, path.read_text(encoding="utf-8", errors="ignore"), path)
        self.assertNotIn(KEY, out + err)

    def test_no_key_variable_sends_no_authorization_header(self):
        with Stub() as stub:
            cfg = self.configure(stub.url)
            cfg.assess.api_key_env = None
            res = draft.run(cfg, self.out, env={}, now=NOW)
        self.assertEqual(res["status"], "written")
        self.assertNotIn("Authorization", stub.requests[0]["headers"])

    def test_missing_key_variable_fails_before_sending(self):
        with Stub() as stub:
            cfg = self.configure(stub.url)
            res = draft.run(cfg, self.out, env={}, now=NOW)
        self.assertEqual((res["status"], stub.requests), ("failed", []))
        self.assertIn("TEST_ASSESS_KEY is not set", res["reason"])

    def test_key_file_must_be_private(self):
        key_file = self.tmp / "key"
        key_file.write_text(KEY + "\n")
        with Stub() as stub:
            cfg = self.configure(stub.url, f'api_key_file = "{key_file}"\n')
            key_file.chmod(0o644)
            res = draft.run(cfg, self.out, env={}, now=NOW)
            self.assertIn("chmod 600", res["reason"])
            key_file.chmod(0o600)
            res = draft.run(cfg, self.out, env={}, now=NOW)
        self.assertEqual(res["status"], "written")
        self.assertEqual(stub.requests[0]["headers"]["Authorization"], f"Bearer {KEY}")

    def test_http_error_reports_status_only(self):
        with Stub(status=401, body={"error": {"message": f"bad key {KEY}"}}) as stub:
            res = draft.run(self.configure(stub.url), self.out, now=NOW)
        self.assertEqual(res["status"], "failed")
        self.assertEqual(res["reason"], "HTTP 401 (key rejected)")
        self.assertFalse(list(self.out.glob("reports/*proposal*")))

    def test_redirect_is_not_followed(self):
        with Stub() as target, Stub(status=307, location=target.url + "/chat/completions") as stub:
            res = draft.run(self.configure(stub.url), self.out, now=NOW)
        self.assertEqual(res["status"], "failed")
        self.assertIn("HTTP 307", res["reason"])
        self.assertEqual(target.requests, [])

    def test_cut_off_empty_and_non_json_answers_fail(self):
        for body, reason in ((completion(ANSWER, finish="length"), "cut off"), (completion("  "), "empty answer"),
                             (b"<html>", "not JSON"), ({"choices": []}, "no answer")):
            with Stub(body=body) as stub:
                res = draft.run(self.configure(stub.url), self.out, now=NOW)
            self.assertEqual(res["status"], "failed")
            self.assertIn(reason, res["reason"])
            (self.out / "sbom-audit.toml").write_text((FIXTURE / "sbom-audit.toml").read_text(), encoding="utf-8")
        self.assertFalse(list(self.out.glob("reports/*proposal*")))

    def test_list_content_and_think_block(self):
        parts = [{"type": "text", "text": "<think>private</think>\n"}, {"type": "text", "text": ANSWER}]
        with Stub(body=completion(parts)) as stub:
            res = draft.run(self.configure(stub.url), self.out, now=NOW)
        text = (self.out / res["path"]).read_text()
        self.assertNotIn("private", text)
        self.assertIn("## Assessment 2026-11-08", text)

    def test_answer_with_cache_material_is_dropped(self):
        key = self.out / KEY_FILE
        key.parent.mkdir(parents=True, exist_ok=True)
        key.write_text("fingerprint-key-material-0123456789")
        with Stub(body=completion(ANSWER + "fingerprint-key-material-0123456789")) as stub:
            res = draft.run(self.configure(stub.url), self.out, now=NOW)
        self.assertEqual((res["status"], res["reason"]), ("failed", "proposal contained cache material"))
        self.assertFalse(list(self.out.glob("reports/*proposal*")))

    def test_answer_echoing_the_key_is_dropped(self):
        with Stub(body=completion(ANSWER + KEY)) as stub:
            res = draft.run(self.configure(stub.url), self.out, now=NOW)
        self.assertEqual(res["status"], "failed")
        self.assertFalse(list(self.out.glob("reports/*proposal*")))

    def test_code_based_not_affected_gets_a_warning(self):
        answer = ANSWER + "vex add app CVE-1 not_affected --justification vulnerable_code_not_present unverified\n"
        with Stub(body=completion(answer)) as stub:
            res = draft.run(self.configure(stub.url), self.out, now=NOW)
        self.assertIn("cannot establish it", (self.out / res["path"]).read_text())
        self.assertFalse((self.out / "vex").exists() and any((self.out / "vex").iterdir()))

    def test_hosts_are_left_out_unless_included(self):
        (self.out / "hosts.json").write_text(json.dumps({"hosts": {"web-1": {"findings": []}}}))
        with Stub() as stub:
            cfg = self.configure(stub.url)
        self.assertNotIn("hosts", [d for d, _ in draft.documents(cfg, self.out) if "hosts" in d])
        with mock.patch.object(draft.issues, "build", wraps=draft.issues.build) as build:
            draft.documents(cfg, self.out)
            self.assertIsNone(build.call_args.args[2])

    def test_no_audit_fails(self):
        (self.out / "audit.json").unlink()
        with Stub() as stub:
            res = draft.run(self.configure(stub.url), self.out, now=NOW)
        self.assertEqual((res["status"], stub.requests), ("failed", []))
        self.assertIn("no audit yet", res["reason"])


if __name__ == "__main__":
    unittest.main()
