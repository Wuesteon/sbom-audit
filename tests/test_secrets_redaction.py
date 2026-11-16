"""Redaction end to end: after a full run with commit, no output anywhere holds a planted value.

Every file under the evidence folder (`.cache/` and `reports/` included), the evidence repository's
`git log -p`, and everything the run and the secrets CLI printed is checked with `findings.assert_redacted`
for each planted value and every window of its random part (5 characters, 8 where they start with 5 hex
characters, so per-run commit hashes never match by chance). Failures name the file only.
"""
from __future__ import annotations

import contextlib
import io
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import cli, config, pipeline
from sbomaudit.secrets import store
from sbomaudit.secrets.findings import assert_redacted
from tests import secrets_fixture as fx
from tests import test_pipeline as tp

PLANTED = list(fx.PLANTED.values())


def clean(text: str) -> bool:
    return len(assert_redacted(text, PLANTED)) == 0


@unittest.skipUnless(shutil.which("gitleaks"), "gitleaks not installed")
class RedactionTests(unittest.TestCase):
    def test_no_output_contains_any_planted_value_or_window(self):
        self.assertFalse(clean("x " + fx.PLANTED["github-pat"].value), "a planted value must be caught")
        self.assertFalse(clean(fx.PLANTED["github-pat"].core[3:8]), "a 5-character window must be caught")
        hex_core = fx.PLANTED["inngest-signing-key"].core
        self.assertFalse(clean("x" + hex_core[20:28] + "x"), "an 8-character hex window must be caught")
        self.assertTrue(clean("x" + hex_core[20:27] + "x"), "a short hex run must not count as a leak")
        with tempfile.TemporaryDirectory() as tmp:
            root = fx.write_fixture_portfolio(Path(tmp).resolve())
            cfg = config.load(root / "security")
            cfg.fetch = False
            tp.git_init(cfg.out)
            printed, errors = io.StringIO(), io.StringIO()
            with tp.tools_present(), \
                 mock.patch.object(pipeline.scan, "scan", return_value=tp.scan_result(tp.inventory())), \
                 mock.patch.object(pipeline.matching, "run_osv_scanner", return_value={"results": []}), \
                 contextlib.redirect_stdout(printed), contextlib.redirect_stderr(errors):
                rc = pipeline.run(cfg, http=tp.offline, log=print)
                first = store.read(cfg.out)
                open_fp = next(f["fingerprint"] for f in first["findings"] if f["class"] == "A")
                cli_codes = [cli.main(["secrets", "scan", "--out", str(cfg.out)]),
                             cli.main(["secrets", "resolve", open_fp, "accepted", "kept on purpose",
                                       "--out", str(cfg.out)]),
                             cli.main(["secrets", "report", "--out", str(cfg.out)]),
                             cli.main(["status", "--out", str(cfg.out)])]
            self.assertEqual(rc, 0)
            self.assertEqual(cli_codes, [1, 0, 1, 0])
            self.assertTrue(len(first["findings"]) >= len(PLANTED), "the scan found too little")

            walked = set()
            for path in sorted(cfg.out.rglob("*")):
                rel = path.relative_to(cfg.out)
                if rel.parts[0] == ".git" or not path.is_file():
                    continue
                walked.add(rel.as_posix())
                text = path.read_bytes().decode("utf-8", errors="replace")
                self.assertTrue(clean(text), f"planted value or window in {rel.as_posix()}")
            day = first["generated_at"][:10]
            expected = {"secrets.json", "SECRETS.md", f"reports/{day}-secrets.md", "log.md", "STATUS.md",
                        "status.json", store.IGNORE_FILE, store.DECISIONS_FILE}
            self.assertTrue(expected <= walked, "an output file was not written")
            history = tp.git(cfg.out, "log", "-p", "--all")
            self.assertTrue("SECRETS.md" in history, 'missing: "SECRETS.md"')
            self.assertTrue(clean(history), "planted value or window in the evidence git history")
            self.assertTrue(clean(printed.getvalue()), "planted value or window on stdout")
            self.assertTrue(clean(errors.getvalue()), "planted value or window on stderr")
            raw = cfg.out / ".cache" / "secrets" / "raw"
            self.assertEqual(sorted(p.name for p in raw.iterdir()) if raw.exists() else [], [])


if __name__ == "__main__":
    unittest.main()
