"""parity.py: compares two audit.json files by (project, branch, name, version, vuln id)."""
import io
import json
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import parity  # noqa: E402


def entry(name, version, locs, ids, ecosystem="npm", kev=False):
    return {"ecosystem": ecosystem, "name": name, "version": version, "kev": kev,
            "locations": [{"project": p, "branch": b} for p, b in locs],
            "vulns": [{"id": i, "aliases": a} for i, a in ids]}


OLD = {"vulnerabilities": [
    entry("lodash", "4.17.20", [("alpha", "main")], [("GHSA-1", ["CVE-1"])]),
    entry("Pillow", "9.0.0", [("beta", "main")], [("PYSEC-2", ["CVE-2"])], ecosystem="PyPI", kev=True),
    entry("gone", "1.0.0", [("alpha", "dev")], [("GHSA-3", [])]),
], "runtimes": [{"product": "nodejs", "cycle": "18", "status": "EOL"}],
    "unpinned_images": [{"image": "nginx:alpine"}]}

NEW = {"vulnerabilities": [
    entry("lodash", "4.17.20", [("alpha", "main")], [("CVE-1", ["GHSA-1"])]),      # same, id/alias swapped
    entry("pillow", "9.0.0", [("beta", "main")], [("CVE-2", ["PYSEC-2"])], ecosystem="PyPI", kev=True),  # PyPI case
    entry("extra", "2.0.0", [("alpha", "main")], [("GHSA-9", [])]),              # new only
], "runtimes": [{"product": "nodejs", "cycle": "18", "status": "EOL"}, {"product": "deno", "cycle": "1", "status": "EOL"}],
    "unpinned_images": [{"image": "nginx:alpine"}, {"image": "caddy:2-alpine"}]}


class ParityTest(unittest.TestCase):
    def test_tuples_match_across_alias_and_case(self):
        old, new = parity.tuples(OLD), parity.tuples(NEW)
        missing, added = parity.diff(old, new)
        self.assertEqual(missing, {("alpha", "dev", "npm", "gone", "1.0.0", "GHSA-3")})
        self.assertEqual(added, {("alpha", "main", "npm", "extra", "2.0.0", "GHSA-9")})

    def test_counts_and_exit_code(self):
        self.assertEqual(parity.counts(NEW), {"kev": 1, "eol": 2, "floating": 2})
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / "old.json", Path(tmp) / "new.json"
            a.write_text(json.dumps(OLD)); b.write_text(json.dumps(NEW))
            buf = io.StringIO()
            with unittest.mock.patch("sys.stdout", buf):
                rc = parity.main([str(a), str(b)])
            self.assertEqual(rc, 1)
            self.assertIn("gone", buf.getvalue())
            self.assertIn("KEV", buf.getvalue())
            b.write_text(json.dumps({**NEW, "vulnerabilities": NEW["vulnerabilities"] + [OLD["vulnerabilities"][2]]}))
            with unittest.mock.patch("sys.stdout", io.StringIO()):
                self.assertEqual(parity.main([str(a), str(b)]), 0)


if __name__ == "__main__":
    unittest.main()
