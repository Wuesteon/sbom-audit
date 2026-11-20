"""OpenVEX documents: add statements, load/validate, suppress findings."""
from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from sbomaudit import cli, vex
from sbomaudit.errors import VexError
from sbomaudit.model import Component, Finding
from tests.helpers import make_repo

PURL = "pkg:github/example-org/app"


def finding(vuln_id, aliases=(), project="app", branch="main", purl="pkg:npm/lodash@4.17.20"):
    comp = Component(ecosystem="npm", name="lodash", version="4.17.20", purl=purl, scope="required")
    return Finding(project=project, branch=branch, component=comp,
                   vulns=[{"id": vuln_id, "aliases": list(aliases), "severity": "HIGH"}])


class AddTests(unittest.TestCase):
    def test_add_creates_valid_openvex_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "security"
            p = vex.add(out, "app", PURL, "CVE-2021-23337", "not_affected",
                        justification="vulnerable_code_not_in_execute_path",
                        subcomponent="pkg:npm/lodash", author="alice@example.invalid")
            self.assertEqual(p, out / "vex" / "app.openvex.json")
            vex.add(out, "app", PURL, "GHSA-xxxx-yyyy-zzzz", "fixed", author="alice@example.invalid")
            doc = json.loads(p.read_text())
            self.assertEqual(doc["@context"], "https://openvex.dev/ns/v0.2.0")
            self.assertTrue(doc["@id"].startswith("https://github.com/Wuesteon/sbom-audit/vex/app/"))
            self.assertEqual(doc["author"], "alice@example.invalid")
            self.assertEqual(doc["version"], 2)
            dt.datetime.fromisoformat(doc["timestamp"])
            dt.datetime.fromisoformat(doc["last_updated"])
            self.assertEqual(len(doc["statements"]), 2)
            first = doc["statements"][0]
            self.assertEqual(first["vulnerability"], {"name": "CVE-2021-23337"})
            self.assertEqual(first["products"], [{"@id": PURL, "subcomponents": [{"@id": "pkg:npm/lodash"}]}])
            self.assertEqual(first["status"], "not_affected")
            self.assertEqual(first["justification"], "vulnerable_code_not_in_execute_path")
            self.assertEqual(doc["statements"][1]["products"], [{"@id": PURL}])
            self.assertNotIn("justification", doc["statements"][1])

            statements = vex.load_all(out)
            self.assertEqual([s.vuln for s in statements], ["CVE-2021-23337", "GHSA-xxxx-yyyy-zzzz"])
            self.assertEqual(statements[0].product, PURL)
            self.assertEqual(statements[0].subcomponents, ["pkg:npm/lodash"])
            self.assertEqual(statements[0].project, "app")
            self.assertEqual(statements[1].subcomponents, [])
            self.assertIsNone(statements[1].justification)

    def test_not_affected_requires_justification(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            with self.assertRaises(ValueError):
                vex.add(out, "app", PURL, "CVE-2021-23337", "not_affected")
            with self.assertRaises(ValueError):
                vex.add(out, "app", PURL, "CVE-2021-23337", "not_affected", justification="because")
            with self.assertRaises(ValueError):
                vex.add(out, "app", PURL, "CVE-2021-23337", "bogus_status")
            self.assertFalse((out / "vex").exists())
            vex.add(out, "app", PURL, "CVE-2021-23337", "affected", impact="patch planned")
            self.assertEqual(vex.load_all(out)[0].status, "affected")


    def test_no_author_and_no_git_identity_refuses(self):
        """Never a made-up author such as "sbom-audit": the decision needs a person."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            with unittest.mock.patch.object(vex, "default_author", return_value=None):
                with self.assertRaisesRegex(ValueError, "--author"):
                    vex.add(out, "app", PURL, "CVE-2021-23337", "fixed")
                self.assertFalse((out / "vex").exists())
                vex.add(out, "app", PURL, "CVE-2021-23337", "fixed", author="alice@example.invalid")
            self.assertEqual(json.loads(vex.path(out, "app").read_text())["author"], "alice@example.invalid")

    def test_default_author_is_none_without_git_identity(self):
        empty = unittest.mock.Mock(stdout="")
        with unittest.mock.patch.object(vex.subprocess, "run", return_value=empty):
            self.assertIsNone(vex.default_author())


class LoadTests(unittest.TestCase):
    def test_malformed_vex_file_aborts(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "vex").mkdir()
            bad = out / "vex" / "app.openvex.json"
            bad.write_text("{not json")
            with self.assertRaises(VexError) as ctx:
                vex.load_all(out)
            self.assertEqual(ctx.exception.path, bad)
            bad.write_text(json.dumps({"@context": "https://openvex.dev/ns/v0.2.0", "author": "x"}))
            with self.assertRaises(VexError) as ctx:
                vex.load_all(out)
            self.assertIn("statements", ctx.exception.reason)
            bad.write_text(json.dumps({"@context": "https://openvex.dev/ns/v0.2.0", "statements": [
                {"vulnerability": {"name": "CVE-1"}, "products": [{"@id": PURL}], "status": "maybe"}]}))
            with self.assertRaises(VexError) as ctx:
                vex.load_all(out)
            self.assertIn("maybe", ctx.exception.reason)

    def test_load_all_without_vex_folder_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(vex.load_all(Path(tmp)), [])


class ApplyTests(unittest.TestCase):
    def test_apply_matches_on_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            vex.add(out, "app", PURL, "CVE-2021-23337", "not_affected", justification="component_not_present")
            statements = vex.load_all(out)
        hit = finding("GHSA-35jh-r3h4-6jhm", aliases=["CVE-2021-23337"])
        other = finding("GHSA-29mw-wpgm-hmr9", aliases=["CVE-2020-28500"])
        kept, suppressed = vex.apply([hit, other], statements)
        self.assertEqual([f.vulns[0]["id"] for f in kept], ["GHSA-29mw-wpgm-hmr9"])
        self.assertEqual(len(suppressed), 1)
        self.assertEqual(suppressed[0].finding.vulns[0]["id"], "GHSA-35jh-r3h4-6jhm")
        self.assertEqual(suppressed[0].statement.justification, "component_not_present")

    def test_apply_respects_branch_suffix(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            vex.add(out, "app", f"{PURL}@dev", "CVE-2021-23337", "fixed")
            statements = vex.load_all(out)
        on_main = finding("CVE-2021-23337", branch="main")
        on_dev = finding("CVE-2021-23337", branch="dev")
        kept, suppressed = vex.apply([on_main, on_dev], statements)
        self.assertEqual([f.branch for f in kept], ["main"])
        self.assertEqual([s.finding.branch for s in suppressed], ["dev"])

    def test_apply_branch_suffix_with_slash_is_percent_encoded(self):
        """A branch or release label with "/" (`tags/v1`, `feature/x`) is written percent-encoded after `@`."""
        self.assertEqual(vex.split_product(f"{PURL}@tags%2Fv1.0"), (PURL, "tags/v1.0"))
        self.assertEqual(vex.product_for_branch(PURL, "feature/x"), f"{PURL}@feature%2Fx")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            vex.add(out, "app", vex.product_for_branch(PURL, "tags/v1"), "CVE-2021-23337", "fixed")
            statements = vex.load_all(out)
        kept, suppressed = vex.apply([finding("CVE-2021-23337", branch="main"),
                                      finding("CVE-2021-23337", branch="tags/v1")], statements)
        self.assertEqual([f.branch for f in kept], ["main"])
        self.assertEqual([s.finding.branch for s in suppressed], ["tags/v1"])

    def test_apply_subcomponent_matches_with_or_without_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            vex.add(out, "app", PURL, "CVE-1", "not_affected", justification="component_not_present",
                    subcomponent="pkg:npm/lodash")
            vex.add(out, "app", PURL, "CVE-2", "not_affected", justification="component_not_present",
                    subcomponent="pkg:npm/lodash@4.17.21")
            vex.add(out, "app", PURL, "CVE-3", "not_affected", justification="component_not_present",
                    subcomponent="pkg:npm/left-pad")
            statements = vex.load_all(out)
        f1 = finding("CVE-1", purl="pkg:npm/lodash@4.17.20?package-id=abc")
        f2 = finding("CVE-2")                      # statement names a different version
        f3 = finding("CVE-3")                      # statement names a different package
        kept, suppressed = vex.apply([f1, f2, f3], statements)
        self.assertEqual(sorted(f.vulns[0]["id"] for f in kept), ["CVE-2", "CVE-3"])
        self.assertEqual([s.finding.vulns[0]["id"] for s in suppressed], ["CVE-1"])

    def test_apply_affected_annotates_but_keeps(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            vex.add(out, "app", PURL, "CVE-1", "under_investigation")
            statements = vex.load_all(out)
        f = finding("CVE-1")
        f.vulns.append({"id": "CVE-9", "aliases": []})
        kept, suppressed = vex.apply([f], statements)
        self.assertEqual(suppressed, [])
        self.assertEqual(kept[0].vulns[0]["vex"], "under_investigation")
        self.assertNotIn("vex", kept[0].vulns[1])

    def test_apply_other_project_statement_does_not_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            vex.add(out, "other", "pkg:github/example-org/other", "CVE-1", "fixed")
            statements = vex.load_all(out)
        kept, suppressed = vex.apply([finding("CVE-1")], statements)
        self.assertEqual(len(kept), 1)
        self.assertEqual(suppressed, [])

    def test_apply_with_purl_map_matches_on_product(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            vex.add(out, "app", PURL, "CVE-1", "fixed")
            statements = vex.load_all(out)
        kept, suppressed = vex.apply([finding("CVE-1")], statements, purl_of={"app": "pkg:github/x/y"})
        self.assertEqual(suppressed, [], "product purl differs from the project's purl")
        kept, suppressed = vex.apply([finding("CVE-1")], statements, purl_of={"app": PURL})
        self.assertEqual(len(suppressed), 1)


class CliTests(unittest.TestCase):
    def test_vex_add_command_without_author_or_git_identity_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "PROJECTS"
            make_repo(root, "app", {"README.md": "hi\n"}, remote="git@github.com:Example-Org/App.git")
            out = root / "security"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                 unittest.mock.patch.object(vex, "default_author", return_value=None):
                rc = cli.main(["vex", "add", "app", "CVE-2021-23337", "fixed", "--out", str(out)])
            self.assertEqual(rc, 2)
            self.assertIn("--author", buf.getvalue())
            self.assertFalse((out / "vex").exists())

    def test_vex_add_command_resolves_project_purl(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "PROJECTS"
            make_repo(root, "app", {"README.md": "hi\n"}, remote="git@github.com:Example-Org/App.git")
            out = root / "security"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.main(["vex", "add", "app", "CVE-2021-23337", "not_affected",
                               "--justification", "component_not_present", "--subcomponent", "pkg:npm/lodash",
                               "--author", "tester", "--out", str(out)])
            self.assertEqual(rc, 0)
            self.assertIn("pkg:github/example-org/app", buf.getvalue())
            doc = json.loads((out / "vex" / "app.openvex.json").read_text())
            self.assertEqual(doc["statements"][0]["products"][0]["@id"], "pkg:github/example-org/app")
            self.assertEqual(doc["author"], "tester")
            with contextlib.redirect_stdout(io.StringIO()):
                rc = cli.main(["vex", "add", "nope", "CVE-1", "fixed", "--out", str(out)])
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
