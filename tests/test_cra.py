"""CRA readiness: config, the checks per obligation, init (plan, confirm, never overwrite), REPORT.html."""
import contextlib
import datetime as dt
import io
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sbomaudit import config, cra, management
from sbomaudit import cli
from sbomaudit.errors import ConfigError
from tests.helpers import make_repo

TODAY = dt.date(2026, 11, 18)
FILLED_SECURITY_MD = "# Security policy\n\nReport vulnerabilities to security@example.invalid.\n"
VALID_TXT = "Contact: mailto:security@example.invalid\nExpires: 2027-06-30T00:00:00Z\n"
# claims no output or template may make; the negating caveat ("does not decide whether ... meets it") is fine
CLAIMS = re.compile(r"\b(is|are|being|fully|now)\s+(cra[- ])?(compliant|conform|certified)\b|cra-conform|"
                    r"\b(ist|sind)\s+(cra-)?(konform|zertifiziert)\b", re.I)


def statuses(product: dict) -> dict:
    return {o["id"]: o for o in product["obligations"]}


class CraTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()
        self.out = self.tmp / "security"
        self.out.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def config(self, body: str, base: str = 'branches = ["main", "dev"]\n') -> None:
        (self.out / "sbom-audit.toml").write_text(base + body)

    def check(self, **kw) -> dict:
        kw.setdefault("today", TODAY)
        kw.setdefault("fetch", self.no_fetch)
        return cra.check(config.load(self.out), self.out, **kw)

    def no_fetch(self, origin):
        raise AssertionError(f"fetched {origin} although check_well_known is off")

    def main(self, *argv) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                patch.dict(os.environ, {"SBOM_AUDIT_READ_ONLY": ""}):
            code = cli.main([*argv, "--out", str(self.out)])
        return code, out.getvalue(), err.getvalue()

    def repo_files(self, repo: Path) -> str:
        return subprocess.run(["git", "-C", str(repo), "status", "--porcelain", "--ignored"],
                              text=True, capture_output=True, check=True).stdout


class ConfigTests(CraTestCase):
    def test_absent_table_means_no_products(self):
        self.config("")
        ccfg = cra.load_config(self.out)
        self.assertEqual(ccfg.products, [])
        self.assertEqual(ccfg.review_interval_days, cra.DEFAULT_REVIEW_DAYS)
        self.assertFalse(ccfg.check_well_known)

    def test_products_and_keys(self):
        self.config('[cra]\nreview_interval_days = 180\naudit_max_age_days = 3\ncheck_well_known = true\n'
                    '[cra.products."shop"]\nname = "Shop"\nbranch = "dev"\nurl = "https://shop.example/"\n'
                    '[cra.products."api"]\n')
        ccfg = cra.load_config(self.out)
        self.assertEqual((ccfg.review_interval_days, ccfg.audit_max_age_days, ccfg.check_well_known), (180, 3, True))
        shop, api = ccfg.products
        self.assertEqual((shop.key, shop.name, shop.branch, shop.url), ("shop", "Shop", "dev", "https://shop.example"))
        self.assertEqual((api.key, api.name, api.branch, api.url), ("api", "api", None, None))

    def test_invalid_values_raise(self):
        cases = ['[cra]\nreview_interval_days = "a year"\n', '[cra]\nreview_interval_days = 0\n',
                 '[cra]\ncheck_well_known = "yes"\n', '[cra]\nproducts = 3\n', '[cra.products]\nshop = 1\n',
                 '[cra.products.shop]\nurl = "http://shop.example"\n',
                 '[cra.products.shop]\nurl = "https://shop.example/path?x=1"\n',
                 '[cra.products.shop]\nurl = "https://user:pw@shop.example"\n', '[cra.products.shop]\nbranch = 1\n']
        for body in cases:
            self.config(body)
            with self.subTest(body=body), self.assertRaises(ConfigError):
                cra.load_config(self.out)


class SecurityTxtTests(unittest.TestCase):
    def test_states(self):
        cases = [(VALID_TXT, "present"),
                 ("Expires: 2027-06-30T00:00:00Z\n", "missing"),                     # no Contact
                 ("Contact: mailto:a@b.invalid\n", "missing"),                         # no Expires
                 (VALID_TXT + "Expires: 2027-07-30T00:00:00Z\n", "missing"),           # two Expires
                 ("Contact: mailto:a@b.invalid\nExpires: next year\n", "missing"),     # not RFC 3339
                 ("Contact: mailto:a@b.invalid\nExpires: 2026-01-01T00:00:00Z\n", "stale"),
                 ("# " + cra.STARTER_MARK + "\n" + VALID_TXT, "missing")]
        for text, want in cases:
            with self.subTest(text=text):
                self.assertEqual(cra.security_txt_state(text, TODAY)[0], want)

    def test_far_expires_gets_a_note(self):
        status, note = cra.security_txt_state("Contact: mailto:a@b.invalid\nExpires: 2029-01-01T00:00:00Z\n", TODAY)
        self.assertEqual(status, "present")
        self.assertIn("less than a year", note)

    def test_review_date_both_languages(self):
        self.assertEqual(cra.reviewed_on("x\nLast reviewed: 2026-03-01\n"), dt.date(2026, 3, 1))
        self.assertEqual(cra.reviewed_on("Zuletzt geprüft: 2026-03-02"), dt.date(2026, 3, 2))
        self.assertIsNone(cra.reviewed_on("Last reviewed: ____-__-__"))


class CheckTests(CraTestCase):
    def test_bare_repository_reads_missing_and_manufacturer_rows(self):
        repo = make_repo(self.tmp, "shop", {"README.md": "x\n"})
        self.config('[cra.products."shop"]\n')
        p = self.check()["products"]["shop"]
        s = statuses(p)
        self.assertEqual(p["branch"], "main")
        self.assertIsNone(p["error"])
        for oid in cra.OBLIGATIONS:
            self.assertEqual(s[oid]["status"], "missing", oid)
        for oid in cra.MANUFACTURER:
            self.assertEqual(s[oid]["status"], "manufacturer", oid)
        self.assertEqual(s["released_versions"]["note"], "no released versions under audit")
        self.assertEqual(s["support_period"]["note"], "no released versions under audit")
        self.assertIn("check_well_known", s["security_txt"]["note"])
        for o in p["obligations"]:
            self.assertTrue(o["ref"], o["id"])
            self.assertIn(o["status"], cra.STATUSES)
        self.assertEqual(self.repo_files(repo), "")

    def test_repository_files_are_read_from_the_branch_not_the_working_tree(self):
        repo = make_repo(self.tmp, "shop", {".github/SECURITY.md": FILLED_SECURITY_MD,
                                            ".well-known/security.txt": VALID_TXT})
        (repo / "SECURITY.md").write_text(FILLED_SECURITY_MD)        # untracked: must not count
        self.config('[cra.products."shop"]\n')
        s = statuses(self.check()["products"]["shop"])
        self.assertEqual(s["contact"]["status"], "present")
        self.assertEqual(s["contact"]["evidence"], ["shop@main:.github/SECURITY.md"])
        self.assertEqual(s["security_txt"]["status"], "present")
        self.assertEqual(s["security_txt"]["evidence"], ["shop@main:.well-known/security.txt"])

    def test_starter_security_md_in_the_repository_counts_as_missing(self):
        make_repo(self.tmp, "shop", {"SECURITY.md": f"<!-- {cra.STARTER_MARK} -->\n# x\n"})
        self.config('[cra.products."shop"]\n')
        s = statuses(self.check()["products"]["shop"])
        self.assertEqual(s["contact"]["status"], "missing")
        self.assertEqual(s["contact"]["evidence"], ["shop@main:SECURITY.md"])

    def test_configured_branch_and_unknown_project(self):
        make_repo(self.tmp, "shop", {"README.md": "x\n"}, branches=["main", "dev"])
        self.config('[cra.products."shop"]\nbranch = "dev"\n[cra.products."ghost"]\n')
        products = self.check()["products"]
        self.assertEqual(products["shop"]["branch"], "dev")
        self.assertIn("no project 'ghost'", products["ghost"]["error"])
        self.assertEqual(statuses(products["ghost"])["contact"]["status"], "missing")

    def test_risk_assessment_starter_review_date_and_stale(self):
        make_repo(self.tmp, "shop", {"README.md": "x\n"})
        self.config('[cra]\nreview_interval_days = 30\n[cra.products."shop"]\n')
        doc = self.out / "cra" / "shop" / "risk-assessment.md"
        doc.parent.mkdir(parents=True)
        cases = [(f"<!-- {cra.STARTER_MARK} -->\nLast reviewed: 2026-11-01\n", "missing"),
                 ("# Risk\nno date\n", "missing"),
                 ("# Risk\nLast reviewed: 2026-11-01\n", "present"),
                 ("# Risk\nZuletzt geprüft: 2026-01-01\n", "stale")]
        for text, want in cases:
            doc.write_text(text)
            with self.subTest(text=text):
                o = statuses(self.check()["products"]["shop"])["risk_assessment"]
                self.assertEqual(o["status"], want)
                self.assertEqual(o["evidence"], ["cra/shop/risk-assessment.md"])

    def test_audit_sbom_trail_and_kev_note(self):
        make_repo(self.tmp, "shop", {"README.md": "x\n"})
        self.config('[cra]\naudit_max_age_days = 8\n[cra.products."shop"]\n')
        (self.out / "sbom" / "shop").mkdir(parents=True)
        (self.out / "sbom" / "shop" / "main.cdx.json").write_text("{}")
        (self.out / "log.md").write_text("run\n")
        (self.out / "vex").mkdir()
        (self.out / "vex" / "shop.openvex.json").write_text("{}")
        recent = dt.datetime.now().astimezone().replace(microsecond=0).isoformat()
        kev = {"id": "CVE-2026-1", "kev": True, "locations": [{"project": "shop", "branch": "main"}]}
        other = {"id": "CVE-2026-2", "kev": True, "locations": [{"project": "else", "branch": "main"}]}
        (self.out / "audit.json").write_text(json.dumps({"generated_at": recent, "vulnerabilities": [kev, other]}))
        p = self.check(today=dt.date.today())["products"]["shop"]
        s = statuses(p)
        self.assertEqual(s["sbom"]["evidence"], ["sbom/shop/main.cdx.json"])
        self.assertEqual(s["sbom"]["status"], "missing")              # "{}" is a file, not a CycloneDX SBOM
        self.assertIn("structural errors (bom-format, spec-version)", s["sbom"]["note"])
        self.assertEqual(s["vulnerability_handling"]["status"], "present")
        self.assertEqual(s["decisions_trail"]["status"], "present")
        self.assertIn("vex/shop.openvex.json", s["decisions_trail"]["evidence"])
        self.assertEqual(p["kev_open"], 1)
        self.assertIn("cra/shop/art14-procedure.md", s["reporting"]["note"])
        self.assertIn("Art. 14(2)(a)", s["reporting"]["note"])
        self.assertEqual(s["reporting"]["status"], "missing")          # the KEV is a note, not a verdict
        old = "2026-01-01T00:00:00+00:00"
        (self.out / "audit.json").write_text(json.dumps({"generated_at": old, "vulnerabilities": []}))
        s = statuses(self.check()["products"]["shop"])
        self.assertEqual(s["vulnerability_handling"]["status"], "stale")

    def test_sbom_valid_with_coverage_note_and_slash_branch(self):
        make_repo(self.tmp, "shop", {"README.md": "x\n"}, branches=["main", "release/1"])
        self.config('[cra.products."shop"]\nbranch = "release/1"\n')
        doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
               "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
               "metadata": {"timestamp": "2026-11-18T10:00:00Z",
                            "component": {"bom-ref": "shop", "type": "application", "name": "shop", "version": "1"}},
               "components": [{"bom-ref": "a", "type": "library", "name": "a", "version": "1", "purl": "pkg:npm/a@1"}],
               "dependencies": [{"ref": "shop", "dependsOn": ["a"]}]}
        (self.out / "sbom" / "shop").mkdir(parents=True)
        (self.out / "sbom" / "shop" / "release__1.cdx.json").write_text(json.dumps(doc))
        s = statuses(self.check()["products"]["shop"])
        self.assertEqual((s["sbom"]["status"], s["sbom"]["evidence"]), ("present", ["sbom/shop/release__1.cdx.json"]))
        self.assertIn("1 component entries: version 100%, purl 100%, licence 0%", s["sbom"]["note"])
        self.assertIn("dependency graph yes", s["sbom"]["note"])
        self.assertNotRegex(s["sbom"]["note"], r"(?i)compl(y|ies|iant)|meets")
        # a firmware tree the scan could not see into: the row says so instead of reading as complete
        gap = {"submodules": [{"path": "lib/mbedtls", "url": ""}], "submodule_count": 1, "manifests": [],
               "manifest_count": 0, "c_sources": 900}
        (self.out / "inventory.json").write_text(json.dumps({"inventories": [
            {"project": "shop", "branch": "release/1", "ref": "x", "commit": "y", "components": [],
             "coverage_gaps": gap}]}))
        note = statuses(self.check()["products"]["shop"])["sbom"]["note"]
        self.assertIn("INCOMPLETE, coverage gap: 1 git submodule(s) not scanned (`lib/mbedtls`)", note)
        self.assertIn("900 C/C++ source files", note)

    def test_releases_json_present(self):
        make_repo(self.tmp, "shop", {"README.md": "x\n"})
        self.config('[cra.products."shop"]\n[cra.products."api"]\n')
        make_repo(self.tmp, "api", {"README.md": "x\n"})
        releases = {"schema": 1, "generated": "2026-11-18T00:00:00+00:00", "projects": {"shop": {
            "support": {"period_months": 60, "until": "2031-11-30"},
            "releases": [{"tag": "v1.0.0", "commit": "abc", "date": "2026-10-01", "supported": True,
                          "support_until": "2031-11-30", "sbom": "x", "open": {"kev": 1, "critical": 0, "high": 2},
                          "eol_before_support_end": ["nodejs 20"], "fixed_since_previous": []},
                         {"tag": "v0.9.0", "supported": False}]}}}
        (self.out / cra.RELEASES_JSON).write_text(json.dumps(releases))
        doc = self.check()
        self.assertTrue(doc["releases_json"])
        s = statuses(doc["products"]["shop"])
        self.assertEqual(s["support_period"]["status"], "present")
        self.assertIn("60 months", s["support_period"]["note"])
        self.assertEqual(s["released_versions"]["status"], "present")
        note = s["released_versions"]["note"]
        for needle in ("2 release(s), 1 supported", "v1.0.0: 1 open KEV", "nodejs 20"):
            self.assertIn(needle, note)
        api = statuses(doc["products"]["api"])                      # not in releases.json
        self.assertEqual(api["released_versions"]["note"], "no released versions under audit")

    def test_well_known_fetch_only_when_enabled(self):
        make_repo(self.tmp, "shop", {"README.md": "x\n"})
        self.config('[cra.products."shop"]\nurl = "https://shop.example"\n')
        self.assertEqual(statuses(self.check()["products"]["shop"])["security_txt"]["status"], "missing")
        self.config('[cra]\ncheck_well_known = true\n[cra.products."shop"]\nurl = "https://shop.example"\n')
        seen = []
        responses = {"ok": (200, VALID_TXT), "expired": (200, "Contact: x\nExpires: 2025-01-01T00:00:00Z\n"),
                     "404": (404, ""), "down": (None, "")}
        for name, (code, body) in responses.items():
            def fake(origin, code=code, body=body):
                seen.append(origin)
                return code, body
            with self.subTest(name=name):
                o = statuses(self.check(fetch=fake)["products"]["shop"])["security_txt"]
                want = {"ok": "present", "expired": "stale"}.get(name, "missing")
                self.assertEqual(o["status"], want)
                if name in ("ok", "expired"):
                    self.assertEqual(o["evidence"], ["https://shop.example/.well-known/security.txt"])
        self.assertEqual(set(seen), {"https://shop.example"})

    def test_cli_check_writes_two_files_and_run_step(self):
        make_repo(self.tmp, "shop", {"README.md": "x\n"})
        self.config("")
        code, _out, err = self.main("cra", "check")
        self.assertEqual(code, 2)
        self.assertIn("no product configured", err)
        self.assertEqual(cra.try_check(config.load(self.out), self.out, say=lambda _m: None), [])
        self.assertFalse((self.out / cra.CRA_JSON).exists())
        self.config('[cra.products."shop"]\n')
        code, out, _err = self.main("cra", "check")
        self.assertEqual(code, 0, out)
        doc = json.loads((self.out / cra.CRA_JSON).read_text())
        md = (self.out / cra.CRA_FILE).read_text()
        self.assertEqual(doc["caveat"], cra.CAVEAT)
        self.assertIn("not legal advice", md)
        self.assertIn("Art. 71(2)", md)
        self.assertIn("evidence missing", md)
        self.assertIsNone(CLAIMS.search(md), CLAIMS.search(md))
        (self.out / cra.CRA_JSON).unlink()
        said = []
        paths = cra.try_check(config.load(self.out), self.out, say=said.append)
        self.assertEqual(sorted(p.name for p in paths), [cra.CRA_FILE, cra.CRA_JSON])
        self.assertIn("readiness for 1 product(s)", said[0])

    def test_try_check_never_raises(self):
        self.config('[cra]\nreview_interval_days = "x"\n[cra.products."shop"]\n')
        said = []
        self.assertEqual(cra.try_check(config.load(self.out), self.out, say=said.append), [])
        self.assertIn("cra: skipped", said[0])


class InitTests(CraTestCase):
    def setUp(self):
        super().setUp()
        self.repo = make_repo(self.tmp, "shop", {"README.md": "x\n"})
        self.config('[cra.products."shop"]\nname = "Shop"\n')

    def test_plan_only_without_yes(self):
        code, out, _err = self.main("cra", "init", "shop")
        self.assertEqual(code, 0)
        self.assertIn("plan only: nothing written", out)
        self.assertIn("belongs in the product", out)
        self.assertFalse((self.out / "cra").exists())

    def test_yes_writes_never_overwrites_and_never_touches_the_repo(self):
        mine = self.out / "cra" / "shop" / "cvd-policy.md"
        mine.parent.mkdir(parents=True)
        mine.write_text("my own policy\n")
        code, out, _err = self.main("cra", "init", "shop", "--yes", "--lang", "de")
        self.assertEqual(code, 0, out)
        self.assertEqual(mine.read_text(), "my own policy\n")
        written = sorted(str(p.relative_to(self.out / "cra" / "shop")) for p in (self.out / "cra" / "shop").rglob("*")
                         if p.is_file())
        self.assertEqual(written, sorted(["art14-procedure.md", "art14/early-warning.md", "art14/final.md",
                                          "art14/notification.md", "cvd-policy.md", "proposed-for-repo/SECURITY.md",
                                          "proposed-for-repo/security.txt", "risk-assessment.md"]))
        risk = (self.out / "cra" / "shop" / "risk-assessment.md").read_text()
        self.assertIn("Shop", risk)
        self.assertIn("Zuletzt geprüft", risk)
        self.assertNotIn("{{", risk)
        self.assertEqual(self.repo_files(self.repo), "")
        # the starters count as missing until the user removes the first line
        s = statuses(self.check()["products"]["shop"])
        for oid in ("risk_assessment", "reporting"):
            self.assertEqual(s[oid]["status"], "missing", oid)
            self.assertIn("starter", s[oid]["note"])
        self.assertEqual(s["cvd_policy"]["status"], "present")      # the user's own file
        self.assertIn("proposed-for-repo/SECURITY.md", s["contact"]["note"])
        code, out, _err = self.main("cra", "init", "shop")
        self.assertEqual(out.count("exists, kept"), 8)

    def test_unknown_product_is_a_config_error(self):
        with contextlib.redirect_stderr(io.StringIO()):
            code, _out, _err = self.main("cra", "init", "other", "--yes")
        self.assertEqual(code, 2)
        self.assertFalse((self.out / "cra").exists())

    def test_read_only_mode(self):
        with patch.dict(os.environ, {"SBOM_AUDIT_READ_ONLY": "1"}), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["cra", "init", "shop", "--yes", "--out", str(self.out)]), 5)
            self.assertEqual(cli.main(["cra", "check", "--out", str(self.out)]), 5)
            self.assertEqual(cli.main(["cra", "init", "shop", "--out", str(self.out)]), 0)   # the plan writes nothing
        self.assertFalse((self.out / "cra").exists())
        self.assertFalse((self.out / cra.CRA_JSON).exists())


class TemplateTests(unittest.TestCase):
    def test_both_languages_have_every_starter_and_ask_rather_than_claim(self):
        for lang in cra.LANGUAGES:
            for tmpl, _dest in cra.STARTERS:
                text = (cra.TEMPLATE_DIR / lang / tmpl).read_text(encoding="utf-8")
                with self.subTest(lang=lang, tmpl=tmpl):
                    self.assertTrue(cra.is_starter(text))
                    self.assertIn("____", text)
                    self.assertIsNone(CLAIMS.search(text), CLAIMS.search(text))

    def test_art14_deadlines_in_the_procedure(self):
        for lang, needles in (("en", ("24 hours", "72 hours", "14 days", "one month")),
                              ("de", ("24 Stunden", "72 Stunden", "14 Tage", "eines Monats"))):
            text = (cra.TEMPLATE_DIR / lang / "art14-procedure.md").read_text(encoding="utf-8")
            for needle in needles:
                self.assertIn(needle, text, f"{lang}: {needle}")

    def test_risk_assessment_walks_annex_i(self):
        for lang in cra.LANGUAGES:
            text = (cra.TEMPLATE_DIR / lang / "risk-assessment.md").read_text(encoding="utf-8")
            for letter in "abcdefghijklm":
                self.assertRegex(text, rf"\|\s*\(?{letter}\)\s*\|", f"{lang}: Annex I Part I (2)({letter})")


class ReportTests(CraTestCase):
    def page(self, lang: str) -> str:
        if not (self.out / "audit.json").exists():
            (self.out / "audit.json").write_text(json.dumps({"generated_at": "2026-11-18T08:00:00+00:00",
                                                             "vulnerabilities": [], "sources": {}}))
        management.write(self.out, lang=lang, dated=False)
        return (self.out / management.REPORT_FILE).read_text(encoding="utf-8")

    def test_no_products_says_so_in_both_languages(self):
        self.assertIn("No product is configured", self.page("en"))
        self.assertIn("Kein Produkt konfiguriert", self.page("de"))

    def test_configured_but_not_run(self):
        self.config('[cra.products."shop"]\n')
        self.assertIn("cra.json is missing", self.page("en"))

    def test_readiness_table_per_product(self):
        make_repo(self.tmp, "shop", {"SECURITY.md": FILLED_SECURITY_MD})
        self.config('[cra.products."shop"]\nname = "Shop"\n')
        doc = self.check()
        doc["products"]["shop"]["kev_open"] = 2
        cra.write(self.out, doc)
        en, de = self.page("en"), self.page("de")
        for needle in ("CRA readiness per product", "Shop (project shop, branch main)", "evidence present",
                       "manufacturer&#x27;s responsibility", "shop@main:SECURITY.md", "Art. 13(17)",
                       "2 open KEV finding(s)", "cra/shop/art14-procedure.md"):
            self.assertIn(needle, en, needle)
        for needle in ("CRA-Bereitschaft je Produkt", "Nachweis vorhanden", "Verantwortung des Herstellers",
                       "Zentrale Anlaufstelle"):
            self.assertIn(needle, de, needle)
        self.assertIn("not legal advice", en.lower())
        for page in (en, de):
            self.assertIsNone(CLAIMS.search(page), CLAIMS.search(page))

    def test_unreadable_cra_json(self):
        (self.out / cra.CRA_JSON).write_text("{not json")
        self.assertIn("cra.json is unreadable", self.page("en"))

    def test_strings_cover_every_obligation(self):
        for lang in ("en", "de"):
            self.assertEqual(set(management.STRINGS[lang]["cra_ob"]), set(cra.OBLIGATIONS) | set(cra.MANUFACTURER))
            self.assertEqual(set(management.STRINGS[lang]["cra_status"]), set(cra.STATUSES))


if __name__ == "__main__":
    unittest.main()
