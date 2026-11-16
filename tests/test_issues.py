"""issues.json / ISSUES.md: the flat work list of open issues and where they occur."""
from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sbomaudit import cli, issues


def vuln(name, sev, locations, kev=False, fixed=("1.2.0", None)):
    return {"ecosystem": "npm", "name": name, "version": "1.0.0", "scope": "required", "direct_anywhere": True,
            "locations": [{"project": p, "branch": b, "manifest": m, "direct": True, "scope": s}
                          for p, b, m, s in locations],
            "vulns": [{"id": f"GHSA-{name}-{n}", "cves": [], "summary": "s", "severity": sev, "kev": kev,
                       "fixed_in": f} for n, f in enumerate(fixed)],
            "max_severity": sev, "kev": kev}


def make_rep(**kw):
    rep = {"generated_at": "2026-11-10T10:00:00+01:00", "production_projects": ["prod"], "vulnerabilities": [],
           "runtimes": [], "unpinned_images": [], "suppressed": [{"name": "hidden"}]}
    rep.update(kw)
    return rep


def secret(fp, cls, status="open", **kw):
    f = {"fingerprint": fp, "value_id": "v-" + fp, "repo": "prod", "branches": ["main"], "commit": "abc1234",
         "file": ".env", "line": 3, "rule_id": "stripe-key", "provider": "stripe", "class": cls,
         "live_in_tree": True, "age_days": 9, "status": status, "first_seen": "2026-10-01"}
    f.update(kw)
    return f


def host_doc(findings, production=True):
    return {"last_checked": "2026-11-11T03:00:00Z",
            "hosts": {"web": {"status": "ok", "production": production, "projects": ["prod"], "findings": findings}}}


def by_id(doc):
    return {i["id"]: i for i in doc["issues"]}


class BuildTest(unittest.TestCase):
    def test_one_vulnerability_issue_per_project_and_manifest_with_its_branches(self):
        rep = make_rep(vulnerabilities=[vuln("lib", "HIGH", [
            ("prod", "main", "package.json", "required"), ("prod", "dev", "package.json", "required"),
            ("prod", "main", "tools/package.json", "optional"), ("side", "main", "package.json", "required")])])
        got = by_id(issues.build(rep, None, None))
        self.assertEqual(sorted(got), ["vuln:prod:package.json:npm:lib@1.0.0",
                                       "vuln:prod:tools/package.json:npm:lib@1.0.0",
                                       "vuln:side:package.json:npm:lib@1.0.0"])
        main = got["vuln:prod:package.json:npm:lib@1.0.0"]
        self.assertEqual(main["where"], {"project": "prod", "branches": ["dev", "main"],
                                         "path": "package.json", "line": None})
        self.assertEqual((main["priority"], main["reason"]), (3, "critical_high_production"))
        self.assertEqual(main["fix"]["action"], "upgrade")
        self.assertEqual(main["fix"]["target"], "1.2.0")
        self.assertEqual(main["fix"]["unfixed_advisories"], 1)
        # dev-only in production and anything outside production are not priority 3
        self.assertEqual(got["vuln:prod:tools/package.json:npm:lib@1.0.0"]["priority"], 6)
        self.assertEqual(got["vuln:side:package.json:npm:lib@1.0.0"]["priority"], 6)

    def test_kev_is_priority_two_everywhere_and_no_fix_is_said_so(self):
        rep = make_rep(vulnerabilities=[vuln("lib", "MEDIUM", [("side", "main", "uv.lock", "optional")],
                                             kev=True, fixed=(None,))])
        (issue,) = issues.build(rep, None, None)["issues"]
        self.assertEqual((issue["priority"], issue["reason"]), (2, "kev"))
        self.assertEqual(issue["fix"]["action"], "no_fix_released")
        self.assertIsNone(issue["fix"]["target"])

    def test_suppressed_findings_are_not_listed(self):
        doc = issues.build(make_rep(), None, None)
        self.assertEqual(doc["issues"], [])
        self.assertEqual(doc["counts"], {"total": 0, "by_priority": {}, "by_kind": {}})

    def test_only_open_secrets_and_never_a_value(self):
        secrets = {"generated_at": "t", "findings": [
            secret("fp-a", "A", secret="sk_live_VALUE", match="sk_live_VALUE"), secret("fp-b", "B"),
            secret("fp-c", "A", status="rotated"), secret("fp-d", "A", status="false_positive")]}
        doc = issues.build(make_rep(), secrets, None)
        got = by_id(doc)
        self.assertEqual(sorted(got), ["secret:fp-a", "secret:fp-b"])
        self.assertEqual((got["secret:fp-a"]["priority"], got["secret:fp-b"]["priority"]), (1, 3))
        self.assertEqual(got["secret:fp-a"]["where"],
                         {"project": "prod", "branches": ["main"], "path": ".env", "line": 3})
        self.assertEqual(got["secret:fp-a"]["fix"]["action"], "rotate")
        self.assertEqual(got["secret:fp-a"]["first_seen"], "2026-10-01")
        text = json.dumps(doc) + issues.render_md(doc)
        self.assertNotIn("sk_live_VALUE", text)
        self.assertNotIn("v-fp-a", text)            # the value id stays in secrets.json

    def test_eol_and_floating_tags(self):
        rep = make_rep(
            runtimes=[{"product": "nodejs", "cycle": "18", "status": "EOL", "eol_date": "2025-04-30", "latest": "18.20.8",
                       "locations": [{"project": "prod", "branch": "main", "source": "Dockerfile: FROM node:18"},
                                     {"project": "prod", "branch": "dev", "source": "Dockerfile: FROM node:18"}]},
                      {"product": "python", "cycle": "3.12", "status": "supported", "locations": [
                          {"project": "prod", "branch": "main", "source": ".python-version"}]},
                      {"product": "deno", "cycle": "2", "status": "EOL soon", "locations": [
                          {"project": "prod", "branch": "main", "source": "x"}]}],
            unpinned_images=[{"project": "prod", "branch": "main", "image": "redis:latest", "source": "compose.yml", "own": False},
                             {"project": "prod", "branch": "dev", "image": "redis:latest", "source": "compose.yml", "own": False},
                             {"project": "prod", "branch": "main", "image": "me/app:latest", "source": "compose.yml", "own": True}])
        got = by_id(issues.build(rep, None, None))
        eol = got["eol:prod:nodejs@18:Dockerfile: FROM node:18"]
        self.assertEqual(eol["priority"], 4)
        self.assertEqual(eol["where"], {"project": "prod", "branches": ["dev", "main"], "path": "Dockerfile", "line": None})
        self.assertEqual(got["floating:prod:compose.yml:redis:latest"]["priority"], 5)
        self.assertEqual(got["floating:prod:compose.yml:redis:latest"]["where"]["branches"], ["dev", "main"])
        self.assertEqual(got["floating:prod:compose.yml:me/app:latest"]["priority"], 6)
        self.assertEqual(len(got), 3)               # supported and "EOL soon" runtimes are not issues

    def test_host_findings_actionable_only(self):
        hosts = host_doc([
            {"id": "warning:ssh", "group": "warning", "text": "check failed", "accepted": True},
            {"id": "kev:CVE-1", "group": "kev", "text": "kev open", "package": "openssl"},
            {"id": "kev:CVE-2", "group": "kev", "text": "kev accepted", "accepted": True},
            {"id": "kev:CVE-3", "group": "kev", "text": "kev accepted since the check"},
            {"id": "vuln:curl", "group": "vuln", "text": "curl", "fixable": 2, "fix": "installable", "candidate": "8.5"},
            {"id": "vuln:zlib", "group": "vuln", "text": "zlib", "fixable": 0, "fix": "not released"},
            {"id": "change:port", "group": "change", "text": "new port"},
            {"id": "info:x", "group": "info", "text": "info"},
            {"id": "lynis-suggestion:Y", "group": "lynis_suggestion", "text": "suggestion"},
            {"id": "login:z", "group": "login", "text": "login"},
            {"group": "change", "text": "no id"}])
        got = by_id(issues.build(make_rep(), None, hosts, hosts_accepted={"web": {"kev:CVE-3"}}))
        self.assertEqual(sorted(got), ["host:web:change:port", "host:web:kev:CVE-1", "host:web:vuln:curl",
                                       "host:web:warning:ssh"])
        self.assertEqual(got["host:web:kev:CVE-1"]["priority"], 2)
        self.assertEqual(got["host:web:warning:ssh"]["priority"], 2)    # a failed check cannot be accepted away
        self.assertEqual(got["host:web:change:port"]["priority"], 6)
        self.assertEqual(got["host:web:vuln:curl"]["fix"], {**got["host:web:vuln:curl"]["fix"],
                                                            "action": "apt_upgrade", "target": "8.5"})
        self.assertEqual(got["host:web:kev:CVE-1"]["where"],
                         {"host": "web", "projects": ["prod"], "path": None, "line": None})

    def test_first_seen_is_kept_and_order_is_priority_then_production(self):
        rep = make_rep(vulnerabilities=[vuln("b", "HIGH", [("side", "main", "p.json", "required")]),
                                        vuln("a", "HIGH", [("prod", "main", "p.json", "required")])])
        secrets = {"findings": [secret("fp", "A")]}
        first = issues.build(rep, secrets, None, now="2026-11-01T00:00:00+00:00")
        second = issues.build(rep, secrets, None, previous=first, now="2026-11-13T00:00:00+00:00")
        self.assertEqual([i["id"] for i in second["issues"]],
                         ["secret:fp", "vuln:prod:p.json:npm:a@1.0.0", "vuln:side:p.json:npm:b@1.0.0"])
        self.assertEqual([i["first_seen"] for i in second["issues"]], ["2026-10-01", "2026-11-01", "2026-11-01"])
        self.assertEqual(second["counts"], {"total": 3, "by_priority": {"1": 1, "3": 1, "6": 1},
                                            "by_kind": {"secret": 1, "vulnerability": 2}})

    def test_incomplete_sources_are_carried_and_shown(self):
        failed = [{"source": "osv", "detail": "timeout"}]
        doc = issues.build(make_rep(), None, None, incomplete=failed)
        self.assertEqual(doc["incomplete"], failed)
        text = issues.render_md(doc)
        self.assertIn("**Incomplete:**", text)
        self.assertIn("- osv: timeout", text)
        self.assertNotIn("Nothing open.", text)     # a failed source is empty, not clean

    def test_markdown_names_a_few_branches_and_counts_the_rest(self):
        secrets = {"findings": [secret("fp", "A", branches=[f"b{n}" for n in range(9)])]}
        doc = issues.build(make_rep(), secrets, None)
        self.assertEqual(len(doc["issues"][0]["where"]["branches"]), 9)
        self.assertIn("(b0, b1, b2 +6 more)", issues.render_md(doc))


class RefreshTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name) / "security"
        self.out.mkdir()

    def write(self, name, doc):
        (self.out / name).write_text(json.dumps(doc), encoding="utf-8")

    def run_cli(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = cli.main([*argv, "--out", str(self.out)])
        return code, buf.getvalue()

    def test_refresh_writes_both_files_from_the_reports_on_disk(self):
        self.write("audit.json", make_rep(vulnerabilities=[vuln("a", "HIGH", [("prod", "main", "p.json", "required")])]))
        self.write("secrets.json", {"findings": [secret("fp", "A")]})
        self.write("hosts.json", host_doc([{"id": "kev:CVE-1", "group": "kev", "text": "kev"}]))
        self.write("status.json", {"failed_sources": [{"source": "kev", "detail": "HTTPError"}]})
        paths = issues.refresh(self.out)
        self.assertEqual([p.name for p in paths], ["issues.json", "ISSUES.md"])
        doc = issues.read(self.out)
        # no [hosts] in the config: an old hosts.json contributes nothing
        self.assertEqual(doc["counts"]["by_kind"], {"secret": 1, "vulnerability": 1})
        self.assertEqual(doc["incomplete"], [{"source": "kev", "detail": "HTTPError"}])
        self.assertEqual(issues.refresh(self.out, hosts_active=True) and
                         issues.read(self.out)["counts"]["by_kind"], {"secret": 1, "vulnerability": 1, "host": 1})
        self.assertIn("## Host web (production)", (self.out / "ISSUES.md").read_text(encoding="utf-8"))

    def test_disabled_secrets_step_contributes_nothing(self):
        self.write("audit.json", make_rep())
        self.write("secrets.json", {"findings": [secret("fp", "A")]})
        (self.out / "sbom-audit.toml").write_text("[secrets]\nenabled = false\n", encoding="utf-8")
        issues.refresh(self.out)
        self.assertEqual(issues.read(self.out)["issues"], [])

    def test_try_refresh_reports_the_type_and_never_raises(self):
        said = []
        with mock.patch.object(issues, "build", side_effect=KeyError("secret detail")):
            self.assertEqual(issues.try_refresh(self.out, said.append), [])
        self.assertEqual(said, ["issues: not refreshed (KeyError)"])

    def test_cli_needs_an_audit_and_prints_the_counts(self):
        code, text = self.run_cli("issues")
        self.assertEqual(code, 2)
        self.assertIn("no audit.json yet", text)
        self.assertFalse((self.out / "issues.json").exists())
        self.write("audit.json", make_rep(vulnerabilities=[vuln("a", "HIGH", [("prod", "main", "p.json", "required")])]))
        code, text = self.run_cli("issues")
        self.assertEqual(code, 0)
        self.assertIn("1 open issues (P3: 1); issues.json and ISSUES.md written", text)

    def test_file_has_one_issue_per_line_and_no_advisory_texts(self):
        long_text = "a very long advisory summary " * 5
        v = vuln("a", "HIGH", [("prod", "main", "p.json", "required")])
        v["vulns"][1].update(severity="CRITICAL", summary=long_text)
        self.write("audit.json", make_rep(vulnerabilities=[v, vuln("b", "LOW", [("side", "main", "p.json", "required")])]))
        issues.refresh(self.out)
        text = (self.out / "issues.json").read_text(encoding="utf-8")
        doc = json.loads(text)
        lines = [line for line in text.splitlines() if line.startswith('{"id"')]
        self.assertEqual(len(lines), len(doc["issues"]))
        self.assertEqual(json.loads(lines[0].rstrip(","))["id"], doc["issues"][0]["id"])
        first = doc["issues"][0]["details"]
        self.assertEqual(first["worst"], {"id": "GHSA-a-1", "severity": "CRITICAL", "summary": long_text})
        self.assertEqual(text.count(long_text), 1)                  # once, on the advisory to read first
        self.assertEqual(first["advisories"][0], {"id": "GHSA-a-0", "cves": [], "severity": "HIGH", "fixed_in": "1.2.0"})
        self.write("audit.json", make_rep())
        issues.refresh(self.out)
        self.assertEqual(json.loads((self.out / "issues.json").read_text(encoding="utf-8"))["issues"], [])

    def test_query_selects_prints_and_writes_nothing(self):
        code, text = self.run_cli("issues", "--json")
        self.assertEqual(code, 2)
        self.assertIn("no issues.json yet", text)
        self.write("audit.json", make_rep(vulnerabilities=[
            vuln("a", "HIGH", [("prod", "main", "p.json", "required"), ("side", "main", "p.json", "required")])]))
        self.write("secrets.json", {"findings": [secret("fp", "A")]})
        self.write("hosts.json", host_doc([{"id": "kev:CVE-1", "group": "kev", "text": "kev"}]))
        issues.refresh(self.out, hosts_active=True)
        stamp = (self.out / "issues.json").stat().st_mtime_ns
        with mock.patch.dict(os.environ, {"SBOM_AUDIT_READ_ONLY": "1"}):       # a query is a read
            code, text = self.run_cli("issues", "--project", "prod", "--json")
        self.assertEqual(code, 0)
        got = json.loads(text)
        # the project's own issues and the host that runs it
        self.assertEqual([i["id"] for i in got["issues"]],
                         ["secret:fp", "host:web:kev:CVE-1", "vuln:prod:p.json:npm:a@1.0.0"])
        self.assertEqual(got["counts"]["total"], 3)
        code, text = self.run_cli("issues", "--max-priority", "2", "--kind", "host")
        self.assertEqual(code, 0)
        self.assertIn("P2 host          web: kev [review] host:web:kev:CVE-1", text)
        self.assertIn("1 of 4 open issues", text)
        code, text = self.run_cli("issues", "--host", "nope")
        self.assertIn("0 of 4 open issues", text)
        self.assertEqual((self.out / "issues.json").stat().st_mtime_ns, stamp)

    def test_cli_is_refused_in_read_only_mode(self):
        self.write("audit.json", make_rep())
        with mock.patch.dict(os.environ, {"SBOM_AUDIT_READ_ONLY": "1"}):
            code, _ = self.run_cli("issues")
        self.assertEqual(code, 5)
        self.assertFalse((self.out / "issues.json").exists())


if __name__ == "__main__":
    unittest.main()
