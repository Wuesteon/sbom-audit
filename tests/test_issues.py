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

from sbomaudit import cli, issues, report


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

    def test_go_mod_minimum_is_not_an_eol_issue(self):
        rep = make_rep(runtimes=[{"product": "go", "cycle": "1.20", "status": "minimum", "basis": "go.mod",
                                  "cycle_status": "EOL", "eol_date": "2024-02-06", "latest": "1.20.14",
                                  "locations": [{"project": "prod", "branch": "main", "source": "go.mod: go 1.20"}]}])
        doc = issues.build(rep, None, None)
        self.assertEqual(doc["issues"], [])

    def test_declared_minimum_allowing_eol_is_a_lower_priority_issue(self):
        rep = make_rep(runtimes=[
            {"product": "python", "cycle": "3.8", "status": "minimum", "basis": "requires-python",
             "cycle_status": "EOL", "eol_date": "2024-10-07", "latest": "3.8.20",
             "locations": [{"project": "prod", "branch": "main", "source": "pyproject.toml: requires-python >=3.8",
                            "declared": ["requires-python >=3.8"], "pinned": []},
                           {"project": "prod", "branch": "dev", "source": "pyproject.toml: requires-python >=3.8",
                            "declared": ["requires-python >=3.8"], "pinned": []}]},
            {"product": "python", "cycle": "3.12", "status": "minimum", "basis": "requires-python",
             "cycle_status": "supported", "eol_date": "2028-10-31",
             "locations": [{"project": "prod", "branch": "main", "source": "api/pyproject.toml: requires-python >=3.12",
                            "declared": ["requires-python >=3.12"], "pinned": []}]},
            {"product": "nodejs", "cycle": "18", "status": "EOL", "eol_date": "2025-04-30",
             "locations": [{"project": "prod", "branch": "main", "source": "Dockerfile: image node:18"}]}])
        doc = issues.build(rep, None, None)
        got = by_id(doc)
        self.assertEqual(sorted(got), ["eol-minimum:prod:python@3.8:pyproject.toml: requires-python >=3.8",
                                       "eol:prod:nodejs@18:Dockerfile: image node:18"])
        floor = got["eol-minimum:prod:python@3.8:pyproject.toml: requires-python >=3.8"]
        real = got["eol:prod:nodejs@18:Dockerfile: image node:18"]
        self.assertGreater(floor["priority"], real["priority"])
        self.assertEqual((floor["kind"], floor["priority"], floor["reason"]), ("eol", 6, "eol_minimum"))
        self.assertIn("eol_minimum", issues.PRIORITY_REASONS[6])
        self.assertEqual(floor["title"], "requires-python >=3.8 allows Python 3.8, past end of life (2024-10-07)")
        self.assertEqual(floor["where"], {"project": "prod", "branches": ["dev", "main"], "path": "pyproject.toml",
                                          "line": None})
        self.assertEqual(floor["fix"]["action"], "raise_minimum")
        self.assertIn("allows Python 3.8", floor["details"]["text"])
        self.assertNotIn("runs", floor["title"])
        self.assertEqual([i["id"] for i in doc["issues"]][-1], floor["id"])     # after the real EOL runtime
        self.assertIn("raise minimum", issues.render_md(doc))

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

    def test_direct_before_transitive_within_a_priority_and_counted(self):
        def transitive(v):
            for loc in v["locations"]:
                loc["direct"] = False
            return v
        rep = make_rep(vulnerabilities=[
            transitive(vuln("crit", "CRITICAL", [("prod", "main", "p.json", "required")])),
            vuln("high", "HIGH", [("prod", "main", "p.json", "required")]),
            transitive(vuln("kev", "HIGH", [("prod", "main", "p.json", "required")], kev=True)),
            transitive(vuln("dev", "HIGH", [("prod", "main", "tools.json", "optional")])),
        ])
        doc = issues.build(rep, None, None)
        ids = [i["id"] for i in doc["issues"]]
        # priorities and ids unchanged; within priority 3 the direct HIGH comes before the transitive CRITICAL
        self.assertEqual(ids, ["vuln:prod:p.json:npm:kev@1.0.0", "vuln:prod:p.json:npm:high@1.0.0",
                               "vuln:prod:p.json:npm:crit@1.0.0", "vuln:prod:tools.json:npm:dev@1.0.0"])
        self.assertEqual([i["priority"] for i in doc["issues"]], [2, 3, 3, 6])
        self.assertEqual(issues.dependency_split(doc["issues"]),
                         {"total": 3, "direct": 1, "transitive": 2, "unknown": 0, "dev_only": 0})
        self.assertFalse(issues.is_transitive({"kind": "secret", "details": {}}))
        text = issues.render_md(doc)
        self.assertIn("priority 2 and 3 (KEV, or CRITICAL/HIGH in production or a supported release): 3, of which "
                      "1 in direct dependencies and 2 in transitive ones", text)
        self.assertIn("Transitive does not mean harmless", text)
        self.assertIn("no reachability analysis", text)
        self.assertIn("| 3 | vulnerability, direct | high 1.0.0", text)
        self.assertIn("| 3 | vulnerability, transitive | crit 1.0.0", text)
        self.assertIn("| 6 | vulnerability, transitive, dev-only | dev 1.0.0", text)
        # nothing urgent: no split sentence
        self.assertNotIn("transitive ones", issues.render_md(issues.build(make_rep(), None, None)))

    def test_unknown_dependency_type_is_not_transitive(self):
        def unknown(v, imported=False):
            for loc in v["locations"]:
                loc["direct"] = None
                if imported:
                    loc["imported"] = True
            return v
        rep = make_rep(vulnerabilities=[
            unknown(vuln("unk", "CRITICAL", [("prod", "main", "p.json", "required")])),
            vuln("high", "HIGH", [("prod", "main", "p.json", "required")]),
            unknown(vuln("imp", "HIGH", [("prod", "main", "pom.xml", "required")]), imported=True),
            dict(vuln("mixed", "HIGH", [("prod", "main", "q.json", "required"), ("prod", "dev", "q.json", "required")])),
        ])
        rep["vulnerabilities"][3]["locations"][0]["direct"] = None     # one branch unknown, the other direct
        doc = issues.build(rep, None, None)
        got = by_id(doc)
        unk = got["vuln:prod:p.json:npm:unk@1.0.0"]
        self.assertIsNone(unk["details"]["direct"])
        self.assertTrue(got["vuln:prod:q.json:npm:mixed@1.0.0"]["details"]["direct"])
        self.assertFalse(issues.is_transitive(unk))
        self.assertNotIn("transitive", unk["fix"]["hint"])
        self.assertIn("could not tell", unk["fix"]["hint"])
        imp = got["vuln:prod:pom.xml:npm:imp@1.0.0"]
        self.assertNotIn("transitive", imp["fix"]["hint"])
        self.assertIn("build SBOM", imp["fix"]["hint"])
        self.assertEqual(issues.dependency_split(doc["issues"]),
                         {"total": 4, "direct": 2, "transitive": 0, "unknown": 2, "dev_only": 0})
        # direct first, then unknown, then transitive
        self.assertEqual([i["id"] for i in doc["issues"]][:2],
                         ["vuln:prod:p.json:npm:high@1.0.0", "vuln:prod:q.json:npm:mixed@1.0.0"])
        text = issues.render_md(doc)
        self.assertIn("| 3 | vulnerability, dependency type unknown | unk 1.0.0", text)
        self.assertIn("4, of which 2 in direct dependencies, 0 in transitive ones and 2 whose dependency type the "
                      "scan could not tell", text)

    def test_maven_title_names_group_and_artifact_and_the_id_is_unchanged(self):
        v = vuln("lib", "HIGH", [("prod", "main", "pom.xml", "required")])
        v.update(ecosystem="Maven", package="org.lib:lib")
        doc = issues.build(make_rep(vulnerabilities=[v]), None, None)
        i = doc["issues"][0]
        self.assertEqual(i["id"], "vuln:prod:pom.xml:Maven:lib@1.0.0")          # stable id: the short name
        self.assertTrue(i["title"].startswith("org.lib:lib 1.0.0: 2 advisories"), i["title"])
        self.assertEqual(i["details"]["package"], "org.lib:lib")
        self.assertIn("org.lib:lib 1.0.0", issues.render_md(doc))

    def test_markdown_names_a_few_branches_and_counts_the_rest(self):
        secrets = {"findings": [secret("fp", "A", branches=[f"b{n}" for n in range(9)])]}
        doc = issues.build(make_rep(), secrets, None)
        self.assertEqual(len(doc["issues"][0]["where"]["branches"]), 9)
        self.assertIn("(b0, b1, b2 +6 more)", issues.render_md(doc))


EPSS = {"threshold": 0.10, "available": True, "score_date": "2026-11-23T12:00:23Z"}


def scored(name, sev, max_epss, project="zeta", scope="required", direct=True, kev=False):
    """A vulnerability row as audit.json has it after the EPSS step: `max_epss` on the row, a score per advisory."""
    v = vuln(name, sev, [(project, "main", "package.json", scope)], kev=kev)
    for loc in v["locations"]:
        loc["direct"] = direct
    for a in v["vulns"]:
        a.update(epss=max_epss, epss_percentile=None if max_epss is None else 0.95)
    v["max_epss"] = max_epss
    return v


def epss_rep(*rows, epss=EPSS):
    return make_rep(production_projects=["zeta"], vulnerabilities=list(rows), epss=dict(epss))


class EpssTest(unittest.TestCase):
    def test_likely_exploited_medium_in_production_is_priority_3(self):
        (i,) = issues.build(epss_rep(scored("lib", "MEDIUM", 0.12)), None, None)["issues"]
        self.assertEqual((i["priority"], i["reason"]), (3, "epss_production"))
        self.assertIn(i["reason"], issues.PRIORITY_REASONS[3])
        self.assertTrue(i["title"].endswith(" (likely to be exploited: EPSS at or above 10.0%)"))
        self.assertEqual((i["details"]["max_epss"], i["details"]["epss_likely"]), (0.12, True))
        self.assertEqual([(a["epss"], a["epss_percentile"]) for a in i["details"]["advisories"]],
                         [(0.12, 0.95), (0.12, 0.95)])

    def test_epss_rule_needs_production_runtime_scope_and_a_score(self):   # Review Focus 5
        cases = {"not production": scored("lib", "MEDIUM", 0.12, project="side"),
                 "optional scope": scored("lib", "MEDIUM", 0.12, scope="optional"),
                 "no score": scored("lib", "MEDIUM", None),
                 "below the threshold": scored("lib", "MEDIUM", 0.0999)}
        for case, row in cases.items():
            with self.subTest(case):
                (i,) = issues.build(epss_rep(row), None, None)["issues"]
                self.assertEqual((i["priority"], i["reason"]), (6, "other"))
                self.assertNotIn("likely to be exploited", i["title"])
        (i,) = issues.build(epss_rep(cases["optional scope"]), None, None)["issues"]
        self.assertEqual((i["details"]["max_epss"], i["details"]["epss_likely"]), (0.12, True))

    def test_epss_never_lowers_a_priority(self):
        got = by_id(issues.build(epss_rep(scored("kev", "MEDIUM", 0.0001, kev=True),
                                          scored("crit", "CRITICAL", 0.0001),
                                          scored("unrated", None, None)), None, None))
        self.assertEqual((got["vuln:zeta:package.json:npm:kev@1.0.0"]["priority"],
                          got["vuln:zeta:package.json:npm:kev@1.0.0"]["reason"]), (2, "kev"))
        self.assertEqual((got["vuln:zeta:package.json:npm:crit@1.0.0"]["priority"],
                          got["vuln:zeta:package.json:npm:crit@1.0.0"]["reason"]), (3, "critical_high_production"))
        self.assertEqual((got["vuln:zeta:package.json:npm:unrated@1.0.0"]["priority"],
                          got["vuln:zeta:package.json:npm:unrated@1.0.0"]["reason"]), (3, "unrated_production"))

    def test_threshold_zero_turns_promotion_off(self):
        (i,) = issues.build(epss_rep(scored("lib", "MEDIUM", 0.9), epss={**EPSS, "threshold": 0}),
                            None, None)["issues"]
        self.assertEqual(i["priority"], 6)
        self.assertFalse(i["details"]["epss_likely"])

    def test_order_inside_a_priority(self):
        rep = epss_rep(scored("t_likely", "HIGH", 0.30, direct=False), scored("d_high", "HIGH", 0.05),
                       scored("d_none", "HIGH", None), scored("d_low", "HIGH", 0.01),
                       scored("t_mid", "HIGH", 0.08, direct=False))
        doc = issues.build(rep, None, None)
        self.assertEqual({i["priority"] for i in doc["issues"]}, {3})
        names = [i["details"]["package"] for i in doc["issues"]]
        self.assertEqual(names, ["t_likely", "d_none", "d_high", "d_low", "t_mid"])

    def test_audit_without_epss_builds_issues_as_before(self):       # Review Focus 3
        doc = issues.build(make_rep(production_projects=["zeta"],
                                    vulnerabilities=[vuln("lib", "MEDIUM", [("zeta", "main", "package.json",
                                                                             "required")])]), None, None)
        self.assertNotIn("epss", doc)
        self.assertNotIn("max_epss", doc["issues"][0]["details"])
        self.assertNotIn("epss_likely", doc["issues"][0]["details"])
        self.assertNotIn("epss", doc["issues"][0]["details"]["advisories"][0])
        self.assertNotIn("EPSS", issues.render_md(doc))
        self.assertNotIn("EPSS", issues._line(doc["issues"][0]))

    def test_issues_md_has_the_epss_column(self):
        rep = epss_rep(scored("lib", "MEDIUM", 0.12), scored("cold", "HIGH", None))
        secrets = {"findings": [secret("fp", "A")]}
        doc = issues.build(rep, secrets, None)
        self.assertEqual(doc["epss"], EPSS)
        md = issues.render_md(doc)
        self.assertIn("| P | Kind | EPSS | Issue | Where | Fix | Open since |", md)
        self.assertIn("EPSS at or above 10.0% there", md)
        self.assertIn("3 CRITICAL/HIGH in production or a supported release, or not rated there, or EPSS at or "
                      "above 10.0% there (off when the threshold is 0), class B secret", md)
        self.assertIn("Within a priority, production comes first, then findings at or above the EPSS threshold, "
                      "then direct dependencies before transitive ones, then the higher EPSS score.", md)
        self.assertNotIn("direct dependencies are listed first", md)
        self.assertIn("Transitive does not mean harmless", md)
        self.assertIn("| 3 | vulnerability, direct | 12.0% | lib 1.0.0", md)
        self.assertIn("| 3 | vulnerability, direct | no EPSS | cold 1.0.0", md)
        self.assertIn("| 1 | secret | – |", md)
        got = by_id(doc)
        self.assertTrue(issues._line(got["vuln:zeta:package.json:npm:lib@1.0.0"]).endswith(" EPSS 12.0%"))
        self.assertTrue(issues._line(got["vuln:zeta:package.json:npm:cold@1.0.0"]).endswith("] "
                        "vuln:zeta:package.json:npm:cold@1.0.0 no EPSS"))
        self.assertNotIn("EPSS", issues._line(got["secret:fp"]))
        off = issues.build(epss_rep(scored("lib", "MEDIUM", None), epss={**EPSS, "available": False}), None, None)
        self.assertIn("| 6 | vulnerability, direct | n/a | lib 1.0.0", issues.render_md(off))

    SPLIT_131 = "Vulnerabilities at priority 2 and 3 (KEV, or CRITICAL/HIGH in production or a supported release): "
    LEGEND_131 = "3 CRITICAL/HIGH in production or a supported release or not rated there, class B secret"

    def test_split_sentence_covers_promoted_issues(self):
        rows = (scored("lib", "MEDIUM", 0.12), scored("hot", "HIGH", 0.01))
        on = issues.render_md(issues.build(epss_rep(*rows), None, None))
        self.assertIn("Vulnerabilities at priority 2 and 3 (KEV, CRITICAL/HIGH or not rated in production or a "
                      "supported release, or likely to be exploited by EPSS there): 2, of which 2 in direct", on)
        self.assertNotIn(self.SPLIT_131, on)
        off = issues.render_md(issues.build(epss_rep(*rows, epss={**EPSS, "threshold": 0}), None, None))
        self.assertIn(self.SPLIT_131 + "1, of which 1 in direct", off)
        self.assertIn("Within a priority, production comes first, then direct dependencies before transitive ones, "
                      "then the higher EPSS score. A direct one is fixed in your own manifest", off)
        self.assertNotIn("EPSS threshold", off)
        plain = issues.render_md(issues.build(make_rep(production_projects=["zeta"], vulnerabilities=[
            vuln("hot", "HIGH", [("zeta", "main", "package.json", "required")])]), None, None))
        self.assertIn(self.SPLIT_131, plain)
        self.assertIn(self.LEGEND_131, plain)

    def test_legend_says_promotion_is_off(self):
        for threshold in (0, None):
            with self.subTest(threshold=threshold):
                md = issues.render_md(issues.build(epss_rep(scored("hot", "HIGH", 0.5),
                                                            epss={**EPSS, "threshold": threshold}), None, None))
                self.assertIn("3 CRITICAL/HIGH in production or a supported release, or not rated there (promotion "
                              "by EPSS is off: `[epss] promote_at = 0`), class B secret", md)
                self.assertNotIn("EPSS at or above", md)

    def test_score_exactly_at_the_threshold_is_promoted(self):
        rep = epss_rep(scored("edge", "MEDIUM", 0.10), scored("under", "MEDIUM", 0.0999))
        got = by_id(issues.build(rep, None, None))
        edge, under = got["vuln:zeta:package.json:npm:edge@1.0.0"], got["vuln:zeta:package.json:npm:under@1.0.0"]
        self.assertEqual((edge["priority"], edge["reason"], edge["details"]["epss_likely"]),
                         (3, "epss_production", True))
        self.assertEqual((under["priority"], under["reason"], under["details"]["epss_likely"]), (6, "other", False))
        self.assertEqual(sum(1 for v in rep["vulnerabilities"]
                             if report.epss_promoted(v, {"zeta"}, rep["epss"]["threshold"])), 1)

    def test_host_priorities_do_not_change_with_epss(self):
        hosts = host_doc([{"id": "vuln:curl", "group": "vuln", "text": "curl", "fixable": 1, "fix": "installable",
                           "candidate": "8.5", "max_epss": 0.9},
                          {"id": "kev:CVE-1", "group": "kev", "text": "kev open", "max_epss": 0.9}])
        with_epss = by_id(issues.build(make_rep(epss=dict(EPSS)), None, hosts))
        without = by_id(issues.build(make_rep(), None, hosts))
        self.assertEqual(sorted(with_epss), sorted(without))
        for key, i in without.items():
            self.assertEqual((with_epss[key]["priority"], with_epss[key]["reason"]), (i["priority"], i["reason"]))
            self.assertEqual(with_epss[key]["title"], i["title"])
        self.assertEqual(with_epss["host:web:vuln:curl"]["priority"], 6)

    def test_host_issue_details_carry_the_finding_score(self):
        hosts = host_doc([{"id": "vuln:curl", "group": "vuln", "text": "curl", "fixable": 1, "fix": "installable",
                           "candidate": "8.5", "max_epss": 0.05},
                          {"id": "vuln:zlib", "group": "vuln", "text": "zlib", "fixable": 1, "fix": "installable",
                           "candidate": "1.3"},
                          {"id": "kev:CVE-1", "group": "kev", "text": "kev open", "epss": 0.9144,
                           "epss_percentile": 0.999},
                          {"id": "kev:CVE-2", "group": "kev", "text": "kev unscored", "epss": None,
                           "epss_percentile": None}])
        got = by_id(issues.build(make_rep(), None, hosts))
        self.assertEqual(got["host:web:vuln:curl"]["details"]["max_epss"], 0.05)
        self.assertNotIn("max_epss", got["host:web:vuln:zlib"]["details"])
        self.assertNotIn("epss", got["host:web:vuln:zlib"]["details"])
        self.assertEqual(got["host:web:kev:CVE-1"]["details"]["epss"], 0.9144)
        self.assertNotIn("max_epss", got["host:web:kev:CVE-1"]["details"])
        self.assertIn("epss", got["host:web:kev:CVE-2"]["details"])
        self.assertIsNone(got["host:web:kev:CVE-2"]["details"]["epss"])
        self.assertEqual(got["host:web:kev:CVE-1"]["priority"], 2)
        self.assertEqual(got["host:web:vuln:curl"]["title"], "curl")

    def test_host_issue_order_does_not_depend_on_epss(self):
        def findings(**scores):
            return [{"id": f"vuln:{name}", "group": "vuln", "text": name, "fixable": 1, "fix": "installable",
                     "candidate": "9", **({"max_epss": scores[name]} if name in scores else {})}
                    for name in ("aaa", "zzz")]
        plain = [i["id"] for i in issues.build(make_rep(), None, host_doc(findings()))["issues"]]
        self.assertEqual(plain, ["host:web:vuln:aaa", "host:web:vuln:zzz"])
        for rep in (make_rep(), make_rep(epss=dict(EPSS))):
            with self.subTest(epss="epss" in rep):
                scored = issues.build(rep, None, host_doc(findings(aaa=0.001, zzz=0.9)))["issues"]
                self.assertEqual([i["id"] for i in scored], plain)
                self.assertEqual({i["priority"] for i in scored}, {6})


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
        self.assertRegex(text, r"/sbom-audit:run \(CLI: python3 \S*sbom_audit_cli\.py'? run\)")
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
