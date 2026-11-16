"""Host-mode rules: patch automation, permissive defaults, Lynis, third-party packages and vendor binaries."""
from __future__ import annotations

import datetime as dt
import tempfile
import unittest
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

from sbomaudit.cache import Cache
from sbomaudit.hosts import parse, rules, store, vendors
from tests.hosts_fixture import collector_doc, section_text

NOW = datetime(2026, 11, 9, 8, 0, tzinfo=timezone.utc)
DOCKER = 'Unattended-Upgrade::Allowed-Origins:: "Docker:${distro_codename}";\n'


def facts_of(**sections) -> dict:
    return parse.parse(collector_doc(**sections))


def apt_config(extra: str = "", drop: str | None = None, replace: tuple[str, str] | None = None) -> str:
    text = section_text("apt_config")
    if drop:
        text = "".join(line for line in text.splitlines(True) if drop not in line)
    if replace:
        text = text.replace(*replace)
    return text + extra


def ids(findings: list[dict]) -> list[str]:
    return [f["id"] for f in findings]


def by_id(findings: list[dict], id_: str) -> dict:
    return next(f for f in findings if f["id"] == id_)


class PatchAutomationTest(unittest.TestCase):
    def test_clean_box_has_no_patch_critical(self):
        findings = rules.patch_automation(facts_of(), NOW)
        self.assertEqual([f for f in findings if f["critical"]], [])
        self.assertEqual(ids(findings), ["patch:automatic-reboot"])

    def test_periodic_off_is_critical(self):
        f = facts_of(apt_config=apt_config(replace=('Unattended-Upgrade "1"', 'Unattended-Upgrade "0"')))
        self.assertTrue(by_id(rules.patch_automation(f, NOW), "patch:periodic-off")["critical"])

    def test_periodic_missing_is_critical(self):
        f = facts_of(apt_config=apt_config(drop="APT::Periodic::Unattended-Upgrade"))
        self.assertIn("patch:periodic-off", ids(rules.patch_automation(f, NOW)))

    def test_no_security_origin_is_critical_even_with_esm(self):
        f = facts_of(apt_config=apt_config(drop='Allowed-Origins:: "${distro_id}:${distro_codename}-security"'))
        findings = rules.patch_automation(f, NOW)
        self.assertTrue(by_id(findings, "patch:no-security-origin")["critical"])
        self.assertEqual([i for i in ids(findings) if i.startswith("origin:")], [])

    def test_origins_pattern_with_security_suite_satisfies(self):
        cfg = apt_config(drop='Allowed-Origins:: "${distro_id}:${distro_codename}-security"',
                         extra='Unattended-Upgrade::Origins-Pattern:: "origin=Ubuntu,a=${distro_codename}-security";\n')
        self.assertNotIn("patch:no-security-origin", ids(rules.patch_automation(facts_of(apt_config=cfg), NOW)))

    def test_debian_pattern_forms(self):
        os_debian = 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\nID=debian\n'
        for pattern, critical in (("origin=Debian,codename=${distro_codename},label=Debian-Security", False),
                                  ("origin=Debian,codename=${distro_codename}-security,label=Debian-Security", False),
                                  ("Debian:${distro_codename}-security", False),
                                  ("origin=Debian,codename=${distro_codename}-updates", True)):
            cfg = ('Unattended-Upgrade::Origins-Pattern:: "%s";\n' % pattern)
            f = facts_of(os=os_debian, apt_config="APT::Periodic::Unattended-Upgrade \"1\";\n" + cfg)
            got = "patch:no-security-origin" in ids(rules.patch_automation(f, NOW))
            self.assertEqual(got, critical, pattern)

    def test_timer_inactive_is_critical(self):
        f = facts_of(uu_timer="enabled\ninactive\n")
        self.assertTrue(by_id(rules.patch_automation(f, NOW), "patch:timer-inactive")["critical"])

    def test_last_run_old_is_critical(self):
        f = facts_of(uu_log="2026-11-05 06:00:00,000 INFO Starting unattended upgrades script\n")
        self.assertTrue(by_id(rules.patch_automation(f, NOW), "patch:last-run-old")["critical"])

    def test_last_run_exactly_three_days_is_fine(self):
        f = facts_of(uu_log="2026-11-06 08:00:00,000 INFO Starting unattended upgrades script\n")
        self.assertNotIn("patch:last-run-old", ids(rules.patch_automation(f, NOW)))

    def test_no_run_found_is_critical(self):
        f = facts_of(uu_log="")
        findings = rules.patch_automation(f, NOW)
        self.assertTrue(by_id(findings, "patch:no-run-found")["critical"])
        self.assertNotIn("patch:last-run-old", ids(findings))

    def test_docker_origin_is_named_not_critical(self):
        f = facts_of(apt_config=apt_config(extra=DOCKER + 'Unattended-Upgrade::Allowed-Origins:: '
                                           '"${distro_id}:${distro_codename}-updates";\n'))
        findings = rules.patch_automation(f, NOW)
        docker = by_id(findings, "origin:Docker:${distro_codename}")
        self.assertFalse(docker["critical"])
        self.assertEqual(docker["group"], "patch")
        self.assertFalse(by_id(findings, "origin:${distro_id}:${distro_codename}-updates")["critical"])
        self.assertEqual([f for f in findings if f["critical"]], [])

    def test_esm_and_release_pocket_produce_nothing(self):
        findings = rules.patch_automation(facts_of(), NOW)
        self.assertEqual([i for i in ids(findings) if i.startswith("origin:")], [])

    def test_site_pattern_is_a_named_origin_not_release(self):
        cfg = apt_config(extra='Unattended-Upgrade::Origins-Pattern:: "site=download.docker.com,a=${distro_codename}";\n')
        findings = rules.patch_automation(facts_of(apt_config=cfg), NOW)
        self.assertIn("origin:site=download.docker.com,a=${distro_codename}", ids(findings))

    def test_release_pattern_with_distro_origin_is_silent(self):
        cfg = apt_config(extra='Unattended-Upgrade::Origins-Pattern:: "o=${distro_id},a=${distro_codename}";\n')
        self.assertEqual([i for i in ids(rules.patch_automation(facts_of(apt_config=cfg), NOW))
                          if i.startswith("origin:")], [])

    def test_unparseable_last_run_is_no_run_found(self):
        f = facts_of()
        f["uu_last_run"] = "yesterday"
        findings = rules.patch_automation(f, NOW)
        self.assertTrue(by_id(findings, "patch:no-run-found")["critical"])
        self.assertNotIn("patch:last-run-old", ids(findings))

    def test_absent_inputs_fail_closed(self):
        f = facts_of()
        for key in ("apt_config", "uu_timer", "uu_last_run"):
            f.pop(key)
        findings = rules.patch_automation(f, NOW)
        self.assertEqual(sorted(i for i in ids(findings) if i.startswith("patch:") and i != "patch:automatic-reboot"),
                         ["patch:no-run-found", "patch:no-security-origin", "patch:periodic-off", "patch:timer-inactive"])
        f["apt_config"] = None
        f["uu_timer"] = None
        self.assertIn("patch:timer-inactive", ids(rules.patch_automation(f, NOW)))

    def test_automatic_reboot_truthy_spellings(self):
        for value, on in (("true", True), ("TRUE", True), ("1", True), ("yes", True), ("on", True),
                          ("false", False), ("0", False), ("no", False)):
            f = facts_of(apt_config=apt_config(replace=('Automatic-Reboot "false"', f'Automatic-Reboot "{value}"')))
            info = by_id(rules.patch_automation(f, NOW), "patch:automatic-reboot")
            self.assertIs(info["automatic_reboot"], on, value)
            self.assertEqual("03:30" in info["text"], on, value)

    def test_automatic_reboot_is_info(self):
        f = facts_of(apt_config=apt_config(replace=('Automatic-Reboot "false"', 'Automatic-Reboot "true"')))
        info = by_id(rules.patch_automation(f, NOW), "patch:automatic-reboot")
        self.assertEqual(info["group"], "info")
        self.assertFalse(info["critical"])
        self.assertIn("true", info["text"])
        self.assertIn("03:30", info["text"])
        off = by_id(rules.patch_automation(facts_of(), NOW), "patch:automatic-reboot")
        self.assertIn("false", off["text"])


class PermissiveTest(unittest.TestCase):
    def test_clean_box_has_nothing(self):
        self.assertEqual(rules.permissive(facts_of()), [])

    def test_permissive_each(self):
        sshd = (section_text("sshd").replace("passwordauthentication no", "passwordauthentication yes")
                .replace("permitrootlogin no", "permitrootlogin yes")
                .replace("kbdinteractiveauthentication no", "kbdinteractiveauthentication yes"))
        f = facts_of(apparmor="N\n", sshd=sshd,
                     firewall="Status: active\nDefault: allow (incoming), allow (outgoing), deny (routed)\n\n"
                              "To   Action   From\n--   ------   ----\n22/tcp  ALLOW IN  Anywhere\n")
        f["apparmor"] = {"enabled": False, "complain": ["/usr/bin/man"], "enforce_count": 0}
        findings = rules.permissive(f)
        self.assertEqual(sorted(ids(findings)), sorted([
            "permissive:apparmor-disabled", "permissive:apparmor-complain:/usr/bin/man",
            "permissive:firewall-incoming-allow", "permissive:sshd-passwordauthentication",
            "permissive:sshd-permitrootlogin", "permissive:sshd-kbdinteractiveauthentication"]))
        self.assertTrue(all(x["group"] == "permissive" and x["critical"] is False for x in findings))

    def test_untrusted_binary_is_critical(self):
        f = facts_of(binaries="U\tnode\t/usr/local/bin/node\n")
        findings = rules.permissive(f)
        self.assertEqual(ids(findings), ["permissive:binary-untrusted:/usr/local/bin/node"])
        self.assertTrue(findings[0]["critical"])
        self.assertEqual((findings[0]["binary"], findings[0]["path"]), ("node", "/usr/local/bin/node"))

    def test_apparmor_complain_from_collector(self):
        aa = section_text("apparmor").replace('"/usr/bin/man": "enforce"', '"/usr/bin/man": "complain"')
        self.assertEqual(ids(rules.permissive(facts_of(apparmor=aa))), ["permissive:apparmor-complain:/usr/bin/man"])

    def test_permitrootlogin_prohibit_password_is_fine(self):
        sshd = section_text("sshd").replace("permitrootlogin no", "permitrootlogin prohibit-password")
        self.assertEqual(rules.permissive(facts_of(sshd=sshd)), [])

    def test_firewall_policy_words(self):
        f = facts_of()
        for tool, policy, expected in (("iptables", "drop", []), ("ufw", "reject", []), ("ufw", "deny", []),
                                       ("iptables", "accept", ["permissive:firewall-incoming-accept"]),
                                       ("ufw", "allow", ["permissive:firewall-incoming-allow"]),
                                       ("ufw", None, ["permissive:firewall-incoming-unknown"]),
                                       ("none", None, ["permissive:firewall-none"])):
            f["firewall"] = {"tool": tool, "default_incoming": policy, "ruleset_sha256": None}
            self.assertEqual(ids(rules.permissive(f)), expected, (tool, policy))


def lynis_text(index: int, warnings: tuple[str, ...] = ("SSH-7408",)) -> str:
    lines = ["START 1794211150", "report_datetime_end=2026-11-09 08:02:10", f"hardening_index={index}"]
    lines += [f"warning[]={w}|Something is off ({w})|-|-|" for w in warnings]
    lines += ["suggestion[]=AUTH-9230|Configure password hashing rounds|-|-|", "MTIME 1794211330"]
    return "\n".join(lines) + "\n"


class LynisTest(unittest.TestCase):
    def test_lynis_first_run_sets_nothing_critical(self):
        findings = rules.lynis(facts_of(), None)
        self.assertEqual([f for f in findings if f["critical"]], [])
        self.assertEqual(ids(findings), ["lynis-warning:SSH-7408", "lynis-suggestion:AUTH-9230",
                                         "lynis-suggestion:PKGS-7346"])
        self.assertEqual(by_id(findings, "lynis-warning:SSH-7408")["group"], "lynis_warning")
        self.assertIn("SSH-7408", by_id(findings, "lynis-warning:SSH-7408")["text"])

    def test_lynis_known_warning_not_critical(self):
        findings = rules.lynis(facts_of(), {"index": 72, "warnings": ["SSH-7408"]})
        self.assertEqual([f for f in findings if f["critical"]], [])
        self.assertIn("lynis-warning:SSH-7408", ids(findings))

    def test_lynis_new_warning_critical(self):
        f = facts_of(lynis=lynis_text(72, ("SSH-7408", "AUTH-9328")))
        findings = rules.lynis(f, {"index": 72, "warnings": ["SSH-7408"]})
        self.assertTrue(by_id(findings, "lynis-warning:AUTH-9328")["critical"])
        self.assertFalse(by_id(findings, "lynis-warning:SSH-7408")["critical"])
        self.assertEqual([f for f in findings if f["group"] == "lynis_suggestion" and f["critical"]], [])

    def test_lynis_index_drop_5_critical_4_not(self):
        base = {"index": 72, "warnings": ["SSH-7408"]}
        drop5 = rules.lynis(facts_of(lynis=lynis_text(67)), base)
        crit = by_id(drop5, "lynis-index:67")
        self.assertTrue(crit["critical"])
        self.assertEqual(crit["group"], "lynis_index")
        drop4 = rules.lynis(facts_of(lynis=lynis_text(68)), base)
        self.assertEqual([f for f in drop4 if f["critical"]], [])
        self.assertEqual([f for f in drop4 if f["group"] == "lynis_index"], [])

    def test_lynis_index_ignored_without_baseline_index(self):
        self.assertEqual([f for f in rules.lynis(facts_of(lynis=lynis_text(10)), {"index": None, "warnings": []})
                          if f["group"] == "lynis_index"], [])

    def test_baseline_without_index_counts_as_no_baseline(self):
        findings = rules.lynis(facts_of(lynis=lynis_text(40, ("SSH-7408", "AUTH-9328"))), {"index": None, "warnings": []})
        self.assertEqual([f for f in findings if f["critical"]], [])

    def test_lynis_ok_without_index_is_info(self):
        text = "START 1794211150\nwarning[]=SSH-7408|x|-|-|\nMTIME 1794211330\n"
        findings = rules.lynis(facts_of(lynis=text), {"index": 72, "warnings": ["SSH-7408"]})
        info = by_id(findings, "lynis:no-index")
        self.assertEqual((info["group"], info["critical"]), ("info", False))
        self.assertEqual([f for f in findings if f["critical"]], [])

    def test_lynis_unavailable_is_info(self):
        f = facts_of(lynis=(127, "lynis: not found\n"))
        findings = rules.lynis(f, {"index": 72, "warnings": []})
        self.assertEqual(ids(findings), ["lynis:unavailable"])
        self.assertFalse(findings[0]["critical"])
        self.assertEqual(findings[0]["group"], "info")
        self.assertIn("lynis not installed", findings[0]["text"])


class ThirdPartyTest(unittest.TestCase):
    def test_third_party_docker_ce(self):
        findings = rules.third_party(facts_of())
        self.assertEqual(sorted(f["package"] for f in findings), ["containerd.io", "docker-ce"])
        docker = next(f for f in findings if f["package"] == "docker-ce")
        self.assertEqual(docker["group"], "third_party")
        self.assertFalse(docker["critical"])
        self.assertEqual(docker["installed"], "5:27.2.0-1~ubuntu.24.04~noble")
        self.assertEqual(docker["candidate"], "5:27.3.1-1~ubuntu.24.04~noble")
        self.assertEqual(docker["site"], "download.docker.com")
        self.assertIn("5:27.3.1", docker["text"])

    def test_distro_packages_none(self):
        names = {f["package"] for f in rules.third_party(facts_of())}
        self.assertTrue({"openssl", "libc6", "sudo", "base-files"}.isdisjoint(names))

    def _with_origin(self, site, name, suite="noble-updates"):
        f = facts_of()
        f["origins"]["openssl"] = [{"version": "3.0.13-0ubuntu3.4", "origin": f"https://{site}/ubuntu", "suite": suite,
                                    "site": site, "origin_name": name, "installed": True, "candidate": True}]
        return [x["package"] for x in rules.third_party(f)]

    def test_provider_mirror_with_ubuntu_release_is_distro(self):
        self.assertNotIn("openssl", self._with_origin("mirror.hetzner.example", "Ubuntu"))
        self.assertNotIn("openssl", self._with_origin("mirror.hetzner.example", "Debian"))
        self.assertNotIn("openssl", self._with_origin("mirror.hetzner.example", "UbuntuESM"))

    def test_docker_and_ppa_repositories_are_third_party(self):
        self.assertIn("openssl", self._with_origin("download.docker.com", "Docker", "noble"))
        self.assertIn("openssl", self._with_origin("ppa.launchpadcontent.net", "LP-PPA-foo", "noble"))

    def test_mirror_without_release_name_is_third_party(self):
        self.assertIn("openssl", self._with_origin("mirror.hetzner.example", None))

    def test_name_fallback_when_release_name_missing(self):
        self.assertNotIn("openssl", self._with_origin("archive.ubuntu.com", None))

    def test_country_mirror_and_esm_are_distro(self):
        f = facts_of()
        f["origins"]["docker-ce"] = [{"version": "5:27.2.0-1~ubuntu.24.04~noble", "origin": "https://esm.ubuntu.com/apps",
                                      "suite": "noble-apps-security", "site": "esm.ubuntu.com",
                                      "installed": True, "candidate": True}]
        f["origins"]["containerd.io"][0]["site"] = "de.archive.ubuntu.com"
        f["origins"]["containerd.io"][1]["site"] = "de.archive.ubuntu.com"
        self.assertEqual(rules.third_party(f), [])


class VendorsTest(unittest.TestCase):
    BIN = [{"name": "caddy", "path": "/usr/local/bin/caddy", "owner": None, "version": "v2.8.4 h1:example="},
           {"name": "node", "path": "/usr/local/bin/node", "owner": None, "version": "v20.11.0"},
           {"name": "unknowntool", "path": "/usr/local/bin/x", "owner": None, "version": "1.0.0"}]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cache = Cache(Path(self.tmp.name), ttl_hours=24)
        self.calls: list[str] = []

    def fetch(self, url):
        self.calls.append(url)
        if url == "https://api.github.com/repos/caddyserver/caddy/releases/latest":
            return {"tag_name": "v2.10.2"}
        if url == "https://endoflife.date/api/nodejs/20.json":
            return {"cycle": "20", "latest": "20.18.1", "eol": "2026-04-30"}
        raise AssertionError(url)

    def test_vendors_github_and_eol(self):
        findings = vendors.check(self.BIN, self.cache, fetch=self.fetch)
        self.assertEqual(ids(findings), ["vendor:caddy", "vendor:node", "vendor:node:eol"])
        self.assertEqual(findings[0]["text"], "caddy 2.8.4 → 2.10.2 (github caddyserver/caddy)")
        self.assertEqual(findings[0]["group"], "third_party")
        self.assertIn("20.11.0 → 20.18.1", findings[1]["text"])
        self.assertIn("EOL", findings[2]["text"])
        self.assertTrue(all(f["critical"] is False for f in findings))

    def test_up_to_date_has_no_finding(self):
        bins = [{"name": "caddy", "path": "/usr/bin/caddy", "owner": None, "version": "v2.10.2 h1:x="}]
        self.assertEqual(vendors.check(bins, self.cache, fetch=self.fetch), [])

    def test_vendor_owned_by_dpkg_skipped(self):
        bins = [{"name": "caddy", "path": "/usr/bin/caddy", "owner": "caddy", "version": "v2.8.4 h1:example="}]
        self.assertEqual(vendors.check(bins, self.cache, fetch=self.fetch), [])
        self.assertEqual(self.calls, [])

    def test_untrusted_binary_is_not_looked_up(self):
        bins = [{"name": "node", "path": "/usr/local/bin/node", "owner": None, "version": "", "untrusted": True}]
        self.assertEqual(vendors.check(bins, self.cache, fetch=self.fetch), [])
        self.assertEqual(self.calls, [])

    def test_clean_fixture_binaries_are_owned(self):
        self.assertEqual(vendors.check(facts_of()["binaries"], self.cache, fetch=self.fetch), [])

    def test_lookups_are_cached(self):
        vendors.check(self.BIN, self.cache, fetch=self.fetch)
        n = len(self.calls)
        vendors.check(self.BIN, self.cache, fetch=self.fetch)
        self.assertEqual(len(self.calls), n)

    def test_failed_fetch_is_info_not_raise(self):
        def broken(url):
            raise urllib.error.URLError("offline")
        findings = vendors.check(self.BIN, self.cache, fetch=broken)
        self.assertEqual(ids(findings), ["vendor:caddy:lookup-failed", "vendor:node:lookup-failed"])
        self.assertTrue(all(f["group"] == "info" and not f["critical"] for f in findings))
        self.assertIn("offline", findings[0]["text"])
        self.assertEqual(self.cache.get("github-caddyserver/caddy"), None)   # failures are not cached

    def test_unrecognised_version_is_info(self):
        bins = [{"name": "caddy", "path": "/usr/local/bin/caddy", "owner": None, "version": "unknown"}]
        self.assertEqual(ids(vendors.check(bins, self.cache, fetch=self.fetch)), ["vendor:caddy:version-unknown"])

    def test_node_up_to_date_but_eol(self):
        bins = [{"name": "node", "path": "/usr/local/bin/node", "owner": None, "version": "v20.18.1"}]
        findings = vendors.check(bins, self.cache, fetch=self.fetch)
        self.assertEqual(ids(findings), ["vendor:node:eol"])
        self.assertIn("2026-04-30", findings[0]["text"])

    def test_node_supported_and_current_is_silent(self):
        bins = [{"name": "node", "path": "/usr/local/bin/node", "owner": None, "version": "v22.1.0"}]
        fetch = lambda url: {"cycle": "22", "latest": "22.1.0", "eol": "2099-04-30"}  # noqa: E731
        self.assertEqual(vendors.check(bins, self.cache, fetch=fetch), [])

    def test_malformed_spec_is_lookup_failed(self):
        bins = [{"name": "caddy", "path": "/x", "owner": None, "version": "v2.8.4"},
                {"name": "node", "path": "/y", "owner": None, "version": "v20.1.0"}]
        specs = {"caddy": {"source": "github", "version": r"v?(\d+\.\d+\.\d+)"},     # no repo
                 "node": {"source": "carrier-pigeon", "version": r"v(\d+\.\d+\.\d+)"}}
        self.assertEqual(ids(vendors.check(bins, self.cache, fetch=self.fetch, specs=specs)),
                         ["vendor:caddy:lookup-failed", "vendor:node:lookup-failed"])
        broken_regex = {"caddy": {"source": "github", "repo": "a/b", "version": "("}}
        self.assertEqual(ids(vendors.check(bins[:1], self.cache, fetch=self.fetch, specs=broken_regex)),
                         ["vendor:caddy:lookup-failed"])

    def test_answer_without_tag_name_is_not_cached(self):
        bins = [{"name": "caddy", "path": "/x", "owner": None, "version": "v2.8.4"}]
        findings = vendors.check(bins, self.cache, fetch=lambda url: {"message": "API rate limit exceeded"})
        self.assertEqual(ids(findings), ["vendor:caddy:lookup-failed"])
        self.assertIsNone(self.cache.get("github-caddyserver/caddy"))
        self.assertEqual(ids(vendors.check(bins, self.cache, fetch=self.fetch)), ["vendor:caddy"])

    def test_vendors_toml_loads(self):
        specs = vendors.load()
        self.assertEqual(specs["caddy"]["repo"], "caddyserver/caddy")
        self.assertEqual(specs["node"]["product"], "nodejs")
        self.assertEqual(specs["docker-compose"]["source"], "github")


class OsEolTest(unittest.TestCase):
    TODAY = dt.date(2026, 11, 9)
    ANSWERS = {"https://endoflife.date/api/ubuntu/24.04.json": {"eol": "2029-05-31", "extendedSupport": "2036-04-25"},
               "https://endoflife.date/api/ubuntu/20.04.json": {"eol": "2025-05-29", "extendedSupport": "2030-04-02"},
               "https://endoflife.date/api/ubuntu/22.04.json": {"eol": "2027-01-15"},
               "https://endoflife.date/api/debian/11.json": {"eol": "2026-08-31", "extendedSupport": "2031-06-30"},
               "https://endoflife.date/api/debian/12.json": {"eol": "2028-06-30"}}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cache = Cache(Path(self.tmp.name), ttl_hours=24)
        self.calls: list[str] = []

    def fetch(self, url):
        self.calls.append(url)
        if url in self.ANSWERS:
            return self.ANSWERS[url]
        exc = urllib.error.HTTPError(url, 404, "not found", None, None)
        exc.close()                     # as enrich.http_get_json does before raising
        raise exc

    def eol(self, id_, version, fetch=None, today=None):
        return vendors.os_eol({"id": id_, "version_id": version}, self.cache, fetch=fetch or self.fetch,
                              today=today or self.TODAY)

    def test_supported_release_is_silent(self):
        self.assertEqual(self.eol("ubuntu", "24.04"), [])
        self.assertEqual(self.eol("debian", "12.7"), [])            # Debian's cycle is the major version
        self.assertEqual(self.calls, ["https://endoflife.date/api/ubuntu/24.04.json",
                                      "https://endoflife.date/api/debian/12.json"])

    def test_past_eol_is_critical_and_names_paid_support(self):
        for id_, version, paid in (("ubuntu", "20.04", "Ubuntu Pro (ESM) until 2030-04-02"),
                                   ("debian", "11", "paid Extended LTS until 2031-06-30")):
            with self.subTest(os=id_):
                [f] = self.eol(id_, version, today=dt.date(2026, 11, 9) if id_ == "ubuntu" else dt.date(2026, 9, 1))
                self.assertEqual((f["id"], f["group"], f["critical"]), ("os:eol", "patch", True))
                self.assertIn("reached the end of its security support", f["text"])
                self.assertIn(paid, f["text"])

    def test_eol_soon_is_not_critical(self):
        [f] = self.eol("ubuntu", "22.04")
        self.assertEqual((f["id"], f["critical"], f["eol"]), ("os:eol", False, "2027-01-15"))
        self.assertIn("plan the release upgrade", f["text"])

    def test_failed_lookup_is_info_never_a_crash(self):
        def broken(url):
            raise urllib.error.URLError("offline")
        [f] = self.eol("ubuntu", "24.04", fetch=broken)
        self.assertEqual((f["id"], f["group"], f["critical"]), ("info:os-eol-unavailable", "info", False))
        self.assertIn("offline", f["text"])
        self.assertIsNone(self.cache.get("eol-os-ubuntu-24.04"))     # a failure is not cached
        [f] = self.eol("ubuntu", "19.10")                            # unknown cycle (404)
        self.assertEqual(f["id"], "info:os-eol-unavailable")
        [f] = self.eol("ubuntu", "24.04", fetch=lambda url: ["not", "a", "dict"])
        self.assertEqual(f["id"], "info:os-eol-unavailable")

    def test_answers_are_cached_with_the_vendor_cache(self):
        self.eol("ubuntu", "24.04")
        self.eol("ubuntu", "24.04")
        self.assertEqual(len(self.calls), 1)

    def test_other_or_unknown_os_is_skipped(self):
        self.assertEqual(self.eol("alpine", "3.20"), [])
        self.assertEqual(self.eol("debian", None), [])
        self.assertEqual(self.calls, [])

    def test_os_eol_cannot_be_accepted(self):
        self.assertIn("upgrading", store._refusal("os:eol"))


if __name__ == "__main__":
    unittest.main()
