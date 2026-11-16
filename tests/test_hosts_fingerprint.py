"""Host mode: state fingerprint, baseline diff and the noise rules.

Facts come from the clean fixture host (`box-a`, example data); each test changes one thing and diffs
the fingerprint against the clean one.
"""
import copy
import unittest

from sbomaudit.hosts import fingerprint, parse
from tests.hosts_fixture import collector_doc

OLD_SSH = "1:9.6p1-3ubuntu13.4"
NEW_SSH = "1:9.6p1-3ubuntu13.5"
NEW_SHA = "e" * 64


def clean_facts():
    return parse.parse(collector_doc())


def seen(facts, **overrides):
    out = {p["name"]: p["version"] for p in facts["packages"]}
    out.update(overrides)
    return out


def run_diff(base_facts, cur_facts, packages_seen=None):
    base = fingerprint.build(base_facts)
    cur = fingerprint.build(cur_facts)
    return fingerprint.diff(base, cur, cur_facts, packages_seen if packages_seen is not None else seen(base_facts))


def by_id(findings):
    return {f["id"]: f for f in findings}


class BuildTests(unittest.TestCase):
    def test_build_shape(self):
        fp = fingerprint.build(clean_facts())
        self.assertEqual(set(fp), {"users", "sudoers", "authorized_keys", "sockets", "units", "cron", "sshd",
                                   "firewall", "apt_sources", "containers", "host_keys"})
        self.assertEqual(fp["users"]["deploy"], "uid=1000 shell=/bin/bash groups=deploy,docker,sudo")
        self.assertEqual(fp["sudoers"]["/etc/sudoers.d/90-deploy"],
                         "d7fa50cb8272905f286046d2e43b8a7aca5d5cf0599a3683f97663f343a392b3 deploy")
        self.assertEqual(fp["authorized_keys"]["deploy/SHA256:DJAtqSefbS0x0aOApnlCyNKOglphGM2PMe8HI0T09m8"], "ED25519")
        self.assertEqual(fp["sockets"]["tcp/0.0.0.0:22"], "sshd")
        self.assertEqual(fp["host_keys"]["ed25519"], "SHA256:Jb8YoS73vgQc1tnkcaLuWW5IEe64bus+FGrutQl7bL0")
        self.assertEqual(fp["containers"]["app"], "8080/tcp")
        self.assertEqual(set(fp["firewall"]), {"default_incoming", "ruleset"})
        self.assertEqual(fp["firewall"]["default_incoming"], "deny")
        self.assertIn("permitrootlogin", fp["sshd"])
        self.assertNotIn("logingracetime", fp["sshd"])
        self.assertTrue(all(isinstance(v, str) for section in fp.values() for v in section.values()))

    def test_build_excludes_kernel_reboot_loopback_and_digests(self):
        facts = clean_facts()
        facts["containers"].append({"name": "db", "ports": "5432/tcp"})
        facts["sockets"].append({"proto": "tcp", "addr": "::1", "port": 631, "process": "cupsd"})
        text = repr(fingerprint.build(facts))
        for needle in ("6.8.0-45", "reboot", "127.0.0.1:38211", "::1", "sha256:"):
            self.assertNotIn(needle, text)
        self.assertNotIn("tcp/127.0.0.1:38211", fingerprint.build(facts)["sockets"])

    def test_build_is_stable_under_reordering(self):
        facts = clean_facts()
        shuffled = copy.deepcopy(facts)
        shuffled["users"].reverse()
        shuffled["sockets"].reverse()
        shuffled["users"][0]["groups"].reverse()
        self.assertEqual(fingerprint.build(facts), fingerprint.build(shuffled))

    def test_build_tolerates_missing_firewall_values(self):
        facts = clean_facts()
        facts["firewall"] = {"tool": "none", "default_incoming": None, "ruleset_sha256": None}
        self.assertEqual(fingerprint.build(facts)["firewall"], {"default_incoming": "", "ruleset": ""})


    def test_build_null_unit_hash_is_empty_string(self):
        facts = clean_facts()
        facts["units"]["ghost.service"] = {"path": None, "sha256": None}
        fp = fingerprint.build(facts)
        self.assertEqual(fp["units"]["ghost.service"], "")
        self.assertTrue(all(isinstance(v, str) for v in fp["units"].values()))

    def test_build_strips_credentials_from_apt_sources(self):
        facts = clean_facts()
        facts["apt_sources"].append("/etc/apt/sources.list.d/x.list: deb https://user:s3cret@repo.example.net/debian noble main")
        facts["apt_sources"].append("/etc/apt/sources.list.d/y.list: deb http://token@203.0.113.9:8080/apt noble main")
        text = repr(fingerprint.build(facts)["apt_sources"])
        self.assertNotIn("s3cret", text)
        self.assertNotIn("token@", text)
        self.assertIn("deb https://repo.example.net/debian noble main", text)
        self.assertIn("deb http://203.0.113.9:8080/apt noble main", text)
        # URLs without userinfo are untouched
        self.assertIn("https://download.docker.com/linux/ubuntu", text)


class InfoTests(unittest.TestCase):
    def test_info_reports_kernel_reboot_and_loopback(self):
        facts = clean_facts()
        facts["reboot_required"] = True
        findings = fingerprint.info(facts)
        self.assertTrue(all(f["group"] == "info" and f["critical"] is False for f in findings))
        text = "\n".join(f["text"] for f in findings)
        self.assertIn("6.8.0-45-generic", text)
        self.assertIn("reboot", text.lower())
        self.assertIn("127.0.0.1:38211", text)
        self.assertEqual(len({f["id"] for f in findings}), len(findings))

    def test_info_without_reboot_has_no_reboot_finding(self):
        findings = fingerprint.info(clean_facts())
        self.assertFalse(any("reboot" in f["id"] for f in findings))


class DiffTests(unittest.TestCase):
    def test_identical_is_quiet(self):
        fp = fingerprint.build(clean_facts())
        facts = clean_facts()
        self.assertEqual(fingerprint.diff(fp, fp, facts, seen(facts)), ([], {}))

    def test_new_sudoers_rule_is_critical(self):
        cur = clean_facts()
        cur["sudoers"]["/etc/sudoers.d/91-x"] = {"sha256": "a" * 64, "principals": ["ALL"]}
        findings, explained = run_diff(clean_facts(), cur)
        self.assertEqual([f["id"] for f in findings], ["change:sudoers:+/etc/sudoers.d/91-x"])
        self.assertIs(findings[0]["critical"], True)
        self.assertEqual(findings[0]["group"], "change")
        self.assertEqual(explained, {})

    def test_new_user_and_key(self):
        cur = clean_facts()
        cur["users"].append({"name": "deploy2", "uid": 1001, "shell": "/bin/bash", "groups": ["deploy2"]})
        cur["authorized_keys"]["deploy2"] = [{"type": "ED25519", "fp": "SHA256:abc", "bits": "256"}]
        findings, _ = run_diff(clean_facts(), cur)
        self.assertEqual({f["id"] for f in findings},
                         {"change:users:+deploy2", "change:authorized_keys:+deploy2/SHA256:abc"})
        self.assertTrue(all(f["critical"] for f in findings))

    def test_removed_and_changed_keys(self):
        cur = clean_facts()
        cur["users"][1]["groups"].append("adm")
        del cur["units"]["ufw.service"]
        findings, _ = run_diff(clean_facts(), cur)
        got = by_id(findings)
        self.assertEqual(set(got), {"change:users:~deploy", "change:units:-ufw.service"})
        self.assertTrue(all(f["critical"] for f in findings))

    def test_new_public_socket_is_change_loopback_is_not(self):
        cur = clean_facts()
        cur["sockets"].append({"proto": "tcp", "addr": "0.0.0.0", "port": 8080, "process": "node"})
        cur["sockets"].append({"proto": "tcp", "addr": "127.0.0.1", "port": 9000, "process": "node"})
        cur["sockets"].append({"proto": "tcp", "addr": "[::1]", "port": 9001, "process": "node"})
        findings, _ = run_diff(clean_facts(), cur)
        self.assertEqual([f["id"] for f in findings], ["change:sockets:+tcp/0.0.0.0:8080"])
        self.assertIs(findings[0]["critical"], True)

    def test_new_ipv6_wildcard_socket_is_change(self):
        base = clean_facts()
        base["sockets"] = [s for s in base["sockets"] if s["addr"] != "::"]
        findings, _ = run_diff(base, clean_facts())
        self.assertEqual([f["id"] for f in findings], ["change:sockets:+tcp/:::22"])
        self.assertIs(findings[0]["critical"], True)

    def test_socket_process_rename_is_info(self):
        cur = clean_facts()
        cur["sockets"][1]["process"] = "caddy"
        findings, explained = run_diff(clean_facts(), cur)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["group"], "info")
        self.assertIs(findings[0]["critical"], False)
        self.assertIn("docker-proxy", findings[0]["text"])
        self.assertIn("caddy", findings[0]["text"])
        self.assertEqual(explained, {})

    def test_unit_change_explained_by_upgrade(self):
        base = clean_facts()
        cur = clean_facts()
        cur["units"]["ssh.service"]["sha256"] = NEW_SHA
        findings, explained = run_diff(base, cur, seen(base, **{"openssh-server": OLD_SSH}))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["group"], "info")
        self.assertIs(findings[0]["critical"], False)
        self.assertTrue(findings[0]["text"].endswith(f"explained by package update (openssh-server {OLD_SSH} → {NEW_SSH})"))
        self.assertEqual(explained, {"units": {"ssh.service": NEW_SHA}})

    def test_cron_change_explained_by_upgrade(self):
        cur = clean_facts()
        cur["cron"]["/etc/crontab"] = NEW_SHA
        cur["packages"].append({"name": "cron", "version": "3.0pl1-184ubuntu2", "arch": "amd64",
                                "source": "cron", "source_version": "3.0pl1-184ubuntu2"})
        findings, explained = run_diff(clean_facts(), cur, {"cron": "3.0pl1-184ubuntu1"})
        self.assertEqual([f["group"] for f in findings], ["info"])
        self.assertEqual(explained, {"cron": {"/etc/crontab": NEW_SHA}})

    def test_unit_change_without_upgrade_is_change(self):
        base = clean_facts()
        cur = clean_facts()
        cur["units"]["ssh.service"]["sha256"] = NEW_SHA
        findings, explained = run_diff(base, cur)  # installed version == version seen
        self.assertEqual([f["id"] for f in findings], ["change:units:~ssh.service"])
        self.assertIs(findings[0]["critical"], True)
        self.assertEqual(explained, {})

    def test_unit_removed_is_change_even_with_upgrade(self):
        base = clean_facts()
        cur = clean_facts()
        del cur["units"]["ssh.service"]
        findings, _ = run_diff(base, cur, seen(base, **{"openssh-server": OLD_SSH}))
        self.assertEqual([f["id"] for f in findings], ["change:units:-ssh.service"])

    def test_unit_of_package_not_seen_before_is_change(self):
        cur = clean_facts()
        cur["units"]["new.service"] = {"path": "/usr/lib/systemd/system/new.service", "sha256": NEW_SHA}
        cur["owners"]["/usr/lib/systemd/system/new.service"] = "openssh-server"
        findings, _ = run_diff(clean_facts(), cur, {})
        self.assertEqual([f["id"] for f in findings], ["change:units:+new.service"])
        self.assertTrue(findings[0]["critical"])

    def test_unowned_cron_change_is_change(self):
        cur = clean_facts()
        cur["cron"]["/etc/cron.d/backdoor"] = NEW_SHA
        findings, explained = run_diff(clean_facts(), cur, seen(clean_facts(), cron="0"))
        self.assertEqual([f["id"] for f in findings], ["change:cron:+/etc/cron.d/backdoor"])
        self.assertTrue(findings[0]["critical"])
        self.assertEqual(explained, {})

    def test_host_key_added_is_change(self):
        base = clean_facts()
        base["host_keys"] = [k for k in base["host_keys"] if k["type"] != "ecdsa"]
        findings, _ = run_diff(base, clean_facts())
        self.assertEqual([f["id"] for f in findings], ["change:host_keys:+ecdsa"])
        self.assertTrue(findings[0]["critical"])

    def test_sshd_and_firewall_changes(self):
        cur = clean_facts()
        cur["sshd"]["permitrootlogin"] = "yes"
        cur["firewall"]["default_incoming"] = "allow"
        findings, _ = run_diff(clean_facts(), cur)
        self.assertEqual({f["id"] for f in findings},
                         {"change:sshd:~permitrootlogin", "change:firewall:~default_incoming"})

    def test_patch_week_is_quiet(self):
        base = clean_facts()
        cur = clean_facts()
        cur["kernel"] = "6.8.0-47-generic"
        cur["reboot_required"] = True
        for s in cur["sockets"]:
            if s["process"] == "containerd":
                s["port"] = 41907
        cur["units"]["ssh.service"]["sha256"] = NEW_SHA
        cur["containers"] = copy.deepcopy(base["containers"])  # restarted: same names and ports
        findings, explained = run_diff(base, cur, seen(base, **{"openssh-server": OLD_SSH}))
        self.assertFalse([f for f in findings if f["critical"]])
        self.assertEqual(explained, {"units": {"ssh.service": NEW_SHA}})


if __name__ == "__main__":
    unittest.main()
