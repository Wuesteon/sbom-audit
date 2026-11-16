import re
import unittest
from unittest import mock

from sbomaudit.hosts import parse
from tests.hosts_fixture import STARTED, collector_doc, section_text

FP_DEPLOY = "SHA256:DJAtqSefbS0x0aOApnlCyNKOglphGM2PMe8HI0T09m8"


def logins(*lines: str, source: str = "journal", zone: str | None = "+0000") -> str:
    head = [f"S\t{source}"] + ([f"Z\t{zone}"] if zone else [])
    return "\n".join(head + list(lines)) + "\n"


class CleanDocTests(unittest.TestCase):
    def setUp(self):
        self.facts = parse.parse(collector_doc())

    def test_clean_doc_parses(self):
        f = self.facts
        self.assertEqual(f["collector"], parse.SHIPPED_VERSION)
        self.assertEqual(f["os"], {"id": "ubuntu", "version_id": "24.04", "codename": "noble", "supported": True})
        self.assertEqual(f["kernel"], "6.8.0-45-generic")
        self.assertIs(f["reboot_required"], False)
        self.assertEqual(len(f["packages"]), 10)  # the config-files kernel is not installed
        kernel = [p for p in f["packages"] if p["name"].startswith("linux-image-")]
        self.assertEqual(kernel, [{"name": "linux-image-6.8.0-45-generic", "version": "6.8.0-45.45", "arch": "amd64",
                                   "source": "linux-signed", "source_version": "6.8.0-45.45"}])
        self.assertEqual(f["errors"], {})

    def test_every_facts_key_present(self):
        keys = {"collector", "os", "kernel", "reboot_required", "packages", "upgradable", "origins", "apt_config",
                "uu_timer", "uu_last_run", "users", "sudoers", "authorized_keys", "sockets", "units", "cron",
                "owners", "sshd", "host_keys", "firewall", "apparmor", "apt_sources", "containers", "logins",
                "lynis", "binaries", "errors"}
        self.assertEqual(set(self.facts), keys)

    def test_upgradable_and_origins(self):
        f = self.facts
        self.assertEqual(f["upgradable"]["docker-ce"], {"installed": "5:27.2.0-1~ubuntu.24.04~noble",
                                                         "candidate": "5:27.3.1-1~ubuntu.24.04~noble",
                                                         "suite": "noble"})
        docker = f["origins"]["docker-ce"]
        self.assertEqual(docker[0]["site"], "download.docker.com")
        self.assertEqual(docker[0], {"version": "5:27.3.1-1~ubuntu.24.04~noble",
                                     "origin": "https://download.docker.com/linux/ubuntu", "suite": "noble",
                                     "site": "download.docker.com", "origin_name": "Docker",
                                     "installed": False, "candidate": True})
        self.assertEqual([o["installed"] for o in docker], [False, True])  # dpkg status line is not an origin
        libc = f["origins"]["libc6"]
        self.assertEqual({o["site"] for o in libc}, {"archive.ubuntu.com", "security.ubuntu.com"})
        self.assertEqual({o["suite"] for o in libc}, {"noble-updates", "noble-security"})
        self.assertTrue(all(o["installed"] and o["candidate"] for o in libc))

    def test_origin_name_from_release_lines(self):
        f = self.facts
        self.assertEqual({o["origin_name"] for o in f["origins"]["libc6"]}, {"Ubuntu"})
        self.assertEqual({o["origin_name"] for o in f["origins"]["docker-ce"]}, {"Docker"})
        self.assertEqual({o["origin_name"] for o in f["origins"]["base-files"]}, {"Ubuntu"})
        self.assertNotIn("Package files", f["origins"])
        self.assertNotIn("Pinned packages", f["origins"])

    def test_origin_name_is_per_repository_and_suite_and_mirror_independent(self):
        policy = ("foo:\n  Installed: 1.0\n  Candidate: 1.0\n  Version table:\n"
                  " *** 1.0 500\n        500 https://mirror.example.net/ubuntu noble-updates/main amd64 Packages\n"
                  "        500 https://ppa.launchpadcontent.net/foo/bar/ubuntu noble/main amd64 Packages\n"
                  "Package files:\n 100 /var/lib/dpkg/status\n     release a=now\n"
                  " 500 https://mirror.example.net/ubuntu noble-updates/main amd64 Packages\n"
                  "     release v=24.04,o=Ubuntu,a=noble-updates,n=noble,l=Ubuntu,c=main,b=amd64\n"
                  " 500 https://ppa.launchpadcontent.net/foo/bar/ubuntu noble/main amd64 Packages\n"
                  "     release v=24.04,o=LP-PPA-foo,a=noble,n=noble,l=bar,c=main,b=amd64\n"
                  "Pinned packages:\n")
        foo = parse.parse(collector_doc(policy=policy))["origins"]["foo"]
        self.assertEqual([(o["site"], o["origin_name"]) for o in foo],
                         [("mirror.example.net", "Ubuntu"), ("ppa.launchpadcontent.net", "LP-PPA-foo")])

    def test_policy_version_only_in_dpkg_status(self):
        policy = ("foo:\n  Installed: 1.0\n  Candidate: 1.0\n  Version table:\n"
                  " *** 1.0 100\n        100 /var/lib/dpkg/status\n")
        foo = parse.parse(collector_doc(policy=policy))["origins"]["foo"]
        self.assertEqual(foo, [{"version": "1.0", "origin": "/var/lib/dpkg/status", "suite": None, "site": None,
                                "origin_name": None, "installed": True, "candidate": True}])

    def test_apt_config_lists(self):
        cfg = self.facts["apt_config"]
        origins = cfg["Unattended-Upgrade::Allowed-Origins"]
        self.assertIsInstance(origins, list)
        self.assertIn("${distro_id}:${distro_codename}-security", origins)
        self.assertEqual(len(origins), 4)
        self.assertEqual(cfg["APT::Periodic::Unattended-Upgrade"], "1")
        self.assertEqual(cfg["Unattended-Upgrade::Automatic-Reboot-Time"], "03:30")
        self.assertEqual(cfg["Unattended-Upgrade::Package-Blacklist"], [])

    def test_uu_timer_and_last_run(self):
        self.assertEqual(self.facts["uu_timer"], {"enabled": "enabled", "active": "active"})
        self.assertEqual(self.facts["uu_last_run"], "2026-11-08T06:25:11")
        self.assertIsNone(parse.parse(collector_doc(uu_log=""))["uu_last_run"])
        timer = parse.parse(collector_doc(uu_timer=(3, "disabled\ninactive\n")))
        self.assertEqual(timer["uu_timer"], {"enabled": "disabled", "active": "inactive"})
        self.assertNotIn("uu_timer", timer["errors"])

    def test_users_are_login_shells_or_uid0(self):
        users = {u["name"]: u for u in self.facts["users"]}
        self.assertEqual(set(users), {"root", "deploy"})
        self.assertEqual(users["deploy"], {"name": "deploy", "uid": 1000, "shell": "/bin/bash",
                                           "groups": ["deploy", "docker", "sudo"]})
        self.assertEqual(users["root"]["uid"], 0)

    def test_sockets_split(self):
        sockets = self.facts["sockets"]
        self.assertIn({"proto": "tcp", "addr": "127.0.0.1", "port": 38211, "process": "containerd"}, sockets)
        self.assertIn({"proto": "tcp", "addr": "0.0.0.0", "port": 22, "process": "sshd"}, sockets)
        self.assertIn({"proto": "tcp", "addr": "::", "port": 22, "process": "sshd"}, sockets)
        extra = ('udp   UNCONN 0      0       127.0.0.53%lo:53         0.0.0.0:*    '
                 'users:(("systemd-resolve",pid=612,fd=14))\n'
                 'udp   UNCONN 0      0                   *:5353              *:*\n'
                 'tcp   LISTEN 0      511    [fe80::1%eth0]:8080          [::]:*    users:(("node",pid=9,fd=3))\n')
        more = parse.parse(collector_doc(sockets=extra))["sockets"]
        self.assertEqual(more, [{"proto": "udp", "addr": "127.0.0.53", "port": 53, "process": "systemd-resolve"},
                                {"proto": "udp", "addr": "*", "port": 5353, "process": ""},
                                {"proto": "tcp", "addr": "fe80::1", "port": 8080, "process": "node"}])

    def test_sudoers_never_has_content(self):
        sudoers = self.facts["sudoers"]
        entry = sudoers["/etc/sudoers.d/90-deploy"]
        self.assertEqual(set(entry), {"sha256", "principals"})
        self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(entry["principals"], ["deploy"])
        self.assertEqual(sudoers["/etc/sudoers"]["principals"], ["%admin", "%sudo", "root"])
        self.assertEqual(sudoers["/etc/sudoers.d/README"]["principals"], [])

    def test_authorized_keys_have_no_comment(self):
        keys = self.facts["authorized_keys"]
        self.assertEqual(set(keys), {"deploy"})
        self.assertEqual(keys["deploy"][0], {"type": "ED25519", "fp": FP_DEPLOY, "bits": "256"})
        for entry in keys["deploy"]:
            self.assertEqual(set(entry), {"type", "fp", "bits"})

    def test_units_cron_owners(self):
        f = self.facts
        self.assertEqual(f["units"]["ssh.service"]["path"], "/usr/lib/systemd/system/ssh.service")
        self.assertRegex(f["units"]["ssh.service"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(len(f["units"]), 7)
        self.assertEqual(len(f["cron"]), 3)
        self.assertEqual(f["owners"]["/usr/lib/systemd/system/ssh.service"], "openssh-server")
        self.assertEqual(f["owners"]["/etc/cron.d/e2scrub_all"], "e2fsprogs")
        self.assertNotIn("uu_timer", f["errors"])
        self.assertNotIn("owners", f["errors"])  # dpkg -S exits 1 for any unowned path

    def test_owner_found_through_usr_merge_alias(self):
        owners = "openssh-server: /lib/systemd/system/ssh.service\ndiversion by x from: /etc/foo\n"
        f = parse.parse(collector_doc(owners=(1, owners)))
        self.assertEqual(f["owners"]["/usr/lib/systemd/system/ssh.service"], "openssh-server")
        self.assertNotIn("/etc/foo", f["owners"])

    def test_sshd_and_host_keys(self):
        f = self.facts
        self.assertEqual(f["sshd"]["permitrootlogin"], "no")
        self.assertEqual(f["sshd"]["listenaddress"], "[::]:22 0.0.0.0:22")
        self.assertEqual(f["sshd"]["authorizedkeysfile"], ".ssh/authorized_keys .ssh/authorized_keys2")
        self.assertIn({"type": "ed25519", "fp": "SHA256:Jb8YoS73vgQc1tnkcaLuWW5IEe64bus+FGrutQl7bL0"}, f["host_keys"])
        self.assertEqual(len(f["host_keys"]), 3)

    def test_firewall_ufw_and_iptables(self):
        fw = self.facts["firewall"]
        self.assertEqual(fw["tool"], "ufw")
        self.assertEqual(fw["default_incoming"], "deny")
        self.assertRegex(fw["ruleset_sha256"], r"^[0-9a-f]{64}$")
        ipt = parse.parse(collector_doc(firewall="-P INPUT DROP\n" + "a" * 64 + "  -\n"))["firewall"]
        self.assertEqual(ipt, {"tool": "iptables", "default_incoming": "drop", "ruleset_sha256": "a" * 64})
        none = parse.parse(collector_doc(firewall=""))["firewall"]
        self.assertEqual(none, {"tool": "none", "default_incoming": None, "ruleset_sha256": None})

    def test_apparmor(self):
        self.assertEqual(self.facts["apparmor"], {"enabled": True, "complain": [], "enforce_count": 6})
        text = ("Y\napparmor module is loaded.\n3 profiles are loaded.\n2 profiles are in enforce mode.\n"
                "   /usr/bin/man\n   tcpdump\n1 profiles are in complain mode.\n   ntpd\n"
                "0 processes have profiles defined.\n")
        self.assertEqual(parse.parse(collector_doc(apparmor=text))["apparmor"],
                         {"enabled": True, "complain": ["ntpd"], "enforce_count": 2})
        off = parse.parse(collector_doc(apparmor=(1, "N\napparmor module is not loaded.\n")))["apparmor"]
        self.assertEqual(off, {"enabled": False, "complain": [], "enforce_count": 0})

    def test_apt_sources_containers_binaries(self):
        f = self.facts
        self.assertEqual(len(f["apt_sources"]), 3)
        self.assertTrue(f["apt_sources"][0].startswith("/etc/apt/sources.list.d/docker.list: deb "))
        self.assertEqual(f["containers"], [{"name": "edge", "ports": "0.0.0.0:443->443/tcp, [::]:443->443/tcp"},
                                           {"name": "app", "ports": "8080/tcp"}])
        self.assertEqual(f["binaries"][0], {"name": "caddy", "path": "/usr/bin/caddy", "owner": "caddy",
                                            "version": "v2.8.4 h1:example="})
        self.assertIsNone(parse.parse(collector_doc(binaries="node\t/usr/local/bin/node\t-\tv22.11.0\n"))
                          ["binaries"][0]["owner"])

    def test_untrusted_binary_line(self):
        f = parse.parse(collector_doc(binaries="U\tnode\t/usr/local/bin/node\n"))
        self.assertEqual(f["binaries"], [{"name": "node", "path": "/usr/local/bin/node", "owner": None,
                                          "version": "", "untrusted": True}])
        self.assertNotIn("binaries", f["errors"])


class LoginTests(unittest.TestCase):
    def test_logins(self):
        lg = parse.parse(collector_doc())["logins"]
        self.assertEqual(lg["source"], "journal")
        self.assertEqual(lg["accepted"], [{"time": "2026-11-08T09:14:22Z", "user": "deploy", "method": "publickey",
                                           "fp": FP_DEPLOY, "key_type": "ED25519", "ip": "203.0.113.7"}])
        self.assertEqual(sum(f["count"] for f in lg["failures"]), 3)
        self.assertIn({"hour": "2026-11-08T03", "ip": "203.0.113.50", "count": 2}, lg["failures"])

    def test_failures_summed_per_hour_and_ip(self):
        text = logins("F\t2026-11-08T03\t203.0.113.50\t2", "F\t2026-11-08T03\t203.0.113.50\t5",
                      "F\t2026-11-08T03\t203.0.113.51\t1")
        lg = parse.parse(collector_doc(logins=text))["logins"]
        self.assertEqual(lg["failures"], [{"hour": "2026-11-08T03", "ip": "203.0.113.50", "count": 7},
                                          {"hour": "2026-11-08T03", "ip": "203.0.113.51", "count": 1}])

    def test_methods_and_key_types(self):
        text = logins(
            "A\t2026-11-08T10:00:00+0000 box-a sshd[1]: Accepted publickey for deploy from 203.0.113.8 port 1 ssh2: "
            "ED25519-CERT SHA256:certfp ID ci (serial 4) CA ED25519 SHA256:cafp",
            "A\t2026-11-08T11:00:00Z box-a sshd[2]: Accepted password for alice from 203.0.113.9 port 2 ssh2",
            "A\t2026-11-08T12:00:00.123456+01:00 box-a sshd[3]: Accepted keyboard-interactive/pam for alice "
            "from 2001:db8::5 port 3 ssh2")
        acc = parse.parse(collector_doc(logins=text))["logins"]["accepted"]
        self.assertEqual(acc[0]["key_type"], "ED25519-CERT")
        self.assertEqual(acc[0]["fp"], "SHA256:certfp")
        self.assertEqual((acc[1]["method"], acc[1]["fp"], acc[1]["key_type"]), ("password", None, None))
        self.assertEqual(acc[1]["time"], "2026-11-08T11:00:00Z")
        self.assertEqual(acc[2]["method"], "keyboard-interactive")
        self.assertEqual(acc[2]["time"], "2026-11-08T11:00:00Z")  # +01:00 converted to UTC
        self.assertEqual(acc[2]["ip"], "2001:db8::5")

    def test_classic_syslog_timestamp_gets_year_of_started(self):
        line = "A\tNov  8 10:12:03 box-a sshd[7]: Accepted publickey for deploy from 203.0.113.7 port 9 ssh2: " \
               f"ED25519 {FP_DEPLOY}"
        lg = parse.parse(collector_doc(logins=logins(line, source="auth.log", zone="+0100")))["logins"]
        self.assertEqual(lg["source"], "auth.log")
        self.assertEqual(lg["accepted"][0]["time"], "2026-11-08T09:12:03Z")  # host zone +0100
        doc = collector_doc(logins=logins(line.replace("Nov  8", "Dec 31"), source="auth.log", zone=None))
        doc["started"] = 1798848000  # 2027-01-02T00:00:00Z: Dec 31 lies after it in 2027, so it is 2026
        self.assertEqual(parse.parse(doc)["logins"]["accepted"][0]["time"], "2026-12-31T10:12:03Z")

    def test_auth_log_failure_hours_shift_to_utc(self):
        text = logins("F\t2026-11-08T03\t203.0.113.50\t4", source="auth.log", zone="+0100")
        lg = parse.parse(collector_doc(logins=text))["logins"]
        self.assertEqual(lg["failures"], [{"hour": "2026-11-08T02", "ip": "203.0.113.50", "count": 4}])

    def test_no_login_source(self):
        lg = parse.parse(collector_doc(logins="S\tnone\n"))["logins"]
        self.assertEqual(lg, {"source": None, "accepted": [], "failures": []})


    def test_forged_accepted_in_user_name_is_not_a_login(self):
        # an unauthenticated client picks the user name; sshd logs it inside an "Invalid user" message
        forged = ("2026-11-08T09:20:00+00:00 box-a sshd[41000]: Invalid user x Accepted publickey for root from "
                  "203.0.113.66 port 1 ssh2: ED25519 SHA256:forged from 203.0.113.50 port 50000")
        lg = parse.parse(collector_doc(logins=logins(f"A\t{forged}")))["logins"]
        self.assertEqual(lg["accepted"], [])
        failed = forged.replace("Invalid user x", "Failed password for invalid user x")
        self.assertEqual(parse.parse(collector_doc(logins=logins(f"A\t{failed}")))["logins"]["accepted"], [])

    def test_reader_failure_note_lands_in_errors(self):
        facts = parse.parse(collector_doc(logins="E\tjournalctl rc 124\n" + logins()))
        self.assertEqual(facts["errors"]["logins"], "journalctl rc 124")
        self.assertEqual(facts["logins"]["source"], "journal")
        self.assertNotIn("logins", parse.parse(collector_doc())["errors"])


class LynisTests(unittest.TestCase):
    def test_lynis_clean(self):
        ly = parse.parse(collector_doc())["lynis"]
        self.assertEqual(ly["ok"], True)
        self.assertIsNone(ly["error"])
        self.assertEqual(ly["index"], 72)
        self.assertEqual(ly["warnings"], [{"id": "SSH-7408", "text": "SSH option AllowTcpForwarding is not hardened"}])
        self.assertEqual([s["id"] for s in ly["suggestions"]], ["AUTH-9230", "PKGS-7346"])

    def test_lynis_stale_report_is_not_ok(self):
        stale = "START 1794211150\nhardening_index=72\nMTIME 1794100000\n"
        ly = parse.parse(collector_doc(lynis=stale))["lynis"]
        self.assertEqual((ly["ok"], ly["error"]), (False, "report not refreshed"))
        missing = parse.parse(collector_doc(lynis="START 1794211150\n"))["lynis"]
        self.assertEqual((missing["ok"], missing["error"]), (False, "report not refreshed"))
        timed_out = parse.parse(collector_doc(lynis=(124, "START 1794211150\n")))["lynis"]
        self.assertEqual((timed_out["ok"], timed_out["error"]), (False, "timed out"))
        absent = parse.parse(collector_doc(lynis=(127, "")))["lynis"]
        self.assertEqual(absent, {"ok": False, "index": None, "warnings": [], "suggestions": [],
                                  "error": "lynis not installed"})

    def test_lynis_without_profile_is_an_error(self):
        # collect.sh never runs Lynis without its profile (the default config writes /var/lib/apt/lists)
        no_profile = parse.parse(collector_doc(lynis=(127, "lynis: profile missing\n")))["lynis"]
        self.assertEqual(no_profile, {"ok": False, "index": None, "warnings": [], "suggestions": [],
                                      "error": "lynis profile missing"})


class DocumentTests(unittest.TestCase):
    def test_unsupported_os(self):
        rhel = 'NAME="Red Hat Enterprise Linux"\nID="rhel"\nVERSION_ID="9.4"\nID_LIKE="fedora"\n'
        facts = parse.parse(collector_doc(os=rhel))
        self.assertEqual(facts["os"], {"id": "rhel", "version_id": "9.4", "codename": None, "supported": False})
        trixie = parse.parse(collector_doc(os="ID=debian\nVERSION_CODENAME=trixie\n"))["os"]
        self.assertEqual(trixie, {"id": "debian", "version_id": None, "codename": "trixie", "supported": True})

    def test_not_a_collector_document(self):
        for doc in ({}, {"sections": "x"}, [], {"collector": "1", "started": STARTED, "sections": []},
                    {"collector": "1", "sections": {}}):
            with self.subTest(doc=doc), self.assertRaises(parse.CollectorError):
                parse.parse(doc)

    def test_failed_section_lands_in_errors(self):
        doc = collector_doc(sshd=(255, "sshd: no hostkeys available -- exiting.\n"), containers=(1, "Cannot connect "
                            "to the Docker daemon at unix:///var/run/docker.sock.\nmore\n"))
        del doc["sections"]["passwd"]
        facts = parse.parse(doc)
        self.assertEqual(facts["errors"]["sshd"], "rc 255: sshd: no hostkeys available -- exiting.")
        self.assertEqual(facts["errors"]["containers"],
                         "rc 1: Cannot connect to the Docker daemon at unix:///var/run/docker.sock.")
        self.assertEqual(facts["errors"]["passwd"], "missing")
        self.assertEqual(facts["sshd"], {})
        self.assertEqual(facts["users"], [])

    def test_reboot_required(self):
        facts = parse.parse(collector_doc(reboot=(0, "linux-image-6.8.0-47-generic\n")))
        self.assertIs(facts["reboot_required"], True)
        self.assertNotIn("reboot", parse.parse(collector_doc())["errors"])

    def test_rc_answers_are_per_exit_code(self):
        facts = parse.parse(collector_doc(reboot=(1, ""), owners=(1, section_text("owners"))))
        self.assertNotIn("reboot", facts["errors"])
        self.assertNotIn("owners", facts["errors"])
        facts = parse.parse(collector_doc(reboot=(124, ""), owners=(127, "dpkg: not found\n"),
                                          apparmor=(124, "Y\n")))
        self.assertEqual(facts["errors"]["reboot"], "rc 124")
        self.assertIs(facts["reboot_required"], False)
        self.assertEqual(facts["errors"]["owners"], "rc 127: dpkg: not found")
        self.assertEqual(facts["owners"], {})
        self.assertEqual(facts["errors"]["apparmor"], "rc 124: Y")

    def test_firewall_tool_failure_is_an_error(self):
        facts = parse.parse(collector_doc(firewall=(1, "iptables-save failed\nPermission denied (you must be root)\n")))
        self.assertEqual(facts["errors"]["firewall"], "rc 1: iptables-save failed")
        self.assertEqual(facts["firewall"], {"tool": "none", "default_incoming": None, "ruleset_sha256": None})

    def test_phased_version_keeps_its_origin(self):
        policy = ("foo:\n  Installed: 1.0\n  Candidate: 1.1\n  Version table:\n"
                  "     1.1 500 (phased 20%)\n        500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages\n"
                  " *** 1.0 100\n        100 /var/lib/dpkg/status\n")
        foo = parse.parse(collector_doc(policy=policy))["origins"]["foo"]
        self.assertEqual(foo[0], {"version": "1.1", "origin": "http://archive.ubuntu.com/ubuntu",
                                  "suite": "noble-updates", "site": "archive.ubuntu.com",
                                  "origin_name": None, "installed": False, "candidate": True})
        self.assertEqual(foo[1]["origin"], "/var/lib/dpkg/status")

    def test_held_and_removal_marked_packages_are_installed(self):
        stanza = "Package: {0}\nStatus: {1}\nVersion: 1\nArchitecture: amd64\nSource: {0} (1)\n\n"
        dpkg = "".join(stanza.format(n, st) for n, st in (
            ("held", "hold ok installed"), ("remove-marked", "deinstall ok installed"),
            ("purge-marked", "purge ok installed"), ("gone", "deinstall ok config-files"),
            ("half", "install reinstreq half-installed")))
        names = [p["name"] for p in parse.parse(collector_doc(dpkg=dpkg))["packages"]]
        self.assertEqual(names, ["held", "remove-marked", "purge-marked"])

    def test_huge_started_is_not_a_collector_document(self):
        doc = collector_doc()
        doc["started"] = 10 ** 20
        with self.assertRaises(parse.CollectorError):
            parse.parse(doc)

    def test_a_crashing_section_parser_becomes_an_error(self):
        with mock.patch.object(parse, "_sockets", side_effect=RuntimeError("boom")):
            facts = parse.parse(collector_doc())
        self.assertEqual(facts["errors"], {"sockets": "unparseable: RuntimeError"})
        self.assertEqual(facts["sockets"], [])
        self.assertEqual(len(facts["packages"]), 10)

    def test_garbage_never_escapes(self):
        garbage = [
            "²", "+9999", "2026-02-31T10:00:00", "\x00\x1f\ud800", "{", "{\"profiles\": [1]}", "Y\n{\"profiles\": 7}",
            "a:x:²:²:x:/:/bin/sh\nb:x:1::", "tcp LISTEN 0 0 0.0.0.0:² 0.0.0.0:*\nudp UNCONN 0 0 [::]:99999999999 *",
            "² SHA256:x (ED25519)\nalice\t² SHA256:x (RSA)",
            "S\tauth.log\nZ\t+9999\nA\t2026-02-31T10:00:00+9999 h sshd[1]: Accepted publickey for a from b port 1\n"
            "A\tFeb 31 25:61:61 h sshd[1]: Accepted password for a from b port 1\n"
            "F\t2026-02-31T03\t203.0.113.9\t²\nF\t2026-02-31T03\t203.0.113.9\t5\nF\t²\t²\t²",
            "START ²\nMTIME ²\nhardening_index=²\nwarning[]=\nsuggestion[]=|",
            "foo:\n  Installed: ²\n  Version table:\n *** \n 1 2 3\n   500 http://[::1 x\n",
            "Status: active\nDefault: \n--\n-P INPUT\n",
            "x\t-\t-\nPackage: a\nStatus: install ok installed\nSource: (\n\n",
            "\t\t\t\n" * 3, "\n" * 50, "x" * 100000,
        ]
        for name in parse.SECTIONS:
            for rc in (0, 1, 124):
                for text in garbage:
                    with self.subTest(section=name, rc=rc, text=text[:40]):
                        facts = parse.parse(collector_doc(**{name: (rc, text)}))
                        self.assertEqual(set(facts) - {"errors"}, set(parse.parse(collector_doc())) - {"errors"})

    def test_shipped_version_is_a_plain_token(self):
        self.assertTrue(re.fullmatch(r"[0-9A-Za-z.]+", parse.SHIPPED_VERSION))


if __name__ == "__main__":
    unittest.main()
