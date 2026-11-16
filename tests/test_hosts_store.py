import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from sbomaudit.hosts import store

TODAY = dt.date(2026, 11, 9)
HOST = "web-1.example"
KEV_ID = "kev:CVE-2024-1086:linux-image-6.8.0-45-generic@6.8.0-45.45"
SUDOERS_ID = "change:sudoers:+/etc/sudoers.d/91-x"
GONE_ID = "change:users:-olduser"


def finding(id_, group="change", critical=True):
    return {"id": id_, "group": group, "critical": critical, "text": id_}


def host_doc():
    findings = [
        finding(SUDOERS_ID),
        finding(GONE_ID),
        finding("change:sockets:+tcp/0.0.0.0:8080"),
        finding("change:cron:~/etc/cron.d/job"),
        finding(KEV_ID, "kev"),
        finding("info:kev:CVE-2024-1:pkg@1", "info", False),
        finding("vuln:CVE-2024-2:pkg@1", "vuln"),
        finding("patch:timer-inactive", "patch"),
        finding("origin:Docker:noble", "patch", False),
        finding("permissive:sshd-passwordauthentication", "permissive", False),
        finding("vendor:docker", "info", False),
        finding("info:kernel", "info", False),
        finding("login:root@2026-11-08T10:12:03Z/SHA256:abc", "login"),
        finding("lynis-warning:SSH-7408", "lynis_warning"),
        finding("lynis-index:58", "lynis_index"),
        finding("hostkey:changed", "change"),
    ]
    return {
        "production": True, "projects": [], "status": "ok", "findings": findings,
        "fingerprint": {
            "users": {"deploy": "uid=1000"},
            "sudoers": {"/etc/sudoers.d/91-x": "abc root", "/etc/sudoers.d/10": "def admin"},
            "sockets": {"tcp/0.0.0.0:8080": "nginx"},
            "cron": {"/etc/cron.d/job": "newhash"},
        },
    }


def baseline():
    return {"schema": 1, "created": "2026-11-01T00:00:00Z",
            "fingerprint": {"users": {"deploy": "uid=1000", "olduser": "uid=1001"},
                            "sudoers": {"/etc/sudoers.d/10": "def admin"},
                            "cron": {"/etc/cron.d/job": "oldhash"}},
            "lynis": {"index": 60, "warnings": ["AUTH-1"]}, "packages_seen": {}}


class StoreTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.out = Path(self._tmp.name)
        store.write(self.out, {"schema": 1, "hosts": {HOST: host_doc(), "db-1.example": host_doc()}})
        store.write_baseline(self.out, HOST, baseline())

    def accept(self, id_, review_by=None, note="ok"):
        return store.accept(self.out, HOST, id_, note, review_by, TODAY)

    def test_roundtrip_hosts_json_and_corrupt_is_none(self):
        self.assertEqual(store.read(self.out)["hosts"][HOST]["status"], "ok")
        (self.out / store.HOSTS_JSON).write_text("{not json", encoding="utf-8")
        self.assertIsNone(store.read(self.out))
        (self.out / store.HOSTS_JSON).write_text("[1]", encoding="utf-8")
        self.assertIsNone(store.read(self.out))
        self.assertIsNone(store.read(self.out / "missing"))
        self.assertIsNone(store.read_baseline(self.out, "nobody.example"))

    def test_write_drops_raw_facts(self):
        doc = {"schema": 1, "hosts": {HOST: {"status": "ok", "facts": {"apt_sources": ["deb https://u:p@x/"]}}}}
        original = json.dumps(doc)
        store.write(self.out, doc)
        self.assertNotIn("facts", store.read(self.out)["hosts"][HOST])
        self.assertNotIn("u:p@", (self.out / store.HOSTS_JSON).read_text(encoding="utf-8"))
        self.assertEqual(json.dumps(doc), original)  # the caller's document is not mutated

    def test_accept_change_moves_into_baseline(self):
        paths = self.accept(SUDOERS_ID)
        self.assertEqual({p.name for p in paths}, {f"{HOST}.json", store.DECISIONS_FILE})
        self.assertEqual(store.read_baseline(self.out, HOST)["fingerprint"]["sudoers"]["/etc/sudoers.d/91-x"],
                         "abc root")
        # keys that contain colons survive the id split, and a changed value is overwritten
        self.accept("change:sockets:+tcp/0.0.0.0:8080")
        self.accept("change:cron:~/etc/cron.d/job")
        fp = store.read_baseline(self.out, HOST)["fingerprint"]
        self.assertEqual(fp["sockets"], {"tcp/0.0.0.0:8080": "nginx"})  # section created by the accept
        self.assertEqual(fp["cron"]["/etc/cron.d/job"], "newhash")

    def test_accept_removal_deletes_key(self):
        self.accept(GONE_ID)
        self.assertEqual(store.read_baseline(self.out, HOST)["fingerprint"]["users"], {"deploy": "uid=1000"})

    def test_accept_change_backfills_missing_baseline_section(self):
        old = baseline()
        del old["fingerprint"]["sudoers"]
        store.write_baseline(self.out, HOST, old)
        self.accept(SUDOERS_ID)
        self.assertEqual(store.read_baseline(self.out, HOST)["fingerprint"]["sudoers"],
                         {"/etc/sudoers.d/91-x": "abc root"})

    def test_accept_change_stale_against_fingerprint_is_unknown(self):
        doc = store.read(self.out)
        host = doc["hosts"][HOST]
        del host["fingerprint"]["sudoers"]["/etc/sudoers.d/91-x"]
        host["fingerprint"]["users"]["olduser"] = "uid=1001"
        del host["fingerprint"]["cron"]
        store.write(self.out, doc)
        for id_ in (SUDOERS_ID, GONE_ID, "change:cron:~/etc/cron.d/job"):
            with self.assertRaisesRegex(ValueError, "unknown change-id"):
                self.accept(id_)
        self.assertFalse((self.out / store.DECISIONS_FILE).exists())

    def test_accept_patch_refused(self):
        with self.assertRaisesRegex(ValueError, "patch automation can only be fixed, not accepted"):
            self.accept("patch:timer-inactive")

    def test_accept_refused_prefixes(self):
        cases = {"permissive:sshd-passwordauthentication": "can only be fixed, not accepted",
                 "vuln:CVE-2024-2:pkg@1": "patching",
                 "info:kev:CVE-2024-1:pkg@1": "patching",
                 "vendor:docker": "no decision",
                 "info:kernel": "no decision"}
        for id_, message in cases.items():
            with self.subTest(id_=id_), self.assertRaisesRegex(ValueError, message):
                self.accept(id_)
        self.assertFalse((self.out / store.DECISIONS_FILE).exists())

    def test_origin_is_acceptable_and_only_recorded(self):
        paths = self.accept("origin:Docker:noble")
        self.assertEqual([p.name for p in paths], [store.DECISIONS_FILE])
        self.assertEqual(store.read_baseline(self.out, HOST), baseline())

    def test_accept_kev_requires_review_by_within_30_days(self):
        with self.assertRaisesRegex(ValueError, "review-by"):
            self.accept(KEV_ID)
        for bad in (TODAY, TODAY + dt.timedelta(days=31), "next week"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.accept(KEV_ID, review_by=bad if isinstance(bad, str) else bad.isoformat())
        self.accept(KEV_ID, review_by=(TODAY + dt.timedelta(days=30)).isoformat())
        with self.assertRaisesRegex(ValueError, "only valid for a KEV"):
            self.accept("login:root@2026-11-08T10:12:03Z/SHA256:abc", review_by="2026-11-20")

    def test_kev_critical_again_after_review_date(self):
        review_by = TODAY + dt.timedelta(days=10)
        self.accept(KEV_ID, review_by=review_by.isoformat())
        self.accept("login:root@2026-11-08T10:12:03Z/SHA256:abc")
        decisions = store.read_decisions(self.out)
        self.assertIn(KEV_ID, store.accepted_ids(decisions, HOST, review_by))
        after = store.accepted_ids(decisions, HOST, review_by + dt.timedelta(days=1))
        self.assertNotIn(KEV_ID, after)
        self.assertIn("login:root@2026-11-08T10:12:03Z/SHA256:abc", after)
        self.assertEqual(store.accepted_ids(decisions, "db-1.example", TODAY), set())

    def test_accept_lynis_warning_and_index(self):
        self.accept("lynis-warning:SSH-7408")
        self.accept("lynis-warning:SSH-7408")
        self.accept("lynis-index:58")
        self.assertEqual(store.read_baseline(self.out, HOST)["lynis"], {"index": 58, "warnings": ["AUTH-1", "SSH-7408"]})

    def test_accept_unknown_id_refused(self):
        with self.assertRaisesRegex(ValueError, r"unknown change-id .* \(run hosts check first\)"):
            self.accept("login:nobody@2026-01-01T00:00:00Z/password")
        with self.assertRaisesRegex(ValueError, "unknown change-id"):
            store.accept(self.out, "other.example", SUDOERS_ID, "", None, TODAY)

    def test_accept_hostkey_points_to_bootstrap(self):
        with self.assertRaisesRegex(ValueError, "re-pin with hosts bootstrap <host>"):
            self.accept("hostkey:changed")

    def test_decisions_file_regenerated_with_header(self):
        self.accept(SUDOERS_ID, note='say "hi"\nline two')
        self.accept(KEV_ID, review_by="2026-11-20", note="pro only")
        path = self.out / store.DECISIONS_FILE
        self.assertTrue(path.read_text(encoding="utf-8").startswith("# regenerated by sbom-audit on every change"))
        decisions = store.read_decisions(self.out)
        self.assertEqual(decisions[(HOST, SUDOERS_ID)].note, 'say "hi"\nline two')
        self.assertEqual(decisions[(HOST, SUDOERS_ID)].date, "2026-11-09")
        self.assertEqual(decisions[(HOST, KEV_ID)].review_by, "2026-11-20")
        path.write_text(path.read_text(encoding="utf-8") + "\n# hand comment\n", encoding="utf-8")
        self.accept("origin:Docker:noble")
        self.assertNotIn("hand comment", path.read_text(encoding="utf-8"))
        self.assertEqual(len(store.read_decisions(self.out)), 3)

    def test_unreadable_decisions_file_is_not_overwritten(self):
        path = self.out / store.DECISIONS_FILE
        path.write_text("[decisions\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "not valid TOML"):
            self.accept(SUDOERS_ID)
        self.assertEqual(path.read_text(encoding="utf-8"), "[decisions\n")

    def test_pin_host_keys_keeps_other_hosts(self):
        store.pin_host_keys(self.out, "web-1.example", ["203.0.113.5 ssh-ed25519 AAAAone", "# comment"])
        store.pin_host_keys(self.out, "db-1.example", ["203.0.113.6 ssh-ed25519 AAAAtwo"])
        path = store.pin_host_keys(self.out, "web-1.example",
                                   ["203.0.113.5 ssh-ed25519 AAAAnew", "203.0.113.5 ssh-rsa AAAArsa"])
        lines = [x for x in path.read_text(encoding="utf-8").splitlines() if not x.startswith("#")]
        self.assertEqual(lines, ["sbom-audit-db-1.example ssh-ed25519 AAAAtwo",
                                 "sbom-audit-web-1.example ssh-ed25519 AAAAnew",
                                 "sbom-audit-web-1.example ssh-rsa AAAArsa"])
        comments = [x.split()[1] for x in path.read_text(encoding="utf-8").splitlines() if x.startswith("#")]
        self.assertEqual(comments, ["sbom-audit-db-1.example", "sbom-audit-web-1.example"])
        self.assertEqual(path, self.out / store.KNOWN_HOSTS)
        with self.assertRaises(ValueError):
            store.pin_host_keys(self.out, "web-1.example", [])
        with self.assertRaises(ValueError):
            store.pin_host_keys(self.out, "../evil", ["x ssh-ed25519 AAAA"])

    def test_host_name_allowlist(self):
        for bad in ("a,b", "*", "a b", "a?", "a!b", "[a]", ".hidden", "-x", "a/b", ""):
            with self.subTest(host=bad):
                with self.assertRaises(ValueError):
                    store.pin_host_keys(self.out, bad, ["203.0.113.5 ssh-ed25519 AAAA"])
                with self.assertRaises(ValueError):
                    store.write_baseline(self.out, bad, baseline())
        self.assertFalse((self.out / store.KNOWN_HOSTS).exists())

    def test_pin_host_keys_prefix_hosts_do_not_collide(self):
        store.pin_host_keys(self.out, "a", ["203.0.113.5 ssh-ed25519 AAAAa"])
        store.pin_host_keys(self.out, "ab", ["203.0.113.6 ssh-ed25519 AAAAab"])
        path = store.pin_host_keys(self.out, "a", ["203.0.113.5 ssh-ed25519 AAAAa2"])
        self.assertEqual([x for x in path.read_text(encoding="utf-8").splitlines() if not x.startswith("#")],
                         ["sbom-audit-ab ssh-ed25519 AAAAab", "sbom-audit-a ssh-ed25519 AAAAa2"])
        self.assertEqual([x.split()[1] for x in path.read_text(encoding="utf-8").splitlines() if x.startswith("#")],
                         ["sbom-audit-ab", "sbom-audit-a"])

    def test_pin_host_keys_unreadable_known_hosts_raises(self):
        (self.out / store.KNOWN_HOSTS).mkdir(parents=True)  # a directory: IsADirectoryError, not "missing"
        with self.assertRaises(OSError):
            store.pin_host_keys(self.out, "a", ["203.0.113.5 ssh-ed25519 AAAA"])

    def test_corrupt_baseline_raises_value_error(self):
        corrupt = [{"fingerprint": []}, {"fingerprint": {"sudoers": "x"}}]
        for bad in corrupt:
            store.write_baseline(self.out, HOST, bad)
            with self.subTest(baseline=bad), self.assertRaisesRegex(ValueError, f"baseline for {HOST} is corrupt"):
                self.accept(SUDOERS_ID)
        for bad in ({"lynis": 3}, {"lynis": {"warnings": "x"}}):
            store.write_baseline(self.out, HOST, bad)
            with self.subTest(baseline=bad), self.assertRaisesRegex(ValueError, f"baseline for {HOST} is corrupt"):
                self.accept("lynis-warning:SSH-7408")
        store.write_baseline(self.out, HOST, {"lynis": []})
        with self.assertRaisesRegex(ValueError, "is corrupt"):
            self.accept("lynis-index:58")
        self.assertFalse((self.out / store.DECISIONS_FILE).exists())

    def test_decision_is_written_before_the_baseline(self):
        calls = []
        real = store.atomic_write

        def spy(path, text):
            calls.append(Path(path).name)
            return real(path, text)
        original = store.atomic_write
        store.atomic_write = spy
        self.addCleanup(setattr, store, "atomic_write", original)
        self.accept(SUDOERS_ID)
        self.assertEqual(calls, [store.DECISIONS_FILE, f"{HOST}.json"])

    def test_note_with_toml_special_characters_roundtrips(self):
        note = 'back\\slash \\n ]] "q" \x7f end [x]'
        self.accept("origin:Docker:noble", note=note)
        self.assertEqual(store.read_decisions(self.out)[(HOST, "origin:Docker:noble")].note, note)


if __name__ == "__main__":
    unittest.main()
