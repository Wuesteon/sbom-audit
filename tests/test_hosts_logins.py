"""Host-mode login anomalies: keyed on the key fingerprint, carried forward until accepted."""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from sbomaudit.hosts import logins

NOW = datetime(2026, 11, 9, 8, 0, tzinfo=timezone.utc)
KNOWN = "SHA256:DJAtqSefbS0x0aOApnlCyNKOglphGM2PMe8HI0T09m8"
OTHER_KNOWN = "SHA256:0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
UNKNOWN = "SHA256:ZZZZ9999unknownkeyunknownkeyunknownkeyunknown"
AUDIT = "SHA256:AUDITKEYAUDITKEYAUDITKEYAUDITKEYAUDITKEYAUDIT"
BASELINE = {"authorized_keys": {f"deploy/{KNOWN}": "ED25519", f"ops/{OTHER_KNOWN}": "ED25519"},
            "sshd": {"permitrootlogin": "no"}}


def event(time="2026-11-08T14:03:00Z", user="deploy", method="publickey", fp=KNOWN, ip="203.0.113.7",
          key_type="ED25519") -> dict:
    return {"time": time, "user": user, "method": method, "fp": fp, "key_type": key_type, "ip": ip}


def facts_of(*accepted: dict, failures=(), source="journal") -> dict:
    return {"logins": {"source": source, "accepted": list(accepted), "failures": list(failures)}}


def run(facts, baseline=BASELINE, *, since=None, now=NOW, audit_fp=AUDIT, previous_open=(), accepted=()):
    return logins.evaluate(facts, baseline, since=since, now=now, audit_fp=audit_fp,
                           previous_open=list(previous_open), accepted=set(accepted))


class ClassificationTest(unittest.TestCase):
    def test_known_key_new_ip_not_critical(self):
        # a CI deploy key logging in from a runner address nobody has seen before is routine
        findings, _ = run(facts_of(event(ip="198.51.100.77")))
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual((f["group"], f["critical"]), ("login", False))
        self.assertEqual(f["id"], f"login:deploy@2026-11-08T14:03:00Z/{KNOWN}")
        self.assertIn("198.51.100.77", f["text"])

    def test_known_key_of_another_user_is_known(self):
        findings, _ = run(facts_of(event(user="deploy", fp=OTHER_KNOWN)))
        self.assertFalse(findings[0]["critical"])

    def test_unknown_key_critical(self):
        findings, _ = run(facts_of(event(fp=UNKNOWN)))
        self.assertEqual((findings[0]["group"], findings[0]["critical"]), ("login", True))
        self.assertEqual(findings[0]["id"], f"login:deploy@2026-11-08T14:03:00Z/{UNKNOWN}")

    def test_certificate_with_unlisted_fingerprint_critical(self):
        findings, _ = run(facts_of(event(fp=UNKNOWN, key_type="ED25519-CERT")))
        self.assertTrue(findings[0]["critical"])

    def test_password_login_critical(self):
        findings, _ = run(facts_of(event(method="password", fp=None, key_type=None)))
        self.assertTrue(findings[0]["critical"])
        self.assertEqual(findings[0]["id"], "login:deploy@2026-11-08T14:03:00Z/password")

    def test_kbd_interactive_critical(self):
        findings, _ = run(facts_of(event(method="keyboard-interactive", fp=None, key_type=None)))
        self.assertTrue(findings[0]["critical"])
        self.assertEqual(findings[0]["id"], "login:deploy@2026-11-08T14:03:00Z/keyboard-interactive")

    def test_other_method_without_fingerprint_fails_closed(self):
        findings, _ = run(facts_of(event(method="hostbased", fp=None, key_type=None)))
        self.assertTrue(findings[0]["critical"])

    def test_audit_key_filtered(self):
        findings, _ = run(facts_of(event(fp=AUDIT, user="sbom-audit"), event(time="2026-11-08T15:00:00Z")))
        self.assertEqual([f["id"] for f in findings], [f"login:deploy@2026-11-08T15:00:00Z/{KNOWN}"])

    def test_audit_fp_none_or_empty_drops_nothing(self):
        password = event(method="password", fp=None, key_type=None)
        empty_fp = event(time="2026-11-08T15:00:00Z", fp="", method="hostbased", key_type=None)
        for audit_fp in (None, ""):
            with self.subTest(audit_fp=audit_fp):
                findings, _ = run(facts_of(password, empty_fp), audit_fp=audit_fp)
                self.assertEqual(len(findings), 2)
                self.assertTrue(all(f["critical"] for f in findings))

    def test_fingerprint_containing_slash_is_known(self):
        fp = "SHA256:ab/cd+ef/ghijklmnopqrstuvwxyz0123456789ABCDE"
        baseline = {**BASELINE, "authorized_keys": {f"ci/{fp}": "ED25519"}}
        findings, _ = run(facts_of(event(user="ci", fp=fp)), baseline)
        self.assertFalse(findings[0]["critical"])
        self.assertEqual(findings[0]["id"], f"login:ci@2026-11-08T14:03:00Z/{fp}")

    def test_permit_root_login_value_is_case_insensitive(self):
        baseline = {**BASELINE, "sshd": {"permitrootlogin": " No "}}
        findings, _ = run(facts_of(event(user="root")), baseline)
        self.assertTrue(findings[0]["critical"])

    def test_none_baseline_is_an_empty_baseline(self):
        findings, _ = run(facts_of(event()), None)
        self.assertTrue(findings[0]["critical"])

    def test_time_without_seconds_gets_the_canonical_id(self):
        findings, _ = run(facts_of(event(time="2026-11-08T14:03Z", method="password", fp=None)))
        self.assertEqual(findings[0]["id"], "login:deploy@2026-11-08T14:03:00Z/password")
        self.assertEqual(findings[0]["time"], "2026-11-08T14:03:00Z")

    def test_same_id_from_two_addresses_keeps_the_critical_one_in_either_order(self):
        clean = event(ip="198.51.100.1")
        noisy = event(ip="198.51.100.2")
        failures = [{"hour": "2026-11-08T14", "ip": "198.51.100.2", "count": 20}]
        for order in ((clean, noisy), (noisy, clean)):
            with self.subTest(first=order[0]["ip"]):
                findings, _ = run(facts_of(*order, failures=failures))
                self.assertEqual(len(findings), 1)
                self.assertTrue(findings[0]["critical"])
                self.assertEqual(findings[0]["ip"], "198.51.100.2")

    def test_root_login_when_baseline_says_no(self):
        findings, _ = run(facts_of(event(user="root")))
        self.assertTrue(findings[0]["critical"])

    def test_root_login_with_prohibit_password_not_critical(self):
        baseline = {**BASELINE, "sshd": {"permitrootlogin": "prohibit-password"}}
        findings, _ = run(facts_of(event(user="root")), baseline)
        self.assertFalse(findings[0]["critical"])

    def test_root_login_with_unknown_baseline_setting_not_critical(self):
        findings, _ = run(facts_of(event(user="root")), {"authorized_keys": BASELINE["authorized_keys"], "sshd": {}})
        self.assertFalse(findings[0]["critical"])


class FailureRuleTest(unittest.TestCase):
    def failures(self, hour: str, count: int, ip="203.0.113.7") -> dict:
        return {"hour": hour, "ip": ip, "count": count}

    def test_ten_failures_before_success_critical_nine_not(self):
        spread = [self.failures("2026-11-08T12", 4), self.failures("2026-11-08T13", 3),
                  self.failures("2026-11-08T14", 3)]
        findings, _ = run(facts_of(event(), failures=spread))
        self.assertTrue(findings[0]["critical"], "4 + 3 + 3 = 10 failures")
        findings, _ = run(facts_of(event(), failures=spread[:2] + [self.failures("2026-11-08T14", 2)]))
        self.assertFalse(findings[0]["critical"], "4 + 3 + 2 = 9 failures")

    def test_failures_25_hours_before_do_not_count(self):
        # login 2026-11-08T14:03: the buckets are 2026-11-07T14 (the first hour that still overlaps the 24 h
        # before the login) .. 2026-11-08T14
        findings, _ = run(facts_of(event(), failures=[self.failures("2026-11-07T13", 50)]))
        self.assertFalse(findings[0]["critical"])
        findings, _ = run(facts_of(event(), failures=[self.failures("2026-11-07T14", 10)]))
        self.assertTrue(findings[0]["critical"], "the hour 24 h before the login hour is covered")
        findings, _ = run(facts_of(event(), failures=[self.failures("2026-11-07T15", 10)]))
        self.assertTrue(findings[0]["critical"])

    def test_failures_after_the_login_hour_do_not_count(self):
        findings, _ = run(facts_of(event(), failures=[self.failures("2026-11-08T15", 50)]))
        self.assertFalse(findings[0]["critical"])

    def test_failures_from_other_sources_do_not_count(self):
        findings, _ = run(facts_of(event(), failures=[self.failures("2026-11-08T13", 50, ip="198.51.100.9")]))
        self.assertFalse(findings[0]["critical"])


class WindowTest(unittest.TestCase):
    def test_window_capped_at_8_days(self):
        old = event(time="2026-10-30T10:00:00Z", fp=UNKNOWN)       # 10 days before now
        recent = event(time="2026-11-02T10:00:00Z", fp=UNKNOWN)    # 6.9 days before now
        findings, window = run(facts_of(old, recent), since="2026-10-01T00:00:00Z")
        self.assertEqual([f["time"] for f in findings], ["2026-11-02T10:00:00Z"])
        self.assertEqual(window, {"since": "2026-11-01T08:00:00Z", "until": "2026-11-09T08:00:00Z"})

    def test_future_since_is_clamped_to_now(self):
        findings, window = run(facts_of(event(time="2026-11-08T11:00:00Z", fp=UNKNOWN)), since="2026-11-10T00:00:00Z")
        self.assertEqual(window, {"since": "2026-11-09T08:00:00Z", "until": "2026-11-09T08:00:00Z"})
        self.assertEqual(findings, [])

    def test_window_without_previous_check_is_8_days(self):
        _, window = run(facts_of(), since=None)
        self.assertEqual(window, {"since": "2026-11-01T08:00:00Z", "until": "2026-11-09T08:00:00Z"})

    def test_window_starts_at_last_check(self):
        before = event(time="2026-11-08T09:00:00Z", fp=UNKNOWN)
        after = event(time="2026-11-08T11:00:00Z", fp=UNKNOWN)
        findings, window = run(facts_of(before, after), since="2026-11-08T10:00:00+00:00")
        self.assertEqual([f["time"] for f in findings], ["2026-11-08T11:00:00Z"])
        self.assertEqual(window, {"since": "2026-11-08T10:00:00Z", "until": "2026-11-09T08:00:00Z"})

    def test_since_with_offset_is_converted_to_utc(self):
        _, window = run(facts_of(), since="2026-11-08T12:00:00+02:00")
        self.assertEqual(window["since"], "2026-11-08T10:00:00Z")

    def test_events_after_now_are_ignored(self):
        findings, _ = run(facts_of(event(time="2026-11-09T09:00:00Z", fp=UNKNOWN)))
        self.assertEqual(findings, [])


class CarryTest(unittest.TestCase):
    OLD_ID = f"login:deploy@2026-10-20T10:00:00Z/{UNKNOWN}"

    def previous(self) -> list[dict]:
        return [{"id": self.OLD_ID, "group": "login", "critical": True, "text": "deploy logged in",
                 "time": "2026-10-20T10:00:00Z"},
                {"id": "login:deploy@2026-10-20T11:00:00Z/" + KNOWN, "group": "login", "critical": False,
                 "text": "routine"},
                {"id": "change:users:+x", "group": "change", "critical": True, "text": "not a login"}]

    def test_open_anomaly_carried_until_accepted(self):
        findings, _ = run(facts_of(), previous_open=self.previous())
        self.assertEqual([f["id"] for f in findings], [self.OLD_ID])
        self.assertTrue(findings[0]["critical"])
        findings, _ = run(facts_of(), previous_open=self.previous(), accepted={self.OLD_ID})
        self.assertEqual(findings, [])

    def test_carried_anomaly_is_not_duplicated_when_seen_again(self):
        again = event(time="2026-11-08T10:00:00Z", fp=UNKNOWN)
        open_id = f"login:deploy@2026-11-08T10:00:00Z/{UNKNOWN}"
        previous = [{"id": open_id, "group": "login", "critical": True, "text": "earlier"}]
        findings, _ = run(facts_of(again), previous_open=previous, since="2026-11-08T09:00:00Z")
        self.assertEqual([f["id"] for f in findings], [open_id])

    def test_open_anomaly_stays_critical_when_baseline_now_knows_the_key(self):
        # the key was accepted into the baseline, the login itself was not
        baseline = {**BASELINE, "authorized_keys": {**BASELINE["authorized_keys"], f"deploy/{UNKNOWN}": "ED25519"}}
        again = event(time="2026-11-08T10:00:00Z", fp=UNKNOWN)
        open_id = f"login:deploy@2026-11-08T10:00:00Z/{UNKNOWN}"
        previous = [{"id": open_id, "group": "login", "critical": True, "text": "earlier"}]
        findings, _ = run(facts_of(again), baseline, previous_open=previous)
        self.assertEqual([(f["id"], f["critical"]) for f in findings], [(open_id, True)])

    def test_accepted_event_seen_again_is_not_critical(self):
        again = event(time="2026-11-08T10:00:00Z", fp=UNKNOWN)
        open_id = f"login:deploy@2026-11-08T10:00:00Z/{UNKNOWN}"
        findings, _ = run(facts_of(again), accepted={open_id})
        self.assertEqual([(f["id"], f["critical"]) for f in findings], [(open_id, False)])

    def test_ids_are_stable_across_runs(self):
        first, _ = run(facts_of(event(fp=UNKNOWN)), now=NOW)
        second, _ = run(facts_of(event(fp=UNKNOWN)), now=NOW + timedelta(hours=3))
        self.assertEqual([f["id"] for f in first], [f["id"] for f in second])

    def test_findings_sorted_by_time(self):
        findings, _ = run(facts_of(event(time="2026-11-08T15:00:00Z"), event(time="2026-11-08T09:00:00Z")))
        self.assertEqual([f["time"] for f in findings], ["2026-11-08T09:00:00Z", "2026-11-08T15:00:00Z"])


class NoSourceTest(unittest.TestCase):
    def test_no_login_source_is_reported_not_clean(self):
        findings, window = run(facts_of(source=None))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "logins:no-source")
        self.assertEqual((findings[0]["group"], findings[0]["critical"]), ("info", False))
        self.assertEqual(findings[0]["text"], "logins: no source on this host")
        self.assertEqual(window["until"], "2026-11-09T08:00:00Z")

    def test_no_source_still_carries_open_anomalies(self):
        previous = [{"id": f"login:deploy@2026-10-20T10:00:00Z/{UNKNOWN}", "group": "login", "critical": True,
                     "text": "x"}]
        findings, _ = run(facts_of(source=None), previous_open=previous)
        self.assertEqual([f["id"] for f in findings], ["logins:no-source", previous[0]["id"]])


if __name__ == "__main__":
    unittest.main()
