"""Host-mode login anomalies: one finding per user and key, keyed on the key fingerprint, carried until accepted."""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from sbomaudit.hosts import logins

NOW = datetime(2026, 11, 9, 8, 0, tzinfo=timezone.utc)
KNOWN = "SHA256:DJAtqSefbS0x0aOApnlCyNKOglphGM2PMe8HI0T09m8"
OTHER_KNOWN = "SHA256:0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
UNKNOWN = "SHA256:ZZZZ9999unknownkeyunknownkeyunknownkeyunknown"
UNKNOWN_2 = "SHA256:YYYY8888secondkeysecondkeysecondkeysecondkey"
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


def by_id(findings: list[dict]) -> dict[str, dict]:
    return {f["id"]: f for f in findings}


def burst(time="2026-11-08T14:03:00Z", user="deploy", how=KNOWN) -> str:
    return f"login:{user}@{time}/{how}"


class ClassificationTest(unittest.TestCase):
    def test_known_key_new_ip_not_critical(self):
        # a CI deploy key logging in from a runner address nobody has seen before is routine
        findings, _ = run(facts_of(event(ip="198.51.100.77")))
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual((f["group"], f["critical"], f["kind"]), ("login", False, "key"))
        self.assertEqual(f["id"], f"login:deploy/{KNOWN}")
        self.assertIn("198.51.100.77", f["text"])
        self.assertEqual(f["ips"], ["198.51.100.77"])

    def test_known_key_of_another_user_is_known(self):
        findings, _ = run(facts_of(event(user="deploy", fp=OTHER_KNOWN)))
        self.assertFalse(findings[0]["critical"])

    def test_unknown_key_critical(self):
        findings, _ = run(facts_of(event(fp=UNKNOWN)))
        self.assertEqual((findings[0]["group"], findings[0]["critical"]), ("login", True))
        self.assertEqual(findings[0]["id"], f"login:deploy/{UNKNOWN}")
        self.assertIn("not in the baseline's authorized_keys", findings[0]["text"])

    def test_certificate_with_unlisted_fingerprint_critical(self):
        findings, _ = run(facts_of(event(fp=UNKNOWN, key_type="ED25519-CERT")))
        self.assertTrue(findings[0]["critical"])

    def test_password_login_critical(self):
        findings, _ = run(facts_of(event(method="password", fp=None, key_type=None)))
        self.assertTrue(findings[0]["critical"])
        self.assertEqual(findings[0]["id"], "login:deploy/password")

    def test_kbd_interactive_critical(self):
        findings, _ = run(facts_of(event(method="keyboard-interactive", fp=None, key_type=None)))
        self.assertTrue(findings[0]["critical"])
        self.assertEqual(findings[0]["id"], "login:deploy/keyboard-interactive")

    def test_other_method_without_fingerprint_fails_closed(self):
        findings, _ = run(facts_of(event(method="hostbased", fp=None, key_type=None)))
        self.assertTrue(findings[0]["critical"])

    def test_audit_key_filtered(self):
        findings, _ = run(facts_of(event(fp=AUDIT, user="sbom-audit"), event(time="2026-11-08T15:00:00Z")))
        self.assertEqual([f["id"] for f in findings], [f"login:deploy/{KNOWN}"])
        self.assertEqual(findings[0]["count"], 1)

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
        self.assertEqual(findings[0]["id"], f"login:ci/{fp}")

    def test_permit_root_login_value_is_case_insensitive(self):
        baseline = {**BASELINE, "sshd": {"permitrootlogin": " No "}}
        findings, _ = run(facts_of(event(user="root")), baseline)
        self.assertTrue(findings[0]["critical"])

    def test_none_baseline_is_an_empty_baseline(self):
        findings, _ = run(facts_of(event()), None)
        self.assertTrue(findings[0]["critical"])

    def test_time_without_seconds_is_canonical(self):
        findings, _ = run(facts_of(event(time="2026-11-08T14:03Z", method="password", fp=None)))
        self.assertEqual(findings[0]["id"], "login:deploy/password")
        self.assertEqual((findings[0]["first"], findings[0]["time"]), ("2026-11-08T14:03:00Z", "2026-11-08T14:03:00Z"))

    def test_root_login_when_baseline_says_no(self):
        findings, _ = run(facts_of(event(user="root")))
        self.assertTrue(findings[0]["critical"])
        self.assertIn("PermitRootLogin is no", findings[0]["text"])

    def test_root_login_with_prohibit_password_not_critical(self):
        baseline = {**BASELINE, "sshd": {"permitrootlogin": "prohibit-password"}}
        findings, _ = run(facts_of(event(user="root")), baseline)
        self.assertFalse(findings[0]["critical"])

    def test_root_login_with_unknown_baseline_setting_not_critical(self):
        findings, _ = run(facts_of(event(user="root")), {"authorized_keys": BASELINE["authorized_keys"], "sshd": {}})
        self.assertFalse(findings[0]["critical"])

    def test_user_not_in_the_baseline_is_critical_even_with_a_known_key(self):
        baseline = {**BASELINE, "users": {"deploy": "uid=1000 shell=/bin/bash groups=deploy"}}
        findings, _ = run(facts_of(event(user="tunnel", fp=KNOWN)), baseline)
        self.assertTrue(findings[0]["critical"])
        self.assertIn("user tunnel is not a login user in the baseline", findings[0]["text"])
        findings, _ = run(facts_of(event(user="deploy", fp=KNOWN)), baseline)
        self.assertFalse(findings[0]["critical"])

    def test_baseline_without_users_does_not_flag_users(self):
        findings, _ = run(facts_of(event(user="tunnel", fp=KNOWN)), {**BASELINE, "users": {}})
        self.assertFalse(findings[0]["critical"])


class AggregationTest(unittest.TestCase):
    def ci_burst(self, fp=UNKNOWN, n=30, user="deploy") -> list[dict]:
        base = datetime(2026, 11, 8, 6, 30, tzinfo=timezone.utc)
        return [event(time=(base + timedelta(seconds=3 * i)).strftime("%Y-%m-%dT%H:%M:%SZ"), user=user, fp=fp,
                      ip=f"198.51.100.{i % 7 + 1}") for i in range(n)]

    def test_many_logins_with_one_key_are_one_finding(self):
        findings, _ = run(facts_of(*self.ci_burst()))
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["id"], f"login:deploy/{UNKNOWN}")
        self.assertTrue(f["critical"])
        self.assertEqual(f["count"], 30)
        self.assertEqual((f["first"], f["last"]), ("2026-11-08T06:30:00Z", "2026-11-08T06:31:27Z"))
        self.assertEqual(f["ips"], [f"198.51.100.{i}" for i in range(1, 8)])
        self.assertIn("30 times", f["text"])
        self.assertIn("7 addresses", f["text"])
        self.assertIn("and 2 more", f["text"])

    def test_two_keys_two_users_are_four_findings(self):
        findings, _ = run(facts_of(*self.ci_burst(UNKNOWN), *self.ci_burst(UNKNOWN_2),
                                   *self.ci_burst(KNOWN), *self.ci_burst(UNKNOWN, user="tunnel")))
        self.assertEqual(sorted(f["id"] for f in findings),
                         sorted([f"login:deploy/{UNKNOWN}", f"login:deploy/{UNKNOWN_2}", f"login:deploy/{KNOWN}",
                                 f"login:tunnel/{UNKNOWN}"]))
        self.assertEqual(sum(f["critical"] for f in findings), 3)

    def test_id_does_not_depend_on_time_address_or_count(self):
        first, _ = run(facts_of(*self.ci_burst(n=3)))
        second, _ = run(facts_of(event(time="2026-11-09T07:00:00Z", fp=UNKNOWN, ip="192.0.2.200")),
                        now=NOW + timedelta(hours=3))
        self.assertEqual([f["id"] for f in first], [f["id"] for f in second])

    def test_key_id_is_login_plus_the_baseline_key(self):
        self.assertEqual(logins.key_id("deploy", KNOWN)[len("login:"):], f"deploy/{KNOWN}")
        self.assertIn(logins.key_id("deploy", KNOWN)[len("login:"):], BASELINE["authorized_keys"])

    def test_event_and_key_ids_are_told_apart(self):
        self.assertTrue(logins.EVENT_ID.match(burst()))
        self.assertIsNone(logins.EVENT_ID.match(logins.key_id("deploy", KNOWN)))
        self.assertIsNone(logins.EVENT_ID.match(logins.key_id("a@b", "password")))


class DecisionTest(unittest.TestCase):
    def test_accepted_key_covers_later_logins(self):
        kid = f"login:deploy/{UNKNOWN}"
        findings, _ = run(facts_of(event(fp=UNKNOWN, ip="192.0.2.1")), accepted={kid})
        self.assertEqual([(f["id"], f["critical"], f.get("accepted")) for f in findings], [(kid, False, True)])
        later, _ = run(facts_of(event(time="2026-11-15T10:00:00Z", fp=UNKNOWN, ip="192.0.2.99")),
                       now=NOW + timedelta(days=7), since=NOW.strftime(logins.TIME_FORMAT), accepted={kid})
        self.assertEqual([(f["id"], f["critical"]) for f in later], [(kid, False)])

    def test_accepted_key_does_not_cover_a_new_key_another_user_or_a_password(self):
        kid = f"login:deploy/{UNKNOWN}"
        findings, _ = run(facts_of(event(fp=UNKNOWN_2), event(user="ops", fp=UNKNOWN),
                                   event(method="password", fp=None)), accepted={kid})
        self.assertEqual(sorted(f["id"] for f in findings if f["critical"]),
                         sorted([f"login:deploy/{UNKNOWN_2}", f"login:ops/{UNKNOWN}", "login:deploy/password"]))

    def test_old_per_login_decision_matches_only_that_login(self):
        # decisions recorded before aggregation name one login: that one stays accepted, nothing more
        old = burst("2026-11-08T10:00:00Z", how=UNKNOWN)
        findings, _ = run(facts_of(event(time="2026-11-08T10:00:00Z", fp=UNKNOWN)), accepted={old})
        self.assertEqual([(f["critical"], f.get("legacy_accepted")) for f in findings], [(False, 1)])
        self.assertIn("accepted one by one earlier", findings[0]["text"])
        findings, _ = run(facts_of(event(time="2026-11-08T10:00:00Z", fp=UNKNOWN),
                                   event(time="2026-11-08T11:00:00Z", fp=UNKNOWN)), accepted={old})
        self.assertEqual([(f["critical"], f["count"]) for f in findings], [(True, 2)])


class FailureRuleTest(unittest.TestCase):
    def failures(self, hour: str, count: int, ip="203.0.113.7") -> dict:
        return {"hour": hour, "ip": ip, "count": count}

    def critical_burst(self, failures) -> bool:
        findings, _ = run(facts_of(event(), failures=failures))
        f = by_id(findings).get(burst())
        return bool(f and f["critical"])

    def test_burst_is_its_own_finding_and_counted_in_the_key(self):
        findings, _ = run(facts_of(event(), failures=[self.failures("2026-11-08T14", 12)]))
        ids = by_id(findings)
        self.assertEqual(set(ids), {burst(), f"login:deploy/{KNOWN}"})
        self.assertEqual((ids[burst()]["critical"], ids[burst()]["kind"]), (True, "event"))
        self.assertIn("12 failures from 203.0.113.7", ids[burst()]["text"])
        self.assertEqual((ids[f"login:deploy/{KNOWN}"]["critical"], ids[f"login:deploy/{KNOWN}"]["count"]), (False, 1))

    def test_accepted_key_does_not_hide_a_burst(self):
        findings, _ = run(facts_of(event(), failures=[self.failures("2026-11-08T14", 12)]),
                          accepted={f"login:deploy/{KNOWN}"})
        self.assertEqual([f["id"] for f in findings if f["critical"]], [burst()])

    def test_ten_failures_before_success_critical_nine_not(self):
        spread = [self.failures("2026-11-08T12", 4), self.failures("2026-11-08T13", 3),
                  self.failures("2026-11-08T14", 3)]
        self.assertTrue(self.critical_burst(spread), "4 + 3 + 3 = 10 failures")
        self.assertFalse(self.critical_burst(spread[:2] + [self.failures("2026-11-08T14", 2)]), "4 + 3 + 2 = 9")

    def test_failures_25_hours_before_do_not_count(self):
        # login 2026-11-08T14:03: the buckets are 2026-11-07T14 (the first hour that still overlaps the 24 h
        # before the login) .. 2026-11-08T14
        self.assertFalse(self.critical_burst([self.failures("2026-11-07T13", 50)]))
        self.assertTrue(self.critical_burst([self.failures("2026-11-07T14", 10)]),
                        "the hour 24 h before the login hour is covered")
        self.assertTrue(self.critical_burst([self.failures("2026-11-07T15", 10)]))

    def test_failures_after_the_login_hour_do_not_count(self):
        self.assertFalse(self.critical_burst([self.failures("2026-11-08T15", 50)]))

    def test_failures_from_other_sources_do_not_count(self):
        self.assertFalse(self.critical_burst([self.failures("2026-11-08T13", 50, ip="198.51.100.9")]))

    def test_same_burst_id_from_two_addresses_keeps_the_critical_one_in_either_order(self):
        clean = event(ip="198.51.100.1")
        noisy = event(ip="198.51.100.2")
        failures = [{"hour": "2026-11-08T14", "ip": "198.51.100.2", "count": 20}]
        for order in ((clean, noisy), (noisy, clean)):
            with self.subTest(first=order[0]["ip"]):
                findings, _ = run(facts_of(*order, failures=failures))
                ids = by_id(findings)
                self.assertTrue(ids[burst()]["critical"])
                self.assertEqual(ids[burst()]["ip"], "198.51.100.2")
                self.assertEqual(ids[f"login:deploy/{KNOWN}"]["count"], 2)

    def test_accepted_burst_is_not_critical(self):
        findings, _ = run(facts_of(event(), failures=[self.failures("2026-11-08T14", 12)]), accepted={burst()})
        self.assertFalse(by_id(findings)[burst()]["critical"])


class WindowTest(unittest.TestCase):
    def test_window_capped_at_8_days(self):
        old = event(time="2026-10-30T10:00:00Z", fp=UNKNOWN)       # 10 days before now
        recent = event(time="2026-11-02T10:00:00Z", fp=UNKNOWN)    # 6.9 days before now
        findings, window = run(facts_of(old, recent), since="2026-10-01T00:00:00Z")
        self.assertEqual([(f["first"], f["count"]) for f in findings], [("2026-11-02T10:00:00Z", 1)])
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
        self.assertEqual([(f["first"], f["count"]) for f in findings], [("2026-11-08T11:00:00Z", 1)])
        self.assertEqual(window, {"since": "2026-11-08T10:00:00Z", "until": "2026-11-09T08:00:00Z"})

    def test_since_with_offset_is_converted_to_utc(self):
        _, window = run(facts_of(), since="2026-11-08T12:00:00+02:00")
        self.assertEqual(window["since"], "2026-11-08T10:00:00Z")

    def test_events_after_now_are_ignored(self):
        findings, _ = run(facts_of(event(time="2026-11-09T09:00:00Z", fp=UNKNOWN)))
        self.assertEqual(findings, [])


class CarryTest(unittest.TestCase):
    KID = f"login:deploy/{UNKNOWN}"

    def carried(self, **extra) -> dict:
        first, _ = run(facts_of(event(time="2026-10-20T10:00:00Z", fp=UNKNOWN, ip="192.0.2.5")),
                       now=datetime(2026, 10, 21, tzinfo=timezone.utc))
        return {**first[0], **extra}

    def previous(self) -> list[dict]:
        return [self.carried(),
                {"id": f"login:deploy/{KNOWN}", "group": "login", "critical": False, "kind": "key", "text": "routine"},
                {"id": "change:users:+x", "group": "change", "critical": True, "text": "not a login"}]

    def test_open_anomaly_carried_until_accepted(self):
        findings, _ = run(facts_of(), previous_open=self.previous())
        self.assertEqual([(f["id"], f["critical"], f["count"]) for f in findings], [(self.KID, True, 1)])
        findings, _ = run(facts_of(), previous_open=self.previous(), accepted={self.KID})
        self.assertEqual(findings, [])

    def test_carried_key_takes_in_new_logins(self):
        new = event(time="2026-11-08T10:00:00Z", fp=UNKNOWN, ip="192.0.2.6")
        findings, _ = run(facts_of(new), previous_open=self.previous(), since="2026-11-08T09:00:00Z")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual((f["id"], f["critical"], f["count"]), (self.KID, True, 2))
        self.assertEqual((f["first"], f["last"], f["ips"]),
                         ("2026-10-20T10:00:00Z", "2026-11-08T10:00:00Z", ["192.0.2.5", "192.0.2.6"]))

    def test_rereading_a_held_window_does_not_count_twice(self):
        # the logins section failed last time: the window was not advanced and is read again
        again = event(time="2026-11-08T10:00:00Z", fp=UNKNOWN)
        first, _ = run(facts_of(again))
        findings, _ = run(facts_of(again), previous_open=first)
        self.assertEqual([(f["id"], f["count"]) for f in findings], [(self.KID, 1)])

    def test_open_anomaly_stays_critical_when_baseline_now_knows_the_key(self):
        # the key was accepted into the baseline, the logins already seen with it were not
        baseline = {**BASELINE, "authorized_keys": {**BASELINE["authorized_keys"], f"deploy/{UNKNOWN}": "ED25519"}}
        again = event(time="2026-11-08T10:00:00Z", fp=UNKNOWN)
        findings, _ = run(facts_of(again), baseline, previous_open=self.previous())
        self.assertEqual([(f["id"], f["critical"]) for f in findings], [(self.KID, True)])

    def test_findings_sorted_by_last_time(self):
        findings, _ = run(facts_of(event(time="2026-11-08T15:00:00Z"),
                                   event(time="2026-11-08T09:00:00Z", fp=UNKNOWN)))
        self.assertEqual([f["time"] for f in findings], ["2026-11-08T09:00:00Z", "2026-11-08T15:00:00Z"])


class MigrationTest(unittest.TestCase):
    """`hosts.json` written before aggregation holds one critical finding per login."""

    def legacy(self, time: str, fp=UNKNOWN, ip="192.0.2.10", reasons=None) -> dict:
        reasons = reasons if reasons is not None else [f"unknown key {fp}"]
        text = f"deploy logged in from {ip} at {time} (publickey, {fp})" + (f": {'; '.join(reasons)}" if reasons else "")
        return {"id": f"login:deploy@{time}/{fp}", "group": "login", "critical": True, "text": text,
                "time": time, "user": "deploy", "ip": ip, "method": "publickey", "fp": fp}

    def test_per_login_findings_fold_into_one_key_finding(self):
        old = [self.legacy(f"2026-10-2{i}T10:00:00Z", ip=f"192.0.2.{i}") for i in range(5)]
        findings, _ = run(facts_of(), previous_open=old)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual((f["id"], f["critical"], f["count"], f["kind"]), (f"login:deploy/{UNKNOWN}", True, 5, "key"))
        self.assertEqual((f["first"], f["last"]), ("2026-10-20T10:00:00Z", "2026-10-24T10:00:00Z"))
        self.assertIn(f"unknown key {UNKNOWN}", f["text"])

    def test_one_key_decision_clears_all_folded_logins(self):
        old = [self.legacy(f"2026-10-2{i}T10:00:00Z") for i in range(5)]
        findings, _ = run(facts_of(), previous_open=old, accepted={f"login:deploy/{UNKNOWN}"})
        self.assertEqual(findings, [])

    def test_folded_logins_already_accepted_one_by_one_stay_accepted(self):
        old = [self.legacy("2026-10-20T10:00:00Z"), self.legacy("2026-10-21T10:00:00Z")]
        findings, _ = run(facts_of(), previous_open=old, accepted={old[0]["id"]})
        self.assertEqual([(f["critical"], f["count"]) for f in findings], [(True, 1)])
        findings, _ = run(facts_of(), previous_open=old, accepted={o["id"] for o in old})
        self.assertEqual(findings, [])

    def test_legacy_id_without_fields_is_folded_from_its_id(self):
        old = {"id": f"login:deploy@2026-10-20T10:00:00Z/{UNKNOWN}", "group": "login", "critical": True, "text": "x"}
        password = {"id": "login:ops@2026-10-20T11:00:00Z/password", "group": "login", "critical": True, "text": "y"}
        findings, _ = run(facts_of(), previous_open=[old, password])
        self.assertEqual(sorted((f["id"], f["count"]) for f in findings),
                         [(f"login:deploy/{UNKNOWN}", 1), ("login:ops/password", 1)])
        self.assertTrue(all(f["critical"] for f in findings))

    def test_legacy_burst_stays_per_login(self):
        old = self.legacy("2026-10-20T10:00:00Z", fp=KNOWN, reasons=["12 failures from 192.0.2.10 in the 24 hours before"])
        findings, _ = run(facts_of(), previous_open=[old])
        self.assertEqual([(f["id"], f["critical"]) for f in findings], [(old["id"], True)])

    def test_folded_and_fresh_logins_merge(self):
        old = [self.legacy("2026-10-20T10:00:00Z")]
        new = event(time="2026-11-08T10:00:00Z", fp=UNKNOWN, ip="192.0.2.77")
        findings, _ = run(facts_of(new), previous_open=old, since="2026-11-08T09:00:00Z")
        self.assertEqual([(f["count"], f["ips"]) for f in findings], [(2, ["192.0.2.10", "192.0.2.77"])])


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
        self.assertEqual([f["id"] for f in findings], ["logins:no-source", f"login:deploy/{UNKNOWN}"])


if __name__ == "__main__":
    unittest.main()
