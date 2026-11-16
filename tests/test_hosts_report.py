"""Host mode: `HOSTS.md`, its dated copy and the `log.md` lines.

The documents here are built by hand in the `hosts.json` shape (see `sbomaudit.hosts.checker`); hosts and
addresses are example data (203.0.113.0/24, 198.51.100.0/24, box-a style names).
"""
import datetime as dt
import re
import tempfile
import unittest
from pathlib import Path

from sbomaudit import hosts as hosts_pkg, report as core
from sbomaudit.hosts import report, store
from tests import test_hosts_check as tc
from tests.hosts_fixture import collector_doc

TODAY = dt.date(2026, 11, 9)
GENERATED = "2026-11-09T09:00:00Z"
CHECKED = "2026-11-02T09:00:00Z"


def f(id_, group, critical, text=None, **extra):
    return {"id": id_, "group": group, "critical": critical, "text": text or f"text of {id_}", **extra}


def entry(findings=(), status="ok", production=False, projects=("Example",), error=None, checked_at=GENERATED,
          attempted_at=GENERATED, summary=None, address="203.0.113.10"):
    findings = list(findings)
    if summary is None and status != "unsupported":
        summary = {"os": "ubuntu 24.04", "kernel": "6.8.0-45-generic", "reboot_required": False, "index": 70,
                   "index_prev": 70, "last_unattended": "2026-11-08 06:25:11", "updates_pending": 3, "kev": 0}
    return {"address": address, "production": production, "projects": list(projects), "status": status,
            "error": error, "checked_at": checked_at, "attempted_at": attempted_at, "summary": summary,
            "collector": {"installed": "1", "outdated": False}, "findings": findings,
            "critical": sorted(x["id"] for x in findings if x["critical"]), "known_hosts_sha": None}


def document(hosts, skipped=None, last_checked=GENERATED):
    return {"schema": 1, "generated_at": GENERATED, "skipped": skipped, "last_checked": last_checked,
            "collector_shipped": "1", "hosts": hosts}


# one finding per group of the section order
GROUPS = [
    f("section-failed:osv", "warning", True),
    f("hostkey:changed", "hostkey", True, known_hosts_sha=None),
    f("change:users:+deploy2", "change", True),
    f("kev:CVE-2024-1086:linux-image-6.8.0-45-generic@6.8.0-45.45", "kev", True, cve="CVE-2024-1086",
      package="linux-image-6.8.0-45-generic", version="6.8.0-45.45", fix="installable", fixed="6.8.0-46.46",
      candidate="6.8.0-46.46"),
    f("login:root@2026-11-08T10:12:03Z/SHA256:abc", "login", True),
    f("patch:timer-inactive", "patch", True),
    f("permissive:sshd-passwordauthentication", "permissive", False, "sshd PasswordAuthentication yes"),
    f("lynis-index:58", "lynis_index", True, "Lynis index dropped from 70 to 58"),
    f("lynis-warning:SSH-7408", "lynis_warning", False),
    f("vuln:openssl@3.0.13", "vuln", False, "2 open CVEs, no fix installable"),
    f("third-party:docker-ce", "third_party", False),
    f("lynis-suggestion:BOOT-5122", "lynis_suggestion", False),
    f("info:collector-outdated", "info", False),
]


class ReportCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.out = Path(self._tmp.name) / "security"
        self.out.mkdir()

    def render(self, doc) -> str:
        return report.write_md(self.out, doc).read_text(encoding="utf-8")

    def lines(self, text, prefix):
        return [line for line in text.splitlines() if line.startswith(prefix)]


class LayoutTest(ReportCase):
    def test_write_md_path_title_and_generated_at(self):
        path = report.write_md(self.out, document({"box-a": entry()}))
        self.assertEqual(path, self.out / "HOSTS.md")
        text = path.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("# "))
        self.assertIn(GENERATED, text.splitlines()[0] + text.splitlines()[2])

    def test_section_order(self):
        order = ["## box-a", "### Critical", "### Failed checks", "### Host key", "### Patch automation",
                 "### Logins", "### Fingerprint changes", "### Permissive defaults", "### Lynis warnings",
                 "### Vulnerabilities", "### Third-party updates", "Lynis suggestions", "### Informational"]
        # accepted findings of the record-only groups surface in their own section
        text = self.render(document({"box-a": entry(GROUPS + [
            f("kev:CVE-2025-1:pkg@1", "kev", False, accepted=True),
            f("login:x@2026-11-01T00:00:00Z/m", "login", False, accepted=True),
            f("change:users:+x", "change", False),
            f("origin:Docker:noble", "patch", False)])}))
        order.insert(4, "### KEV")
        positions = [text.index(h) for h in order]
        self.assertEqual(positions, sorted(positions), order)

    def test_empty_sections_are_omitted(self):
        text = self.render(document({"box-a": entry([f("info:collector-outdated", "info", False)])}))
        for heading in ("### Critical", "### Failed checks", "### KEV", "### Logins", "### Lynis warnings"):
            self.assertNotIn(heading, text)
        self.assertIn("### Informational", text)

    def test_host_without_findings(self):
        text = self.render(document({"box-a": entry()}))
        self.assertIn("No findings", text)

    def test_host_section_names_projects_and_address(self):
        text = self.render(document({"box-a": entry(projects=("Shop", "Blog"))}))
        self.assertRegex(text, r"Projects:.*Shop.*Blog")
        self.assertIn("203.0.113.10", text)

    def test_lynis_suggestions_are_collapsed(self):
        text = self.render(document({"box-a": entry([f("lynis-suggestion:BOOT-5122", "lynis_suggestion", False)])}))
        self.assertRegex(text, r"<details>\s*<summary>Lynis suggestions[^<]*</summary>")
        self.assertLess(text.index("<details>"), text.index("`lynis-suggestion:BOOT-5122`"))
        self.assertLess(text.index("`lynis-suggestion:BOOT-5122`"), text.index("</details>"))

    def test_kernel_not_assessable_is_informational(self):
        info = f("info:running-kernel:6.8.0-45-generic", "info", False,
                 "running kernel 6.8.0-45-generic not assessable: no kernel image installed")
        text = self.render(document({"box-a": entry([info])}))
        info_part = text[text.index("### Informational"):]
        self.assertIn("not assessable: no kernel image installed", info_part)
        self.assertNotIn("### Critical", text)


class CriticalTest(ReportCase):
    def test_critical_lines_carry_backticked_ids_and_accept_hint(self):
        text = self.render(document({"box-a": entry(GROUPS)}))
        critical = text[text.index("### Critical"):text.index("### Failed checks")]
        self.assertIn("`change:users:+deploy2`", critical)
        self.assertIn('hosts accept box-a `change:users:+deploy2`', critical)
        self.assertIn("`login:root@2026-11-08T10:12:03Z/SHA256:abc`", critical)
        self.assertIn("`lynis-index:58`", critical)

    def test_kev_accept_hint_names_review_by(self):
        text = self.render(document({"box-a": entry(GROUPS)}))
        critical = text[text.index("### Critical"):text.index("### Failed checks")]
        kev_line = [line for line in critical.splitlines() if "kev:CVE-2024-1086" in line][0]
        self.assertIn("--review-by", kev_line)

    def test_section_failed_and_patch_and_hostkey_have_no_accept_hint(self):
        text = self.render(document({"box-a": entry(GROUPS)}))
        critical = text[text.index("### Critical"):text.index("### Failed checks")]
        by_id = {id_: line for line in critical.splitlines()
                 for id_ in ("section-failed:osv", "patch:timer-inactive", "hostkey:changed") if f"`{id_}`" in line}
        self.assertEqual(set(by_id), {"section-failed:osv", "patch:timer-inactive", "hostkey:changed"})
        for line in by_id.values():
            self.assertNotIn("hosts accept", line)
        self.assertIn("fix the cause and re-run `hosts check`", by_id["section-failed:osv"])
        self.assertIn("only clears when fixed", by_id["patch:timer-inactive"])
        self.assertIn("re-pin with `hosts bootstrap box-a`", by_id["hostkey:changed"])

    def test_baseline_unreadable_has_no_accept_hint(self):
        text = self.render(document({"box-a": entry([f("baseline:unreadable", "change", True)])}))
        line = self.lines(text, "- ")[0]
        self.assertIn("`baseline:unreadable`", line)
        self.assertNotIn("hosts accept", line)
        self.assertIn("restore", line)

    def test_failed_checks_section_and_hostkey_section(self):
        text = self.render(document({"box-a": entry(GROUPS)}))
        failed = text[text.index("### Failed checks"):text.index("### Host key")]
        self.assertIn("`section-failed:osv`", failed)
        self.assertIn("as clean", failed)
        hostkey = text[text.index("### Host key"):text.index("### Permissive defaults")]
        self.assertIn("`hostkey:changed`", hostkey)

    def test_kev_without_critical_flag_is_still_critical(self):
        kev = f("kev:CVE-2024-1:pkg@1", "kev", False)   # defensive: a KEV finding is critical unless accepted
        text = self.render(document({"box-a": entry([kev])}))
        self.assertIn("`kev:CVE-2024-1:pkg@1`", text[text.index("### Critical"):])
        row = self.lines(text, "| box-a")[0]
        self.assertRegex(row, r"\| 1 \|")

    def test_info_only_host_counts_as_clean(self):
        text = self.render(document({"box-a": entry([f("info:collector-outdated", "info", False)])}))
        row = self.lines(text, "| box-a")[0]
        cells = [c.strip() for c in row.strip("|").split("|")]
        self.assertEqual(cells[4], "0")
        self.assertNotIn("### Critical", text)
        self.assertRegex(text, r"1 clean")

    def test_pipe_in_critical_text_does_not_break_a_table(self):
        bad = f("login:a|b@2026-11-08T10:12:03Z/m", "login", True, "login a|b from 203.0.113.9")
        text = self.render(document({"box-a": entry([bad])}))
        self.assertIn("a\\|b from 203.0.113.9", text)


class FixStateTest(ReportCase):
    CASES = {
        "installable": ("fix installable", dict(fix="installable", fixed="1.2-3", candidate="1.2-3")),
        "reboot": ("reboot", dict(fix="reboot", fixed="6.8.0-46.46", candidate=None)),
        "not installable": ("not installable", dict(fix="not installable", fixed="1.2-3", candidate="1.1-1")),
        "pro-only": ("Ubuntu Pro", dict(fix="pro-only", fixed="1.2-3+esm1", candidate=None)),
        "not released": ("no fix released", dict(fix="not released", fixed=None, candidate=None)),
        "unknown": ("fix state unknown", dict(fix="unknown", fixed=None, candidate=None)),
        "unknown+fixed": ("1.2-3", dict(fix="unknown", fixed="1.2-3", candidate="1:1.2-3")),
    }

    def test_every_fix_state_is_rendered_on_kev_lines(self):
        for name, (expected, extra) in self.CASES.items():
            with self.subTest(name):
                kev = f("kev:CVE-2024-1:pkg@1.0", "kev", True, "CVE-2024-1 (KEV) in pkg 1.0", cve="CVE-2024-1",
                        package="pkg", version="1.0", **extra)
                line = [x for x in self.render(document({"box-a": entry([kev])})).splitlines()
                        if "`kev:CVE-2024-1:pkg@1.0`" in x][0]
                self.assertIn(expected, line)
                self.assertIn("CVE-2024-1", line)
                self.assertIn("pkg", line)

    def test_unknown_with_fixed_version_differs_from_plain_unknown(self):
        plain = self.CASES["unknown"][1]
        with_fix = self.CASES["unknown+fixed"][1]
        def render(extra):
            kev = f("kev:CVE-2024-1:pkg@1.0", "kev", True, cve="CVE-2024-1", package="pkg", version="1.0", **extra)
            return [x for x in self.render(document({"box-a": entry([kev])})).splitlines() if "`kev:" in x][0]
        self.assertNotEqual(render(plain), render(with_fix))

    def test_vuln_line_shows_its_outlook(self):
        vuln = f("vuln:openssl@3.0.13", "vuln", False, "3 open CVEs, 2 fixed by the installable update to 3.0.14",
                 package="openssl", version="3.0.13", open=3, fixable=2, candidate="3.0.14")
        text = self.render(document({"box-a": entry([vuln])}))
        self.assertIn("2 fixed by the installable update to 3.0.14", text)

    def test_unknown_fix_value_is_escaped_not_dropped(self):
        kev = f("kev:CVE-2024-1:pkg@1.0", "kev", True, cve="CVE-2024-1", package="pkg", version="1.0", fix="a|b")
        text = self.render(document({"box-a": entry([kev])}))
        self.assertIn("a\\|b", text)


class StatusTest(ReportCase):
    def failed_doc(self, findings=(), checked_at=CHECKED, summary=None):
        return document({"box-a": entry(findings, status="failed", error="ssh: connect timed out",
                                        checked_at=checked_at, summary=summary)})

    def test_failed_host_is_never_clean(self):
        text = self.render(self.failed_doc())
        section = text[text.index("## box-a"):]
        self.assertIn("failed", section)
        self.assertIn("ssh: connect timed out", section)
        self.assertIn(f"last successful check {CHECKED}", section)
        self.assertNotIn("No findings", section)
        row = self.lines(text, "| box-a")[0]
        cells = [c.strip() for c in row.strip("|").split("|")]
        self.assertEqual(cells[2], "no")
        self.assertNotEqual(cells[4], "0")
        self.assertNotIn("1 clean", text)

    def test_failed_host_never_checked(self):
        text = self.render(self.failed_doc(checked_at=None))
        self.assertIn("last successful check never", text)

    def test_failed_host_marks_carried_findings(self):
        text = self.render(self.failed_doc([f("change:users:+deploy2", "change", True),
                                            f("permissive:sshd-passwordauthentication", "permissive", False)]))
        for id_ in ("change:users:+deploy2", "permissive:sshd-passwordauthentication"):
            line = [x for x in text.splitlines() if f"`{id_}`" in x][0]
            self.assertIn(f"from the last check {CHECKED}", line)

    def test_current_hostkey_finding_is_not_marked_stale(self):
        text = self.render(self.failed_doc([f("hostkey:changed", "hostkey", True)]))
        line = [x for x in text.splitlines() if "`hostkey:changed`" in x][0]
        self.assertNotIn("from the last check", line)

    def test_failed_error_is_escaped(self):
        doc = document({"box-a": entry(status="failed", error="bad | host\nline two", checked_at=None)})
        text = self.render(doc)
        self.assertIn("bad \\| host line two", text)

    def test_skipped_document_has_reason_and_last_checked(self):
        doc = document({"box-a": entry(checked_at=CHECKED)}, skipped="no audit key on this machine",
                       last_checked=CHECKED)
        text = self.render(doc)
        self.assertIn("no audit key on this machine", text)
        self.assertIn("last checked 2026-11-02", text)

    def test_skipped_without_any_check(self):
        text = self.render(document({}, skipped="no audit key on this machine", last_checked=None))
        self.assertIn("last checked never", text)

    def test_unsupported_host(self):
        unsupported = entry(status="unsupported", summary={"os": "alpine 3.20"}, projects=())
        text = self.render(document({"box-a": unsupported}))
        self.assertIn("unsupported OS", text)
        self.assertIn("alpine 3.20", text)
        self.assertNotIn("No findings", text)
        row = self.lines(text, "| box-a")[0]
        self.assertIn("unsupported OS", row)

    def test_unsupported_host_with_hostkey_finding_is_critical(self):
        unsupported = entry([f("hostkey:changed", "hostkey", True)], status="unsupported",
                            summary={"os": "alpine 3.20"})
        text = self.render(document({"box-a": unsupported}))
        self.assertIn("`hostkey:changed`", text[text.index("### Critical"):])


class FailClosedTest(ReportCase):
    def test_missing_or_unknown_status_is_not_reachable_and_not_clean(self):
        for status in (None, "weird", ""):
            with self.subTest(status=status):
                h = entry()
                if status is None:
                    del h["status"]
                else:
                    h["status"] = status
                text = self.render(document({"box-a": h}))
                cells = [c.strip() for c in self.lines(text, "| box-a")[0].strip("|").split("|")]
                self.assertEqual(cells[2], "no")
                self.assertEqual(cells[4], "unknown")
                self.assertIn("unknown status", text[text.index("## box-a"):])
                self.assertIn("0 clean", text)
                self.assertIn("1 unknown status", text)
                self.assertNotIn("No findings", text)

    def test_unknown_status_with_critical_findings_counts_them(self):
        h = entry([f("change:users:+x", "change", True)])
        h["status"] = "weird"
        text = self.render(document({"box-a": h}))
        self.assertIn("1 with critical findings", text)
        self.assertIn("`change:users:+x`", text)

    def test_unknown_status_value_is_escaped(self):
        h = entry()
        h["status"] = "a|b"
        self.assertIn("(a\\|b)", self.render(document({"box-a": h})))


class HeadlineTest(ReportCase):
    def test_headline_counts_critical_on_failed_and_unsupported_hosts(self):
        hosts = {"ok-crit": entry([f("change:users:+x", "change", True)]),
                 "failed-crit": entry([f("change:users:+y", "change", True)], status="failed", error="e"),
                 "unsup-crit": entry([f("hostkey:changed", "hostkey", True)], status="unsupported",
                                     summary={"os": "alpine 3.20"}),
                 "failed-clean": entry(status="failed", error="e"),
                 "clean": entry()}
        text = self.render(document(hosts))
        self.assertIn("5 hosts: 1 clean, 3 with critical findings, 2 failed, 1 unsupported OS, 0 unknown status",
                      text)


class LineSeparatorTest(ReportCase):
    SEPARATORS = {"CR": "\r", "CRLF": "\r\n", "VT": "\x0b", "FF": "\x0c", "FS": "\x1c", "GS": "\x1d",
                  "RS": "\x1e", "NEL": "\x85", "LS": "\u2028", "PS": "\u2029", "LF": "\n"}

    def test_md_normalizes_every_line_separator(self):
        for name, sep in self.SEPARATORS.items():
            with self.subTest(name):
                self.assertEqual(core.md(f"a{sep}b"), "a b")
                self.assertEqual(len(core.md(f"a{sep}b").splitlines()), 1)

    def test_log_line_cannot_be_split_by_a_separator(self):
        for name, sep in self.SEPARATORS.items():
            with self.subTest(name):
                report.append_log_admin(self.out, "patch", "box-a", f"ok{sep}2026-11-09 | hosts accept | x | y")
        self.assertEqual(len((self.out / "log.md").read_text(encoding="utf-8").splitlines()),
                         len(core.LOG_HEADER.splitlines()) + len(self.SEPARATORS))


class AcceptedTest(ReportCase):
    def test_accepted_record_only_finding_with_decision(self):
        store.accept  # decisions are read from the file store
        (self.out / store.DECISIONS_FILE).write_text(
            '[decisions."box-a"."login:root@2026-11-08T10:12:03Z/SHA256:abc"]\n'
            'date = "2026-11-09"\nnote = "my own | login"\n', encoding="utf-8")
        login = f("login:root@2026-11-08T10:12:03Z/SHA256:abc", "login", False, accepted=True)
        text = self.render(document({"box-a": entry([login])}))
        self.assertNotIn("### Critical", text)
        line = [x for x in text.splitlines() if "`login:root@" in x][0]
        self.assertIn("(accepted 2026-11-09: my own \\| login)", line)
        logins = text[text.index("### Logins"):]
        self.assertIn("`login:root@", logins)

    def test_accepted_without_decision_data(self):
        kev = f("kev:CVE-2024-1:pkg@1", "kev", False, accepted=True)
        text = self.render(document({"box-a": entry([kev])}))
        self.assertNotIn("### Critical", text)
        self.assertIn("### KEV", text)
        line = [x for x in text.splitlines() if "`kev:" in x][0]
        self.assertIn("(accepted)", line)
        row = self.lines(text, "| box-a")[0]
        self.assertEqual([c.strip() for c in row.strip("|").split("|")][4], "0")

    def test_unreadable_decisions_file_does_not_stop_the_report(self):
        (self.out / store.DECISIONS_FILE).write_text("not = [valid", encoding="utf-8")
        kev = f("kev:CVE-2024-1:pkg@1", "kev", False, accepted=True)
        text = self.render(document({"box-a": entry([kev])}))
        self.assertIn("(accepted)", text)

    def test_kev_decision_shows_review_by(self):
        (self.out / store.DECISIONS_FILE).write_text(
            '[decisions."box-a"."kev:CVE-2024-1:pkg@1"]\ndate = "2026-11-09"\nnote = "n"\n'
            'review_by = "2026-11-20"\n', encoding="utf-8")
        kev = f("kev:CVE-2024-1:pkg@1", "kev", False, accepted=True)
        text = self.render(document({"box-a": entry([kev])}))
        self.assertIn("review by 2026-11-20", text)


class TableTest(ReportCase):
    HEADER = "| Host | Production | Reachable | Index (Δ) | Critical | Updates pending | KEV | Last unattended run |"

    def rows(self, text):
        return [line for line in text.splitlines() if line.startswith("| ") and "---" not in line][1:]

    def test_header_and_production_first(self):
        hosts = {"a-dev": entry(), "z-prod": entry(production=True), "b-prod": entry(production=True),
                 "c-dev": entry()}
        text = self.render(document(hosts))
        self.assertIn(self.HEADER, text)
        names = [row.split("|")[1].strip() for row in self.rows(text)]
        self.assertEqual(names, ["b-prod", "z-prod", "a-dev", "c-dev"])
        self.assertLess(text.index("## b-prod"), text.index("## z-prod"))
        self.assertLess(text.index("## z-prod"), text.index("## a-dev"))

    def test_index_delta(self):
        def s(index, prev):
            return {"os": "ubuntu 24.04", "kernel": "k", "reboot_required": False, "index": index,
                    "index_prev": prev, "last_unattended": None, "updates_pending": 0, "kev": 0}
        hosts = {"up": entry(summary=s(75, 70)), "down": entry(summary=s(58, 70)), "same": entry(summary=s(70, 70)),
                 "first": entry(summary=s(70, None)), "none": entry(summary=s(None, None))}
        text = self.render(document(hosts))
        cells = {r.split("|")[1].strip(): [c.strip() for c in r.strip("|").split("|")] for r in self.rows(text)}
        self.assertEqual(cells["up"][3], "75 (+5)")
        self.assertEqual(cells["down"][3], "58 (-12)")
        self.assertEqual(cells["same"][3], "70 (±0)")
        self.assertEqual(cells["first"][3], "70")
        self.assertEqual(cells["none"][3], "-")

    def test_row_values(self):
        summary = {"os": "x", "kernel": "k", "reboot_required": False, "index": 70, "index_prev": 70,
                   "last_unattended": "2026-11-08 06:25:11", "updates_pending": 7, "kev": 2}
        text = self.render(document({"box-a": entry(GROUPS, production=True, summary=summary)}))
        cells = [c.strip() for c in self.rows(text)[0].strip("|").split("|")]
        self.assertEqual(cells[0], "box-a")
        self.assertEqual(cells[1], "yes")
        self.assertEqual(cells[2], "yes")
        self.assertEqual(cells[4], "7")   # warning, hostkey, change, kev, login, patch, lynis-index
        self.assertEqual(cells[5], "7")
        self.assertEqual(cells[6], "2")
        self.assertEqual(cells[7], "2026-11-08 06:25:11")

    def test_hostname_with_pipe_cannot_break_the_table(self):
        text = self.render(document({"a|b": entry()}))
        self.assertIn("| a\\|b |", text)


class EscapingTest(ReportCase):
    def test_user_controlled_strings_pass_through_md(self):
        nasty = "proc|name\nnext"
        findings = [
            f("change:sockets:+tcp/0.0.0.0:8080", "change", True, f"new listener {nasty}"),
            f("lynis-warning:SSH-7408", "lynis_warning", False, f"SSH | warning {nasty}"),
            f("third-party:pkg|x", "third_party", False, f"repo http://198.51.100.5/a|b {nasty}"),
        ]
        text = self.render(document({"box-a": entry(findings, projects=("p|q",))}))
        self.assertIn("new listener proc\\|name next", text)
        self.assertIn("SSH \\| warning proc\\|name next", text)
        self.assertIn("a\\|b proc\\|name next", text)
        self.assertIn("p\\|q", text)

    def test_ids_with_backticks_stay_in_one_code_span(self):
        odd = f("change:units:+we`ird.service", "change", True)
        text = self.render(document({"box-a": entry([odd])}))
        self.assertIn("``change:units:+we`ird.service``", text)

    def test_no_secret_material(self):
        # the document carries findings and a summary, never facts: sudoers content and key comments
        # cannot reach the report (this guards later changes to the document)
        doc = document({"box-a": {**entry([f("change:sudoers:+/etc/sudoers.d/91-x", "change", True)]),
                                  "facts": {"authorized_keys": {"root": [{"comment": "alice@laptop-secret"}]},
                                            "sudoers": "deploy ALL=(ALL) NOPASSWD: ALL"}}})
        text = self.render(doc)
        self.assertNotIn("alice@laptop-secret", text)
        self.assertNotIn("NOPASSWD", text)
        self.assertIn("`change:sudoers:+/etc/sudoers.d/91-x`", text)


class DatedCopyTest(ReportCase):
    def test_dated_copy(self):
        doc = document({"box-a": entry(GROUPS)})
        path = report.write_dated(self.out, doc, TODAY)
        self.assertEqual(path, self.out / "reports" / "2026-11-09-hosts.md")
        self.assertEqual(path.read_text(encoding="utf-8"), self.render(doc))


class LogTest(ReportCase):
    def log(self):
        return (self.out / core.LOG_FILE).read_text(encoding="utf-8")

    def test_check_line(self):
        hosts = {"box-a": entry([f("change:users:+x", "change", True), f("kev:CVE-1:p@1", "kev", True)]),
                 "box-b": entry(status="failed", error="ssh: connect timed out", checked_at=CHECKED,
                                attempted_at=GENERATED),
                 "box-c": entry(attempted_at="2026-11-02T09:00:00Z")}   # not part of this run
        path = report.append_log_check(self.out, document(hosts))
        self.assertEqual(path, self.out / "log.md")
        lines = self.log().splitlines()
        self.assertEqual(self.log().split("\n\n", 1)[0], core.LOG_HEADER.split("\n\n", 1)[0])
        self.assertEqual(lines[-1], f"{GENERATED} | hosts | checked 2 | failed 1 | critical 2"
                                    " | failed: box-b: ssh: connect timed out")

    def test_check_line_without_failures(self):
        report.append_log_check(self.out, document({"box-a": entry()}))
        self.assertEqual(self.log().splitlines()[-1], f"{GENERATED} | hosts | checked 1 | failed 0 | critical 0")

    def test_check_line_skipped(self):
        doc = document({"box-a": entry(attempted_at=CHECKED)}, skipped="no audit key on this machine")
        report.append_log_check(self.out, doc)
        self.assertEqual(self.log().splitlines()[-1], f"{GENERATED} | hosts | checked 0 | failed 0 | critical 0"
                                                      " | skipped: no audit key on this machine")

    def test_failed_list_is_escaped_and_joined(self):
        hosts = {"box-a": entry(status="failed", error="a | b\nc"), "box-b": entry(status="failed", error="timeout")}
        report.append_log_check(self.out, document(hosts))
        self.assertTrue(self.log().splitlines()[-1].endswith(" | failed: box-a: a \\| b c; box-b: timeout"))

    def test_log_is_appended_not_replaced(self):
        (self.out / "log.md").write_text(core.LOG_HEADER + "2026-11-08 | run | 3\n", encoding="utf-8")
        report.append_log_check(self.out, document({"box-a": entry()}))
        lines = self.log().splitlines()
        self.assertIn("2026-11-08 | run | 3", lines)
        self.assertEqual(sum(1 for x in lines if "| hosts |" in x), 1)

    def test_accept_line(self):
        path = report.append_log_accept(self.out, "box-a", "change:users:+deploy2")
        self.assertEqual(path, self.out / "log.md")
        line = self.log().splitlines()[-1]
        self.assertRegex(line, r"^\d{4}-\d{2}-\d{2}T[^ ]+ \| hosts accept \| box-a \| change:users:\+deploy2$")

    def test_admin_line(self):
        for action in ("bootstrap", "unbootstrap", "patch"):
            report.append_log_admin(self.out, action, "box-a", "ok")
            self.assertRegex(self.log().splitlines()[-1], rf"\| hosts {action} \| box-a \| ok$")
        with self.assertRaises(ValueError):
            report.append_log_admin(self.out, "reboot", "box-a", "ok")

    def test_admin_outcome_is_escaped(self):
        report.append_log_admin(self.out, "patch", "box-a", "failed: a | b\nc")
        self.assertTrue(self.log().splitlines()[-1].endswith("| hosts patch | box-a | failed: a \\| b c"))

    def test_store_accept_logs_host_and_id_never_the_note(self):
        host_doc = {**entry([f("change:users:+deploy2", "change", True)]),
                    "fingerprint": {"users": {"deploy2": "uid=1001"}}}
        store.write(self.out, document({"box-a": host_doc}))
        store.write_baseline(self.out, "box-a", {"schema": 1, "created": GENERATED,
                                                 "fingerprint": {"users": {}}, "lynis": {}, "packages_seen": {}})
        store.accept(self.out, "box-a", "change:users:+deploy2", "SECRET-NOTE-TEXT", None, TODAY)
        text = self.log()
        self.assertIn("| hosts accept | box-a | change:users:+deploy2", text)
        self.assertNotIn("SECRET-NOTE-TEXT", text)

    def test_refused_accept_logs_nothing(self):
        store.write(self.out, document({"box-a": entry([f("patch:timer-inactive", "patch", True)])}))
        with self.assertRaises(ValueError):
            store.accept(self.out, "box-a", "patch:timer-inactive", "n", None, TODAY)
        self.assertFalse((self.out / "log.md").exists())


class CheckWiringTest(tc.CheckCase):
    """`hosts.check` writes HOSTS.md, the dated copy and the log line (only the log line when skipped)."""

    def test_check_writes_report_dated_copy_and_log(self):
        doc, _ = self.check({"box-a": [tc.ok(collector_doc())]})
        md_text = (self.out / "HOSTS.md").read_text(encoding="utf-8")
        self.assertIn("## box-a", md_text)
        self.assertEqual((self.out / "reports" / "2026-11-09-hosts.md").read_text(encoding="utf-8"), md_text)
        last = (self.out / "log.md").read_text(encoding="utf-8").splitlines()[-1]
        self.assertEqual(last, f"{doc['generated_at']} | hosts | checked 1 | failed 0 | critical 0")

    def test_failed_host_is_logged_and_rendered(self):
        self.check({"box-a": [tc.ok(collector_doc())]})
        doc, _ = self.check({"box-a": [tc.fail(255, b"ssh: connect to host 203.0.113.10 port 22: Connection refused")]},
                            now=tc.LATER)
        self.assertEqual(doc["hosts"]["box-a"]["status"], "failed")
        last = (self.out / "log.md").read_text(encoding="utf-8").splitlines()[-1]
        self.assertRegex(last, r"\| hosts \| checked 1 \| failed 1 \| critical \d+ \| failed: box-a: ")
        text = (self.out / "HOSTS.md").read_text(encoding="utf-8")
        self.assertIn("**Status: failed**", text)
        self.assertIn("last successful check 2026-11-09T09:00:00Z", text)

    def test_skipped_run_only_logs(self):
        self.check({"box-a": [tc.ok(collector_doc())]})
        md_before = (self.out / "HOSTS.md").read_bytes()
        doc = hosts_pkg.check(self.cfg(key=self.out / "missing_key"), None, self.logs.append,
                              run=tc.FakeRun({}), sleep=self.sleeps.append, fetch=self.net.fetch,
                              post=self.net.post, now=tc.LATER)
        self.assertEqual(doc["skipped"], "no audit key on this machine")
        self.assertEqual((self.out / "HOSTS.md").read_bytes(), md_before)
        self.assertFalse((self.out / "reports" / "2026-11-09-hosts.md").read_text().count("Skipped"))
        last = (self.out / "log.md").read_text(encoding="utf-8").splitlines()[-1]
        self.assertTrue(last.endswith("| hosts | checked 0 | failed 0 | critical 0 | skipped: no audit key on "
                                      "this machine"))

    def test_skipped_run_without_previous_output_creates_only_the_log(self):
        hosts_pkg.check(self.cfg(key=self.out / "missing_key"), None, self.logs.append, run=tc.FakeRun({}),
                        sleep=self.sleeps.append, fetch=self.net.fetch, post=self.net.post, now=tc.NOW)
        self.assertTrue((self.out / "log.md").exists())
        self.assertFalse((self.out / "HOSTS.md").exists())
        self.assertFalse((self.out / "reports").exists())


if __name__ == "__main__":
    unittest.main()
