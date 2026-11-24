"""Host mode: the ssh transport and `hosts check` (collection, evaluation, hosts.json and baselines).

Nothing here opens a connection: `run` is a fake that answers each ssh call with a canned
`CompletedProcess`, `sleep` records its calls, and osv.dev and CISA KEV are fakes too. Hosts and
addresses are example data (203.0.113.0/24, box-a style names).
"""
import dataclasses
import datetime as dt
import json
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
from pathlib import Path

from sbomaudit import config, enrich, epss, status
from sbomaudit.hosts import checker, osvhost, parse, store, transport
from sbomaudit import hosts
from unittest import mock

from tests.helpers import epss_fetch, epss_gz
from tests.hosts_fixture import collector_doc, section_text

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 11, 9, 9, 0, tzinfo=UTC)
LATER = dt.datetime(2026, 11, 9, 10, 0, tzinfo=UTC)
NEXT_WEEK = dt.datetime(2026, 11, 16, 9, 0, tzinfo=UTC)
AUDIT_FP = "SHA256:AuditKeyFingerprintExample0000000000000000000"
DEPLOY_FP = "SHA256:DJAtqSefbS0x0aOApnlCyNKOglphGM2PMe8HI0T09m8"
OSV_DIR = Path(__file__).resolve().parent / "fixtures" / "hosts" / "osv"
KEV_CVE = "CVE-2024-9143"
CHANGED = (b"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
           b"@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n"
           b"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
           b"Host key verification failed.\n")


def ok(doc: dict) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(["ssh"], 0, json.dumps(doc).encode(), b"")


def fail(rc: int, stderr: bytes, stdout: bytes = b"") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(["ssh"], rc, stdout, stderr)


def login_line(time_: str, ip: str, fp: str, user: str = "deploy") -> str:
    return (f"A\t{time_} box-a sshd[1]: Accepted publickey for {user} from {ip} port 50000 ssh2: "
            f"ED25519 {fp}")


def logins_text(*lines: str) -> str:
    return "S\tjournal\nZ\t+0000\n" + "".join(line + "\n" for line in lines)


FRESH_UU = "2026-11-15 06:25:11,402 INFO Starting unattended upgrades script\n"


class FakeRun:
    """`subprocess.run` stand-in: ssh calls get the next canned answer for their host (the last one
    repeats); `ssh-keygen -lf` answers with the audit key fingerprint."""

    def __init__(self, answers: dict, keygen=None, delay: float = 0.0):
        self.answers = {h: list(a) for h, a in answers.items()}
        self.keygen = keygen
        self.delay = delay
        self.calls: list[list[str]] = []
        self.kwargs: list[dict] = []
        self.events: list[str] = []
        self.lock = threading.Lock()
        self.in_flight = 0
        self.max_in_flight = 0

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        with self.lock:
            self.calls.append(argv)
            self.kwargs.append(kwargs)
        if argv[0] == "ssh-keygen":
            if isinstance(self.keygen, BaseException):
                raise self.keygen
            return subprocess.CompletedProcess(argv, 0, (self.keygen or f"256 {AUDIT_FP} sbom-audit (ED25519)\n")
                                               .encode(), b"")
        host = next(a.split("=", 1)[1][len("sbom-audit-"):] for a in argv if a.startswith("HostKeyAlias="))
        with self.lock:
            self.in_flight += 1
            self.max_in_flight = max(self.max_in_flight, self.in_flight)
            queue = self.answers[host]
            answer = queue.pop(0) if len(queue) > 1 else queue[0]
            self.events.append(f"ssh:{host}")
        try:
            if self.delay:
                time.sleep(self.delay)
            if isinstance(answer, BaseException):
                raise answer
            return answer
        finally:
            with self.lock:
                self.in_flight -= 1

    def ssh_calls(self):
        return [c for c in self.calls if c[0] == "ssh"]


class FakeNet:
    """osv.dev (`post` querybatch, `fetch` records), the CISA KEV feed and endoflife.date (`fetch`)."""

    def __init__(self, kev=(), vulns=None, records=None, events=None):
        self.kev = list(kev)
        self.vulns = dict(vulns or {})
        self.records = dict(records or {})
        self.events = events if events is not None else []
        self.os_eol = {"eol": "2029-05-31"}       # endoflife.date: the OS release is supported

    def post(self, url, body):
        self.events.append("osv")
        results = []
        for q in body["queries"]:
            key = (q["package"]["name"], q["version"])
            ids = ["UBUNTU-CVE-2024-0001"] if key == ("openssl", "0") else self.vulns.get(key, [])
            results.append({"vulns": [{"id": i, "modified": "2026-11-01T00:00:00Z"} for i in ids]} if ids else {})
        return {"results": results}

    def fetch(self, url):
        if url == enrich.KEV_URL:
            return {"vulnerabilities": [{"cveID": c} for c in self.kev]}
        if url.startswith(f"{enrich.EOL_API}/ubuntu/") or url.startswith(f"{enrich.EOL_API}/debian/"):
            return self.os_eol
        if url.startswith(osvhost.VULN_URL):
            vid = url.rsplit("/", 1)[1]
            if vid in self.records:
                return self.records[vid]
        raise urllib.error.URLError(f"unexpected url {url}")


def kev_net() -> FakeNet:
    record = json.loads((OSV_DIR / "vuln-UBUNTU-CVE-2024-9143.json").read_text())
    return FakeNet(kev=[KEV_CVE], vulns={("openssl", "3.0.13-0ubuntu3.4"): ["UBUNTU-CVE-2024-9143"]},
                   records={"UBUNTU-CVE-2024-9143": record})


class CheckCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.out = root / "security"
        self.out.mkdir()
        self.key = root / "sbom-audit_ed25519"
        self.key.write_text("private\n")
        Path(f"{self.key}.pub").write_text("ssh-ed25519 AAAA sbom-audit\n")
        self.sleeps: list[float] = []
        self.logs: list[str] = []
        self.net = FakeNet()

    def cfg(self, servers=None, concurrency=4, key=None) -> config.Config:
        servers = servers or {"box-a": config.HostOpts(address="203.0.113.10", production=True,
                                                       projects=["Example"])}
        opts = config.HostsOpts(enabled=True, concurrency=concurrency, timeout_minutes=10,
                                key=key or self.key, servers=servers)
        return config.Config(out=self.out, root=self.out.parent, mode="portfolio", hosts=opts)

    def check(self, answers, now=NOW, cfg=None, names=None, net=None, run=None):
        run = run or FakeRun(answers)
        net = net or self.net
        doc = hosts.check(cfg or self.cfg(), names, self.logs.append, run=run, sleep=self.sleeps.append,
                          fetch=net.fetch, post=net.post, now=now)
        return doc, run

    def entry(self, doc, host="box-a"):
        return doc["hosts"][host]

    def accept(self, change_id, review_by=None, today=NOW.date()):
        store.accept(self.out, "box-a", change_id, "expected", review_by, today)


# --------------------------------------------------------------------------- transport

class TransportTest(CheckCase):
    def test_ssh_argv_exact(self):
        opts = self.cfg().hosts
        argv = transport.ssh_argv(opts, "box-a", opts.servers["box-a"], self.out)
        self.assertEqual(argv, [
            "ssh", "-i", str(self.key), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={self.out}/hosts/known_hosts",
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", "HostKeyAlias=sbom-audit-box-a",
            "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=4",
            "-o", "ControlPath=none", "-l", "sbom-audit", "203.0.113.10", "collect"])

    def test_alias_with_port_uses_host_key_alias(self):
        opts = self.cfg({"box-a": config.HostOpts(address="box-a")}).hosts
        argv = transport.ssh_argv(opts, "box-a", opts.servers["box-a"], self.out)
        self.assertIn("HostKeyAlias=sbom-audit-box-a", argv)
        self.assertEqual(argv[argv.index("-l"):], ["-l", "sbom-audit", "box-a", "collect"])
        self.assertNotIn("-p", argv)

    def test_address_that_looks_like_an_option_is_refused(self):
        opts = self.cfg({"box-a": config.HostOpts(address="-oProxyCommand=x")}).hosts
        with self.assertRaises(ValueError):
            transport.ssh_argv(opts, "box-a", opts.servers["box-a"], self.out)

    def test_known_hosts_path_with_space_is_quoted(self):
        opts = self.cfg().hosts
        argv = transport.ssh_argv(opts, "box-a", opts.servers["box-a"], Path("/x/my evidence"))
        self.assertIn('UserKnownHostsFile="/x/my evidence/hosts/known_hosts"', argv)

    def test_collect_timeout_retries_then_fails(self):
        run = FakeRun({"box-a": [subprocess.TimeoutExpired(["ssh"], 600)]})
        argv = transport.ssh_argv(self.cfg().hosts, "box-a", self.cfg().hosts.servers["box-a"], self.out)
        res = transport.collect(argv, 600, run=run, sleep=self.sleeps.append)
        self.assertIsNone(res.doc)
        self.assertIn("timed out", res.error)
        self.assertEqual(self.sleeps, [300])
        self.assertEqual({k["timeout"] for k in run.kwargs}, {600})

    def test_undecodable_stderr_does_not_crash(self):
        run = FakeRun({"box-a": [fail(255, b"\xff\xfe broken \xc3\n")]})
        argv = transport.ssh_argv(self.cfg().hosts, "box-a", self.cfg().hosts.servers["box-a"], self.out)
        res = transport.collect(argv, 600, run=run, sleep=self.sleeps.append)
        self.assertIn("broken", res.error)

    def test_audit_fingerprint(self):
        run = FakeRun({})
        self.assertEqual(transport.audit_fingerprint(self.key, run=run), AUDIT_FP)
        self.assertEqual(run.calls, [["ssh-keygen", "-lf", f"{self.key}.pub"]])
        with self.assertRaises(ValueError):
            transport.audit_fingerprint(self.key, run=FakeRun({}, keygen="garbage\n"))


# --------------------------------------------------------------------------- failed sources

class FailedSourceTest(CheckCase):
    def test_unreachable_retries_once_then_failed_source(self):
        refused = fail(255, b"ssh: connect to host 203.0.113.10 port 22: Connection refused\n")
        doc, run = self.check({"box-a": [refused, refused]})
        e = self.entry(doc)
        self.assertEqual(self.sleeps, [300])
        self.assertEqual(len(run.ssh_calls()), 2)
        self.assertEqual(e["status"], "failed")
        self.assertIn("Connection refused", e["error"])
        self.assertEqual(e["critical"], [])

    def test_reboot_window_recovers_on_retry(self):
        refused = fail(255, b"ssh: connect to host 203.0.113.10 port 22: Connection refused\n")
        doc, _ = self.check({"box-a": [refused, ok(collector_doc())]})
        self.assertEqual(self.sleeps, [300])
        self.assertEqual(self.entry(doc)["status"], "ok")

    def test_host_key_change_not_retried_and_critical(self):
        doc, run = self.check({"box-a": [fail(255, CHANGED)]})
        e = self.entry(doc)
        self.assertEqual(self.sleeps, [])
        self.assertEqual(len(run.ssh_calls()), 1)
        self.assertEqual(e["status"], "failed")
        self.assertEqual(e["critical"], ["hostkey:changed"])

    def test_unpinned_host_key_is_failed_not_changed(self):
        doc, _ = self.check({"box-a": [fail(255, b"No ED25519 host key is known for sbom-audit-box-a and you "
                                                 b"have requested strict checking.\r\nHost key verification "
                                                 b"failed.\r\n")]})
        e = self.entry(doc)
        self.assertEqual(self.sleeps, [])
        self.assertEqual((e["status"], e["critical"]), ("failed", []))
        self.assertIn("hosts bootstrap", e["error"])

    def test_truncated_output_is_failed_source(self):
        truncated = subprocess.CompletedProcess(["ssh"], 0, json.dumps(collector_doc()).encode()[:500], b"")
        doc, _ = self.check({"box-a": [truncated, truncated]})
        e = self.entry(doc)
        self.assertEqual(self.sleeps, [300])
        self.assertEqual(e["status"], "failed")
        self.assertIn("not JSON", e["error"])

    def test_sudo_password_prompt_is_failed_source(self):
        doc, _ = self.check({"box-a": [fail(1, b"sudo: a password is required\n")]})
        e = self.entry(doc)
        self.assertEqual(self.sleeps, [])
        self.assertEqual(e["status"], "failed")
        self.assertIn("sudo: a password is required", e["error"])

    def test_not_a_collector_document_is_failed_source(self):
        doc, _ = self.check({"box-a": [ok({"hello": 1})]})
        self.assertEqual(self.entry(doc)["status"], "failed")

    def test_failed_host_keeps_previous_findings_and_window(self):
        unknown = "SHA256:UnknownKeyExample000000000000000000000000000"
        self.check({"box-a": [ok(collector_doc())]})
        doc, _ = self.check({"box-a": [ok(collector_doc(logins=logins_text(
            login_line("2026-11-09T09:30:00+00:00", "203.0.113.66", unknown))))]}, now=LATER)
        open_id = self.entry(doc)["critical"][0]
        previous = self.entry(doc)
        doc, _ = self.check({"box-a": [fail(1, b"sudo: a password is required\n")]},
                            now=NEXT_WEEK)
        e = self.entry(doc)
        self.assertEqual(e["status"], "failed")
        self.assertEqual(e["critical"], [open_id])
        self.assertEqual(e["login_window"], previous["login_window"])
        self.assertEqual(e["checked_at"], previous["checked_at"])

    def test_os_section_failure_is_failed_source(self):
        doc, _ = self.check({"box-a": [ok(collector_doc(os=(1, "cat: /etc/os-release: No such file")))]})
        self.assertEqual(self.entry(doc)["status"], "failed")
        self.assertFalse((self.out / "hosts" / "baseline" / "box-a.json").exists())


# --------------------------------------------------------------------------- evaluation

class EvaluateTest(CheckCase):
    def test_first_run_writes_baseline_no_changes(self):
        doc, _ = self.check({"box-a": [ok(collector_doc())]})
        e = self.entry(doc)
        self.assertEqual((e["status"], e["error"], e["critical"]), ("ok", None, []))
        self.assertFalse([f for f in e["findings"] if f["group"] == "change"])
        base = store.read_baseline(self.out, "box-a")
        self.assertEqual(base["schema"], 1)
        self.assertEqual(base["fingerprint"], e["fingerprint"])
        self.assertEqual(base["lynis"], {"index": 72, "warnings": ["SSH-7408"]})
        self.assertEqual(base["packages_seen"]["containerd.io"], "1.7.22-1")
        self.assertEqual(store.read(self.out), doc)
        self.assertEqual(e["checked_at"], "2026-11-09T09:00:00Z")
        self.assertEqual((e["production"], e["projects"]), (True, ["Example"]))
        self.assertEqual(e["summary"]["index"], 72)
        self.assertEqual(e["summary"]["updates_pending"], 2)
        self.assertEqual(doc["last_checked"], "2026-11-09T09:00:00Z")
        self.assertEqual(doc["collector_shipped"], parse.SHIPPED_VERSION)
        self.assertIsNone(doc["skipped"])

    def test_first_run_known_key_login_not_critical(self):
        # the first-run baseline for logins is the fresh fingerprint, so the deploy key is known
        doc, _ = self.check({"box-a": [ok(collector_doc())]})
        logins_ = [f for f in self.entry(doc)["findings"] if f["group"] == "login"]
        self.assertEqual(len(logins_), 1)
        self.assertFalse(logins_[0]["critical"])

    def test_only_info_findings_is_clean(self):
        doc, _ = self.check({"box-a": [ok(collector_doc())]})
        e = self.entry(doc)
        self.assertTrue(e["findings"])
        self.assertFalse([f for f in e["findings"] if f["critical"]])
        self.assertEqual(e["critical"], [])

    def test_unsupported_ecosystem_keeps_other_checks(self):
        trixie = "PRETTY_NAME=\"Debian GNU/Linux trixie/sid\"\nID=debian\nVERSION_CODENAME=trixie\n"
        doc, _ = self.check({"box-a": [ok(collector_doc(os=trixie))]})
        e = self.entry(doc)
        self.assertEqual(e["status"], "ok")
        vuln = [f for f in e["findings"] if f["group"] == "vuln"]
        self.assertEqual(len(vuln), 1)
        self.assertFalse(vuln[0]["critical"])
        self.assertIn("unsupported for debian trixie", vuln[0]["text"])
        ids = {f["id"] for f in e["findings"]}
        self.assertIn("patch:automatic-reboot", ids)
        self.assertIn("info:kernel", ids)
        self.assertTrue(e["fingerprint"]["users"])

    def test_unsupported_os_is_not_checked(self):
        alpine = "ID=alpine\nVERSION_ID=3.20.3\n"
        doc, _ = self.check({"box-a": [ok(collector_doc(os=alpine))]})
        e = self.entry(doc)
        self.assertEqual((e["status"], e["findings"], e["critical"]), ("unsupported", [], []))
        self.assertFalse((self.out / "hosts" / "baseline" / "box-a.json").exists())

    def test_collector_outdated_reported(self):
        old = collector_doc()
        old["collector"] = "0"
        doc, _ = self.check({"box-a": [ok(old)]})
        e = self.entry(doc)
        self.assertEqual(e["collector"], {"installed": "0", "outdated": True})
        found = [f for f in e["findings"] if f["id"] == "info:collector-outdated"]
        self.assertEqual(found[0]["group"], "info")
        self.assertEqual(found[0]["text"], "collector outdated: run `hosts bootstrap box-a`")
        current, _ = self.check({"box-a": [ok(collector_doc())]})
        self.assertEqual(self.entry(current)["collector"], {"installed": parse.SHIPPED_VERSION, "outdated": False})

    def test_section_failure_is_critical_and_holds_the_login_window(self):
        self.check({"box-a": [ok(collector_doc())]})
        first = store.read(self.out)["hosts"]["box-a"]
        broken = collector_doc(logins=(124, "S\tjournal\nE\tjournalctl timed out\n"), policy=(1, "E: lock"))
        doc, _ = self.check({"box-a": [ok(broken)]}, now=NEXT_WEEK)
        e = self.entry(doc)
        self.assertEqual(e["status"], "ok")
        self.assertIn("section-failed:logins", e["critical"])
        self.assertIn("section-failed:policy", e["critical"])
        self.assertEqual(e["logins_checked_until"], first["logins_checked_until"])

    def test_failed_fingerprint_section_keeps_the_baseline_section(self):
        self.check({"box-a": [ok(collector_doc())]})
        doc, _ = self.check({"box-a": [ok(collector_doc(authorized_keys=(2, "boom")))]}, now=LATER)
        e = self.entry(doc)
        self.assertEqual(e["critical"], ["section-failed:authorized_keys"])
        self.assertEqual(store.read_baseline(self.out, "box-a")["fingerprint"]["authorized_keys"],
                         e["fingerprint"]["authorized_keys"])

    def test_first_run_with_failed_section_writes_no_baseline(self):
        doc, _ = self.check({"box-a": [ok(collector_doc(sudoers=(1, "boom")))]})
        self.assertIn("section-failed:sudoers", self.entry(doc)["critical"])
        self.assertFalse((self.out / "hosts" / "baseline" / "box-a.json").exists())

    def test_corrupt_baseline_is_critical_and_not_overwritten(self):
        self.check({"box-a": [ok(collector_doc())]})
        path = self.out / "hosts" / "baseline" / "box-a.json"
        path.write_text("{corrupt", encoding="utf-8")
        doc, _ = self.check({"box-a": [ok(collector_doc(sudoers=section_text("sudoers") +
                                                        "/etc/sudoers.d/91-x\tabc\tmallory\n"))]}, now=LATER)
        e = self.entry(doc)
        self.assertIn("baseline:unreadable", e["critical"])
        self.assertEqual(path.read_text(encoding="utf-8"), "{corrupt")
        with self.assertRaises(ValueError):
            self.accept("baseline:unreadable")

    def test_raw_facts_and_source_credentials_never_written(self):
        sources = "deb https://user:s3cretpass@203.0.113.5/repo noble main\n"
        doc, _ = self.check({"box-a": [ok(collector_doc(apt_sources=sources))]})
        self.assertNotIn("facts", self.entry(doc))
        for path in (self.out / store.HOSTS_JSON, self.out / "hosts" / "baseline" / "box-a.json"):
            self.assertNotIn("s3cretpass", path.read_text(encoding="utf-8"))
        # a failed section must not carry its output lines into hosts.json either
        failed = (1, "deb https://user:s3cretpass@203.0.113.5/repo noble main\nE: something\n")
        doc, _ = self.check({"box-a": [ok(collector_doc(apt_sources=failed))]}, now=LATER)
        self.assertIn("section-failed:apt_sources", self.entry(doc)["critical"])
        self.assertNotIn(b"s3cretpass", (self.out / store.HOSTS_JSON).read_bytes())
        for path in (self.out / "hosts" / "baseline").iterdir():
            self.assertNotIn(b"s3cretpass", path.read_bytes())

    def test_audit_key_logins_are_dropped(self):
        text = logins_text(login_line("2026-11-08T09:00:00+00:00", "198.51.100.4", AUDIT_FP, "sbom-audit"))
        doc, _ = self.check({"box-a": [ok(collector_doc(logins=text))]})
        self.assertFalse([f for f in self.entry(doc)["findings"] if f["group"] == "login"])

    def test_audit_fingerprint_failure_is_guarded(self):
        text = logins_text(login_line("2026-11-08T09:00:00+00:00", "198.51.100.4", AUDIT_FP, "sbom-audit"))
        run = FakeRun({"box-a": [ok(collector_doc(logins=text))]}, keygen=OSError("no ssh-keygen"))
        doc, _ = self.check(None, run=run)
        logins_ = [f for f in self.entry(doc)["findings"] if f["group"] == "login"]
        self.assertEqual(len(logins_), 1)      # not dropped, and judged like any other unknown key
        self.assertEqual(self.entry(doc)["status"], "ok")

    def test_osv_runs_after_the_ssh_call(self):
        run = FakeRun({"box-a": [ok(collector_doc())]})
        self.net.events = run.events
        self.check(None, run=run)
        self.assertEqual(run.events[0], "ssh:box-a")
        self.assertIn("osv", run.events[1:])
        ssh_kwargs = [k for c, k in zip(run.calls, run.kwargs) if c[0] == "ssh"]
        self.assertEqual(ssh_kwargs[0]["timeout"], 600)

    def test_kev_load_error_is_a_failed_section_and_keeps_kev_findings(self):
        net = FakeNet()
        net.fetch = lambda url: (_ for _ in ()).throw(urllib.error.URLError("offline"))
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, net=net)
        e = self.entry(doc)
        self.assertEqual(e["status"], "ok")                    # the host answered; one section did not run
        failed = [f for f in e["findings"] if f["id"] == "section-failed:kev"]
        self.assertEqual(len(failed), 1)
        self.assertTrue(failed[0]["critical"])
        self.assertIn("CISA KEV", failed[0]["text"])
        self.assertIn("section-failed:kev", e["critical"])
        self.assertFalse(any(f["id"] == "info:kev-unavailable" for f in e["findings"]))
        failed_hosts, critical = checker.outcome(doc, ["box-a"])
        self.assertEqual((failed_hosts, critical), ([], True))

    def test_kev_outage_never_resolves_previous_kev_findings(self):
        good = kev_net()
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, net=good)
        kev_ids = sorted(i for i in self.entry(doc)["critical"] if i.startswith("kev:"))
        self.assertTrue(kev_ids)
        before = status.build(status.empty_report(), secrets=None, previous=None, duration_s=1, exit_code=0,
                              run_host="mac", mode="full", hosts=doc)
        shutil.rmtree(self.out / ".cache" / "enrich")            # no cached KEV list: the outage is real
        down = kev_net()
        fetch = down.fetch
        down.fetch = lambda url: (_ for _ in ()).throw(urllib.error.URLError("offline")) \
            if url == enrich.KEV_URL else fetch(url)
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, net=down, now=LATER)
        e = self.entry(doc)
        self.assertEqual(sorted(i for i in e["critical"] if i.startswith("kev:")), kev_ids)
        self.assertIn("section-failed:kev", e["critical"])
        after = status.refresh_hosts(before, doc)
        self.assertEqual(after["deltas"]["hosts_critical"]["resolved"], [])
        self.assertEqual(after["deltas"]["hosts_critical"]["new"], ["box-a section-failed:kev"])

    def test_kev_outage_reapplies_a_kev_decision_to_carried_findings(self):
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, net=kev_net())
        kid = next(i for i in self.entry(doc)["critical"] if i.startswith("kev:"))
        self.accept(kid, review_by="2026-11-20")
        shutil.rmtree(self.out / ".cache" / "enrich")
        down = kev_net()
        fetch = down.fetch
        down.fetch = lambda url: (_ for _ in ()).throw(urllib.error.URLError("offline")) \
            if url == enrich.KEV_URL else fetch(url)
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, net=down, now=LATER)
        self.assertNotIn(kid, self.entry(doc)["critical"])
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, net=down,
                            now=dt.datetime(2026, 11, 21, 9, 0, tzinfo=UTC))
        self.assertIn(kid, self.entry(doc)["critical"])          # the decision lapsed: critical again

    def test_unparsable_os_eol_date_is_info_not_silence(self):
        net = FakeNet()
        net.os_eol = {"eol": "sometime in 2029"}
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, net=net)
        e = self.entry(doc)
        self.assertNotIn("os:eol", e["critical"])
        finding = next(f for f in e["findings"] if f["id"] == "info:os-eol-unavailable")
        self.assertFalse(finding["critical"])
        self.assertIn("sometime in 2029", finding["text"])

    def osv_down_net(self) -> FakeNet:
        down = kev_net()
        def broken(url, body):
            raise urllib.error.URLError("offline")
        down.post = broken
        return down

    def test_osv_outage_never_resolves_previous_kev_findings(self):
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, net=kev_net())
        kev_ids = sorted(i for i in self.entry(doc)["critical"] if i.startswith("kev:"))
        self.assertTrue(kev_ids)
        before = status.build(status.empty_report(), secrets=None, previous=None, duration_s=1, exit_code=0,
                              run_host="mac", mode="full", hosts=doc)
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, net=self.osv_down_net(), now=LATER)
        e = self.entry(doc)
        self.assertEqual(sorted(i for i in e["critical"] if i.startswith("kev:")), kev_ids)
        self.assertIn("section-failed:osv", e["critical"])
        after = status.refresh_hosts(before, doc)
        self.assertEqual(after["deltas"]["hosts_critical"]["resolved"], [])
        self.assertEqual(after["deltas"]["hosts_critical"]["new"], ["box-a section-failed:osv"])

    def test_osv_outage_reapplies_a_kev_decision_to_carried_findings(self):
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, net=kev_net())
        kid = next(i for i in self.entry(doc)["critical"] if i.startswith("kev:"))
        self.accept(kid, review_by="2026-11-20")
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, net=self.osv_down_net(), now=LATER)
        self.assertNotIn(kid, self.entry(doc)["critical"])
        self.assertIn(kid, [f["id"] for f in self.entry(doc)["findings"]])
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, net=self.osv_down_net(),
                            now=dt.datetime(2026, 11, 21, 9, 0, tzinfo=UTC))
        self.assertIn(kid, self.entry(doc)["critical"])

    def test_os_end_of_life_is_checked_and_a_failed_lookup_is_info(self):
        doc, _ = self.check({"box-a": [ok(collector_doc())]})
        ids_ = [f["id"] for f in self.entry(doc)["findings"]]
        self.assertNotIn("os:eol", ids_)
        self.assertNotIn("info:os-eol-unavailable", ids_)
        shutil.rmtree(self.out / ".cache" / "vendors")
        net = FakeNet()
        net.os_eol = {"eol": "2026-05-31", "extendedSupport": "2036-04-25"}
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, net=net, now=LATER)
        e = self.entry(doc)
        self.assertIn("os:eol", e["critical"])
        finding = next(f for f in e["findings"] if f["id"] == "os:eol")
        self.assertIn("ubuntu 24.04", finding["text"])
        shutil.rmtree(self.out / ".cache" / "vendors")
        net.fetch = lambda url: (_ for _ in ()).throw(urllib.error.URLError("offline")) \
            if url.startswith(enrich.EOL_API) else FakeNet.fetch(net, url)
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, net=net, now=LATER)
        e = self.entry(doc)
        self.assertEqual(e["status"], "ok")
        self.assertNotIn("os:eol", e["critical"])
        self.assertIn("info:os-eol-unavailable", [f["id"] for f in e["findings"]])

    def test_unknown_host_name_is_an_error(self):
        with self.assertRaisesRegex(ValueError, "box-z"):
            self.check({"box-a": [ok(collector_doc())]}, names=["box-z"])


# --------------------------------------------------------------------------- noise and critical groups

class CriticalGroupTest(CheckCase):
    def baseline_run(self):
        doc, _ = self.check({"box-a": [ok(collector_doc())]})
        self.assertEqual(self.entry(doc)["critical"], [])

    def test_deploy_between_runs_is_quiet(self):
        self.baseline_run()
        sockets = section_text("sockets").replace("127.0.0.1:38211", "127.0.0.1:41999")
        logins = logins_text(login_line("2026-11-15T10:00:00+00:00", "198.51.100.77", DEPLOY_FP))
        doc, _ = self.check({"box-a": [ok(collector_doc(sockets=sockets, logins=logins, uu_log=FRESH_UU))]},
                            now=NEXT_WEEK)
        e = self.entry(doc)
        self.assertEqual(e["critical"], [])
        self.assertEqual(len([f for f in e["findings"] if f["group"] == "login"]), 1)

    def test_patch_week_is_quiet(self):
        self.baseline_run()
        dpkg = section_text("dpkg").replace("1.7.22-1", "1.7.23-1").replace("6.8.0-45", "6.8.0-50")
        units = section_text("units").replace("2b3d0a410473c30ec55ee353c51305df15d0ca6424853083a2dcd155df75a15f",
                                              "0" * 64)
        doc, _ = self.check({"box-a": [ok(collector_doc(dpkg=dpkg, units=units, kernel="6.8.0-50-generic\n",
                                                        reboot=(0, "linux-image-6.8.0-50-generic\n"),
                                                        uu_log=FRESH_UU))]}, now=NEXT_WEEK)
        e = self.entry(doc)
        self.assertEqual(e["critical"], [])
        explained = [f for f in e["findings"] if f["id"] == "change:units:~containerd.service"]
        self.assertFalse(explained[0]["critical"])
        base = store.read_baseline(self.out, "box-a")
        self.assertEqual(base["fingerprint"]["units"]["containerd.service"], "0" * 64)
        self.assertEqual(base["packages_seen"]["containerd.io"], "1.7.23-1")

    def test_kev_package_cleared_by_accept_until_review_by(self):
        net = kev_net()
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, net=net)
        kev_ids = [i for i in self.entry(doc)["critical"] if i.startswith("kev:")]
        self.assertIn(f"kev:{KEV_CVE}:openssl@3.0.13-0ubuntu3.4", kev_ids)
        finding = next(f for f in self.entry(doc)["findings"] if f["id"] == kev_ids[0])
        self.assertIn("fix", finding)      # osvhost's fix state is kept for the report
        self.assertEqual(self.entry(doc)["summary"]["kev"], len(kev_ids))
        for kid in kev_ids:
            self.accept(kid, review_by="2026-11-20")
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, net=net, now=LATER)
        self.assertEqual(self.entry(doc)["critical"], [])
        doc, _ = self.check({"box-a": [ok(collector_doc(uu_log="2026-11-21 06:25:11,402 INFO Starting unattended upgrades script\n"))]},
                            net=net, now=dt.datetime(2026, 11, 21, 9, 0, tzinfo=UTC))
        self.assertEqual(sorted(self.entry(doc)["critical"]), sorted(kev_ids))

    def test_unattended_upgrades_disabled_clears_only_when_fixed(self):
        self.baseline_run()
        off = section_text("apt_config").replace('APT::Periodic::Unattended-Upgrade "1";',
                                                  'APT::Periodic::Unattended-Upgrade "0";')
        doc, _ = self.check({"box-a": [ok(collector_doc(apt_config=off))]}, now=LATER)
        self.assertEqual(self.entry(doc)["critical"], ["patch:periodic-off"])
        with self.assertRaises(ValueError):
            self.accept("patch:periodic-off")
        doc, _ = self.check({"box-a": [ok(collector_doc(apt_config=off))]}, now=LATER)
        self.assertEqual(self.entry(doc)["critical"], ["patch:periodic-off"])
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, now=LATER)
        self.assertEqual(self.entry(doc)["critical"], [])

    def test_unknown_login_key_cleared_by_accept(self):
        self.baseline_run()
        unknown = "SHA256:UnknownKeyExample000000000000000000000000000"
        text = logins_text(login_line("2026-11-09T09:30:00+00:00", "203.0.113.66", unknown))
        doc, _ = self.check({"box-a": [ok(collector_doc(logins=text))]}, now=LATER)
        crit = self.entry(doc)["critical"]
        self.assertEqual(crit, [f"login:deploy/{unknown}"])
        # carried while open, even when the event is outside the next window
        doc, _ = self.check({"box-a": [ok(collector_doc(uu_log=FRESH_UU))]}, now=NEXT_WEEK)
        self.assertEqual(self.entry(doc)["critical"], crit)
        self.accept(crit[0], today=NEXT_WEEK.date())
        doc, _ = self.check({"box-a": [ok(collector_doc(uu_log=FRESH_UU))]}, now=NEXT_WEEK)
        self.assertEqual(self.entry(doc)["critical"], [])
        # the one decision covers later logins with the same key from another address
        later = logins_text(login_line("2026-11-16T09:30:00+00:00", "198.51.100.200", unknown))
        doc, _ = self.check({"box-a": [ok(collector_doc(logins=later, uu_log=FRESH_UU))]},
                            now=NEXT_WEEK + dt.timedelta(days=1))
        self.assertEqual(self.entry(doc)["critical"], [])

    def test_new_sudoers_rule_cleared_by_accept(self):
        self.baseline_run()
        sudoers = section_text("sudoers") + "/etc/sudoers.d/91-x\t" + "a" * 64 + "\tmallory\n"
        doc, _ = self.check({"box-a": [ok(collector_doc(sudoers=sudoers))]}, now=LATER)
        self.assertEqual(self.entry(doc)["critical"], ["change:sudoers:+/etc/sudoers.d/91-x"])
        self.accept("change:sudoers:+/etc/sudoers.d/91-x")
        doc, _ = self.check({"box-a": [ok(collector_doc(sudoers=sudoers))]}, now=LATER)
        self.assertEqual(self.entry(doc)["critical"], [])

    def test_new_lynis_warning_cleared_by_accept(self):
        self.baseline_run()
        lynis = section_text("lynis").replace("MTIME", "warning[]=AUTH-9999|Example new warning|-|-|\nMTIME")
        doc, _ = self.check({"box-a": [ok(collector_doc(lynis=lynis))]}, now=LATER)
        self.assertEqual(self.entry(doc)["critical"], ["lynis-warning:AUTH-9999"])
        self.accept("lynis-warning:AUTH-9999")
        doc, _ = self.check({"box-a": [ok(collector_doc(lynis=lynis))]}, now=LATER)
        self.assertEqual(self.entry(doc)["critical"], [])

    def test_decision_alone_does_not_clear_a_baseline_change(self):
        # a recorded decision whose baseline write never happened keeps the change open
        self.baseline_run()
        sudoers = section_text("sudoers") + "/etc/sudoers.d/91-x\t" + "a" * 64 + "\tmallory\n"
        self.check({"box-a": [ok(collector_doc(sudoers=sudoers))]}, now=LATER)
        base = (self.out / "hosts" / "baseline" / "box-a.json").read_text(encoding="utf-8")
        self.accept("change:sudoers:+/etc/sudoers.d/91-x")
        (self.out / "hosts" / "baseline" / "box-a.json").write_text(base, encoding="utf-8")
        doc, _ = self.check({"box-a": [ok(collector_doc(sudoers=sudoers))]}, now=LATER)
        self.assertEqual(self.entry(doc)["critical"], ["change:sudoers:+/etc/sudoers.d/91-x"])


# --------------------------------------------------------------------------- the run

class RunTest(CheckCase):
    def test_no_key_is_skipped_not_failed(self):
        self.check({"box-a": [ok(collector_doc())]})
        before = (self.out / store.HOSTS_JSON).read_bytes()
        run = FakeRun({"box-a": [ok(collector_doc())]})
        doc = hosts.check(self.cfg(key=self.out / "missing_key"), None, self.logs.append, run=run,
                          sleep=self.sleeps.append, fetch=self.net.fetch, post=self.net.post, now=LATER)
        self.assertEqual(doc["skipped"], "no audit key on this machine")
        self.assertEqual(run.calls, [])
        self.assertEqual((self.out / store.HOSTS_JSON).read_bytes(), before)
        self.assertEqual(doc["hosts"], json.loads(before)["hosts"])
        self.assertEqual(doc["last_checked"], "2026-11-09T09:00:00Z")

    def test_concurrency_bounded(self):
        servers = {f"box-{i}": config.HostOpts(address=f"203.0.113.{10 + i}") for i in range(9)}
        run = FakeRun({name: [ok(collector_doc())] for name in servers}, delay=0.05)
        doc, _ = self.check(None, cfg=self.cfg(servers, concurrency=4), run=run)
        self.assertEqual(len(run.ssh_calls()), 9)
        self.assertLessEqual(run.max_in_flight, 4)
        self.assertGreaterEqual(run.max_in_flight, 2)
        self.assertEqual({e["status"] for e in doc["hosts"].values()}, {"ok"})

    def test_check_never_writes_on_host(self):
        servers = {"box-a": config.HostOpts(address="203.0.113.10"), "box-b": config.HostOpts(address="box-b")}
        cfg = self.cfg(servers)
        refused = fail(255, b"ssh: connect to host box-b port 22: Connection timed out\n")
        run = FakeRun({"box-a": [ok(collector_doc())], "box-b": [refused]})
        self.check(None, cfg=cfg, run=run)
        expected = {tuple(transport.ssh_argv(cfg.hosts, name, h, self.out)) for name, h in servers.items()}
        for argv in run.calls:
            if argv[0] == "ssh-keygen":
                self.assertEqual(argv, ["ssh-keygen", "-lf", f"{self.key}.pub"])
                continue
            self.assertIn(tuple(argv), expected)
            self.assertEqual(argv[-1], "collect")

    def test_names_limit_the_run_and_keep_other_entries(self):
        servers = {"box-a": config.HostOpts(address="203.0.113.10"), "box-b": config.HostOpts(address="203.0.113.11")}
        cfg = self.cfg(servers)
        self.check({"box-a": [ok(collector_doc())], "box-b": [ok(collector_doc())]}, cfg=cfg)
        first_b = store.read(self.out)["hosts"]["box-b"]
        doc, run = self.check({"box-a": [ok(collector_doc())], "box-b": [ok(collector_doc())]}, cfg=cfg,
                              names=["box-a"], now=LATER)
        self.assertEqual([c[-2] for c in run.ssh_calls()], ["203.0.113.10"])
        self.assertEqual(doc["hosts"]["box-b"], first_b)
        self.assertEqual(doc["hosts"]["box-a"]["checked_at"], "2026-11-09T10:00:00Z")

    def test_read_reexported(self):
        self.check({"box-a": [ok(collector_doc())]})
        self.assertEqual(hosts.read(self.out)["hosts"]["box-a"]["status"], "ok")
        self.assertEqual((hosts.HOSTS_JSON, hosts.HOSTS_MD), ("hosts.json", "HOSTS.md"))
        self.assertIs(hosts.check, checker.check)


class EpssCheckTest(CheckCase):
    """EPSS scores on host findings: information only; the step needs `fetch_bytes` when `fetch` is injected."""
    SCORES = {KEV_CVE: (0.9144, 0.999), "CVE-2024-13176": (0.05, 0.9)}

    def scored_net(self) -> FakeNet:
        net = kev_net()
        net.vulns[("openssl", "3.0.13-0ubuntu3.4")] = ["UBUNTU-CVE-2024-9143", "UBUNTU-CVE-2024-13176"]
        return net

    def epss_check(self, fetch_bytes, now=NOW, cfg=None):
        net = self.scored_net()
        return hosts.check(cfg or self.cfg(), None, self.logs.append, run=FakeRun({"box-a": [ok(collector_doc())]}),
                           sleep=self.sleeps.append, fetch=net.fetch, post=net.post, now=now,
                           fetch_bytes=fetch_bytes)

    def test_check_with_epss_scores(self):
        fetch_bytes = epss_fetch(epss_gz(self.SCORES))
        doc = self.epss_check(fetch_bytes)
        self.assertEqual(doc["epss"], {"available": True, "score_date": "2026-11-23T12:00:23Z"})
        self.assertEqual(fetch_bytes.calls, [epss.EPSS_URL])          # the whole file; nothing about the host
        by_id = {f["id"]: f for f in self.entry(doc)["findings"]}
        kev = by_id["kev:CVE-2024-9143:openssl@3.0.13-0ubuntu3.4"]
        self.assertEqual((kev["epss"], kev["epss_percentile"]), (0.9144, 0.999))
        self.assertEqual(by_id["vuln:openssl@3.0.13-0ubuntu3.4"]["max_epss"], 0.05)
        self.assertEqual(by_id["vuln:openssl@3.0.13-0ubuntu3.4"]["max_epss_cve"], "CVE-2024-13176")
        self.assertEqual(store.read(self.out)["epss"], doc["epss"])
        self.assertTrue((self.out / ".cache" / "enrich" / epss.CACHE_FILE).exists())   # shared with the audit

    def test_check_with_epss_outage_adds_no_finding(self):
        without = self.epss_check(None)
        shutil.rmtree(self.out)
        self.out.mkdir()
        doc = self.epss_check(epss_fetch(OSError("down")))
        self.assertEqual(doc["epss"], {"available": False, "score_date": None})
        got, before = self.entry(doc), self.entry(without)
        self.assertEqual([(f["id"], f["critical"]) for f in got["findings"]],
                         [(f["id"], f["critical"]) for f in before["findings"]])
        self.assertEqual(got["critical"], before["critical"])
        self.assertEqual(got["status"], "ok")
        self.assertFalse(any(f["id"].startswith("section-failed:") for f in got["findings"]))
        self.assertEqual([f["text"] for f in got["findings"]], [f["text"] for f in before["findings"]])

    def test_check_without_fetch_bytes_has_no_epss(self):
        doc = self.epss_check(None)
        self.assertNotIn("epss", doc)
        self.assertNotIn("epss", store.read(self.out))
        for f in self.entry(doc)["findings"]:
            self.assertFalse({"epss", "epss_percentile", "max_epss", "max_epss_cve"} & set(f), f["id"])

    def test_epss_disabled_skips_the_download(self):
        cfg = self.cfg()
        cfg = dataclasses.replace(cfg, epss=dataclasses.replace(cfg.epss, enabled=False))
        fetch_bytes = epss_fetch(epss_gz(self.SCORES))
        doc = self.epss_check(fetch_bytes, cfg=cfg)
        self.assertNotIn("epss", doc)
        self.assertEqual(fetch_bytes.calls, [])

    def test_changed_scores_are_not_a_change_between_checks(self):
        first = self.epss_check(epss_fetch(epss_gz(self.SCORES)))
        before = status.build(status.empty_report(), secrets=None, previous=None, duration_s=1, exit_code=0,
                              run_host="mac", mode="full", hosts=first)
        shutil.rmtree(self.out / ".cache" / "enrich")                # a new day's file with other scores
        doc = self.epss_check(epss_fetch(epss_gz({KEV_CVE: (0.2, 0.5)}, score_date="2026-11-24T12:00:00Z")),
                              now=LATER)
        kev = next(f for f in self.entry(doc)["findings"] if f["id"].startswith("kev:"))
        self.assertEqual(kev["epss"], 0.2)
        self.assertEqual(self.entry(doc)["critical"], self.entry(first)["critical"])
        after = status.refresh_hosts(before, doc)
        self.assertEqual((after["deltas"]["hosts_critical"]["new"], after["deltas"]["hosts_critical"]["resolved"]),
                         ([], []))

    def test_failed_host_keeps_the_scores_of_its_last_check(self):
        first = self.epss_check(epss_fetch(epss_gz(self.SCORES)))
        net = self.scored_net()
        doc = hosts.check(self.cfg(), None, self.logs.append,
                          run=FakeRun({"box-a": [fail(1, b"sudo: a password is required\n")]}),
                          sleep=self.sleeps.append, fetch=net.fetch, post=net.post, now=LATER,
                          fetch_bytes=epss_fetch(OSError("down")))
        self.assertEqual(self.entry(doc)["status"], "failed")
        self.assertEqual(self.entry(doc)["findings"], self.entry(first)["findings"])


# --------------------------------------------------------------------------- review fix round 1

PIN = ["203.0.113.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleHostKeyOne000000000000000000000000"]
REPIN = ["203.0.113.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleHostKeyTwo000000000000000000000000"]
NOT_KNOWN = (b"No RSA host key is known for sbom-audit-box-a and you have requested strict checking.\r\n"
             b"Host key verification failed.\r\n")


class FixRoundOneTest(CheckCase):
    def test_osv_down_is_critical_and_not_acceptable(self):
        net = FakeNet()

        def down(url, body):
            raise urllib.error.URLError("osv.dev unreachable")
        net.post = down
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, net=net)
        e = self.entry(doc)
        self.assertTrue(e["critical"])
        self.assertIn("section-failed:osv", e["critical"])
        with self.assertRaises(ValueError):
            self.accept("section-failed:osv")

    def test_osv_record_fetch_failure_is_critical(self):
        net = kev_net()
        net.records = {}
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, net=net)
        self.assertIn("section-failed:osv", self.entry(doc)["critical"])

    def test_osv_unsupported_stays_info(self):
        trixie = "ID=debian\nVERSION_CODENAME=trixie\n"
        doc, _ = self.check({"box-a": [ok(collector_doc(os=trixie))]})
        self.assertNotIn("section-failed:osv", self.entry(doc)["critical"])

    def test_host_key_change_persists_until_repinned(self):
        store.pin_host_keys(self.out, "box-a", PIN)
        self.check({"box-a": [ok(collector_doc())]})
        doc, _ = self.check({"box-a": [fail(255, CHANGED)]}, now=LATER)
        self.assertEqual(self.entry(doc)["critical"], ["hostkey:changed"])
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, now=LATER)
        e = self.entry(doc)
        self.assertEqual(e["status"], "ok")
        self.assertIn("hostkey:changed", e["critical"])
        self.assertTrue(e["known_hosts_sha"])
        store.pin_host_keys(self.out, "box-a", REPIN)
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, now=LATER)
        self.assertNotIn("hostkey:changed", self.entry(doc)["critical"])
        self.assertNotEqual(self.entry(doc)["known_hosts_sha"], e["known_hosts_sha"])

    def test_host_key_change_carried_on_unsupported_os(self):
        alpine = "ID=alpine\nVERSION_ID=3.20.3\n"
        self.check({"box-a": [fail(255, CHANGED)]})
        doc, _ = self.check({"box-a": [ok(collector_doc(os=alpine))]}, now=LATER)
        e = self.entry(doc)
        self.assertEqual((e["status"], e["critical"]), ("unsupported", ["hostkey:changed"]))

    def test_lynis_failure_after_a_working_baseline_is_critical(self):
        self.check({"box-a": [ok(collector_doc())]})
        self.assertEqual(store.read_baseline(self.out, "box-a")["lynis"]["index"], 72)
        doc, _ = self.check({"box-a": [ok(collector_doc(lynis=(124, "")))]}, now=LATER)
        e = self.entry(doc)
        self.assertEqual(e["status"], "ok")
        self.assertIn("section-failed:lynis", e["critical"])
        self.assertEqual(store.read_baseline(self.out, "box-a")["lynis"]["index"], 72)

    def test_lynis_not_installed_without_baseline_index_is_info(self):
        doc, _ = self.check({"box-a": [ok(collector_doc(lynis=(127, "")))]})
        self.assertEqual(self.entry(doc)["critical"], [])

    def test_stdout_never_becomes_error_detail(self):
        leak = fail(1, b"", stdout=b'{"collector": "1", "sections": {"apt_sources": "user:s3cretpass@x"}}')
        doc, _ = self.check({"box-a": [leak]})
        e = self.entry(doc)
        self.assertEqual(e["status"], "failed")
        self.assertNotIn("s3cretpass", e["error"])
        self.assertIn("exit 1", e["error"])

    def test_unknown_key_type_with_pinned_alias_is_changed(self):
        argv = transport.ssh_argv(self.cfg().hosts, "box-a", self.cfg().hosts.servers["box-a"], self.out)
        res = transport.collect(argv, 600, run=FakeRun({"box-a": [fail(255, NOT_KNOWN)]}),
                                sleep=self.sleeps.append, pinned=True)
        self.assertTrue(res.host_key_changed)
        store.pin_host_keys(self.out, "box-a", PIN)
        doc, _ = self.check({"box-a": [fail(255, NOT_KNOWN)]})
        self.assertEqual(self.entry(doc)["critical"], ["hostkey:changed"])
        self.assertEqual(self.sleeps, [])

    def test_unexpected_parse_error_fails_only_that_host(self):
        servers = {"box-a": config.HostOpts(address="203.0.113.10"), "box-b": config.HostOpts(address="203.0.113.11")}
        real = parse.parse
        calls = []

        def flaky(doc):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("parser bug")
            return real(doc)
        with mock.patch.object(parse, "parse", flaky):
            doc, _ = self.check({"box-a": [ok(collector_doc())], "box-b": [ok(collector_doc())]},
                                cfg=self.cfg(servers))
        self.assertEqual(sorted(e["status"] for e in doc["hosts"].values()), ["failed", "ok"])
        self.assertTrue((self.out / store.HOSTS_JSON).exists())

    def test_collection_crash_text_is_capped_to_one_line(self):
        long_text = "first line " + "x" * 1000 + "\nsecond line /home/x/.ssh/audit-key"
        with mock.patch.object(transport, "collect", side_effect=RuntimeError(long_text)):
            doc, _ = self.check({"box-a": [ok(collector_doc())]})
        error = self.entry(doc)["error"]
        self.assertEqual(self.entry(doc)["status"], "failed")
        self.assertTrue(error.startswith("collection failed: RuntimeError: first line"))
        self.assertLessEqual(len(error), len("collection failed: RuntimeError: ") + transport.MAX_ERROR)
        self.assertNotIn("second line", error)
        self.assertNotIn("audit-key", error)

    def test_store_helpers_are_public(self):
        self.assertEqual(store.check_host("box-a"), "box-a")
        self.assertEqual(store.baseline_path(self.out, "box-a"), self.out / "hosts" / "baseline" / "box-a.json")
        self.assertEqual(store.RECORD_ONLY, ("login:", "origin:", "kev:"))


# --------------------------------------------------------------------------- review fix round 2

class FixRoundTwoTest(CheckCase):
    def two_hosts(self):
        return self.cfg({"box-a": config.HostOpts(address="203.0.113.10"),
                         "box-b": config.HostOpts(address="203.0.113.11")})

    def test_osv_empty_answer_on_a_supported_lts_is_critical(self):
        net = FakeNet()
        net.post = lambda url, body: {"results": [{} for _ in body["queries"]]}
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, net=net)
        e = self.entry(doc)
        self.assertEqual(e["status"], "ok")
        self.assertIn("section-failed:osv", e["critical"])
        self.assertNotIn("vuln:unavailable", [f["id"] for f in e["findings"]])

    def test_osv_unsupported_ecosystem_is_the_info_finding(self):
        doc, _ = self.check({"box-a": [ok(collector_doc(os="ID=debian\nVERSION_CODENAME=trixie\n"))]})
        [f] = [f for f in self.entry(doc)["findings"] if f["id"] == "vuln:unavailable"]
        self.assertFalse(f["critical"])

    def test_repin_of_the_same_key_clears_hostkey_changed(self):
        store.pin_host_keys(self.out, "box-a", PIN, now=NOW)
        self.check({"box-a": [ok(collector_doc())]})
        doc, _ = self.check({"box-a": [fail(255, CHANGED)]}, now=LATER)
        self.assertEqual(self.entry(doc)["critical"], ["hostkey:changed"])
        store.pin_host_keys(self.out, "box-a", PIN, now=NEXT_WEEK)
        doc, _ = self.check({"box-a": [ok(collector_doc(uu_log=FRESH_UU))]}, now=NEXT_WEEK)
        self.assertNotIn("hostkey:changed", self.entry(doc)["critical"])

    def test_pin_writes_one_comment_line_per_host(self):
        store.pin_host_keys(self.out, "box-a", PIN, now=NOW)
        store.pin_host_keys(self.out, "box-b", REPIN, now=NOW)
        store.pin_host_keys(self.out, "box-a", PIN, now=NEXT_WEEK)
        lines = (self.out / store.KNOWN_HOSTS).read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines, ["# sbom-audit-box-b pinned 2026-11-09T09:00:00.000000Z",
                                 "sbom-audit-box-b " + REPIN[0].split(" ", 1)[1],
                                 "# sbom-audit-box-a pinned 2026-11-16T09:00:00.000000Z",
                                 "sbom-audit-box-a " + PIN[0].split(" ", 1)[1]])

    def test_repin_within_the_same_second_still_clears(self):
        store.pin_host_keys(self.out, "box-a", PIN, now=NOW)
        self.check({"box-a": [fail(255, CHANGED)]})
        store.pin_host_keys(self.out, "box-a", PIN, now=NOW + dt.timedelta(microseconds=1))
        doc, _ = self.check({"box-a": [ok(collector_doc())]}, now=LATER)
        self.assertNotIn("hostkey:changed", self.entry(doc)["critical"])

    def test_hostkey_finding_without_a_stored_sha_is_carried(self):
        store.pin_host_keys(self.out, "box-a", PIN, now=NOW)
        self.check({"box-a": [ok(collector_doc())]})
        self.check({"box-a": [fail(255, CHANGED)]}, now=LATER)
        d = store.read(self.out)
        for f in d["hosts"]["box-a"]["findings"]:
            f.pop("known_hosts_sha", None)
        store.write(self.out, d)
        doc, _ = self.check({"box-a": [ok(collector_doc(uu_log=FRESH_UU))]}, now=NEXT_WEEK)
        self.assertIn("hostkey:changed", self.entry(doc)["critical"])
        doc, _ = self.check({"box-a": [fail(255, CHANGED)]}, now=NEXT_WEEK)
        self.assertEqual(self.entry(doc)["critical"].count("hostkey:changed"), 1)
        store.pin_host_keys(self.out, "box-a", PIN, now=NEXT_WEEK + dt.timedelta(hours=1))
        doc, _ = self.check({"box-a": [ok(collector_doc(uu_log=FRESH_UU))]}, now=NEXT_WEEK + dt.timedelta(hours=1))
        self.assertNotIn("hostkey:changed", self.entry(doc)["critical"])   # carried with the hash it had then

    def test_removed_pin_is_not_a_repin(self):
        store.pin_host_keys(self.out, "box-a", PIN, now=NOW)
        self.check({"box-a": [ok(collector_doc())]})
        self.check({"box-a": [fail(255, CHANGED)]}, now=LATER)
        (self.out / store.KNOWN_HOSTS).unlink()
        doc, _ = self.check({"box-a": [fail(255, NOT_KNOWN)]}, now=NEXT_WEEK)
        self.assertIn("hostkey:changed", self.entry(doc)["critical"])

    def test_undecodable_known_hosts_line_fails_only_that_host(self):
        store.pin_host_keys(self.out, "box-a", PIN, now=NOW)
        path = self.out / store.KNOWN_HOSTS
        path.write_bytes(path.read_bytes() + b"sbom-audit-box-b ssh-ed25519 AAAA\xff\xfe\n")
        doc, run = self.check({"box-a": [ok(collector_doc())], "box-b": [ok(collector_doc())]}, cfg=self.two_hosts())
        a, b = self.entry(doc, "box-a"), self.entry(doc, "box-b")
        self.assertEqual(a["status"], "ok")
        self.assertEqual((b["status"], b["error"]), ("failed", "known_hosts unreadable"))
        self.assertEqual(len(run.ssh_calls()), 1)
        self.assertTrue((self.out / store.HOSTS_JSON).exists())

    def test_unreadable_known_hosts_does_not_abort_the_run(self):
        (self.out / store.KNOWN_HOSTS).mkdir(parents=True)   # a directory: IsADirectoryError
        doc, run = self.check({"box-a": [], "box-b": []}, cfg=self.two_hosts())
        self.assertEqual({e["status"] for e in doc["hosts"].values()}, {"failed"})
        self.assertEqual({e["error"] for e in doc["hosts"].values()}, {"known_hosts unreadable"})
        self.assertEqual(run.ssh_calls(), [])

    def test_missing_lynis_section_gives_one_section_failed_id(self):
        self.check({"box-a": [ok(collector_doc())]})
        d = collector_doc()
        d["sections"].pop("lynis")
        doc, _ = self.check({"box-a": [ok(d)]}, now=LATER)
        ids = [f["id"] for f in self.entry(doc)["findings"]]
        self.assertEqual(ids.count("section-failed:lynis"), 1)
        self.assertEqual(len(ids), len(set(ids)))


if __name__ == "__main__":
    unittest.main()
