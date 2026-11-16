"""The collector script itself: static read-only checks, and a real run in Docker when it is available."""
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import unittest

from pathlib import Path

from sbomaudit.hosts import parse

SCRIPT = parse.COLLECT_SH
PROFILE = SCRIPT.parent / "lynis.prf"


def _code_lines() -> list[str]:
    """collect.sh without comment lines (the header explains the rules and names what it never reads)."""
    return [line for line in SCRIPT.read_text().splitlines() if not line.lstrip().startswith("#")]


def _shell_code() -> tuple[str, list[str]]:
    """(code with every single-quoted span blanked, the single-quoted spans): awk programs live in quotes."""
    code = "\n".join(_code_lines())
    return re.sub(r"'[^']*'", "''", code), re.findall(r"'[^']*'", code)


def _logins_awk() -> str:
    m = re.search(r"""awk -v year="\$\(date \+%Y\)" -v month="\$\(date \+%m\)" '([^']*)'""", SCRIPT.read_text())
    assert m, "logins awk program not found"
    return m.group(1)


def _docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


class CollectorTextTests(unittest.TestCase):
    def test_shipped_version_matches_script(self):
        m = re.search(r"^COLLECTOR_VERSION=(\S+)$", SCRIPT.read_text(), re.M)
        self.assertIsNotNone(m)
        self.assertEqual(parse.SHIPPED_VERSION, m.group(1))

    def test_collector_is_posix_sh(self):
        self.assertTrue(SCRIPT.read_text().startswith("#!/bin/sh\n"))
        self.assertEqual(subprocess.run(["sh", "-n", str(SCRIPT)], capture_output=True).returncode, 0)
        # sh is bash on macOS: the strict checks run when the tools exist
        for tool in (["dash", "-n"], ["checkbashisms"]):
            with self.subTest(tool=tool[0]):
                if not shutil.which(tool[0]):
                    self.skipTest(f"{tool[0]} not installed")
                run = subprocess.run([*tool, str(SCRIPT)], capture_output=True, text=True)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_sections_match_parser(self):
        names = re.findall(r"^\s*run (\w+) s_\w+", SCRIPT.read_text(), re.M)
        self.assertEqual(tuple(names), parse.SECTIONS)

    def test_collector_text_has_no_secret_reads(self):
        code = "\n".join(_code_lines())
        self.assertNotIn(".env", code)
        self.assertNotIn("/opt/", code)
        self.assertNotIn("mktemp", code)
        for word in ("tee", "touch", "rm", "mv", "cp", "install", "dd", "truncate", "mkdir", "ln"):
            self.assertIsNone(re.search(rf"(^|[\s;|&(]){word}\s", code, re.M), word)
        self.assertNotIn("sed -i", code)
        for m in re.finditer(r"/home/\S*", code):
            self.assertIn(".ssh/authorized_keys", m.group(0))
        for m in re.finditer(r"ssh_host_\S*", code):
            self.assertIn(".pub", m.group(0))  # private host keys are never touched
        shell, quoted = _shell_code()  # in awk programs `>` is a comparison
        for m in re.finditer(r"(?<![<&])[0-9]*>>?\|?\s*([^\s;)|]+)", shell):  # also fd-prefixed: 2>/tmp/x
            self.assertIn(m.group(1), ("/dev/null", "&1", "&2"), m.group(0))  # no file is ever written
        for program in quoted:
            self.assertIsNone(re.search(r'>>|>\s*"|[^"\s]\s*\|\s*"|system\(|getline', program), program[:80])

    def test_collector_has_no_side_effect_commands(self):
        shell, _ = _shell_code()
        for pattern in (r"apt(-get)?\s+(-\S+\s+)*(update|upgrade|install|remove|purge|autoremove|clean)\b",
                        r"systemctl\s+(start|restart|stop|enable|disable|reload|mask|unmask|daemon-reload)\b",
                        r"journalctl\b[^\n]*--(vacuum|rotate|flush)", r"\bufw\s+(enable|disable|reset|allow|deny|delete)\b",
                        r"\bip6?tables\s+(-\S+\s+)*-[AFPIDXNZRE]\b", r"\bdpkg\s+(-i|--configure|--purge|-r)\b"):
            with self.subTest(pattern=pattern):
                self.assertIsNone(re.search(pattern, shell), pattern)

    def test_apt_runs_without_binary_caches(self):
        # as root, apt and apt-cache would rebuild /var/cache/apt/pkgcache.bin and srcpkgcache.bin
        shell, _ = _shell_code()
        calls = re.findall(r"^.*\bt apt(?:-cache)? .*$", shell, re.M)
        self.assertEqual(len(calls), 3, calls)
        for call in calls:
            self.assertIn("-o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache=", call)

    def test_every_timeout_kills(self):
        shell, _ = _shell_code()
        uses = re.findall(r"\btimeout\s+(\S+)", shell)
        self.assertTrue(uses)
        self.assertEqual(set(uses), {"-k"})

    def test_logins_awk_classifies_by_sshd_message(self):
        lines = [
            "2026-11-08T09:14:22+00:00 box-a sshd[40211]: Accepted publickey for deploy from 203.0.113.7 port 51544 "
            "ssh2: ED25519 SHA256:DJAtqSefbS0x0aOApnlCyNKOglphGM2PMe8HI0T09m8",
            # a client-chosen user name that reads like a login
            "2026-11-08T09:20:00+00:00 box-a sshd[41000]: Invalid user x Accepted publickey for root from "
            "203.0.113.66 port 1 ssh2: ED25519 SHA256:forged from 203.0.113.50 port 50000",
            "2026-11-08T09:21:00+00:00 box-a sshd-session[41001]: Failed password for invalid user x Accepted "
            "publickey for root from 203.0.113.66 port 1 ssh2: ED25519 SHA256:forged from 203.0.113.50 port 50001",
            "2026-11-08T09:22:00+00:00 box-a cron[1]: Accepted publickey for root from 203.0.113.66 port 1 ssh2",
        ]
        awks = [a for a in ("awk", "mawk", "gawk", "busybox") if shutil.which(a)]
        for awk in awks:
            with self.subTest(awk=awk):
                cmd = [awk] + (["awk"] if awk == "busybox" else []) + ["-v", "year=2026", "-v", "month=11",
                                                                         _logins_awk()]
                out = subprocess.run(cmd, input="\n".join(lines) + "\n", capture_output=True, text=True,
                                     check=True).stdout.splitlines()
                self.assertEqual([line for line in out if line.startswith("A\t")], ["A\t" + lines[0]])
                self.assertEqual(sorted(line for line in out if line.startswith("F\t")),
                                 ["F\t2026-11-08T09\t203.0.113.50\t2"])

    def run_logins_awk(self, lines: list[str]) -> list[str]:
        awks = [a for a in ("awk", "mawk", "gawk", "busybox") if shutil.which(a)]
        self.assertTrue(awks)
        results = []
        for awk in awks:
            cmd = [awk] + (["awk"] if awk == "busybox" else []) + ["-v", "year=2026", "-v", "month=11",
                                                                     _logins_awk()]
            out = subprocess.run(cmd, input="\n".join(lines) + "\n", capture_output=True, text=True,
                                 check=True).stdout.splitlines()
            results.append(sorted(line for line in out if line.startswith("F\t")))
        self.assertTrue(all(r == results[0] for r in results), results)
        return results[0]

    def test_logins_awk_counts_each_attempt_once(self):
        ip = "203.0.113.50"
        t = "2026-11-08T09:20:30+00:00 box-a sshd[%d]: %s"
        lines = [
            # one connection: "Invalid user" once, then one "Failed" per password attempt -> 3
            t % (500, f"Invalid user admin from {ip} port 5001"),
            t % (500, f"Failed password for invalid user admin from {ip} port 5001 ssh2"),
            t % (500, f"Failed password for invalid user admin from {ip} port 5001 ssh2"),
            t % (500, f"Failed password for invalid user admin from {ip} port 5001 ssh2"),
            # a probe that leaves before authenticating -> 1
            t % (501, f"Invalid user oracle from {ip} port 5002"),
            t % (501, f"Connection closed by invalid user oracle {ip} port 5002 [preauth]"),
            # an existing user -> 1
            t % (502, f"Failed password for root from {ip} port 5003 ssh2"),
        ]
        self.assertEqual(self.run_logins_awk(lines), [f"F\t2026-11-08T09\t{ip}\t5"])
        # the order of a connection's lines does not matter
        self.assertEqual(self.run_logins_awk(lines[::-1]), [f"F\t2026-11-08T09\t{ip}\t5"])

    def test_logins_awk_invalid_user_counts_per_connection_and_hour(self):
        ip = "203.0.113.51"
        lines = [
            f"2026-11-08T09:59:59+00:00 box-a sshd[600]: Invalid user a from {ip} port 1",
            f"2026-11-08T10:00:01+00:00 box-a sshd[600]: Failed password for invalid user a from {ip} port 1 ssh2",
        ]
        # same pid, different hours: the hour is part of the connection key, so each hour counts 1
        self.assertEqual(self.run_logins_awk(lines),
                         [f"F\t2026-11-08T09\t{ip}\t1", f"F\t2026-11-08T10\t{ip}\t1"])

    def test_logins_awk_failed_text_in_user_name_is_not_a_failure(self):
        lines = ["2026-11-08T09:20:30+00:00 box-a sshd[700]: Connection from 203.0.113.52 port 1 on 198.51.100.1 "
                 "port 22 Failed password for invalid user x from 203.0.113.52 port 1"]
        self.assertEqual(self.run_logins_awk(lines), [])

    def test_lynis_runs_only_with_profile(self):
        code = "\n".join(_code_lines())
        runs = re.findall(r"^.*lynis audit system.*$", code, re.M)
        self.assertEqual(len(runs), 1, runs)
        self.assertIn('--profile "$LYNIS_PROFILE"', runs[0])
        self.assertRegex(code, r'\[ -f "\$LYNIS_PROFILE" \] \|\| \{ echo "lynis: profile missing"; return 127; \}')

    def test_lynis_profile_skips_tests(self):
        lines = PROFILE.read_text().splitlines()
        self.assertTrue(any(re.fullmatch(r"skip-test=[A-Z]+-\d{4}", line) for line in lines))
        self.assertIn("refresh-repositories=no", lines)  # else PKGS-7392 runs `apt-get update` (a host write)
        self.assertTrue(all(line.startswith(("#", "skip-test=")) or line in ("refresh-repositories=no", "")
                            for line in lines))
        self.assertRegex(PROFILE.read_text(), r"# Measured \d{4}-\d{2}-\d{2}, Lynis [0-9.]+ in the [a-z0-9.:]+ "
                                              r"container: \d+ s without this profile, \d+ s with")


def _function(name: str) -> str:
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", SCRIPT.read_text(), re.M | re.S)
    assert m, f"{name} not found"
    return m.group(0)


class ContainersSectionTests(unittest.TestCase):
    """s_containers with stubbed pgrep, ps and docker: the system daemon and rootless ones per user."""

    # a rootless socket must be owned by its uid: the test user's own, or 1000 (chowned) when run as root
    UID = os.getuid() if hasattr(os, "getuid") and os.getuid() != 0 else 1000
    SYSTEM = r"docker ps --format {{.Names}}\t{{.Ports}}"

    def setUp(self):
        # short path: a unix socket path is capped at ~104 bytes on macOS
        self.run_dir = Path(tempfile.mkdtemp(prefix="sa", dir="/tmp" if Path("/tmp").is_dir() else None))
        self.addCleanup(shutil.rmtree, self.run_dir, True)

    def socket_for(self, uid: int) -> Path:
        (self.run_dir / str(uid)).mkdir()
        path = self.run_dir / str(uid) / "docker.sock"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(path))
        self.addCleanup(sock.close)
        if uid == self.UID and hasattr(os, "getuid") and os.getuid() == 0:
            os.chown(path, uid, -1)
        return path

    def rootless(self, uid: int) -> str:
        return f"uid{uid}/docker -H unix://{self.run_dir}/{uid}/docker.sock ps --format {{{{.Names}}}}\\t{{{{.Ports}}}}"

    def run_section(self, pgrep: str, uids: dict[str, str] | None = None, docker_rc: int = 0,
                    have_pgrep: bool = True, ns: dict[str, str] | None = None,
                    rootless_out: str = "", docker_stub: str = "") -> tuple[int, list[str]]:
        """pgrep: the stub's body; uids: pid -> uid for `ps -o uid= -p <pid>`; ns: pid -> PID namespace
        (default: the host's, pid:[1]); rootless_out: extra printf text a `docker -H` call returns;
        docker_stub: a whole `docker()` definition replacing the default one.
        Returns (rc, output lines)."""
        uids = uids or {}
        proc = self.run_dir / "proc"
        shutil.rmtree(proc, ignore_errors=True)  # fresh per call
        for pid in ["1", *uids]:
            (proc / pid / "ns").mkdir(parents=True, exist_ok=True)
            os.symlink((ns or {}).get(pid, "pid:[1]"), proc / pid / "ns" / "pid")
        ps_cases = "".join(f'{pid}) echo " {uid}" ;; ' for pid, uid in uids.items())
        docker_stub = docker_stub or (f"""docker() {{ printf '%s\\n' "docker $*"; [ "$1" = -H ] && printf '{rootless_out}';"""
                                      f" return {docker_rc}; }}")
        stubs = f"""
t() {{ "$@"; }}
have() {{ [ "$1" = pgrep ] && return {0 if have_pgrep else 1}; [ "$1" = docker ] && return 0; return 1; }}
pgrep() {{ {pgrep} }}
ps() {{ eval "pid=\\${{$#}}"; case $pid in {ps_cases}*) return 1 ;; esac; }}
{docker_stub}
USER_RUN={self.run_dir}
PROC={proc}
"""
        script = stubs + _function("s_containers") + 's_containers; echo "rc=$?"\n'
        results = []
        for shell in [s for s in ("sh", "dash") if shutil.which(s)]:  # sh is bash on macOS
            out = subprocess.run([shell, "-c", script], capture_output=True, text=True, timeout=30).stdout.splitlines()
            self.assertTrue(out and out[-1].startswith("rc="), (shell, out))
            results.append((int(out[-1][3:]), out[:-1]))
        self.assertTrue(results and all(r == results[0] for r in results), results)
        return results[0]

    def test_no_daemon_is_an_empty_list(self):
        # docker installed, no dockerd running (a masked unit with a stale /var/run/docker.sock)
        self.assertEqual(self.run_section("return 1;"), (0, []))

    def test_system_daemon(self):
        self.assertEqual(self.run_section("echo 10; return 0;", {"10": "0"}), (0, [self.SYSTEM]))

    def test_rootless_daemon_is_listed_through_its_socket(self):
        self.socket_for(self.UID)
        self.assertEqual(self.run_section("echo 10; echo 20; return 0;", {"10": "0", "20": str(self.UID)}),
                         (0, [self.SYSTEM, self.rootless(self.UID)]))

    def test_every_rootless_line_is_prefixed(self):
        # a user's daemon returning a name with a newline must not produce an unprefixed (root) entry
        self.socket_for(self.UID)
        rc, out = self.run_section("echo 20; return 0;", {"20": str(self.UID)}, rootless_out=r"x\nweb\t127.0.0.1:8080\n")
        self.assertEqual(rc, 0)
        self.assertEqual(out, [self.rootless(self.UID), f"uid{self.UID}/x", f"uid{self.UID}/web\t127.0.0.1:8080"])

    def test_rootless_daemon_without_socket_fails(self):
        rc, out = self.run_section("echo 20; return 0;", {"20": "1000"})
        self.assertNotEqual(rc, 0)
        self.assertEqual(out, [f"docker: rootless daemon of uid 1000 has no socket of its own at {self.run_dir}/1000/docker.sock"])

    def test_socket_of_another_owner_or_a_symlink_is_refused(self):
        other = self.UID + 1
        self.socket_for(other)  # owned by the test user, not by uid `other`
        mine = self.socket_for(self.UID)
        (self.run_dir / "s").mkdir()
        os.rename(mine, self.run_dir / "s" / "docker.sock")
        os.symlink(self.run_dir / "s" / "docker.sock", mine)  # a symlink to a socket the uid does own
        for uid in (other, self.UID):
            with self.subTest(uid=uid):
                rc, out = self.run_section("echo 20; return 0;", {"20": str(uid)})
                self.assertEqual(rc, 1)
                self.assertEqual(out, [f"docker: rootless daemon of uid {uid} has no socket of its own at {self.run_dir}/{uid}/docker.sock"])

    def test_rootless_errors_are_prefixed_too(self):
        self.socket_for(self.UID)
        script_docker = "docker() { echo 'boom'; printf 'web\\t127.0.0.1:8080\\n' >&2; return 0; }"
        rc, out = self.run_section("echo 20; return 0;", {"20": str(self.UID)}, docker_stub=script_docker)
        self.assertEqual((rc, out), (0, [f"uid{self.UID}/boom", f"uid{self.UID}/web\t127.0.0.1:8080"]))

    def test_probes_run_under_the_timeout(self):
        body = _function("s_containers")
        self.assertIn("$(t pgrep -x dockerd)", body)
        self.assertIn("t ps -o uid= -p", body)

    def test_dockerd_in_another_pid_namespace_is_skipped(self):
        # a dockerd inside an unprivileged LXC guest shows up with a mapped uid and no socket here
        self.assertEqual(self.run_section("echo 10; echo 30; return 0;", {"10": "0", "30": "100000"},
                                          ns={"30": "pid:[2]"}), (0, [self.SYSTEM]))

    def test_one_daemon_per_uid(self):
        self.assertEqual(self.run_section("echo 10; echo 11; return 0;", {"10": "0", "11": "0"}), (0, [self.SYSTEM]))

    def test_failing_docker_ps_still_fails(self):
        self.assertEqual(self.run_section("echo 10; return 0;", {"10": "0"}, docker_rc=1), (1, [self.SYSTEM]))
        self.socket_for(self.UID)
        self.assertEqual(self.run_section("echo 20; return 0;", {"20": str(self.UID)}, docker_rc=2),
                         (2, [self.rootless(self.UID)]))

    def test_without_pgrep_the_system_daemon_is_asked(self):
        self.assertEqual(self.run_section("return 1;", have_pgrep=False), (0, [self.SYSTEM]))
        self.assertEqual(self.run_section("return 3;"), (0, [self.SYSTEM]))  # pgrep error: same fallback
        self.assertEqual(self.run_section("return 124;"), (0, [self.SYSTEM]))  # pgrep timed out: same


class TrustedBinaryTests(unittest.TestCase):
    """s_binaries runs a binary as root only when root alone can change it: `trusted` on a scratch tree, with
    the test user standing in for root (TRUST_UID) and the tree's top standing in for / (TRUST_TOP)."""

    UID = os.getuid()

    def setUp(self):
        self.top = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.top, True)
        (self.top / "bin").mkdir(mode=0o755)
        os.chmod(self.top / "bin", 0o755)
        self.exe(self.top / "bin" / "node")

    @staticmethod
    def exe(path: Path, mode: int = 0o755) -> Path:
        path.write_text("#!/bin/sh\necho pwned\n")
        os.chmod(path, mode)
        return path

    def trusted(self, path: Path | str, uid: int | None = None) -> bool:
        script = (_function("root_only") + _function("dirs_ok") + _function("trusted")
                  + f"TRUST_UID={self.UID if uid is None else uid}\nTRUST_TOP={self.top}\n"
                  + f'trusted "{path}"; echo "rc=$?"\n')
        results = []
        for shell in [x for x in ("sh", "dash") if shutil.which(x)]:
            out = subprocess.run([shell, "-c", script], capture_output=True, text=True, timeout=30).stdout
            self.assertNotIn("pwned", out)
            results.append(out.strip().splitlines()[-1] == "rc=0")
        self.assertTrue(results and all(r == results[0] for r in results), results)
        return results[0]

    def test_root_only_file_is_trusted(self):
        self.assertTrue(self.trusted(self.top / "bin" / "node"))

    def test_symlinks_within_root_only_directories_are_followed(self):
        (self.top / "alt").mkdir(mode=0o755)
        os.chmod(self.top / "alt", 0o755)
        (self.top / "alt" / "node").symlink_to("../bin/node")              # relative hop
        (self.top / "bin" / "nodejs").symlink_to(self.top / "alt" / "node")  # absolute hop
        self.assertTrue(self.trusted(self.top / "bin" / "nodejs"))

    def test_another_owner_is_refused(self):
        self.assertFalse(self.trusted(self.top / "bin" / "node", uid=self.UID + 1))

    def test_group_or_other_writable_file_is_refused(self):
        for mode in (0o775, 0o757):
            with self.subTest(mode=oct(mode)):
                os.chmod(self.top / "bin" / "node", mode)
                self.assertFalse(self.trusted(self.top / "bin" / "node"))

    def test_writable_directory_is_refused(self):
        (self.top / "w").mkdir()
        os.chmod(self.top / "w", 0o777)
        self.exe(self.top / "w" / "node")
        self.assertFalse(self.trusted(self.top / "w" / "node"))
        (self.top / "bin" / "evil").symlink_to(self.top / "w" / "node")   # the reviewer's case: a link into it
        self.assertFalse(self.trusted(self.top / "bin" / "evil"))

    def test_symlinked_directory_in_the_path_is_refused(self):
        (self.top / "lnk").symlink_to(self.top / "bin")
        self.assertFalse(self.trusted(self.top / "lnk" / "node"))

    def test_not_executable_loop_and_long_chain_are_refused(self):
        self.exe(self.top / "bin" / "plain", 0o644)
        self.assertFalse(self.trusted(self.top / "bin" / "plain"))
        (self.top / "bin" / "a").symlink_to("b")
        (self.top / "bin" / "b").symlink_to("a")
        self.assertFalse(self.trusted(self.top / "bin" / "a"))
        prev = "node"
        for i in range(9):
            (self.top / "bin" / f"l{i}").symlink_to(prev)
            prev = f"l{i}"
        self.assertTrue(self.trusted(self.top / "bin" / "l7"))   # 8 hops
        self.assertFalse(self.trusted(self.top / "bin" / "l8"))  # 9 hops

    def test_s_binaries_checks_before_running(self):
        body = _function("s_binaries")
        self.assertLess(body.index('trusted "$p"'), body.index('t "$p"'))
        self.assertRegex(body, r'if ! trusted "\$p"; then\n\s*printf \'U\\t%s\\t%s\\n\' "\$n" "\$p"\n\s*continue')

    def test_defaults_are_root_and_slash(self):
        text = SCRIPT.read_text()
        self.assertRegex(text, r"(?m)^TRUST_UID=0$")
        self.assertRegex(text, r"(?m)^TRUST_TOP=$")


@unittest.skipUnless(os.environ.get("SBOM_AUDIT_DOCKER_TESTS") == "1" and _docker_ok(),
                     "set SBOM_AUDIT_DOCKER_TESTS=1 (and have docker) to run the collector in containers")
class CollectorContainerTests(unittest.TestCase):
    # The images ship /etc/apt/apt.conf.d/docker-clean, which turns apt's binary caches off and would hide
    # a cache rebuild: remove it and empty the caches first. The script is kept in /dev/shm (outside the
    # -xdev scan), run through `sh -s` as on a host, then every file newer than the marker is listed.
    RUN = ("rm -f /etc/apt/apt.conf.d/docker-clean && apt-get clean && cat > /dev/shm/collect.sh"
           " && dash -n /dev/shm/collect.sh && touch /tmp/.marker && sleep 1.1"
           " && sh -s < /dev/shm/collect.sh && echo @@NEWFILES"
           " && find / -xdev -newer /tmp/.marker -type f ! -path '/var/log/*'")

    def test_collector_in_container(self):
        for image in ("ubuntu:24.04", "debian:12"):
            with self.subTest(image=image):
                subprocess.run(["docker", "pull", "-q", image], capture_output=True, timeout=300)
                with SCRIPT.open("rb") as stdin:
                    run = subprocess.run(["docker", "run", "--rm", "-i", image, "sh", "-c", self.RUN], stdin=stdin,
                                         capture_output=True, timeout=300)
                self.assertEqual(run.returncode, 0, run.stderr.decode(errors="replace")[-2000:])
                doc, _, written = run.stdout.decode(errors="replace").partition("@@NEWFILES\n")
                self.assertEqual(written.split(), [], "the collector wrote files on the host")
                facts = parse.parse(json.loads(doc))
                self.assertTrue(facts["os"]["supported"])
                self.assertGreater(len(facts["packages"]), 50)
                self.assertEqual(facts["lynis"]["error"], "lynis not installed")
                self.assertEqual(facts["collector"], parse.SHIPPED_VERSION)


if __name__ == "__main__":
    unittest.main()
