"""The Linux systemd user timer end to end in a throwaway systemd container (tests/linux-timer/inside.sh).

Opt-in (`SBOM_AUDIT_DOCKER_TESTS=1`, docker running): it builds a small Ubuntu 24.04 image with systemd as
PID 1 (needs the network for apt), runs it privileged with this checkout mounted read-only, and checks:
units verify, the timer is enabled and listed, a shortened timer fires and the wrapper records the run,
linger starts the user manager with no login after a container restart, and a fire missed while the
container was stopped runs right after it starts (Persistent=true). A container restart is a reboot of the
container's systemd, not of a kernel: see docs/testing-linux-timer.md for the VM procedure. Takes about
5 minutes; the container and image are removed afterwards.
"""
import datetime as dt
import os
import shutil
import subprocess
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "sbom-audit-systemd-test:24.04"
DOCKERFILE = """FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -q && apt-get install -y -q --no-install-recommends systemd systemd-sysv dbus dbus-user-session \
    libpam-systemd python3 && rm -rf /var/lib/apt/lists/* \
 && systemctl mask systemd-firstboot.service getty.target console-getty.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
"""


def _docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@unittest.skipUnless(os.environ.get("SBOM_AUDIT_DOCKER_TESTS") == "1" and _docker_ok(),
                     "set SBOM_AUDIT_DOCKER_TESTS=1 (and have docker) to run the systemd timer in a container")
class SystemdTimerContainerTests(unittest.TestCase):
    def docker(self, *args, timeout=120, check=True):
        proc = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
        if check:
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return proc

    def inside(self, phase, timeout=300):
        proc = self.docker("exec", self.cid, "sh", "/opt/sbom-audit/tests/linux-timer/inside.sh", phase,
                           timeout=timeout, check=False)
        print(proc.stdout + proc.stderr)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("FAIL:", proc.stdout)
        return proc.stdout

    def wait_running(self):
        for _ in range(60):
            state = self.docker("exec", self.cid, "systemctl", "is-system-running", check=False).stdout.strip()
            if state in ("running", "degraded"):
                return
            time.sleep(1)
        self.fail("systemd did not finish booting in the container")

    def setUp(self):
        proc = subprocess.run(["docker", "build", "-t", IMAGE, "-"], input=DOCKERFILE, capture_output=True,
                              text=True, timeout=900)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.cid = self.docker("run", "-d", "--privileged", "--cgroupns=host", "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw",
                               "--tmpfs", "/run", "--tmpfs", "/run/lock", "-v", f"{ROOT}:/opt/sbom-audit:ro",
                               IMAGE).stdout.strip()
        self.addCleanup(subprocess.run, ["docker", "rm", "-f", self.cid], capture_output=True, timeout=60)
        self.wait_running()

    def test_timer_fires_survives_restart_with_linger_and_catches_up(self):
        out = self.inside("setup")
        for needle in ("systemd-analyze --user verify", "timer listed", "shortened timer fired",
                       "user manager user@"):
            self.assertIn("PASS: " + needle, out)
        at = self.inside("arm-persist").strip().splitlines()[-1]          # e.g. 2026-11-21 10:42:00 UTC
        fire = dt.datetime.strptime(at, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=dt.timezone.utc)
        self.docker("stop", self.cid, timeout=120)
        delay = (fire - dt.datetime.now(dt.timezone.utc)).total_seconds() + 20
        self.assertGreater(delay, 0, "the container stopped after the armed fire time")
        time.sleep(delay)                                                 # the fire passes while it is down
        self.docker("start", self.cid)
        self.wait_running()
        out = self.inside("after-reboot")
        self.assertIn("PASS: user manager started at boot with no login", out)
        self.assertIn("PASS: missed fire caught up after boot", out)


if __name__ == "__main__":
    unittest.main()
