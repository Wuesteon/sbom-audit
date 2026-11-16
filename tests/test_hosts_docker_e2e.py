"""bootstrap.sh / unbootstrap.sh / the rollback script end to end in a throwaway Ubuntu container.

Opt-in (`SBOM_AUDIT_DOCKER_TESTS=1`, docker running): it pulls ubuntu:24.04, installs openssh-server and sudo,
and lets bootstrap.sh apt-get install lynis, so it needs the network and takes several minutes (two full
collector runs). sshd's port is published on 127.0.0.1 only; the container is removed afterwards. There is no
systemd in the container: a stand-in `systemctl` answers only `reload ssh|sshd` (SIGHUP to sshd) and fails
everything else, so a restart or any other service call would fail the run. Nothing here reads the user's ssh
config (`-F /dev/null`) or known_hosts.
"""
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from sbomaudit.hosts import admin, parse, transport

IMAGE = "ubuntu:24.04"
SETUP = r"""set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null
apt-get install -y -q --no-install-recommends openssh-server sudo >/dev/null
mkdir -p /run/sshd
printf '%s\n' '#!/bin/sh' \
  'case "$1 $2" in "reload ssh"|"reload sshd") kill -HUP "$(cat /run/sshd.pid)" && sleep 1 ;; *) echo "systemctl $*: refused by the test" >&2; exit 1 ;; esac' \
  > /usr/sbin/systemctl
chmod 755 /usr/sbin/systemctl
printf '%s\n' 'AllowUsers root' >> /etc/ssh/sshd_config
sshd -t
/usr/sbin/sshd
"""


def _docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@unittest.skipUnless(os.environ.get("SBOM_AUDIT_DOCKER_TESTS") == "1" and _docker_ok(),
                     "set SBOM_AUDIT_DOCKER_TESTS=1 (and have docker) to run bootstrap in a container")
class BootstrapContainerTests(unittest.TestCase):
    def setUp(self):
        proc = subprocess.run(["docker", "run", "-d", "--rm", "-p", "127.0.0.1::22", IMAGE, "sleep", "infinity"],
                              capture_output=True, text=True, timeout=300)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.cid = proc.stdout.strip()
        self.addCleanup(subprocess.run, ["docker", "rm", "-f", self.cid], capture_output=True, timeout=60)
        tmp = tempfile.mkdtemp(prefix="sbom-audit-e2e-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.key = Path(tmp) / "audit"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "sbom-audit", "-f", str(self.key)],
                       check=True, timeout=60)
        self.sh(SETUP, timeout=900, check=True)
        port = subprocess.run(["docker", "port", self.cid, "22/tcp"], capture_output=True, text=True, timeout=30)
        self.port = port.stdout.split()[0].rsplit(":", 1)[1]

    # ------------------------------------------------------------------ helpers

    def sh(self, script, args=(), *, timeout=600, check=False):
        proc = subprocess.run(["docker", "exec", "-i", self.cid, "sh", "-s", "--", *args], input=script.encode(),
                              capture_output=True, timeout=timeout)
        out, err = proc.stdout.decode(errors="replace"), proc.stderr.decode(errors="replace")
        if check:
            self.assertEqual(proc.returncode, 0, f"stdout:\n{out}\nstderr:\n{err[-3000:]}")
        return proc.returncode, out, err

    def bootstrap(self):
        pub = Path(f"{self.key}.pub").read_text()
        return self.sh(admin.script_text("bootstrap.sh") + admin.bootstrap_payload(), admin.bootstrap_args(pub),
                       timeout=900)

    def ssh_argv(self, *extra):
        return ["ssh", "-F", "/dev/null", "-i", str(self.key), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
                "-p", self.port, *extra, "sbom-audit@127.0.0.1"]

    def collect(self, *extra, command="id"):
        for _ in range(10):                                 # sshd re-execs after the HUP: give it a moment
            result = transport.collect_once(self.ssh_argv(*extra) + [command], 600, subprocess.run)
            if result.doc is not None or "exit 255" not in (result.error or ""):
                return result
            time.sleep(2)
        return result

    def allowusers(self):
        return self.sh("grep -i '^allowusers' /etc/ssh/sshd_config", check=True)[1].strip()

    # ------------------------------------------------------------------ the lifecycle

    def test_lifecycle(self):
        # a Match-scoped AllowUsers: rc 4, ALLOWUSERS_MANUAL, nothing changed
        self.sh("printf 'Match User nobody\\n  AllowUsers nobody\\n' > /etc/ssh/sshd_config.d/50-match.conf",
                check=True)
        rc, out, err = self.bootstrap()
        self.assertEqual(rc, 4, out + err[-2000:])
        self.assertIn("ALLOWUSERS_MANUAL", out)
        self.assertNotEqual(self.sh("id -u sbom-audit")[0], 0, "a refused bootstrap created the user")
        self.assertNotEqual(self.sh("test -e /etc/sudoers.d/sbom-audit")[0], 0)
        self.sh("rm /etc/ssh/sshd_config.d/50-match.conf", check=True)

        # bootstrap: user, key, sudoers, lynis, AllowUsers edited with a backup
        rc, out, err = self.bootstrap()
        self.assertEqual(rc, 0, out + err[-3000:])
        self.assertIn("ALLOWUSERS_EDITED /etc/ssh/sshd_config", out)
        self.assertTrue(out.rstrip().endswith("DONE"), out)
        self.assertEqual(self.allowusers(), "AllowUsers root sbom-audit")
        self.sh("test -f /etc/ssh/sshd_config.sbom-audit.bak", check=True)

        # (a) the audit login returns a collector document whatever the command asked for
        result = self.collect()
        self.assertIsNotNone(result.doc, result.error)
        parse.parse(result.doc)
        self.assertEqual(str(result.doc.get("collector")), parse.SHIPPED_VERSION)
        self.assertNotIn("uid=", str(result.doc))

        # (c) sudo allows exactly the collector
        _, sudo_l, _ = self.sh("sudo -l -U sbom-audit", check=True)
        allowed = [ln.strip() for ln in sudo_l.splitlines() if "NOPASSWD" in ln]
        self.assertEqual(len(allowed), 1, sudo_l)
        self.assertIn("/usr/local/lib/sbom-audit/collect", allowed[0])
        _, keys, _ = self.sh("cat /var/lib/sbom-audit/.ssh/authorized_keys", check=True)
        self.assertEqual(len(keys.splitlines()), 1)
        self.assertTrue(keys.startswith(admin.KEY_PREFIX), "authorized_keys lacks the forced command")

        # the rollback script restores the backup and reloads
        rc, out, err = self.sh(admin.ROLLBACK_SCRIPT, ["/etc/ssh/sshd_config"])
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self.allowusers(), "AllowUsers root")

        # re-bootstrap over an existing user, then (b) a forced tty still gets no shell
        rc, out, err = self.bootstrap()
        self.assertEqual(rc, 0, out + err[-3000:])
        self.assertEqual(self.allowusers(), "AllowUsers root sbom-audit")
        # `restrict` refuses the pty and ssh -tt then gives up (exit 255) instead of falling back to anything
        tty = subprocess.run(self.ssh_argv("-tt") + ["echo SHELL-$((1+1))"], capture_output=True, timeout=600,
                             stdin=subprocess.DEVNULL)
        tty_text = tty.stdout.decode(errors="replace") + tty.stderr.decode(errors="replace")
        self.assertNotIn("SHELL-2", tty_text)
        self.assertTrue(tty.returncode == 255 and "PTY allocation request failed" in tty_text
                        or transport._text(tty.stdout).lstrip().startswith("{"), tty_text[-2000:])
        result = self.collect(command="echo SHELL-$((1+1))")
        self.assertIsNotNone(result.doc, result.error)
        self.assertNotIn("SHELL-2", str(result.doc))

        # unbootstrap with the recorded file: everything but lynis is gone, AllowUsers is back
        rc, out, err = self.sh(admin.script_text("unbootstrap.sh"), ["/etc/ssh/sshd_config"])
        self.assertEqual(rc, 0, out + err)
        self.assertIn("ALLOWUSERS_REMOVED /etc/ssh/sshd_config", out)
        self.assertEqual(self.allowusers(), "AllowUsers root")
        for path in ("/etc/sudoers.d/sbom-audit", "/var/lib/sbom-audit", "/usr/local/lib/sbom-audit"):
            self.assertNotEqual(self.sh(f"test -e {path}")[0], 0, f"{path} survived unbootstrap")
        self.assertNotEqual(self.sh("id -u sbom-audit")[0], 0)
        self.sh("command -v lynis", check=True)
        self.assertIsNone(self.collect().doc)


if __name__ == "__main__":
    unittest.main()
