# Testing the Linux timer

`setup --schedule weekly` on Linux writes a systemd user service and timer to `~/.config/systemd/user/`
(`OnCalendar=Sat 03:00`, `Persistent=true`) and needs `loginctl enable-linger` so that the timer runs when
nobody is logged in. The unit tests check the generated files as text. This page explains how to check
them on a real systemd. Nothing here touches a real portfolio. The output directory is
`/home/auditor/security`, and the CLI is a stub that records its arguments and exits 1 ("findings present").

The checks are in [`tests/linux-timer/inside.sh`](../tests/linux-timer/inside.sh), which runs as root on
the systemd machine. It has three phases:

| Phase | Checks |
|---|---|
| `setup` | user `auditor` with linger; the user manager runs without a login; the real `scheduler.install_weekly()` installs and enables the timer; `systemd-analyze --user verify` on the service and timer; timer enabled, active and in `systemctl --user list-timers`; a drop-in shortens it to every minute; one fire happens; `scheduler.json` gets `last_exit 1` and no error; the stub ran with the scheduled marker and its output is in `.cache/runs/` |
| `arm-persist` | moves the timer to one fixed minute, 2 minutes ahead, and prints that time (UTC) |
| `after-reboot` | after a reboot during which that minute passed: linger kept; the user manager started at boot with no login; the timer is active; the missed fire ran after boot (`Persistent=true`) |

Each check prints `PASS:` or `FAIL:`. The script exits 1 on the first `FAIL`.

## Option A: systemd container (Docker)

```sh
SBOM_AUDIT_DOCKER_TESTS=1 python3 -m unittest tests.test_scheduler_systemd_e2e -v
```

This builds `ubuntu:24.04` with systemd as PID 1 (needs the network for apt). It runs the container
privileged with `--cgroupns=host`, mounts this checkout read-only at `/opt/sbom-audit`, and runs `setup`
and `arm-persist`. It then stops the container until the armed minute has passed, starts it again, and runs
`after-reboot`. It takes about 5 minutes. The container is removed afterwards. You can delete the image
with `docker rmi sbom-audit-systemd-test:24.04`.

Limits: a container restart reboots the container's systemd, not a kernel. Logind and linger behave as on a
host, but the clock is the host's. Docker Desktop on macOS runs cgroup v2 in a LinuxKit VM; if the
container does not reach `running`/`degraded`, use option B.

## Option B: a throwaway VM (the full test)

Any Linux VM with systemd works, and Python must be 3.11 or newer. For example, Ubuntu 24.04 in UTM,
Multipass or a cloud VM. On the VM:

```sh
sudo apt-get install -y python3 git        # usually present already
git clone https://github.com/Wuesteon/sbom-audit /opt/sbom-audit   # or copy the checkout under test
cd /opt/sbom-audit && git checkout <branch-or-tag>
sudo SRC=/opt/sbom-audit sh tests/linux-timer/inside.sh setup
AT=$(sudo SRC=/opt/sbom-audit sh tests/linux-timer/inside.sh arm-persist | tail -1); echo "armed for $AT"
sudo poweroff
```

Wait until the armed time plus a minute has passed. Then boot the VM, but do not log in as `auditor`, and
from an admin login run:

```sh
sudo SRC=/opt/sbom-audit sh tests/linux-timer/inside.sh after-reboot
```

To check the real weekly calendar instead of the shortened one, remove the drop-in and check the next
elapse:

```sh
sudo rm -r /home/auditor/.config/systemd/user/sbom-audit-*.timer.d
sudo -u auditor XDG_RUNTIME_DIR=/run/user/$(id -u auditor) systemctl --user daemon-reload
sudo -u auditor XDG_RUNTIME_DIR=/run/user/$(id -u auditor) systemctl --user list-timers --all   # NEXT = Sat 03:00 local
```

To clean up, run `sudo loginctl disable-linger auditor && sudo userdel -r auditor`, or delete the VM.

## What a real install adds

The test runs the plugin's own `install_weekly()` with a stub CLI. A real `/sbom-audit:schedule weekly`
also runs `setup`, which needs the portfolio config, `git`, Syft and osv-scanner. Those parts are covered
elsewhere and are not part of this test.
