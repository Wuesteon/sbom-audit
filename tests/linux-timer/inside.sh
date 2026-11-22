#!/bin/sh
# The systemd user timer of `setup --schedule weekly` on a real systemd machine: a throwaway VM, or the
# systemd container of tests/test_scheduler_systemd_e2e.py. Run as root; the checkout is at $SRC.
#
#   inside.sh setup          user `auditor` with linger, the real install_weekly() with a stub CLI, verify the
#                            units, list the timer, shorten it to every minute and wait for one fire
#   inside.sh arm-persist    move the timer to one fixed minute 2 minutes ahead; print that time (UTC)
#   inside.sh after-reboot   with no login: user manager up (linger), timer active, and the run that the
#                            reboot missed has fired after boot (Persistent=true)
#
# It never touches a real portfolio: OUT is /home/auditor/security and the CLI is a stub that records its
# arguments and exits 1 ("findings present"). Each check prints PASS or FAIL; exit 1 on the first FAIL.
set -eu
SRC=${SRC:-/opt/sbom-audit}
U=auditor
OUT=/home/$U/security
STUB=/home/$U/stub-plugin
STATE=$OUT/.cache/scheduler.json

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; exit 1; }

uid() { id -u "$U"; }
as_user() {
    runuser -u "$U" -- env HOME="/home/$U" XDG_RUNTIME_DIR="/run/user/$(uid)" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(uid)/bus" "$@"
}
unit() {
    as_user python3 -c "import sys; sys.path.insert(0, '$SRC/plugin/scripts')
from sbomaudit import scheduler; print(scheduler.unit_name('$OUT'))"
}
last_fired() {
    python3 -c "import json; print(json.load(open('$STATE')).get('last_fired') or '')" 2>/dev/null || true
}
wait_user_manager() {
    i=0
    until systemctl is-active --quiet "user@$(uid).service"; do
        i=$((i + 1)); [ "$i" -gt 60 ] && return 1; sleep 1
    done
    i=0
    until [ -S "/run/user/$(uid)/bus" ]; do
        i=$((i + 1)); [ "$i" -gt 30 ] && return 1; sleep 1
    done
}
wait_fire_after() {    # $1: a UTC stamp; waits up to $2 seconds for last_fired > $1
    i=0
    while :; do
        now=$(last_fired)
        if [ -n "$now" ] && [ "$now" \> "$1" ]; then echo "$now"; return 0; fi
        i=$((i + 1)); [ "$i" -gt "$2" ] && return 1; sleep 1
    done
}

case "${1:-}" in
setup)
    python3 -c 'import sys; assert sys.version_info >= (3, 11), sys.version' || fail "python3 >= 3.11 needed"
    id "$U" >/dev/null 2>&1 || useradd -m -s /bin/sh "$U"
    loginctl enable-linger "$U"
    [ "$(loginctl show-user "$U" -p Linger --value)" = yes ] && pass "linger enabled for $U" || fail "linger"
    wait_user_manager && pass "user manager user@$(uid) running without a login" || fail "user manager not started"
    mkdir -p "$STUB/scripts" "$OUT"
    cat > "$STUB/scripts/sbom_audit_cli.py" <<'EOF'
import os, sys, datetime
print("stub run", sys.argv[1:], "scheduled=" + str(os.environ.get("SBOM_AUDIT_SCHEDULED")),
      datetime.datetime.now(datetime.timezone.utc).isoformat())
sys.exit(1)
EOF
    chown -R "$U:$U" "$STUB" "$OUT"
    as_user python3 -c "import sys; sys.path.insert(0, '$SRC/plugin/scripts')
from pathlib import Path
from sbomaudit import scheduler
for line in scheduler.install_weekly(Path('$OUT'), Path('$STUB'), home=Path('/home/$U'), platform='linux'):
    print('  ' + line)
state = scheduler.read_state(Path('$OUT'))
assert state['installed'] is True, state"
    pass "install_weekly() installed and enabled the timer"
    N=$(unit)
    D=/home/$U/.config/systemd/user
    as_user systemd-analyze --user verify "$D/$N.service" "$D/$N.timer" && pass "systemd-analyze --user verify" \
        || fail "systemd-analyze --user verify"
    as_user systemctl --user is-enabled --quiet "$N.timer" && pass "timer enabled" || fail "timer not enabled"
    as_user systemctl --user is-active --quiet "$N.timer" && pass "timer active" || fail "timer not active"
    as_user systemctl --user list-timers --all --no-pager | tee /dev/stderr | grep -q "$N.timer" \
        && pass "timer listed" || fail "timer not listed"
    as_user systemd-analyze calendar "Sat 03:00" | sed 's/^/  /'
    mkdir -p "$D/$N.timer.d"
    printf '[Timer]\nOnCalendar=\nOnCalendar=*-*-* *:*:00\nAccuracySec=1s\n' > "$D/$N.timer.d/zz-test.conf"
    chown -R "$U:$U" "$D/$N.timer.d"
    as_user systemctl --user daemon-reload
    as_user systemctl --user restart "$N.timer"
    before=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    fired=$(wait_fire_after "$before" 150) && pass "shortened timer fired (last_fired $fired)" || fail "no fire in 150 s"
    sleep 3
    python3 - "$STATE" <<'EOF' && pass "state after the fire: last_exit 1, no error" || fail "state after fire"
import json, sys
s = json.load(open(sys.argv[1]))
print("  ", {k: s.get(k) for k in ("last_fired", "last_exit", "last_error", "plugin_install")})
assert s.get("last_exit") == 1 and not s.get("last_error"), s
EOF
    grep -h "stub run" "$OUT"/.cache/runs/*.log | tail -1 | grep -q "scheduled=1" && pass "CLI ran with --out and the scheduled marker" \
        || fail "stub CLI output missing from .cache/runs"
    ;;
arm-persist)
    N=$(unit)
    D=/home/$U/.config/systemd/user
    at=$(date -u -d '+2 min' '+%Y-%m-%d %H:%M:00 UTC')
    printf '[Timer]\nOnCalendar=\nOnCalendar=%s\nAccuracySec=1s\n' "$at" > "$D/$N.timer.d/zz-test.conf"
    as_user systemctl --user daemon-reload
    as_user systemctl --user restart "$N.timer"
    as_user systemctl --user list-timers --all --no-pager | grep "$N.timer" >&2 || true
    echo "$at"
    ;;
after-reboot)
    N=$(unit)
    # PID 1's start, not /proc/uptime: in a container that is the host kernel's uptime
    boot=$(date -u -d "$(systemctl show -p UserspaceTimestamp --value)" +%Y-%m-%dT%H:%M:%SZ)
    echo "  systemd started $boot"
    [ "$(loginctl show-user "$U" -p Linger --value)" = yes ] && pass "linger survives the reboot" || fail "linger lost"
    wait_user_manager && pass "user manager started at boot with no login" || fail "user manager not started at boot"
    as_user systemctl --user is-active --quiet "$N.timer" && pass "timer active after reboot" || fail "timer inactive after reboot"
    fired=$(wait_fire_after "$boot" 120) && pass "missed fire caught up after boot (Persistent=true; last_fired $fired)" \
        || fail "no catch-up fire after boot (last_fired $(last_fired))"
    as_user journalctl --user -u "$N.service" --no-pager -n 5 2>/dev/null | sed 's/^/  /' || true
    ;;
*)
    echo "usage: $0 setup|arm-persist|after-reboot" >&2; exit 2 ;;
esac
