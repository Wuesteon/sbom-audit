#!/bin/sh
# sbom-audit host patch: runs the host's own unattended-upgrades once. Run as root by `hosts patch <host>`
# (plan) and `hosts patch <host> --confirm <host>` (apply) through the admin login
# (`sh -s -- <plan|apply> <0|1> <held-back package>... [-- <confirmed package>...]`), or by hand with the command
# that `hosts patch` prints.
#
#   $1  plan  = apt-get update, then unattended-upgrade --dry-run (installs nothing)
#       apply = unattended-upgrade, pinned to the confirmed packages, then reports the pending-restart state
#   $2  1 = also upgrade the held-back packages, 0 = hold them back
#   $3... the package names to hold back (the plugin passes its one list). With $2 = 0 an empty list is refused:
#       no hold-back, no run.
#   --  apply only, then the confirmed packages: at least one. Every name (both lists) must be a Debian package
#       name, else the script stops before it touches anything.
#
# The settings are one private apt config file per run in /run (tmpfs, so nothing outlives a restart of the
# host), pointed to by APT_CONFIG and removed on exit. The host's own apt.conf and apt.conf.d stay in force as
# always (apt reads them next to APT_CONFIG); nothing in /etc is written. The file holds:
#   - the hold-back: one Package-Blacklist entry per held-back name (include flag 0);
#   - apply: Package-Whitelist with each confirmed package (anchored) and Package-Whitelist-Strict, so
#     unattended-upgrade installs nothing outside the confirmed list;
#   - plan and apply: no automatic removal of kernels or unused dependencies, so the plan is the whole change.
# Before unattended-upgrade runs, `apt-config dump` must show every one of these settings in force, else the
# script stops (a host file may clear or override them).
#
# What the script itself never does: restart or stop services or containers, shut the host down or restart it.
# needrestart is suspended during the upgrade (NEEDRESTART_SUSPEND=1) and only asked afterwards, in list mode
# (-r l). Package maintainer scripts may still restart their own services on upgrade.
#
# stdout is the protocol; tool output of apt-get goes to stderr, the output of unattended-upgrade stays on
# stdout (the plugin reads the package lists from it). Markers: REBOOT_ALREADY 0|1 (plan), REBOOT_REQUIRED 0|1,
# NEEDRESTART-SVC:/NEEDRESTART-KSTA: lines or `NEEDRESTART unknown` (apply), and DONE as the last line. A failing
# step stops with `ERROR <reason>` on stderr and exit 1; the plugin trusts only those two endings. Every tool
# reads /dev/null as stdin: this script itself arrives on stdin.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
DEBIAN_FRONTEND=noninteractive
export PATH LC_ALL DEBIAN_FRONTEND
umask 022

CONF=/run/sbom-audit/apt-$$.conf
MARK=/var/run/reboot-required

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR %s\n' "$*" >&2; exit 1; }

[ "$#" -ge 2 ] || die "usage: patch.sh <plan|apply> <0|1> [package...] [-- package...]"
MODE=$1
INCLUDE=$2
shift 2
case $MODE in plan | apply) ;; *) die "mode must be plan or apply" ;; esac
case $INCLUDE in 0 | 1) ;; *) die "include flag must be 0 or 1" ;; esac
HOLD=""
ONLY=""
after=0
for name in "$@"; do
	if [ "$name" = -- ]; then
		[ "$after" = 0 ] || die "more than one -- separator"
		after=1
		continue
	fi
	case $name in
		'' | [!a-z0-9]* | *[!a-z0-9.+-]*) die "invalid package name in the package lists" ;;
	esac
	if [ "$after" = 0 ]; then HOLD="$HOLD $name"; else ONLY="$ONLY $name"; fi
done
if [ "$MODE" = plan ]; then
	[ "$after" = 0 ] || die "plan takes no confirmed package list"
else
	[ "$after" = 1 ] && [ -n "$ONLY" ] || die "apply needs the confirmed package list after --"
fi
if [ "$INCLUDE" = 0 ] && [ -z "$HOLD" ]; then
	die "no hold-back list given: refusing to run without it"
fi
[ "$(id -u)" = 0 ] || die "must run as root"
command -v unattended-upgrade >/dev/null 2>&1 || die "unattended-upgrade is not installed"
command -v apt-config >/dev/null 2>&1 || die "apt-config is not installed: cannot verify the hold-back"

# A package name as an anchored regular expression for Package-Whitelist (no backslashes: dot and plus in a class).
anchored() { printf '^%s$' "$(printf '%s' "$1" | sed -e 's/[.]/[.]/g' -e 's/[+]/[+]/g')"; }

mkdir -p /run/sbom-audit
trap 'rm -f "$CONF"' EXIT
trap 'exit 1' HUP INT TERM
{
	if [ "$INCLUDE" = 0 ]; then
		for name in $HOLD; do
			printf 'Unattended-Upgrade::Package-Blacklist { "%s"; };\n' "$name"
		done
	fi
	if [ "$MODE" = apply ]; then
		for name in $ONLY; do
			printf 'Unattended-Upgrade::Package-Whitelist { "%s"; };\n' "$(anchored "$name")"
		done
		printf 'Unattended-Upgrade::Package-Whitelist-Strict "true";\n'
	fi
	printf 'Unattended-Upgrade::Remove-Unused-Kernel-Packages "false";\n'
	printf 'Unattended-Upgrade::Remove-New-Unused-Dependencies "false";\n'
	printf 'Unattended-Upgrade::Remove-Unused-Dependencies "false";\n'
} >"$CONF" || die "could not write the apt config"
APT_CONFIG=$CONF
export APT_CONFIG

# `apt-config dump` must list a line with the key and the value.
in_force() { printf '%s\n' "$dump" | grep -F "$1" | grep -Fq "$2"; }
verify_config() {
	dump=$(apt-config dump </dev/null 2>/dev/null) || die "apt-config dump failed: cannot verify the hold-back"
	if [ "$INCLUDE" = 0 ]; then
		for name in $HOLD; do
			in_force Unattended-Upgrade::Package-Blacklist "\"$name\"" || die "hold-back not in force for $name"
		done
	fi
	if [ "$MODE" = apply ]; then
		for name in $ONLY; do
			in_force Unattended-Upgrade::Package-Whitelist "\"$(anchored "$name")\"" ||
				die "confirmed-list pin not in force for $name"
		done
		in_force Unattended-Upgrade::Package-Whitelist-Strict true || die "strict whitelist not in force"
	fi
	for key in Remove-Unused-Kernel-Packages Remove-New-Unused-Dependencies Remove-Unused-Dependencies; do
		in_force "Unattended-Upgrade::$key" false || die "$key=false not in force"
	done
}

pending() { if [ -f "$MARK" ]; then say 1; else say 0; fi; }

if [ "$MODE" = plan ]; then
	say "REBOOT_ALREADY $(pending)"
	rc=0
	aptout=$(apt-get update -q 2>&1 </dev/null) || rc=$?
	if [ "$rc" -ne 0 ]; then
		printf '%s\n' "$aptout" >&2
		case $aptout in
			*"Could not get lock"* | *"Unable to acquire the dpkg"* | *"is held by process"*)
				die "apt is busy, retry later (another apt or unattended-upgrades run holds the lock)" ;;
		esac
		die "apt-get update failed (exit $rc)"
	fi
	verify_config
	rc=0
	NEEDRESTART_SUSPEND=1 unattended-upgrade --dry-run -v </dev/null 2>&1 || rc=$?
	[ "$rc" -eq 0 ] || die "unattended-upgrade --dry-run failed (exit $rc)"
	say DONE
	exit 0
fi

verify_config
rc=0
NEEDRESTART_SUSPEND=1 unattended-upgrade -v </dev/null 2>&1 || rc=$?
[ "$rc" -eq 0 ] || die "unattended-upgrade failed (exit $rc)"
say "REBOOT_REQUIRED $(pending)"
if command -v needrestart >/dev/null 2>&1; then
	rc=0
	nr=$(needrestart -b -r l </dev/null 2>/dev/null) || rc=$?
	if [ "$rc" -eq 0 ]; then
		printf '%s\n' "$nr" | grep -E '^NEEDRESTART-(SVC|KSTA):' || true
		say "NEEDRESTART listed"
	else
		say "NEEDRESTART unknown"
	fi
else
	say "NEEDRESTART unknown"
fi
say DONE
