#!/bin/sh
# sbom-audit host collector. Prints one JSON document on stdout:
#   {"collector": "<version>", "started": <epoch>, "sections": {"<name>": {"rc": <n>, "out": "<raw text>"}}}
# The plugin turns the raw sections into facts (scripts/sbomaudit/hosts/parse.py).
#
# Installed by `hosts bootstrap` as /usr/local/lib/sbom-audit/collect (root-owned) and run as root
# through the audit user's forced command. Read-only by design:
#   - it writes no file; the only writes on the host are Lynis's own files in /var/log (Lynis runs only
#     with the installed lynis.prf, which turns off its `apt-get update`). apt runs with its binary
#     caches disabled (-o Dir::Cache::pkgcache= ...): as root it would otherwise rebuild
#     /var/cache/apt/*.bin;
#   - it reads no .env file, no application directory and no private key;
#   - keys, sudoers and cron files leave the host only as fingerprints and hashes, never as content.
# Strict POSIX sh (dash on Debian/Ubuntu). Never updated silently: a changed script needs a new
# COLLECTOR_VERSION, and `hosts check` reports an installed older one as outdated.
COLLECTOR_VERSION=3

LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL PATH
umask 077

TAB=$(printf '\t')
LYNIS_PROFILE=/usr/local/lib/sbom-audit/lynis.prf
USER_RUN=/run/user
PROC=/proc
TRUST_UID=0
TRUST_TOP=
STARTED=$(date +%s)
UNITS_OUT=
CRON_OUT=
SEP=

# Every command runs under a timeout (KILL 5 s after TERM) so a hung probe cannot stall the whole run.
t() { timeout -k 5 60 "$@"; }
have() { command -v "$1" >/dev/null 2>&1; }
# Inside a section (each runs in its own $(...) subshell): stop it with rc 127 when a tool is missing.
need() { have "$1" || { echo "$1: not found"; exit 127; }; }

# JSON string body: drop control characters other than tab, CR and newline, then escape
# backslash, quote, tab and CR, and join lines with \n.
json_escape() {
	tr -d '\000-\010\013\014\016-\037\177' | awk '
		{ gsub(/\\/, "&&"); gsub(/"/, "\\\""); gsub(/\t/, "\\t"); gsub(/\r/, "\\r")
		  printf "%s%s", (NR == 1 ? "" : "\\n"), $0 }'
}

# run NAME FUNCTION: the function's stdout and stderr become the section's out, its status the rc.
run() {
	out=$("$2" 2>&1)
	rc=$?
	printf '%s"%s":{"rc":%d,"out":"' "$SEP" "$1" "$rc"
	printf '%s' "$out" | json_escape
	printf '"}'
	SEP=,
}

s_os() { t cat /etc/os-release; }

s_kernel() { t uname -r; }

s_reboot() {
	[ -e /var/run/reboot-required ] || return 1
	if [ -f /var/run/reboot-required.pkgs ]; then t cat /var/run/reboot-required.pkgs || return $?; fi
	return 0
}

# dpkg status-file format, so osv-scanner can read it as a dpkg status file.
# shellcheck disable=SC2016
s_dpkg() {
	need dpkg-query
	t dpkg-query -W -f='Package: ${Package}\nStatus: ${Status}\nVersion: ${Version}\nArchitecture: ${Architecture}\nSource: ${source:Package} (${source:Version})\n\n'
}

# No binary caches: as root, apt would otherwise write /var/cache/apt/pkgcache.bin and srcpkgcache.bin.
s_upgradable() { need apt; t apt -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= list --upgradable; }

# shellcheck disable=SC2016,SC2086
s_policy() {
	need apt-cache
	pkgs=$(t dpkg-query -W -f='${Package}\n' | sort -u)
	[ -n "$pkgs" ] || return 1
	set -f
	t apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy $pkgs || return $?
	# the unfiltered listing ("Package files:") carries each repository's release o=/a= fields
	t apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy
}

s_apt_config() {
	need apt-config
	dump=$(t apt-config dump) || return $?
	printf '%s\n' "$dump" | grep -E '^(APT::Periodic|Unattended-Upgrade)::'
	return 0
}

s_uu_timer() {
	e=$(t systemctl is-enabled apt-daily-upgrade.timer 2>/dev/null | head -n 1)
	a=$(t systemctl is-active apt-daily-upgrade.timer 2>/dev/null | head -n 1)
	printf '%s\n%s\n' "${e:-unknown}" "${a:-unknown}"
}

s_uu_log() {
	t zcat -f /var/log/unattended-upgrades/unattended-upgrades.log* 2>/dev/null \
		| grep 'Starting unattended upgrades script' | sort | tail -n 1
}

s_passwd() { t getent passwd; }

s_group() { t getent group; }

# Per file: path, sha256 and the first token (user list) of every rule line. Never the content.
# shellcheck disable=SC2016
s_sudoers() {
	for f in /etc/sudoers /etc/sudoers.d/*; do
		[ -f "$f" ] || continue
		h=$(t sha256sum < "$f" | cut -d ' ' -f 1)
		p=$(t awk '
			cont { cont = /\\$/; next }
			{ cont = /\\$/ }
			/^[ \t]*#[0-9]+[ \t]/ { line = $0 }
			!/^[ \t]*#[0-9]+[ \t]/ {
				if ($0 ~ /^[ \t]*(#|@|$)/) next
				if ($0 ~ /^[ \t]*(Defaults|User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias|Cmd_Alias)([ \t:@!>]|$)/) next
				line = $0
			}
			{ gsub(/[ \t]*,[ \t]*/, ",", line); split(line, w, " "); out = out (out == "" ? "" : ",") w[1] }
			END { print out }' "$f")
		printf '%s\t%s\t%s\n' "$f" "$h" "$p"
	done
	return 0
}

# Per login user (or uid 0) and AuthorizedKeysFile entry: bits, fingerprint and type; the comment is dropped.
s_authorized_keys() {
	need ssh-keygen
	akf=$(t sshd -T 2>/dev/null | awk '$1 == "authorizedkeysfile" { $1 = ""; print; exit }')
	[ -n "$akf" ] || akf='.ssh/authorized_keys .ssh/authorized_keys2'
	t getent passwd | awk -F : -v akf="$akf" '
		function rep(s, a, b,   i, r) {
			r = ""
			while ((i = index(s, a)) > 0) { r = r substr(s, 1, i - 1) b; s = substr(s, i + length(a)) }
			return r s
		}
		$3 == 0 || $7 !~ /(nologin|false|sync)$/ {
			n = split(akf, p, " ")
			for (i = 1; i <= n; i++) {
				if (p[i] == "none") continue
				f = rep(p[i], "%%", "\001"); f = rep(f, "%h", $6); f = rep(f, "%u", $1); f = rep(f, "\001", "%")
				if (substr(f, 1, 1) != "/") f = $6 "/" f
				print $1 "\t" f
			}
		}' | while IFS="$TAB" read -r u f; do
		[ -f "$f" ] || continue
		t ssh-keygen -lf "$f" 2>/dev/null | awk -v u="$u" '{ print u "\t" $1 " " $2 " " $NF }'
	done
	return 0
}

s_sockets() { need ss; t ss -H -tulpn; }

# Enabled units and timers: name, fragment path and the fragment's sha256.
# shellcheck disable=SC2086
s_units() {
	need systemctl
	list=$(t systemctl list-unit-files --state=enabled --no-legend --no-pager) || return $?
	set -f
	for u in $(printf '%s\n' "$list" | awk '{ print $1 }'); do
		fp=$(t systemctl show -p FragmentPath --value "$u" 2>/dev/null | head -n 1)
		h=-
		if [ -n "$fp" ] && [ -f "$fp" ]; then h=$(t sha256sum < "$fp" | cut -d ' ' -f 1); fi
		printf '%s\t%s\t%s\n' "$u" "${fp:--}" "$h"
	done
}

s_cron() {
	for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* \
		/etc/cron.monthly/* /var/spool/cron/crontabs/*; do
		[ -f "$f" ] && t sha256sum "$f"
	done
	return 0
}

# Owning package of every unit fragment and cron file, one dpkg -S call. Paths under /usr/lib, /usr/bin
# and /usr/sbin are also asked without /usr (and the reverse): dpkg before 1.22 knows only one spelling.
# shellcheck disable=SC2086
s_owners() {
	need dpkg
	paths=$({
		printf '%s\n' "$UNITS_OUT" | awk -F '\t' '$2 ~ /^\// { print $2 }'
		printf '%s\n' "$CRON_OUT" | awk '$2 ~ /^\// { print $2 }'
	} | awk '{ print }
		/^\/usr\/(lib|bin|sbin)\// { print substr($0, 5) }
		/^\/(lib|bin|sbin)\// { print "/usr" $0 }' | sort -u)
	[ -n "$paths" ] || return 0
	set -f
	t dpkg -S $paths
}

s_sshd() { need sshd; t sshd -T; }

s_host_keys() {
	need ssh-keygen
	for f in /etc/ssh/ssh_host_*_key.pub; do
		[ -f "$f" ] && t ssh-keygen -lf "$f" | awk '{ print $1 " " $2 " " $NF }'
	done
	return 0
}

# ufw when active; else the INPUT policy plus a hash of the iptables rules without comments, counters
# and the Docker chains (Docker rewrites those on every container restart). A failing tool fails the
# section: an empty ruleset's hash must never pass for a real one.
s_firewall() {
	if have ufw; then
		u=$(t ufw status verbose 2>&1) || { r=$?; echo "ufw status failed"; printf '%s\n' "$u"; return "$r"; }
		case $u in "Status: active"*) printf '%s\n' "$u"; return 0 ;; esac
	fi
	have iptables || return 0
	p=$(t iptables -S INPUT 2>&1) || { r=$?; echo "iptables -S INPUT failed"; printf '%s\n' "$p"; return "$r"; }
	v4=$(t iptables-save 2>&1) || { r=$?; echo "iptables-save failed"; printf '%s\n' "$v4"; return "$r"; }
	v6=
	if have ip6tables-save; then
		v6=$(t ip6tables-save 2>&1) || { r=$?; echo "ip6tables-save failed"; printf '%s\n' "$v6"; return "$r"; }
	fi
	printf '%s\n' "$p" | head -n 1
	printf '%s\n%s\n' "$v4" "$v6" | grep -v '^#' | sed 's/\[[0-9]*:[0-9]*\]//g' \
		| grep -Ev 'DOCKER|docker0|br-' | sha256sum
}

s_apparmor() {
	t cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo -
	have aa-status || return 0
	t aa-status --json 2>/dev/null || t aa-status
}

# Non-comment lines of every apt source file, prefixed with the file name. A deb822 stanza becomes one
# line ("Field: value | Field: value"); continuation lines (e.g. an inline Signed-By key) are dropped.
# shellcheck disable=SC2016
s_apt_sources() {
	for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
		[ -f "$f" ] || continue
		d=0
		case $f in *.sources) d=1 ;; esac
		t awk -v f="$f" -v deb822="$d" '
			/^[ \t]*#/ { next }
			deb822 && /^[ \t]*$/ { if (s != "") print f ": " s; s = ""; next }
			deb822 && /^[ \t]/ { next }
			deb822 { sub(/[ \t]+$/, ""); s = (s == "" ? $0 : s " | " $0); next }
			/^[ \t]*$/ { next }
			{ sub(/[ \t]+$/, ""); print f ": " $0 }
			END { if (s != "") print f ": " s }' "$f"
	done
	return 0
}

# Names and published ports only: image digests change on every deploy. One `docker ps` per dockerd in
# the host's PID namespace (one inside a container or LXC guest belongs to that guest): root's through
# the system socket, a rootless one (Docker run by a user) through $USER_RUN/<uid>/docker.sock, which must
# be a socket owned by that uid, not a symlink. Every line a rootless daemon returns gets the prefix
# "uid<uid>/" (its error messages too), so a user's daemon cannot speak for root's containers. No dockerd running gives an empty
# list, even with a stale /var/run/docker.sock left behind; containers that live-restore keeps running
# while dockerd is down are not seen then. Without a usable pgrep it asks the system socket, as before.
s_containers() {
	have docker || return 0
	if have pgrep; then
		pids=$(t pgrep -x dockerd)
		case $? in
			0) ;;
			1) return 0 ;;
			*) t docker ps --format '{{.Names}}\t{{.Ports}}'; return $? ;;
		esac
	else
		t docker ps --format '{{.Names}}\t{{.Ports}}'
		return $?
	fi
	hostns=$(readlink "$PROC/1/ns/pid")
	status=0
	for uid in $(for pid in $pids; do
		[ "$(readlink "$PROC/$pid/ns/pid")" = "$hostns" ] && t ps -o uid= -p "$pid"
	done | sort -un); do
		sock=$USER_RUN/$uid/docker.sock
		if [ "$uid" = 0 ]; then
			t docker ps --format '{{.Names}}\t{{.Ports}}' || status=$?
		elif [ -n "$(find "$sock" -prune -type s -user "$uid" 2>/dev/null)" ]; then
			lines=$(t docker -H "unix://$sock" ps --format '{{.Names}}\t{{.Ports}}' 2>&1)
			r=$?
			[ -z "$lines" ] || printf '%s\n' "$lines" | awk -v p="uid$uid/" '{ print p $0 }'
			[ "$r" -eq 0 ] || status=$r
		else
			echo "docker: rootless daemon of uid $uid has no socket of its own at $sock"
			status=1
		fi
	done
	return $status
}

# sshd logins of the last 8 days. "S\t<source>", "Z\t<UTC offset>", "E\t<note>" when a reader failed or
# timed out, then "A\t<line>" per accepted login and "F\t<YYYY-MM-DDTHH>\t<ip>\t<count>" per hour and
# source of failures. Journal times are UTC. A line is classified by its sshd message (the text after
# "sshd[pid]: "), never by text anywhere in the line: a user name can contain " Accepted ".
# Failure count, one per attempt: every "Failed ..." message counts 1 (existing and invalid users alike;
# sshd logs one per password attempt). An "Invalid user ..." message is logged once per connection, before
# its "Failed" lines, so it adds 1 only when no "Failed" message shares its connection (a probe that
# leaves before authenticating). A connection is the "sshd[pid]: " text plus hour and source, resolved in END.
s_logins() {
	src=none
	lines=
	if have journalctl; then
		lines=$(t journalctl --utc -q -t sshd -t sshd-session --since -8d -o short-iso --no-pager 2>/dev/null)
		r=$?
		[ "$r" -eq 0 ] || printf 'E\tjournalctl rc %s\n' "$r"
		[ -n "$lines" ] && src=journal
	fi
	if [ "$src" = none ] && [ -f /var/log/auth.log ]; then
		# zcat's status travels as a last line (a log line never starts with "@@"): sh has no pipefail.
		lines=$({ t zcat -f /var/log/auth.log* 2>/dev/null; echo "@@rc $?"; } | grep -E 'sshd(-session)?\[|^@@rc ')
		r=$(printf '%s\n' "$lines" | sed -n 's/^@@rc //p' | tail -n 1)
		lines=$(printf '%s\n' "$lines" | grep -v '^@@rc ')
		[ "$r" = 0 ] || printf 'E\tzcat auth.log rc %s\n' "${r:-?}"
		src=auth.log
	fi
	if [ "$src" = none ] && have journalctl && [ -n "$(t journalctl -q -n 1 --no-pager 2>/dev/null)" ]; then
		src=journal
	fi
	printf 'S\t%s\nZ\t%s\n' "$src" "$(date +%z)"
	[ -n "$lines" ] || return 0
	printf '%s\n' "$lines" | awk -v year="$(date +%Y)" -v month="$(date +%m)" '
		BEGIN { split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " "); for (i = 1; i <= 12; i++) mon[m[i]] = i }
		!match($0, /sshd(-session)?\[[0-9]+\]: /) { next }
		{ conn = substr($0, RSTART, RLENGTH); msg = substr($0, RSTART + RLENGTH) }
		msg ~ /^Accepted / { print "A\t" $0; next }
		msg ~ /^(Failed |Invalid user )/ {
			ip = ""
			for (i = NF - 1; i >= 1; i--) if ($i == "from") { ip = $(i + 1); break }
			if (ip == "") next
			if ($1 ~ /^[0-9][0-9][0-9][0-9]-/) h = substr($1, 1, 13)
			else {
				mo = mon[$1]
				if (mo == "") next
				y = year
				if (mo > month + 0) y = year - 1
				h = sprintf("%04d-%02d-%02dT%s", y, mo, $2, substr($3, 1, 2))
			}
			if (msg ~ /^Failed /) { n[h "\t" ip]++; failed[conn "\t" h "\t" ip] = 1 }
			else probe[conn "\t" h "\t" ip] = 1
		}
		END {
			for (k in probe) if (!(k in failed)) { split(k, p, "\t"); n[p[2] "\t" p[3]]++ }
			for (k in n) print "F\t" k "\t" n[k]
		}'
}

# Lynis in non-interactive mode with the slow tests skipped by the profile, then the report lines the
# plugin reads. START (before the run) and MTIME (of the report) tell a stale report from a fresh one.
# Never without the profile: Lynis's defaults run `apt-get update`, a write outside /var/log.
s_lynis() {
	have lynis || { echo "lynis: not found"; return 127; }
	[ -f "$LYNIS_PROFILE" ] || { echo "lynis: profile missing"; return 127; }
	echo "START $(date +%s)"
	timeout -k 5 200 lynis audit system --cronjob --profile "$LYNIS_PROFILE" >/dev/null 2>&1
	rc=$?
	r=/var/log/lynis-report.dat
	if [ -f "$r" ]; then
		grep -E '^(hardening_index|warning\[\]|suggestion\[\]|report_datetime_end)=' "$r"
		echo "MTIME $(stat -c %Y "$r")"
	fi
	return "$rc"
}

# root_only <path>: a regular file or directory (never a symlink) owned by root and writable by no group
# or other user. find without -L looks at the path itself.
root_only() {
	[ -n "$(find "$1" -prune -user "$TRUST_UID" ! -perm -020 ! -perm -002 \( -type f -o -type d \) 2>/dev/null)" ]
}

# dirs_ok <absolute path>: every directory above it (up to, not including, / or $TRUST_TOP) is root_only.
dirs_ok() {
	d=${1%/*}
	while [ -n "$d" ] && [ "$d" != "$TRUST_TOP" ]; do
		root_only "$d" || return 1
		d=${d%/*}
	done
	return 0
}

# trusted <path>: only root can change what running <path> executes. Every hop of a symlink chain (at most
# 8, e.g. /usr/bin/node -> /etc/alternatives/node -> /usr/bin/nodejs) sits in root_only directories, and the
# file at the end is root_only and executable. A path anyone else can change is never run as root.
trusted() {
	f=$1
	k=0
	while :; do
		case $f in /*) ;; *) return 1 ;; esac
		dirs_ok "$f" || return 1
		[ -L "$f" ] || break
		k=$((k + 1))
		[ "$k" -le 8 ] || return 1
		l=$(readlink "$f") || return 1
		case $l in /*) f=$l ;; *) f=${f%/*}/$l ;; esac
	done
	root_only "$f" && [ -f "$f" ] && [ -x "$f" ]
}

# Binaries the plugin compares with upstream releases: name, path, owning package (or -), version line.
# Runs each one (as root) only when trusted; otherwise "U\t<name>\t<path>" and it is not run.
s_binaries() {
	for p in /usr/local/bin/caddy /usr/bin/caddy /usr/local/bin/node /usr/bin/node \
		/usr/local/bin/docker-compose /usr/bin/docker-compose /usr/local/lib/docker/cli-plugins/docker-compose \
		/usr/libexec/docker/cli-plugins/docker-compose /usr/lib/docker/cli-plugins/docker-compose; do
		[ -f "$p" ] && [ -x "$p" ] || continue
		n=${p##*/}
		if ! trusted "$p"; then
			printf 'U\t%s\t%s\n' "$n" "$p"
			continue
		fi
		case $n in
			node) v=$(t "$p" --version 2>&1 | head -n 1) ;;
			*) v=$(t "$p" version 2>&1 | head -n 1) ;;
		esac
		o=
		for q in "$p" "$(readlink -f "$p")"; do
			[ -n "$o" ] && break
			o=$(t dpkg -S "$q" 2>/dev/null | awk '!/^diversion by/ { sub(/:.*/, ""); print; exit }')
		done
		printf '%s\t%s\t%s\t%s\n' "$n" "$p" "${o:--}" "$v"
	done
	return 0
}

main() {
	printf '{"collector":"%s","started":%s,"sections":{' "$COLLECTOR_VERSION" "$STARTED"
	run os s_os
	run kernel s_kernel
	run reboot s_reboot
	run dpkg s_dpkg
	run upgradable s_upgradable
	run policy s_policy
	run apt_config s_apt_config
	run uu_timer s_uu_timer
	run uu_log s_uu_log
	run passwd s_passwd
	run group s_group
	run sudoers s_sudoers
	run authorized_keys s_authorized_keys
	run sockets s_sockets
	run units s_units
	UNITS_OUT=$out
	run cron s_cron
	CRON_OUT=$out
	run owners s_owners
	run sshd s_sshd
	run host_keys s_host_keys
	run firewall s_firewall
	run apparmor s_apparmor
	run apt_sources s_apt_sources
	run containers s_containers
	run logins s_logins
	run lynis s_lynis
	run binaries s_binaries
	printf '}}\n'
}

# stdin from /dev/null: no probe may read the rest of the script when it arrives on stdin (`sh -s`).
main < /dev/null
