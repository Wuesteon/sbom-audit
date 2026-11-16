#!/bin/sh
# sbom-audit host unbootstrap: removes what bootstrap.sh installed. Run as root by `hosts unbootstrap <host>
# --confirm <host>` through the admin login (`sh -s -- <file>`), or by hand with the command it prints.
#
# <file> is the sshd config file bootstrap appended sbom-audit to (recorded by the plugin), or `-` when it
# edited none. From that file's global AllowUsers lines the token sbom-audit is removed (backup
# <file>.sbom-audit.bak, `sshd -t`, reload, never restart; restored when either fails). A line that would be
# left without names keeps the token: removing it would open the server to every user. With `-` it only
# reports AllowUsers lines that still name sbom-audit (ALLOWUSERS_LEFT).
#
# It leaves lynis installed (the admin may use it; removing packages is not this tool's call).
# stdout is the protocol (STEP <name> ok, ALLOWUSERS_*, DONE); tool output goes to stderr.
# Exit codes: 0 done, 1 error, 5 sshd config edit rejected, restored (and reloaded where it had been), 8 sshd
# config restore failed, 9 the edit was restored on disk but sshd did not reload either time (the running sshd
# still has the old config: nothing to undo). Exits 5, 8 and 9 follow their marker (ALLOWUSERS_FAILED,
# ALLOWUSERS_RESTORE_FAILED, ALLOWUSERS_RELOAD_FAILED) as the last stdout line; the plugin trusts the code only
# with it (a bare `set -e` failure exits with the command's own status).
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
umask 022

AUDIT_USER=sbom-audit

# Drops the word sbom-audit from AllowUsers lines outside Match blocks; a line it would empty stays as it is.
REMOVE_AWK='{
	t = $0
	sub(/^[ \t]+/, "", t)
	kw = t
	sub(/[ \t=].*$/, "", kw)
	kw = tolower(kw)
	if (kw == "match") inm = 1
	if (!inm && kw == "allowusers") {
		line = $0
		cr = ""
		if (sub(/\r$/, "", line)) cr = "\r"
		out = line " "
		while (match(out, /[ \t]sbom-audit[ \t]/)) out = substr(out, 1, RSTART - 1) substr(out, RSTART + RLENGTH - 1)
		out = substr(out, 1, length(out) - 1)
		rest = out
		sub(/^[ \t]*[^ \t=]+[ \t=]*/, "", rest)
		if (rest != "") { print out cr; next }
	}
	print
}'

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR %s\n' "$*" >&2; exit 1; }

check_file() {
	case $1 in
	/etc/ssh/sshd_config) ;;
	/etc/ssh/sshd_config.d/*.conf)
		case ${1#/etc/ssh/sshd_config.d/} in */*|*[!A-Za-z0-9._-]*) die "unexpected sshd config file" ;; esac ;;
	*) die "unexpected sshd config file" ;;
	esac
}

remove_token() {
	f=$1
	bak="$f.sbom-audit.bak"
	new="$f.sbom-audit.new"
	if [ ! -f "$f" ]; then
		say "ALLOWUSERS_UNCHANGED $f is gone"
		return 0
	fi
	cp -p "$f" "$new"
	awk "$REMOVE_AWK" "$f" >"$new"
	if cmp -s "$f" "$new"; then
		rm -f "$new"
		say "ALLOWUSERS_UNCHANGED $f"
		return 0
	fi
	cp -p "$f" "$bak"
	mv "$new" "$f"
	if ! sshd -t >&2; then
		if ! cp "$bak" "$f"; then
			say "ALLOWUSERS_RESTORE_FAILED $f"
			exit 8
		fi
		say "ALLOWUSERS_FAILED sshd -t rejected the edited $f; restored, nothing reloaded"
		exit 5
	fi
	if ! { systemctl reload ssh || systemctl reload sshd; } >&2; then
		if ! { cp "$bak" "$f" && sshd -t >&2; }; then
			say "ALLOWUSERS_RESTORE_FAILED $f"
			exit 8
		fi
		if { systemctl reload ssh || systemctl reload sshd; } >&2; then
			say "ALLOWUSERS_FAILED reloading sshd failed; $f restored and reloaded"
			exit 5
		fi
		say "ALLOWUSERS_RELOAD_FAILED $f"
		exit 9
	fi
	say "ALLOWUSERS_REMOVED $f"
}

main() {
	[ $# -eq 1 ] || die "usage: sh -s -- <sshd config file | ->"
	[ "$(id -u)" = 0 ] || die "must run as root"
	[ "$1" = - ] || check_file "$1"

	rm -f /etc/sudoers.d/sbom-audit /etc/sudoers.d/.sbom-audit.new
	say "STEP sudoers ok"

	if id -u "$AUDIT_USER" >/dev/null 2>&1; then
		[ "$(id -u "$AUDIT_USER")" != 0 ] || die "user $AUDIT_USER has uid 0; refusing"
		userdel sbom-audit >&2 \
			|| die "userdel sbom-audit failed (exit $?): a process of sbom-audit may still run (an audit); retry later"
	fi
	say "STEP user ok"

	rm -rf /var/lib/sbom-audit /usr/local/lib/sbom-audit
	say "STEP files ok"

	if [ "$1" != - ]; then
		remove_token "$1"
	else
		for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
			if [ -f "$f" ] && grep -Eiq '^[[:space:]]*allowusers[[:space:]=].*[[:space:]=]sbom-audit([[:space:]]|$)' "$f"; then
				say "ALLOWUSERS_LEFT $f"
			fi
		done
	fi
	say "STEP allowusers ok"
	say "DONE"
}

main "$@" </dev/null
