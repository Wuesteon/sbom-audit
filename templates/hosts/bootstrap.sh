#!/bin/sh
# sbom-audit host bootstrap: creates the read-only audit login. Run as root by `hosts bootstrap <host>
# --confirm <host>` through the admin login (`sh -s -- <authorized_keys line> <sha256 collect> <sha256 lynis.prf>`),
# or by hand with the command that `hosts bootstrap` prints when the admin login has no passwordless sudo.
#
# The script text arrives on stdin, followed by a quoted here-document with the payload (collect.sh, a marker
# line, lynis.prf): see the last line. Every command before the payload is split off reads /dev/null, so
# none of them can swallow the rest of the script.
#
# What it changes, idempotently:
#   - user sbom-audit (system user, no password: `*`), home /var/lib/sbom-audit, all of it root-owned so the
#     user cannot change its own authorized_keys; one key, forced command, `restrict`;
#   - /usr/local/lib/sbom-audit/{collect,lynis.prf} (root:root);
#   - /etc/sudoers.d/sbom-audit: the collector, no arguments, nothing else (checked with visudo first);
#   - the lynis package (apt-get install; needrestart is suspended, no service is restarted);
#   - only when AllowUsers keeps sbom-audit out: appends it to the one global AllowUsers line (backup
#     <file>.sbom-audit.bak, `sshd -t`, reload, never restart). The plugin then proves a fresh admin login and
#     an audit collect still work, and restores the backup if not.
# Before it changes anything it refuses AllowUsers/AllowGroups inside a Match block, an AllowUsers edit when
# the config has an Include it does not follow (anything but the standard sshd_config.d/*.conf one, including
# an Include nested in a sshd_config.d file), an AllowGroups that does not admit the user, more than one
# AllowUsers line and an AllowUsers line with a comment (ALLOWUSERS_MANUAL, exit 4): those are edited by hand.
# Exit 4 always means nothing changed.
#
# The apt step waits at most 3 x 300 s for the dpkg lock (install, update, install) plus downloads; the plugin's
# timeout for the whole script is well above that.
#
# stdout is the protocol (STEP <name> ok, ALLOWUSERS_*, DONE); tool output goes to stderr. Every exit code
# but 0 and 1 follows its own marker as the last stdout line (3 UNSUPPORTED, 4 ALLOWUSERS_MANUAL, 5
# ALLOWUSERS_FAILED, 6 NEEDS_SUDO, 7 PAYLOAD_CORRUPT, 8 ALLOWUSERS_RESTORE_FAILED, 9 ALLOWUSERS_RELOAD_FAILED):
# the plugin trusts a code only with its marker, since a bare command failure under `set -e` exits with the
# command's own status (usermod/userdel exit 8 when the user is busy).
# Exit codes: 0 done, 1 error, 3 unsupported OS, 4 AllowUsers needs a manual edit (nothing changed), 5 sshd
# config edit rejected, restored (and reloaded where it had been), 6 sudo/visudo missing, 7 payload corrupt,
# 8 sshd config restore failed (the edited file may be on disk), 9 the edit was restored on disk but sshd did
# not reload either time (the running sshd never loaded the edit: nothing to undo).
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
umask 022

AUDIT_USER=sbom-audit
KEY_PREFIX='restrict,command="sudo -n /usr/local/lib/sbom-audit/collect" '
SUDOERS_LINE='sbom-audit ALL=(root) NOPASSWD: /usr/local/lib/sbom-audit/collect ""'
PRF_MARKER='@@SBOM_AUDIT_LYNIS_PRF@@'

# Reads `file<TAB>line<TAB>text` records in the order sshd reads them; prints
# `<global|match> <allowusers|allowgroups> <names sbom-audit: 0|1> <file> <line> <has a comment: 0|1>`, and
# `match include 0 <file> <line> 0` for an Include this script cannot follow. Once a Match line (or such an
# Include) was seen, every later line counts as inside a Match block (sshd has no "end of Match" but the next
# Match).
SCOPE_AWK='BEGIN { FS = "\t" }
{
	text = substr($0, length($1) + length($2) + 3)
	sub(/\r$/, "", text)
	sub(/^[ \t]+/, "", text)
	if (text == "" || substr(text, 1, 1) == "#") next
	kw = text
	sub(/[ \t=].*$/, "", kw)
	kw = tolower(kw)
	if (kw == "match") { inm = 1; next }
	if (kw == "include") { inm = 1; print "match", "include", 0, $1, $2, 0; next }
	if (kw != "allowusers" && kw != "allowgroups") next
	val = " " substr(text, length(kw) + 1) " "
	gsub(/[\t=]/, " ", val)
	print (inm ? "match" : "global"), kw, (index(val, " sbom-audit ") ? 1 : 0), $1, $2, (index(text, "#") ? 1 : 0)
}'

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR %s\n' "$*" >&2; exit 1; }

# admits <patterns, whitespace separated> <names>: 0 when a plain pattern (no user@host, no negation) matches
# one of the names. user@host patterns never count: the client address is not known here.
admits() {
	set -f
	for p in $1; do
		case $p in *@*|!*) continue ;; esac
		for n in $2; do
			case $n in $p) set +f; return 0 ;; esac
		done
	done
	set +f
	return 1
}

# decide <allowusers values> <allowgroups values> <groups of the audit user> <scope records>
# prints UNCHANGED, EDIT <file> <line> or MANUAL <reason>: <files>
decide() {
	m=$(printf '%s\n' "$4" | awk '$1 == "match" && $2 != "include" && $3 == 0 { print $4 }' | sort -u | tr '\n' ' ')
	inc=$(printf '%s\n' "$4" | awk '$2 == "include" { print $4 }' | sort -u | tr '\n' ' ')
	if [ -n "$m" ] && [ -n "$inc" ]; then
		# after an Include this script does not follow, a line may or may not sit in a Match block: say so
		printf '%s\n' "MANUAL AllowUsers or AllowGroups after an Include outside sshd_config.d/*.conf (it may open a Match block; edit by hand): ${inc% } ${m% }"
		return 0
	fi
	if [ -n "$m" ]; then
		printf '%s\n' "MANUAL AllowUsers or AllowGroups inside a Match block (sshd -T cannot evaluate it): ${m% }"
		return 0
	fi
	if [ -n "$2" ] && ! admits "$2" "$3"; then
		g=$(printf '%s\n' "$4" | awk '$2 == "allowgroups" { print $4 }' | sort -u | tr '\n' ' ')
		printf '%s\n' "MANUAL AllowGroups does not admit $AUDIT_USER (add it to an allowed group by hand): ${g% }"
		return 0
	fi
	if [ -z "$1" ] || admits "$1" "$AUDIT_USER"; then
		printf '%s\n' UNCHANGED
		return 0
	fi
	if [ -n "$inc" ]; then
		printf '%s\n' "MANUAL an Include outside sshd_config.d/*.conf may hold AllowUsers (edit by hand): ${inc% }"
		return 0
	fi
	u=$(printf '%s\n' "$4" | awk '$1 == "global" && $2 == "allowusers"')
	count=$(printf '%s\n' "$u" | grep -c . || true)
	files=$(printf '%s\n' "$u" | awk 'NF { print $4 }' | tr '\n' ' ')
	if [ "$count" -ne 1 ]; then
		printf '%s\n' "MANUAL AllowUsers is set on $count lines (only a single line is edited): ${files% }"
		return 0
	fi
	set -f
	set -- $u
	set +f
	case $4 in
	/etc/ssh/sshd_config) ;;
	/etc/ssh/sshd_config.d/*.conf)
		case ${4#/etc/ssh/sshd_config.d/} in */*|*[!A-Za-z0-9._-]*)
			printf '%s\n' "MANUAL AllowUsers is in an unexpected file: $4"; return 0 ;;
		esac ;;
	*) printf '%s\n' "MANUAL AllowUsers is in an unexpected file: $4"; return 0 ;;
	esac
	case $5 in ''|*[!0-9]*) printf '%s\n' "MANUAL AllowUsers line number unreadable: $4"; return 0 ;; esac
	if [ "${6:-0}" = 1 ]; then
		printf '%s\n' "MANUAL the AllowUsers line carries a comment (edited by hand): $4"
		return 0
	fi
	printf '%s\n' "EDIT $4 $5"
}

# The sshd configuration as `file<TAB>line<TAB>text`, in the order sshd reads it: the main file's lines up to
# the standard Include line, the sshd_config.d/*.conf files, then the rest of the main file. Any other Include,
# in the main file or nested in a sshd_config.d file, is passed on as `Include (unresolved)`: SCOPE_AWK reports
# it and decide() leaves any AllowUsers edit to the user (MANUAL, nothing changed).
config_stream() {
	awk '{
		w = tolower($1)
		if (w == "include" && $2 == "/etc/ssh/sshd_config.d/*.conf" && NF == 2) print "@@INCLUDE@@"
		else if (w == "include") printf "%s\t%d\tInclude (unresolved)\n", FILENAME, FNR
		else printf "%s\t%d\t%s\n", FILENAME, FNR, $0
	}' /etc/ssh/sshd_config </dev/null | while IFS= read -r rec; do
		if [ "$rec" = "@@INCLUDE@@" ]; then
			for f in /etc/ssh/sshd_config.d/*.conf; do
				if [ -f "$f" ]; then
					awk '{
						if (tolower($1) == "include") printf "%s\t%d\tInclude (unresolved)\n", FILENAME, FNR
						else printf "%s\t%d\t%s\n", FILENAME, FNR, $0
					}' "$f" </dev/null
				fi
			done
		else
			printf '%s\n' "$rec"
		fi
	done
}

allowusers_verdict() {
	t=$(sshd -T </dev/null 2>/dev/null) || die "sshd -T failed: fix the sshd configuration first"
	au=$(printf '%s\n' "$t" | awk '$1 == "allowusers" { print $2 }')
	ag=$(printf '%s\n' "$t" | awk '$1 == "allowgroups" { print $2 }')
	groups=$(id -Gn "$AUDIT_USER" 2>/dev/null </dev/null || echo "$AUDIT_USER")
	lines=$(config_stream | awk "$SCOPE_AWK")
	decide "$au" "$ag" "$groups" "$lines"
}

manual() {
	reason=$1
	say "ALLOWUSERS_MANUAL ${reason##*: }"
	printf '%s\n' "$reason" >&2
	exit 4
}

edit_allowusers() {
	f=$1
	n=$2
	bak="$f.sbom-audit.bak"
	new="$f.sbom-audit.new"
	orig=$(sed -n "${n}p" "$f" </dev/null)
	# decide() refuses a comment before anything changes; this is only a backstop (exit 1, not 4)
	case $orig in *'#'*) die "the AllowUsers line in $f carries a comment" ;; esac
	cp -p "$f" "$bak"
	cp -p "$f" "$new"
	awk -v n="$n" -v u="$AUDIT_USER" 'FNR == n { sub(/[ \t\r]+$/, ""); $0 = $0 " " u } { print }' "$bak" >"$new" </dev/null
	mv "$new" "$f"
	if ! sshd -t </dev/null >&2; then
		if ! cp "$bak" "$f"; then
			say "ALLOWUSERS_RESTORE_FAILED $f"
			exit 8
		fi
		say "ALLOWUSERS_FAILED sshd -t rejected the edited $f; restored, nothing reloaded"
		exit 5
	fi
	if ! { systemctl reload ssh || systemctl reload sshd; } </dev/null >&2; then
		if ! { cp "$bak" "$f" && sshd -t </dev/null >&2; }; then
			say "ALLOWUSERS_RESTORE_FAILED $f"
			exit 8
		fi
		if { systemctl reload ssh || systemctl reload sshd; } </dev/null >&2; then
			say "ALLOWUSERS_FAILED reloading sshd failed; $f restored and reloaded"
			exit 5
		fi
		say "ALLOWUSERS_RELOAD_FAILED $f"
		exit 9
	fi
	say "ALLOWUSERS_EDITED $f"
}

main() {
	[ $# -eq 3 ] || die "usage: sh -s -- <authorized_keys line> <sha256 collect> <sha256 lynis.prf>"
	[ "$(id -u)" = 0 ] || die "must run as root"
	key_line=$1
	nl='
'
	case $key_line in *"$nl"*|*"$(printf '\r')"*) die "the key line must be one line" ;; esac
	case $key_line in "$KEY_PREFIX"ssh-*|"$KEY_PREFIX"ecdsa-*|"$KEY_PREFIX"sk-*) ;; *) die "unexpected key line" ;; esac

	# the payload first: it is this function's stdin (the here-document)
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	awk -v m="$PRF_MARKER" -v a="$tmp/collect" -v b="$tmp/lynis.prf" \
		'BEGIN { o = a } $0 == m && o == a { o = b; next } { print > o }'
	if [ ! -f "$tmp/collect" ] || [ ! -f "$tmp/lynis.prf" ] \
			|| [ "$(sha256sum <"$tmp/collect" | cut -d' ' -f1)" != "$2" ] \
			|| [ "$(sha256sum <"$tmp/lynis.prf" | cut -d' ' -f1)" != "$3" ]; then
		say "PAYLOAD_CORRUPT"
		exit 7
	fi

	os=$( (. /etc/os-release && printf '%s' "${ID:-}") </dev/null 2>/dev/null || true)
	case $os in debian|ubuntu) ;; *) say "UNSUPPORTED ${os:-unknown}"; exit 3 ;; esac
	if ! command -v sudo >/dev/null 2>&1 || ! command -v visudo >/dev/null 2>&1; then
		say "NEEDS_SUDO"
		exit 6
	fi
	say "STEP os ok"

	# decided before anything changes: a manual case leaves the host untouched
	verdict=$(allowusers_verdict) || exit 1
	case $verdict in MANUAL*) manual "${verdict#MANUAL }" ;; esac
	say "STEP preflight ok"

	if id -u "$AUDIT_USER" >/dev/null 2>&1 </dev/null; then
		[ "$(id -u "$AUDIT_USER" </dev/null)" != 0 ] || die "user $AUDIT_USER has uid 0; refusing"
		usermod -d /var/lib/sbom-audit -s /bin/sh -p '*' sbom-audit </dev/null >&2 \
			|| die "usermod sbom-audit failed (exit $?): a process of sbom-audit may still run (an audit); retry later"
	else
		useradd --system --home-dir /var/lib/sbom-audit --shell /bin/sh sbom-audit </dev/null >&2 \
			|| die "useradd sbom-audit failed (exit $?)"
		usermod -p '*' sbom-audit </dev/null >&2 || die "usermod sbom-audit failed (exit $?)"
	fi
	say "STEP user ok"

	install -d -o root -g root -m 755 /var/lib/sbom-audit /var/lib/sbom-audit/.ssh </dev/null
	printf '%s\n' "$key_line" >/var/lib/sbom-audit/.ssh/authorized_keys.new
	chown root:root /var/lib/sbom-audit/.ssh/authorized_keys.new
	chmod 644 /var/lib/sbom-audit/.ssh/authorized_keys.new
	mv /var/lib/sbom-audit/.ssh/authorized_keys.new /var/lib/sbom-audit/.ssh/authorized_keys
	say "STEP home ok"

	install -d -o root -g root -m 755 /usr/local/lib/sbom-audit </dev/null
	install -o root -g root -m 755 "$tmp/collect" /usr/local/lib/sbom-audit/collect.new </dev/null
	install -o root -g root -m 644 "$tmp/lynis.prf" /usr/local/lib/sbom-audit/lynis.prf.new </dev/null
	mv /usr/local/lib/sbom-audit/collect.new /usr/local/lib/sbom-audit/collect
	mv /usr/local/lib/sbom-audit/lynis.prf.new /usr/local/lib/sbom-audit/lynis.prf
	say "STEP collector ok"

	printf '%s\n' "$SUDOERS_LINE" >/etc/sudoers.d/.sbom-audit.new
	chown root:root /etc/sudoers.d/.sbom-audit.new
	chmod 440 /etc/sudoers.d/.sbom-audit.new
	if ! visudo -cf /etc/sudoers.d/.sbom-audit.new </dev/null >&2; then
		rm -f /etc/sudoers.d/.sbom-audit.new
		die "visudo rejected the sudoers drop-in"
	fi
	mv /etc/sudoers.d/.sbom-audit.new /etc/sudoers.d/sbom-audit
	if ! visudo -c </dev/null >/dev/null 2>&1; then
		rm -f /etc/sudoers.d/sbom-audit
		die "visudo -c failed with the drop-in installed; removed it again"
	fi
	say "STEP sudoers ok"

	if ! command -v lynis >/dev/null 2>&1; then
		if ! DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt-get install -y -q -o DPkg::Lock::Timeout=300 lynis </dev/null >&2; then
			DEBIAN_FRONTEND=noninteractive apt-get update -q -o DPkg::Lock::Timeout=300 </dev/null >&2 || true
			DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt-get install -y -q -o DPkg::Lock::Timeout=300 lynis </dev/null >&2 \
				|| die "apt-get install lynis failed"
		fi
	fi
	say "STEP lynis ok"

	verdict=$(allowusers_verdict) || exit 1
	case $verdict in
	UNCHANGED) say "ALLOWUSERS_UNCHANGED" ;;
	EDIT\ *)
		set -f
		set -- $verdict
		set +f
		edit_allowusers "$2" "$3"
		;;
	*)	# the preflight said otherwise: something changed mid-run. Not exit 4: the user is already installed.
		die "AllowUsers verdict changed during the run: ${verdict#MANUAL }" ;;
	esac
	say "STEP allowusers ok"
	say "DONE"
}

main "$@" <<'SBOM_AUDIT_PAYLOAD_END'
