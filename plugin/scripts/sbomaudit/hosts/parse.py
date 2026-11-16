"""Collector document (stdout of `templates/hosts/collect.sh`) → `facts`.

The document is `{"collector": "<version>", "started": <epoch>, "sections": {name: {"rc": n, "out": text}}}`.
`parse` turns each raw section into the `facts` shape the other host-mode modules consume; one private
parser per section. A section that failed (non-zero rc, except where a non-zero rc is a normal answer)
or is missing is recorded in `facts["errors"]` and parsed as empty, so stale or garbled text never
becomes a fact.

Builder choices the spec leaves open, fixed here:
- `packages` keeps every package whose dpkg status is installed (`ii`, and `hi` for held packages).
- `origins[pkg]` has one entry per (version, repository) of `apt-cache policy`; `origin` is the
  repository URL and `suite` its distribution without the component; `origin_name` is the repository's
  release `o=` field (`Ubuntu`, `Debian`, `Docker`, `LP-PPA-x`), read from the unfiltered "Package files:"
  listing the collector appends to the policy section, or None when absent. A version that only
  `/var/lib/dpkg/status` knows gets one entry with `origin` "/var/lib/dpkg/status", `suite`/`site` None.
- `firewall.default_incoming` is ufw's word (`deny`, `reject`, `allow`) or the lowercased iptables
  policy (`drop`, `accept`).
- Login times are UTC (`...Z`). The collector reads the journal in UTC; auth.log times are local and
  are shifted by the host's offset (the `Z` line). A classic syslog time gets the year of `started`.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

COLLECT_SH = Path(__file__).resolve().parents[3] / "templates" / "hosts" / "collect.sh"

SECTIONS = ("os", "kernel", "reboot", "dpkg", "upgradable", "policy", "apt_config", "uu_timer", "uu_log",
            "passwd", "group", "sudoers", "authorized_keys", "sockets", "units", "cron", "owners", "sshd",
            "host_keys", "firewall", "apparmor", "apt_sources", "containers", "logins", "lynis", "binaries")
# Exit codes that are an answer, not a failure, per section: no reboot pending (1), timer state
# (is-active 3), unowned paths (dpkg -S 1), AppArmor off or without policy (aa-status 1, 2). Any other
# non-zero rc (a timeout's 124, a missing tool's 127) is an error. Lynis's rc becomes its own `error`.
RC_ANSWERS = {"reboot": frozenset({0, 1}), "uu_timer": frozenset({0, 1, 3}), "owners": frozenset({0, 1}),
              "apparmor": frozenset({0, 1, 2})}
OWN_ERROR = frozenset({"lynis"})
DIGITS = re.compile(r"[0-9]+")  # str.isdigit() accepts "²", which int() rejects
PRIORITY = re.compile(r"-?[0-9]+")
SUPPORTED_OS = frozenset({"debian", "ubuntu"})
NO_LOGIN_SHELL = re.compile(r"(nologin|false|sync)$")
LIST_KEYS = ("Unattended-Upgrade::Allowed-Origins", "Unattended-Upgrade::Origins-Pattern",
             "Unattended-Upgrade::Package-Blacklist", "Unattended-Upgrade::Package-Whitelist")
DPKG_STATUS = "/var/lib/dpkg/status"


class CollectorError(Exception):
    """The input is not a collector document."""


def _shipped_version(path: Path = COLLECT_SH) -> str:
    match = re.search(r"^COLLECTOR_VERSION=[\"']?([0-9A-Za-z.]+)[\"']?\s*$", path.read_text(), re.M)
    if not match:
        raise RuntimeError(f"{path}: no COLLECTOR_VERSION line")
    return match.group(1)


SHIPPED_VERSION = _shipped_version()


def parse(doc: dict) -> dict:
    if not isinstance(doc, dict) or not isinstance(doc.get("sections"), dict) or "collector" not in doc \
            or not isinstance(doc.get("started"), int) or isinstance(doc.get("started"), bool):
        raise CollectorError("not a collector document")
    try:
        started = datetime.fromtimestamp(doc["started"], timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise CollectorError("not a collector document: bad started") from exc
    errors: dict[str, str] = {}
    raw: dict[str, tuple[int | None, str]] = {}
    for name in SECTIONS:
        rc, out = _section(doc["sections"], name)
        if rc is None:
            errors[name] = "missing"
        elif name not in OWN_ERROR and rc not in RC_ANSWERS.get(name, (0,)):
            first = next((line.strip() for line in out.splitlines() if line.strip()), "")
            errors[name] = f"rc {rc}: {first}" if first else f"rc {rc}"
        raw[name] = (rc, "" if name in errors else out)

    def out(name: str) -> str:
        return raw[name][1]

    facts: dict = {"collector": str(doc["collector"])}

    def fact(key: str, section: str, value, default) -> None:
        """facts[key] = value(); a parser that fails on garbage gives the empty default and an error."""
        try:
            facts[key] = value()
        except Exception as exc:  # noqa: BLE001 - any garbage in one section must not sink the others
            errors.setdefault(section, f"unparseable: {type(exc).__name__}")
            facts[key] = default

    fact("os", "os", lambda: _os(out("os")), _os(""))
    fact("kernel", "kernel", lambda: out("kernel").strip(), "")
    fact("reboot_required", "reboot", lambda: raw["reboot"][0] == 0 and "reboot" not in errors, False)
    fact("packages", "dpkg", lambda: _packages(out("dpkg")), [])
    fact("upgradable", "upgradable", lambda: _upgradable(out("upgradable")), {})
    fact("origins", "policy", lambda: _origins(out("policy")), {})
    fact("apt_config", "apt_config", lambda: _apt_config(out("apt_config")), {})
    fact("uu_timer", "uu_timer", lambda: _uu_timer(out("uu_timer")), _uu_timer(""))
    fact("uu_last_run", "uu_log", lambda: _uu_last_run(out("uu_log")), None)
    fact("users", "passwd", lambda: _users(out("passwd"), out("group")), [])
    fact("sudoers", "sudoers", lambda: _sudoers(out("sudoers")), {})
    fact("authorized_keys", "authorized_keys", lambda: _authorized_keys(out("authorized_keys")), {})
    fact("sockets", "sockets", lambda: _sockets(out("sockets")), [])
    fact("units", "units", lambda: _units(out("units")), {})
    fact("cron", "cron", lambda: _cron(out("cron")), {})
    paths = [u["path"] for u in facts["units"].values() if u["path"]] + list(facts["cron"])
    fact("owners", "owners", lambda: _owners(out("owners"), paths), {})
    fact("sshd", "sshd", lambda: _sshd(out("sshd")), {})
    fact("host_keys", "host_keys", lambda: _host_keys(out("host_keys")), [])
    fact("firewall", "firewall", lambda: _firewall(out("firewall")), _firewall(""))
    fact("apparmor", "apparmor", lambda: _apparmor(out("apparmor")), _apparmor(""))
    fact("apt_sources", "apt_sources",
         lambda: [line.strip() for line in out("apt_sources").splitlines() if line.strip()], [])
    fact("containers", "containers", lambda: _containers(out("containers")), [])
    fact("logins", "logins", lambda: _logins(out("logins"), started), _logins("", started))
    notes = [rest.strip() for kind, _, rest in (line.partition("\t") for line in out("logins").splitlines())
             if kind == "E"]
    if notes:  # a log reader failed or timed out: the logins are incomplete
        errors.setdefault("logins", "; ".join(notes))
    fact("lynis", "lynis", lambda: _lynis(*raw["lynis"]), _lynis(raw["lynis"][0], ""))
    fact("binaries", "binaries", lambda: _binaries(out("binaries")), [])
    facts["errors"] = errors
    return facts


def _section(sections: dict, name: str) -> tuple[int | None, str]:
    s = sections.get(name)
    if not isinstance(s, dict) or not isinstance(s.get("out"), str) \
            or not isinstance(s.get("rc"), int) or isinstance(s.get("rc"), bool):
        return None, ""
    return s["rc"], s["out"]


def _os(text: str) -> dict:
    vals = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and re.fullmatch(r"[A-Z0-9_]+", key):
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            vals[key] = value
    os_id = vals.get("ID", "").lower() or None
    return {"id": os_id, "version_id": vals.get("VERSION_ID") or None,
            "codename": vals.get("VERSION_CODENAME") or vals.get("UBUNTU_CODENAME") or None,
            "supported": os_id in SUPPORTED_OS}


def _packages(text: str) -> list[dict]:
    packages = []
    for stanza in re.split(r"\n\s*\n", text):
        fields = {}
        for line in stanza.splitlines():
            key, sep, value = line.partition(": ")
            if sep:
                fields[key.strip()] = value.strip()
        status = fields.get("Status", "").split()
        if not fields.get("Package") or len(status) != 3 or status[2] != "installed":
            continue
        name, version = fields["Package"], fields.get("Version", "")
        source = re.fullmatch(r"(\S+) \((.*)\)", fields.get("Source", ""))
        packages.append({"name": name, "version": version, "arch": fields.get("Architecture", ""),
                         "source": source.group(1) if source else name,
                         "source_version": (source.group(2) if source else "") or version})
    return packages


def _upgradable(text: str) -> dict[str, dict]:
    result = {}
    for line in text.splitlines():
        m = re.match(r"^([^/\s]+)/(\S+) (\S+) \S+ \[upgradable from: ([^\]]+)\]", line)
        if m:
            result[m.group(1)] = {"installed": m.group(4), "candidate": m.group(3), "suite": m.group(2)}
    return result


def _release_names(text: str) -> dict[tuple[str, str], str]:
    """(repository URL, suite) -> release `o=` value, from the "Package files:" listing of `apt-cache policy`."""
    names: dict[tuple[str, str], str] = {}
    key = None
    for line in text.splitlines():
        toks = line.split()
        if len(toks) >= 3 and PRIORITY.fullmatch(toks[0]) and "://" in toks[1]:
            key = (toks[1], toks[2].split("/")[0])
        elif toks and toks[0] == "release" and key is not None and len(toks) > 1:
            for part in toks[1].split(","):
                k, _, v = part.partition("=")
                if k == "o" and v:
                    names[key] = v
        elif toks and PRIORITY.fullmatch(toks[0]):
            key = None
    return names


def _origins(text: str) -> dict[str, list[dict]]:
    cut = ("\n" + text).find("\nPackage files:\n")
    names = _release_names(text[cut:]) if cut >= 0 else {}
    text = text[:max(cut, 0)] if cut >= 0 else text
    origins: dict[str, list[dict]] = {}
    name = installed = candidate = version = None
    table: list[tuple[str, list[dict], bool]] = []  # (version, repository entries, known to dpkg status)

    def flush() -> None:
        if name is None:
            return
        entries = []
        for ver, repos, in_status in table:
            if repos:
                entries += repos
            elif in_status:
                entries.append({"version": ver, "origin": DPKG_STATUS, "suite": None, "site": None,
                                "origin_name": None, "installed": ver == installed, "candidate": ver == candidate})
        origins[name] = entries

    for line in text.splitlines():
        if line and not line[0].isspace() and line.endswith(":"):
            flush()
            name, installed, candidate, version, table = line[:-1], None, None, None, []
            continue
        if name is None:
            continue
        s = line.strip()
        if s.startswith("Installed:"):
            installed = s.split(":", 1)[1].strip()
        elif s.startswith("Candidate:"):
            candidate = s.split(":", 1)[1].strip()
        elif s and not s.startswith("Version table"):
            toks = s.split()
            if toks[0] == "***":  # marks the installed version
                toks = toks[1:]
            is_source = len(toks) >= 2 and PRIORITY.fullmatch(toks[0]) and ("://" in toks[1] or toks[1].startswith("/"))
            if not is_source:
                # "<version> <priority>", maybe followed by "(phased 20%)"
                if len(toks) >= 2 and PRIORITY.fullmatch(toks[1]):
                    version = toks[0]
                    table.append((version, [], False))
            elif version is not None:
                if toks[1] == DPKG_STATUS:
                    table[-1] = (table[-1][0], table[-1][1], True)
                else:
                    suite = toks[2].split("/")[0] if len(toks) > 2 else None
                    table[-1][1].append({"version": version, "origin": toks[1], "suite": suite,
                                         "origin_name": names.get((toks[1], suite)),
                                         "site": urlsplit(toks[1]).hostname,
                                         "installed": version == installed, "candidate": version == candidate})
    flush()
    return origins


def _apt_config(text: str) -> dict:
    cfg: dict = {}
    lists: dict[str, list[str]] = {}
    for line in text.splitlines():
        m = re.match(r'^(\S+) "(.*)";\s*$', line)
        if not m:
            continue
        key, value = m.groups()
        if key.endswith("::"):
            lists.setdefault(key[:-2], []).append(value)
        else:
            cfg[key] = value
    for key in LIST_KEYS:
        if cfg.get(key) == "":
            cfg[key] = []
    cfg.update(lists)
    return cfg


def _uu_timer(text: str) -> dict:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return {"enabled": lines[0] if lines else "unknown", "active": lines[1] if len(lines) > 1 else "unknown"}


def _uu_last_run(text: str) -> str | None:
    last = None
    for line in text.splitlines():
        m = re.match(r"^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})", line)
        if m and "Starting unattended upgrades script" in line:
            last = f"{m.group(1)}T{m.group(2)}"
    return last


def _users(passwd: str, group: str) -> list[dict]:
    gid_name: dict[str, str] = {}
    member_of: dict[str, set[str]] = {}
    for line in group.splitlines():
        parts = line.split(":")
        if len(parts) >= 4:
            gid_name[parts[2]] = parts[0]
            for member in filter(None, parts[3].split(",")):
                member_of.setdefault(member, set()).add(parts[0])
    users = []
    for line in passwd.splitlines():
        parts = line.split(":")
        if len(parts) < 7 or not DIGITS.fullmatch(parts[2]):
            continue
        name, uid, gid, shell = parts[0], int(parts[2]), parts[3], parts[6]
        if uid != 0 and NO_LOGIN_SHELL.search(shell):
            continue
        groups = set(member_of.get(name, set()))
        if gid in gid_name:
            groups.add(gid_name[gid])
        users.append({"name": name, "uid": uid, "shell": shell, "groups": sorted(groups)})
    return users


def _sudoers(text: str) -> dict[str, dict]:
    result = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and re.fullmatch(r"[0-9a-f]{64}", parts[1]):
            result[parts[0]] = {"sha256": parts[1], "principals": sorted(set(filter(None, parts[2].split(","))))}
    return result


def _key_line(text: str) -> tuple[str, str, str] | None:
    """`<bits> <fingerprint> (<TYPE>)` → (bits, fp, TYPE)."""
    toks = text.split()
    if len(toks) < 3 or not DIGITS.fullmatch(toks[0]) or ":" not in toks[1]:
        return None
    return toks[0], toks[1], toks[-1].strip("()")


def _authorized_keys(text: str) -> dict[str, list[dict]]:
    result: dict[str, list[dict]] = {}
    for line in text.splitlines():
        user, sep, rest = line.partition("\t")
        key = _key_line(rest) if sep else None
        if key:
            bits, fp, key_type = key
            result.setdefault(user, []).append({"type": key_type, "fp": fp, "bits": bits})
    return result


def _sockets(text: str) -> list[dict]:
    sockets, seen = [], set()
    for line in text.splitlines():
        toks = line.split()
        if len(toks) < 5 or toks[0] not in ("tcp", "udp"):
            continue
        addr, _, port = toks[4].rpartition(":")
        if addr.startswith("[") and addr.endswith("]"):
            addr = addr[1:-1]
        addr = addr.split("%", 1)[0]
        if not DIGITS.fullmatch(port) or (toks[0], addr, int(port)) in seen:
            continue
        seen.add((toks[0], addr, int(port)))
        process = re.search(r'users:\(\("([^"]*)"', line)
        sockets.append({"proto": toks[0], "addr": addr, "port": int(port),
                        "process": process.group(1) if process else ""})
    return sockets


def _units(text: str) -> dict[str, dict]:
    result = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[0]:
            result[parts[0]] = {"path": None if parts[1] == "-" else parts[1],
                                "sha256": None if parts[2] == "-" else parts[2]}
    return result


def _cron(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        m = re.fullmatch(r"([0-9a-f]{64}) [ *](/.+)", line)
        if m:
            result[m.group(2)] = m.group(1)
    return result


def _owners(text: str, paths: list[str]) -> dict[str, str]:
    owners = {}
    for line in text.splitlines():
        if line.startswith(("diversion by", "dpkg-query:", "dpkg:")):
            continue
        pkgs, sep, path = line.partition(": ")
        if sep and path.startswith("/"):
            owners[path] = pkgs.split(",")[0].strip().split(":")[0]
    for path in paths:  # dpkg before 1.22 knows /lib/... where systemd reports /usr/lib/... (and back)
        if path not in owners:
            alias = path[4:] if path.startswith("/usr/") else "/usr" + path
            if alias in owners:
                owners[path] = owners[alias]
    return owners


def _sshd(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        key, _, value = line.strip().partition(" ")
        if key:
            result[key] = f"{result[key]} {value}" if key in result else value
    return result


def _host_keys(text: str) -> list[dict]:
    keys = []
    for line in text.splitlines():
        key = _key_line(line)
        if key:
            keys.append({"type": key[2].lower(), "fp": key[1]})
    return keys


def _firewall(text: str) -> dict:
    lines = text.splitlines()
    if any(line.startswith("Status: active") for line in lines):
        default = re.search(r"^Default: (\w+) \(incoming\)", text, re.M)
        dash = next((i for i, line in enumerate(lines) if line.startswith("--")), len(lines))
        rules = "\n".join(line.rstrip() for line in lines[dash + 1:] if line.strip())
        return {"tool": "ufw", "default_incoming": default.group(1) if default else None,
                "ruleset_sha256": hashlib.sha256(rules.encode()).hexdigest()}
    policy = re.search(r"^-P INPUT (\S+)", text, re.M)
    if policy:
        digest = re.search(r"^([0-9a-f]{64})\b", text, re.M)
        return {"tool": "iptables", "default_incoming": policy.group(1).lower(),
                "ruleset_sha256": digest.group(1) if digest else None}
    return {"tool": "none", "default_incoming": None, "ruleset_sha256": None}


def _apparmor(text: str) -> dict:
    lines = text.splitlines()
    enabled = bool(lines) and lines[0].strip() == "Y"
    complain: list[str] = []
    enforce = 0
    data = next((line for line in lines[1:] if line.lstrip().startswith("{")), None)
    try:
        profiles = json.loads(data).get("profiles", {}) if data else None
    except (ValueError, AttributeError):
        profiles = None
    if isinstance(profiles, dict):
        complain = sorted(p for p, mode in profiles.items() if mode == "complain")
        enforce = sum(1 for mode in profiles.values() if mode == "enforce")
    else:
        mode = None
        for line in lines[1:]:
            m = re.match(r"^\s*(\d+) profiles are in (\w+) mode\.", line)
            if m:
                mode = m.group(2)
                if mode == "enforce":
                    enforce = int(m.group(1))
            elif re.match(r"^\s*\d+ ", line) or not line[:1].isspace():
                mode = None
            elif mode == "complain" and line.strip():
                complain.append(line.strip())
        complain.sort()
    return {"enabled": enabled, "complain": complain, "enforce_count": enforce}


def _containers(text: str) -> list[dict]:
    result = []
    for line in text.splitlines():
        name, sep, ports = line.partition("\t")
        if sep and name:
            result.append({"name": name, "ports": ports.strip()})
    return result


TS_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?", re.ASCII)
TS_SYSLOG = re.compile(r"^([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})", re.ASCII)
MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
                                      "Nov", "Dec"), start=1)}
# The sshd message starts after "sshd[pid]: ". Only a message that STARTS with "Accepted " is a login:
# a client chooses its user name, and "x Accepted publickey for root ..." inside one must stay text.
SSHD_MSG = re.compile(r"sshd(?:-session)?\[[0-9]+\]: ")
ACCEPTED = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port [0-9]+(?: [^:\s]+)?(?:: (\S+) ((?:SHA256|MD5):\S+))?")


def _zone(text: str) -> timezone | None:
    if text == "Z":
        return timezone.utc
    m = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", text)
    if not m:
        return None
    offset = timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))
    try:
        return timezone(-offset if m.group(1) == "-" else offset)
    except ValueError:  # beyond ±24 h, e.g. "+9999"
        return None


def _login_time(line: str, zone: timezone, started: datetime) -> str:
    try:
        m = TS_ISO.match(line)
        if m:
            dt = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=_zone(m.group(2) or "") or zone)
        else:
            m = TS_SYSLOG.match(line)
            dt = datetime(started.year, MONTHS[m.group(1)], int(m.group(2)), int(m.group(3)), int(m.group(4)),
                          int(m.group(5)), tzinfo=zone)
            if dt > started + timedelta(days=1):  # a December line read in January
                dt = dt.replace(year=started.year - 1)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (AttributeError, KeyError, ValueError, OverflowError):
        # unreadable or impossible time: keep the login, dated at collection, rather than drop it
        return started.strftime("%Y-%m-%dT%H:%M:%SZ")


def _logins(text: str, started: datetime) -> dict:
    lines = [line.partition("\t") for line in text.splitlines()]
    source = next((rest.strip() for kind, _, rest in lines if kind == "S"), "none")
    zone = next((_zone(rest.strip()) for kind, _, rest in lines if kind == "Z"), None) or timezone.utc
    accepted, failures = [], {}
    for kind, _, rest in lines:
        if kind == "A":
            head = SSHD_MSG.search(rest)
            m = ACCEPTED.match(rest, head.end()) if head else None
            if m:
                accepted.append({"time": _login_time(rest, zone, started), "user": m.group(2),
                                 "method": m.group(1).split("/")[0], "fp": m.group(5), "key_type": m.group(4),
                                 "ip": m.group(3)})
        elif kind == "F":
            parts = rest.split("\t")
            if len(parts) != 3 or not DIGITS.fullmatch(parts[2]):
                continue
            hour = parts[0]
            if source == "auth.log":
                try:
                    hour = datetime.strptime(hour, "%Y-%m-%dT%H").replace(tzinfo=zone) \
                        .astimezone(timezone.utc).strftime("%Y-%m-%dT%H")
                except (ValueError, OverflowError):
                    continue
            failures[(hour, parts[1])] = failures.get((hour, parts[1]), 0) + int(parts[2])
    return {"source": source if source in ("journal", "auth.log") else None, "accepted": accepted,
            "failures": [{"hour": h, "ip": ip, "count": n} for (h, ip), n in sorted(failures.items())]}


def _lynis(rc: int | None, text: str) -> dict:
    start = mtime = index = None
    warnings, suggestions = [], []
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if line.startswith("START ") and DIGITS.fullmatch(line[6:].strip()):
            start = int(line[6:])
        elif line.startswith("MTIME ") and DIGITS.fullmatch(line[6:].strip()):
            mtime = int(line[6:])
        elif key == "hardening_index" and DIGITS.fullmatch(value.strip()):
            index = int(value)
        elif key in ("warning[]", "suggestion[]"):
            parts = value.split("|")
            text_ = parts[1] if len(parts) > 1 else ""
            if len(parts) > 2 and parts[2] not in ("", "-"):
                text_ = f"{text_} ({parts[2]})"
            (warnings if key == "warning[]" else suggestions).append({"id": parts[0], "text": text_})
    if rc is None:
        error = "missing"
    elif rc == 127:
        error = "lynis profile missing" if "profile missing" in text else "lynis not installed"
    elif rc == 124:
        error = "timed out"
    elif start is None or mtime is None or mtime < start:
        error = "report not refreshed"
    elif rc != 0:
        error = f"rc {rc}"
    else:
        error = None
    if error:
        return {"ok": False, "index": None, "warnings": [], "suggestions": [], "error": error}
    return {"ok": True, "index": index, "warnings": warnings, "suggestions": suggestions, "error": None}


def _binaries(text: str) -> list[dict]:
    """`<name>\\t<path>\\t<owner or ->\\t<version line>` per binary run; `U\\t<name>\\t<path>` for one the
    collector did not run because someone other than root can change it (collector 3)."""
    result = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[0] == "U" and parts[1]:
            result.append({"name": parts[1], "path": parts[2], "owner": None, "version": "", "untrusted": True})
        elif len(parts) == 4 and parts[0]:
            result.append({"name": parts[0], "path": parts[1], "owner": None if parts[2] == "-" else parts[2],
                           "version": parts[3]})
    return result
