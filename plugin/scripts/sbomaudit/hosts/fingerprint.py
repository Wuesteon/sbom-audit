"""Host mode: the state fingerprint of a host and its diff against the accepted baseline.

`build` reduces `facts` to `{section: {key: value}}` string maps: only what an intruder or a careless
change would alter. Left out on purpose: the kernel and the reboot flag (they move with every patch;
`info` reports them), loopback sockets (ports change on restart; `info` reports them) and container image
digests. `diff` turns every added, removed or changed key into a critical `change` finding, except the two
noise rules that make a normal patch week quiet:

- a socket whose address and port stayed but whose process name changed is `info`;
- a unit or cron file changed or added by a package whose installed version differs from the version
  seen at the last accepted check is `info` ("explained by package update"), and the new value goes into
  the returned `explained` map, which the caller merges into the baseline. Unowned files and owners whose
  version did not change stay `change`.
"""
from __future__ import annotations

import ipaddress
import re

SSHD_KEYS = ("permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication", "pubkeyauthentication",
             "permitemptypasswords", "allowusers", "allowgroups", "authorizedkeysfile", "authorizedkeyscommand",
             "trustedusercakeys", "authenticationmethods", "port", "listenaddress", "usepam", "x11forwarding")
SECTIONS = ("users", "sudoers", "authorized_keys", "sockets", "units", "cron", "sshd", "firewall",
            "apt_sources", "containers", "host_keys")
EXPLAINABLE = ("units", "cron")
URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@]*@")


def is_loopback(addr: str) -> bool:
    host = addr.strip().strip("[]").split("%", 1)[0].lower()
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    return (mapped or ip).is_loopback


def socket_key(s: dict) -> str:
    return f"{s['proto']}/{s['addr']}:{s['port']}"


def build(facts: dict) -> dict[str, dict[str, str]]:
    firewall = facts.get("firewall") or {}
    sshd = facts.get("sshd") or {}
    return {
        "users": {u["name"]: f"uid={u['uid']} shell={u['shell']} groups={','.join(sorted(u['groups']))}"
                  for u in facts["users"]},
        "sudoers": {path: f"{v['sha256']} {','.join(sorted(v['principals']))}"
                    for path, v in facts["sudoers"].items()},
        "authorized_keys": {f"{user}/{k['fp']}": k["type"]
                            for user, keys in facts["authorized_keys"].items() for k in keys},
        "sockets": {socket_key(s): s["process"] for s in facts["sockets"] if not is_loopback(s["addr"])},
        "units": {unit: v["sha256"] or "" for unit, v in facts["units"].items()},
        "cron": dict(facts["cron"]),
        "sshd": {k: str(sshd[k]) for k in SSHD_KEYS if k in sshd},
        "firewall": {"default_incoming": firewall.get("default_incoming") or "",
                     "ruleset": firewall.get("ruleset_sha256") or ""},
        "apt_sources": {URL_USERINFO.sub(r"\1", line): "" for line in facts["apt_sources"]},
        "containers": {c["name"]: c["ports"] for c in facts["containers"]},
        "host_keys": {k["type"]: k["fp"] for k in facts["host_keys"]},
    }


def finding(fid: str, group: str, critical: bool, text: str) -> dict:
    return {"id": fid, "group": group, "critical": critical, "text": text}


def info(facts: dict) -> list[dict]:
    """Kernel, reboot flag and loopback sockets: shown, never compared."""
    out = [finding("info:kernel", "info", False, f"running kernel {facts['kernel']}")]
    if facts["reboot_required"]:
        out.append(finding("info:reboot-required", "info", False, "reboot required"))
    for s in sorted(facts["sockets"], key=socket_key):
        if is_loopback(s["addr"]):
            out.append(finding(f"info:loopback:{socket_key(s)}", "info", False,
                               f"loopback socket {socket_key(s)} ({s['process']})"))
    return out


def installed_versions(facts: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in facts["packages"]:
        out.setdefault(p["name"], p["version"])
    return out


def path_of(facts: dict, section: str, key: str) -> str | None:
    if section == "units":
        return (facts["units"].get(key) or {}).get("path")
    return key


def describe(section: str, op: str, key: str, old: str | None, new: str | None) -> str:
    if op == "+":
        return f"{section}: added {key}" + (f" ({new})" if new else "")
    if op == "-":
        return f"{section}: removed {key}" + (f" (was {old})" if old else "")
    return f"{section}: {key} changed ({old} → {new})"


def diff(baseline: dict, current: dict, facts: dict, packages_seen: dict[str, str]) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    explained: dict[str, dict[str, str]] = {}
    installed = installed_versions(facts)
    for section in SECTIONS:
        old_map = baseline.get(section) or {}
        new_map = current.get(section) or {}
        changes = [("+", k) for k in new_map if k not in old_map]
        changes += [("-", k) for k in old_map if k not in new_map]
        changes += [("~", k) for k in new_map if k in old_map and new_map[k] != old_map[k]]
        for op, key in sorted(changes, key=lambda c: (c[1], c[0])):
            old, new = old_map.get(key), new_map.get(key)
            fid = f"change:{section}:{op}{key}"
            text = describe(section, op, key, old, new)
            if section == "sockets" and op == "~":
                findings.append(finding(fid, "info", False, text))
                continue
            if section in EXPLAINABLE and op in ("+", "~"):
                owner = (facts.get("owners") or {}).get(path_of(facts, section, key) or "")
                was, now = packages_seen.get(owner) if owner else None, installed.get(owner) if owner else None
                if was and now and was != now:
                    findings.append(finding(fid, "info", False,
                                            f"{text}, explained by package update ({owner} {was} → {now})"))
                    explained.setdefault(section, {})[key] = new
                    continue
            findings.append(finding(fid, "change", True, text))
    return findings, explained
