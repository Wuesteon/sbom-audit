"""Host mode rules on `facts`: patch automation, permissive defaults, Lynis and third-party package sources.

Spec checks 4 to 7 and decision 14. Every function returns `list[dict]` findings (`id`, `group`,
`critical`, `text`, plus extras). Builder choices the spec leaves open:
- A firewall policy of `drop`, `reject` or `deny` is fine; `allow` or `accept` is permissive. No firewall
  found (`firewall.tool == "none"`, which includes an inactive ufw) is `permissive:firewall-none`, and a
  firewall without a readable incoming policy is `permissive:firewall-incoming-unknown`; neither is critical.
- `patch:automatic-reboot` and `lynis:unavailable` are group `info`.
- Third-party means: no repository of the installed version has an apt release `o=` of Ubuntu, Debian or
  Ubuntu ESM (so a provider mirror counts as the distro); where the collector gave no `o=`, the host name
  (`*.ubuntu.com`, `*.debian.org`) decides.
- A package whose installed version only dpkg knows (no repository lists it) has no origin site and is
  not reported as third-party.
- The unattended-upgrades log carries host-local times without an offset; `now` is compared as given.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

MAX_RUN_AGE = timedelta(days=3)
INDEX_DROP = 5
UU_ORIGINS = ("Unattended-Upgrade::Allowed-Origins", "Unattended-Upgrade::Origins-Pattern")
DISTRO_DOMAINS = ("ubuntu.com", "debian.org")      # fallback when apt gives no release o=: archive, security, esm
DISTRO_RELEASE_NAMES = ("Ubuntu", "Debian", "UbuntuESM", "UbuntuESMApps")   # apt release o= of a distro archive
PERMISSIVE_POLICIES = ("allow", "accept")
PERMISSIVE_SSHD = ("passwordauthentication", "permitrootlogin", "kbdinteractiveauthentication")


def _finding(id_: str, group: str, critical: bool, text: str, **extra) -> dict:
    return {"id": id_, "group": group, "critical": critical, "text": text, **extra}


# --------------------------------------------------------------------------- patch automation

def _distro_id(facts: dict) -> str:
    raw = (facts.get("os") or {}).get("id") or ""
    return raw[:1].upper() + raw[1:]


def _as_list(value) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def _expand(entry: str, distro_id: str, codename: str) -> str:
    return entry.replace("${distro_id}", distro_id).replace("${distro_codename}", codename)


def _pattern(entry: str) -> dict[str, str] | None:
    """`origin=Debian,codename=bookworm-security,label=Debian-Security` -> {"o": ..., "n": ..., "l": ...}"""
    if "=" not in entry:
        return None
    aliases = {"origin": "o", "archive": "a", "suite": "a", "codename": "n", "label": "l", "site": "s",
               "component": "c", "version": "v"}
    out = {}
    for part in entry.split(","):
        key, _, value = part.partition("=")
        key = key.strip().lower()
        out[aliases.get(key, key)] = value.strip().lower()
    return out


def _classify(entry: str, distro_id: str, codename: str) -> str:
    """"security", "release", "esm" or "other" for one expanded Allowed-Origins / Origins-Pattern entry."""
    low = entry.strip().lower()
    did, cn = distro_id.lower(), codename.lower()
    pat = _pattern(entry)
    if pat is not None:
        origin, suite, name, label = pat.get("o", ""), pat.get("a", ""), pat.get("n", ""), pat.get("l", "")
        if origin.startswith("ubuntuesm") or suite.endswith(("-infra-security", "-apps-security")) \
                or name.endswith(("-infra-security", "-apps-security")):
            return "esm"
        if suite == f"{cn}-security" or name == f"{cn}-security" \
                or (label == "debian-security" and name in (cn, f"{cn}-security")):
            return "security"
        if cn and cn in (suite, name) and label != "debian-security" and origin == did:
            return "release"
        return "other"
    origin, _, suite = low.partition(":")
    if origin.startswith("ubuntuesm") or suite.endswith(("-infra-security", "-apps-security")):
        return "esm"
    if origin in (did, "debian-security") and suite == f"{cn}-security":
        return "security"
    if origin == did and suite == cn:
        return "release"
    return "other"


def patch_automation(facts: dict, now: datetime) -> list[dict]:
    findings: list[dict] = []
    cfg = facts.get("apt_config") or {}

    if cfg.get("APT::Periodic::Unattended-Upgrade") != "1":
        value = cfg.get("APT::Periodic::Unattended-Upgrade")
        findings.append(_finding("patch:periodic-off", "patch", True,
                                 "APT::Periodic::Unattended-Upgrade is "
                                 f"{'not set' if value is None else repr(value)}, not \"1\": "
                                 "unattended upgrades are not enabled"))

    distro_id, codename = _distro_id(facts), (facts.get("os") or {}).get("codename") or ""
    entries = [e for key in UU_ORIGINS for e in _as_list(cfg.get(key))]
    classes = [(e, _classify(_expand(e, distro_id, codename), distro_id, codename)) for e in entries]
    if not any(kind == "security" for _, kind in classes):
        findings.append(_finding("patch:no-security-origin", "patch", True,
                                 f"no {distro_id or 'distribution'}:{codename or '<codename>'}-security origin "
                                 "is allowed for unattended upgrades: security updates are not installed "
                                 "automatically"))
    for entry, kind in classes:
        if kind == "other":
            findings.append(_finding(f"origin:{entry}", "patch", False,
                                     f"unattended upgrades also install from {entry!r}", entry=entry))

    timer = facts.get("uu_timer") or {}
    if timer.get("active") != "active":
        findings.append(_finding("patch:timer-inactive", "patch", True,
                                 f"apt-daily-upgrade.timer is {timer.get('active', 'unknown')} "
                                 f"({timer.get('enabled', 'unknown')}), not active"))

    last = facts.get("uu_last_run")
    if not last:
        findings.append(_finding("patch:no-run-found", "patch", True,
                                 "no unattended-upgrades run found in its log"))
    else:
        try:
            ran = datetime.fromisoformat(last)
        except ValueError:
            ran = None
        ref = now.astimezone(timezone.utc).replace(tzinfo=None) if now.tzinfo else now
        if ran is None:
            findings.append(_finding("patch:no-run-found", "patch", True,
                                     f"unattended-upgrades run time {last!r} is not a date"))
        elif ran.tzinfo is not None:
            ran = ran.astimezone(timezone.utc).replace(tzinfo=None)
        if ran is not None and ref - ran > MAX_RUN_AGE:
            days = (ref - ran).days
            findings.append(_finding("patch:last-run-old", "patch", True,
                                     f"last unattended-upgrades run {last} is {days} days old "
                                     f"(limit {MAX_RUN_AGE.days})", last_run=last))

    reboot = cfg.get("Unattended-Upgrade::Automatic-Reboot", "false")
    at = cfg.get("Unattended-Upgrade::Automatic-Reboot-Time")
    on = str(reboot).strip().lower() in ("true", "1", "yes", "on")
    findings.append(_finding("patch:automatic-reboot", "info", False,
                             f"Automatic-Reboot {reboot}" + (f" at {at}" if on and at else ""),
                             automatic_reboot=on, time=at))
    return findings


# --------------------------------------------------------------------------- permissive defaults

def permissive(facts: dict) -> list[dict]:
    findings: list[dict] = []
    apparmor = facts.get("apparmor") or {}
    if not apparmor.get("enabled"):
        findings.append(_finding("permissive:apparmor-disabled", "permissive", False, "AppArmor is disabled"))
    for profile in apparmor.get("complain") or []:
        findings.append(_finding(f"permissive:apparmor-complain:{profile}", "permissive", False,
                                 f"AppArmor profile {profile} is in complain mode"))

    fw = facts.get("firewall") or {}
    policy = fw.get("default_incoming")
    if fw.get("tool", "none") == "none":
        findings.append(_finding("permissive:firewall-none", "permissive", False,
                                 "no host firewall found (ufw inactive, no iptables policy)"))
    elif not policy:
        findings.append(_finding("permissive:firewall-incoming-unknown", "permissive", False,
                                 f"{fw.get('tool')} is present but its default incoming policy is unreadable"))
    elif policy.lower() in PERMISSIVE_POLICIES:
        findings.append(_finding(f"permissive:firewall-incoming-{policy}", "permissive", False,
                                 f"{fw.get('tool')} default incoming policy is {policy}"))

    sshd = facts.get("sshd") or {}
    for key in PERMISSIVE_SSHD:
        if str(sshd.get(key, "")).strip().lower() == "yes":
            findings.append(_finding(f"permissive:sshd-{key}", "permissive", False, f"sshd {key} yes"))

    for b in facts.get("binaries") or []:
        if b.get("untrusted"):   # anyone who can change it gets root when root runs it (systemd, cron, sudo)
            findings.append(_finding(f"permissive:binary-untrusted:{b.get('path')}", "permissive", True,
                                     f"{b.get('path')} can be changed by a user other than root (a non-root "
                                     "owner, a group/other-writable file or directory, or a symlink into one); "
                                     "the collector did not run it", binary=b.get("name"), path=b.get("path")))
    return findings


# --------------------------------------------------------------------------- Lynis

def lynis(facts: dict, baseline_lynis: dict | None) -> list[dict]:
    data = facts.get("lynis") or {}
    if not data.get("ok"):
        return [_finding("lynis:unavailable", "info", False,
                         f"Lynis unavailable: {data.get('error') or 'no result'}", error=data.get("error"))]
    findings: list[dict] = []
    # a baseline recorded while Lynis was unavailable (no index) is no baseline at all
    if baseline_lynis is not None and baseline_lynis.get("index") is None:
        baseline_lynis = None
    known = set((baseline_lynis or {}).get("warnings") or [])
    seen: set[str] = set()
    for w in data.get("warnings") or []:
        if w["id"] in seen:
            continue
        seen.add(w["id"])
        new = baseline_lynis is not None and w["id"] not in known
        findings.append(_finding(f"lynis-warning:{w['id']}", "lynis_warning", new,
                                 f"{w['id']}: {w['text']}" + (" (new since baseline)" if new else ""),
                                 test_id=w["id"]))
    seen = set()
    for s in data.get("suggestions") or []:
        if s["id"] in seen:
            continue
        seen.add(s["id"])
        findings.append(_finding(f"lynis-suggestion:{s['id']}", "lynis_suggestion", False,
                                 f"{s['id']}: {s['text']}", test_id=s["id"]))
    index = data.get("index")
    if index is None:
        findings.append(_finding("lynis:no-index", "info", False,
                                 "Lynis ran but its report has no hardening index"))
    base = (baseline_lynis or {}).get("index")
    if isinstance(index, int) and isinstance(base, int) and index <= base - INDEX_DROP:
        findings.append(_finding(f"lynis-index:{index}", "lynis_index", True,
                                 f"Lynis hardening index {index} is {base - index} below the baseline {base}",
                                 index=index, baseline=base))
    return findings


# --------------------------------------------------------------------------- third-party packages

def _distro_entry(entry: dict) -> bool:
    """A repository is the distribution's when apt's release `o=` says so (provider mirrors included);
    without it, by host name."""
    return entry.get("origin_name") in DISTRO_RELEASE_NAMES or _distro_site(entry.get("site"))


def _distro_site(site: str | None) -> bool:
    return bool(site) and any(site == d or site.endswith("." + d) for d in DISTRO_DOMAINS)


def third_party(facts: dict) -> list[dict]:
    findings: list[dict] = []
    origins = facts.get("origins") or {}
    seen: set[str] = set()
    for pkg in facts.get("packages") or []:
        if pkg["name"] in seen:     # multiarch: one finding per package name
            continue
        entries = [e for e in origins.get(pkg["name"], []) if e.get("installed") and e.get("site")]
        if not entries or any(_distro_entry(e) for e in entries):
            continue
        seen.add(pkg["name"])
        site = entries[0]["site"]
        candidate = next((e["version"] for e in origins[pkg["name"]] if e.get("candidate")), pkg["version"])
        text = f"{pkg['name']} {pkg['version']} from {site}"
        if candidate != pkg["version"]:
            text += f" → {candidate}"
        findings.append(_finding(f"third-party:{pkg['name']}", "third_party", False, text,
                                 package=pkg["name"], installed=pkg["version"], candidate=candidate, site=site))
    return findings
