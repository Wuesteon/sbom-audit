"""REPORT.html: the management report, one self-contained page built from the JSON a run already wrote.

Inline CSS, no script, no external request; prints to A4 from a browser. Reads `status.json`, `audit.json`,
`issues.json` (or derives the work list from the reports when it is missing), `inventory.json`,
`secrets.json`, `hosts.json`, `vex/*.openvex.json`, `secrets-decisions.toml` and `hosts-decisions.toml`;
never scans. Rules: every value from a file is HTML-escaped; no secret value exists in any input, and the
report names findings by fingerprint, file and line only; a number the data does not hold reads as "not
available", never 0; a skipped secrets scan never reads as clean. All user-facing text is in `STRINGS`.
"""
from __future__ import annotations

import contextvars
import html
import json
from pathlib import Path

from . import __version__, sbomimport
from .cra import MANUFACTURER, OBLIGATIONS
from .cache import atomic_write

REPORT_FILE = "REPORT.html"
REPORTS_DIR = "reports"
DATED_SUFFIX = "-report.html"
TOP_PRIORITY = 3          # "what needs action now": priorities 1 to 3 of issues.json
TOP_LIMIT = 25            # at most this many rows; the rest is counted and left to ISSUES.md
NOTE_MAX = 300            # decision notes are cut to this many characters
BRANCHES_SHOWN = 3
LANGUAGES = ("en", "de")

# --------------------------------------------------------------------------- strings (all text lives here)

STRINGS: dict[str, dict] = {
    "en": {
        "html_lang": "en",
        "title": "Security report",
        "title_for": "Security report: {org}",
        "report_date": "Report date",
        "scope": "Scope",
        "scope_text": "{projects} projects, {branches} project branches ({names}); configured branches: {configured}",
        "scope_releases": "; {n} release tags under audit",
        "scope_hosts": "Hosts: {hosts}",
        "scope_no_hosts": "Hosts: not part of this audit",
        "tool": "Tool",
        "tool_text": "sbom-audit {run} (run), report rendered by {now}",
        "unknown": "unknown",
        "na": "not available",
        "none": "none",
        "yes": "yes",
        "no": "no",
        "production": "production",
        "s_overall": "1. Overall state",
        "s_action": "2. What needs action now",
        "s_decisions": "3. Decisions on record",
        "s_coverage": "4. Coverage and limits",
        "s_evidence": "5. Evidence mapping (EU Cyber Resilience Act)",
        "verdict_action": "Action needed now.",
        "verdict_clear": "No finding in this run requires immediate action.",
        "verdict_incomplete": "No urgent finding in the data that is available, but this run is incomplete: "
                              "the gaps below may hide findings.",
        "verdict_none": "There is no audit data to report on.",
        "fact_kev": "{n} package version(s) carry a vulnerability that CISA lists as actively exploited (KEV).",
        "fact_secrets_a": "{n} leaked credential(s) of class A are open and must be rotated.",
        "fact_crit": "{n} package version(s) with CRITICAL or HIGH advisories are used in production projects.",
        "fact_hosts": "{n} critical host finding(s) are open.",
        "fact_gap": "Not available in this run: {what}.",
        "m_head": ("Measure", "Now", "Change since previous run"),
        "m_kev": "Actively exploited vulnerabilities (CISA KEV), package versions",
        "m_crit": "CRITICAL/HIGH in production projects, package versions",
        "m_eol": "Runtimes and base images past end of life, product cycles",
        "m_secrets": "Leaked credentials, open, class {cls}",
        "m_hosts": "Critical host findings",
        "m_short_kev": "KEV findings",
        "m_short_crit": "CRITICAL/HIGH in production",
        "m_short_eol": "end-of-life runtimes",
        "m_short_secrets": "leaked-credential findings",
        "m_short_hosts": "host findings",
        "eol_soon": "{n} more reach end of life soon",
        "eol_allowed": ("{n} allowed but unsupported: a declared minimum (engines.node, requires-python) allows an "
                        "end-of-life version; not counted here, what runs is not stated or has its own row"),
        "incomplete": "incomplete: {what}",
        "inc_osv": "{n} branch(es) could not be matched against OSV",
        "inc_eol": "{n} endoflife.date lookup(s) failed",
        "inc_secrets": "{n} repository scan(s) failed",
        "inc_hosts": "{n} host(s) could not be checked",
        "na_no_audit": "no audit.json",
        "na_kev": "the KEV catalogue was not loaded in this run",
        "na_osv": "the OSV match did not run",
        "na_eol": "endoflife.date was not queried in this run",
        "na_secrets_skipped": "secrets scan skipped ({reason}); not the same as clean",
        "na_secrets_failed": "the secrets scan failed; not the same as clean",
        "na_secrets_none": "no secrets scan result",
        "na_hosts_skipped": "host check skipped ({reason})",
        "carried": "{n} finding(s) from an earlier scan are still open (A {a}, B {b}, C {c})",
        "delta": "{new} new, {resolved} resolved",
        "delta_first": "first run: no comparison",
        "delta_rules": "not comparable: the previous run counted by other rules",
        "delta_none": "no previous run on record",
        "delta_untracked": "not tracked",
        "delta_note": "Changes are counted per advisory (KEV, CRITICAL/HIGH), per product cycle (end of life) "
                      "and per finding (credentials, hosts).",
        "action_intro": "Open issues of priority 1 to 3 from the work list, most urgent first. "
                        "The full list with every location is ISSUES.md / issues.json.",
        "action_derived": "issues.json is not in the folder; the list below was derived from the reports at "
                          "report time.",
        "action_incomplete": "Sources failed in this run ({what}); the work list may be missing issues.",
        "action_head": ("Priority", "Project or host", "What", "Fix", "Open since"),
        "action_none": "Nothing open at priority 1 to 3.",
        "action_more": "{n} more issue(s) at priority 1 to 3 are not shown here; see ISSUES.md.",
        "action_rest": "Also open, for planning: {parts}.",
        "action_rest_none": "Nothing else is open.",
        "action_unavailable": "The work list is not available: no audit.json.",
        "rest_part": "{n} × {label}",
        "reason": {"secret_a": "Leaked credential, class A", "kev": "Actively exploited (KEV)",
                   "host_critical": "Critical host finding", "critical_high_production": "CRITICAL/HIGH in production",
                   "secret_b": "Leaked credential, class B", "eol": "End of life", "floating_tag": "Floating image tag",
                   "secret_context": "Possible credential in test, docs or vendored files", "other": "Other",
                   "eol_minimum": "Declared minimum allows an end-of-life version"},
        "fix": {"upgrade": "Upgrade to {target}", "no_fix_released": "No fix released yet; mitigate or decide",
                "rotate": "Rotate the credential at the provider", "upgrade_runtime": "Move to a supported version",
                "pin": "Pin the image to a version or digest", "apt_upgrade": "Install the update {target}",
                "reboot": "Reboot (the fixed kernel is installed)", "no_fix_installable": "No installable fix yet",
                "review": "Review and decide", "raise_minimum": "Raise the declared minimum to a supported version"},
        "fix_unfixed": "{n} advisory(ies) without a fix",
        "dep_direct": "direct dependency",
        "dep_transitive": "transitive dependency",
        "dep_unknown": "dependency type unknown",
        "dep_dev_only": "dev-only",
        "action_deps_split": "{direct} in direct dependencies and {transitive} in transitive ones",
        "action_deps_split_unknown": "{direct} in direct dependencies, {transitive} in transitive ones and {unknown} "
                                     "whose dependency type the scan could not tell (unknown is not transitive: "
                                     "check the manifest first; listed after the direct ones)",
        "action_deps": "Vulnerability issues at priority 2 and 3 (KEV, or CRITICAL/HIGH in production or a supported "
                       "release): {n}, of which {split}. Within a priority, direct dependencies are listed "
                       "first: they are fixed in your own manifest. Transitive does not mean harmless: a transitive "
                       "package is installed and can run like a direct one, and there is no reachability analysis, "
                       "so each one stays a finding until it is fixed or a decision says otherwise.",
        "branches": "branches: {list}",
        "more": "+{n} more",
        "line": "line {n}",
        "d_vex": "Vulnerability decisions (OpenVEX)",
        "d_vex_head": ("Vulnerability", "Product", "Decision", "Justification", "Recorded", "Recorded by"),
        "d_vex_none": "No VEX decisions on record.",
        "d_vex_bad": "{file} could not be read; its decisions are not shown.",
        "d_vex_who": "\"Recorded by\" is the author of the decision file (set when the file was created); "
                     "OpenVEX keeps no author per statement. The git history of vex/ shows who added each one.",
        "d_vex_applied": "{n} finding(s) are suppressed in this run by these decisions.",
        "d_secrets": "Leaked-credential decisions",
        "d_secrets_head": ("Fingerprint", "Where", "Decision", "Date", "Note"),
        "d_secrets_none": "No leaked-credential decisions on record.",
        "d_secrets_bad": "secrets-decisions.toml could not be read; its decisions are not shown.",
        "d_secrets_who": "The decisions file records no author; the git history of secrets-decisions.toml does.",
        "rotated_on": "rotated on {date}",
        "d_hosts": "Accepted host findings",
        "d_hosts_head": ("Host", "Finding", "Accepted", "Review by", "Note"),
        "d_hosts_none": "No accepted host findings on record.",
        "d_hosts_bad": "hosts-decisions.toml could not be read; its decisions are not shown.",
        "c_scanned": "Projects and branches read",
        "c_scanned_head": ("Project", "Branch", "Commit", "State"),
        "c_read": "read",
        "c_failed": "failed (see STATUS.md)",
        "c_production": "{name} (production)",
        "c_skipped": "Not scanned: {list}.",
        "c_no_inventory": "inventory.json is not available; which branches were read is not known.",
        "c_sources": "Data sources",
        "c_sources_head": ("Source", "State", "Data as of"),
        "c_ok": "answered",
        "c_src_failed": "{n} failure(s)",
        "c_src_error": "failed",
        "c_src_skipped": "skipped ({reason})",
        "c_src_absent": "not run",
        "src": {"osv-scanner": "OSV vulnerability match (osv-scanner)", "cisa_kev": "CISA KEV catalogue",
                "endoflife": "endoflife.date", "registries": "Package registries (latest versions)",
                "openvex": "OpenVEX decisions", "secrets": "Secrets scan (gitleaks)", "hosts": "Host check (SSH)",
                "git": "git (reading branches)", "run": "Run"},
        "c_secrets": "Secrets scan",
        "label_skipped": "skipped",
        "c_secrets_skipped": "Skipped: {reason}. Not the same as clean: no repository history was searched "
                             "for leaked credentials in this run.",
        "c_secrets_ran": "{mode} scan with {engine} over {repos} repositories.",
        "secrets_modes": {"full": "full", "incremental": "incremental"},
        "c_secrets_failed": "{n} repository scan(s) failed; their history may hold findings this report does not show.",
        "c_secrets_unknown": "No secrets scan result is available.",
        "c_hosts": "Hosts",
        "c_hosts_off": "Not configured: no server was checked.",
        "c_hosts_text": "{checked} checked, {failed} failed, {unsupported} unsupported; last checked {last}.",
        "c_hosts_skipped": "Skipped: {reason}; last checked {last}.",
        "c_times": "Data timestamps",
        "c_times_head": ("File", "Written"),
        "c_times_zone": "All times in this report are in the run's time zone ({zone}), converted where a file "
                        "records another; a day without a time (first seen, decision dates) is shown as the file "
                        "records it, and secrets.json records UTC days.",
        "t_inventory": "inventory.json (scan)",
        "t_audit": "audit.json (audit)",
        "t_status": "status.json (end of run)",
        "t_issues": "issues.json (work list)",
        "t_issues_derived": "derived at report time",
        "t_secrets": "secrets.json (secrets scan)",
        "t_hosts": "hosts.json (last host check)",
        "t_kev": "CISA KEV catalogue (local cache)",
        "t_absent": "not present",
        "t_unreadable": "present but unreadable",
        "c_limits": "Limits",
        "limits": [
            "Dependencies are read from git objects of the configured branches (and of the release tags under "
            "audit); the secrets scan reads the whole git history of every branch of each repository. Working "
            "trees, unpushed changes and repositories outside the portfolio are not read.",
            "Vulnerabilities are matched against published advisories (OSV). Ecosystems OSV does not cover are "
            "inventoried but not matched, and code written in-house is not reviewed.",
            "There is no reachability analysis: a vulnerable package counts as a finding until a decision says "
            "otherwise.",
            "The secrets scan finds what the gitleaks rules match. It does not check whether a credential still "
            "works and cannot see secrets that never reached git.",
            "RELEASES.md, ISSUES.md, CRA.md and the other Markdown and JSON files are always in English; the "
            "language setting applies only to this report and the cra init templates.",
        ],
        "limit_imports": "For {n} project branches or releases, the packages of some ecosystems come from an "
                         "imported build SBOM, with the packages only the repository scan found kept in addition; "
                         "the plugin checks its format, not its completeness.",
        "limit_imports_off": "Not built from the scanned commit, or with no commit recorded ({n}): {which}.",
        "limit_actions": "GitHub Actions used in workflows are inventoried but not checked for vulnerabilities "
                         "(OSV does not match versions for this ecosystem): {n} in this run's branches.",
        "limit_gaps": "Not seen by the repository scan: {what}. That code is not in the SBOMs and not checked for "
                      "vulnerabilities; for C/C++ and firmware, import a build SBOM (see AUDIT.md Notes).",
        "limit_gap_projects": "{n} projects not scanned (no configured branch)",
        "limit_gap_branches": "{n} branches with git submodules, C/C++ code or firmware manifests",
        "limit_gap_unmatched": "{n} packages of types OSV holds no advisories for (generic, GitHub, Conan, vcpkg)",
        "e_intro": "Where the artefacts of this folder serve the EU Cyber Resilience Act (Regulation (EU) "
                   "2024/2847).",
        "e_caveat": "Evidence tooling, not legal advice: the plugin produces the artefacts an assessment asks for; "
                    "it does not decide whether a product is in scope or compliant.",
        "e_head": ("Artefact", "What it serves", "In this folder"),
        "e_rows": [
            ("sbom/<project>/<branch>.cdx.json (CycloneDX)",
             "Annex I Part II (1): identify and document components and vulnerabilities, including an SBOM in a "
             "commonly used machine-readable format"),
            ("AUDIT.md, audit.json, STATUS.md, the weekly schedule",
             "Annex I Part II (2) and (3): address vulnerabilities without delay, regular tests and reviews"),
            ("The KEV section of AUDIT.md, class A secrets in SECRETS.md",
             "Art. 14: the trigger to run the reporting procedure (cra/<product>/art14-procedure.md) for actively "
             "exploited vulnerabilities and severe incidents"),
            ("vex/<project>.openvex.json, secrets-decisions.toml",
             "Art. 13(7) and Annex I Part II: documented vulnerability handling decisions"),
            ("log.md, reports/, the git history of security/",
             "Art. 13(7), Annex VII point 2(b): the evidence trail for the technical documentation"),
            ("INVENTORY.md, the endoflife.date section of AUDIT.md, releases.json",
             "Support period (Art. 13(8)): runtimes and images past or near end of life, released versions"),
            ("sbom/<project>/tags__<tag>.cdx.json, releases.json",
             "SBOM per released version: Annex I Part II (1) and Annex VII points 2(b) and 8 (the SBOM in the "
             "technical documentation); Art. 13(8) (vulnerability handling for the support period); Art. 13(13) "
             "(keep it at least 10 years or for the support period, whichever is longer)"),
            ("cra/<product>/, CRA.md, cra.json",
             "Art. 13(2), 13(3), 13(17), Art. 14, Annex I Part II (5), (6): risk assessment, reporting procedure, "
             "disclosure policy, contact; readiness per product below"),
        ],
        "cra_title": "CRA readiness per product",
        "cra_intro": "From cra.json ({date}). One status per obligation; a present document is evidence that it "
                     "exists, not that its content is complete or right.",
        "cra_none": "No product is configured, so there is no readiness overview: list the projects that are "
                    "products under [cra.products] in sbom-audit.toml. Nothing is assumed to be in scope.",
        "cra_unreadable": "cra.json is unreadable; run `cra check` again.",
        "cra_not_run": "Products are configured but cra.json is missing; it is written by the next run or by "
                       "`cra check`.",
        "cra_product": "{name} (project {project}, branch {branch})",
        "cra_error": "Repository not read: {error}",
        "cra_kev": "{n} open KEV finding(s) in this product: check the reporting procedure "
                   "(cra/{project}/art14-procedure.md); an actively exploited vulnerability starts the 24-hour "
                   "early warning of Art. 14(2)(a).",
        "cra_head": ("Obligation", "Reference", "Status", "Evidence"),
        "cra_status": {"present": "evidence present", "missing": "evidence missing", "stale": "stale",
                       "manufacturer": "manufacturer's responsibility"},
        "cra_ob": {
            "risk_assessment": "Cybersecurity risk assessment, documented and updated",
            "contact": "Single point of contact, contact address for vulnerability reports",
            "security_txt": "security.txt with a valid Expires date",
            "cvd_policy": "Coordinated vulnerability disclosure policy",
            "reporting": "Reporting procedure for exploited vulnerabilities and severe incidents",
            "sbom": "Software bill of materials",
            "vulnerability_handling": "Vulnerabilities identified and addressed, regular reviews",
            "decisions_trail": "Documented decisions and evidence trail",
            "support_period": "Support period and its end date",
            "released_versions": "Released versions under audit",
            "scope": "Scope and product category",
            "essential_requirements": "Product properties of Annex I Part I",
            "advisories": "Advisories, secure update distribution",
            "components": "Reporting vulnerabilities in components to their maintainers",
            "user_information": "Information and instructions to the user",
            "technical_documentation": "Technical documentation",
            "conformity": "Conformity assessment, declaration, CE marking",
        },
        "cra_ref": {k: ref for k, (ref, _) in {**OBLIGATIONS, **MANUFACTURER}.items()},     # as cra.json has them
        "c_releases": "Releases under audit",
        "c_releases_head": ("Project", "Release", "Date", "Support", "Open: KEV / critical / high",
                            "No longer present vs previous"),
        "c_rel_until": "supported until {date}",
        "c_rel_no_period": "supported (no period configured)",
        "c_rel_out": "out of support since {date}",
        "c_rel_oldest": "oldest kept",
        "c_rel_unknown": "unknown (incomplete scan)",
        "c_rel_fixed": "{n} vs {prev}",
        "c_rel_change": {"upgraded": "{n} upgraded to a higher version",
                         "replaced": "{n} replaced by another version",
                         "affected_removed": "{n} affected version removed, an unaffected version that was already "
                                             "there remains",
                         "package_gone": "{n} package no longer in the SBOM",
                         "no_longer_matched": "{n} still in the SBOM, no longer matched"},
        "c_rel_eol": "end of life before the support period ends: {list}",
        "c_rel_eol_unknown": "end of life unknown (endoflife.date gives no date; check yourself): {list}",
        "c_rel_eol_terms": (),                          # releases.json wording is English already
        "c_rel_note": "Each release has its own SBOM and is audited like a branch. Releases past their support period "
                      "are listed but not counted as open work. \"No longer present\" means exactly: the advisory "
                      "matched a package in the SBOM of the previous release and matches none in the SBOM of this "
                      "release, both checked against today's OSV data. It does not by itself mean an upgrade: the "
                      "breakdown says whether the package moved to a higher version, an affected copy was removed "
                      "while another version remains, or the package left the SBOM. Details: RELEASES.md.",
        "e_schedule": "the schedule is not visible from the folder",
        "e_git": "git history not checked",
        "s_produced": "6. How this report was produced",
        "p_intro": "sbom-audit {version} on Python {python} ({platform}). Configuration sbom-audit.toml, "
                   "SHA-256 {config}.",
        "p_no_config": "no configuration file read",
        "p_none": "Not recorded: audit.json predates this information or could not be read.",
        "p_tools_head": ["Tool", "Version as reported by the tool"],
        "p_sources_head": ["Data source", "Status", "Freshness"],
        "p_engine": "{name} (secrets scan)",
        "p_status": {"ok": "ok", "partial": "partial", "failed": "failed", "skipped": "skipped",
                     "not run": "not run"},
        "p_osv": "queried live during the audit, {at}",
        "p_kev": "catalogue {date}, fetched {at} ({origin})",
        "p_kev_none": "not loaded",
        "p_live": "downloaded during this audit",
        "p_cache": "from the local cache",
        "p_lookups": "{n} lookups: {live} during this audit, {cached} from the local cache; oldest {oldest}",
        "p_nothing": "nothing to look up",
        "p_vex": "{n} statements",
        "p_manifest": "manifest.json lists the run's start and end, the audited commit of every project branch and "
                      "the SHA-256 and size of every file the run wrote. "
                      "<code>sbom_audit_cli.py verify</code> recomputes them and names any file that changed "
                      "since.",
        "footer": "Generated by sbom-audit from the files in this folder. No secret value is part of any input; "
                  "credentials are named by fingerprint, file and line.",
    },
    "de": {
        "html_lang": "de",
        "title": "Sicherheitsbericht",
        "title_for": "Sicherheitsbericht: {org}",
        "report_date": "Berichtsdatum",
        "scope": "Umfang",
        "scope_text": "{projects} Projekte, {branches} Projekt-Branches ({names}); konfigurierte Branches: {configured}",
        "scope_releases": "; {n} Release-Tags unter Prüfung",
        "scope_hosts": "Server: {hosts}",
        "scope_no_hosts": "Server: nicht Teil dieser Prüfung",
        "tool": "Werkzeug",
        "tool_text": "sbom-audit {run} (Lauf), Bericht erstellt mit {now}",
        "unknown": "unbekannt",
        "na": "nicht verfügbar",
        "none": "keine",
        "yes": "ja",
        "no": "nein",
        "production": "Produktion",
        "s_overall": "1. Gesamtlage",
        "s_action": "2. Was jetzt zu tun ist",
        "s_decisions": "3. Dokumentierte Entscheidungen",
        "s_coverage": "4. Abdeckung und Grenzen",
        "s_evidence": "5. Nachweiszuordnung (EU Cyber Resilience Act)",
        "verdict_action": "Handlungsbedarf jetzt.",
        "verdict_clear": "Kein Befund dieses Laufs erfordert sofortiges Handeln.",
        "verdict_incomplete": "In den verfügbaren Daten gibt es keinen dringenden Befund, aber dieser Lauf ist "
                              "unvollständig: Die unten genannten Lücken können Befunde verdecken.",
        "verdict_none": "Es liegen keine Prüfdaten vor.",
        "fact_kev": "{n} Paketversion(en) haben eine Schwachstelle, die CISA als aktiv ausgenutzt führt (KEV).",
        "fact_secrets_a": "{n} offengelegte Zugangsdaten der Klasse A sind offen und müssen ausgetauscht werden.",
        "fact_crit": "{n} Paketversion(en) mit CRITICAL- oder HIGH-Hinweisen werden in Produktionsprojekten "
                     "verwendet.",
        "fact_hosts": "{n} kritische Server-Befund(e) sind offen.",
        "fact_gap": "In diesem Lauf nicht verfügbar: {what}.",
        "m_head": ("Kennzahl", "Aktuell", "Veränderung seit dem letzten Lauf"),
        "m_kev": "Aktiv ausgenutzte Schwachstellen (CISA KEV), Paketversionen",
        "m_crit": "CRITICAL/HIGH in Produktionsprojekten, Paketversionen",
        "m_eol": "Laufzeitumgebungen und Basis-Images ohne Support (End of Life), Produktzyklen",
        "m_secrets": "Offengelegte Zugangsdaten, offen, Klasse {cls}",
        "m_hosts": "Kritische Server-Befunde",
        "m_short_kev": "KEV-Befunde",
        "m_short_crit": "CRITICAL/HIGH in Produktion",
        "m_short_eol": "Laufzeitumgebungen ohne Support",
        "m_short_secrets": "Befunde zu offengelegten Zugangsdaten",
        "m_short_hosts": "Server-Befunde",
        "eol_soon": "{n} weitere erreichen bald das Support-Ende",
        "eol_allowed": ("{n} erlaubt, aber ohne Support: eine erklärte Mindestversion (engines.node, requires-python) "
                        "erlaubt eine Version ohne Support; hier nicht mitgezählt, die tatsächlich laufende Version "
                        "ist nicht angegeben oder hat eine eigene Zeile"),
        "incomplete": "unvollständig: {what}",
        "inc_osv": "{n} Branch(es) konnten nicht mit OSV abgeglichen werden",
        "inc_eol": "{n} Abfrage(n) bei endoflife.date fehlgeschlagen",
        "inc_secrets": "{n} Repository-Scan(s) fehlgeschlagen",
        "inc_hosts": "{n} Server konnten nicht geprüft werden",
        "na_no_audit": "keine audit.json",
        "na_kev": "der KEV-Katalog wurde in diesem Lauf nicht geladen",
        "na_osv": "der OSV-Abgleich lief nicht",
        "na_eol": "endoflife.date wurde in diesem Lauf nicht abgefragt",
        "na_secrets_skipped": "Secrets-Scan übersprungen ({reason}); das ist nicht dasselbe wie unbedenklich",
        "na_secrets_failed": "der Secrets-Scan ist fehlgeschlagen; das ist nicht dasselbe wie unbedenklich",
        "na_secrets_none": "kein Ergebnis eines Secrets-Scans",
        "na_hosts_skipped": "Server-Prüfung übersprungen ({reason})",
        "carried": "{n} Befund(e) aus einem früheren Scan sind weiterhin offen (A {a}, B {b}, C {c})",
        "delta": "{new} neu, {resolved} erledigt",
        "delta_first": "erster Lauf: kein Vergleich",
        "delta_rules": "nicht vergleichbar: der vorige Lauf zählte nach anderen Regeln",
        "delta_none": "kein früherer Lauf erfasst",
        "delta_untracked": "nicht erfasst",
        "delta_note": "Veränderungen zählen je Advisory (KEV, CRITICAL/HIGH), je Produktzyklus (End of Life) und "
                      "je Befund (Zugangsdaten, Server).",
        "action_intro": "Offene Punkte der Priorität 1 bis 3 aus der Arbeitsliste, die dringendsten zuerst. "
                        "Die vollständige Liste mit allen Fundstellen ist ISSUES.md / issues.json.",
        "action_derived": "issues.json liegt nicht im Ordner; die Liste unten wurde beim Erstellen des Berichts "
                          "aus den Prüfberichten abgeleitet.",
        "action_incomplete": "In diesem Lauf sind Quellen ausgefallen ({what}); der Arbeitsliste können Punkte "
                             "fehlen.",
        "action_head": ("Priorität", "Projekt oder Server", "Was", "Behebung", "Offen seit"),
        "action_none": "Nichts offen mit Priorität 1 bis 3.",
        "action_more": "{n} weitere Punkte mit Priorität 1 bis 3 sind hier nicht aufgeführt; siehe ISSUES.md.",
        "action_rest": "Ebenfalls offen, zur Planung: {parts}.",
        "action_rest_none": "Sonst ist nichts offen.",
        "action_unavailable": "Die Arbeitsliste ist nicht verfügbar: keine audit.json.",
        "rest_part": "{n} × {label}",
        "reason": {"secret_a": "Offengelegte Zugangsdaten, Klasse A", "kev": "Aktiv ausgenutzt (KEV)",
                   "host_critical": "Kritischer Server-Befund", "critical_high_production": "CRITICAL/HIGH in Produktion",
                   "secret_b": "Offengelegte Zugangsdaten, Klasse B", "eol": "Support-Ende (End of Life)",
                   "floating_tag": "Nicht fixiertes Image-Tag",
                   "secret_context": "Mögliche Zugangsdaten in Test-, Doku- oder Fremdcode", "other": "Sonstiges",
                   "eol_minimum": "Erklärte Mindestversion erlaubt eine Version ohne Support"},
        "fix": {"upgrade": "Aktualisieren auf {target}",
                "no_fix_released": "Noch kein Fix veröffentlicht; abmildern oder entscheiden",
                "rotate": "Zugangsdaten beim Anbieter austauschen", "upgrade_runtime": "Auf eine unterstützte Version wechseln",
                "pin": "Image auf Version oder Digest festlegen", "apt_upgrade": "Update {target} installieren",
                "reboot": "Neustart (der korrigierte Kernel ist installiert)",
                "no_fix_installable": "Noch kein installierbarer Fix", "review": "Prüfen und entscheiden",
                "raise_minimum": "Erklärte Mindestversion auf eine unterstützte Version anheben"},
        "fix_unfixed": "{n} Advisory(s) ohne Fix",
        "dep_direct": "direkte Abhängigkeit",
        "dep_transitive": "transitive Abhängigkeit",
        "dep_unknown": "Abhängigkeitsart unbekannt",
        "dep_dev_only": "nur Entwicklung",
        "action_deps_split": "{direct} in direkten und {transitive} in transitiven Abhängigkeiten",
        "action_deps_split_unknown": "{direct} in direkten, {transitive} in transitiven Abhängigkeiten und {unknown}, "
                                     "bei denen der Scan die Abhängigkeitsart nicht erkennen konnte (unbekannt heißt "
                                     "nicht transitiv: zuerst das Manifest prüfen; sie stehen nach den direkten)",
        "action_deps": "Schwachstellen mit Priorität 2 und 3 (KEV, oder CRITICAL/HIGH in Produktion oder einem "
                       "unterstützten Release): {n}, davon {split}. Innerhalb einer Priorität stehen direkte "
                       "Abhängigkeiten zuerst: Sie werden im eigenen Manifest behoben. Transitiv heißt nicht harmlos: "
                       "Ein transitives Paket wird installiert und kann laufen wie ein direktes, und es gibt keine "
                       "Erreichbarkeitsanalyse; jeder Punkt bleibt ein Befund, bis er behoben ist oder eine "
                       "Entscheidung etwas anderes festhält.",
        "branches": "Branches: {list}",
        "more": "+{n} weitere",
        "line": "Zeile {n}",
        "d_vex": "Entscheidungen zu Schwachstellen (OpenVEX)",
        "d_vex_head": ("Schwachstelle", "Produkt", "Entscheidung", "Begründung", "Erfasst", "Erfasst von"),
        "d_vex_none": "Keine VEX-Entscheidungen erfasst.",
        "d_vex_bad": "{file} konnte nicht gelesen werden; ihre Entscheidungen fehlen hier.",
        "d_vex_who": "„Erfasst von“ ist der Autor der Entscheidungsdatei (gesetzt beim Anlegen der Datei); "
                     "OpenVEX speichert keinen Autor je Aussage. Die git-Historie von vex/ zeigt, wer welche "
                     "Aussage ergänzt hat.",
        "d_vex_applied": "{n} Befund(e) werden in diesem Lauf durch diese Entscheidungen unterdrückt.",
        "d_secrets": "Entscheidungen zu offengelegten Zugangsdaten",
        "d_secrets_head": ("Fingerprint", "Fundstelle", "Entscheidung", "Datum", "Notiz"),
        "d_secrets_none": "Keine Entscheidungen zu offengelegten Zugangsdaten erfasst.",
        "d_secrets_bad": "secrets-decisions.toml konnte nicht gelesen werden; ihre Entscheidungen fehlen hier.",
        "d_secrets_who": "Die Entscheidungsdatei erfasst keinen Autor; die git-Historie von secrets-decisions.toml "
                         "schon.",
        "rotated_on": "ausgetauscht am {date}",
        "d_hosts": "Akzeptierte Server-Befunde",
        "d_hosts_head": ("Server", "Befund", "Akzeptiert", "Überprüfen bis", "Notiz"),
        "d_hosts_none": "Keine akzeptierten Server-Befunde erfasst.",
        "d_hosts_bad": "hosts-decisions.toml konnte nicht gelesen werden; ihre Entscheidungen fehlen hier.",
        "c_scanned": "Gelesene Projekte und Branches",
        "c_scanned_head": ("Projekt", "Branch", "Commit", "Zustand"),
        "c_read": "gelesen",
        "c_failed": "fehlgeschlagen (siehe STATUS.md)",
        "c_production": "{name} (Produktion)",
        "c_skipped": "Nicht gescannt: {list}.",
        "c_no_inventory": "inventory.json ist nicht verfügbar; welche Branches gelesen wurden, ist nicht bekannt.",
        "c_sources": "Datenquellen",
        "c_sources_head": ("Quelle", "Zustand", "Datenstand"),
        "c_ok": "beantwortet",
        "c_src_failed": "{n} Fehler",
        "c_src_error": "fehlgeschlagen",
        "c_src_skipped": "übersprungen ({reason})",
        "c_src_absent": "nicht gelaufen",
        "src": {"osv-scanner": "OSV-Schwachstellenabgleich (osv-scanner)", "cisa_kev": "CISA-KEV-Katalog",
                "endoflife": "endoflife.date", "registries": "Paket-Registries (aktuelle Versionen)",
                "openvex": "OpenVEX-Entscheidungen", "secrets": "Secrets-Scan (gitleaks)",
                "hosts": "Server-Prüfung (SSH)", "git": "git (Lesen der Branches)", "run": "Lauf"},
        "c_secrets": "Secrets-Scan",
        "label_skipped": "übersprungen",
        "c_secrets_skipped": "Übersprungen: {reason}. Das ist nicht dasselbe wie unbedenklich: In diesem Lauf wurde "
                             "keine Repository-Historie nach offengelegten Zugangsdaten durchsucht.",
        "c_secrets_ran": "Scan ({mode}) mit {engine} über {repos} Repositories.",
        "secrets_modes": {"full": "vollständig", "incremental": "inkrementell"},
        "c_secrets_failed": "{n} Repository-Scan(s) fehlgeschlagen; deren Historie kann Befunde enthalten, die dieser "
                            "Bericht nicht zeigt.",
        "c_secrets_unknown": "Kein Ergebnis eines Secrets-Scans verfügbar.",
        "c_hosts": "Server",
        "c_hosts_off": "Nicht konfiguriert: Es wurde kein Server geprüft.",
        "c_hosts_text": "{checked} geprüft, {failed} fehlgeschlagen, {unsupported} nicht unterstützt; zuletzt geprüft "
                        "{last}.",
        "c_hosts_skipped": "Übersprungen: {reason}; zuletzt geprüft {last}.",
        "c_times": "Zeitstempel der Daten",
        "c_times_head": ("Datei", "Geschrieben"),
        "c_times_zone": "Alle Zeiten in diesem Bericht stehen in der Zeitzone des Laufs ({zone}), umgerechnet, wo "
                        "eine Datei eine andere festhält; ein Tag ohne Uhrzeit (erstmals gesehen, Datum einer "
                        "Entscheidung) steht so da, wie die Datei ihn festhält, und secrets.json hält Tage in UTC fest.",
        "t_inventory": "inventory.json (Scan)",
        "t_audit": "audit.json (Prüfung)",
        "t_status": "status.json (Ende des Laufs)",
        "t_issues": "issues.json (Arbeitsliste)",
        "t_issues_derived": "beim Erstellen des Berichts abgeleitet",
        "t_secrets": "secrets.json (Secrets-Scan)",
        "t_hosts": "hosts.json (letzte Server-Prüfung)",
        "t_kev": "CISA-KEV-Katalog (lokaler Cache)",
        "t_absent": "nicht vorhanden",
        "t_unreadable": "vorhanden, aber nicht lesbar",
        "c_limits": "Grenzen",
        "limits": [
            "Abhängigkeiten werden aus den git-Objekten der konfigurierten Branches (und der geprüften "
            "Release-Tags) gelesen; der Secrets-Scan liest die gesamte git-Historie aller Branches jedes "
            "Repositorys. Arbeitskopien, nicht gepushte Änderungen und Repositories außerhalb des Portfolios "
            "werden nicht gelesen.",
            "Schwachstellen werden mit veröffentlichten Advisories (OSV) abgeglichen. Ökosysteme, die OSV nicht "
            "abdeckt, werden inventarisiert, aber nicht abgeglichen; selbst geschriebener Code wird nicht geprüft.",
            "Es gibt keine Erreichbarkeitsanalyse: Ein verwundbares Paket zählt als Befund, bis eine Entscheidung "
            "etwas anderes festhält.",
            "Der Secrets-Scan findet, was die gitleaks-Regeln erkennen. Er prüft nicht, ob Zugangsdaten noch gültig "
            "sind, und sieht keine Geheimnisse, die nie in git gelandet sind.",
            "RELEASES.md, ISSUES.md, CRA.md und die übrigen Markdown- und JSON-Dateien sind immer englisch; die "
            "Einstellung language gilt nur für diesen Bericht und die Vorlagen von cra init.",
        ],
        "limit_imports": "Bei {n} Branches oder Releases stammen die Pakete einiger Ökosysteme aus einer "
                         "importierten Build-SBOM; Pakete, die nur der Repository-Scan gefunden hat, bleiben "
                         "zusätzlich erhalten. Das Plugin prüft ihr Format, nicht ihre Vollständigkeit.",
        "limit_imports_off": "Nicht aus dem gescannten Commit gebaut oder ohne Commit-Angabe ({n}): {which}.",
        "limit_actions": "In Workflows verwendete GitHub Actions werden inventarisiert, aber nicht auf "
                         "Schwachstellen geprüft (OSV gleicht für dieses Ökosystem keine Versionen ab): {n} in den "
                         "Branches dieses Laufs.",
        "limit_gaps": "Vom Repository-Scan nicht erfasst: {what}. Dieser Code steht in keiner SBOM und wird nicht auf "
                      "Schwachstellen geprüft; für C/C++ und Firmware eine Build-SBOM importieren (siehe Notes in "
                      "AUDIT.md).",
        "limit_gap_projects": "{n} Projekte nicht gescannt (kein konfigurierter Branch)",
        "limit_gap_branches": "{n} Branches mit Git-Submodulen, C/C++-Code oder Firmware-Manifesten",
        "limit_gap_unmatched": "{n} Pakete von Typen, für die OSV keine Advisories führt (generic, GitHub, Conan, "
                               "vcpkg)",
        "e_intro": "Wofür die Artefakte dieses Ordners im Sinne des EU Cyber Resilience Act (Verordnung (EU) "
                   "2024/2847) dienen.",
        "e_caveat": "Nachweiswerkzeug, keine Rechtsberatung: Das Plugin erzeugt die Artefakte, nach denen eine "
                    "Bewertung fragt; es entscheidet nicht, ob ein Produkt in den Anwendungsbereich fällt oder "
                    "konform ist.",
        "e_head": ("Artefakt", "Wofür es dient", "In diesem Ordner"),
        "e_rows": [
            ("sbom/<project>/<branch>.cdx.json (CycloneDX)",
             "Anhang I Teil II Nr. 1: Komponenten und Schwachstellen ermitteln und dokumentieren, einschließlich einer "
             "SBOM in einem gängigen maschinenlesbaren Format"),
            ("AUDIT.md, audit.json, STATUS.md, der wöchentliche Zeitplan",
             "Anhang I Teil II Nr. 2 und 3: Schwachstellen unverzüglich beheben, regelmäßige Tests und Überprüfungen"),
            ("Der KEV-Abschnitt von AUDIT.md, Zugangsdaten der Klasse A in SECRETS.md",
             "Art. 14: der Anlass, das Meldeverfahren (cra/<product>/art14-procedure.md) für aktiv ausgenutzte "
             "Schwachstellen und schwerwiegende Sicherheitsvorfälle durchzugehen"),
            ("vex/<project>.openvex.json, secrets-decisions.toml",
             "Art. 13 Abs. 7 und Anhang I Teil II: dokumentierte Entscheidungen zur Behandlung von Schwachstellen"),
            ("log.md, reports/, die git-Historie von security/",
             "Art. 13 Abs. 7, Anhang VII Nr. 2 Buchst. b: die Nachweiskette für die technische Dokumentation"),
            ("INVENTORY.md, der endoflife.date-Abschnitt von AUDIT.md, releases.json",
             "Unterstützungszeitraum (Art. 13 Abs. 8): Laufzeitumgebungen und Images nach oder kurz vor dem "
             "Support-Ende, veröffentlichte Versionen"),
            ("sbom/<project>/tags__<tag>.cdx.json, releases.json",
             "SBOM je veröffentlichter Version: Anhang I Teil II Nr. 1 und Anhang VII Nr. 2 Buchst. b und Nr. 8 (SBOM "
             "in der technischen Dokumentation); Art. 13 Abs. 8 (Schwachstellenbehandlung während des "
             "Support-Zeitraums); Art. 13 Abs. 13 (Aufbewahrung mindestens 10 Jahre oder für den Support-Zeitraum, "
             "je nachdem, welcher länger ist)"),
            ("cra/<product>/, CRA.md, cra.json",
             "Art. 13 Abs. 2, 3 und 17, Art. 14, Anhang I Teil II Nr. 5 und 6: Risikobewertung, Meldeverfahren, "
             "Offenlegungsstrategie, Kontakt; Bereitschaft je Produkt unten"),
        ],
        "cra_title": "CRA-Bereitschaft je Produkt",
        "cra_intro": "Aus cra.json ({date}). Ein Status je Pflicht; ein vorhandenes Dokument belegt, dass es "
                     "existiert, nicht, dass sein Inhalt vollständig oder richtig ist.",
        "cra_none": "Kein Produkt konfiguriert, daher keine Bereitschaftsübersicht: Tragen Sie die Projekte, die "
                    "Produkte sind, unter [cra.products] in sbom-audit.toml ein. Nichts gilt ungefragt als erfasst.",
        "cra_unreadable": "cra.json ist nicht lesbar; `cra check` erneut ausführen.",
        "cra_not_run": "Produkte sind konfiguriert, aber cra.json fehlt; der nächste Lauf oder `cra check` "
                       "schreibt sie.",
        "cra_product": "{name} (Projekt {project}, Branch {branch})",
        "cra_error": "Repository nicht gelesen: {error}",
        "cra_kev": "{n} offene(r) KEV-Befund(e) in diesem Produkt: Meldeverfahren prüfen "
                   "(cra/{project}/art14-procedure.md); eine aktiv ausgenutzte Schwachstelle löst die "
                   "24-Stunden-Frühwarnung nach Art. 14 Abs. 2 Buchst. a aus.",
        "cra_head": ("Pflicht", "Fundstelle", "Status", "Nachweis"),
        "cra_status": {"present": "Nachweis vorhanden", "missing": "Nachweis fehlt", "stale": "veraltet",
                       "manufacturer": "Verantwortung des Herstellers"},
        "cra_ob": {
            "risk_assessment": "Bewertung der Cybersicherheitsrisiken, dokumentiert und aktualisiert",
            "contact": "Zentrale Anlaufstelle, Kontaktadresse für Schwachstellenmeldungen",
            "security_txt": "security.txt mit gültigem Expires-Datum",
            "cvd_policy": "Strategie für die koordinierte Offenlegung von Schwachstellen",
            "reporting": "Meldeverfahren für ausgenutzte Schwachstellen und schwerwiegende Sicherheitsvorfälle",
            "sbom": "Software-Stückliste",
            "vulnerability_handling": "Schwachstellen ermittelt und behoben, regelmäßige Überprüfung",
            "decisions_trail": "Dokumentierte Entscheidungen und Nachweiskette",
            "support_period": "Unterstützungszeitraum und sein Enddatum",
            "released_versions": "Veröffentlichte Versionen in der Prüfung",
            "scope": "Anwendungsbereich und Produktkategorie",
            "essential_requirements": "Produkteigenschaften nach Anhang I Teil I",
            "advisories": "Sicherheitshinweise, sichere Verbreitung von Aktualisierungen",
            "components": "Schwachstellen in Komponenten an deren Verantwortliche melden",
            "user_information": "Informationen und Anleitungen für die Nutzer",
            "technical_documentation": "Technische Dokumentation",
            "conformity": "Konformitätsbewertung, Erklärung, CE-Kennzeichnung",
        },
        # the same provisions as cra.OBLIGATIONS / MANUFACTURER, cited the way the German Official Journal text
        # does (Abs. = paragraph, Nr. = point, Buchst. = letter); a new obligation without an entry shows cra.json's
        "cra_ref": {
            "risk_assessment": "Art. 13 Abs. 2, 3 und 7; Anhang I Teil I; Anhang VII Nr. 3",
            "contact": "Art. 13 Abs. 17; Anhang I Teil II Nr. 6; Anhang II Nr. 2",
            "security_txt": "Anhang I Teil II Nr. 6; Anhang II Nr. 2 (RFC 9116 ist ein verbreiteter Weg, keine "
                            "Anforderung des CRA)",
            "cvd_policy": "Anhang I Teil II Nr. 5; Art. 13 Abs. 8; Anhang VII Nr. 2 Buchst. b",
            "reporting": "Art. 14 Abs. 1 bis 8; Art. 16; Art. 69 Abs. 3; Art. 71 Abs. 2",
            "sbom": "Anhang I Teil II Nr. 1; Anhang VII Nr. 2 Buchst. b",
            "vulnerability_handling": "Anhang I Teil II Nr. 2 und 3; Art. 13 Abs. 8",
            "decisions_trail": "Art. 13 Abs. 7; Anhang VII Nr. 2 Buchst. b",
            "support_period": "Art. 13 Abs. 8 und 19; Anhang II Nr. 7; Anhang VII Nr. 4",
            "released_versions": "Anhang I Teil II Nr. 2 und 8; Art. 13 Abs. 9",
            "scope": "Art. 2, 3 und 7; Anhang III und IV",
            "essential_requirements": "Anhang I Teil I Nr. 1 und Nr. 2 Buchst. a bis m",
            "advisories": "Anhang I Teil II Nr. 4, 7 und 8",
            "components": "Art. 13 Abs. 6",
            "user_information": "Art. 13 Abs. 16 und 18; Anhang II",
            "technical_documentation": "Art. 13 Abs. 13, Art. 31; Anhang VII",
            "conformity": "Art. 28, 30 und 32; Anhang V",
        },
        "c_releases": "Releases unter Prüfung",
        "c_releases_head": ("Projekt", "Release", "Datum", "Support", "Offen: KEV / kritisch / hoch",
                            "Nicht mehr vorhanden ggü. Vorgänger"),
        "c_rel_until": "unterstützt bis {date}",
        "c_rel_no_period": "unterstützt (kein Zeitraum konfiguriert)",
        "c_rel_out": "Support beendet am {date}",
        "c_rel_oldest": "älteste geprüfte",
        "c_rel_unknown": "unbekannt (Scan unvollständig)",
        "c_rel_fixed": "{n} ggü. {prev}",
        "c_rel_change": {"upgraded": "{n} auf eine höhere Version aktualisiert",
                         "replaced": "{n} durch eine andere Version ersetzt",
                         "affected_removed": "{n} betroffene Version entfernt, eine nicht betroffene, schon "
                                             "vorhandene Version bleibt",
                         "package_gone": "{n} Paket nicht mehr in der SBOM",
                         "no_longer_matched": "{n} noch in der SBOM, nicht mehr zugeordnet"},
        "c_rel_eol": "Support-Ende vor Ende des Support-Zeitraums: {list}",
        "c_rel_eol_unknown": "Support-Ende unbekannt (endoflife.date nennt kein Datum; selbst prüfen): {list}",
        "c_rel_eol_terms": (("(EOL, no date published)", "(Support-Ende erreicht, kein Datum veröffentlicht)"),
                            ("(EOL ", "(Support-Ende "),
                            ("(version unknown)", "(Version unbekannt)"),
                            ("(no endoflife.date data)", "(keine Daten bei endoflife.date)"),
                            ("(no end-of-life date published)", "(kein Support-Ende veröffentlicht)")),
        "c_rel_note": "Jedes Release hat eine eigene SBOM und wird wie ein Branch geprüft. Releases außerhalb des "
                      "Support-Zeitraums sind aufgeführt, zählen aber nicht als offene Arbeit. „Nicht mehr vorhanden“ "
                      "heißt genau: die Meldung traf ein Paket in der SBOM des vorherigen Releases und trifft keines in "
                      "der SBOM dieses Releases, beides mit den heutigen OSV-Daten geprüft. Das heißt für sich noch "
                      "nicht, dass aktualisiert wurde: Die Aufschlüsselung zeigt, ob das Paket auf eine höhere "
                      "Version kam, eine betroffene Kopie entfernt wurde, während eine andere Version bleibt, oder "
                      "das Paket nicht mehr in der SBOM ist. Details: RELEASES.md.",
        "e_schedule": "der Zeitplan ist im Ordner nicht sichtbar",
        "e_git": "git-Historie nicht geprüft",
        "s_produced": "6. Wie dieser Bericht entstanden ist",
        "p_intro": "sbom-audit {version} mit Python {python} ({platform}). Konfiguration sbom-audit.toml, "
                   "SHA-256 {config}.",
        "p_no_config": "keine Konfigurationsdatei gelesen",
        "p_none": "Nicht erfasst: audit.json ist älter als diese Angaben oder nicht lesbar.",
        "p_tools_head": ["Werkzeug", "Version laut Werkzeug"],
        "p_sources_head": ["Datenquelle", "Status", "Aktualität"],
        "p_engine": "{name} (Secrets-Scan)",
        "p_status": {"ok": "ok", "partial": "teilweise", "failed": "fehlgeschlagen", "skipped": "übersprungen",
                     "not run": "nicht ausgeführt"},
        "p_osv": "während des Audits live abgefragt, {at}",
        "p_kev": "Katalog vom {date}, abgerufen {at} ({origin})",
        "p_kev_none": "nicht geladen",
        "p_live": "während dieses Audits heruntergeladen",
        "p_cache": "aus dem lokalen Cache",
        "p_lookups": "{n} Abfragen: {live} während dieses Audits, {cached} aus dem lokalen Cache; älteste {oldest}",
        "p_nothing": "nichts abzufragen",
        "p_vex": "{n} Aussagen",
        "p_manifest": "manifest.json enthält Beginn und Ende des Laufs, den geprüften Commit jedes Projekt-Branches "
                      "sowie SHA-256 und Größe jeder Datei, die der Lauf geschrieben hat. "
                      "<code>sbom_audit_cli.py verify</code> berechnet sie neu und nennt jede Datei, die sich seitdem "
                      "geändert hat.",
        "footer": "Erstellt von sbom-audit aus den Dateien dieses Ordners. Kein geheimer Wert ist Teil einer Eingabe; "
                  "Zugangsdaten werden über Fingerprint, Datei und Zeile benannt.",
    },
}

CSS = """
:root { color-scheme: light; }
@page { size: A4; margin: 16mm 15mm 18mm 15mm; }
* { box-sizing: border-box; }
html { background: #fff; }
body { margin: 0 auto; max-width: 190mm; padding: 12mm 8mm 16mm; color: #111; background: #fff;
       font: 10.5pt/1.45 -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; }
header { border-bottom: 2px solid #111; padding-bottom: 4mm; margin-bottom: 6mm; }
h1 { font-size: 19pt; margin: 0 0 3mm; line-height: 1.2; }
h2 { font-size: 13.5pt; margin: 8mm 0 3mm; padding-bottom: 1mm; border-bottom: 1px solid #999;
     break-after: avoid; page-break-after: avoid; }
h3 { font-size: 11pt; margin: 5mm 0 2mm; break-after: avoid; page-break-after: avoid; }
p, ul { margin: 0 0 2.5mm; }
ul { padding-left: 5mm; }
dl.meta { display: grid; grid-template-columns: max-content 1fr; gap: 1mm 5mm; margin: 0; }
dl.meta dt { font-weight: 600; }
dl.meta dd { margin: 0; }
table { width: 100%; border-collapse: collapse; margin: 1mm 0 3mm; font-size: 9.5pt; }
th, td { border: 1px solid #888; padding: 1.2mm 1.8mm; text-align: left; vertical-align: top;
         overflow-wrap: anywhere; }
th { background: #eee; font-weight: 600; }
thead { display: table-header-group; }
tr { break-inside: avoid; page-break-inside: avoid; }
td.num { white-space: nowrap; font-weight: 700; }
code, .mono { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 8.8pt; }
.label { display: inline-block; border: 1px solid #111; padding: 0 1.2mm; font-size: 8.5pt; font-weight: 700;
         letter-spacing: .02em; white-space: nowrap; }
.label.strong { border-width: 2px; }
.na { font-style: italic; }
.verdict { font-size: 12pt; font-weight: 700; margin: 0 0 2mm; }
.note { font-size: 9pt; color: #333; }
.warn { border-left: 3px solid #111; padding: 1mm 0 1mm 3mm; margin: 2mm 0 3mm; }
.caveat { border: 1px solid #111; padding: 2mm 3mm; font-weight: 600; }
section { break-inside: auto; }
footer { break-before: avoid; page-break-before: avoid; margin-top: 4mm; padding-top: 2mm; border-top: 1px solid #999; font-size: 8.5pt; color: #333; }
@media screen and (max-width: 700px) {
  body { padding: 16px; font-size: 10pt; }
  dl.meta { grid-template-columns: 1fr; }
  table { display: block; overflow-x: auto; }
}
@media print {
  body { max-width: none; padding: 0; font-size: 10pt; }
  a { color: inherit; text-decoration: none; }
}
""".strip()


# --------------------------------------------------------------------------- reading (never raises)

def e(value) -> str:
    """HTML-escape any value that comes from a file."""
    return html.escape("" if value is None else str(value), quote=True)


def _read_json(path: Path):
    """(document, state): state is "ok", "absent" or "unreadable"; a document that is not an object is unreadable."""
    if not path.exists():
        return None, "absent"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, "unreadable"
    return (doc, "ok") if isinstance(doc, dict) else (None, "unreadable")


def _kev_fetched(out: Path) -> str | None:
    """When the KEV catalogue in the local cache was downloaded (UTC), or None; the cache is gitignored."""
    import datetime as dt
    try:
        entry = json.loads((out / ".cache" / "enrich" / "kev-catalog.json").read_text(encoding="utf-8"))
        return dt.datetime.fromtimestamp(float(entry["stored_at"]), dt.timezone.utc).replace(microsecond=0).isoformat()
    except (OSError, ValueError, KeyError, TypeError, OverflowError):
        return None


def _vex_docs(out: Path) -> list[tuple[str, dict | None]]:
    folder = out / "vex"
    if not folder.is_dir():
        return []
    docs = []
    for path in sorted(folder.glob("*.openvex.json")):
        doc, state = _read_json(path)
        ok = state == "ok" and isinstance(doc.get("statements", []), list)
        docs.append((f"vex/{path.name}", doc if ok else None))
    return docs


def _secret_decisions(out: Path):
    """{fingerprint: Decision} or None when the file is unreadable."""
    from .secrets import store
    try:
        return store.read_decisions(out)
    except Exception:                               # ValueError and anything a broken file raises
        return None


def _host_decisions(out: Path):
    from .hosts import store
    try:
        return store.read_decisions(out)
    except Exception:
        return None


def load(out: Path, *, secrets_enabled: bool = True, hosts_active: bool | None = None) -> dict:
    """Everything the report reads, each document None when absent or unreadable (its state is kept)."""
    out = Path(out)
    data: dict = {"out": out, "states": {}}
    for key, name in (("status", "status.json"), ("audit", "audit.json"), ("issues", "issues.json"),
                      ("inventory", "inventory.json"), ("secrets", "secrets.json"), ("hosts", "hosts.json"),
                      ("cra", "cra.json"), ("releases", "releases.json")):
        data[key], data["states"][key] = _read_json(out / name)
    status = data["status"] or {}
    hosts_counts = (status.get("counts") or {}).get("hosts")
    if hosts_active is None:
        hosts_active = hosts_counts is not None
    data["hosts_active"] = bool(hosts_active)
    data["secrets_enabled"] = secrets_enabled
    if not data["hosts_active"]:
        data["hosts"] = None
    data["issues_derived"] = False
    if data["issues"] is None and data["audit"] is not None:
        from . import issues
        try:
            data["issues"] = issues.build(data["audit"], data["secrets"] if secrets_enabled else None,
                                          data["hosts"], incomplete=status.get("failed_sources") or [],
                                          now=status.get("generated_at") or data["audit"].get("generated_at"))
            data["issues_derived"] = True
        except Exception:
            data["issues"] = None
    data["vex"] = _vex_docs(out)
    data["secret_decisions"] = _secret_decisions(out)
    data["host_decisions"] = _host_decisions(out) if data["hosts_active"] else {}
    data["kev_fetched"] = _kev_fetched(out)
    data["cra_configured"] = _cra_configured(out)
    return data


def _cra_configured(out: Path) -> bool | None:
    """True when [cra.products] lists a product, None when the config cannot be read."""
    from . import cra
    try:
        return bool(cra.load_config(out).products)
    except Exception:
        return None


# --------------------------------------------------------------------------- facts

def _failed_count(info) -> int:
    failed = info.get("failed") if isinstance(info, dict) else None
    return len(failed) if isinstance(failed, list) else 0


def _metrics(data: dict, S: dict) -> list[dict]:
    """One row per measure: value (int) or None with a reason, an incomplete note, the delta key."""
    from .report import _actionable, allowed_unsupported
    from .status import _in_production
    audit, status = data["audit"], data["status"] or {}
    sources = (audit or {}).get("sources") or {}
    sources = sources if isinstance(sources, dict) else {}
    rows = []

    def row(key, label, value=None, reason=None, incomplete=None, delta=None, extra=None):
        rows.append({"key": key, "label": label, "value": value, "reason": reason, "incomplete": incomplete,
                     "delta": delta, "extra": extra})

    vulns = [v for v in (audit or {}).get("vulnerabilities") or [] if isinstance(v, dict)]
    osv = sources.get("osv-scanner")
    osv_ok = isinstance(osv, dict) and not osv.get("error")
    osv_inc = S["inc_osv"].format(n=_failed_count(osv)) if osv_ok and _failed_count(osv) else None
    # KEV
    if audit is None:
        row("kev", S["m_kev"], reason=S["na_no_audit"], delta="kev")
    elif not osv_ok:
        row("kev", S["m_kev"], reason=S["na_osv"], delta="kev")
    elif not isinstance(sources.get("cisa_kev"), dict) or sources["cisa_kev"].get("error"):
        row("kev", S["m_kev"], reason=S["na_kev"], delta="kev")
    else:
        row("kev", S["m_kev"], sum(1 for v in vulns if v.get("kev")), incomplete=osv_inc, delta="kev")
    # CRITICAL/HIGH in production
    production = set((audit or {}).get("production_projects") or [])
    if audit is None:
        row("crit", S["m_crit"], reason=S["na_no_audit"], delta="critical_high_production")
    elif not osv_ok:
        row("crit", S["m_crit"], reason=S["na_osv"], delta="critical_high_production")
    else:
        n = sum(1 for v in vulns if _actionable(v) and _in_production(v, production))
        row("crit", S["m_crit"], n, incomplete=osv_inc, delta="critical_high_production")
    # end of life
    eol_src = sources.get("endoflife")
    if audit is None:
        row("eol", S["m_eol"], reason=S["na_no_audit"], delta="eol")
    elif not isinstance(eol_src, dict) or eol_src.get("error"):
        row("eol", S["m_eol"], reason=S["na_eol"], delta="eol")
    else:
        runtimes = [r for r in audit.get("runtimes") or [] if isinstance(r, dict)]
        eol = {(r.get("product"), r.get("cycle")) for r in runtimes if r.get("status") == "EOL"}
        soon = {(r.get("product"), r.get("cycle")) for r in runtimes if r.get("status") == "EOL soon"}
        allowed = {(r.get("product"), r.get("cycle")) for r in runtimes if allowed_unsupported(r)}
        extra = "; ".join(x for x in (S["eol_soon"].format(n=len(soon)) if soon else "",
                                      S["eol_allowed"].format(n=len(allowed)) if allowed else "") if x)
        row("eol", S["m_eol"], len(eol), delta="eol",
            incomplete=S["inc_eol"].format(n=_failed_count(eol_src)) if _failed_count(eol_src) else None,
            extra=extra or None)
    # leaked credentials, per class
    sec = _secrets_state(data)
    for cls in "ABC":
        delta = {"A": "secrets_a", "B": "secrets_b"}.get(cls)
        label = S["m_secrets"].format(cls=cls)
        if sec["state"] == "ok":
            inc = S["inc_secrets"].format(n=sec["failed"]) if sec["failed"] else None
            row(f"secrets_{cls}", label, sec["counts"].get(cls, 0), incomplete=inc, delta=delta)
        else:
            reason = {"skipped": S["na_secrets_skipped"].format(reason=e(sec["reason"] or S["unknown"])),
                      "failed": S["na_secrets_failed"]}.get(sec["state"], S["na_secrets_none"])
            row(f"secrets_{cls}", label, reason=reason, delta=delta)
    # hosts, only when configured
    hosts = (status.get("counts") or {}).get("hosts") if data["hosts_active"] else None
    if isinstance(hosts, dict):
        if hosts.get("skipped"):
            row("hosts", S["m_hosts"], reason=S["na_hosts_skipped"].format(reason=e(hosts["skipped"])),
                delta="hosts_critical")
        else:
            failed = hosts.get("failed") or 0
            row("hosts", S["m_hosts"], hosts.get("critical") or 0, delta="hosts_critical",
                incomplete=S["inc_hosts"].format(n=failed) if failed else None)
    return rows


def _secrets_state(data: dict) -> dict:
    """state: ok | skipped | failed | none; counts of open findings per class (only meaningful when ok)."""
    status = data["status"] or {}
    secrets = data["secrets"]
    scan = status.get("secrets_scan") if isinstance(status.get("secrets_scan"), dict) else None
    failed_sources = {f.get("source") for f in status.get("failed_sources") or [] if isinstance(f, dict)}
    src = ((data["audit"] or {}).get("sources") or {}).get("secrets")
    sscan = (secrets or {}).get("scan") if isinstance((secrets or {}).get("scan"), dict) else None
    findings = [f for f in (secrets or {}).get("findings") or [] if isinstance(f, dict) and f.get("status") == "open"]
    carried = {cls: sum(1 for f in findings if f.get("class") == cls) for cls in "ABC"}
    if scan is None and sscan is None:
        return {"state": "none", "reason": None, "counts": {}, "failed": 0, "carried": carried}
    mode = (scan or sscan).get("mode")
    reason = (scan or sscan).get("skipped_reason")
    if isinstance(src, dict) and src.get("error"):
        return {"state": "failed", "reason": reason, "counts": {}, "failed": 0, "carried": carried}
    if mode == "skipped" or not mode:
        return {"state": "skipped", "reason": reason, "counts": {}, "failed": 0, "carried": carried}
    counts = (status.get("counts") or {}).get("secrets") if scan is not None else None
    if not isinstance(counts, dict):
        counts = carried
    failed = _failed_count(src) or _failed_count(sscan)
    if "secrets" in failed_sources and not failed:
        failed = 1
    return {"state": "ok", "reason": None, "counts": counts, "failed": failed, "carried": carried,
            "mode": mode, "engine": (scan or {}).get("engine") or ((secrets or {}).get("engine") or {}).get("name"),
            "repos": (scan or sscan).get("repos")}


def _delta_text(data: dict, key: str | None, S: dict) -> str:
    status = data["status"]
    if key is None:
        return f'<span class="na">{S["delta_untracked"]}</span>'
    if not status:
        return f'<span class="na">{S["delta_none"]}</span>'
    if status.get("first_run"):
        return f'<span class="na">{S["delta_first"]}</span>'
    d = (status.get("deltas") or {}).get(key)
    if not isinstance(d, dict):
        return f'<span class="na">{S["na"]}</span>'
    if d.get("not_comparable"):         # the previous run counted this set by other rules (status.OPEN_RULES)
        return f'<span class="na">{S["delta_rules"]}</span>'
    return S["delta"].format(new=len(d.get("new") or []), resolved=len(d.get("resolved") or []))


# --------------------------------------------------------------------------- sections

def _run_date(data: dict):
    """The audit's own timestamp (local time, as reports/<date>-audit.md is named), else the status file's."""
    return (data["audit"] or {}).get("generated_at") or (data["status"] or {}).get("generated_at")


def _zone_of(value):
    """The time zone of an ISO timestamp, or None (no value, a date only, or no offset)."""
    import datetime as dt
    try:
        return dt.datetime.fromisoformat(str(value)).tzinfo
    except ValueError:
        return None


def _in_zone(value, zone) -> str:
    """An ISO timestamp with an offset converted to `zone` (the run's), so every time in the report reads in
    one zone and a day is the run's day; anything else (a date only, a naive time, no zone) unchanged."""
    import datetime as dt
    text = str(value)
    if zone is None or len(text) <= 10:
        return text
    try:
        when = dt.datetime.fromisoformat(text)
    except ValueError:
        return text
    if when.tzinfo is None:
        return text
    moved = when.astimezone(zone)
    return text if moved.utcoffset() == when.utcoffset() else moved.isoformat()     # already in the zone: as written


def _offset(zone) -> str:
    import datetime as dt
    delta = dt.datetime.now(zone).utcoffset() if zone else None
    if delta is None:
        return ""
    minutes = int(delta.total_seconds() // 60)
    sign, minutes = ("+" if minutes >= 0 else "-"), abs(minutes)
    return f"UTC{sign}{minutes // 60:02d}:{minutes % 60:02d}"


_ZONE = contextvars.ContextVar("report_zone", default=None)    # the run's zone while `render` runs


def _date(value) -> str:
    return e(_in_zone(value, _ZONE.get())[:10]) if value else ""


def _time(value) -> str:
    return e(_in_zone(value, _ZONE.get())) if value else ""


def _table(head, rows: list[list[str]], cls: str = "") -> str:
    """`rows` hold ready HTML (each value escaped by the caller)."""
    h = "".join(f"<th>{e(c)}</th>" for c in head)
    body = "".join("<tr>" + "".join(r) + "</tr>" for r in rows)
    attr = f' class="{cls}"' if cls else ""
    return f"<table{attr}><thead><tr>{h}</tr></thead><tbody>{body}</tbody></table>"


def _td(content: str, cls: str = "") -> str:
    return f'<td class="{cls}">{content}</td>' if cls else f"<td>{content}</td>"


def _header(data: dict, S: dict, organisation: str | None) -> str:
    status, audit, inventory = data["status"] or {}, data["audit"] or {}, data["inventory"] or {}
    title = S["title_for"].format(org=e(organisation)) if organisation else e(S["title"])
    when = _run_date(data)
    invs = [i for i in inventory.get("inventories") or [] if isinstance(i, dict)]
    if invs:
        names = sorted({str(i.get("project")) for i in invs})
        n_rel = sum(1 for i in invs if i.get("release"))
        scope = S["scope_text"].format(projects=len(names), branches=len(invs) - n_rel, names=e(", ".join(names)),
                                       configured=e(", ".join(map(str, inventory.get("branches") or [])) or S["unknown"]))
        if n_rel:
            scope += e(S["scope_releases"].format(n=n_rel))
    elif status.get("counts"):
        c = status["counts"]
        scope = S["scope_text"].format(projects=e(c.get("projects", "?")), branches=e(c.get("branches", "?")),
                                       names=e(S["unknown"]), configured=e(S["unknown"]))
    else:
        scope = f'<span class="na">{S["na"]}</span>'
    host_names = sorted(((data["hosts"] or {}).get("hosts") or {}).keys()) \
        if isinstance((data["hosts"] or {}).get("hosts"), dict) else []
    hosts = S["scope_hosts"].format(hosts=e(", ".join(host_names))) if host_names else (
        S["scope_hosts"].format(hosts=S["na"]) if data["hosts_active"] else S["scope_no_hosts"])
    tool = S["tool_text"].format(run=e(status.get("plugin_version") or S["unknown"]), now=e(__version__))
    return (f"<header><h1>{title}</h1><dl class=\"meta\">"
            f"<dt>{S['report_date']}</dt><dd>{_date(when) or S['unknown']}</dd>"
            f"<dt>{S['scope']}</dt><dd>{scope}<br>{hosts}</dd>"
            f"<dt>{S['tool']}</dt><dd>{tool}</dd></dl></header>")


def _overall(data: dict, S: dict, metrics: list[dict]) -> str:
    by = {m["key"]: m for m in metrics}
    L = [f"<section><h2>{S['s_overall']}</h2>"]
    if data["audit"] is None:
        L.append(f'<p class="verdict">{S["verdict_none"]}</p>')
    facts = []
    for key, text in (("kev", "fact_kev"), ("secrets_A", "fact_secrets_a"), ("crit", "fact_crit"),
                      ("hosts", "fact_hosts")):
        m = by.get(key)
        if m and m["value"]:
            facts.append(S[text].format(n=m["value"]))
    gaps = [m for m in metrics if m["value"] is None or m["incomplete"]]
    if data["audit"] is not None:
        verdict = "verdict_action" if facts else ("verdict_incomplete" if gaps else "verdict_clear")
        L.append(f'<p class="verdict">{S[verdict]}</p>')
    if facts:
        L.append("<ul>" + "".join(f"<li>{f}</li>" for f in facts) + "</ul>")
    short = {"kev": "m_short_kev", "crit": "m_short_crit", "eol": "m_short_eol", "hosts": "m_short_hosts"}
    missing = []
    for m in metrics:
        if m["value"] is None:
            name = S["m_short_secrets"] if m["key"].startswith("secrets_") else S[short[m["key"]]]
            if name not in missing:
                missing.append(name)
    if missing:
        L.append(f'<p class="warn">{S["fact_gap"].format(what=", ".join(missing))}</p>')
    rows = []
    for m in metrics:
        if m["value"] is None:
            now = f'<span class="na">{S["na"]}</span><br><span class="note">{m["reason"]}</span>'
            cls = ""
        else:
            now = f'{m["value"]}'
            cls = "num"
            notes = [x for x in (m["extra"], m["incomplete"] and S["incomplete"].format(what=m["incomplete"])) if x]
            if notes:
                now += "".join(f'<br><span class="note">{n}</span>' for n in notes)
                cls = ""
        delta = _delta_text(data, m["delta"], S) if m["value"] is not None else f'<span class="na">{S["na"]}</span>'
        rows.append([_td(e(m["label"])), _td(now, cls), _td(delta)])
    L.append(_table(S["m_head"], rows))
    sec = _secrets_state(data)
    if sec["state"] != "ok" and any(sec["carried"].values()):
        c = sec["carried"]
        L.append(f'<p class="note">{S["carried"].format(n=sum(c.values()), a=c["A"], b=c["B"], c=c["C"])}</p>')
    L.append(f'<p class="note">{S["delta_note"]}</p></section>')
    return "".join(L)


def _where(i: dict, S: dict) -> str:
    w = i.get("where") or {}
    parts = []
    if w.get("path"):
        loc = e(w["path"]) + (f":{e(w['line'])}" if w.get("line") else "")
        parts.append(f"<code>{loc}</code>")
    branches = [str(b) for b in w.get("branches") or []]
    if branches:
        shown = ", ".join(branches[:BRANCHES_SHOWN])
        if len(branches) > BRANCHES_SHOWN:
            shown += " " + S["more"].format(n=len(branches) - BRANCHES_SHOWN)
        parts.append(e(S["branches"].format(list=shown)))
    return "<br>".join(parts)


def _fix(i: dict, S: dict) -> str:
    fix = i.get("fix") if isinstance(i.get("fix"), dict) else {}
    action = str(fix.get("action") or "")
    template = S["fix"].get(action)
    target = fix.get("target")
    if template is None:
        text = e(action.replace("_", " ")) + (f" → <code>{e(target)}</code>" if target else "")
    elif "{target}" in template:
        text = e(template).replace("{target}", f"<code>{e(target)}</code>" if target else e(S["unknown"]))
    else:
        text = e(template)
    unfixed = fix.get("unfixed_advisories")
    if unfixed and target:
        text += f'<br><span class="note">{e(S["fix_unfixed"].format(n=unfixed))}</span>'
    return text


def _action(data: dict, S: dict) -> str:
    from . import issues
    L = [f"<section><h2>{S['s_action']}</h2>"]
    doc = data["issues"]
    if doc is None:
        L.append(f'<p class="na">{S["action_unavailable"]}</p></section>')
        return "".join(L)
    L.append(f"<p>{S['action_intro']}</p>")
    if data["issues_derived"]:
        L.append(f'<p class="note">{S["action_derived"]}</p>')
    incomplete = [s for s in doc.get("incomplete") or [] if isinstance(s, dict)]
    if incomplete:
        names = ", ".join(sorted({e(S["src"].get(str(s.get("source")), s.get("source"))) for s in incomplete}))
        L.append(f'<p class="warn">{S["action_incomplete"].format(what=names)}</p>')
    items = [i for i in doc.get("issues") or [] if isinstance(i, dict)]
    urgent = [i for i in items if isinstance(i.get("priority"), int) and i["priority"] <= TOP_PRIORITY]
    # direct, then unknown, then transitive within a priority, also for an issues.json written before that order
    urgent.sort(key=lambda i: (i["priority"], not i.get("production"), issues.dependency_rank(i)))
    split = issues.dependency_split(urgent)
    if split["total"]:
        parts = S["action_deps_split_unknown" if split["unknown"] else "action_deps_split"].format(**split)
        deps = S["action_deps"].format(n=split["total"], split=parts)
        L.append(f"<p>{e(deps)}</p>")
    if urgent:
        rows = []
        for i in urgent[:TOP_LIMIT]:
            reason = S["reason"].get(str(i.get("reason")), str(i.get("reason") or ""))
            strong = " strong" if i["priority"] <= 2 else ""
            prio = f'<span class="label{strong}">P{e(i["priority"])}</span><br>{e(reason)}'
            w = i.get("where") or {}
            place = e(w.get("project") or w.get("host") or "?")
            if i.get("production"):
                place += f'<br><span class="label">{e(S["production"].upper())}</span>'
            sev = i.get("severity")
            what = (f'<span class="label">{e(str(sev).upper())}</span> ' if sev and i.get("kind") != "secret" else "") \
                + e(i.get("title"))
            if i.get("kind") == "vulnerability" and isinstance(i.get("details"), dict):
                dep = [S["dep_" + (issues.dependency_type(i) or "direct")]]
                if i["details"].get("dev_only"):
                    dep.append(S["dep_dev_only"])
                what += f'<br><span class="note">{e(", ".join(dep))}</span>'
            where = _where(i, S)
            if where:
                what += f'<br><span class="note">{where}</span>'
            rows.append([_td(prio), _td(place), _td(what), _td(_fix(i, S)), _td(_date(i.get("first_seen")))])
        L.append(_table(S["action_head"], rows))
        if len(urgent) > TOP_LIMIT:
            L.append(f"<p>{S['action_more'].format(n=len(urgent) - TOP_LIMIT)}</p>")
    else:
        L.append(f"<p><strong>{S['action_none']}</strong></p>")
    rest: dict[str, int] = {}
    for i in items:
        if not (isinstance(i.get("priority"), int) and i["priority"] <= TOP_PRIORITY):
            label = S["reason"].get(str(i.get("reason")), str(i.get("reason") or ""))
            rest[label] = rest.get(label, 0) + 1
    if rest:
        parts = ", ".join(S["rest_part"].format(n=n, label=e(label)) for label, n in rest.items())
        L.append(f"<p>{S['action_rest'].format(parts=parts)}</p>")
    else:
        L.append(f"<p>{S['action_rest_none']}</p>")
    L.append("</section>")
    return "".join(L)


def _cut(text) -> str:
    text = " ".join(str(text or "").split())
    return text[:NOTE_MAX] + "…" if len(text) > NOTE_MAX else text


def _decisions(data: dict, S: dict) -> str:
    L = [f"<section><h2>{S['s_decisions']}</h2>", f"<h3>{S['d_vex']}</h3>"]
    rows, bad = [], []
    for name, doc in data["vex"]:
        if doc is None:
            bad.append(name)
            continue
        author = doc.get("author")
        for st in doc.get("statements") or []:
            if not isinstance(st, dict):
                continue
            vuln = (st.get("vulnerability") or {}).get("name") if isinstance(st.get("vulnerability"), dict) else None
            products = []
            for p in st.get("products") or []:
                pid = p.get("@id") if isinstance(p, dict) else p
                subs = [s.get("@id") if isinstance(s, dict) else s for s in (p.get("subcomponents") or [])] \
                    if isinstance(p, dict) else []
                products.append(f"<code>{e(pid)}</code>" + "".join(f"<br>↳ <code>{e(s)}</code>" for s in subs))
            why = [e(str(st["justification"]).replace("_", " "))] if st.get("justification") else []
            if st.get("impact_statement"):
                why.append(e(_cut(st["impact_statement"])))
            rows.append([_td(f"<code>{e(vuln)}</code>"), _td("<br>".join(products)),
                         _td(f'<span class="label">{e(str(st.get("status") or "?").replace("_", " ").upper())}</span>'),
                         _td("<br>".join(why) or "–"), _td(_date(st.get("timestamp") or doc.get("timestamp")) or "–"),
                         _td(e(author) if author else f'<span class="na">{S["unknown"]}</span>')])
    if rows:
        L.append(_table(S["d_vex_head"], rows))
        L.append(f'<p class="note">{S["d_vex_who"]}</p>')
    elif not bad:
        L.append(f"<p>{S['d_vex_none']}</p>")
    L += [f'<p class="warn">{S["d_vex_bad"].format(file=f"<code>{e(b)}</code>")}</p>' for b in bad]
    suppressed = (data["audit"] or {}).get("suppressed")
    if isinstance(suppressed, list) and suppressed:
        L.append(f"<p>{S['d_vex_applied'].format(n=len(suppressed))}</p>")
    # leaked credentials
    L.append(f"<h3>{S['d_secrets']}</h3>")
    decisions = data["secret_decisions"]
    if decisions is None:
        L.append(f'<p class="warn">{S["d_secrets_bad"]}</p>')
    elif not decisions:
        L.append(f"<p>{S['d_secrets_none']}</p>")
    else:
        found = {f.get("fingerprint"): f for f in (data["secrets"] or {}).get("findings") or [] if isinstance(f, dict)}
        rows = []
        for fp, d in sorted(decisions.items()):
            f = found.get(fp) or {}
            where = (e(f.get("repo")) + f"<br><code>{e(f.get('file'))}:{e(f.get('line'))}</code>") if f else "–"
            status = f'<span class="label">{e(str(d.status).replace("_", " ").upper())}</span>'
            if d.rotated_on:
                status += f'<br>{e(S["rotated_on"].format(date=d.rotated_on))}'
            rows.append([_td(f'<code>{e(fp)}</code>'), _td(where), _td(status), _td(_date(d.date)),
                         _td(e(_cut(d.note)) or "–")])
        L.append(_table(S["d_secrets_head"], rows))
        L.append(f'<p class="note">{S["d_secrets_who"]}</p>')
    # hosts
    if data["hosts_active"]:
        L.append(f"<h3>{S['d_hosts']}</h3>")
        decisions = data["host_decisions"]
        if decisions is None:
            L.append(f'<p class="warn">{S["d_hosts_bad"]}</p>')
        elif not decisions:
            L.append(f"<p>{S['d_hosts_none']}</p>")
        else:
            rows = [[_td(e(d.host)), _td(f"<code>{e(d.id)}</code>"), _td(_date(d.date)), _td(_date(d.review_by) or "–"),
                     _td(e(_cut(d.note)) or "–")] for _, d in sorted(decisions.items())]
            L.append(_table(S["d_hosts_head"], rows))
    L.append("</section>")
    return "".join(L)


def _source_state(info, S: dict) -> str:
    if not isinstance(info, dict):
        return e(S["c_src_absent"])
    if info.get("skipped"):
        return e(S["c_src_skipped"].format(reason=info["skipped"]))
    if info.get("error"):
        return f'<span class="label strong">{e(S["c_src_error"].upper())}</span>'
    n = _failed_count(info)
    if n:
        return f'<span class="label strong">{e(S["c_src_failed"].format(n=n).upper())}</span>'
    return e(S["c_ok"])


def _coverage(data: dict, S: dict) -> str:
    L = [f"<section><h2>{S['s_coverage']}</h2>", f"<h3>{S['c_scanned']}</h3>"]
    inventory, audit, status = data["inventory"], data["audit"] or {}, data["status"] or {}
    production = set(audit.get("production_projects") or [])
    if inventory is None:
        L.append(f'<p class="warn">{S["c_no_inventory"]}</p>')
    else:
        rows = []
        for inv in inventory.get("inventories") or []:
            if not isinstance(inv, dict) or inv.get("release"):     # releases: their own table below
                continue
            name = str(inv.get("project"))
            label = e(S["c_production"].format(name=name)) if name in production else e(name)
            failed = any(str(x).startswith("git:") for x in inv.get("errors") or []) or not inv.get("commit")
            state = f'<span class="label strong">{e(S["c_failed"].upper())}</span>' if failed else e(S["c_read"])
            rows.append([_td(label), _td(e(inv.get("branch"))), _td(f'<code>{e(str(inv.get("commit") or "")[:7])}</code>'),
                         _td(state)])
        if rows:
            L.append(_table(S["c_scanned_head"], rows))
        skipped = [s for s in inventory.get("skipped") or [] if isinstance(s, dict)]
        if skipped:
            listed = "; ".join(f"{e(s.get('project'))} ({e(s.get('reason'))})" for s in skipped)
            L.append(f"<p>{S['c_skipped'].format(list=listed)}</p>")
    L.append(_releases(data, S))
    # data sources
    L.append(f"<h3>{S['c_sources']}</h3>")
    sources = audit.get("sources") if isinstance(audit.get("sources"), dict) else {}
    stamps = {"osv-scanner": audit.get("generated_at"), "cisa_kev": data["kev_fetched"],
              "endoflife": audit.get("generated_at"), "registries": audit.get("generated_at"),
              "openvex": audit.get("generated_at"), "secrets": (data["secrets"] or {}).get("generated_at"),
              "hosts": (data["hosts"] or {}).get("last_checked")}
    order = ["git", "osv-scanner", "cisa_kev", "endoflife", "registries", "openvex", "secrets", "hosts"]
    names = [n for n in order if n in sources or n in ("osv-scanner", "cisa_kev", "endoflife", "secrets")]
    names += [n for n in sources if n not in names]
    if not data["hosts_active"] and "hosts" not in sources:
        names = [n for n in names if n != "hosts"]
    rows = []
    for n in names:
        info = sources.get(n)
        if n == "secrets" and not isinstance(info, dict):
            sec = _secrets_state(data)
            state = (e(S["c_ok"]) if sec["state"] == "ok" else
                     e(S["c_src_skipped"].format(reason=sec["reason"] or S["unknown"])) if sec["state"] == "skipped"
                     else e(S["c_src_absent"]))
        else:
            state = _source_state(info, S)
        stamp = stamps.get(n) if isinstance(info, dict) or n == "secrets" else None
        rows.append([_td(e(S["src"].get(n, n))), _td(state),
                     _td(_time(stamp) if stamp else f'<span class="na">{S["na"]}</span>')])
    L.append(_table(S["c_sources_head"], rows))
    # secrets scan
    L.append(f"<h3>{S['c_secrets']}</h3>")
    sec = _secrets_state(data)
    if sec["state"] == "ok":
        L.append(f"<p>{S['c_secrets_ran'].format(mode=e(S['secrets_modes'].get(sec.get('mode'), sec.get('mode'))), engine=e(sec.get('engine') or S['unknown']), repos=e(sec.get('repos')))}</p>")
        if sec["failed"]:
            L.append(f'<p class="warn">{S["c_secrets_failed"].format(n=sec["failed"])}</p>')
    elif sec["state"] in ("skipped", "failed"):
        reason = sec["reason"] or (S["na_secrets_failed"] if sec["state"] == "failed" else S["unknown"])
        L.append(f'<p class="warn"><span class="label strong">{e(S["label_skipped"].upper())}</span> '
                 f'{S["c_secrets_skipped"].format(reason=e(reason))}</p>')
    else:
        L.append(f'<p class="warn">{S["c_secrets_unknown"]}</p>')
    # hosts
    L.append(f"<h3>{S['c_hosts']}</h3>")
    hosts = (status.get("counts") or {}).get("hosts") if data["hosts_active"] else None
    if not data["hosts_active"]:
        L.append(f"<p>{S['c_hosts_off']}</p>")
    elif not isinstance(hosts, dict):
        L.append(f'<p class="na">{S["na"]}</p>')
    elif hosts.get("skipped"):
        L.append(f'<p class="warn">{S["c_hosts_skipped"].format(reason=e(hosts["skipped"]), last=e(hosts.get("last_checked") or S["unknown"]))}</p>')
    else:
        L.append(f"<p>{S['c_hosts_text'].format(checked=e(hosts.get('checked', 0)), failed=e(hosts.get('failed', 0)), unsupported=e(hosts.get('unsupported', 0)), last=_time(hosts.get('last_checked')) or e(S['unknown']))}</p>")
    # timestamps
    L.append(f"<h3>{S['c_times']}</h3>")
    states = data["states"]

    def stamp(key, value):
        if data.get(f"{key}_derived"):
            return e(S["t_issues_derived"])
        if states.get(key) == "absent":
            return f'<span class="na">{S["t_absent"]}</span>'
        if states.get(key) == "unreadable":
            return f'<span class="label strong">{e(S["t_unreadable"].upper())}</span>'
        return _time(value) if value else f'<span class="na">{S["na"]}</span>'

    zone = _offset(_ZONE.get())
    if zone:
        L.append(f"<p>{e(S['c_times_zone'].format(zone=zone))}</p>")
    rows = [[_td(e(S["t_inventory"])), _td(stamp("inventory", (data["inventory"] or {}).get("generated_at")))],
            [_td(e(S["t_audit"])), _td(stamp("audit", audit.get("generated_at")))],
            [_td(e(S["t_status"])), _td(stamp("status", status.get("generated_at")))],
            [_td(e(S["t_issues"])), _td(stamp("issues", (data["issues"] or {}).get("generated_at")))]]
    if data["secrets_enabled"] or states.get("secrets") == "ok":
        rows.append([_td(e(S["t_secrets"])), _td(stamp("secrets", (data["secrets"] or {}).get("generated_at")))])
    if data["hosts_active"]:
        rows.append([_td(e(S["t_hosts"])), _td(stamp("hosts", (data["hosts"] or {}).get("last_checked")))])
    rows.append([_td(e(S["t_kev"])), _td(_time(data["kev_fetched"]) if data["kev_fetched"]
                                         else f'<span class="na">{S["na"]}</span>')])
    L.append(_table(S["c_times_head"], rows))
    limits = list(S["limits"])
    actions = (audit.get("stats") or {}).get("github_actions_unchecked")
    if actions:
        limits.insert(2, S["limit_actions"].format(n=actions))
    st = audit.get("stats") or {}
    what = [S[key].format(n=st[stat]) for key, stat in (("limit_gap_projects", "projects_not_scanned"),
                                                         ("limit_gap_branches", "coverage_gaps"),
                                                         ("limit_gap_unmatched", "packages_unmatched")) if st.get(stat)]
    if what:
        limits.insert(0, S["limit_gaps"].format(what="; ".join(what)))
    imports = [r for r in audit.get("imported_sboms") or [] if isinstance(r, dict)]
    if imports:
        text = S["limit_imports"].format(n=len(imports))
        off = [f"{r.get('project')}@{r.get('branch')}" for r in imports if sbomimport.staleness(r)]
        if off:
            text += " " + S["limit_imports_off"].format(n=len(off), which=", ".join(off))
        limits.insert(1, text)
    L.append(f"<h3>{S['c_limits']}</h3><ul>" + "".join(f"<li>{e(x)}</li>" for x in limits) + "</ul></section>")
    return "".join(L)


def _eol_terms(items: list, S: dict) -> str:
    """The `releases.json` end-of-life entries (`nodejs 20 (EOL 2026-04-30)`, written in English) joined, with
    their fixed English wording put into the report's language."""
    out = []
    for item in items:
        text = str(item)
        for en, local in S.get("c_rel_eol_terms") or ():
            text = text.replace(en, local)
        out.append(text)
    return ", ".join(out)


def _releases(data: dict, S: dict) -> str:
    """The releases under audit (from `releases.json`), or '' when no project has release scanning."""
    doc = data.get("releases")
    projects = doc.get("projects") if isinstance(doc, dict) else None
    if not isinstance(projects, dict) or not projects:
        return ""
    rows = []
    for name, p in projects.items():
        for r in (p or {}).get("releases") or []:
            if not isinstance(r, dict):
                continue
            until = r.get("support_until")
            support = (e(S["c_rel_no_period"]) if not until else e(S["c_rel_until"].format(date=until))
                       if r.get("supported") else
                       f'<span class="label">{e(S["c_rel_out"].format(date=until).upper())}</span>')
            eol = r.get("eol_before_support_end") or []
            if eol:
                support += (f'<br><span class="warn">'
                            f'{e(S["c_rel_eol"].format(list=_eol_terms(eol, S)))}</span>')
            unknown = r.get("eol_unknown") or []
            if isinstance(unknown, list) and unknown:
                support += (f'<br><span class="warn">'
                            f'{e(S["c_rel_eol_unknown"].format(list=_eol_terms(unknown, S)))}</span>')
            o = r.get("open") or {}
            counts = f"{o.get('kev', 0)} / {o.get('critical', 0)} / {o.get('high', 0)}"
            if r.get("previous") is None:
                fixed = e(S["c_rel_oldest"])
            elif r.get("fixed_since_previous_unknown"):
                fixed = e(S["c_rel_unknown"])
            else:
                items = [f for f in r.get("fixed_since_previous") or [] if isinstance(f, dict)]
                fixed = e(S["c_rel_fixed"].format(n=len(items), prev=r["previous"]))
                kinds: dict[str, int] = {}
                for f in items:
                    if isinstance(f.get("change"), str) and f["change"] in S["c_rel_change"]:
                        kinds[f["change"]] = kinds.get(f["change"], 0) + 1
                if kinds:
                    fixed += '<br><span class="note">' + e("; ".join(
                        S["c_rel_change"][k].format(n=kinds[k]) for k in S["c_rel_change"] if k in kinds)) + "</span>"
            rows.append([_td(e(name)), _td(f"<code>{e(r.get('tag'))}</code>"), _td(e(_date(r.get("date")))),
                         _td(support), _td(e(counts)), _td(fixed)])
    if not rows:
        return ""
    return (f"<h3>{S['c_releases']}</h3>" + _table(S["c_releases_head"], rows)
            + f'<p class="caveat">{e(S["c_rel_note"])}</p>')


def _present(out: Path, row: int, S: dict) -> str:
    def has(*names):
        return [n for n in names if (out / n).exists()]

    yes, no = S["yes"], S["no"]
    if row == 0:
        n = len(list((out / "sbom").glob("*/*.cdx.json"))) if (out / "sbom").is_dir() else 0
        return f"{yes} ({n})" if n else no
    if row == 1:
        found = has("AUDIT.md", "audit.json", "STATUS.md")
        return (", ".join(found) or no) + f"; {S['e_schedule']}"
    if row == 2:
        return ", ".join(has("AUDIT.md", "SECRETS.md")) or no
    if row == 3:
        vex = len(list((out / "vex").glob("*.openvex.json"))) if (out / "vex").is_dir() else 0
        found = ([f"vex/ ({vex})"] if vex else []) + has("secrets-decisions.toml")
        return ", ".join(found) or no
    if row == 4:
        return (", ".join(has("log.md", "reports")) or no) + f"; {S['e_git']}"
    if row == 5:
        return ", ".join(has("INVENTORY.md", "AUDIT.md", "releases.json")) or no
    if row == 6:
        n = len(list((out / "sbom").glob("*/tags__*.cdx.json"))) if (out / "sbom").is_dir() else 0
        return f"{yes} ({n})" if n else no
    return ", ".join(has("cra", "CRA.md", "cra.json")) or no


def _evidence(data: dict, S: dict) -> str:
    rows = [[_td(f"<code>{e(a)}</code>" if i in (0, 3, 6, 7) else e(a)), _td(e(b)),
             _td(e(_present(data["out"], i, S)))]
            for i, (a, b) in enumerate(S["e_rows"])]
    return (f"<section><h2>{S['s_evidence']}</h2><p>{S['e_intro']}</p>"
            f'<p class="caveat">{S["e_caveat"]}</p>' + _table(S["e_head"], rows) + _cra(data, S) + "</section>")


def _cra(data: dict, S: dict) -> str:
    """Per product: one status per obligation from cra.json; a readiness overview, never a verdict."""
    L = [f"<h3>{e(S['cra_title'])}</h3>"]
    doc, state = data.get("cra"), data["states"].get("cra")
    products = (doc or {}).get("products")
    if state == "unreadable" or (doc is not None and not isinstance(products, dict)):
        return "".join(L) + f'<p class="na">{e(S["cra_unreadable"])}</p>'
    if doc is None:
        key = "cra_not_run" if data.get("cra_configured") else "cra_none"
        return "".join(L) + f'<p class="na">{e(S[key])}</p>'
    if not products:
        return "".join(L) + f'<p class="na">{e(S["cra_none"])}</p>'
    L.append(f"<p>{e(S['cra_intro'].format(date=_in_zone(doc.get('generated_at') or '', _ZONE.get())[:10]))}</p>")
    for key, p in products.items():
        if not isinstance(p, dict):
            continue
        head = S["cra_product"].format(name=p.get("name") or key, project=key, branch=p.get("branch") or S["na"])
        L.append(f"<h4>{e(head)}</h4>")
        if p.get("error"):
            L.append(f'<p class="na">{e(S["cra_error"].format(error=p["error"]))}</p>')
        if isinstance(p.get("kev_open"), int) and not isinstance(p["kev_open"], bool) and p["kev_open"] > 0:
            L.append(f'<p class="warn">{e(S["cra_kev"].format(n=p["kev_open"], project=key))}</p>')
        rows = []
        for o in p.get("obligations") or []:
            if not isinstance(o, dict):
                continue
            title = S["cra_ob"].get(o.get("id"), o.get("title") or o.get("id"))
            status = S["cra_status"].get(o.get("status"), S["na"])
            evidence = ", ".join(f"<code>{e(x)}</code>" for x in o.get("evidence") or [])
            ref = S["cra_ref"].get(o.get("id"), o.get("ref"))
            rows.append([_td(e(title)), _td(e(ref)), _td(e(status)), _td(evidence or "&ndash;")])
        L.append(_table(S["cra_head"], rows))
    return "".join(L)


def _produced(data: dict, S: dict) -> str:
    """Tool versions and data source freshness from audit.json `provenance` (manifest.py), and the manifest."""
    from .manifest import SOURCE_NAMES
    prov = data["audit"].get("provenance") if isinstance(data["audit"], dict) else None
    L = [f"<section><h2>{e(S['s_produced'])}</h2>"]
    if not isinstance(prov, dict) or not isinstance(prov.get("tools"), dict):
        return "".join(L) + f'<p class="na">{e(S["p_none"])}</p><p>{S["p_manifest"]}</p></section>'
    zone = _ZONE.get()

    def when(value):
        return _in_zone(value, zone) if value else S["na"]
    L.append("<p>" + e(S["p_intro"].format(version=prov.get("sbom_audit") or S["na"],
                                           python=prov.get("python") or S["na"],
                                           platform=prov.get("platform") or S["na"],
                                           config=prov.get("config_sha256") or S["p_no_config"])) + "</p>")
    tools = [[_td(e(n)), _td(e(v))] for n, v in prov["tools"].items()]
    engine = data["secrets"].get("engine") if isinstance(data.get("secrets"), dict) else None
    if isinstance(engine, dict) and engine.get("name"):
        tools.append([_td(e(S["p_engine"].format(name=engine["name"]))), _td(e(engine.get("version") or S["na"]))])
    L.append(_table(S["p_tools_head"], tools))
    rows = []
    for key, info in (prov.get("data_sources") or {}).items():
        if not isinstance(info, dict):
            continue
        if key == "osv":
            fresh = S["p_osv"].format(at=when(info.get("queried_at")))
        elif key == "cisa_kev":
            fresh = (S["p_kev"].format(date=info.get("catalog_date") or S["na"], at=when(info["fetched_at"]),
                                       origin=S["p_live"] if info.get("origin") == "live" else S["p_cache"])
                     if info.get("fetched_at") else S["p_kev_none"])
        elif key in ("endoflife", "registries"):
            fresh = (S["p_lookups"].format(n=info["answers"], live=info.get("live", 0), cached=info.get("cached", 0),
                                           oldest=when(info.get("oldest_fetch")))
                     if info.get("answers") else S["p_nothing"])
        elif key == "openvex":
            n = info.get("statements")
            fresh = S["p_vex"].format(n=n if n is not None else S["na"])
        else:
            fresh = ""
        rows.append([_td(e(SOURCE_NAMES.get(key, key))), _td(e(S["p_status"].get(info.get("status"), S["na"]))),
                     _td(e(fresh))])
    L.append(_table(S["p_sources_head"], rows))
    L.append(f"<p>{S['p_manifest']}</p></section>")
    return "".join(L)


# --------------------------------------------------------------------------- page

def render(data: dict, *, lang: str = "en", organisation: str | None = None) -> str:
    """The whole page for the documents in `data` (see `load`)."""
    if lang not in STRINGS:
        raise ValueError(f"language must be one of {', '.join(LANGUAGES)}")
    S = STRINGS[lang]
    data = {**data, "lang": lang}
    metrics = _metrics(data, S)
    title = S["title_for"].format(org=organisation) if organisation else S["title"]
    when = _run_date(data)
    token = _ZONE.set(_zone_of(when))
    try:
        body = (_header(data, S, organisation) + _overall(data, S, metrics) + _action(data, S)
                + _decisions(data, S) + _coverage(data, S) + _evidence(data, S) + _produced(data, S)
                + f"<footer>{S['footer']}</footer>")
    finally:
        _ZONE.reset(token)
    return ("<!doctype html>\n"
            f'<html lang="{S["html_lang"]}"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<meta name="referrer" content="no-referrer">'
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
            f"<title>{e(title)}{' ' + _date(when) if when else ''}</title><style>{CSS}</style></head>"
            f"<body>{body}</body></html>\n")


def _options(out: Path, lang: str | None, organisation: str | None):
    """(lang, organisation, secrets enabled, hosts active) from the config, overridden by the arguments."""
    from . import config
    cfg = config.load(out)                              # ConfigError propagates: a wrong key is the user's to fix
    return (lang or cfg.report.language, organisation if organisation is not None else cfg.report.organisation,
            cfg.secrets.enabled, cfg.hosts.active)


def write(out: Path, *, lang: str | None = None, organisation: str | None = None, dated: bool = True,
          hosts_active: bool | None = None) -> list[Path]:
    """Write REPORT.html and, with `dated`, `reports/<run date>-report.html`; returns the paths written.
    FileNotFoundError when there is no audit.json (nothing to report on)."""
    out = Path(out)
    if not (out / "audit.json").exists():
        raise FileNotFoundError("audit.json")
    lang, organisation, secrets_enabled, cfg_hosts = _options(out, lang, organisation)
    data = load(out, secrets_enabled=secrets_enabled, hosts_active=cfg_hosts if hosts_active is None else hosts_active)
    page = render(data, lang=lang, organisation=organisation)
    written = [atomic_write(out / REPORT_FILE, page)]
    if dated:
        day = str(_run_date(data) or "")[:10]
        if len(day) == 10:
            written.append(atomic_write(out / REPORTS_DIR / f"{day}{DATED_SUFFIX}", page))
    return written


def try_write(out: Path, say=print, hosts_active: bool | None = None) -> list[Path]:
    """`write` that never raises: the run has done its work and keeps its exit code."""
    try:
        return write(out, hosts_active=hosts_active)
    except Exception as exc:
        say(f"management report: not written ({describe_error(exc)})")
        return []


def describe_error(exc: BaseException, limit: int = 200) -> str:
    """`Type: message (file.py:line in function)` for a log line, never a traceback. The place comes from the
    last traceback frame (where it was raised). The message is given for an OSError only (the reason and the
    file name): any other exception raised while rendering may quote the data it was handling, and the report
    reads secrets.json, so its message stays out of the log, as everywhere a run logs a failure."""
    import traceback
    msg = ""
    if isinstance(exc, OSError):
        msg = exc.strerror or (str(exc) if not exc.filename else "")
        if exc.filename:
            msg += f": {Path(str(exc.filename)).name}"
        msg = " ".join(msg.split())
        if len(msg) > limit:
            msg = msg[:limit - 1] + "…"
    text = type(exc).__name__ + (f": {msg}" if msg else "")
    frames = traceback.extract_tb(exc.__traceback__) if exc.__traceback__ else []
    if frames:
        last = frames[-1]
        text += f" ({Path(last.filename).name}:{last.lineno} in {last.name})"
    return text


def cli(args) -> int:
    import sys
    out = Path(args.out)
    try:
        paths = write(out, lang=getattr(args, "lang", None))
    except FileNotFoundError:
        print(f"no audit.json in {out}: run /sbom-audit:run first", file=sys.stderr)
        return 2
    for p in paths:
        print(p.relative_to(out) if p.is_relative_to(out) else p)
    return 0
