"""Data model shared by every pipeline stage. Plain dataclasses, JSON round-trippable."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from urllib.parse import unquote


def purl_namespace(purl: str) -> str:
    """'pkg:maven/org.postgresql/postgresql@42.7.1?type=jar' -> 'org.postgresql'; '' without a namespace."""
    body = (purl or "").split("?", 1)[0].split("#", 1)[0]
    if not body.startswith("pkg:"):
        return ""
    parts = body[4:].split("/")
    if len(parts) < 3:                     # type/name only
        return ""
    return "/".join(unquote(p) for p in parts[1:-1])


def qualified_name(ecosystem: str, name: str, purl: str = "") -> str:
    """The package name as OSV writes it. Maven is `group:artifact` (Syft stores the bare artifact, the
    group is the purl namespace); every other ecosystem already carries its full name (npm `@scope/x`,
    Go module path)."""
    if (ecosystem or "").lower() == "maven" and ":" not in name:
        group = purl_namespace(purl)
        if group:
            return f"{group}:{name}"
    return name


def merge_direct(values) -> bool | None:
    """One `direct` for several places of a package: True when any place declares it, False only when every
    place is known to be transitive, else None. Unknown is never turned into transitive."""
    values = list(values)
    if any(v is True for v in values):
        return True
    if values and all(v is False for v in values):
        return False
    return None


def direct_text(direct: bool | None) -> str:
    """'direct', 'transitive' or 'unknown' for a `direct` value."""
    return "direct" if direct is True else "transitive" if direct is False else "unknown"


@dataclass
class Component:
    kind: str = "package"          # package | image | runtime
    ecosystem: str = ""            # npm, PyPI, cocoapods, docker, nodejs, ...
    name: str = ""
    version: str = ""              # "" when unresolved (manifest without lockfile, floating tag)
    purl: str = ""
    scope: str = "unknown"         # required | optional (dev-only) | unknown
    locations: list[str] = field(default_factory=list)   # repo-relative manifest paths
    direct: bool | None = None
    props: dict = field(default_factory=dict)

    def key(self) -> tuple[str, str, str, str]:
        return (self.kind, self.ecosystem, self.name, self.version)

    def qualified_name(self) -> str:
        return qualified_name(self.ecosystem, self.name, self.purl)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Component":
        return cls(**d)


@dataclass
class BranchInventory:
    project: str
    branch: str
    ref: str
    commit: str
    behind: int = 0
    components: list[Component] = field(default_factory=list)
    sbom_path: str = ""
    errors: list[str] = field(default_factory=list)
    # a release tag instead of a branch: {"tag", "date", "order"}; `branch` is then "tags/<tag>"
    release: dict | None = None
    # an imported build SBOM supplied the packages of some ecosystems (sbomimport.source plus "replaced", the
    # ecosystems it replaced); None: everything comes from the repository scan
    package_source: dict | None = None
    # structural check and data-field coverage of the written SBOM (sbomquality.summary); None: no SBOM written
    sbom_quality: dict | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["components"] = [c.to_dict() for c in self.components]
        for key in ("release", "package_source", "sbom_quality"):   # absent: the inventory.json entry stays as before
            if d[key] is None:
                del d[key]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "BranchInventory":
        d = dict(d)
        d["components"] = [Component.from_dict(c) for c in d.get("components", [])]
        return cls(**d)


@dataclass
class Finding:
    project: str
    branch: str
    component: Component
    vulns: list[dict] = field(default_factory=list)   # matching.summarize() dicts

    def to_dict(self) -> dict:
        return {"project": self.project, "branch": self.branch,
                "component": self.component.to_dict(), "vulns": self.vulns}

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(project=d["project"], branch=d["branch"],
                   component=Component.from_dict(d["component"]), vulns=list(d.get("vulns", [])))
