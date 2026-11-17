"""Data model shared by every pipeline stage. Plain dataclasses, JSON round-trippable."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


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

    def to_dict(self) -> dict:
        d = asdict(self)
        d["components"] = [c.to_dict() for c in self.components]
        if d["release"] is None:            # a branch: the inventory.json entry stays as before
            del d["release"]
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
