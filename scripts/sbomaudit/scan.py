"""`scan`: export every project@branch, run Syft plus own readers, write SBOMs and inventory.json."""
from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import config, cyclonedx, gitio, preflight, readers, syft
from .config import Config, Project
from .errors import ToolError
from .model import BranchInventory, Component
from .versions import norm_py

INVENTORY_FILE = "inventory.json"


@dataclass
class ScanResult:
    inventories: list[BranchInventory] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    generated_at: str = ""


def sbom_path(out: Path, project: str, branch: str) -> Path:
    return out / "sbom" / project / f"{branch.replace('/', '__')}.cdx.json"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _direct_key(c: Component) -> tuple[str, str]:
    return (c.ecosystem, norm_py(c.name) if c.ecosystem == "PyPI" else c.name)


def _dedupe(comps: list[Component]) -> list[Component]:
    """Same (kind, ecosystem, name, version, purl) → one component with merged locations."""
    merged: dict[tuple, Component] = {}
    for c in comps:
        key = (*c.key(), c.purl)
        if key in merged:
            for loc in c.locations:
                if loc not in merged[key].locations:
                    merged[key].locations.append(loc)
        else:
            merged[key] = c
    return list(merged.values())


def _syft_excludes(ignore: list[str]) -> list[str]:
    out = []
    for entry in ignore:
        entry = entry.strip().strip("/")
        if entry:
            out.append(f"./{entry}/**")
    return out


def scan_branch(cfg: Config, project: Project, branch: str) -> BranchInventory:
    ref, sha, behind = gitio.branch_ref(project.path, branch)
    inv = BranchInventory(project=project.name, branch=branch, ref=ref, commit=sha, behind=behind)
    purl = config.project_purl(project)
    with tempfile.TemporaryDirectory(prefix="sbom-audit-") as tmp:
        src = Path(tmp) / "src"
        try:
            gitio.export_ref(project.path, ref, src)
        except gitio.GitError as exc:
            inv.errors.append(f"git: {exc}")
            return inv
        try:
            bom, packages = syft.inventory(src, exclude=_syft_excludes(project.ignore))
        except ToolError as exc:
            inv.errors.append(f"syft: {exc}")
            bom, packages = cyclonedx.empty_bom(), []
        own_names = readers.self_packages(src)
        direct = readers.direct_deps(src, project.ignore)
        extra = readers.read_tree(src, project.ignore, remote=project.remote)
    for image in [c for c in extra if c.kind == "image"]:
        runtime = readers.runtime_from_image(image)
        if runtime is not None:
            extra.append(runtime)
    extra = _dedupe(extra)

    subject_ref = cyclonedx.set_subject(bom, project.name, purl, f"{branch}@{sha[:12]}")
    cyclonedx.drop_components(
        bom,
        lambda e: (syft.ECOSYSTEM_BY_PURL_TYPE.get(syft.purl_type(e.get("purl", "")),
                                                   syft.purl_type(e.get("purl", ""))),
                   e.get("name", "")) in own_names if e.get("purl") else False,
        keep_ref=subject_ref,
    )
    packages = [c for c in packages if (c.ecosystem, c.name) not in own_names]
    for c in packages:
        c.direct = _direct_key(c) in direct
    direct_by_purl = {c.purl: c.direct for c in packages}
    cyclonedx.mark_direct(bom, lambda e: direct_by_purl.get(e.get("purl")))
    known = {c.key() for c in packages}            # a package Syft already catalogued is not added twice
    extra = [c for c in extra if c.kind != "package" or c.key() not in known]
    cyclonedx.merge(bom, extra)

    path = sbom_path(cfg.out, project.name, branch)
    cyclonedx.write(bom, path)
    inv.sbom_path = path.relative_to(cfg.out).as_posix()
    inv.components = packages + extra
    return inv


def write_inventory(cfg: Config, result: ScanResult) -> Path:
    path = cfg.out / INVENTORY_FILE
    doc = {
        "generated_at": result.generated_at,
        "root": str(cfg.root),
        "mode": cfg.mode,
        "branches": cfg.branches,
        "inventories": [i.to_dict() for i in result.inventories],
        "skipped": result.skipped,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def read_inventory(out: Path) -> tuple[list[BranchInventory], dict]:
    """Inventories from `out/inventory.json` plus the document's header fields."""
    doc = json.loads((out / INVENTORY_FILE).read_text(encoding="utf-8"))
    invs = [BranchInventory.from_dict(d) for d in doc.get("inventories", [])]
    return invs, {k: v for k, v in doc.items() if k != "inventories"}


def scan(cfg: Config, only: list[str] | None = None, fetch: bool | None = None,
         log=None) -> ScanResult:
    """Scan every discovered project (or `only`), writing SBOMs and inventory.json under cfg.out."""
    say = log or (lambda msg: None)
    result = ScanResult(generated_at=_now())
    projects = config.discover(cfg)
    if only:
        wanted = list(only)
        by_name = {p.name: p for p in projects}
        projects = [by_name[n] for n in wanted if n in by_name]
        for n in wanted:
            if n not in by_name:
                result.skipped.append({"project": n, "reason": "not found under root"})
    do_fetch = cfg.fetch if fetch is None else fetch
    for project in projects:
        fetch_error = None
        if do_fetch and project.remote:
            fetch_error = gitio.fetch_origin(project.path)
        try:
            branches = gitio.pick_branches(project.path, cfg.branches)
        except gitio.GitError as exc:           # broken or half-cloned repo: a failed source, not a crash
            say(f"{project.name}: git failed ({exc})")
            for branch in dict.fromkeys(cfg.branches):
                inv = BranchInventory(project=project.name, branch=branch, ref=branch,
                                      commit="", errors=[f"git: {exc}"])
                if fetch_error:
                    inv.errors.append(f"fetch: {fetch_error}")
                result.inventories.append(inv)
            continue
        if not branches:
            result.skipped.append({"project": project.name,
                                   "reason": f"none of {cfg.branches} exist"})
            continue
        for branch in branches:
            say(f"{project.name}@{branch} …")
            try:
                inv = scan_branch(cfg, project, branch)
            except gitio.GitError as exc:
                inv = BranchInventory(project=project.name, branch=branch, ref=branch,
                                      commit="", errors=[f"git: {exc}"])
            if fetch_error:
                inv.errors.append(f"fetch: {fetch_error}")
            result.inventories.append(inv)
            say(f"  {len(inv.components)} components" + (f", errors: {inv.errors}" if inv.errors else ""))
    write_inventory(cfg, result)
    return result


def cli(args) -> int:
    cfg = config.load(args.out, root=args.root)
    missing = preflight.check(tools=preflight.SCAN_TOOLS)
    if missing:
        print(preflight.message(missing))
        return 4
    result = scan(cfg, only=args.only, fetch=args.fetch, log=print)
    failed = [i for i in result.inventories if i.errors]
    for s in result.skipped:
        print(f"skipped {s['project']}: {s['reason']}")
    print(f"{len(result.inventories)} SBOMs under {cfg.out / 'sbom'}; inventory: {cfg.out / INVENTORY_FILE}")
    return 2 if failed else 0
