"""`scan`: export every project@branch, run Syft plus own readers, write SBOMs and inventory.json."""
from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import config, cyclonedx, gaps, gitio, matching, pomresolve, preflight, readers, sbomimport, sbomquality, syft
from .config import Config, Project
from .errors import ToolError
from .model import BranchInventory, Component

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
    return (c.ecosystem, readers.package_key(c.ecosystem, c.name, c.purl))


def _entry_key(e: dict) -> tuple[str, str]:
    """`_direct_key` of a Syft CycloneDX entry."""
    purl = e.get("purl", "")
    eco = syft.ECOSYSTEM_BY_PURL_TYPE.get(syft.purl_type(purl), syft.purl_type(purl))
    return (eco, readers.package_key(eco, e.get("name", ""), purl))


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


def _resolved(c: Component) -> bool:
    return c.kind == "package" and not c.props.get("unresolved") and not matching.version_unresolved(c.version)


def _fold_gradle(packages: list[Component], extra: list[Component]) -> tuple[list[Component], dict[int, list[str]]]:
    """`extra` without the Gradle declarations that would only repeat a package another source already lists,
    and the build files added to Syft's entries (`id(component)` -> locations, for `cyclonedx.annotate`):
    - a package Syft lists with the same name and version: the Gradle entry's build files join Syft's entry;
    - a Gradle declaration without a resolved version whose `group:artifact` another reader on this branch
      resolves (a pom.xml through Syft, a legacy lock file): no unresolved duplicate; its build files join every
      resolved entry of that coordinate and are named in `gradle_unversioned` there, since the Gradle build may
      still pick a different version.
    A coordinate only Gradle declares, or that nothing resolves, stays as it is. An imported build SBOM is
    applied afterwards (`_apply_import`) and takes over a coordinate it names in either case."""
    syft_by_key = {c.key(): c for c in packages}
    syft_ids = {id(c) for c in packages}
    resolved: dict[tuple[str, str], list[Component]] = {}
    for c in packages + extra:
        if c.ecosystem == "Maven" and _resolved(c) and "gradle_config" not in c.props:
            resolved.setdefault(_direct_key(c), []).append(c)
    added: dict[int, list[str]] = {}

    def join(target: Component, locations: list[str]) -> None:
        for loc in locations:
            if loc not in target.locations:
                target.locations.append(loc)
                if id(target) in syft_ids:
                    added.setdefault(id(target), []).append(loc)

    out = []
    for c in extra:
        if c.kind != "package" or "gradle_config" not in c.props:
            out.append(c)
            continue
        same = syft_by_key.get(c.key())
        if same is not None:
            join(same, c.locations)
            continue
        hits = resolved.get(_direct_key(c)) if c.purl and not _resolved(c) else None
        if hits:
            for r in hits:
                join(r, c.locations)
                noted = r.props.setdefault("gradle_unversioned", [])
                noted.extend(loc for loc in c.locations if loc not in noted)
            continue
        out.append(c)
    return out, added


def _syft_excludes(ignore: list[str]) -> list[str]:
    out = []
    for entry in ignore:
        entry = entry.strip().strip("/")
        if entry:
            out.append(f"./{entry}/**")
    return out


def _read_import(cfg: Config, project: Project, branch: str, src: Path, inv: BranchInventory):
    """(Document, package_source) of the build SBOM imported for this project@branch, or None. A broken file is
    an error on the inventory, and the repository scan stands."""
    where = None
    try:
        found = sbomimport.find(cfg.out, project.name, branch, src, project.sbom)
        if found is None:
            return None
        path, where, from_evidence = found
        raw = sbomimport.read_capped(path)
        doc = sbomimport.parse(raw)
    except (sbomimport.Rejected, OSError) as exc:
        inv.errors.append(f"import: {where or project.sbom}: {exc}; the repository scan is used")
        return None
    provenance = sbomimport.read_provenance(path) if from_evidence else {}
    # a file committed in the repository: its commit is the last one on this branch that changed it
    last = None if from_evidence else gitio.last_change(project.path, inv.commit, where)
    return doc, sbomimport.source(doc, raw, where, from_evidence, provenance, inv.commit, last_change=last)


def _kept_label(c: Component) -> str:
    version = c.version if c.version and not matching.version_unresolved(c.version) else "(version not resolved)"
    return f"{c.qualified_name()} {version}"


def _apply_import(bom: dict, subject_ref: str, imported, packages: list[Component], extra: list[Component],
                  own_names: set, direct: dict, dev_only: set,
                  inv: BranchInventory) -> tuple[list[Component], list[Component]]:
    """Add the import's packages to the scan's. In every ecosystem the import holds, a package both name is the
    import's (version, scope, direct); a scan package the import does not name stays, marked
    `not_in_build_sbom` (with an unresolved version it stays listed as not checked). Other ecosystems, images
    and runtime pins are untouched. An imported package keeps the manifests the scan found it in (or that
    declare it), else it points at the import file."""
    doc, src = imported
    comps, via = sbomimport.packages(doc, own_names, direct)
    replaced = sorted({c.ecosystem for c in comps})
    named = {_direct_key(c) for c in comps}
    manifests: dict[tuple, list[str]] = {}
    unversioned: dict[tuple, list[str]] = {}       # Gradle build files that leave the version to the build
    for c in packages + [e for e in extra if e.kind == "package"]:
        key = _direct_key(c)
        for loc in c.locations:
            manifests.setdefault(key, [])
            if loc not in manifests[key]:
                manifests[key].append(loc)
        gradle_open = list(c.props.get("gradle_unversioned") or [])
        if "gradle_config" in c.props and not _resolved(c):
            gradle_open += c.locations
        for loc in gradle_open:
            unversioned.setdefault(key, [])
            if loc not in unversioned[key]:
                unversioned[key].append(loc)
    for c in comps:
        key = _direct_key(c)
        c.locations = sorted(manifests.get(key) or direct.get(key) or [src["file"]])
        if unversioned.get(key):
            c.props["gradle_unversioned"] = sorted(unversioned[key])
        # Maven <scope>test</scope> everywhere it is declared; a package the build reaches through another
        # dependency is on that one's classpath whatever its own declarations say
        if key in dev_only and c.direct is not False:
            c.scope = "optional"
    cyclonedx.drop_components(bom, lambda e: bool(e.get("purl")) and _entry_key(e) in named, keep_ref=subject_ref)
    cyclonedx.mark_not_in_build_sbom(bom, lambda e: _entry_key(e)[0] in replaced and _entry_key(e) not in named)
    covered = [c for c in packages + extra if c.kind == "package" and c.ecosystem in replaced]
    kept = [c for c in covered if _direct_key(c) not in named]
    for c in kept:
        c.props[cyclonedx.NOT_IN_BUILD_SBOM] = True
    labels = sorted({_kept_label(c) for c in kept})
    # repository entries without a version that the import gives one (a Gradle declaration that leaves the
    # version to a platform, an unexpanded `${…}`): the import resolved them
    versioned = {_direct_key(c) for c in comps if _resolved(c)}
    resolved_now = sum(1 for c in covered if not _resolved(c) and _direct_key(c) in versioned)
    inv.package_source = {**src, "replaced": replaced, "direct_from": via, "packages": len(comps),
                          "kept_from_scan": len(labels),
                          "kept_unresolved": sum(1 for x in labels if x.endswith("(version not resolved)")),
                          "kept": labels, "replaced_entries": len(covered) - len(kept),
                          "resolved_by_import": resolved_now,
                          "skipped_no_purl": doc.skipped_no_purl, "invalid": doc.invalid}
    packages = [c for c in packages if c.ecosystem not in replaced or _direct_key(c) not in named]
    extra = [c for c in extra if c.kind != "package" or c.ecosystem not in replaced or _direct_key(c) not in named]
    return packages, extra + comps


def scan_branch(cfg: Config, project: Project, branch: str, release: dict | None = None) -> BranchInventory:
    """SBOM and inventory of one branch, or of one release tag when `release` (from `gitio.list_tags`
    plus `order` and `index`) is given; `branch` is then the label `tags/<tag>`."""
    if release is not None:
        ref, sha, behind = release["ref"], release["commit"], 0
        meta = {k: release[k] for k in ("tag", "date", "order", "index") if k in release}
    else:
        ref, sha, behind = gitio.branch_ref(project.path, branch)
        meta = None
    inv = BranchInventory(project=project.name, branch=branch, ref=ref, commit=sha, behind=behind, release=meta)
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
        pomresolve.resolve_managed(src, bom, packages)   # Maven versions managed by poms in the same repo
        own_names = readers.self_packages(src)
        direct = readers.direct_deps(src, project.ignore)
        dev_only = readers.dev_only_deps(src, project.ignore)
        gradle_unknown = readers.gradle_unknown_direct(src, project.ignore)
        extra = readers.read_tree(src, project.ignore, remote=project.remote)
        imported = _read_import(cfg, project, branch, src, inv)
        inv.coverage_gaps = gaps.detect(src)       # submodules, unread C/C++/firmware manifests, C sources
    for image in [c for c in extra if c.kind == "image"]:
        runtime = readers.runtime_from_image(image)
        if runtime is not None:
            extra.append(runtime)
    extra = _dedupe(extra)

    version = release["tag"] if release is not None else branch   # a release SBOM names its version
    subject_ref = cyclonedx.set_subject(bom, project.name, purl, f"{version}@{sha[:12]}")
    # the project's own packages (npm/Python packages, Go modules, Maven reactor modules) are not dependencies
    cyclonedx.drop_components(bom, lambda e: _entry_key(e) in own_names if e.get("purl") else False,
                              keep_ref=subject_ref)
    packages = [c for c in packages if _direct_key(c) not in own_names]
    extra, gradle_added = _fold_gradle(packages, extra)
    if imported is not None:
        packages, extra = _apply_import(bom, subject_ref, imported, packages, extra, own_names, direct, dev_only, inv)
    for c in packages:
        # no manifest reader for the ecosystem: unknown (None), never a guessed "transitive"
        c.direct = _direct_key(c) in direct if c.ecosystem in readers.DIRECT_ECOSYSTEMS else None
        if c.direct is False and gradle_unknown.intersection(c.locations):   # a Gradle declaration not understood
            c.direct = None
        if _direct_key(c) in dev_only:     # Maven <scope>test</scope> everywhere it is declared
            c.scope = "optional"
    direct_by_purl = {c.purl: c.direct for c in packages}
    cyclonedx.mark_direct(bom, lambda e: direct_by_purl.get(e.get("purl")))
    cyclonedx.mark_scope(bom, lambda e: "optional" if _entry_key(e) in dev_only else None)
    notes = {c.purl: (gradle_added.get(id(c), []),
                      {k: c.props[k] for k in ("gradle_unversioned",) if c.props.get(k)})
             for c in packages if gradle_added.get(id(c)) or c.props.get("gradle_unversioned")}
    cyclonedx.annotate(bom, lambda e: notes.get(e.get("purl")))
    known = {c.key() for c in packages}            # a package Syft already catalogued is not added twice
    extra = [c for c in extra if c.kind != "package" or c.key() not in known]
    cyclonedx.merge(bom, extra)
    if imported is not None and imported[0].graph:
        # the import's dependency graph, in the bom-refs its packages were written under
        written = {e.get("bom-ref") for e in bom.get("components", []) or []}
        rows, cut = sbomimport.graph_rows(
            imported[0], lambda c: ref if (ref := cyclonedx.bom_ref(c)) in written else None, subject_ref)
        inv.package_source["graph_edges"] = cyclonedx.add_dependencies(bom, rows)
        if cut:
            inv.package_source["graph_truncated"] = True
    if inv.package_source:
        cyclonedx.set_package_source(bom, inv.package_source)

    path = sbom_path(cfg.out, project.name, branch)
    cyclonedx.write(bom, path)
    inv.sbom_path = path.relative_to(cfg.out).as_posix()
    inv.sbom_quality = sbomquality.summary(sbomquality.check(bom))
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
        if project.releases is not None:
            result.inventories += scan_releases(cfg, project, say)
    write_inventory(cfg, result)
    return result


def scan_releases(cfg: Config, project: Project, say) -> list[BranchInventory]:
    """One inventory per kept release tag (the newest `keep` matching `tags`), oldest first."""
    from . import releases
    opts = project.releases
    try:
        tags = gitio.list_tags(project.path, opts.tags)
    except gitio.GitError as exc:
        say(f"{project.name}: listing tags failed ({exc})")
        return [BranchInventory(project=project.name, branch=releases.label(opts.tags), ref=opts.tags, commit="",
                                errors=[f"git: listing tags: {exc}"], release={"tag": opts.tags, "index": 0})]
    chosen, order = releases.select(tags, opts.keep, opts.tags, prereleases=opts.prereleases)
    say(f"{project.name}: {len(tags)} tags match {opts.tags!r}; keeping {len(chosen)}, ordered by {order}")
    invs = []
    for index, tag in enumerate(chosen):
        branch = releases.label(tag["tag"])
        say(f"{project.name}@{branch} …")
        meta = {**tag, "order": order, "index": index}
        try:
            inv = scan_branch(cfg, project, branch, release=meta)
        except gitio.GitError as exc:
            inv = BranchInventory(project=project.name, branch=branch, ref=tag["ref"], commit=tag["commit"],
                                  errors=[f"git: {exc}"],
                                  release={k: meta[k] for k in ("tag", "date", "order", "index")})
        invs.append(inv)
        say(f"  {len(inv.components)} components" + (f", errors: {inv.errors}" if inv.errors else ""))
    return invs


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
