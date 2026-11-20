"""OSV ecosystem names, and what the repository scan can see of each.

The inventory keeps the ecosystem names Syft and the readers give (purl type based: `swift`, `cocoapods`,
`Go`, `PyPI`, `github`, ...). OSV advisories name the ecosystem in their own spelling (`SwiftURL`,
`GitHub Actions`, `crates.io`). Everything that compares an advisory with the inventory goes through
`key()`, so both sides meet in OSV form. Checked against the OSV schema ecosystem list
(https://ossf.github.io/osv-schema/, 2026-11-21): CocoaPods, Deno and JSR are not OSV ecosystems.
"""
from __future__ import annotations

import fnmatch

# lower-case internal name or purl type -> OSV ecosystem name; None: OSV has no such ecosystem
_OSV_BY_ALIAS: dict[str, str | None] = {
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go", "golang": "Go",
    "rubygems": "RubyGems", "gem": "RubyGems",
    "crates.io": "crates.io", "cargo": "crates.io",
    "maven": "Maven",
    "nuget": "NuGet",
    "hex": "Hex",
    "pub": "Pub",
    "packagist": "Packagist", "composer": "Packagist",
    "swift": "SwiftURL", "swifturl": "SwiftURL",
    "github": "GitHub Actions", "github actions": "GitHub Actions",
    "conan": "ConanCenter", "conancenter": "ConanCenter",
    "hackage": "Hackage",
    "cran": "CRAN",
    "deb": "Debian", "debian": "Debian",
    "apk": "Alpine", "alpine": "Alpine",
    "cocoapods": None, "deno": None, "jsr": None, "docker": None, "generic": None, "oci": None,
}

# OSV ecosystems whose packages the repository scan (Syft on the exported tree plus the plugin's readers)
# inventories. An advisory in any other ecosystem cannot be answered "absent" from the SBOMs.
PACKAGE_COVERAGE = frozenset({"npm", "PyPI", "Go", "RubyGems", "crates.io", "Maven", "NuGet", "Hex", "Pub",
                              "Packagist", "SwiftURL", "GitHub Actions", "ConanCenter", "Hackage"})

# OSV ecosystems of operating-system packages: they reach a project only through a container image (whose
# contents the scan does not inventory). A branch with an image can contain them; one without cannot.
IMAGE_ECOSYSTEMS = frozenset(e.lower() for e in (
    "AlmaLinux", "Alpaquita", "Alpine", "Azure Linux", "BellSoft Hardened Containers", "Bitnami", "Chainguard",
    "CleanStart", "Debian", "Docker Hardened Images", "Echo", "Mageia", "MinimOS", "openEuler", "openSUSE",
    "Photon OS", "Red Hat", "Red Hat Lightwell", "Rocky Linux", "SUSE", "TuxCare", "Ubuntu", "Wolfi"))

# (OSV ecosystem, package) of advisories against a language runtime itself -> the runtime product in the
# inventory. osv-scanner never sees these (the SBOM of a source tree has no Go toolchain component).
RUNTIME_PACKAGES = {("go", "stdlib"): "go", ("go", "toolchain"): "go"}

# basename globs per OSV ecosystem: the files that make the scan list that ecosystem's packages
MANIFEST_GLOBS: dict[str, tuple[str, ...]] = {
    "npm": ("package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock",
            "bun.lock", "bun.lockb"),
    "PyPI": ("requirements*.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "Pipfile.lock",
             "poetry.lock", "uv.lock", "pdm.lock"),
    "Go": ("go.mod",),
    "RubyGems": ("Gemfile", "Gemfile.lock", "*.gemspec"),
    "crates.io": ("Cargo.toml", "Cargo.lock"),
    "Maven": ("pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile"),
    "NuGet": ("*.csproj", "*.fsproj", "*.vbproj", "packages.config", "packages.lock.json"),
    "Hex": ("mix.exs", "mix.lock", "rebar.config", "rebar.lock"),
    "Pub": ("pubspec.yaml", "pubspec.lock"),
    "Packagist": ("composer.json", "composer.lock"),
    "SwiftURL": ("Package.swift", "Package.resolved"),
    "ConanCenter": ("conanfile.txt", "conanfile.py", "conan.lock"),
    "Hackage": ("*.cabal", "stack.yaml", "stack.yaml.lock", "cabal.project.freeze"),
}
MANIFESTS_PER_ECOSYSTEM = 20        # paths kept per ecosystem in inventory.json


def osv_name(ecosystem: str) -> str | None:
    """The OSV spelling of an inventory ecosystem or purl type; None when OSV has no such ecosystem.
    An OSV name passes through unchanged (with any `:<release>` suffix dropped)."""
    base = (ecosystem or "").split(":")[0].strip()
    low = base.lower()
    if low in _OSV_BY_ALIAS:
        return _OSV_BY_ALIAS[low]
    for name in PACKAGE_COVERAGE:
        if name.lower() == low:
            return name
    return base or None


def key(ecosystem: str) -> str:
    """The comparison key: OSV name lower-cased, else the given name lower-cased."""
    return (osv_name(ecosystem) or (ecosystem or "").split(":")[0]).lower()


def covered(ecosystem: str) -> bool:
    """Whether the repository scan inventories this (OSV) ecosystem's packages."""
    return key(ecosystem) in {e.lower() for e in PACKAGE_COVERAGE}


def from_images(ecosystem: str) -> bool:
    return key(ecosystem) in IMAGE_ECOSYSTEMS


def runtime_product(ecosystem: str, name: str) -> str | None:
    return RUNTIME_PACKAGES.get((key(ecosystem), (name or "").lower()))


def manifest_ecosystems(basename: str) -> list[str]:
    return [eco for eco, globs in MANIFEST_GLOBS.items() if any(fnmatch.fnmatchcase(basename, g) for g in globs)]
