"""Package abstraction and parsing"""

import re
from typing import NamedTuple

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from provchain.data.models import PackageIdentifier


class PackageSpec(NamedTuple):
    """Parsed package specification"""

    name: str
    version: str | None = None
    specifier: str | None = None

    def to_identifier(self, ecosystem: str = "pypi") -> PackageIdentifier:
        """Convert to PackageIdentifier"""
        if self.version:
            return PackageIdentifier(ecosystem=ecosystem, name=self.name, version=self.version)
        elif self.specifier:
            # For specifiers, we'll need to resolve the version
            # For now, use the specifier as version
            return PackageIdentifier(
                ecosystem=ecosystem, name=self.name, version=self.specifier
            )
        else:
            # No version specified, use "latest" placeholder
            return PackageIdentifier(ecosystem=ecosystem, name=self.name, version="latest")


def parse_package_spec(spec: str) -> PackageSpec:
    """Parse a package specification string

    Examples:
        "requests" -> PackageSpec(name="requests")
        "requests==2.31.0" -> PackageSpec(name="requests", version="2.31.0")
        "requests>=2.0.0" -> PackageSpec(name="requests", specifier=">=2.0.0")
    """
    spec = spec.strip()

    # Try to parse as requirement
    try:
        req = Requirement(spec)
        if len(req.specifier) == 1:
            specifier = str(list(req.specifier)[0])
            # Check if it's an exact version
            if specifier.startswith("=="):
                version = specifier[2:]
                return PackageSpec(name=req.name, version=version)
            else:
                return PackageSpec(name=req.name, specifier=specifier)
        elif len(req.specifier) == 0:
            return PackageSpec(name=req.name)
        else:
            # Multiple specifiers, use the full specifier string
            return PackageSpec(name=req.name, specifier=str(req.specifier))
    except Exception:
        # Fallback: simple name extraction
        # Match package name (alphanumeric, underscore, hyphen, dot)
        match = re.match(r"^([a-zA-Z0-9_.-]+)(.*)$", spec)
        if match:
            name = match.group(1)
            rest = match.group(2).strip()
            if rest:
                # Try to extract version
                version_match = re.match(r"^==\s*([^\s]+)", rest)
                if version_match:
                    return PackageSpec(name=name, version=version_match.group(1))
                else:
                    return PackageSpec(name=name, specifier=rest)
            return PackageSpec(name=name)

    raise ValueError(f"Invalid package specification: {spec}")


def parse_requirements_file(path: str) -> list[PackageSpec]:
    """Parse a requirements.txt file"""
    specs = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue
            # Handle -r includes (skip for now)
            if line.startswith("-r") or line.startswith("--requirement"):
                continue
            # Handle -e editable installs (extract package name)
            if line.startswith("-e") or line.startswith("--editable"):
                line = line[2:].strip()
                # Extract package name from git URL or path
                if line.startswith("git+"):
                    # Extract from git URL
                    match = re.search(r"/([^/]+?)(?:\.git)?(?:@|#|$)", line)
                    if match:
                        line = match.group(1)
                    else:
                        continue
                else:
                    # Path-based, use directory name
                    line = line.split("/")[-1]

            try:
                spec = parse_package_spec(line)
                specs.append(spec)
            except ValueError:
                # Skip invalid lines
                continue

    return specs


def version_satisfies(version: str, specifier: str) -> bool:
    """Check if a version satisfies a specifier"""
    try:
        v = Version(version)
        spec = SpecifierSet(specifier)
        return v in spec
    except Exception:
        return False

