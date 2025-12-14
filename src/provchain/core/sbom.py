"""SBOM data structures and operations"""

import json
from pathlib import Path
from typing import Any

from provchain.data.models import PackageIdentifier, SBOM


def generate_sbom_from_requirements(
    requirements_path: str, name: str = "project"
) -> SBOM:
    """Generate SBOM from requirements.txt file"""
    from provchain.core.package import parse_requirements_file

    specs = parse_requirements_file(requirements_path)
    packages = []

    for spec in specs:
        if spec.version:
            packages.append(
                PackageIdentifier(ecosystem="pypi", name=spec.name, version=spec.version)
            )
        else:
            # For packages without version specified in requirements file,
            # mark version as "unknown" to indicate it needs to be resolved
            # This is intentional behavior when version is not specified
            packages.append(
                PackageIdentifier(ecosystem="pypi", name=spec.name, version="unknown")
            )

    return SBOM(
        name=name,
        packages=packages,
        source=requirements_path,
    )


def load_sbom_from_file(path: str | Path) -> SBOM:
    """Load SBOM from JSON file"""
    path = Path(path)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
        return SBOM.model_validate(data)


def save_sbom_to_file(sbom: SBOM, path: str | Path) -> None:
    """Save SBOM to JSON file"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sbom.model_dump(), f, indent=2, default=str)


def export_sbom_cyclonedx(sbom: SBOM) -> dict[str, Any]:
    """Export SBOM in CycloneDX format"""
    components = []
    for pkg in sbom.packages:
        components.append(
            {
                "type": "library",
                "name": pkg.name,
                "version": pkg.version,
                "purl": pkg.purl,
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "timestamp": sbom.created.isoformat(),
            "tools": [{"name": "ProvChain", "version": "1.0.0"}],
        },
        "components": components,
    }

