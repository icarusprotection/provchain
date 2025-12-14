"""Tests for SBOM operations"""

import json
from pathlib import Path

import pytest

from provchain.core.sbom import (
    export_sbom_cyclonedx,
    generate_sbom_from_requirements,
    load_sbom_from_file,
    save_sbom_to_file,
)
from provchain.data.models import PackageIdentifier, SBOM


def test_generate_sbom_from_requirements(tmp_path):
    """Test SBOM generation from requirements file"""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.31.0\nflask>=2.0.0\n")
    
    sbom = generate_sbom_from_requirements(str(req_file), "test-project")
    
    assert sbom.name == "test-project"
    assert len(sbom.packages) == 2
    assert sbom.packages[0].name == "requests"
    assert sbom.packages[0].version == "2.31.0"
    assert sbom.source == str(req_file)


def test_generate_sbom_from_requirements_without_version(tmp_path):
    """Test SBOM generation with packages without version"""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests\n")
    
    sbom = generate_sbom_from_requirements(str(req_file), "test-project")
    
    assert len(sbom.packages) == 1
    assert sbom.packages[0].name == "requests"
    assert sbom.packages[0].version == "unknown"


def test_save_and_load_sbom(tmp_path):
    """Test saving and loading SBOM from file"""
    sbom = SBOM(
        name="test-project",
        version="1.0.0",
        packages=[
            PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0")
        ],
    )
    
    sbom_file = tmp_path / "sbom.json"
    save_sbom_to_file(sbom, str(sbom_file))
    
    assert sbom_file.exists()
    
    loaded_sbom = load_sbom_from_file(sbom_file)
    assert loaded_sbom.name == "test-project"
    assert loaded_sbom.version == "1.0.0"
    assert len(loaded_sbom.packages) == 1
    assert loaded_sbom.packages[0].name == "requests"
    assert loaded_sbom.packages[0].version == "2.31.0"


def test_export_sbom_cyclonedx():
    """Test exporting SBOM to CycloneDX format"""
    sbom = SBOM(
        name="test-project",
        packages=[
            PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0")
        ],
    )
    
    cdx = export_sbom_cyclonedx(sbom)
    
    assert cdx["bomFormat"] == "CycloneDX"
    assert cdx["specVersion"] == "1.4"
    assert cdx["version"] == 1
    assert "metadata" in cdx
    assert "components" in cdx
    assert len(cdx["components"]) == 1
    assert cdx["components"][0]["name"] == "requests"
    assert cdx["components"][0]["version"] == "2.31.0"


def test_export_sbom_cyclonedx_multiple_packages():
    """Test exporting SBOM with multiple packages"""
    sbom = SBOM(
        name="test-project",
        packages=[
            PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0"),
            PackageIdentifier(ecosystem="pypi", name="flask", version="2.0.0"),
        ],
    )
    
    cdx = export_sbom_cyclonedx(sbom)
    
    assert len(cdx["components"]) == 2
    assert cdx["components"][0]["name"] == "requests"
    assert cdx["components"][1]["name"] == "flask"

