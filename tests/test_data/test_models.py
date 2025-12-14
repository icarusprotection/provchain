"""Tests for data models"""

import pytest
from provchain.data.models import PackageIdentifier


def test_package_identifier_purl():
    """Test PackageIdentifier purl property - covers line 30"""
    pkg_id = PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0")
    
    purl = pkg_id.purl
    
    assert purl == "pkg:pypi/requests@2.31.0"


def test_package_identifier_str():
    """Test PackageIdentifier __str__ method - covers line 33"""
    pkg_id = PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0")
    
    str_repr = str(pkg_id)
    
    assert str_repr == "requests==2.31.0"

