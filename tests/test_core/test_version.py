"""Tests for version handling"""

import pytest

from provchain.core.version import compare_versions, is_valid_version, parse_version


def test_parse_version():
    """Test parsing version strings"""
    v1 = parse_version("1.0.0")
    assert str(v1) == "1.0.0"
    
    v2 = parse_version("2.3.4")
    assert str(v2) == "2.3.4"


def test_compare_versions():
    """Test version comparison"""
    assert compare_versions("1.0.0", "1.0.1") < 0
    assert compare_versions("1.0.1", "1.0.0") > 0
    assert compare_versions("1.0.0", "1.0.0") == 0
    assert compare_versions("2.0.0", "1.9.9") > 0
    assert compare_versions("0.9.9", "1.0.0") < 0


def test_compare_versions_with_prerelease():
    """Test version comparison with prerelease versions"""
    assert compare_versions("1.0.0", "1.0.0a1") > 0
    assert compare_versions("1.0.0b1", "1.0.0a1") > 0


def test_is_valid_version():
    """Test version validation"""
    assert is_valid_version("1.0.0") is True
    assert is_valid_version("2.3.4") is True
    assert is_valid_version("0.1.0") is True
    assert is_valid_version("invalid") is False
    assert is_valid_version("") is False


def test_is_valid_version_with_prerelease():
    """Test version validation with prerelease"""
    assert is_valid_version("1.0.0a1") is True
    assert is_valid_version("1.0.0b2") is True
    assert is_valid_version("1.0.0rc1") is True

