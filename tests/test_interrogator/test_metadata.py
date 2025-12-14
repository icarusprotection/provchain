"""Tests for metadata analyzer"""

import pytest

from provchain.data.models import PackageIdentifier, PackageMetadata
from provchain.interrogator.analyzers.metadata import MetadataAnalyzer


def test_metadata_analyzer_complete_metadata(sample_package_metadata):
    """Test analyzer with complete metadata"""
    analyzer = MetadataAnalyzer()
    result = analyzer.analyze(sample_package_metadata)
    
    assert result.analyzer == "metadata"
    assert result.risk_score >= 0.0
    # Complete metadata should have low risk
    assert result.risk_score < 3.0


def test_metadata_analyzer_missing_fields():
    """Test analyzer flags missing metadata fields"""
    metadata = PackageMetadata(
        identifier=PackageIdentifier(ecosystem="pypi", name="test", version="1.0.0"),
        # Missing description, homepage, repository, license
    )
    
    analyzer = MetadataAnalyzer()
    result = analyzer.analyze(metadata)
    
    assert result.analyzer == "metadata"
    assert result.risk_score > 0.0
    assert len(result.findings) > 0
    # Should flag missing description and repository
    assert any("description" in f.id.lower() or "repository" in f.id.lower() for f in result.findings)


def test_metadata_analyzer_empty_description():
    """Test analyzer detects empty descriptions"""
    metadata = PackageMetadata(
        identifier=PackageIdentifier(ecosystem="pypi", name="test", version="1.0.0"),
        description="",  # Empty description
    )
    
    analyzer = MetadataAnalyzer()
    result = analyzer.analyze(metadata)
    
    # Should flag empty description
    assert result.risk_score > 0.0
    assert any("description" in f.id.lower() for f in result.findings)


def test_metadata_analyzer_short_description():
    """Test analyzer flags very short descriptions"""
    metadata = PackageMetadata(
        identifier=PackageIdentifier(ecosystem="pypi", name="test", version="1.0.0"),
        description="test",  # Too short
    )
    
    analyzer = MetadataAnalyzer()
    result = analyzer.analyze(metadata)
    
    assert result.risk_score > 0.0
    assert any("description" in f.id.lower() for f in result.findings)


def test_metadata_analyzer_invalid_urls():
    """Test analyzer flags invalid URLs"""
    metadata = PackageMetadata(
        identifier=PackageIdentifier(ecosystem="pypi", name="test", version="1.0.0"),
        homepage="not-a-valid-url",
        repository="also-invalid",
    )
    
    analyzer = MetadataAnalyzer()
    result = analyzer.analyze(metadata)
    
    assert result.risk_score > 0.0
    assert any("invalid" in f.id.lower() for f in result.findings)


def test_metadata_analyzer_no_license():
    """Test analyzer flags missing license"""
    metadata = PackageMetadata(
        identifier=PackageIdentifier(ecosystem="pypi", name="test", version="1.0.0"),
        description="A test package",
    )
    
    analyzer = MetadataAnalyzer()
    result = analyzer.analyze(metadata)
    
    assert result.risk_score > 0.0
    assert any("license" in f.id.lower() for f in result.findings)


def test_metadata_analyzer_non_osi_license():
    """Test analyzer flags non-OSI approved licenses"""
    metadata = PackageMetadata(
        identifier=PackageIdentifier(ecosystem="pypi", name="test", version="1.0.0"),
        description="A test package",
        license="Proprietary",
    )
    
    analyzer = MetadataAnalyzer()
    result = analyzer.analyze(metadata)
    
    # Should flag non-OSI license (but lower risk)
    assert any("osi" in f.id.lower() or "license" in f.id.lower() for f in result.findings)


def test_metadata_analyzer_is_valid_url():
    """Test URL validation helper"""
    analyzer = MetadataAnalyzer()
    
    assert analyzer.is_valid_url("https://example.com") is True
    assert analyzer.is_valid_url("http://example.com") is True
    assert analyzer.is_valid_url("not-a-url") is False
    assert analyzer.is_valid_url("") is False


def test_metadata_analyzer_is_valid_url_exception():
    """Test URL validation handles exceptions"""
    analyzer = MetadataAnalyzer()
    
    # Test with invalid URL that causes exception in urlparse
    # This is hard to trigger, but we can test the exception path
    # by passing a URL that might cause issues
    result = analyzer.is_valid_url("http://[invalid")
    assert result is False


def test_metadata_analyzer_very_new_package():
    """Test analyzer flags very new packages"""
    from datetime import datetime, timedelta, timezone
    
    metadata = PackageMetadata(
        identifier=PackageIdentifier(ecosystem="pypi", name="test", version="1.0.0"),
        description="A test package",
        first_release=datetime.now(timezone.utc) - timedelta(days=3),
        latest_release=datetime.now(timezone.utc) - timedelta(days=1),
    )
    
    analyzer = MetadataAnalyzer()
    result = analyzer.analyze(metadata)
    
    assert result.analyzer == "metadata"
    assert any("very_new" in f.id.lower() or "Very new" in f.title for f in result.findings)


def test_metadata_analyzer_no_downloads():
    """Test analyzer flags packages with no downloads"""
    metadata = PackageMetadata(
        identifier=PackageIdentifier(ecosystem="pypi", name="test", version="1.0.0"),
        description="A test package",
        download_count=0,
    )
    
    analyzer = MetadataAnalyzer()
    result = analyzer.analyze(metadata)
    
    assert result.analyzer == "metadata"
    assert any("no_downloads" in f.id.lower() or "No downloads" in f.title for f in result.findings)

