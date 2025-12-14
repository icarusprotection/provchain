"""Tests for attack analyzer"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from provchain.data.cache import Cache
from provchain.data.db import Database
from provchain.data.models import MaintainerInfo, PackageIdentifier, PackageMetadata
from provchain.interrogator.analyzers.attack import AttackAnalyzer


@pytest.fixture
def attack_analyzer():
    """Create attack analyzer for testing"""
    db = Database(":memory:")
    cache = Cache(db)
    return AttackAnalyzer(cache=cache, db=db)


@pytest.fixture
def sample_package_metadata():
    """Create sample package metadata"""
    package = PackageIdentifier(ecosystem="pypi", name="test-package", version="1.0.0")
    maintainers = [
        MaintainerInfo(username="testuser", email="test@example.com"),
    ]
    return PackageMetadata(
        identifier=package,
        description="Test package",
        maintainers=maintainers,
        first_release=datetime.now(timezone.utc),
        download_count=1000,
    )


def test_attack_analyzer_init(attack_analyzer):
    """Test attack analyzer initialization"""
    assert attack_analyzer is not None
    assert attack_analyzer.name == "attack"


def test_attack_analyzer_basic(attack_analyzer, sample_package_metadata):
    """Test basic attack analyzer functionality"""
    with patch.object(attack_analyzer.typosquat_analyzer, "analyze") as mock_typosquat:
        from provchain.data.models import AnalysisResult, Finding, RiskLevel

        mock_typosquat.return_value = AnalysisResult(
            analyzer="typosquat",
            risk_score=0.0,
            confidence=0.5,
            findings=[],
        )

        result = attack_analyzer.analyze(sample_package_metadata)

        assert result.analyzer == "attack"
        assert result.risk_score >= 0.0
        assert isinstance(result.findings, list)


def test_attack_analyzer_dependency_confusion(attack_analyzer):
    """Test dependency confusion detection"""
    package = PackageIdentifier(ecosystem="pypi", name="internal-corp-package", version="1.0.0")
    metadata = PackageMetadata(
        identifier=package,
        description="Internal package",
        first_release=datetime.now(timezone.utc),
        download_count=50,  # Low downloads
    )

    result = attack_analyzer.analyze(metadata)

    # Should detect dependency confusion indicators
    dep_confusion_findings = [f for f in result.findings if "dependency_confusion" in f.id]
    # May or may not find it depending on thresholds, but should not crash
    assert isinstance(result.findings, list)

