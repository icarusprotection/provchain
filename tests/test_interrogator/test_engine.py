"""Tests for interrogator engine"""

import pytest
from unittest.mock import Mock, patch, MagicMock

from provchain.data.models import PackageIdentifier, PackageMetadata, RiskLevel
from provchain.interrogator.engine import InterrogatorEngine


@pytest.fixture
def sample_package_identifier():
    """Sample package identifier for testing"""
    return PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0")


@pytest.fixture
def sample_package_metadata():
    """Sample package metadata for testing"""
    from datetime import datetime, timezone
    
    return PackageMetadata(
        identifier=PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0"),
        description="HTTP library",
        homepage="https://requests.readthedocs.io",
        repository="https://github.com/psf/requests",
        license="Apache 2.0",
        maintainers=[],
        dependencies=[],
        first_release=datetime(2020, 1, 1, tzinfo=timezone.utc),
        latest_release=datetime(2024, 1, 1, tzinfo=timezone.utc),
        download_count=1000,
    )


def test_interrogator_engine_init_default():
    """Test engine initialization with defaults"""
    engine = InterrogatorEngine()
    
    assert engine.enable_behavior is False
    assert "typosquat" in engine.analyzers_enabled
    assert "maintainer" in engine.analyzers_enabled
    assert "metadata" in engine.analyzers_enabled
    assert "behavior" not in engine.analyzers_enabled


def test_interrogator_engine_init_with_behavior():
    """Test engine initialization with behavior analysis enabled"""
    engine = InterrogatorEngine(enable_behavior=True)
    
    assert engine.enable_behavior is True
    assert "behavior" in engine.analyzers_enabled


def test_interrogator_engine_init_custom_analyzers():
    """Test engine initialization with custom analyzers"""
    engine = InterrogatorEngine(analyzers=["typosquat", "metadata"])
    
    assert "typosquat" in engine.analyzers_enabled
    assert "metadata" in engine.analyzers_enabled
    assert "maintainer" not in engine.analyzers_enabled


def test_interrogator_engine_get_analyzers(sample_package_metadata):
    """Test getting list of analyzers"""
    engine = InterrogatorEngine()
    analyzers = engine._get_analyzers()
    
    assert len(analyzers) > 0
    assert all(hasattr(a, 'analyze') for a in analyzers)


def test_interrogator_engine_analyze_package_with_metadata(
    sample_package_identifier, sample_package_metadata
):
    """Test analyzing package with provided metadata"""
    engine = InterrogatorEngine(analyzers=["typosquat", "metadata"])
    
    report = engine.analyze_package(sample_package_identifier, sample_package_metadata)
    
    assert report.package == sample_package_identifier
    assert report.risk_score >= 0.0
    # UNKNOWN is valid for very low risk scores (< 2.0)
    assert report.overall_risk in [RiskLevel.UNKNOWN, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert len(report.results) > 0


def test_interrogator_engine_analyze_package_fetch_metadata(sample_package_identifier):
    """Test analyzing package by fetching metadata"""
    with patch('provchain.interrogator.engine.PyPIClient') as mock_pypi_class:
        mock_pypi = Mock()
        mock_pypi.get_package_info.return_value = PackageMetadata(
            identifier=sample_package_identifier,
            description="Test package",
        )
        mock_pypi_class.return_value.__enter__.return_value = mock_pypi
        mock_pypi_class.return_value.__exit__.return_value = None
        
        engine = InterrogatorEngine(analyzers=["typosquat"])
        
        report = engine.analyze_package(sample_package_identifier)
        
        assert report.package == sample_package_identifier
        mock_pypi.get_package_info.assert_called_once()


def test_interrogator_engine_analyzer_error_handling(sample_package_identifier, sample_package_metadata):
    """Test that analyzer errors are handled gracefully"""
    engine = InterrogatorEngine(analyzers=["typosquat", "metadata"])
    
    # Mock an analyzer to raise an error
    with patch.object(engine, '_get_analyzers') as mock_get:
        mock_analyzer = Mock()
        mock_analyzer.name = "test_analyzer"
        mock_analyzer.analyze.side_effect = Exception("Test error")
        mock_get.return_value = [mock_analyzer]
        
        report = engine.analyze_package(sample_package_identifier, sample_package_metadata)
        
        # Should still produce a report
        assert report is not None
        # Should have error result
        error_results = [r for r in report.results if "error" in r.raw_data]
        assert len(error_results) > 0


def test_interrogator_engine_risk_scoring(sample_package_identifier, sample_package_metadata):
    """Test that risk scoring is applied"""
    engine = InterrogatorEngine(analyzers=["typosquat", "metadata"])
    
    report = engine.analyze_package(sample_package_identifier, sample_package_metadata)
    
    assert report.risk_score >= 0.0
    assert report.risk_score <= 10.0
    assert report.confidence >= 0.0
    assert report.confidence <= 1.0


def test_interrogator_engine_recommendations(sample_package_identifier, sample_package_metadata):
    """Test that recommendations are generated"""
    engine = InterrogatorEngine(analyzers=["typosquat", "metadata"])
    
    report = engine.analyze_package(sample_package_identifier, sample_package_metadata)
    
    # Recommendations may be empty, but should be a list
    assert isinstance(report.recommendations, list)

def test_interrogator_engine_behavior_analyzer_docker_check():
    """Test that behavior analyzer checks Docker availability - covers lines 57-58"""
    with patch('provchain.interrogator.engine.check_docker_available') as mock_check_docker, \
         patch('provchain.interrogator.engine.BehaviorAnalyzer') as mock_behavior_class:
        mock_check_docker.return_value = True
        
        engine = InterrogatorEngine(analyzers=["behavior"])
        analyzers = engine._get_analyzers()
        
        # Should have called check_docker_available
        mock_check_docker.assert_called_once()
        # Should have created BehaviorAnalyzer with docker_available=True
        mock_behavior_class.assert_called_once_with(docker_available=True)
        assert len(analyzers) > 0

def test_interrogator_engine_behavior_analyzer_docker_unavailable():
    """Test behavior analyzer when Docker is unavailable"""
    with patch('provchain.interrogator.engine.check_docker_available') as mock_check_docker, \
         patch('provchain.interrogator.engine.BehaviorAnalyzer') as mock_behavior_class:
        mock_check_docker.return_value = False
        
        engine = InterrogatorEngine(analyzers=["behavior"])
        analyzers = engine._get_analyzers()
        
        # Should have called check_docker_available
        mock_check_docker.assert_called_once()
        # Should have created BehaviorAnalyzer with docker_available=False
        mock_behavior_class.assert_called_once_with(docker_available=False)
        assert len(analyzers) > 0

