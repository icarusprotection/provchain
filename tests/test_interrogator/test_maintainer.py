"""Tests for maintainer analyzer"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

from provchain.data.models import (
    MaintainerInfo,
    PackageIdentifier,
    PackageMetadata,
)
from provchain.interrogator.analyzers.maintainer import MaintainerAnalyzer


def test_maintainer_analyzer_new_account(sample_package_metadata):
    """Test analyzer flags new maintainer accounts"""
    # Create metadata with very new account
    metadata = sample_package_metadata.model_copy()
    metadata.maintainers[0].account_created = datetime.now(timezone.utc) - timedelta(days=1)
    
    analyzer = MaintainerAnalyzer()
    result = analyzer.analyze(metadata)
    
    assert result.analyzer == "maintainer"
    assert result.risk_score > 0.0
    assert len(result.findings) > 0
    # Should have finding about new account
    assert any("new" in f.id.lower() or "New" in f.title for f in result.findings)


def test_maintainer_analyzer_established_account(sample_package_metadata):
    """Test analyzer accepts established accounts"""
    # Account created 5 years ago
    metadata = sample_package_metadata.model_copy()
    metadata.maintainers[0].account_created = datetime.now(timezone.utc) - timedelta(days=1825)
    
    analyzer = MaintainerAnalyzer()
    result = analyzer.analyze(metadata)
    
    assert result.analyzer == "maintainer"
    # Should have lower risk score for established account
    assert result.risk_score < 5.0


def test_maintainer_analyzer_no_maintainers():
    """Test analyzer handles packages with no maintainers"""
    metadata = PackageMetadata(
        identifier=PackageIdentifier(ecosystem="pypi", name="test", version="1.0.0"),
        maintainers=[],
    )
    
    analyzer = MaintainerAnalyzer()
    result = analyzer.analyze(metadata)
    
    assert result.analyzer == "maintainer"
    assert result.risk_score > 0.0  # Should flag missing maintainers
    assert any("missing" in f.id.lower() or "No maintainer" in f.title for f in result.findings)


def test_maintainer_analyzer_suspicious_email():
    """Test analyzer flags suspicious email domains"""
    metadata = PackageMetadata(
        identifier=PackageIdentifier(ecosystem="pypi", name="test", version="1.0.0"),
        maintainers=[
            MaintainerInfo(
                username="testuser",
                email="test@tempmail.com",  # Suspicious domain
                account_created=datetime.now(timezone.utc) - timedelta(days=365),
            )
        ],
    )
    
    analyzer = MaintainerAnalyzer()
    result = analyzer.analyze(metadata)
    
    assert result.risk_score > 0.0
    assert any("suspicious" in f.id.lower() or "email" in f.title.lower() for f in result.findings)


def test_maintainer_analyzer_github_integration(sample_package_metadata):
    """Test analyzer with GitHub integration"""
    metadata = sample_package_metadata.model_copy()
    metadata.maintainers[0].profile_url = "https://github.com/testuser"
    
    analyzer = MaintainerAnalyzer()
    
    with patch('provchain.interrogator.analyzers.maintainer.GitHubClient') as mock_github_class:
        mock_github = Mock()
        mock_github.get_user.return_value = {
            "created_at": "2020-01-01T00:00:00Z",
            "followers": 10,
        }
        mock_github_class.return_value = mock_github
        
        result = analyzer.analyze(metadata)
        
        assert result.analyzer == "maintainer"
        mock_github.get_user.assert_called_once_with("testuser")
        mock_github.close.assert_called_once()


def test_maintainer_analyzer_github_api_failure(sample_package_metadata):
    """Test analyzer handles GitHub API failures gracefully"""
    metadata = sample_package_metadata.model_copy()
    metadata.maintainers[0].profile_url = "https://github.com/testuser"
    
    analyzer = MaintainerAnalyzer()
    
    with patch('provchain.interrogator.analyzers.maintainer.GitHubClient') as mock_github_class:
        mock_github = Mock()
        mock_github.get_user.side_effect = Exception("API Error")
        mock_github_class.return_value = mock_github
        
        # Should not raise, should continue without GitHub data
        result = analyzer.analyze(metadata)
        
        assert result.analyzer == "maintainer"
        # Should still produce a result
        assert result.risk_score >= 0.0


def test_maintainer_analyzer_young_account(sample_package_metadata):
    """Test analyzer flags young maintainer accounts (less than 1 year)"""
    metadata = sample_package_metadata.model_copy()
    metadata.maintainers[0].account_created = datetime.now(timezone.utc) - timedelta(days=180)
    
    analyzer = MaintainerAnalyzer()
    result = analyzer.analyze(metadata)
    
    assert result.analyzer == "maintainer"
    assert result.risk_score > 0.0
    assert any("young" in f.id.lower() or "Young" in f.title for f in result.findings)


def test_maintainer_analyzer_no_packages(sample_package_metadata):
    """Test analyzer flags maintainers with no other packages"""
    metadata = sample_package_metadata.model_copy()
    metadata.maintainers[0].package_count = 0
    
    analyzer = MaintainerAnalyzer()
    result = analyzer.analyze(metadata)
    
    assert result.analyzer == "maintainer"
    assert result.risk_score > 0.0
    assert any("no_packages" in f.id.lower() or "no other" in f.title.lower() for f in result.findings)


def test_maintainer_analyzer_many_packages(sample_package_metadata):
    """Test analyzer flags maintainers with many packages"""
    metadata = sample_package_metadata.model_copy()
    metadata.maintainers[0].package_count = 100
    
    analyzer = MaintainerAnalyzer()
    result = analyzer.analyze(metadata)
    
    assert result.analyzer == "maintainer"
    assert any("many" in f.id.lower() or "many" in f.title.lower() for f in result.findings)


def test_maintainer_analyzer_new_github_account(sample_package_metadata):
    """Test analyzer flags new GitHub accounts"""
    metadata = sample_package_metadata.model_copy()
    metadata.maintainers[0].profile_url = "https://github.com/testuser"
    
    analyzer = MaintainerAnalyzer()
    
    with patch('provchain.interrogator.analyzers.maintainer.GitHubClient') as mock_github_class:
        mock_github = Mock()
        # Account created 30 days ago
        mock_github.get_user.return_value = {
            "created_at": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat().replace("+00:00", "Z"),
            "followers": 5,
        }
        mock_github_class.return_value = mock_github
        
        result = analyzer.analyze(metadata)
        
        assert result.analyzer == "maintainer"
        assert any("new_github" in f.id.lower() or "New GitHub" in f.title for f in result.findings)
        mock_github.close.assert_called_once()


def test_maintainer_analyzer_no_github_followers(sample_package_metadata):
    """Test analyzer flags GitHub accounts with no followers"""
    metadata = sample_package_metadata.model_copy()
    metadata.maintainers[0].profile_url = "https://github.com/testuser"
    
    analyzer = MaintainerAnalyzer()
    
    with patch('provchain.interrogator.analyzers.maintainer.GitHubClient') as mock_github_class:
        mock_github = Mock()
        # Account created 2 years ago but no followers
        mock_github.get_user.return_value = {
            "created_at": (datetime.now(timezone.utc) - timedelta(days=730)).isoformat().replace("+00:00", "Z"),
            "followers": 0,
        }
        mock_github_class.return_value = mock_github
        
        result = analyzer.analyze(metadata)
        
        assert result.analyzer == "maintainer"
        assert any("no_followers" in f.id.lower() or "no followers" in f.title.lower() for f in result.findings)
        mock_github.close.assert_called_once()

