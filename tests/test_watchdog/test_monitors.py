"""Tests for watchdog monitors"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta, timezone

from provchain.data.models import SBOM, PackageIdentifier, RiskLevel
from provchain.watchdog.monitors.release import ReleaseMonitor
from provchain.watchdog.monitors.cve import CVEMonitor
from provchain.watchdog.monitors.maintainer import MaintainerMonitor
from provchain.watchdog.monitors.repo import RepositoryMonitor


def test_release_monitor_init(temp_db):
    """Test release monitor initialization"""
    monitor = ReleaseMonitor(temp_db)
    
    assert monitor.db == temp_db


@pytest.mark.asyncio
async def test_release_monitor_check_no_new_release(temp_db):
    """Test release monitor with no new release"""
    monitor = ReleaseMonitor(temp_db)
    
    with patch('provchain.watchdog.monitors.release.PyPIClient') as mock_pypi_class:
        mock_pypi = Mock()
        mock_package_info = Mock()
        mock_package_info.identifier.version = "2.31.0"
        mock_package_info.latest_release = datetime.now(timezone.utc) - timedelta(days=2)
        mock_pypi.get_package_info.return_value = mock_package_info
        mock_pypi_class.return_value.__enter__.return_value = mock_pypi
        mock_pypi_class.return_value.__exit__.return_value = None
        
        alerts = await monitor.check("requests")
        
        assert len(alerts) == 0


@pytest.mark.asyncio
async def test_release_monitor_check_new_release(temp_db):
    """Test release monitor with new release"""
    monitor = ReleaseMonitor(temp_db)
    
    with patch('provchain.watchdog.monitors.release.PyPIClient') as mock_pypi_class:
        mock_pypi = Mock()
        mock_package_info = Mock()
        mock_package_info.identifier.version = "2.32.0"
        # Very recent release (within last hour)
        mock_package_info.latest_release = datetime.now(timezone.utc) - timedelta(minutes=30)
        mock_pypi.get_package_info.return_value = mock_package_info
        mock_pypi_class.return_value.__enter__.return_value = mock_pypi
        mock_pypi_class.return_value.__exit__.return_value = None
        
        alerts = await monitor.check("requests")
        
        assert len(alerts) > 0
        assert alerts[0].alert_type == "new_release"
        assert "2.32.0" in alerts[0].title


@pytest.mark.asyncio
async def test_release_monitor_check_error_handling(temp_db):
    """Test release monitor error handling"""
    monitor = ReleaseMonitor(temp_db)
    
    with patch('provchain.watchdog.monitors.release.PyPIClient') as mock_pypi_class:
        mock_pypi_class.side_effect = Exception("API Error")
        
        alerts = await monitor.check("requests")
        
        # Should return empty list on error
        assert len(alerts) == 0


# CVE Monitor Tests
def test_cve_monitor_init(temp_db):
    """Test CVE monitor initialization"""
    monitor = CVEMonitor(temp_db)
    
    assert monitor.db == temp_db
    assert monitor.CHECK_INTERVAL == timedelta(minutes=15)


@pytest.mark.asyncio
async def test_cve_monitor_check_no_vulnerabilities(temp_db):
    """Test CVE monitor with no vulnerabilities"""
    monitor = CVEMonitor(temp_db)
    
    sbom = SBOM(
        name="test-project",
        packages=[
            PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0")
        ]
    )
    
    with patch('provchain.watchdog.monitors.cve.HTTPClient') as mock_client_class:
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}
        mock_client.post.return_value = mock_response
        mock_client_class.return_value.__enter__.return_value = mock_client
        
        alerts = await monitor.check(sbom)
        
        assert len(alerts) == 0


@pytest.mark.asyncio
async def test_cve_monitor_check_with_vulnerabilities(temp_db):
    """Test CVE monitor with vulnerabilities found"""
    monitor = CVEMonitor(temp_db)
    
    sbom = SBOM(
        name="test-project",
        packages=[
            PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0")
        ]
    )
    
    with patch('provchain.watchdog.monitors.cve.HTTPClient') as mock_client_class:
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "CVE-2023-12345",
                    "summary": "Test vulnerability",
                    "database_specific": {"severity": "HIGH"},
                    "details": "Vulnerability details"
                }
            ]
        }
        mock_client.post.return_value = mock_response
        mock_client_class.return_value.__enter__.return_value = mock_client
        
        alerts = await monitor.check(sbom)
        
        assert len(alerts) > 0
        assert alerts[0].alert_type == "cve"
        assert "CVE-2023-12345" in alerts[0].title
        assert alerts[0].severity == RiskLevel.HIGH


@pytest.mark.asyncio
async def test_cve_monitor_check_error_handling(temp_db):
    """Test CVE monitor error handling"""
    monitor = CVEMonitor(temp_db)
    
    sbom = SBOM(
        name="test-project",
        packages=[
            PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0")
        ]
    )
    
    with patch('provchain.watchdog.monitors.cve.HTTPClient') as mock_client_class:
        mock_client_class.side_effect = Exception("API Error")
        
        alerts = await monitor.check(sbom)
        
        # Should return empty list on error
        assert len(alerts) == 0


@pytest.mark.asyncio
async def test_cve_monitor_check_non_pypi_package(temp_db):
    """Test CVE monitor skips non-PyPI packages"""
    monitor = CVEMonitor(temp_db)
    
    sbom = SBOM(
        name="test-project",
        packages=[
            PackageIdentifier(ecosystem="npm", name="package", version="1.0.0")
        ]
    )
    
    alerts = await monitor.check(sbom)
    
    # Should return empty list for non-PyPI packages
    assert len(alerts) == 0


# Maintainer Monitor Tests
def test_maintainer_monitor_init(temp_db):
    """Test maintainer monitor initialization"""
    monitor = MaintainerMonitor(temp_db, github_token="test_token")
    
    assert monitor.db == temp_db
    assert monitor.github_token == "test_token"


@pytest.mark.asyncio
async def test_maintainer_monitor_check_no_previous_snapshot(temp_db):
    """Test maintainer monitor with no previous snapshot"""
    monitor = MaintainerMonitor(temp_db)
    
    with patch('provchain.watchdog.monitors.maintainer.PyPIClient') as mock_pypi_class:
        mock_pypi = MagicMock()
        mock_package_info = MagicMock()
        mock_maintainer = MagicMock()
        mock_maintainer.username = "testuser"
        mock_maintainer.email = "test@example.com"
        mock_maintainer.profile_url = "https://example.com/testuser"
        mock_package_info.maintainers = [mock_maintainer]
        mock_pypi.get_package_info.return_value = mock_package_info
        mock_pypi_class.return_value.__enter__.return_value = mock_pypi
        
        alerts = await monitor.check("requests")
        
        # Should store snapshot but not create alerts
        assert len(alerts) == 0


@pytest.mark.asyncio
async def test_maintainer_monitor_check_new_maintainer(temp_db):
    """Test maintainer monitor detects new maintainer"""
    monitor = MaintainerMonitor(temp_db)
    
    # Store initial snapshot
    temp_db.store_maintainer_snapshot("pypi", "requests", [
        {"username": "olduser", "email": "old@example.com", "profile_url": "https://example.com/olduser"}
    ])
    
    with patch('provchain.watchdog.monitors.maintainer.PyPIClient') as mock_pypi_class:
        mock_pypi = MagicMock()
        mock_package_info = MagicMock()
        mock_maintainer = MagicMock()
        mock_maintainer.username = "newuser"
        mock_maintainer.email = "new@example.com"
        mock_maintainer.profile_url = "https://example.com/newuser"
        mock_package_info.maintainers = [mock_maintainer]
        mock_pypi.get_package_info.return_value = mock_package_info
        mock_pypi_class.return_value.__enter__.return_value = mock_pypi
        
        alerts = await monitor.check("requests")
        
        assert len(alerts) > 0
        assert alerts[0].alert_type == "maintainer_added"
        assert alerts[0].severity == RiskLevel.HIGH


@pytest.mark.asyncio
async def test_maintainer_monitor_check_removed_maintainer(temp_db):
    """Test maintainer monitor detects removed maintainer"""
    monitor = MaintainerMonitor(temp_db)
    
    # Store initial snapshot with two maintainers
    temp_db.store_maintainer_snapshot("pypi", "requests", [
        {"username": "user1", "email": "user1@example.com", "profile_url": "https://example.com/user1"},
        {"username": "user2", "email": "user2@example.com", "profile_url": "https://example.com/user2"}
    ])
    
    with patch('provchain.watchdog.monitors.maintainer.PyPIClient') as mock_pypi_class:
        mock_pypi = MagicMock()
        mock_package_info = MagicMock()
        mock_maintainer = MagicMock()
        mock_maintainer.username = "user1"
        mock_maintainer.email = "user1@example.com"
        mock_maintainer.profile_url = "https://example.com/user1"
        mock_package_info.maintainers = [mock_maintainer]  # Only user1 remains
        mock_pypi.get_package_info.return_value = mock_package_info
        mock_pypi_class.return_value.__enter__.return_value = mock_pypi
        
        alerts = await monitor.check("requests")
        
        assert len(alerts) > 0
        assert alerts[0].alert_type == "maintainer_removed"
        assert alerts[0].severity == RiskLevel.MEDIUM


@pytest.mark.asyncio
async def test_maintainer_monitor_check_error_handling(temp_db):
    """Test maintainer monitor error handling"""
    monitor = MaintainerMonitor(temp_db)
    
    with patch('provchain.watchdog.monitors.maintainer.PyPIClient') as mock_pypi_class:
        mock_pypi_class.side_effect = Exception("API Error")
        
        alerts = await monitor.check("requests")
        
        # Should return empty list on error
        assert len(alerts) == 0


# Repository Monitor Tests
def test_repo_monitor_init(temp_db):
    """Test repository monitor initialization"""
    monitor = RepositoryMonitor(temp_db, github_token="test_token")
    
    assert monitor.db == temp_db
    assert monitor.github_token == "test_token"


@pytest.mark.asyncio
async def test_repo_monitor_check_public_repo(temp_db):
    """Test repository monitor with public repository"""
    monitor = RepositoryMonitor(temp_db)
    
    with patch('provchain.watchdog.monitors.repo.GitHubClient') as mock_github_class:
        mock_github = MagicMock()
        mock_github.parse_repo_url.return_value = ("owner", "repo")
        mock_github.get_repository.return_value = {"private": False}
        mock_github.close = MagicMock()
        mock_github_class.return_value = mock_github
        
        alerts = await monitor.check("https://github.com/owner/repo")
        
        assert len(alerts) == 0
        mock_github.close.assert_called_once()


@pytest.mark.asyncio
async def test_repo_monitor_check_private_repo(temp_db):
    """Test repository monitor detects private repository"""
    monitor = RepositoryMonitor(temp_db)
    
    with patch('provchain.watchdog.monitors.repo.GitHubClient') as mock_github_class:
        mock_github = MagicMock()
        mock_github.parse_repo_url.return_value = ("owner", "repo")
        mock_github.get_repository.return_value = {"private": True}
        mock_github.close = MagicMock()
        mock_github_class.return_value = mock_github
        
        alerts = await monitor.check("https://github.com/owner/repo")
        
        assert len(alerts) > 0
        assert alerts[0].alert_type == "repo_visibility_change"
        assert alerts[0].severity == RiskLevel.MEDIUM
        mock_github.close.assert_called_once()


@pytest.mark.asyncio
async def test_repo_monitor_check_error_handling(temp_db):
    """Test repository monitor error handling"""
    monitor = RepositoryMonitor(temp_db)
    
    with patch('provchain.watchdog.monitors.repo.GitHubClient') as mock_github_class:
        mock_github_class.side_effect = Exception("API Error")
        
        alerts = await monitor.check("https://github.com/owner/repo")
        
        # Should return empty list on error
        assert len(alerts) == 0

