"""Tests for watch CLI command"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock
from typer.testing import CliRunner

from provchain.cli.commands.watch import app


@pytest.fixture
def runner():
    """CLI test runner"""
    return CliRunner()


def test_watch_help(runner):
    """Test watch command help"""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "monitoring" in result.stdout.lower() or "watch" in result.stdout.lower()


def test_watch_without_sbom(runner):
    """Test watch command without SBOM file"""
    result = runner.invoke(app, ["watch"])
    
    assert result.exit_code == 0
    assert "Error" in result.stdout or "required" in result.stdout.lower()


def test_watch_sbom_not_found(runner):
    """Test watch command with non-existent SBOM file"""
    result = runner.invoke(app, ["watch", "--sbom", "nonexistent.json"])
    
    assert result.exit_code == 0
    assert "Error" in result.stdout or "not found" in result.stdout.lower()


def test_watch_check_sbom(runner, tmp_path):
    """Test watch command checking SBOM"""
    sbom_file = tmp_path / "sbom.json"
    sbom_file.write_text('''{
        "name": "test-project",
        "packages": [
            {
                "ecosystem": "pypi",
                "name": "requests",
                "version": "2.31.0"
            }
        ]
    }''')
    
    with patch('provchain.cli.commands.watch.Database') as mock_db_class, \
         patch('provchain.cli.commands.watch.WatchdogEngine') as mock_engine_class:
        
        mock_db = Mock()
        mock_db_class.return_value = mock_db
        
        mock_engine = Mock()
        mock_engine.check_sbom = AsyncMock(return_value=[])
        mock_engine_class.return_value = mock_engine
        
        result = runner.invoke(app, ["watch", "--sbom", str(sbom_file)])
        
        assert result.exit_code == 0
        assert "Checking SBOM" in result.stdout or "No alerts" in result.stdout


def test_watch_with_alerts(runner, tmp_path):
    """Test watch command with alerts"""
    sbom_file = tmp_path / "sbom.json"
    sbom_file.write_text('''{
        "name": "test-project",
        "packages": [
            {
                "ecosystem": "pypi",
                "name": "requests",
                "version": "2.31.0"
            }
        ]
    }''')
    
    from provchain.data.models import Alert, PackageIdentifier, RiskLevel
    
    test_alert = Alert(
        id="test-alert-1",
        package=PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0"),
        alert_type="maintainer_change",
        severity=RiskLevel.MEDIUM,
        title="Test Alert",
        description="Test description",
    )
    
    with patch('provchain.cli.commands.watch.Database') as mock_db_class, \
         patch('provchain.cli.commands.watch.WatchdogEngine') as mock_engine_class:
        
        mock_db = Mock()
        mock_db_class.return_value = mock_db
        
        mock_engine = Mock()
        mock_engine.check_sbom = AsyncMock(return_value=[test_alert])
        mock_engine_class.return_value = mock_engine
        
        result = runner.invoke(app, ["watch", "--sbom", str(sbom_file)])
        
        assert result.exit_code == 0
        assert "alert" in result.stdout.lower() or "Test Alert" in result.stdout


def test_watch_status(runner):
    """Test watch status command"""
    with patch('provchain.cli.commands.watch.Database') as mock_db_class:
        mock_db = Mock()
        mock_db.get_unresolved_alerts.return_value = []
        mock_db_class.return_value = mock_db
        
        result = runner.invoke(app, ["status"])
        
        assert result.exit_code == 0
        assert "Unresolved alerts" in result.stdout
        mock_db.get_unresolved_alerts.assert_called_once()


def test_watch_status_with_alerts(runner):
    """Test watch status command with alerts"""
    from provchain.data.models import Alert, PackageIdentifier, RiskLevel
    
    test_alert = Alert(
        id="test-alert-1",
        package=PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0"),
        alert_type="maintainer_change",
        severity=RiskLevel.MEDIUM,
        title="Test Alert",
        description="Test description",
    )
    
    with patch('provchain.cli.commands.watch.Database') as mock_db_class:
        mock_db = Mock()
        mock_db.get_unresolved_alerts.return_value = [test_alert]
        mock_db_class.return_value = mock_db
        
        result = runner.invoke(app, ["status"])
        
        assert result.exit_code == 0
        assert "Unresolved alerts: 1" in result.stdout
        assert "Test Alert" in result.stdout


def test_watch_daemon_mode(runner, tmp_path):
    """Test watch command in daemon mode - tests lines 40-41"""
    sbom_file = tmp_path / "sbom.json"
    sbom_file.write_text('''{
        "name": "test-project",
        "packages": [
            {
                "ecosystem": "pypi",
                "name": "requests",
                "version": "2.31.0"
            }
        ]
    }''')
    
    with patch('provchain.cli.commands.watch.Database') as mock_db_class, \
         patch('provchain.cli.commands.watch.WatchdogEngine') as mock_engine_class, \
         patch('provchain.cli.commands.watch.asyncio.run') as mock_asyncio_run:
        
        mock_db = Mock()
        mock_db_class.return_value = mock_db
        
        mock_engine = Mock()
        mock_engine.run_daemon = AsyncMock()
        mock_engine_class.return_value = mock_engine
        
        result = runner.invoke(app, ["watch", "--sbom", str(sbom_file), "--daemon"])
        
        assert result.exit_code == 0
        assert "Starting watchdog daemon" in result.stdout
        # Verify asyncio.run was called (line 41)
        mock_asyncio_run.assert_called_once()
        # Verify run_daemon was called on the engine
        mock_engine.run_daemon.assert_called_once()

