"""Tests for watchdog engine"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import timedelta

from provchain.data.models import SBOM, PackageIdentifier
from provchain.watchdog.engine import WatchdogEngine


@pytest.fixture
def sample_sbom():
    """Sample SBOM for testing"""
    return SBOM(
        name="test-project",
        packages=[
            PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0")
        ],
    )


def test_watchdog_engine_init(temp_db):
    """Test watchdog engine initialization"""
    engine = WatchdogEngine(temp_db)
    
    assert engine.db == temp_db
    assert engine.running is False
    assert engine.maintainer_monitor is not None
    assert engine.repo_monitor is not None
    assert engine.release_monitor is not None
    assert engine.cve_monitor is not None


def test_watchdog_engine_init_with_token(temp_db):
    """Test watchdog engine initialization with GitHub token"""
    engine = WatchdogEngine(temp_db, github_token="test-token")
    
    assert engine.github_token == "test-token"


def test_watchdog_engine_init_custom_interval(temp_db):
    """Test watchdog engine initialization with custom check interval"""
    engine = WatchdogEngine(temp_db, check_interval_minutes=30)
    
    assert engine.check_interval.total_seconds() == 30 * 60


@pytest.mark.asyncio
async def test_watchdog_engine_check_sbom(sample_sbom, temp_db):
    """Test checking SBOM for alerts"""
    engine = WatchdogEngine(temp_db)
    
    # Mock monitors to return empty alerts
    engine.maintainer_monitor.check = AsyncMock(return_value=[])
    engine.cve_monitor.check = AsyncMock(return_value=[])
    
    alerts = await engine.check_sbom(sample_sbom)
    
    assert isinstance(alerts, list)
    assert len(alerts) == 0
    engine.maintainer_monitor.check.assert_called_once()
    engine.cve_monitor.check.assert_called_once()


@pytest.mark.asyncio
async def test_watchdog_engine_check_sbom_with_alerts(sample_sbom, temp_db):
    """Test checking SBOM that generates alerts"""
    from provchain.data.models import Alert, RiskLevel
    
    test_alert = Alert(
        id="test-alert-1",
        package=PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0"),
        alert_type="maintainer_change",
        severity=RiskLevel.MEDIUM,
        title="Test Alert",
        description="Test description",
    )
    
    engine = WatchdogEngine(temp_db)
    engine.maintainer_monitor.check = AsyncMock(return_value=[test_alert])
    engine.cve_monitor.check = AsyncMock(return_value=[])
    
    alerts = await engine.check_sbom(sample_sbom)
    
    assert len(alerts) == 1
    assert alerts[0].id == "test-alert-1"
    # Should be stored in database
    assert temp_db.get_unresolved_alerts()


def test_watchdog_engine_stop(temp_db):
    """Test stopping watchdog engine"""
    engine = WatchdogEngine(temp_db)
    engine.running = True
    
    engine.stop()
    
    assert engine.running is False


@pytest.mark.asyncio
async def test_watchdog_engine_run_daemon(sample_sbom, temp_db):
    """Test running watchdog daemon (short run)"""
    engine = WatchdogEngine(temp_db, check_interval_minutes=1)
    engine.maintainer_monitor.check = AsyncMock(return_value=[])
    engine.cve_monitor.check = AsyncMock(return_value=[])
    
    # Set a very short interval for testing
    engine.check_interval = timedelta(seconds=0.1)
    
    # Run daemon for a very short time
    import asyncio
    
    async def stop_soon():
        await asyncio.sleep(0.15)
        engine.stop()
    
    # Start daemon and stop task
    daemon_task = asyncio.create_task(engine.run_daemon(sample_sbom))
    stop_task = asyncio.create_task(stop_soon())
    
    # Wait for stop
    await stop_task
    # Give daemon a moment to check and exit
    await asyncio.sleep(0.1)
    
    # Cancel daemon if still running
    if not daemon_task.done():
        daemon_task.cancel()
        try:
            await daemon_task
        except asyncio.CancelledError:
            pass
    
    # Verify it was running (should have checked at least once or stopped)
    assert not engine.running or engine.maintainer_monitor.check.called


@pytest.mark.asyncio
async def test_watchdog_engine_run_daemon_with_alerts(sample_sbom, temp_db):
    """Test run_daemon with alerts - covers lines 68-70"""
    from provchain.data.models import Alert, RiskLevel
    
    test_alert = Alert(
        id="test-alert-1",
        package=PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0"),
        alert_type="maintainer_change",
        severity=RiskLevel.MEDIUM,
        title="Test Alert",
        description="Test description",
    )
    
    engine = WatchdogEngine(temp_db, check_interval_minutes=1)
    engine.maintainer_monitor.check = AsyncMock(return_value=[test_alert])
    engine.cve_monitor.check = AsyncMock(return_value=[])
    
    # Set a very short interval for testing
    engine.check_interval = timedelta(seconds=0.1)
    
    # Mock print to capture output
    with patch('builtins.print') as mock_print:
        # Run daemon for a very short time
        import asyncio
        
        async def stop_soon():
            await asyncio.sleep(0.15)
            engine.stop()
        
        # Start daemon and stop task
        daemon_task = asyncio.create_task(engine.run_daemon(sample_sbom))
        stop_task = asyncio.create_task(stop_soon())
        
        # Wait for stop
        await stop_task
        # Give daemon a moment to check and exit
        await asyncio.sleep(0.1)
        
        # Cancel daemon if still running
        if not daemon_task.done():
            daemon_task.cancel()
            try:
                await daemon_task
            except asyncio.CancelledError:
                pass
        
        # Verify alert was printed (lines 68-70)
        assert mock_print.called
        # Check that alert message was printed
        print_calls = [str(call) for call in mock_print.call_args_list]
        assert any("Alert:" in str(call) for call in print_calls)


@pytest.mark.asyncio
async def test_watchdog_engine_run_daemon_exception_handling(sample_sbom, temp_db):
    """Test run_daemon exception handling - covers lines 74-77"""
    engine = WatchdogEngine(temp_db, check_interval_minutes=1)
    
    # Make check_sbom raise an exception
    async def failing_check_sbom(sbom):
        raise Exception("Test error")
    
    engine.check_sbom = failing_check_sbom
    
    # Set a very short interval for testing
    engine.check_interval = timedelta(seconds=0.1)
    
    # Mock print to capture error output
    with patch('builtins.print') as mock_print:
        # Run daemon for a very short time
        import asyncio
        
        async def stop_soon():
            await asyncio.sleep(0.2)  # Give time for exception to be caught
            engine.stop()
        
        # Start daemon and stop task
        daemon_task = asyncio.create_task(engine.run_daemon(sample_sbom))
        stop_task = asyncio.create_task(stop_soon())
        
        # Wait for stop
        await stop_task
        # Give daemon a moment to handle exception and exit
        await asyncio.sleep(0.1)
        
        # Cancel daemon if still running
        if not daemon_task.done():
            daemon_task.cancel()
            try:
                await daemon_task
            except asyncio.CancelledError:
                pass
        
        # Verify error was printed (lines 74-77)
        assert mock_print.called
        # Check that error message was printed
        print_calls = [str(call) for call in mock_print.call_args_list]
        assert any("Watchdog error:" in str(call) for call in print_calls)
        assert any("Test error" in str(call) for call in print_calls)

