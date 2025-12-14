"""Tests for database layer"""

import pytest
from datetime import datetime, timezone

from provchain.data.db import Database
from provchain.data.models import (
    Alert,
    PackageIdentifier,
    SBOM,
    VetReport,
    RiskLevel,
    AnalysisResult,
)


def test_store_and_get_analysis(temp_db):
    """Test storing and retrieving analysis reports"""
    pkg_id = PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0")
    
    report = VetReport(
        package=pkg_id,
        overall_risk=RiskLevel.LOW,
        risk_score=2.5,
        confidence=0.8,
        results=[],
    )
    
    temp_db.store_analysis(report)
    
    retrieved = temp_db.get_analysis("pypi", "requests", "2.31.0")
    assert retrieved is not None
    assert retrieved.package.name == "requests"
    assert retrieved.package.version == "2.31.0"
    assert retrieved.risk_score == 2.5
    assert retrieved.overall_risk == RiskLevel.LOW


def test_get_analysis_not_found(temp_db):
    """Test getting analysis that doesn't exist"""
    retrieved = temp_db.get_analysis("pypi", "nonexistent", "1.0.0")
    assert retrieved is None


def test_store_analysis_updates_existing(temp_db):
    """Test that storing analysis updates existing record"""
    pkg_id = PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0")
    
    report1 = VetReport(
        package=pkg_id,
        overall_risk=RiskLevel.LOW,
        risk_score=2.5,
        confidence=0.8,
        results=[],
    )
    temp_db.store_analysis(report1)
    
    report2 = VetReport(
        package=pkg_id,
        overall_risk=RiskLevel.MEDIUM,
        risk_score=5.0,
        confidence=0.9,
        results=[],
    )
    temp_db.store_analysis(report2)
    
    retrieved = temp_db.get_analysis("pypi", "requests", "2.31.0")
    assert retrieved.risk_score == 5.0
    assert retrieved.overall_risk == RiskLevel.MEDIUM


def test_store_and_get_sbom(temp_db):
    """Test storing and retrieving SBOM"""
    sbom = SBOM(
        name="test-project",
        packages=[
            PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0")
        ],
    )
    
    sbom_id = temp_db.store_sbom(sbom, "requirements.txt")
    assert sbom_id > 0
    
    retrieved = temp_db.get_sbom(sbom_id)
    assert retrieved is not None
    assert retrieved.name == "test-project"
    assert len(retrieved.packages) == 1
    assert retrieved.packages[0].name == "requests"


def test_get_sbom_not_found(temp_db):
    """Test getting SBOM that doesn't exist"""
    retrieved = temp_db.get_sbom(99999)
    assert retrieved is None


def test_store_and_get_alert(temp_db):
    """Test storing and retrieving alerts"""
    alert = Alert(
        id="test-alert-1",
        package=PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0"),
        alert_type="maintainer_change",
        severity=RiskLevel.MEDIUM,
        title="Maintainer changed",
        description="Package maintainer has changed",
    )
    
    temp_db.store_alert(alert)
    
    unresolved = temp_db.get_unresolved_alerts()
    assert len(unresolved) >= 1
    # Find our alert
    found = next((a for a in unresolved if a.id == "test-alert-1"), None)
    assert found is not None
    assert found.title == "Maintainer changed"


def test_get_unresolved_alerts_empty(temp_db):
    """Test getting alerts when none exist"""
    alerts = temp_db.get_unresolved_alerts()
    assert len(alerts) == 0


def test_get_latest_maintainer_snapshot(temp_db):
    """Test getting latest maintainer snapshot"""
    maintainers1 = [{"username": "user1", "email": "user1@example.com"}]
    maintainers2 = [{"username": "user2", "email": "user2@example.com"}]
    
    temp_db.store_maintainer_snapshot("pypi", "requests", maintainers1)
    temp_db.store_maintainer_snapshot("pypi", "requests", maintainers2)
    
    latest = temp_db.get_latest_maintainer_snapshot("pypi", "requests")
    assert latest is not None
    assert latest[0]["username"] == "user2"  # Should be the latest


def test_get_latest_maintainer_snapshot_not_found(temp_db):
    """Test getting latest maintainer snapshot when none exists - covers line 342"""
    # Get snapshot for package that doesn't exist
    latest = temp_db.get_latest_maintainer_snapshot("pypi", "nonexistent-package")
    
    # Should return None (line 342)
    assert latest is None


def test_store_maintainer_snapshot(temp_db):
    """Test storing maintainer snapshot"""
    maintainers = [
        {"username": "testuser", "email": "test@example.com"}
    ]
    
    temp_db.store_maintainer_snapshot("pypi", "requests", maintainers)
    
    # Verify it was stored (check database directly)
    session = temp_db.Session()
    try:
        from provchain.data.db import MaintainerSnapshot
        snapshot = session.query(MaintainerSnapshot).filter_by(
            ecosystem="pypi",
            package_name="requests"
        ).first()
        assert snapshot is not None
        assert "testuser" in snapshot.maintainers_json
    finally:
        session.close()


def test_store_analysis_exception_handling(temp_db):
    """Test exception handling in store_analysis() - covers lines 178-180"""
    from unittest.mock import patch, MagicMock
    
    pkg_id = PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0")
    report = VetReport(
        package=pkg_id,
        overall_risk=RiskLevel.LOW,
        risk_score=2.5,
        confidence=0.8,
        results=[],
    )
    
    # Mock session.commit() to raise an exception
    mock_session = MagicMock()
    mock_session.query.return_value.filter_by.return_value.first.return_value = None
    mock_session.commit.side_effect = Exception("Database error")
    
    with patch.object(temp_db, 'Session', return_value=mock_session):
        with pytest.raises(Exception, match="Database error"):
            temp_db.store_analysis(report)
        
        # Verify rollback was called (line 179)
        mock_session.rollback.assert_called_once()


def test_store_sbom_exception_handling(temp_db):
    """Test exception handling in store_sbom() - covers lines 229-231"""
    from unittest.mock import patch, MagicMock
    
    sbom = SBOM(
        name="test-project",
        packages=[
            PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0")
        ],
    )
    
    # Mock session.commit() to raise an exception
    mock_session = MagicMock()
    mock_session.query.return_value.filter_by.return_value.first.return_value = None
    mock_session.commit.side_effect = Exception("Database error")
    
    with patch.object(temp_db, 'Session', return_value=mock_session):
        with pytest.raises(Exception, match="Database error"):
            temp_db.store_sbom(sbom, "requirements.txt")
        
        # Verify rollback was called (line 230)
        mock_session.rollback.assert_called_once()


def test_store_alert_exception_handling(temp_db):
    """Test exception handling in store_alert() - covers lines 271-273"""
    from unittest.mock import patch, MagicMock
    
    alert = Alert(
        id="test-alert-1",
        package=PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0"),
        alert_type="maintainer_change",
        severity=RiskLevel.MEDIUM,
        title="Test Alert",
        description="Test description",
    )
    
    # Mock session.commit() to raise an exception
    mock_session = MagicMock()
    mock_session.query.return_value.filter_by.return_value.first.return_value = None
    mock_session.commit.side_effect = Exception("Database error")
    
    with patch.object(temp_db, 'Session', return_value=mock_session):
        with pytest.raises(Exception, match="Database error"):
            temp_db.store_alert(alert)
        
        # Verify rollback was called (line 272)
        mock_session.rollback.assert_called_once()


def test_store_maintainer_snapshot_exception_handling(temp_db):
    """Test exception handling in store_maintainer_snapshot() - covers lines 321-323"""
    from unittest.mock import patch, MagicMock
    
    maintainers = [{"username": "testuser", "email": "test@example.com"}]
    
    # Mock session.commit() to raise an exception
    mock_session = MagicMock()
    mock_session.commit.side_effect = Exception("Database error")
    
    with patch.object(temp_db, 'Session', return_value=mock_session):
        with pytest.raises(Exception, match="Database error"):
            temp_db.store_maintainer_snapshot("pypi", "requests", maintainers)
        
        # Verify rollback was called (line 322)
        mock_session.rollback.assert_called_once()


def test_get_analysis_exception_handling(temp_db):
    """Test exception handling in get_analysis() - covers line 132 if it's exception handling"""
    from unittest.mock import patch, MagicMock
    
    # Mock session.query() to raise an exception
    mock_session = MagicMock()
    mock_session.query.side_effect = Exception("Database error")
    
    with patch.object(temp_db, 'Session', return_value=mock_session):
        # get_analysis() should handle the exception gracefully
        # Since there's no except block, the exception will propagate
        with pytest.raises(Exception, match="Database error"):
            temp_db.get_analysis("pypi", "requests", "2.31.0")


def test_get_unresolved_alerts_exception_handling(temp_db):
    """Test exception handling in get_unresolved_alerts()"""
    from unittest.mock import patch, MagicMock
    
    # Mock session.query() to raise an exception
    mock_session = MagicMock()
    mock_session.query.side_effect = Exception("Database error")
    
    with patch.object(temp_db, 'Session', return_value=mock_session):
        # get_unresolved_alerts() should handle the exception gracefully
        # Since there's no except block, the exception will propagate
        with pytest.raises(Exception, match="Database error"):
            temp_db.get_unresolved_alerts()


def test_get_latest_maintainer_snapshot_exception_handling(temp_db):
    """Test exception handling in get_latest_maintainer_snapshot()"""
    from unittest.mock import patch, MagicMock
    
    # Mock session.query() to raise an exception
    mock_session = MagicMock()
    mock_session.query.side_effect = Exception("Database error")
    
    with patch.object(temp_db, 'Session', return_value=mock_session):
        # get_latest_maintainer_snapshot() should handle the exception gracefully
        # Since there's no except block, the exception will propagate
        with pytest.raises(Exception, match="Database error"):
            temp_db.get_latest_maintainer_snapshot("pypi", "requests")


def test_store_analysis_updates_existing_path(temp_db):
    """Test store_analysis updates existing record path - covers lines 172-173"""
    pkg_id = PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0")
    
    # Store first report
    report1 = VetReport(
        package=pkg_id,
        overall_risk=RiskLevel.LOW,
        risk_score=2.5,
        confidence=0.8,
        results=[],
    )
    temp_db.store_analysis(report1)
    
    # Store second report with different values (should update existing)
    report2 = VetReport(
        package=pkg_id,
        overall_risk=RiskLevel.HIGH,
        risk_score=8.0,
        confidence=0.9,
        results=[],
    )
    temp_db.store_analysis(report2)
    
    # Verify it was updated
    retrieved = temp_db.get_analysis("pypi", "requests", "2.31.0")
    assert retrieved.risk_score == 8.0
    assert retrieved.overall_risk == RiskLevel.HIGH


def test_store_alert_updates_existing_path(temp_db):
    """Test store_alert updates existing record path - covers lines 265-266"""
    alert1 = Alert(
        id="test-alert-1",
        package=PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0"),
        alert_type="maintainer_change",
        severity=RiskLevel.MEDIUM,
        title="Original Title",
        description="Original description",
    )
    temp_db.store_alert(alert1)
    
    # Store updated alert (should update existing)
    alert2 = Alert(
        id="test-alert-1",  # Same ID
        package=PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0"),
        alert_type="maintainer_change",
        severity=RiskLevel.HIGH,
        title="Updated Title",
        description="Updated description",
    )
    temp_db.store_alert(alert2)
    
    # Verify it was updated
    unresolved = temp_db.get_unresolved_alerts()
    found = next((a for a in unresolved if a.id == "test-alert-1"), None)
    assert found is not None
    assert found.title == "Updated Title"
    assert found.severity == RiskLevel.HIGH


def test_database_init_default_path():
    """Test Database initialization with default path - covers line 132"""
    from unittest.mock import patch, MagicMock
    from pathlib import Path
    
    mock_home = Path("/mock/home")
    with patch('pathlib.Path.home', return_value=mock_home):
        with patch('provchain.data.db.create_engine') as mock_engine:
            db = Database()
            
            # Should use default path (line 132)
            expected_path = mock_home / ".provchain" / "provchain.db"
            assert db.db_path == expected_path

