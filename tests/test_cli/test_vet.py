"""Tests for vet command"""

import pytest
from unittest.mock import Mock, patch
from typer.testing import CliRunner

from provchain.cli.commands.vet import app


@pytest.fixture
def runner():
    """CLI test runner"""
    return CliRunner()


def test_vet_command_help(runner):
    """Test vet command help"""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Analyze package" in result.stdout or "package" in result.stdout.lower()


def test_vet_command_single_package(runner):
    """Test vetting a single package"""
    with patch('provchain.cli.commands.vet.InterrogatorEngine') as mock_engine_class, \
         patch('provchain.cli.commands.vet.Database') as mock_db_class, \
         patch('provchain.cli.commands.vet.Cache') as mock_cache_class, \
         patch('provchain.cli.commands.vet.format_report') as mock_format:
        
        from provchain.data.models import PackageIdentifier, RiskLevel
        
        mock_engine = Mock()
        # Create a proper mock report with all needed attributes
        mock_report = Mock()
        mock_report.package = PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0")
        mock_report.risk_score = 2.5
        mock_report.overall_risk = RiskLevel.LOW
        mock_report.confidence = 0.8
        mock_report.results = []
        mock_report.recommendations = []
        mock_engine.analyze_package.return_value = mock_report
        mock_engine_class.return_value = mock_engine
        
        mock_db = Mock()
        mock_db.get_analysis.return_value = None
        mock_db_class.return_value = mock_db
        
        mock_cache = Mock()
        mock_cache_class.return_value = mock_cache
        
        result = runner.invoke(app, ["requests==2.31.0"])
        
        # Should complete without error
        assert result.exit_code == 0


def test_vet_command_with_requirements(runner, tmp_path):
    """Test vetting from requirements file"""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.31.0\n")
    
    with patch('provchain.cli.commands.vet.InterrogatorEngine') as mock_engine_class, \
         patch('provchain.cli.commands.vet.Database') as mock_db_class, \
         patch('provchain.cli.commands.vet.Cache') as mock_cache_class, \
         patch('provchain.cli.commands.vet.format_report') as mock_format:
        
        from provchain.data.models import PackageIdentifier, RiskLevel
        
        mock_engine = Mock()
        mock_report = Mock()
        mock_report.package = PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0")
        mock_report.risk_score = 2.5
        mock_report.overall_risk = RiskLevel.LOW
        mock_report.confidence = 0.8
        mock_report.results = []
        mock_report.recommendations = []
        mock_engine.analyze_package.return_value = mock_report
        mock_engine_class.return_value = mock_engine
        
        mock_db = Mock()
        mock_db.get_analysis.return_value = None
        mock_db_class.return_value = mock_db
        
        mock_cache = Mock()
        mock_cache_class.return_value = mock_cache
        
        result = runner.invoke(app, ["-r", str(req_file), "requests"])
        
        assert result.exit_code == 0


def test_vet_command_ci_mode_low_risk(runner):
    """Test vet command in CI mode with low risk"""
    with patch('provchain.cli.commands.vet.InterrogatorEngine') as mock_engine_class, \
         patch('provchain.cli.commands.vet.Database') as mock_db_class, \
         patch('provchain.cli.commands.vet.Cache') as mock_cache_class, \
         patch('provchain.cli.commands.vet.format_report') as mock_format:
        
        from provchain.data.models import PackageIdentifier, RiskLevel
        
        mock_engine = Mock()
        mock_report = Mock()
        mock_report.package = PackageIdentifier(ecosystem="pypi", name="test-package", version="1.0.0")
        mock_report.risk_score = 2.0  # Below threshold
        mock_report.overall_risk = RiskLevel.LOW
        mock_report.confidence = 0.8
        mock_report.results = []
        mock_report.recommendations = []
        mock_engine.analyze_package.return_value = mock_report
        mock_engine_class.return_value = mock_engine
        
        mock_db = Mock()
        mock_db.get_analysis.return_value = None
        mock_db_class.return_value = mock_db
        
        mock_cache = Mock()
        mock_cache_class.return_value = mock_cache
        
        result = runner.invoke(app, ["--ci", "--threshold", "medium", "test-package"])
        
        # Should exit with code 0 for low risk
        assert result.exit_code == 0


def test_vet_command_ci_mode_high_risk(runner):
    """Test vet command in CI mode with high risk"""
    with patch('provchain.cli.commands.vet.InterrogatorEngine') as mock_engine_class, \
         patch('provchain.cli.commands.vet.Database') as mock_db_class, \
         patch('provchain.cli.commands.vet.Cache') as mock_cache_class, \
         patch('provchain.cli.commands.vet.format_report') as mock_format:
        
        from provchain.data.models import PackageIdentifier, RiskLevel
        
        mock_engine = Mock()
        mock_report = Mock()
        mock_report.package = PackageIdentifier(ecosystem="pypi", name="test-package", version="1.0.0")
        mock_report.risk_score = 8.0  # Above threshold
        mock_report.overall_risk = RiskLevel.HIGH
        mock_report.confidence = 0.8
        mock_report.results = []
        mock_report.recommendations = []
        mock_engine.analyze_package.return_value = mock_report
        mock_engine_class.return_value = mock_engine
        
        mock_db = Mock()
        mock_db.get_analysis.return_value = None
        mock_db_class.return_value = mock_db
        
        mock_cache = Mock()
        mock_cache_class.return_value = mock_cache
        
        result = runner.invoke(app, ["--ci", "--threshold", "medium", "test-package"])
        
        # Should exit with code 1 for high risk
        assert result.exit_code == 1


def test_vet_command_no_version_spec(runner, tmp_path):
    """Test vet command with package spec without version - tests line 47"""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests\n")  # No version specified
    
    with patch('provchain.cli.commands.vet.InterrogatorEngine') as mock_engine_class, \
         patch('provchain.cli.commands.vet.Database') as mock_db_class, \
         patch('provchain.cli.commands.vet.Cache') as mock_cache_class, \
         patch('provchain.cli.commands.vet.format_report') as mock_format:
        
        from provchain.data.models import PackageIdentifier, RiskLevel
        
        mock_engine = Mock()
        mock_report = Mock()
        mock_report.package = PackageIdentifier(ecosystem="pypi", name="requests", version="latest")
        mock_report.risk_score = 2.5
        mock_report.overall_risk = RiskLevel.LOW
        mock_report.confidence = 0.8
        mock_report.results = []
        mock_report.recommendations = []
        mock_engine.analyze_package.return_value = mock_report
        mock_engine_class.return_value = mock_engine
        
        mock_db = Mock()
        mock_db.get_analysis.return_value = None
        mock_db_class.return_value = mock_db
        
        mock_cache = Mock()
        mock_cache_class.return_value = mock_cache
        
        result = runner.invoke(app, ["-r", str(req_file), "requests"])
        
        # Should complete without error
        assert result.exit_code == 0
        # Verify that spec.to_identifier() was called (line 47)
        mock_engine.analyze_package.assert_called()


def test_vet_command_uses_cached_report(runner):
    """Test vet command uses cached report - tests line 59"""
    with patch('provchain.cli.commands.vet.InterrogatorEngine') as mock_engine_class, \
         patch('provchain.cli.commands.vet.Database') as mock_db_class, \
         patch('provchain.cli.commands.vet.Cache') as mock_cache_class, \
         patch('provchain.cli.commands.vet.format_report') as mock_format:
        
        from provchain.data.models import PackageIdentifier, RiskLevel, VetReport
        
        # Create a cached report
        cached_report = VetReport(
            package=PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0"),
            overall_risk=RiskLevel.LOW,
            risk_score=2.5,
            confidence=0.8,
            results=[],
        )
        
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine
        
        mock_db = Mock()
        mock_db.get_analysis.return_value = cached_report  # Return cached report
        mock_db_class.return_value = mock_db
        
        mock_cache = Mock()
        mock_cache_class.return_value = mock_cache
        
        result = runner.invoke(app, ["requests==2.31.0"])
        
        # Should complete without error
        assert result.exit_code == 0
        # Verify that cached report was used (line 59) - engine should not be called
        mock_engine.analyze_package.assert_not_called()
        # Verify format_report was called with cached report
        mock_format.assert_called()

