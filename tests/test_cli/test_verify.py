"""Tests for verify CLI command"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch
from typer.testing import CliRunner

from provchain.cli.commands.verify import app


@pytest.fixture
def runner():
    """CLI test runner"""
    return CliRunner()


def test_verify_help(runner):
    """Test verify command help"""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Verify" in result.stdout or "provenance" in result.stdout.lower()


def test_verify_local_artifact(runner, tmp_path):
    """Test verifying a local artifact file"""
    artifact_file = tmp_path / "test-package-1.0.0.whl"
    artifact_file.write_text("fake wheel content")
    
    with patch('provchain.cli.commands.verify.VerifierEngine') as mock_engine_class:
        mock_engine = Mock()
        mock_engine.verify_artifact.return_value = {
            "artifact": str(artifact_file),
            "verifications": {
                "hash": {"status": "verified"}
            }
        }
        mock_engine_class.return_value = mock_engine
        
        # Invoke the command directly (the app has a single "verify" command)
        # File exists, so it should call verify_artifact
        result = runner.invoke(app, [str(artifact_file)], catch_exceptions=True)
        
        # Should succeed (typer may exit with 0 even if there are issues)
        # The key is that verify_artifact was called
        mock_engine.verify_artifact.assert_called_once()
        # Exit code should be 0 for success
        assert result.exit_code == 0 or "Verification result" in result.stdout


def test_verify_package_spec(runner):
    """Test verifying a package specifier"""
    with patch('provchain.cli.commands.verify.VerifierEngine') as mock_engine_class, \
         patch('provchain.cli.commands.verify.Path') as mock_path_class:
        mock_engine = Mock()
        mock_engine.verify_package.return_value = {
            "package": "requests==2.31.0",
            "verifications": {
                "metadata": {"status": "found"}
            }
        }
        mock_engine_class.return_value = mock_engine
        
        # Mock Path to return a non-existent path
        mock_path = Mock()
        mock_path.exists.return_value = False
        mock_path_class.return_value = mock_path
        
        # Invoke the command directly
        result = runner.invoke(app, ["requests==2.31.0"], catch_exceptions=True)
        
        # Verify the method was called
        mock_engine.verify_package.assert_called_once()
        # Exit code should be 0
        assert result.exit_code == 0 or "Verification result" in result.stdout


def test_verify_invalid_path(runner):
    """Test verifying invalid artifact path"""
    with patch('provchain.cli.commands.verify.VerifierEngine') as mock_engine_class, \
         patch('provchain.cli.commands.verify.Path') as mock_path_class, \
         patch('provchain.cli.commands.verify.parse_package_spec') as mock_parse:
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine
        
        # Mock Path to return a non-existent path
        mock_path = Mock()
        mock_path.exists.return_value = False
        mock_path_class.return_value = mock_path
        
        # Mock parse_package_spec to raise ValueError (invalid package spec)
        mock_parse.side_effect = ValueError("Invalid package specifier")
        
        # Invoke the command directly
        result = runner.invoke(app, ["invalid-path"], catch_exceptions=True)
        
        # Should handle error gracefully (exit code 0, but prints error)
        # The command catches ValueError and prints error message
        assert result.exit_code == 0
        # Error should be in output
        assert "Error" in result.stdout or "Invalid" in result.stdout

