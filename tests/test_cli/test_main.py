"""Tests for CLI main entry point"""

import pytest
from typer.testing import CliRunner
from unittest.mock import patch

from provchain.cli.main import app, main


@pytest.fixture
def runner():
    """CLI test runner"""
    return CliRunner()


def test_main_app_help(runner):
    """Test main app help"""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "ProvChain" in result.stdout or "provchain" in result.stdout.lower()


def test_main_app_vet_command(runner):
    """Test that vet command is available"""
    result = runner.invoke(app, ["vet", "--help"])
    assert result.exit_code == 0
    assert "vet" in result.stdout.lower() or "analyze" in result.stdout.lower()


def test_main_app_verify_command(runner):
    """Test that verify command is available"""
    result = runner.invoke(app, ["verify", "--help"])
    assert result.exit_code == 0
    assert "verify" in result.stdout.lower() or "provenance" in result.stdout.lower()


def test_main_app_watch_command(runner):
    """Test that watch command is available"""
    result = runner.invoke(app, ["watch", "--help"])
    assert result.exit_code == 0
    assert "watch" in result.stdout.lower() or "monitor" in result.stdout.lower()


def test_main_app_sbom_command(runner):
    """Test that sbom command is available"""
    result = runner.invoke(app, ["sbom", "--help"])
    assert result.exit_code == 0
    assert "sbom" in result.stdout.lower()


def test_main_app_config_command(runner):
    """Test that config command is available"""
    result = runner.invoke(app, ["config", "--help"])
    assert result.exit_code == 0
    assert "config" in result.stdout.lower()


def test_main_function():
    """Test main() function"""
    with patch('provchain.cli.main.app') as mock_app:
        main()
        mock_app.assert_called_once()


def test_main_app_no_command(runner):
    """Test main app with no command shows help"""
    result = runner.invoke(app, [])
    # Typer typically shows help or exits with code 0/2
    assert result.exit_code in [0, 2]

