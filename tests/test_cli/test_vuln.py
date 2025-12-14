"""Tests for vuln CLI command"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from provchain.cli.commands.vuln import app


@pytest.fixture
def runner():
    """Create CLI runner"""
    return CliRunner()


def test_vuln_scan_missing_requirements(runner):
    """Test vuln scan with missing requirements file"""
    result = runner.invoke(app, ["scan"])
    assert result.exit_code != 0


def test_vuln_check_help(runner):
    """Test vuln check help"""
    result = runner.invoke(app, ["check", "--help"])
    assert result.exit_code == 0
    assert "Check specific package" in result.stdout


def test_vuln_prioritize_help(runner):
    """Test vuln prioritize help"""
    result = runner.invoke(app, ["prioritize", "--help"])
    assert result.exit_code == 0
    assert "Prioritize vulnerabilities" in result.stdout

