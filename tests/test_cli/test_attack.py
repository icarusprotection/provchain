"""Tests for attack CLI command"""

from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from provchain.cli.commands.attack import app


@pytest.fixture
def runner():
    """Create CLI runner"""
    return CliRunner()


def test_attack_detect_help(runner):
    """Test attack detect help"""
    result = runner.invoke(app, ["detect", "--help"])
    assert result.exit_code == 0
    assert "Detect supply chain attacks" in result.stdout


def test_attack_history_help(runner):
    """Test attack history help"""
    result = runner.invoke(app, ["history", "--help"])
    assert result.exit_code == 0
    assert "Show attack history" in result.stdout

