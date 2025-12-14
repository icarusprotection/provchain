"""Tests for config command"""

import pytest
from pathlib import Path
from typer.testing import CliRunner
from unittest.mock import patch

from provchain.cli.commands.config import app
from provchain.config import Config


@pytest.fixture
def runner():
    """CLI test runner"""
    return CliRunner()


def test_config_init(runner, tmp_path):
    """Test config init command"""
    with patch('provchain.cli.commands.config.Path.home', return_value=tmp_path):
        result = runner.invoke(app, ["init"])
        
        assert result.exit_code == 0
        config_path = tmp_path / ".provchain" / "config.toml"
        assert config_path.exists()


def test_config_init_already_exists(runner, tmp_path):
    """Test config init when file already exists"""
    config_path = tmp_path / ".provchain" / "config.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("existing config")
    
    with patch('provchain.cli.commands.config.Path.home', return_value=tmp_path):
        result = runner.invoke(app, ["init"])
        
        assert result.exit_code == 0
        # Should not overwrite
        assert config_path.read_text() == "existing config"


def test_config_show_exists(runner, tmp_path):
    """Test config show when file exists"""
    config_path = tmp_path / ".provchain" / "config.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("test config content")
    
    with patch('provchain.cli.commands.config.Path.home', return_value=tmp_path):
        result = runner.invoke(app, ["show"])
        
        assert result.exit_code == 0
        assert "test config content" in result.stdout


def test_config_show_not_exists(runner, tmp_path):
    """Test config show when file doesn't exist"""
    with patch('provchain.cli.commands.config.Path.home', return_value=tmp_path):
        result = runner.invoke(app, ["show"])
        
        assert result.exit_code == 0
        assert "No configuration file found" in result.stdout or "not found" in result.stdout.lower()


def test_config_set_string_value(runner, tmp_path):
    """Test setting a string configuration value"""
    config_path = tmp_path / ".provchain" / "config.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Initialize config first
    with patch('pathlib.Path.home', return_value=tmp_path):
        runner.invoke(app, ["init"])
        
        # Set a string value
        result = runner.invoke(app, ["set", "general.threshold", "high"])
        
        assert result.exit_code == 0
        assert "Configuration updated" in result.stdout
        assert "general.threshold = high" in result.stdout or "high" in result.stdout
        
        # Verify it was saved
        config = Config(config_path=config_path)
        assert config.get("general", "threshold") == "high"


def test_config_set_integer_value(runner, tmp_path):
    """Test setting an integer configuration value"""
    config_path = tmp_path / ".provchain" / "config.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    with patch('pathlib.Path.home', return_value=tmp_path):
        runner.invoke(app, ["init"])
        
        result = runner.invoke(app, ["set", "behavior.timeout", "120"])
        
        assert result.exit_code == 0
        assert "Configuration updated" in result.stdout
        
        config = Config(config_path=config_path)
        assert config.get("behavior", "timeout") == 120


def test_config_set_boolean_value(runner, tmp_path):
    """Test setting a boolean configuration value"""
    config_path = tmp_path / ".provchain" / "config.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    with patch('pathlib.Path.home', return_value=tmp_path):
        runner.invoke(app, ["init"])
        
        result = runner.invoke(app, ["set", "behavior.enabled", "false"])
        
        assert result.exit_code == 0
        assert "Configuration updated" in result.stdout
        
        config = Config(config_path=config_path)
        assert config.get("behavior", "enabled") is False


def test_config_set_list_value(runner, tmp_path):
    """Test setting a list configuration value"""
    config_path = tmp_path / ".provchain" / "config.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    with patch('pathlib.Path.home', return_value=tmp_path):
        runner.invoke(app, ["init"])
        
        # Test JSON list format
        result = runner.invoke(app, ["set", "general.analyzers", '["typosquat", "maintainer"]'])
        
        assert result.exit_code == 0
        assert "Configuration updated" in result.stdout
        
        config = Config(config_path=config_path)
        analyzers = config.get("general", "analyzers")
        assert isinstance(analyzers, list)
        assert "typosquat" in analyzers


def test_config_set_invalid_section(runner, tmp_path):
    """Test setting value with invalid section"""
    with patch('pathlib.Path.home', return_value=tmp_path):
        result = runner.invoke(app, ["set", "invalid_section.key", "value"])
        
        assert result.exit_code == 1
        assert "Invalid section" in result.stdout or "invalid_section" in result.stdout


def test_config_set_invalid_key(runner, tmp_path):
    """Test setting value with invalid key"""
    config_path = tmp_path / ".provchain" / "config.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    with patch('pathlib.Path.home', return_value=tmp_path):
        runner.invoke(app, ["init"])
        
        result = runner.invoke(app, ["set", "general.invalid_key", "value"])
        
        assert result.exit_code == 1
        assert "Invalid key" in result.stdout or "invalid_key" in result.stdout


def test_config_set_invalid_format(runner, tmp_path):
    """Test setting value with invalid key format"""
    with patch('pathlib.Path.home', return_value=tmp_path):
        result = runner.invoke(app, ["set", "nokey", "value"])
        
        assert result.exit_code == 1
        assert "format" in result.stdout.lower() or "section.key" in result.stdout


def test_config_set_invalid_boolean(runner, tmp_path):
    """Test setting invalid boolean value"""
    config_path = tmp_path / ".provchain" / "config.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    with patch('pathlib.Path.home', return_value=tmp_path):
        runner.invoke(app, ["init"])
        
        result = runner.invoke(app, ["set", "behavior.enabled", "maybe"])
        
        assert result.exit_code == 1
        assert "Invalid boolean" in result.stdout or "boolean" in result.stdout.lower()


def test_config_set_invalid_integer(runner, tmp_path):
    """Test setting invalid integer value"""
    config_path = tmp_path / ".provchain" / "config.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    with patch('pathlib.Path.home', return_value=tmp_path):
        runner.invoke(app, ["init"])
        
        result = runner.invoke(app, ["set", "behavior.timeout", "not_a_number"])
        
        assert result.exit_code == 1
        assert "Invalid value" in result.stdout or "integer" in result.stdout.lower()
