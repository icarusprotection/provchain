"""Tests for configuration management"""

import os
import tempfile
import sys
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock

import pytest

from provchain.config import Config


class TestConfig:
    """Test cases for Config class"""

    def test_config_init_default_path(self, tmp_path):
        """Test Config initialization with default path"""
        with patch('pathlib.Path.home', return_value=tmp_path):
            with patch.object(Config, 'load') as mock_load:
                config = Config()
                assert config.config_path == tmp_path / ".provchain" / "config.toml"
                mock_load.assert_called_once()

    def test_config_init_custom_path(self, tmp_path):
        """Test Config initialization with custom path"""
        custom_path = tmp_path / "custom_config.toml"
        with patch.object(Config, 'load') as mock_load:
            config = Config(config_path=custom_path)
            assert config.config_path == custom_path
            mock_load.assert_called_once()

    def test_config_default_values(self, tmp_path):
        """Test that default configuration values are set"""
        with patch('pathlib.Path.home', return_value=tmp_path):
            with patch.object(Config, 'load'):
                config = Config()
                assert config.config["general"]["threshold"] == "medium"
                assert "typosquat" in config.config["general"]["analyzers"]
                assert config.config["behavior"]["enabled"] is True
                assert config.config["output"]["format"] == "table"

    def test_config_load_file_not_exists(self, tmp_path):
        """Test loading config when file doesn't exist"""
        config_path = tmp_path / "config.toml"
        with patch('pathlib.Path.exists', return_value=False):
            with patch.dict(os.environ, {}, clear=True):
                config = Config(config_path=config_path)
                # Should use defaults
                assert config.config["general"]["threshold"] == "medium"

    def test_config_load_file_exists_with_tomli(self, tmp_path):
        """Test loading config from existing file with tomli available"""
        config_file = tmp_path / "config.toml"
        config_file.write_text("""
[general]
threshold = "high"
cache_ttl = 48

[behavior]
enabled = false
""")
        
        # Create a mock module with a load function
        mock_tomli_module = MagicMock(spec=['load'])
        mock_tomli_module.load = MagicMock(return_value={
            "general": {"threshold": "high", "cache_ttl": 48},
            "behavior": {"enabled": False}
        })
        
        with patch('provchain.config.tomli', mock_tomli_module):
            with patch('pathlib.Path.exists', return_value=True):
                with patch('builtins.open', mock_open(read_data="config content")):
                    config = Config(config_path=config_file)
                    # Verify merge happened
                    assert config.config["general"]["threshold"] == "high"
                    assert config.config["general"]["cache_ttl"] == 48
                    assert config.config["behavior"]["enabled"] is False

    def test_config_load_file_exists_no_tomli(self, tmp_path, monkeypatch):
        """Test loading config when tomli is not available - tests lines 8-13"""
        config_file = tmp_path / "config.toml"
        # Don't write content - file exists but tomli is None
        config_file.touch()
        
        # Ensure clean environment
        monkeypatch.delenv('PROVCHAIN_GITHUB_TOKEN', raising=False)
        
        # Test the import fallback path (lines 8-13)
        # Mock tomli to be None to test the fallback
        with patch('provchain.config.tomli', None):
            with patch('pathlib.Path.exists', return_value=True):
                config = Config(config_path=config_file)
                # Should use defaults when tomli not available (lines 54-56)
                assert config.config["general"]["threshold"] == "medium"
    
    def test_config_tomli_import_fallback(self, tmp_path, monkeypatch):
        """Test tomli import fallback path - tests lines 8-13 behavior"""
        # Note: Lines 8-13 execute at module import time, so we test the behavior
        # when tomli is None (which is the result of the fallback)
        config_file = tmp_path / "config.toml"
        # Create empty file - exists but no content to load
        config_file.touch()
        
        # Ensure clean environment
        monkeypatch.delenv('PROVCHAIN_GITHUB_TOKEN', raising=False)
        
        # Test behavior when tomli is None (result of import fallback)
        with patch('provchain.config.tomli', None):
            with patch('pathlib.Path.exists', return_value=True):
                config = Config(config_path=config_file)
                # When tomli is None and file exists, should return early (line 56)
                # and use defaults
                assert config.config["general"]["threshold"] == "medium"

    def test_config_load_file_read_error(self, tmp_path, monkeypatch):
        """Test handling file read errors"""
        config_file = tmp_path / "config.toml"
        config_file.touch()  # Create file but don't write content
        
        # Ensure clean environment
        monkeypatch.delenv('PROVCHAIN_GITHUB_TOKEN', raising=False)
        
        # Mock tomli to be available but file read fails
        mock_tomli = MagicMock()
        with patch('provchain.config.tomli', mock_tomli):
            with patch('pathlib.Path.exists', return_value=True):
                with patch('builtins.open', side_effect=IOError("Read error")):
                    config = Config(config_path=config_file)
                    # Should use defaults on error (lines 63-65)
                    assert config.config["general"]["threshold"] == "medium"
                    # Verify tomli.load was not called due to exception
                    mock_tomli.load.assert_not_called()

    def test_config_load_environment_variables(self, tmp_path):
        """Test loading configuration from environment variables"""
        config_file = tmp_path / "config.toml"
        with patch('pathlib.Path.home', return_value=tmp_path):
            with patch.dict(os.environ, {'PROVCHAIN_GITHUB_TOKEN': 'test_token_123'}, clear=False):
                with patch('provchain.config.tomli', None):
                    with patch('pathlib.Path.exists', return_value=False):
                        config = Config(config_path=config_file)
                        # load() is called in __init__, so check the result (lines 70-71)
                        assert config.config["integrations"]["github_token"] == "test_token_123"

    def test_config_load_no_environment_variable(self, tmp_path, monkeypatch):
        """Test loading when environment variable is not set"""
        config_file = tmp_path / "config.toml"
        # Ensure environment variable is not set
        monkeypatch.delenv('PROVCHAIN_GITHUB_TOKEN', raising=False)
        
        with patch('pathlib.Path.home', return_value=tmp_path):
            with patch('provchain.config.tomli', None):
                with patch('pathlib.Path.exists', return_value=False):
                    config = Config(config_path=config_file)
                    assert config.config["integrations"]["github_token"] == ""

    def test_config_merge_config_simple(self, tmp_path):
        """Test merging simple configuration values"""
        with patch('pathlib.Path.home', return_value=tmp_path):
            with patch.object(Config, 'load'):
                config = Config()
                base = {"key1": "value1", "key2": "value2"}
                override = {"key1": "new_value1", "key3": "value3"}
                config._merge_config(base, override)
                assert base["key1"] == "new_value1"
                assert base["key2"] == "value2"
                assert base["key3"] == "value3"

    def test_config_merge_config_nested(self, tmp_path):
        """Test merging nested configuration dictionaries"""
        with patch('pathlib.Path.home', return_value=tmp_path):
            with patch.object(Config, 'load'):
                config = Config()
                base = {
                    "section1": {"key1": "value1", "key2": "value2"},
                    "section2": {"key3": "value3"}
                }
                override = {
                    "section1": {"key1": "new_value1", "key4": "value4"},
                    "section3": {"key5": "value5"}
                }
                config._merge_config(base, override)
                assert base["section1"]["key1"] == "new_value1"
                assert base["section1"]["key2"] == "value2"
                assert base["section1"]["key4"] == "value4"
                assert base["section2"]["key3"] == "value3"
                assert base["section3"]["key5"] == "value5"

    def test_config_get_existing_value(self, tmp_path, monkeypatch):
        """Test getting existing configuration value"""
        config_file = tmp_path / "config.toml"
        # Ensure clean environment
        monkeypatch.delenv('PROVCHAIN_GITHUB_TOKEN', raising=False)
        
        with patch('pathlib.Path.home', return_value=tmp_path):
            with patch('provchain.config.tomli', None):
                with patch('pathlib.Path.exists', return_value=False):
                    config = Config(config_path=config_file)
                    value = config.get("general", "threshold")
                    assert value == "medium"

    def test_config_get_nonexistent_section(self, tmp_path):
        """Test getting value from nonexistent section"""
        with patch('pathlib.Path.home', return_value=tmp_path):
            with patch.object(Config, 'load'):
                config = Config()
                value = config.get("nonexistent", "key", default="default_value")
                assert value == "default_value"

    def test_config_get_nonexistent_key(self, tmp_path):
        """Test getting nonexistent key from existing section"""
        with patch('pathlib.Path.home', return_value=tmp_path):
            with patch.object(Config, 'load'):
                config = Config()
                value = config.get("general", "nonexistent_key", default="default_value")
                assert value == "default_value"

    def test_config_set_existing_section(self, tmp_path):
        """Test setting value in existing section"""
        with patch('pathlib.Path.home', return_value=tmp_path):
            with patch.object(Config, 'load'):
                config = Config()
                config.set("general", "threshold", "high")
                assert config.config["general"]["threshold"] == "high"

    def test_config_set_new_section(self, tmp_path):
        """Test setting value in new section"""
        with patch('pathlib.Path.home', return_value=tmp_path):
            with patch.object(Config, 'load'):
                config = Config()
                config.set("new_section", "new_key", "new_value")
                assert config.config["new_section"]["new_key"] == "new_value"

    def test_config_set_overwrite_existing(self, tmp_path):
        """Test overwriting existing configuration value"""
        with patch('pathlib.Path.home', return_value=tmp_path):
            with patch.object(Config, 'load'):
                config = Config()
                original_value = config.config["general"]["threshold"]
                config.set("general", "threshold", "critical")
                assert config.config["general"]["threshold"] == "critical"
                assert config.config["general"]["threshold"] != original_value

    def test_config_save(self, tmp_path, monkeypatch):
        """Test saving configuration to file"""
        config_file = tmp_path / "config.toml"
        monkeypatch.delenv('PROVCHAIN_GITHUB_TOKEN', raising=False)
        
        config = Config(config_path=config_file)
        config.set("general", "threshold", "high")
        config.save()
        
        # Verify file was created and contains the value
        assert config_file.exists()
        # Reload and verify
        config2 = Config(config_path=config_file)
        assert config2.get("general", "threshold") == "high"

    def test_config_save_without_tomli_w(self, tmp_path, monkeypatch):
        """Test that save raises error when tomli-w is not available"""
        config_file = tmp_path / "config.toml"
        monkeypatch.delenv('PROVCHAIN_GITHUB_TOKEN', raising=False)
        
        config = Config(config_path=config_file)
        config.set("general", "threshold", "high")
        
        with patch('provchain.config.tomli_w', None):
            with pytest.raises(RuntimeError, match="tomli-w is required"):
                config.save()

    def test_config_validate_valid(self, tmp_path, monkeypatch):
        """Test validation with valid configuration"""
        config_file = tmp_path / "config.toml"
        monkeypatch.delenv('PROVCHAIN_GITHUB_TOKEN', raising=False)
        
        config = Config(config_path=config_file)
        # Should not raise
        config.validate()

    def test_config_validate_invalid_threshold(self, tmp_path, monkeypatch):
        """Test validation with invalid threshold"""
        config_file = tmp_path / "config.toml"
        monkeypatch.delenv('PROVCHAIN_GITHUB_TOKEN', raising=False)
        
        config = Config(config_path=config_file)
        config.set("general", "threshold", "invalid")
        
        with pytest.raises(ValueError, match="Invalid threshold"):
            config.validate()

    def test_config_validate_invalid_analyzers(self, tmp_path, monkeypatch):
        """Test validation with invalid analyzer"""
        config_file = tmp_path / "config.toml"
        monkeypatch.delenv('PROVCHAIN_GITHUB_TOKEN', raising=False)
        
        config = Config(config_path=config_file)
        config.set("general", "analyzers", ["invalid_analyzer"])
        
        with pytest.raises(ValueError, match="Invalid analyzer"):
            config.validate()

