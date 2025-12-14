"""Tests for logging utilities"""

import logging
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from provchain.utils.logging import setup_logging, get_logger


class TestLogging:
    """Test cases for logging utilities"""

    def test_get_logger(self):
        """Test getting a logger instance"""
        logger = get_logger("test.module")
        
        assert isinstance(logger, logging.Logger)
        assert logger.name == "test.module"

    def test_setup_logging_default(self):
        """Test setting up logging with default parameters"""
        with patch('provchain.utils.logging.logging.basicConfig') as mock_config:
            setup_logging()
            
            mock_config.assert_called_once()
            call_args = mock_config.call_args
            assert call_args[1]['level'] == logging.INFO
            assert len(call_args[1]['handlers']) == 1
            assert isinstance(call_args[1]['handlers'][0], logging.StreamHandler)

    def test_setup_logging_with_level(self):
        """Test setting up logging with specific level"""
        with patch('provchain.utils.logging.logging.basicConfig') as mock_config:
            setup_logging(level="DEBUG")
            
            call_args = mock_config.call_args
            assert call_args[1]['level'] == logging.DEBUG

    def test_setup_logging_with_verbose(self):
        """Test setting up logging with verbose flag"""
        with patch('provchain.utils.logging.logging.basicConfig') as mock_config:
            setup_logging(verbose=True)
            
            call_args = mock_config.call_args
            assert call_args[1]['level'] == logging.DEBUG

    def test_setup_logging_with_log_file(self, tmp_path):
        """Test setting up logging with log file"""
        log_file = tmp_path / "test.log"
        
        with patch('provchain.utils.logging.logging.basicConfig') as mock_config, \
             patch('provchain.utils.logging.logging.FileHandler') as mock_file_handler:
            mock_handler_instance = MagicMock()
            mock_file_handler.return_value = mock_handler_instance
            
            setup_logging(log_file=log_file)
            
            call_args = mock_config.call_args
            assert len(call_args[1]['handlers']) == 2
            mock_file_handler.assert_called_once_with(log_file)

    def test_setup_logging_creates_log_directory(self, tmp_path):
        """Test that log file directory is created if it doesn't exist"""
        log_file = tmp_path / "subdir" / "test.log"
        
        with patch('provchain.utils.logging.logging.basicConfig') as mock_config, \
             patch('provchain.utils.logging.logging.FileHandler') as mock_file_handler:
            mock_handler_instance = MagicMock()
            mock_file_handler.return_value = mock_handler_instance
            
            setup_logging(log_file=log_file)
            
            # Verify directory was created
            assert log_file.parent.exists()
            mock_file_handler.assert_called_once_with(log_file)

    def test_setup_logging_with_warning_level(self):
        """Test setting up logging with WARNING level"""
        with patch('provchain.utils.logging.logging.basicConfig') as mock_config:
            setup_logging(level="WARNING")
            
            call_args = mock_config.call_args
            assert call_args[1]['level'] == logging.WARNING

    def test_setup_logging_with_error_level(self):
        """Test setting up logging with ERROR level"""
        with patch('provchain.utils.logging.logging.basicConfig') as mock_config:
            setup_logging(level="ERROR")
            
            call_args = mock_config.call_args
            assert call_args[1]['level'] == logging.ERROR

    def test_setup_logging_invalid_level_defaults_to_info(self):
        """Test that invalid level defaults to INFO"""
        with patch('provchain.utils.logging.logging.basicConfig') as mock_config:
            setup_logging(level="INVALID")
            
            call_args = mock_config.call_args
            assert call_args[1]['level'] == logging.INFO

    def test_setup_logging_format(self):
        """Test that logging format is set correctly"""
        with patch('provchain.utils.logging.logging.basicConfig') as mock_config:
            setup_logging()
            
            call_args = mock_config.call_args
            assert '%(asctime)s' in call_args[1]['format']
            assert '%(name)s' in call_args[1]['format']
            assert '%(levelname)s' in call_args[1]['format']
            assert '%(message)s' in call_args[1]['format']

    def test_get_logger_returns_same_instance(self):
        """Test that get_logger returns the same logger for same name"""
        logger1 = get_logger("test.module")
        logger2 = get_logger("test.module")
        
        assert logger1 is logger2

    def test_get_logger_different_names(self):
        """Test that get_logger returns different loggers for different names"""
        logger1 = get_logger("test.module1")
        logger2 = get_logger("test.module2")
        
        assert logger1 is not logger2
        assert logger1.name != logger2.name

