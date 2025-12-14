"""Tests for hashing utilities"""

import hashlib
import pytest
from pathlib import Path
from unittest.mock import patch, mock_open

from provchain.utils.hashing import (
    calculate_sha256,
    calculate_md5,
    calculate_blake2b,
    calculate_hash,
)


class TestHashing:
    """Test cases for hashing utilities"""

    def test_calculate_sha256(self, tmp_path):
        """Test SHA256 hash calculation"""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        
        result = calculate_sha256(test_file)
        
        # Verify it's a valid hex string
        assert len(result) == 64
        assert all(c in '0123456789abcdef' for c in result)
        
        # Verify it matches expected hash
        expected = hashlib.sha256(b"test content").hexdigest()
        assert result == expected

    def test_calculate_sha256_with_string_path(self, tmp_path):
        """Test SHA256 with string path"""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        
        result = calculate_sha256(str(test_file))
        
        assert len(result) == 64
        expected = hashlib.sha256(b"test content").hexdigest()
        assert result == expected

    def test_calculate_md5(self, tmp_path):
        """Test MD5 hash calculation"""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        
        result = calculate_md5(test_file)
        
        # Verify it's a valid hex string
        assert len(result) == 32
        assert all(c in '0123456789abcdef' for c in result)
        
        # Verify it matches expected hash
        expected = hashlib.md5(b"test content").hexdigest()
        assert result == expected

    def test_calculate_blake2b(self, tmp_path):
        """Test BLAKE2b hash calculation"""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        
        result = calculate_blake2b(test_file)
        
        # Verify it's a valid hex string (BLAKE2b produces 128 hex chars by default)
        assert len(result) == 128
        assert all(c in '0123456789abcdef' for c in result)
        
        # Verify it matches expected hash
        expected = hashlib.blake2b(b"test content").hexdigest()
        assert result == expected

    def test_calculate_hash_sha256(self, tmp_path):
        """Test calculate_hash with SHA256 algorithm"""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        
        result = calculate_hash(test_file, "sha256")
        
        expected = hashlib.sha256(b"test content").hexdigest()
        assert result == expected

    def test_calculate_hash_md5(self, tmp_path):
        """Test calculate_hash with MD5 algorithm"""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        
        result = calculate_hash(test_file, "md5")
        
        expected = hashlib.md5(b"test content").hexdigest()
        assert result == expected

    def test_calculate_hash_blake2b(self, tmp_path):
        """Test calculate_hash with BLAKE2b algorithm"""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        
        result = calculate_hash(test_file, "blake2b")
        
        expected = hashlib.blake2b(b"test content").hexdigest()
        assert result == expected

    def test_calculate_hash_default(self, tmp_path):
        """Test calculate_hash with default algorithm (SHA256)"""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        
        result = calculate_hash(test_file)
        
        expected = hashlib.sha256(b"test content").hexdigest()
        assert result == expected

    def test_calculate_hash_case_insensitive(self, tmp_path):
        """Test calculate_hash with uppercase algorithm name"""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        
        result = calculate_hash(test_file, "SHA256")
        
        expected = hashlib.sha256(b"test content").hexdigest()
        assert result == expected

    def test_calculate_hash_unsupported_algorithm(self, tmp_path):
        """Test calculate_hash with unsupported algorithm"""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            calculate_hash(test_file, "sha1")

    def test_calculate_hash_large_file(self, tmp_path):
        """Test hash calculation with larger file"""
        test_file = tmp_path / "large.txt"
        # Create a file larger than 4KB to test chunking
        content = b"x" * 5000
        test_file.write_bytes(content)
        
        result = calculate_sha256(test_file)
        
        expected = hashlib.sha256(content).hexdigest()
        assert result == expected

    def test_calculate_hash_file_not_found(self):
        """Test hash calculation with non-existent file"""
        with pytest.raises(FileNotFoundError):
            calculate_sha256(Path("/nonexistent/file.txt"))

