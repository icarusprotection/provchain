"""Tests for GPG verifier"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from provchain.verifier.provenance.gpg import GPGVerifier


class TestGPGVerifier:
    """Test cases for GPG verifier"""

    def test_gpg_verifier_init(self):
        """Test GPG verifier initialization"""
        verifier = GPGVerifier()
        assert verifier is not None

    def test_verify_no_signature_file(self, tmp_path):
        """Test verification when no signature file exists"""
        artifact = tmp_path / "package.whl"
        artifact.write_text("fake package")
        
        verifier = GPGVerifier()
        result = verifier.verify(artifact)
        
        assert result["available"] is False
        assert result["status"] == "no_signature"
        assert "No GPG signature file found" in result["note"]

    def test_verify_gpg_not_installed(self, tmp_path):
        """Test verification when GPG is not installed"""
        artifact = tmp_path / "package.whl"
        artifact.write_text("fake package")
        signature = tmp_path / "package.whl.asc"
        signature.write_text("fake signature")
        
        verifier = GPGVerifier()
        
        with patch('provchain.verifier.provenance.gpg.subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError()
            
            result = verifier.verify(artifact)
            
            assert result["available"] is False
            assert result["status"] == "gpg_not_installed"

    def test_verify_gpg_unavailable(self, tmp_path):
        """Test verification when GPG is unavailable"""
        artifact = tmp_path / "package.whl"
        artifact.write_text("fake package")
        signature = tmp_path / "package.whl.asc"
        signature.write_text("fake signature")
        
        verifier = GPGVerifier()
        
        with patch('provchain.verifier.provenance.gpg.subprocess.run') as mock_run:
            # First call (--version) returns non-zero
            mock_version_result = MagicMock()
            mock_version_result.returncode = 1
            mock_run.return_value = mock_version_result
            
            result = verifier.verify(artifact)
            
            assert result["available"] is False
            assert result["status"] == "gpg_unavailable"

    def test_verify_signature_success(self, tmp_path):
        """Test successful signature verification"""
        artifact = tmp_path / "package.whl"
        artifact.write_text("fake package")
        signature = tmp_path / "package.whl.asc"
        signature.write_text("fake signature")
        
        verifier = GPGVerifier()
        
        with patch('provchain.verifier.provenance.gpg.subprocess.run') as mock_run:
            # First call (--version) succeeds
            mock_version_result = MagicMock()
            mock_version_result.returncode = 0
            # Second call (--verify) succeeds
            mock_verify_result = MagicMock()
            mock_verify_result.returncode = 0
            mock_verify_result.stderr = b"Good signature"
            
            def run_side_effect(*args, **kwargs):
                if "--version" in args[0]:
                    return mock_version_result
                return mock_verify_result
            
            mock_run.side_effect = run_side_effect
            
            result = verifier.verify(artifact)
            
            assert result["available"] is True
            assert result["status"] == "verified"
            assert "verified successfully" in result["note"]

    def test_verify_signature_failure(self, tmp_path):
        """Test failed signature verification"""
        artifact = tmp_path / "package.whl"
        artifact.write_text("fake package")
        signature = tmp_path / "package.whl.asc"
        signature.write_text("fake signature")
        
        verifier = GPGVerifier()
        
        with patch('provchain.verifier.provenance.gpg.subprocess.run') as mock_run:
            # First call (--version) succeeds
            mock_version_result = MagicMock()
            mock_version_result.returncode = 0
            # Second call (--verify) fails
            mock_verify_result = MagicMock()
            mock_verify_result.returncode = 1
            mock_verify_result.stderr = b"Bad signature"
            
            def run_side_effect(*args, **kwargs):
                if "--version" in args[0]:
                    return mock_version_result
                return mock_verify_result
            
            mock_run.side_effect = run_side_effect
            
            result = verifier.verify(artifact)
            
            assert result["available"] is True
            assert result["status"] == "verification_failed"
            assert "verification failed" in result["note"]

    def test_verify_with_explicit_signature_path(self, tmp_path):
        """Test verification with explicit signature path"""
        artifact = tmp_path / "package.whl"
        artifact.write_text("fake package")
        signature = tmp_path / "custom.sig"
        signature.write_text("fake signature")
        
        verifier = GPGVerifier()
        
        with patch('provchain.verifier.provenance.gpg.subprocess.run') as mock_run:
            mock_version_result = MagicMock()
            mock_version_result.returncode = 0
            mock_verify_result = MagicMock()
            mock_verify_result.returncode = 0
            mock_verify_result.stderr = b"Good signature"
            
            def run_side_effect(*args, **kwargs):
                if "--version" in args[0]:
                    return mock_version_result
                return mock_verify_result
            
            mock_run.side_effect = run_side_effect
            
            result = verifier.verify(artifact, signature)
            
            assert result["available"] is True
            assert result["status"] == "verified"

    def test_verify_finds_asc_signature(self, tmp_path):
        """Test that verifier finds .asc signature file"""
        artifact = tmp_path / "package.whl"
        artifact.write_text("fake package")
        signature = tmp_path / "package.asc"
        signature.write_text("fake signature")
        
        verifier = GPGVerifier()
        
        with patch('provchain.verifier.provenance.gpg.subprocess.run') as mock_run:
            mock_version_result = MagicMock()
            mock_version_result.returncode = 0
            mock_verify_result = MagicMock()
            mock_verify_result.returncode = 0
            mock_verify_result.stderr = b"Good signature"
            
            def run_side_effect(*args, **kwargs):
                if "--version" in args[0]:
                    return mock_version_result
                return mock_verify_result
            
            mock_run.side_effect = run_side_effect
            
            result = verifier.verify(artifact)
            
            assert result["available"] is True
            assert result["status"] == "verified"

    def test_verify_timeout(self, tmp_path):
        """Test verification timeout"""
        artifact = tmp_path / "package.whl"
        artifact.write_text("fake package")
        signature = tmp_path / "package.whl.asc"
        signature.write_text("fake signature")
        
        verifier = GPGVerifier()
        
        with patch('provchain.verifier.provenance.gpg.subprocess.run') as mock_run:
            import subprocess
            mock_version_result = MagicMock()
            mock_version_result.returncode = 0
            
            def run_side_effect(*args, **kwargs):
                if "--version" in args[0]:
                    return mock_version_result
                raise subprocess.TimeoutExpired("gpg", 30)
            
            mock_run.side_effect = run_side_effect
            
            result = verifier.verify(artifact)
            
            assert result["available"] is True
            assert result["status"] == "timeout"

    def test_verify_with_string_paths(self, tmp_path):
        """Test verification with string paths"""
        artifact = tmp_path / "package.whl"
        artifact.write_text("fake package")
        signature = tmp_path / "package.whl.asc"
        signature.write_text("fake signature")
        
        verifier = GPGVerifier()
        
        with patch('provchain.verifier.provenance.gpg.subprocess.run') as mock_run:
            mock_version_result = MagicMock()
            mock_version_result.returncode = 0
            mock_verify_result = MagicMock()
            mock_verify_result.returncode = 0
            mock_verify_result.stderr = b"Good signature"
            
            def run_side_effect(*args, **kwargs):
                if "--version" in args[0]:
                    return mock_version_result
                return mock_verify_result
            
            mock_run.side_effect = run_side_effect
            
            result = verifier.verify(str(artifact), str(signature))
            
            assert result["available"] is True
            assert result["status"] == "verified"

    def test_verify_unexpected_exception(self, tmp_path):
        """Test verification when an unexpected exception occurs - covers lines 88-89"""
        artifact = tmp_path / "package.whl"
        artifact.write_text("fake package")
        signature = tmp_path / "package.whl.asc"
        signature.write_text("fake signature")
        
        verifier = GPGVerifier()
        
        with patch('provchain.verifier.provenance.gpg.subprocess.run') as mock_run:
            mock_version_result = MagicMock()
            mock_version_result.returncode = 0
            
            def run_side_effect(*args, **kwargs):
                if "--version" in args[0]:
                    return mock_version_result
                # Raise an unexpected exception (not TimeoutExpired)
                raise ValueError("Unexpected error")
            
            mock_run.side_effect = run_side_effect
            
            result = verifier.verify(artifact)
            
            assert result["available"] is True
            assert result["status"] == "error"
            assert "error" in result

