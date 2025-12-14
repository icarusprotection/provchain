"""Tests for provenance verifiers"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from provchain.verifier.provenance.hash import HashVerifier
from provchain.verifier.provenance.sigstore import SigstoreVerifier


def test_hash_verifier_init():
    """Test hash verifier initialization"""
    verifier = HashVerifier()
    assert verifier is not None


def test_hash_verifier_verify_success(tmp_path):
    """Test successful hash verification"""
    artifact_file = tmp_path / "requests-2.31.0.whl"
    artifact_file.write_text("fake wheel content")
    
    verifier = HashVerifier()
    
    with patch('provchain.verifier.provenance.hash.calculate_hash') as mock_calc, \
         patch('provchain.verifier.provenance.hash.PyPIClient') as mock_pypi_class:
        
        mock_calc.return_value = "abc123hash"
        
        mock_pypi = Mock()
        mock_pypi.get_package_metadata.return_value = {
            "releases": {
                "2.31.0": [{
                    "filename": "requests-2.31.0.whl",
                    "digests": {"sha256": "abc123hash"}
                }]
            }
        }
        mock_pypi_class.return_value.__enter__.return_value = mock_pypi
        mock_pypi_class.return_value.__exit__.return_value = None
        
        result = verifier.verify(artifact_file)
        
        assert result["status"] == "verified"
        assert result["matches"] is True
        assert result["algorithm"] == "sha256"


def test_hash_verifier_verify_mismatch(tmp_path):
    """Test hash verification with mismatch"""
    artifact_file = tmp_path / "requests-2.31.0.whl"
    artifact_file.write_text("fake wheel content")
    
    verifier = HashVerifier()
    
    with patch('provchain.verifier.provenance.hash.calculate_hash') as mock_calc, \
         patch('provchain.verifier.provenance.hash.PyPIClient') as mock_pypi_class:
        
        mock_calc.return_value = "abc123hash"
        
        mock_pypi = Mock()
        mock_pypi.get_package_metadata.return_value = {
            "releases": {
                "2.31.0": [{
                    "filename": "requests-2.31.0.whl",
                    "digests": {"sha256": "differenthash"}
                }]
            }
        }
        mock_pypi_class.return_value.__enter__.return_value = mock_pypi
        mock_pypi_class.return_value.__exit__.return_value = None
        
        result = verifier.verify(artifact_file)
        
        assert result["status"] == "mismatch"
        assert result["matches"] is False


def test_hash_verifier_parse_filename_error(tmp_path):
    """Test hash verifier with unparseable filename"""
    artifact_file = tmp_path / "invalid.whl"
    artifact_file.write_text("content")
    
    verifier = HashVerifier()
    
    result = verifier.verify(artifact_file)
    
    assert "error" in result
    assert "Could not parse" in result["error"]


def test_hash_verifier_calculate_hash_error(tmp_path):
    """Test hash verifier when hash calculation fails"""
    artifact_file = tmp_path / "requests-2.31.0.whl"
    artifact_file.write_text("fake wheel content")
    
    verifier = HashVerifier()
    
    with patch('provchain.verifier.provenance.hash.calculate_hash') as mock_calc:
        mock_calc.side_effect = Exception("Hash calculation failed")
        
        result = verifier.verify(artifact_file)
        
        assert "error" in result
        assert "Failed to calculate hash" in result["error"]


def test_hash_verifier_pypi_error(tmp_path):
    """Test hash verifier when PyPI fetch fails"""
    artifact_file = tmp_path / "requests-2.31.0.whl"
    artifact_file.write_text("fake wheel content")
    
    verifier = HashVerifier()
    
    with patch('provchain.verifier.provenance.hash.calculate_hash') as mock_calc, \
         patch('provchain.verifier.provenance.hash.PyPIClient') as mock_pypi_class:
        
        mock_calc.return_value = "abc123hash"
        mock_pypi_class.side_effect = Exception("PyPI error")
        
        result = verifier.verify(artifact_file)
        
        assert "error" in result
        assert "Failed to fetch" in result["error"]


def test_hash_verifier_hash_not_found_on_pypi(tmp_path):
    """Test hash verifier when hash information is not found on PyPI - covers line 55"""
    artifact_file = tmp_path / "requests-2.31.0.whl"
    artifact_file.write_text("fake wheel content")
    
    verifier = HashVerifier()
    
    with patch('provchain.verifier.provenance.hash.calculate_hash') as mock_calc, \
         patch('provchain.verifier.provenance.hash.PyPIClient') as mock_pypi_class:
        
        mock_calc.return_value = "abc123hash"
        
        mock_pypi = Mock()
        # Return metadata with releases but no matching filename
        mock_pypi.get_package_metadata.return_value = {
            "releases": {
                "2.31.0": [{
                    "filename": "requests-2.31.0.tar.gz",  # Different filename
                    "digests": {"sha256": "abc123hash"}
                }]
            }
        }
        mock_pypi_class.return_value.__enter__.return_value = mock_pypi
        mock_pypi_class.return_value.__exit__.return_value = None
        
        result = verifier.verify(artifact_file)
        
        assert "error" in result
        assert "Hash information not found on PyPI" in result["error"]


# Sigstore Verifier Tests
def test_sigstore_verifier_init():
    """Test sigstore verifier initialization"""
    verifier = SigstoreVerifier()
    assert verifier is not None


def test_sigstore_verifier_no_signature_file(tmp_path):
    """Test sigstore verifier when no signature file exists"""
    artifact = tmp_path / "package.whl"
    artifact.write_text("fake package")
    
    verifier = SigstoreVerifier()
    result = verifier.verify(artifact)
    
    assert result["available"] is False
    assert result["status"] == "no_signature"
    assert "No Sigstore signature file found" in result["note"]


def test_sigstore_verifier_library_missing(tmp_path):
    """Test sigstore verifier when sigstore-python is not available"""
    artifact = tmp_path / "package.whl"
    artifact.write_text("fake package")
    signature = tmp_path / "package.whl.sig"
    signature.write_text("fake signature")
    
    verifier = SigstoreVerifier()
    
    # Patch the import inside the function
    with patch('builtins.__import__', side_effect=ImportError("No module named 'sigstore'")):
        result = verifier.verify(artifact)
        
        assert result["available"] is False
        assert result["status"] == "library_missing"
        assert "sigstore-python library required" in result["note"]


def test_sigstore_verifier_signature_found(tmp_path):
    """Test sigstore verifier when signature file is found"""
    artifact = tmp_path / "package.whl"
    artifact.write_text("fake package")
    signature = tmp_path / "package.whl.sig"
    signature.write_text("fake signature")
    cert = tmp_path / "package.whl.crt"
    cert.write_text("fake certificate")
    
    verifier = SigstoreVerifier()
    
    # Create mock module structure
    import sys
    mock_sigstore_verify = MagicMock()
    mock_verifier_class = MagicMock()
    mock_verifier_instance = MagicMock()
    mock_verifier_class.production.return_value = mock_verifier_instance
    mock_sigstore_verify.Verifier = mock_verifier_class
    
    mock_materials_class = MagicMock()
    mock_materials_class.from_dsse = MagicMock(return_value=MagicMock())
    mock_sigstore_verify.VerificationMaterials = mock_materials_class
    
    # Inject mock into sys.modules
    with patch.dict('sys.modules', {'sigstore.verify': mock_sigstore_verify, 'sigstore.verify.policy': MagicMock()}):
        result = verifier.verify(artifact)
        
        assert result["available"] is True
        assert result["status"] == "signature_found"
        assert "signature file found" in result["note"]


def test_sigstore_verifier_with_certificate(tmp_path):
    """Test sigstore verifier with certificate file"""
    artifact = tmp_path / "package.whl"
    artifact.write_text("fake package")
    signature = tmp_path / "package.whl.sig"
    signature.write_text("fake signature")
    cert = tmp_path / "package.whl.crt"
    cert.write_text("fake certificate")
    
    verifier = SigstoreVerifier()
    
    # Create mock module structure
    import sys
    mock_sigstore_verify = MagicMock()
    mock_verifier_class = MagicMock()
    mock_verifier_instance = MagicMock()
    mock_verifier_class.production.return_value = mock_verifier_instance
    mock_sigstore_verify.Verifier = mock_verifier_class
    
    mock_materials_class = MagicMock()
    mock_materials_class.from_dsse = MagicMock(return_value=MagicMock())
    mock_sigstore_verify.VerificationMaterials = mock_materials_class
    
    # Inject mock into sys.modules
    with patch.dict('sys.modules', {'sigstore.verify': mock_sigstore_verify, 'sigstore.verify.policy': MagicMock()}):
        result = verifier.verify(artifact)
        
        assert result["available"] is True
        assert "signature_file" in result


def test_sigstore_verifier_error_handling(tmp_path):
    """Test sigstore verifier error handling"""
    artifact = tmp_path / "package.whl"
    artifact.write_text("fake package")
    signature = tmp_path / "package.whl.sig"
    signature.write_text("fake signature")
    
    verifier = SigstoreVerifier()
    
    # Create mock module structure that raises exception
    import sys
    mock_sigstore_verify = MagicMock()
    mock_verifier_class = MagicMock()
    mock_verifier_class.production.side_effect = Exception("Test error")
    mock_sigstore_verify.Verifier = mock_verifier_class
    
    # Inject mock into sys.modules
    with patch.dict('sys.modules', {'sigstore.verify': mock_sigstore_verify, 'sigstore.verify.policy': MagicMock()}):
        result = verifier.verify(artifact)
        
        assert result["available"] is False
        assert result["status"] == "error"
        assert "error" in result


def test_sigstore_verifier_with_string_path(tmp_path):
    """Test sigstore verifier with string path"""
    artifact = tmp_path / "package.whl"
    artifact.write_text("fake package")
    signature = tmp_path / "package.whl.sig"
    signature.write_text("fake signature")
    
    verifier = SigstoreVerifier()
    
    # Patch the import to raise ImportError
    with patch('builtins.__import__', side_effect=ImportError("No module named 'sigstore'")):
        result = verifier.verify(str(artifact))
        
        assert result["available"] is False
        assert result["status"] == "library_missing"

