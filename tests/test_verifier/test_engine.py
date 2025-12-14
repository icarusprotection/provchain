"""Tests for verifier engine"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch

from provchain.data.models import PackageIdentifier
from provchain.verifier.engine import VerifierEngine


def test_verifier_engine_init():
    """Test verifier engine initialization"""
    engine = VerifierEngine()
    
    assert engine.hash_verifier is not None
    assert engine.sigstore_verifier is not None


def test_verifier_engine_verify_artifact(tmp_path):
    """Test verifying a local artifact"""
    artifact_file = tmp_path / "test-package-1.0.0.whl"
    artifact_file.write_text("fake wheel content")
    
    engine = VerifierEngine()
    
    with patch.object(engine.hash_verifier, 'verify') as mock_hash, \
         patch.object(engine.sigstore_verifier, 'verify') as mock_sigstore:
        
        mock_hash.return_value = {"status": "verified", "matches": True}
        mock_sigstore.return_value = {"status": "verified", "available": True}
        
        result = engine.verify_artifact(artifact_file)
        
        assert result["artifact"] == str(artifact_file)
        assert "verifications" in result
        assert "hash" in result["verifications"]
        mock_hash.assert_called_once()


def test_verifier_engine_verify_artifact_hash_error(tmp_path):
    """Test verifying artifact when hash verification fails"""
    artifact_file = tmp_path / "test-package-1.0.0.whl"
    artifact_file.write_text("fake wheel content")
    
    engine = VerifierEngine()
    
    with patch.object(engine.hash_verifier, 'verify') as mock_hash, \
         patch.object(engine.sigstore_verifier, 'verify') as mock_sigstore:
        
        mock_hash.side_effect = Exception("Hash error")
        mock_sigstore.return_value = {"status": "verified"}
        
        result = engine.verify_artifact(artifact_file)
        
        assert "verifications" in result
        assert "hash" in result["verifications"]
        assert "error" in result["verifications"]["hash"]

def test_verifier_engine_verify_artifact_sigstore_error(tmp_path):
    """Test verifying artifact when sigstore verification fails"""
    artifact_file = tmp_path / "test-package-1.0.0.whl"
    artifact_file.write_text("fake wheel content")
    
    engine = VerifierEngine()
    
    with patch.object(engine.hash_verifier, 'verify') as mock_hash, \
         patch.object(engine.sigstore_verifier, 'verify') as mock_sigstore:
        
        mock_hash.return_value = {"status": "verified", "matches": True}
        mock_sigstore.side_effect = Exception("Sigstore error")
        
        result = engine.verify_artifact(artifact_file)
        
        assert "verifications" in result
        assert "sigstore" in result["verifications"]
        assert "error" in result["verifications"]["sigstore"]
        assert result["verifications"]["sigstore"]["available"] is False


def test_verifier_engine_verify_package():
    """Test verifying an installed package"""
    engine = VerifierEngine()
    
    pkg_id = PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0")
    
    with patch('importlib.util.find_spec') as mock_find_spec:
        # Mock package not found
        mock_find_spec.return_value = None
        
        result = engine.verify_package(pkg_id)
        
        assert result["package"] == str(pkg_id)
        assert "verifications" in result
        assert "location" in result["verifications"]
        assert result["verifications"]["location"]["status"] == "not_found"


def test_verifier_engine_verify_package_found():
    """Test verifying a found package"""
    engine = VerifierEngine()
    
    pkg_id = PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0")
    
    with patch('importlib.util.find_spec') as mock_find_spec, \
         patch('site.getsitepackages') as mock_site:
        
        mock_spec = Mock()
        mock_spec.origin = "/path/to/requests/__init__.py"
        mock_find_spec.return_value = mock_spec
        mock_site.return_value = ["/path/to/site-packages"]
        
        with patch('pathlib.Path.glob') as mock_glob:
            # Mock no dist-info found
            mock_glob.return_value = []
            
            result = engine.verify_package(pkg_id)
            
            assert result["package"] == str(pkg_id)
            assert "verifications" in result

def test_verifier_engine_verify_package_with_dist_info(tmp_path):
    """Test verifying a package with dist-info directory"""
    engine = VerifierEngine()
    
    pkg_id = PackageIdentifier(ecosystem="pypi", name="test-package", version="1.0.0")
    
    with patch('importlib.util.find_spec') as mock_find_spec, \
         patch('site.getsitepackages') as mock_site:
        
        mock_spec = Mock()
        mock_spec.origin = str(tmp_path / "test_package" / "__init__.py")
        mock_find_spec.return_value = mock_spec
        mock_site.return_value = [str(tmp_path / "site-packages")]
        
        # Create dist-info directory
        dist_info = tmp_path / "site-packages" / "test_package-1.0.0.dist-info"
        dist_info.mkdir(parents=True)
        metadata_file = dist_info / "METADATA"
        metadata_file.write_text("Name: test-package\nVersion: 1.0.0\n")
        
        result = engine.verify_package(pkg_id)
        
        assert result["package"] == str(pkg_id)
        assert "verifications" in result
        assert "metadata" in result["verifications"]
        assert result["verifications"]["metadata"]["status"] == "found"
        assert "hash" in result["verifications"]
        assert result["verifications"]["hash"]["status"] == "limited"

def test_verifier_engine_verify_package_with_egg_info(tmp_path):
    """Test verifying a package with egg-info directory"""
    engine = VerifierEngine()
    
    pkg_id = PackageIdentifier(ecosystem="pypi", name="test-package", version="1.0.0")
    
    with patch('importlib.util.find_spec') as mock_find_spec, \
         patch('site.getsitepackages') as mock_site:
        
        mock_spec = Mock()
        mock_spec.origin = str(tmp_path / "test_package" / "__init__.py")
        mock_find_spec.return_value = mock_spec
        mock_site.return_value = [str(tmp_path / "site-packages")]
        
        # Create egg-info directory (no dist-info)
        egg_info = tmp_path / "site-packages" / "test_package-1.0.0.egg-info"
        egg_info.mkdir(parents=True)
        metadata_file = egg_info / "METADATA"
        metadata_file.write_text("Name: test-package\nVersion: 1.0.0\n")
        
        result = engine.verify_package(pkg_id)
        
        assert result["package"] == str(pkg_id)
        assert "verifications" in result
        assert "metadata" in result["verifications"]
        assert result["verifications"]["metadata"]["status"] == "found"

def test_verifier_engine_verify_package_metadata_not_found(tmp_path):
    """Test verifying a package with dist-info but no METADATA file"""
    engine = VerifierEngine()
    
    pkg_id = PackageIdentifier(ecosystem="pypi", name="test-package", version="1.0.0")
    
    with patch('importlib.util.find_spec') as mock_find_spec, \
         patch('site.getsitepackages') as mock_site:
        
        mock_spec = Mock()
        mock_spec.origin = str(tmp_path / "test_package" / "__init__.py")
        mock_find_spec.return_value = mock_spec
        mock_site.return_value = [str(tmp_path / "site-packages")]
        
        # Create dist-info directory without METADATA
        dist_info = tmp_path / "site-packages" / "test_package-1.0.0.dist-info"
        dist_info.mkdir(parents=True)
        # Don't create METADATA file
        
        result = engine.verify_package(pkg_id)
        
        assert result["package"] == str(pkg_id)
        assert "verifications" in result
        assert "metadata" in result["verifications"]
        assert result["verifications"]["metadata"]["status"] == "not_found"

def test_verifier_engine_verify_package_spec_origin_none():
    """Test verifying a package when spec.origin is None"""
    engine = VerifierEngine()
    
    pkg_id = PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0")
    
    with patch('importlib.util.find_spec') as mock_find_spec:
        mock_spec = Mock()
        mock_spec.origin = None
        mock_find_spec.return_value = mock_spec
        
        result = engine.verify_package(pkg_id)
        
        assert result["package"] == str(pkg_id)
        assert "verifications" in result
        assert "location" in result["verifications"]
        assert result["verifications"]["location"]["status"] == "not_found"


def test_verifier_engine_verify_package_error():
    """Test verifying package with error"""
    engine = VerifierEngine()
    
    pkg_id = PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0")
    
    with patch('importlib.util.find_spec') as mock_find_spec:
        mock_find_spec.side_effect = Exception("Test error")
        
        result = engine.verify_package(pkg_id)
        
        assert "verifications" in result
        assert "error" in result["verifications"]

