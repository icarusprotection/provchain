"""Tests for reproducible build checker"""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from provchain.verifier.reproducible.builder import ReproducibleBuildChecker


class TestReproducibleBuildChecker:
    """Test cases for ReproducibleBuildChecker"""

    def test_reproducible_build_checker_init(self):
        """Test ReproducibleBuildChecker initialization"""
        checker = ReproducibleBuildChecker()
        assert checker is not None

    @patch('provchain.verifier.reproducible.builder.PyPIClient')
    def test_verify_no_source_distribution(self, mock_pypi_class):
        """Test verify when no source distribution is available"""
        mock_pypi = MagicMock()
        mock_pypi.__enter__.return_value = mock_pypi
        mock_pypi.__exit__.return_value = None
        mock_pypi.get_package_metadata.return_value = {
            "releases": {
                "1.0.0": [
                    {"filename": "package-1.0.0.whl", "url": "http://example.com/package.whl"}
                ]
            }
        }
        mock_pypi_class.return_value = mock_pypi
        
        checker = ReproducibleBuildChecker()
        result = checker.verify("test-package", "1.0.0")
        
        assert result["status"] == "no_source"
        assert "No source distribution available" in result["note"]

    @patch('provchain.verifier.reproducible.builder.PyPIClient')
    def test_verify_no_sdist_url(self, mock_pypi_class):
        """Test verify when source distribution has no URL"""
        mock_pypi = MagicMock()
        mock_pypi.__enter__.return_value = mock_pypi
        mock_pypi.__exit__.return_value = None
        mock_pypi.get_package_metadata.return_value = {
            "releases": {
                "1.0.0": [
                    {"filename": "package-1.0.0.tar.gz"}  # No URL
                ]
            }
        }
        mock_pypi_class.return_value = mock_pypi
        
        checker = ReproducibleBuildChecker()
        result = checker.verify("test-package", "1.0.0")
        
        assert result["status"] == "no_url"
        assert "Source distribution URL not available" in result["note"]

    @patch('provchain.verifier.reproducible.builder.calculate_hash')
    @patch('provchain.verifier.reproducible.builder.subprocess.run')
    @patch('provchain.verifier.reproducible.builder.zipfile.ZipFile')
    @patch('provchain.verifier.reproducible.builder.HTTPClient')
    @patch('provchain.verifier.reproducible.builder.PyPIClient')
    def test_verify_extract_zip(self, mock_pypi_class, mock_http_class,
                                 mock_zipfile_class, mock_subprocess, mock_calculate_hash):
        """Test verify with zip file extraction"""
        # Setup PyPI client
        mock_pypi = MagicMock()
        mock_pypi.__enter__.return_value = mock_pypi
        mock_pypi.__exit__.return_value = None
        mock_pypi.get_package_metadata.return_value = {
            "releases": {
                "1.0.0": [
                    {"filename": "package-1.0.0.zip", "url": "http://example.com/package.zip"},
                    {"filename": "package-1.0.0.whl", "digests": {"sha256": "abc123"}}
                ]
            }
        }
        mock_pypi_class.return_value = mock_pypi
        
        # Setup HTTP client
        mock_http = MagicMock()
        mock_http.__enter__.return_value = mock_http
        mock_http.__exit__.return_value = None
        mock_response = MagicMock()
        mock_response.content = b"zip content"
        mock_http.get.return_value = mock_response
        mock_http_class.return_value = mock_http
        
        # Setup zipfile - need to mock extractall to create a directory
        mock_zip = MagicMock()
        def mock_extractall(path):
            # Create a directory to simulate extraction
            extract_path = Path(path) if isinstance(path, str) else path
            (extract_path / "package-1.0.0").mkdir(parents=True, exist_ok=True)
        mock_zip.extractall = mock_extractall
        mock_zipfile_class.return_value.__enter__.return_value = mock_zip
        mock_zipfile_class.return_value.__exit__.return_value = None
        
        # Setup subprocess
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Setup hash calculation
        mock_calculate_hash.return_value = "abc123"
        
        # Mock Path.glob to return a wheel file
        with patch('pathlib.Path.glob') as mock_glob:
            mock_wheel = MagicMock(spec=Path)
            mock_wheel.__str__ = lambda x: "package-1.0.0-py3-none-any.whl"
            mock_glob.return_value = [mock_wheel]
            
            checker = ReproducibleBuildChecker()
            result = checker.verify("test-package", "1.0.0")
            
            # Verify zipfile was used
            mock_zipfile_class.assert_called_once()

    @patch('provchain.verifier.reproducible.builder.calculate_hash')
    @patch('provchain.verifier.reproducible.builder.subprocess.run')
    @patch('provchain.verifier.reproducible.builder.tarfile.open')
    @patch('provchain.verifier.reproducible.builder.HTTPClient')
    @patch('provchain.verifier.reproducible.builder.PyPIClient')
    def test_verify_extract_tar_gz(self, mock_pypi_class, mock_http_class,
                                   mock_tarfile_open, mock_subprocess, mock_calculate_hash):
        """Test verify with tar.gz file extraction"""
        # Setup PyPI client
        mock_pypi = MagicMock()
        mock_pypi.__enter__.return_value = mock_pypi
        mock_pypi.__exit__.return_value = None
        mock_pypi.get_package_metadata.return_value = {
            "releases": {
                "1.0.0": [
                    {"filename": "package-1.0.0.tar.gz", "url": "http://example.com/package.tar.gz"},
                    {"filename": "package-1.0.0.whl", "digests": {"sha256": "abc123"}}
                ]
            }
        }
        mock_pypi_class.return_value = mock_pypi
        
        # Setup HTTP client
        mock_http = MagicMock()
        mock_http.__enter__.return_value = mock_http
        mock_http.__exit__.return_value = None
        mock_response = MagicMock()
        mock_response.content = b"tar content"
        mock_http.get.return_value = mock_response
        mock_http_class.return_value = mock_http
        
        # Setup tarfile - need to mock extractall to create a directory
        mock_tar = MagicMock()
        def mock_extractall(path):
            # Create a directory to simulate extraction
            Path(path) / "package-1.0.0".mkdir(parents=True, exist_ok=True)
        mock_tar.extractall = mock_extractall
        mock_tarfile_open.return_value.__enter__.return_value = mock_tar
        mock_tarfile_open.return_value.__exit__.return_value = None
        
        # Setup subprocess
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Setup hash calculation
        mock_calculate_hash.return_value = "abc123"
        
        # Mock Path.glob to return a wheel file
        with patch('pathlib.Path.glob') as mock_glob:
            mock_wheel = MagicMock(spec=Path)
            mock_wheel.__str__ = lambda x: "package-1.0.0-py3-none-any.whl"
            mock_glob.return_value = [mock_wheel]
            
            checker = ReproducibleBuildChecker()
            result = checker.verify("test-package", "1.0.0")
            
            # Verify tarfile was used
            mock_tarfile_open.assert_called_once()

    @patch('provchain.verifier.reproducible.builder.HTTPClient')
    @patch('provchain.verifier.reproducible.builder.PyPIClient')
    def test_verify_extraction_failed(self, mock_pypi_class, mock_http_class):
        """Test verify when extraction fails (no extracted directories)"""
        # Setup PyPI client
        mock_pypi = MagicMock()
        mock_pypi.__enter__.return_value = mock_pypi
        mock_pypi.__exit__.return_value = None
        mock_pypi.get_package_metadata.return_value = {
            "releases": {
                "1.0.0": [
                    {"filename": "package-1.0.0.tar.gz", "url": "http://example.com/package.tar.gz"}
                ]
            }
        }
        mock_pypi_class.return_value = mock_pypi
        
        # Setup HTTP client
        mock_http = MagicMock()
        mock_http.__enter__.return_value = mock_http
        mock_http.__exit__.return_value = None
        mock_response = MagicMock()
        mock_response.content = b"tar content"
        mock_http.get.return_value = mock_response
        mock_http_class.return_value = mock_http
        
        # Mock tarfile to not create any directories
        with patch('provchain.verifier.reproducible.builder.tarfile.open') as mock_tarfile:
            mock_tar = MagicMock()
            mock_tar.extractall = MagicMock()  # Don't create directories
            mock_tarfile.return_value.__enter__.return_value = mock_tar
            mock_tarfile.return_value.__exit__.return_value = None
            
            # Mock Path.iterdir to return empty (no extracted dirs)
            with patch('pathlib.Path.iterdir') as mock_iterdir:
                mock_iterdir.return_value = []
                
                checker = ReproducibleBuildChecker()
                result = checker.verify("test-package", "1.0.0")
                
                assert result["status"] == "extraction_failed"
                assert "Could not extract source distribution" in result["note"]

    @patch('provchain.verifier.reproducible.builder.calculate_hash')
    @patch('provchain.verifier.reproducible.builder.subprocess.run')
    @patch('provchain.verifier.reproducible.builder.tarfile.open')
    @patch('provchain.verifier.reproducible.builder.HTTPClient')
    @patch('provchain.verifier.reproducible.builder.PyPIClient')
    def test_verify_build_success(self, mock_pypi_class, mock_http_class,
                                  mock_tarfile_open, mock_subprocess, mock_calculate_hash):
        """Test verify with successful build"""
        # Setup PyPI client
        mock_pypi = MagicMock()
        mock_pypi.__enter__.return_value = mock_pypi
        mock_pypi.__exit__.return_value = None
        mock_pypi.get_package_metadata.return_value = {
            "releases": {
                "1.0.0": [
                    {"filename": "package-1.0.0.tar.gz", "url": "http://example.com/package.tar.gz"},
                    {"filename": "package-1.0.0.whl", "digests": {"sha256": "abc123"}}
                ]
            }
        }
        mock_pypi_class.return_value = mock_pypi
        
        # Setup HTTP client
        mock_http = MagicMock()
        mock_http.__enter__.return_value = mock_http
        mock_http.__exit__.return_value = None
        mock_response = MagicMock()
        mock_response.content = b"tar content"
        mock_http.get.return_value = mock_response
        mock_http_class.return_value = mock_http
        
        # Setup tarfile
        mock_tar = MagicMock()
        def mock_extractall(path):
            extract_path = Path(path) if isinstance(path, str) else path
            (extract_path / "package-1.0.0").mkdir(parents=True, exist_ok=True)
        mock_tar.extractall = mock_extractall
        mock_tarfile_open.return_value.__enter__.return_value = mock_tar
        mock_tarfile_open.return_value.__exit__.return_value = None
        
        # Setup subprocess - successful build
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Setup hash calculation - matching hashes
        mock_calculate_hash.return_value = "abc123"
        
        # Mock Path.glob to return a wheel file when called on build_dir
        original_glob = Path.glob
        def mock_glob(self, pattern):
            if pattern == "*.whl":
                # Return a mock wheel path
                mock_wheel = MagicMock(spec=Path)
                mock_wheel.__str__ = lambda x: "package-1.0.0-py3-none-any.whl"
                return [mock_wheel]
            return original_glob(self, pattern)
        
        with patch.object(Path, 'glob', mock_glob):
            checker = ReproducibleBuildChecker()
            result = checker.verify("test-package", "1.0.0")
            
            assert result["status"] == "compared"
            assert result["reproducible"] is True

    @patch('provchain.verifier.reproducible.builder.subprocess.run')
    @patch('provchain.verifier.reproducible.builder.tarfile.open')
    @patch('provchain.verifier.reproducible.builder.HTTPClient')
    @patch('provchain.verifier.reproducible.builder.PyPIClient')
    def test_verify_build_failed(self, mock_pypi_class, mock_http_class,
                                  mock_tarfile_open, mock_subprocess):
        """Test verify when build fails"""
        # Setup PyPI client
        mock_pypi = MagicMock()
        mock_pypi.__enter__.return_value = mock_pypi
        mock_pypi.__exit__.return_value = None
        mock_pypi.get_package_metadata.return_value = {
            "releases": {
                "1.0.0": [
                    {"filename": "package-1.0.0.tar.gz", "url": "http://example.com/package.tar.gz"}
                ]
            }
        }
        mock_pypi_class.return_value = mock_pypi
        
        # Setup HTTP client
        mock_http = MagicMock()
        mock_http.__enter__.return_value = mock_http
        mock_http.__exit__.return_value = None
        mock_response = MagicMock()
        mock_response.content = b"tar content"
        mock_http.get.return_value = mock_response
        mock_http_class.return_value = mock_http
        
        # Setup tarfile
        mock_tar = MagicMock()
        def mock_extractall(path):
            extract_path = Path(path) if isinstance(path, str) else path
            (extract_path / "package-1.0.0").mkdir(parents=True, exist_ok=True)
        mock_tar.extractall = mock_extractall
        mock_tarfile_open.return_value.__enter__.return_value = mock_tar
        mock_tarfile_open.return_value.__exit__.return_value = None
        
        # Setup subprocess - build failed
        mock_subprocess.return_value = MagicMock(
            returncode=1,
            stderr=MagicMock(decode=MagicMock(return_value="Build error"))
        )
        
        checker = ReproducibleBuildChecker()
        result = checker.verify("test-package", "1.0.0")
        
        assert result["status"] == "build_failed"
        assert "Failed to build package from source" in result["note"]

    @patch('provchain.verifier.reproducible.builder.subprocess.run')
    @patch('provchain.verifier.reproducible.builder.tarfile.open')
    @patch('provchain.verifier.reproducible.builder.HTTPClient')
    @patch('provchain.verifier.reproducible.builder.PyPIClient')
    def test_verify_no_wheel_after_build(self, mock_pypi_class, mock_http_class,
                                          mock_tarfile_open, mock_subprocess):
        """Test verify when build succeeds but no wheel is found"""
        # Setup PyPI client
        mock_pypi = MagicMock()
        mock_pypi.__enter__.return_value = mock_pypi
        mock_pypi.__exit__.return_value = None
        mock_pypi.get_package_metadata.return_value = {
            "releases": {
                "1.0.0": [
                    {"filename": "package-1.0.0.tar.gz", "url": "http://example.com/package.tar.gz"}
                ]
            }
        }
        mock_pypi_class.return_value = mock_pypi
        
        # Setup HTTP client
        mock_http = MagicMock()
        mock_http.__enter__.return_value = mock_http
        mock_http.__exit__.return_value = None
        mock_response = MagicMock()
        mock_response.content = b"tar content"
        mock_http.get.return_value = mock_response
        mock_http_class.return_value = mock_http
        
        # Setup tarfile
        mock_tar = MagicMock()
        def mock_extractall(path):
            extract_path = Path(path) if isinstance(path, str) else path
            (extract_path / "package-1.0.0").mkdir(parents=True, exist_ok=True)
        mock_tar.extractall = mock_extractall
        mock_tarfile_open.return_value.__enter__.return_value = mock_tar
        mock_tarfile_open.return_value.__exit__.return_value = None
        
        # Setup subprocess - successful build
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock Path.glob to return empty (no wheel)
        with patch('pathlib.Path.glob') as mock_glob:
            mock_glob.return_value = []
            
            checker = ReproducibleBuildChecker()
            result = checker.verify("test-package", "1.0.0")
            
            assert result["status"] == "no_wheel"
            assert "Build succeeded but no wheel found" in result["note"]

    @patch('provchain.verifier.reproducible.builder.calculate_hash')
    @patch('provchain.verifier.reproducible.builder.subprocess.run')
    @patch('provchain.verifier.reproducible.builder.tarfile.open')
    @patch('provchain.verifier.reproducible.builder.HTTPClient')
    @patch('provchain.verifier.reproducible.builder.PyPIClient')
    def test_verify_hash_comparison_not_reproducible(self, mock_pypi_class,
                                                      mock_http_class, mock_tarfile_open,
                                                      mock_subprocess, mock_calculate_hash):
        """Test verify when hash comparison shows not reproducible"""
        # Setup PyPI client
        mock_pypi = MagicMock()
        mock_pypi.__enter__.return_value = mock_pypi
        mock_pypi.__exit__.return_value = None
        mock_pypi.get_package_metadata.return_value = {
            "releases": {
                "1.0.0": [
                    {"filename": "package-1.0.0.tar.gz", "url": "http://example.com/package.tar.gz"},
                    {"filename": "package-1.0.0.whl", "digests": {"sha256": "abc123"}}
                ]
            }
        }
        mock_pypi_class.return_value = mock_pypi
        
        # Setup HTTP client
        mock_http = MagicMock()
        mock_http.__enter__.return_value = mock_http
        mock_http.__exit__.return_value = None
        mock_response = MagicMock()
        mock_response.content = b"tar content"
        mock_http.get.return_value = mock_response
        mock_http_class.return_value = mock_http
        
        # Setup tarfile
        mock_tar = MagicMock()
        def mock_extractall(path):
            extract_path = Path(path) if isinstance(path, str) else path
            (extract_path / "package-1.0.0").mkdir(parents=True, exist_ok=True)
        mock_tar.extractall = mock_extractall
        mock_tarfile_open.return_value.__enter__.return_value = mock_tar
        mock_tarfile_open.return_value.__exit__.return_value = None
        
        # Setup subprocess - successful build
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Setup hash calculation - different hashes
        mock_calculate_hash.return_value = "def456"
        
        # Mock Path.glob to return a wheel file
        with patch('pathlib.Path.glob') as mock_glob:
            mock_wheel = MagicMock(spec=Path)
            mock_wheel.__str__ = lambda x: "package-1.0.0-py3-none-any.whl"
            mock_glob.return_value = [mock_wheel]
            
            checker = ReproducibleBuildChecker()
            result = checker.verify("test-package", "1.0.0")
            
            assert result["status"] == "compared"
            assert result["reproducible"] is False
            assert "Package is not reproducible" in result["note"]

    @patch('provchain.verifier.reproducible.builder.subprocess.run')
    @patch('provchain.verifier.reproducible.builder.tarfile.open')
    @patch('provchain.verifier.reproducible.builder.HTTPClient')
    @patch('provchain.verifier.reproducible.builder.PyPIClient')
    def test_verify_build_timeout(self, mock_pypi_class, mock_http_class,
                                   mock_tarfile_open, mock_subprocess):
        """Test verify when build times out"""
        # Setup PyPI client
        mock_pypi = MagicMock()
        mock_pypi.__enter__.return_value = mock_pypi
        mock_pypi.__exit__.return_value = None
        mock_pypi.get_package_metadata.return_value = {
            "releases": {
                "1.0.0": [
                    {"filename": "package-1.0.0.tar.gz", "url": "http://example.com/package.tar.gz"}
                ]
            }
        }
        mock_pypi_class.return_value = mock_pypi
        
        # Setup HTTP client
        mock_http = MagicMock()
        mock_http.__enter__.return_value = mock_http
        mock_http.__exit__.return_value = None
        mock_response = MagicMock()
        mock_response.content = b"tar content"
        mock_http.get.return_value = mock_response
        mock_http_class.return_value = mock_http
        
        # Setup tarfile
        mock_tar = MagicMock()
        def mock_extractall(path):
            extract_path = Path(path) if isinstance(path, str) else path
            (extract_path / "package-1.0.0").mkdir(parents=True, exist_ok=True)
        mock_tar.extractall = mock_extractall
        mock_tarfile_open.return_value.__enter__.return_value = mock_tar
        mock_tarfile_open.return_value.__exit__.return_value = None
        
        # Setup subprocess - timeout
        mock_subprocess.side_effect = subprocess.TimeoutExpired("python", 300)
        
        checker = ReproducibleBuildChecker()
        result = checker.verify("test-package", "1.0.0")
        
        assert result["status"] == "timeout"
        assert "Build process timed out" in result["note"]

    @patch('provchain.verifier.reproducible.builder.subprocess.run')
    @patch('provchain.verifier.reproducible.builder.tarfile.open')
    @patch('provchain.verifier.reproducible.builder.HTTPClient')
    @patch('provchain.verifier.reproducible.builder.PyPIClient')
    def test_verify_build_tools_missing(self, mock_pypi_class, mock_http_class,
                                        mock_tarfile_open, mock_subprocess):
        """Test verify when build tools are missing"""
        # Setup PyPI client
        mock_pypi = MagicMock()
        mock_pypi.__enter__.return_value = mock_pypi
        mock_pypi.__exit__.return_value = None
        mock_pypi.get_package_metadata.return_value = {
            "releases": {
                "1.0.0": [
                    {"filename": "package-1.0.0.tar.gz", "url": "http://example.com/package.tar.gz"}
                ]
            }
        }
        mock_pypi_class.return_value = mock_pypi
        
        # Setup HTTP client
        mock_http = MagicMock()
        mock_http.__enter__.return_value = mock_http
        mock_http.__exit__.return_value = None
        mock_response = MagicMock()
        mock_response.content = b"tar content"
        mock_http.get.return_value = mock_response
        mock_http_class.return_value = mock_http
        
        # Setup tarfile
        mock_tar = MagicMock()
        def mock_extractall(path):
            extract_path = Path(path) if isinstance(path, str) else path
            (extract_path / "package-1.0.0").mkdir(parents=True, exist_ok=True)
        mock_tar.extractall = mock_extractall
        mock_tarfile_open.return_value.__enter__.return_value = mock_tar
        mock_tarfile_open.return_value.__exit__.return_value = None
        
        # Setup subprocess - FileNotFoundError
        mock_subprocess.side_effect = FileNotFoundError("python not found")
        
        checker = ReproducibleBuildChecker()
        result = checker.verify("test-package", "1.0.0")
        
        assert result["status"] == "build_tools_missing"
        assert "Python build module not available" in result["note"]

    @patch('provchain.verifier.reproducible.builder.PyPIClient')
    def test_verify_exception_handling(self, mock_pypi_class):
        """Test verify when general exception occurs"""
        # Setup PyPI client to raise exception
        mock_pypi = MagicMock()
        mock_pypi.__enter__.side_effect = Exception("General error")
        mock_pypi_class.return_value = mock_pypi
        
        checker = ReproducibleBuildChecker()
        result = checker.verify("test-package", "1.0.0")
        
        assert result["status"] == "error"
        assert "General error" in result["error"]
        assert "Error during reproducible build check" in result["note"]

    @patch('provchain.verifier.reproducible.builder.calculate_hash')
    @patch('provchain.verifier.reproducible.builder.subprocess.run')
    @patch('provchain.verifier.reproducible.builder.tarfile.open')
    @patch('provchain.verifier.reproducible.builder.HTTPClient')
    @patch('provchain.verifier.reproducible.builder.PyPIClient')
    def test_verify_built_no_original_wheel(self, mock_pypi_class, mock_http_class,
                                             mock_tarfile_open, mock_subprocess, mock_calculate_hash):
        """Test verify when package is built but no original wheel for comparison"""
        # Setup PyPI client - no wheel in releases
        mock_pypi = MagicMock()
        mock_pypi.__enter__.return_value = mock_pypi
        mock_pypi.__exit__.return_value = None
        mock_pypi.get_package_metadata.return_value = {
            "releases": {
                "1.0.0": [
                    {"filename": "package-1.0.0.tar.gz", "url": "http://example.com/package.tar.gz"}
                    # No wheel file
                ]
            }
        }
        mock_pypi_class.return_value = mock_pypi
        
        # Setup HTTP client
        mock_http = MagicMock()
        mock_http.__enter__.return_value = mock_http
        mock_http.__exit__.return_value = None
        mock_response = MagicMock()
        mock_response.content = b"tar content"
        mock_http.get.return_value = mock_response
        mock_http_class.return_value = mock_http
        
        # Setup tarfile
        mock_tar = MagicMock()
        def mock_extractall(path):
            extract_path = Path(path) if isinstance(path, str) else path
            (extract_path / "package-1.0.0").mkdir(parents=True, exist_ok=True)
        mock_tar.extractall = mock_extractall
        mock_tarfile_open.return_value.__enter__.return_value = mock_tar
        mock_tarfile_open.return_value.__exit__.return_value = None
        
        # Setup subprocess - successful build
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock Path.glob to return a wheel file
        with patch('pathlib.Path.glob') as mock_glob:
            mock_wheel = MagicMock(spec=Path)
            mock_wheel.__str__ = lambda x: "package-1.0.0-py3-none-any.whl"
            mock_glob.return_value = [mock_wheel]
            
            checker = ReproducibleBuildChecker()
            result = checker.verify("test-package", "1.0.0")
            
            assert result["status"] == "built"
            assert "Package built successfully but comparison not available" in result["note"]
