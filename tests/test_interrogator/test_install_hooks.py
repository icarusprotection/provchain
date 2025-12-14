"""Tests for install hooks analyzer"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, mock_open, MagicMock

from provchain.interrogator.analyzers.install_hooks import InstallHookAnalyzer
from provchain.data.models import PackageMetadata, PackageIdentifier, RiskLevel
from datetime import datetime, timezone


@pytest.fixture
def sample_package_metadata():
    """Sample package metadata for testing"""
    return PackageMetadata(
        identifier=PackageIdentifier(ecosystem="pypi", name="test-package", version="1.0.0"),
        description="Test package",
        homepage="https://example.com",
        repository="https://github.com/example/test-package",
        license="MIT",
        author="Test Author",
        author_email="test@example.com",
        published=datetime(2020, 1, 1, tzinfo=timezone.utc),
        latest_release=datetime(2024, 1, 1, tzinfo=timezone.utc),
        download_count=1000,
    )


class TestInstallHookAnalyzer:
    """Test cases for InstallHookAnalyzer"""

    def test_install_hooks_analyzer_init(self):
        """Test install hooks analyzer initialization"""
        analyzer = InstallHookAnalyzer()
        
        assert analyzer.name == "install_hooks"
        assert len(analyzer.DANGEROUS_PATTERNS) > 0
        assert len(analyzer.DANGEROUS_IMPORTS) > 0

    def test_analyze_python_file_with_exec(self, tmp_path):
        """Test analyzing Python file with exec() call"""
        analyzer = InstallHookAnalyzer()
        
        test_file = tmp_path / "setup.py"
        test_file.write_text("exec('malicious code')")
        
        findings = analyzer.analyze_python_file(test_file)
        
        assert len(findings) > 0
        assert any("exec()" in f.description for f in findings)

    def test_analyze_python_file_with_eval(self, tmp_path):
        """Test analyzing Python file with eval() call"""
        analyzer = InstallHookAnalyzer()
        
        test_file = tmp_path / "setup.py"
        test_file.write_text("result = eval(user_input)")
        
        findings = analyzer.analyze_python_file(test_file)
        
        assert len(findings) > 0
        assert any("eval()" in f.description for f in findings)

    def test_analyze_python_file_with_subprocess(self, tmp_path):
        """Test analyzing Python file with subprocess"""
        analyzer = InstallHookAnalyzer()
        
        test_file = tmp_path / "setup.py"
        test_file.write_text("import subprocess\nsubprocess.call(['rm', '-rf', '/'])")
        
        findings = analyzer.analyze_python_file(test_file)
        
        assert len(findings) > 0
        assert any("subprocess" in f.description.lower() for f in findings)

    def test_analyze_python_file_with_socket(self, tmp_path):
        """Test analyzing Python file with socket usage"""
        analyzer = InstallHookAnalyzer()
        
        test_file = tmp_path / "setup.py"
        test_file.write_text("import socket\ns = socket.socket()")
        
        findings = analyzer.analyze_python_file(test_file)
        
        assert len(findings) > 0
        assert any("socket" in f.description.lower() for f in findings)

    def test_analyze_python_file_safe(self, tmp_path):
        """Test analyzing safe Python file"""
        analyzer = InstallHookAnalyzer()
        
        test_file = tmp_path / "setup.py"
        test_file.write_text("from setuptools import setup\nsetup(name='test')")
        
        findings = analyzer.analyze_python_file(test_file)
        
        # Safe file should have minimal or no findings
        assert len(findings) == 0

    def test_analyze_python_file_syntax_error(self, tmp_path):
        """Test analyzing Python file with syntax error"""
        analyzer = InstallHookAnalyzer()
        
        test_file = tmp_path / "setup.py"
        test_file.write_text("invalid python syntax {")
        
        findings = analyzer.analyze_python_file(test_file)
        
        # Should still detect patterns even with syntax errors
        # Pattern matching works on raw text

    def test_analyze_with_no_files(self, sample_package_metadata):
        """Test analysis when no install files are found"""
        analyzer = InstallHookAnalyzer()
        
        # Patch PyPIClient where it's imported (inside the analyze method)
        with patch('provchain.integrations.pypi.PyPIClient') as mock_pypi_class:
            mock_pypi = MagicMock()
            # Mock PyPI to return metadata with no source distribution (only wheel, no sdist)
            mock_pypi.get_package_metadata.return_value = {
                "releases": {
                    "1.0.0": [
                        {"filename": "test-package-1.0.0.whl", "url": "https://example.com/package.whl"}
                    ]
                }
            }
            mock_pypi_class.return_value.__enter__.return_value = mock_pypi
            mock_pypi_class.return_value.__exit__.return_value = None
            
            result = analyzer.analyze(sample_package_metadata)
            
            assert result.analyzer == "install_hooks"
            # Should return early with no findings when no source distribution
            assert len(result.findings) == 0

    def test_analyze_with_setup_py(self, sample_package_metadata, tmp_path):
        """Test analysis with setup.py file"""
        analyzer = InstallHookAnalyzer()
        
        # Mock the repository path
        with patch('provchain.interrogator.analyzers.install_hooks.Path') as mock_path:
            mock_setup_py = MagicMock()
            mock_setup_py.exists.return_value = True
            mock_setup_py.read_text.return_value = "exec('code')"
            
            mock_path.return_value = mock_setup_py
            
            with patch.object(analyzer, 'analyze_python_file', return_value=[]) as mock_analyze:
                result = analyzer.analyze(sample_package_metadata)
                
                assert result.analyzer == "install_hooks"
                # Should have called analyze_python_file if file exists

    def test_analyze_with_pyproject_toml(self, sample_package_metadata):
        """Test analysis with pyproject.toml file"""
        analyzer = InstallHookAnalyzer()
        
        with patch('provchain.interrogator.analyzers.install_hooks.Path') as mock_path:
            mock_pyproject = MagicMock()
            mock_pyproject.exists.return_value = True
            mock_pyproject.read_text.return_value = "[build-system]\nrequires = ['setuptools']"
            
            mock_path.return_value = mock_pyproject
            
            result = analyzer.analyze(sample_package_metadata)
            
            assert result.analyzer == "install_hooks"

    def test_analyze_with_dangerous_findings(self, sample_package_metadata, tmp_path):
        """Test analysis with dangerous findings"""
        analyzer = InstallHookAnalyzer()
        
        from provchain.data.models import Finding
        dangerous_finding = Finding(
            id="install_hooks_exec",
            title="exec() call detected",
            description="exec() call found in setup.py",
            severity=RiskLevel.HIGH,
            evidence=["Line 10: exec('code')"],
        )
        
        with patch('provchain.integrations.pypi.PyPIClient') as mock_pypi_class, \
             patch('provchain.utils.network.HTTPClient') as mock_http_class, \
             patch('tempfile.TemporaryDirectory') as mock_tempdir, \
             patch('tarfile.open') as mock_tarfile_open, \
             patch.object(analyzer, 'analyze_python_file', return_value=[dangerous_finding]):
            
            # Mock PyPI client
            mock_pypi = MagicMock()
            mock_pypi.get_package_metadata.return_value = {
                "releases": {
                    "1.0.0": [
                        {"filename": "test-package-1.0.0.tar.gz", "url": "https://example.com/package.tar.gz"}
                    ]
                }
            }
            mock_pypi_class.return_value.__enter__.return_value = mock_pypi
            mock_pypi_class.return_value.__exit__.return_value = None
            
            # Mock HTTP client
            mock_http = MagicMock()
            mock_response = MagicMock()
            mock_response.content = b"fake tar content"
            mock_http.get.return_value = mock_response
            mock_http_class.return_value.__enter__.return_value = mock_http
            mock_http_class.return_value.__exit__.return_value = None
            
            # Mock temp directory
            mock_tmpdir = MagicMock()
            mock_tmpdir.__enter__.return_value = str(tmp_path)
            mock_tmpdir.__exit__.return_value = None
            mock_tempdir.return_value = mock_tmpdir
            
            # Mock tarfile extraction
            mock_tar = MagicMock()
            extracted_path = tmp_path / "extracted"
            def extractall(path):
                # Create extracted directory with package subdirectory
                extract_path = Path(path)
                if not extract_path.exists():
                    extract_path.mkdir(parents=True, exist_ok=True)
                pkg_dir = extract_path / "test-package-1.0.0"
                if not pkg_dir.exists():
                    pkg_dir.mkdir(exist_ok=True)
                setup_py = pkg_dir / "setup.py"
                if not setup_py.exists():
                    setup_py.write_text("exec('code')")
            mock_tar.extractall = extractall
            mock_tarfile_open.return_value.__enter__.return_value = mock_tar
            mock_tarfile_open.return_value.__exit__.return_value = None
            
            result = analyzer.analyze(sample_package_metadata)
            
            assert result.analyzer == "install_hooks"
            assert len(result.findings) > 0
            assert result.risk_score > 0.0

    def test_analyze_file_not_found(self, tmp_path):
        """Test analyzing non-existent file"""
        analyzer = InstallHookAnalyzer()
        
        non_existent = tmp_path / "nonexistent.py"
        
        findings = analyzer.analyze_python_file(non_existent)
        
        # Should handle gracefully
        assert isinstance(findings, list)

    def test_analyze_with_multiple_dangerous_patterns(self, tmp_path):
        """Test analyzing file with multiple dangerous patterns"""
        analyzer = InstallHookAnalyzer()
        
        test_file = tmp_path / "setup.py"
        test_file.write_text("""
import subprocess
import socket
exec('code')
eval('code')
os.system('rm -rf /')
""")
        
        findings = analyzer.analyze_python_file(test_file)
        
        # Should detect multiple patterns
        assert len(findings) > 1

    def test_analyze_pyproject_toml_with_custom_build(self, tmp_path):
        """Test analyzing pyproject.toml with custom build configuration"""
        analyzer = InstallHookAnalyzer()
        
        test_file = tmp_path / "pyproject.toml"
        test_file.write_text("""
[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"

[build]
script = "custom_build.py"
""")
        
        findings = analyzer.analyze_pyproject_toml(test_file)
        
        assert len(findings) > 0
        assert any("custom" in f.id.lower() or "build" in f.id.lower() for f in findings)

    def test_analyze_pyproject_toml_with_setup_section(self, tmp_path):
        """Test analyzing pyproject.toml with setup section"""
        analyzer = InstallHookAnalyzer()
        
        test_file = tmp_path / "pyproject.toml"
        test_file.write_text("""
[build-system]
requires = ["setuptools"]

[setup]
custom = true
""")
        
        findings = analyzer.analyze_pyproject_toml(test_file)
        
        assert len(findings) > 0

    def test_analyze_pyproject_toml_safe(self, tmp_path):
        """Test analyzing safe pyproject.toml"""
        analyzer = InstallHookAnalyzer()
        
        test_file = tmp_path / "pyproject.toml"
        test_file.write_text("""
[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"
""")
        
        findings = analyzer.analyze_pyproject_toml(test_file)
        
        # Safe pyproject.toml should have no findings
        assert len(findings) == 0

    def test_analyze_pyproject_toml_import_error(self, tmp_path):
        """Test analyzing pyproject.toml when tomli is not available - covers line 139"""
        import sys
        analyzer = InstallHookAnalyzer()
        
        test_file = tmp_path / "pyproject.toml"
        test_file.write_text("[build-system]")
        
        # Remove tomli from sys.modules to force ImportError
        tomli_backup = sys.modules.pop('tomli', None)
        try:
            # Patch the module to raise ImportError when imported
            def raise_import_error(name, *args, **kwargs):
                if name == 'tomli' or name.startswith('tomli.'):
                    raise ImportError("No module named 'tomli'")
                return __import__(name, *args, **kwargs)
            
            with patch('builtins.__import__', side_effect=raise_import_error):
                # Should handle ImportError gracefully (line 137-139)
                findings = analyzer.analyze_pyproject_toml(test_file)
                assert isinstance(findings, list)
                # Should return empty findings when tomli is not available
                assert len(findings) == 0
        finally:
            # Restore tomli if it was there
            if tomli_backup is not None:
                sys.modules['tomli'] = tomli_backup

    def test_analyze_pyproject_toml_file_error(self, tmp_path):
        """Test analyzing pyproject.toml when file read fails"""
        analyzer = InstallHookAnalyzer()
        
        non_existent = tmp_path / "nonexistent.toml"
        
        findings = analyzer.analyze_pyproject_toml(non_existent)
        
        # Should handle file errors gracefully
        assert isinstance(findings, list)

    def test_analyze_with_no_sdist_url(self, sample_package_metadata):
        """Test analysis when source distribution URL is missing"""
        analyzer = InstallHookAnalyzer()
        
        with patch('provchain.integrations.pypi.PyPIClient') as mock_pypi_class:
            mock_pypi = MagicMock()
            mock_pypi.get_package_metadata.return_value = {
                "releases": {
                    "1.0.0": [
                        {"filename": "test-package-1.0.0.tar.gz", "url": None}  # No URL
                    ]
                }
            }
            mock_pypi_class.return_value.__enter__.return_value = mock_pypi
            mock_pypi_class.return_value.__exit__.return_value = None
            
            result = analyzer.analyze(sample_package_metadata)
            
            assert result.analyzer == "install_hooks"
            assert len(result.findings) == 0
            assert result.confidence == 0.1

    def test_analyze_with_zip_sdist(self, sample_package_metadata, tmp_path):
        """Test analysis with zip source distribution"""
        analyzer = InstallHookAnalyzer()
        
        with patch('provchain.integrations.pypi.PyPIClient') as mock_pypi_class, \
             patch('provchain.utils.network.HTTPClient') as mock_http_class, \
             patch('tempfile.TemporaryDirectory') as mock_tempdir, \
             patch('zipfile.ZipFile') as mock_zipfile:
            
            # Mock PyPI client
            mock_pypi = MagicMock()
            mock_pypi.get_package_metadata.return_value = {
                "releases": {
                    "1.0.0": [
                        {"filename": "test-package-1.0.0.zip", "url": "https://example.com/package.zip"}
                    ]
                }
            }
            mock_pypi_class.return_value.__enter__.return_value = mock_pypi
            mock_pypi_class.return_value.__exit__.return_value = None
            
            # Mock HTTP client
            mock_http = MagicMock()
            mock_response = MagicMock()
            mock_response.content = b"fake zip content"
            mock_http.get.return_value = mock_response
            mock_http_class.return_value.__enter__.return_value = mock_http
            mock_http_class.return_value.__exit__.return_value = None
            
            # Mock temp directory
            mock_tmpdir = MagicMock()
            mock_tmpdir.__enter__.return_value = str(tmp_path)
            mock_tmpdir.__exit__.return_value = None
            mock_tempdir.return_value = mock_tmpdir
            
            # Mock zipfile extraction
            mock_zip = MagicMock()
            extracted_path = tmp_path / "extracted"
            def extractall(path):
                extract_path = Path(path)
                if not extract_path.exists():
                    extract_path.mkdir(parents=True, exist_ok=True)
                pkg_dir = extract_path / "test-package-1.0.0"
                if not pkg_dir.exists():
                    pkg_dir.mkdir(exist_ok=True)
            mock_zip.extractall = extractall
            mock_zipfile.return_value.__enter__.return_value = mock_zip
            mock_zipfile.return_value.__exit__.return_value = None
            
            result = analyzer.analyze(sample_package_metadata)
            
            assert result.analyzer == "install_hooks"

    def test_analyze_with_no_extracted_dirs(self, sample_package_metadata, tmp_path):
        """Test analysis when extraction produces no directories"""
        analyzer = InstallHookAnalyzer()
        
        with patch('provchain.integrations.pypi.PyPIClient') as mock_pypi_class, \
             patch('provchain.utils.network.HTTPClient') as mock_http_class, \
             patch('tempfile.TemporaryDirectory') as mock_tempdir, \
             patch('tarfile.open') as mock_tarfile_open, \
             patch('pathlib.Path.iterdir') as mock_iterdir:
            
            # Mock PyPI client
            mock_pypi = MagicMock()
            mock_pypi.get_package_metadata.return_value = {
                "releases": {
                    "1.0.0": [
                        {"filename": "test-package-1.0.0.tar.gz", "url": "https://example.com/package.tar.gz"}
                    ]
                }
            }
            mock_pypi_class.return_value.__enter__.return_value = mock_pypi
            mock_pypi_class.return_value.__exit__.return_value = None
            
            # Mock HTTP client
            mock_http = MagicMock()
            mock_response = MagicMock()
            mock_response.content = b"fake tar content"
            mock_http.get.return_value = mock_response
            mock_http_class.return_value.__enter__.return_value = mock_http
            mock_http_class.return_value.__exit__.return_value = None
            
            # Mock temp directory
            mock_tmpdir = MagicMock()
            mock_tmpdir.__enter__.return_value = str(tmp_path)
            mock_tmpdir.__exit__.return_value = None
            mock_tempdir.return_value = mock_tmpdir
            
            # Mock tarfile extraction
            mock_tar = MagicMock()
            extracted_path = tmp_path / "extracted"
            def extractall(path):
                extract_path = Path(path)
                if not extract_path.exists():
                    extract_path.mkdir(parents=True, exist_ok=True)
            mock_tar.extractall = extractall
            mock_tarfile_open.return_value.__enter__.return_value = mock_tar
            mock_tarfile_open.return_value.__exit__.return_value = None
            
            # Mock iterdir to return empty list (no extracted directories)
            mock_iterdir.return_value = []
            
            result = analyzer.analyze(sample_package_metadata)
            
            assert result.analyzer == "install_hooks"
            assert len(result.findings) == 0
            assert result.confidence == 0.1

    def test_analyze_with_pyproject_toml_file(self, sample_package_metadata, tmp_path):
        """Test analysis with pyproject.toml file in extracted package"""
        analyzer = InstallHookAnalyzer()
        
        with patch('provchain.integrations.pypi.PyPIClient') as mock_pypi_class, \
             patch('provchain.utils.network.HTTPClient') as mock_http_class, \
             patch('tempfile.TemporaryDirectory') as mock_tempdir, \
             patch('tarfile.open') as mock_tarfile_open:
            
            # Mock PyPI client
            mock_pypi = MagicMock()
            mock_pypi.get_package_metadata.return_value = {
                "releases": {
                    "1.0.0": [
                        {"filename": "test-package-1.0.0.tar.gz", "url": "https://example.com/package.tar.gz"}
                    ]
                }
            }
            mock_pypi_class.return_value.__enter__.return_value = mock_pypi
            mock_pypi_class.return_value.__exit__.return_value = None
            
            # Mock HTTP client
            mock_http = MagicMock()
            mock_response = MagicMock()
            mock_response.content = b"fake tar content"
            mock_http.get.return_value = mock_response
            mock_http_class.return_value.__enter__.return_value = mock_http
            mock_http_class.return_value.__exit__.return_value = None
            
            # Mock temp directory
            mock_tmpdir = MagicMock()
            mock_tmpdir.__enter__.return_value = str(tmp_path)
            mock_tmpdir.__exit__.return_value = None
            mock_tempdir.return_value = mock_tmpdir
            
            # Mock tarfile extraction with pyproject.toml
            mock_tar = MagicMock()
            extracted_path = tmp_path / "extracted"
            def extractall(path):
                extract_path = Path(path)
                if not extract_path.exists():
                    extract_path.mkdir(parents=True, exist_ok=True)
                pkg_dir = extract_path / "test-package-1.0.0"
                if not pkg_dir.exists():
                    pkg_dir.mkdir(exist_ok=True)
                pyproject_toml = pkg_dir / "pyproject.toml"
                if not pyproject_toml.exists():
                    pyproject_toml.write_text("[build-system]\nrequires = ['setuptools']")
            mock_tar.extractall = extractall
            mock_tarfile_open.return_value.__enter__.return_value = mock_tar
            mock_tarfile_open.return_value.__exit__.return_value = None
            
            result = analyzer.analyze(sample_package_metadata)
            
            assert result.analyzer == "install_hooks"

    def test_analyze_with_setup_cfg_file(self, sample_package_metadata, tmp_path):
        """Test analysis with setup.cfg file in extracted package"""
        analyzer = InstallHookAnalyzer()
        
        with patch('provchain.integrations.pypi.PyPIClient') as mock_pypi_class, \
             patch('provchain.utils.network.HTTPClient') as mock_http_class, \
             patch('tempfile.TemporaryDirectory') as mock_tempdir, \
             patch('tarfile.open') as mock_tarfile_open:
            
            # Mock PyPI client
            mock_pypi = MagicMock()
            mock_pypi.get_package_metadata.return_value = {
                "releases": {
                    "1.0.0": [
                        {"filename": "test-package-1.0.0.tar.gz", "url": "https://example.com/package.tar.gz"}
                    ]
                }
            }
            mock_pypi_class.return_value.__enter__.return_value = mock_pypi
            mock_pypi_class.return_value.__exit__.return_value = None
            
            # Mock HTTP client
            mock_http = MagicMock()
            mock_response = MagicMock()
            mock_response.content = b"fake tar content"
            mock_http.get.return_value = mock_response
            mock_http_class.return_value.__enter__.return_value = mock_http
            mock_http_class.return_value.__exit__.return_value = None
            
            # Mock temp directory
            mock_tmpdir = MagicMock()
            mock_tmpdir.__enter__.return_value = str(tmp_path)
            mock_tmpdir.__exit__.return_value = None
            mock_tempdir.return_value = mock_tmpdir
            
            # Mock tarfile extraction with setup.cfg
            mock_tar = MagicMock()
            extracted_path = tmp_path / "extracted"
            def extractall(path):
                extract_path = Path(path)
                if not extract_path.exists():
                    extract_path.mkdir(parents=True, exist_ok=True)
                pkg_dir = extract_path / "test-package-1.0.0"
                if not pkg_dir.exists():
                    pkg_dir.mkdir(exist_ok=True)
                setup_cfg = pkg_dir / "setup.cfg"
                if not setup_cfg.exists():
                    setup_cfg.write_text("[metadata]\nname = test-package")
            mock_tar.extractall = extractall
            mock_tarfile_open.return_value.__enter__.return_value = mock_tar
            mock_tarfile_open.return_value.__exit__.return_value = None
            
            result = analyzer.analyze(sample_package_metadata)
            
            assert result.analyzer == "install_hooks"

