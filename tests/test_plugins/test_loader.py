"""Tests for plugin loader"""

import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from provchain.plugins.loader import PluginLoader
from provchain.plugins.interface import AnalyzerPlugin, ReporterPlugin
from provchain.data.models import AnalysisResult, PackageMetadata, PackageIdentifier, VetReport
from datetime import datetime, timezone


class TestPluginLoader:
    """Test cases for PluginLoader"""

    def test_plugin_loader_init_default(self):
        """Test PluginLoader initialization with default parameters"""
        loader = PluginLoader()
        assert loader.plugin_dirs == []
        assert loader.analyzers == {}
        assert loader.reporters == {}

    def test_plugin_loader_init_with_dirs(self, tmp_path):
        """Test PluginLoader initialization with plugin directories"""
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        loader = PluginLoader(plugin_dirs=[plugin_dir])
        assert loader.plugin_dirs == [plugin_dir]

    def test_discover_plugins_directory_not_exists(self, tmp_path):
        """Test discovering plugins when directory doesn't exist"""
        non_existent_dir = tmp_path / "nonexistent"
        loader = PluginLoader(plugin_dirs=[non_existent_dir])
        loader.discover_plugins()
        assert len(loader.analyzers) == 0
        assert len(loader.reporters) == 0

    def test_discover_plugins_no_python_files(self, tmp_path):
        """Test discovering plugins when no Python files exist"""
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / "readme.txt").write_text("Not a Python file")
        
        loader = PluginLoader(plugin_dirs=[plugin_dir])
        loader.discover_plugins()
        assert len(loader.analyzers) == 0
        assert len(loader.reporters) == 0

    def test_discover_plugins_analyzer_plugin(self, tmp_path):
        """Test discovering analyzer plugin"""
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        
        plugin_file = plugin_dir / "test_analyzer.py"
        plugin_file.write_text("""
from provchain.plugins.interface import AnalyzerPlugin
from provchain.data.models import AnalysisResult, PackageMetadata

class TestAnalyzer(AnalyzerPlugin):
    name = "test_analyzer"
    
    def analyze(self, package_metadata):
        return AnalysisResult(
            analyzer=self.name,
            risk_score=0.0,
            confidence=1.0,
            findings=[],
        )
""")
        
        loader = PluginLoader(plugin_dirs=[plugin_dir])
        loader.discover_plugins()
        assert "test_analyzer" in loader.analyzers
        assert loader.analyzers["test_analyzer"].name == "test_analyzer"

    def test_discover_plugins_reporter_plugin(self, tmp_path):
        """Test discovering reporter plugin"""
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        
        plugin_file = plugin_dir / "test_reporter.py"
        plugin_file.write_text("""
from provchain.plugins.interface import ReporterPlugin

class TestReporter(ReporterPlugin):
    name = "test_reporter"
    
    def report(self, report):
        pass
""")
        
        loader = PluginLoader(plugin_dirs=[plugin_dir])
        loader.discover_plugins()
        assert "test_reporter" in loader.reporters
        assert loader.reporters["test_reporter"].name == "test_reporter"

    def test_discover_plugins_both_types(self, tmp_path):
        """Test discovering both analyzer and reporter plugins"""
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        
        analyzer_file = plugin_dir / "analyzer.py"
        analyzer_file.write_text("""
from provchain.plugins.interface import AnalyzerPlugin
from provchain.data.models import AnalysisResult, PackageMetadata

class MyAnalyzer(AnalyzerPlugin):
    name = "my_analyzer"
    
    def analyze(self, package_metadata):
        return AnalysisResult(
            analyzer=self.name,
            risk_score=0.0,
            confidence=1.0,
            findings=[],
        )
""")
        
        reporter_file = plugin_dir / "reporter.py"
        reporter_file.write_text("""
from provchain.plugins.interface import ReporterPlugin

class MyReporter(ReporterPlugin):
    name = "my_reporter"
    
    def report(self, report):
        pass
""")
        
        loader = PluginLoader(plugin_dirs=[plugin_dir])
        loader.discover_plugins()
        assert "my_analyzer" in loader.analyzers
        assert "my_reporter" in loader.reporters

    def test_discover_plugins_skip_base_classes(self, tmp_path):
        """Test that base plugin classes are not registered"""
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        
        plugin_file = plugin_dir / "base.py"
        plugin_file.write_text("""
from provchain.plugins.interface import AnalyzerPlugin, ReporterPlugin
""")
        
        loader = PluginLoader(plugin_dirs=[plugin_dir])
        loader.discover_plugins()
        # Base classes should not be registered
        assert len(loader.analyzers) == 0
        assert len(loader.reporters) == 0

    def test_discover_plugins_load_error(self, tmp_path):
        """Test handling plugin load errors gracefully"""
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        
        plugin_file = plugin_dir / "broken.py"
        plugin_file.write_text("""
# This will cause a syntax error
def broken_function(
    # Missing closing parenthesis
""")
        
        loader = PluginLoader(plugin_dirs=[plugin_dir])
        # Should not raise exception
        loader.discover_plugins()
        assert len(loader.analyzers) == 0
        assert len(loader.reporters) == 0

    def test_discover_plugins_non_plugin_classes(self, tmp_path):
        """Test that non-plugin classes are not registered"""
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        
        plugin_file = plugin_dir / "regular.py"
        plugin_file.write_text("""
class RegularClass:
    pass
""")
        
        loader = PluginLoader(plugin_dirs=[plugin_dir])
        loader.discover_plugins()
        assert len(loader.analyzers) == 0
        assert len(loader.reporters) == 0

    def test_get_analyzer_existing(self, tmp_path):
        """Test getting existing analyzer plugin"""
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        
        plugin_file = plugin_dir / "analyzer.py"
        plugin_file.write_text("""
from provchain.plugins.interface import AnalyzerPlugin
from provchain.data.models import AnalysisResult, PackageMetadata

class TestAnalyzer(AnalyzerPlugin):
    name = "test"
    
    def analyze(self, package_metadata):
        return AnalysisResult(
            analyzer=self.name,
            risk_score=0.0,
            confidence=1.0,
            findings=[],
        )
""")
        
        loader = PluginLoader(plugin_dirs=[plugin_dir])
        loader.discover_plugins()
        analyzer = loader.get_analyzer("test")
        assert analyzer is not None
        assert analyzer.name == "test"

    def test_get_analyzer_nonexistent(self):
        """Test getting nonexistent analyzer plugin"""
        loader = PluginLoader()
        analyzer = loader.get_analyzer("nonexistent")
        assert analyzer is None

    def test_get_reporter_existing(self, tmp_path):
        """Test getting existing reporter plugin"""
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        
        plugin_file = plugin_dir / "reporter.py"
        plugin_file.write_text("""
from provchain.plugins.interface import ReporterPlugin

class TestReporter(ReporterPlugin):
    name = "test"
    
    def report(self, report):
        pass
""")
        
        loader = PluginLoader(plugin_dirs=[plugin_dir])
        loader.discover_plugins()
        reporter = loader.get_reporter("test")
        assert reporter is not None
        assert reporter.name == "test"

    def test_get_reporter_nonexistent(self):
        """Test getting nonexistent reporter plugin"""
        loader = PluginLoader()
        reporter = loader.get_reporter("nonexistent")
        assert reporter is None

