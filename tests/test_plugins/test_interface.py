"""Tests for plugin interfaces"""

import pytest
from abc import ABC

from provchain.plugins.interface import AnalyzerPlugin, ReporterPlugin
from provchain.data.models import AnalysisResult, PackageMetadata, PackageIdentifier, RiskLevel
from datetime import datetime, timezone


class TestAnalyzerPlugin:
    """Test cases for AnalyzerPlugin"""

    def test_analyzer_plugin_is_abstract(self):
        """Test that AnalyzerPlugin is an abstract class"""
        assert issubclass(AnalyzerPlugin, ABC)

    def test_analyzer_plugin_has_name_attribute(self):
        """Test that AnalyzerPlugin has name attribute"""
        assert hasattr(AnalyzerPlugin, 'name')

    def test_analyzer_plugin_has_analyze_method(self):
        """Test that AnalyzerPlugin has analyze abstract method"""
        assert hasattr(AnalyzerPlugin, 'analyze')
        # Check it's abstract
        with pytest.raises(TypeError):
            # Can't instantiate abstract class
            AnalyzerPlugin()

    def test_analyzer_plugin_implementation(self):
        """Test implementing AnalyzerPlugin"""
        class TestAnalyzer(AnalyzerPlugin):
            name = "test_analyzer"
            
            def analyze(self, package_metadata: PackageMetadata) -> AnalysisResult:
                return AnalysisResult(
                    analyzer=self.name,
                    risk_score=0.0,
                    confidence=1.0,
                    findings=[],
                )
        
        analyzer = TestAnalyzer()
        assert analyzer.name == "test_analyzer"
        
        metadata = PackageMetadata(
            identifier=PackageIdentifier(ecosystem="pypi", name="test", version="1.0.0"),
            description="Test package",
            latest_release=datetime.now(timezone.utc),
        )
        result = analyzer.analyze(metadata)
        assert result.analyzer == "test_analyzer"


class TestReporterPlugin:
    """Test cases for ReporterPlugin"""

    def test_reporter_plugin_is_abstract(self):
        """Test that ReporterPlugin is an abstract class"""
        assert issubclass(ReporterPlugin, ABC)

    def test_reporter_plugin_has_name_attribute(self):
        """Test that ReporterPlugin has name attribute"""
        assert hasattr(ReporterPlugin, 'name')

    def test_reporter_plugin_has_report_method(self):
        """Test that ReporterPlugin has report abstract method"""
        assert hasattr(ReporterPlugin, 'report')
        # Check it's abstract
        with pytest.raises(TypeError):
            # Can't instantiate abstract class
            ReporterPlugin()

    def test_reporter_plugin_implementation(self):
        """Test implementing ReporterPlugin"""
        from provchain.data.models import VetReport
        
        class TestReporter(ReporterPlugin):
            name = "test_reporter"
            
            def report(self, report: VetReport) -> None:
                pass
        
        reporter = TestReporter()
        assert reporter.name == "test_reporter"

