"""Tests for behavior analyzer"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone

from provchain.interrogator.analyzers.behavior import BehaviorAnalyzer
from provchain.data.models import PackageMetadata, PackageIdentifier, RiskLevel


@pytest.fixture
def sample_package_metadata():
    """Sample package metadata for testing"""
    return PackageMetadata(
        identifier=PackageIdentifier(ecosystem="pypi", name="requests", version="2.31.0"),
        description="HTTP library",
        homepage="https://example.com",
        repository="https://github.com/example/requests",
        license="Apache 2.0",
        author="Test Author",
        author_email="test@example.com",
        published=datetime(2020, 1, 1, tzinfo=timezone.utc),
        latest_release=datetime(2024, 1, 1, tzinfo=timezone.utc),
        download_count=1000,
    )


class TestBehaviorAnalyzer:
    """Test cases for BehaviorAnalyzer"""

    def test_behavior_analyzer_init_without_docker(self):
        """Test behavior analyzer initialization without Docker"""
        analyzer = BehaviorAnalyzer(docker_available=False)
        
        assert analyzer.name == "behavior"
        assert analyzer.docker_available is False

    def test_behavior_analyzer_init_with_docker(self):
        """Test behavior analyzer initialization with Docker"""
        analyzer = BehaviorAnalyzer(docker_available=True)
        
        assert analyzer.name == "behavior"
        assert analyzer.docker_available is True

    def test_analyze_docker_unavailable(self, sample_package_metadata):
        """Test analysis when Docker is not available"""
        analyzer = BehaviorAnalyzer(docker_available=False)
        
        result = analyzer.analyze(sample_package_metadata)
        
        assert result.analyzer == "behavior"
        assert len(result.findings) > 0
        assert result.findings[0].id == "behavior_docker_unavailable"
        assert result.findings[0].severity == RiskLevel.UNKNOWN
        assert result.confidence == 0.0

    def test_analyze_with_docker_success(self, sample_package_metadata):
        """Test analysis with Docker available and successful execution"""
        analyzer = BehaviorAnalyzer(docker_available=True)
        
        with patch('provchain.interrogator.analyzers.behavior.SandboxContainer') as mock_container_class, \
             patch('provchain.interrogator.analyzers.behavior.SystemCallTracer') as mock_tracer_class:
            mock_container = MagicMock()
            mock_container.docker_available = True
            mock_container.install_package = Mock()
            mock_container.run_with_tracing.return_value = "normal system calls"
            mock_container.__enter__.return_value = mock_container
            mock_container.__exit__.return_value = None
            mock_container_class.return_value = mock_container
            
            # Mock tracer to return empty trace data (no suspicious activity)
            mock_tracer = MagicMock()
            mock_tracer.parse_trace.return_value = {
                "network_calls": [],
                "process_spawns": [],
            }
            mock_tracer.analyze_behavior.return_value = []
            mock_tracer_class.return_value = mock_tracer
            
            result = analyzer.analyze(sample_package_metadata)
            
            assert result.analyzer == "behavior"
            mock_container.install_package.assert_called_once_with("requests", "2.31.0")
            mock_container.run_with_tracing.assert_called_once()

    def test_analyze_with_docker_suspicious_activity(self, sample_package_metadata):
        """Test analysis detects suspicious activity"""
        analyzer = BehaviorAnalyzer(docker_available=True)
        
        with patch('provchain.interrogator.analyzers.behavior.SandboxContainer') as mock_container_class, \
             patch('provchain.interrogator.analyzers.behavior.SystemCallTracer') as mock_tracer_class:
            mock_container = MagicMock()
            mock_container.docker_available = True
            mock_container.install_package = Mock()
            mock_container.run_with_tracing.return_value = "socket.connect() called"
            mock_container.__enter__.return_value = mock_container
            mock_container.__exit__.return_value = None
            mock_container_class.return_value = mock_container
            
            # Mock tracer to return suspicious activity (network calls)
            mock_tracer = MagicMock()
            mock_tracer.parse_trace.return_value = {
                "network_calls": ["socket.connect('example.com', 80)"],
                "process_spawns": [],
            }
            mock_tracer.analyze_behavior.return_value = []
            mock_tracer_class.return_value = mock_tracer
            
            result = analyzer.analyze(sample_package_metadata)
            
            assert result.analyzer == "behavior"
            assert result.risk_score > 0.0

    def test_analyze_with_docker_install_failure(self, sample_package_metadata):
        """Test analysis when package installation fails"""
        analyzer = BehaviorAnalyzer(docker_available=True)
        
        with patch('provchain.interrogator.analyzers.behavior.SandboxContainer') as mock_container_class:
            mock_container = MagicMock()
            mock_container.docker_available = True
            mock_container.install_package.side_effect = Exception("Installation failed")
            mock_container.__enter__.return_value = mock_container
            mock_container.__exit__.return_value = None
            mock_container_class.return_value = mock_container
            
            result = analyzer.analyze(sample_package_metadata)
            
            assert result.analyzer == "behavior"
            # Should have a finding about the installation failure
            assert len(result.findings) > 0
            assert any("failed" in f.id.lower() or "error" in f.id.lower() for f in result.findings)

    def test_analyze_with_docker_container_unavailable(self, sample_package_metadata):
        """Test analysis when container is not available"""
        analyzer = BehaviorAnalyzer(docker_available=True)
        
        with patch('provchain.interrogator.analyzers.behavior.SandboxContainer') as mock_container_class:
            mock_container = MagicMock()
            mock_container.docker_available = False
            mock_container.__enter__.return_value = mock_container
            mock_container.__exit__.return_value = None
            
            result = analyzer.analyze(sample_package_metadata)
            
            assert result.analyzer == "behavior"
            # Should handle gracefully when container is not available

    def test_analyze_with_docker_exception(self, sample_package_metadata):
        """Test analysis error handling"""
        analyzer = BehaviorAnalyzer(docker_available=True)
        
        with patch('provchain.interrogator.analyzers.behavior.SandboxContainer') as mock_container_class:
            mock_container_class.side_effect = Exception("Docker error")
            
            result = analyzer.analyze(sample_package_metadata)
            
            assert result.analyzer == "behavior"
            # Should return result even on error

    def test_analyze_with_docker_process_spawning(self, sample_package_metadata):
        """Test analysis detects process spawning"""
        analyzer = BehaviorAnalyzer(docker_available=True)
        
        with patch('provchain.interrogator.analyzers.behavior.SandboxContainer') as mock_container_class, \
             patch('provchain.interrogator.analyzers.behavior.SystemCallTracer') as mock_tracer_class:
            mock_container = MagicMock()
            mock_container.docker_available = True
            mock_container.install_package = Mock()
            mock_container.run_with_tracing.return_value = "process spawn trace"
            mock_container.__enter__.return_value = mock_container
            mock_container.__exit__.return_value = None
            mock_container_class.return_value = mock_container
            
            # Mock tracer to return process spawning
            mock_tracer = MagicMock()
            mock_tracer.parse_trace.return_value = {
                "network_calls": [],
                "process_spawns": ["subprocess.Popen('malicious')"],
            }
            mock_tracer.analyze_behavior.return_value = []
            mock_tracer_class.return_value = mock_tracer
            
            result = analyzer.analyze(sample_package_metadata)
            
            assert result.analyzer == "behavior"
            assert result.risk_score > 0.0
            assert any("process" in f.id.lower() or "spawn" in f.id.lower() for f in result.findings)

    def test_analyze_with_docker_suspicious_file_access(self, sample_package_metadata):
        """Test analysis detects suspicious file access"""
        analyzer = BehaviorAnalyzer(docker_available=True)
        
        with patch('provchain.interrogator.analyzers.behavior.SandboxContainer') as mock_container_class, \
             patch('provchain.interrogator.analyzers.behavior.SystemCallTracer') as mock_tracer_class:
            mock_container = MagicMock()
            mock_container.docker_available = True
            mock_container.install_package = Mock()
            mock_container.run_with_tracing.return_value = "file access trace"
            mock_container.__enter__.return_value = mock_container
            mock_container.__exit__.return_value = None
            mock_container_class.return_value = mock_container
            
            # Mock tracer to return suspicious file access
            mock_tracer = MagicMock()
            mock_tracer.parse_trace.return_value = {
                "network_calls": [],
                "process_spawns": [],
            }
            mock_tracer.analyze_behavior.return_value = ["Suspicious file access: /etc/passwd"]
            mock_tracer_class.return_value = mock_tracer
            
            result = analyzer.analyze(sample_package_metadata)
            
            assert result.analyzer == "behavior"
            assert result.risk_score > 0.0
            assert any("file" in f.id.lower() or "access" in f.id.lower() for f in result.findings)

    def test_analyze_with_docker_container_unavailable_inside(self, sample_package_metadata):
        """Test analysis when container.docker_available is False inside context"""
        analyzer = BehaviorAnalyzer(docker_available=True)
        
        with patch('provchain.interrogator.analyzers.behavior.SandboxContainer') as mock_container_class:
            mock_container = MagicMock()
            mock_container.docker_available = False  # Set to False inside context
            mock_container.__enter__.return_value = mock_container
            mock_container.__exit__.return_value = None
            mock_container_class.return_value = mock_container
            
            result = analyzer.analyze(sample_package_metadata)
            
            assert result.analyzer == "behavior"
            assert len(result.findings) > 0
            assert any("docker" in f.id.lower() or "unavailable" in f.id.lower() for f in result.findings)
            assert result.confidence == 0.0

