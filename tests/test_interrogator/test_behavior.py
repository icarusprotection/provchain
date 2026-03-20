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


def _make_tracer_mock(network_calls=None, process_spawns=None, classified=None, risk=0.0):
    """Helper to create a properly configured SystemCallTracer mock."""
    mock_tracer = MagicMock()
    mock_tracer.parse_trace.return_value = {
        "network_calls": network_calls or [],
        "process_spawns": process_spawns or [],
        "file_operations": [],
    }
    mock_tracer.analyze_behavior.return_value = classified or []
    mock_tracer.classify_risk.return_value = risk
    return mock_tracer


def _make_container_mock(docker_available=True):
    """Helper to create a properly configured SandboxContainer mock."""
    mock_container = MagicMock()
    mock_container.docker_available = docker_available
    mock_container.install_package_with_tracing = Mock(return_value="install trace output")
    mock_container.install_package = Mock()
    mock_container.run_with_tracing = Mock(return_value="import trace output")
    mock_container.__enter__ = Mock(return_value=mock_container)
    mock_container.__exit__ = Mock(return_value=None)
    return mock_container


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
        """Test analysis when Docker is not available - uses static fallback"""
        analyzer = BehaviorAnalyzer(docker_available=False)

        result = analyzer.analyze(sample_package_metadata)

        assert result.analyzer == "behavior"
        assert len(result.findings) > 0
        # Static fallback is used when Docker is unavailable
        assert result.findings[0].id in (
            "behavior_static_fallback",
            "behavior_docker_unavailable",
        )
        # Static fallback has low but non-zero confidence
        assert result.confidence <= 0.4

    def test_analyze_with_docker_success(self, sample_package_metadata):
        """Test analysis with Docker available and successful execution"""
        analyzer = BehaviorAnalyzer(docker_available=True)

        with patch('provchain.interrogator.analyzers.behavior.SandboxContainer') as mock_container_class, \
             patch('provchain.interrogator.analyzers.behavior.SystemCallTracer') as mock_tracer_class:
            mock_container = _make_container_mock(docker_available=True)
            mock_container_class.return_value = mock_container

            # Mock tracer to return empty trace data (no suspicious activity)
            mock_tracer = _make_tracer_mock(risk=0.0)
            mock_tracer_class.return_value = mock_tracer

            result = analyzer.analyze(sample_package_metadata)

            assert result.analyzer == "behavior"
            # New dual-phase analysis traces install and import separately
            mock_container.install_package_with_tracing.assert_called_once_with(
                "requests", "2.31.0"
            )
            mock_container.run_with_tracing.assert_called_once()

    def test_analyze_with_docker_suspicious_activity(self, sample_package_metadata):
        """Test analysis detects suspicious activity"""
        analyzer = BehaviorAnalyzer(docker_available=True)

        with patch('provchain.interrogator.analyzers.behavior.SandboxContainer') as mock_container_class, \
             patch('provchain.interrogator.analyzers.behavior.SystemCallTracer') as mock_tracer_class:
            mock_container = _make_container_mock(docker_available=True)
            mock_container_class.return_value = mock_container

            # Import the ClassifiedFinding to create proper mock data
            from provchain.interrogator.sandbox.tracer import ClassifiedFinding
            classified = [
                ClassifiedFinding(
                    category="network",
                    subcategory="http_connection",
                    description="HTTP connection to example.com:80",
                    severity="high",
                    evidence="connect(3, {sa_family=AF_INET, sin_port=htons(80)}, 16) = 0",
                )
            ]

            mock_tracer = _make_tracer_mock(
                network_calls=["connect(3, {sa_family=AF_INET}, 16) = 0"],
                classified=classified,
                risk=5.0,
            )
            mock_tracer_class.return_value = mock_tracer

            result = analyzer.analyze(sample_package_metadata)

            assert result.analyzer == "behavior"
            assert result.risk_score > 0.0

    def test_analyze_with_docker_install_failure(self, sample_package_metadata):
        """Test analysis when package installation fails"""
        analyzer = BehaviorAnalyzer(docker_available=True)

        with patch('provchain.interrogator.analyzers.behavior.SandboxContainer') as mock_container_class:
            mock_container = _make_container_mock(docker_available=True)
            mock_container.install_package_with_tracing.side_effect = Exception("Installation failed")
            mock_container_class.return_value = mock_container

            result = analyzer.analyze(sample_package_metadata)

            assert result.analyzer == "behavior"
            # Should have a finding about the failure
            assert len(result.findings) > 0

    def test_analyze_with_docker_container_unavailable(self, sample_package_metadata):
        """Test analysis when container is not available"""
        analyzer = BehaviorAnalyzer(docker_available=True)

        with patch('provchain.interrogator.analyzers.behavior.SandboxContainer') as mock_container_class:
            mock_container = _make_container_mock(docker_available=False)
            mock_container_class.return_value = mock_container

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
            mock_container = _make_container_mock(docker_available=True)
            mock_container_class.return_value = mock_container

            from provchain.interrogator.sandbox.tracer import ClassifiedFinding
            classified = [
                ClassifiedFinding(
                    category="process",
                    subcategory="shell_execution",
                    description="Shell execution: /bin/sh",
                    severity="high",
                    evidence="execve(\"/bin/sh\", [\"/bin/sh\", \"-c\", \"malicious\"], ...) = 0",
                )
            ]

            mock_tracer = _make_tracer_mock(
                process_spawns=["execve(\"/bin/sh\") = 0"],
                classified=classified,
                risk=6.0,
            )
            mock_tracer_class.return_value = mock_tracer

            result = analyzer.analyze(sample_package_metadata)

            assert result.analyzer == "behavior"
            assert result.risk_score > 0.0
            assert any("process" in f.id.lower() or "shell" in f.id.lower() for f in result.findings)

    def test_analyze_with_docker_suspicious_file_access(self, sample_package_metadata):
        """Test analysis detects suspicious file access"""
        analyzer = BehaviorAnalyzer(docker_available=True)

        with patch('provchain.interrogator.analyzers.behavior.SandboxContainer') as mock_container_class, \
             patch('provchain.interrogator.analyzers.behavior.SystemCallTracer') as mock_tracer_class:
            mock_container = _make_container_mock(docker_available=True)
            mock_container_class.return_value = mock_container

            from provchain.interrogator.sandbox.tracer import ClassifiedFinding
            classified = [
                ClassifiedFinding(
                    category="file",
                    subcategory="sensitive_file_access",
                    description="Sensitive file access: /etc/passwd",
                    severity="critical",
                    evidence="openat(AT_FDCWD, \"/etc/passwd\", O_RDONLY) = 3",
                )
            ]

            mock_tracer = _make_tracer_mock(classified=classified, risk=7.0)
            mock_tracer_class.return_value = mock_tracer

            result = analyzer.analyze(sample_package_metadata)

            assert result.analyzer == "behavior"
            assert result.risk_score > 0.0
            assert any("file" in f.id.lower() or "sensitive" in f.id.lower() for f in result.findings)

    def test_analyze_with_docker_container_unavailable_inside(self, sample_package_metadata):
        """Test analysis when container.docker_available is False inside context"""
        analyzer = BehaviorAnalyzer(docker_available=True)

        with patch('provchain.interrogator.analyzers.behavior.SandboxContainer') as mock_container_class:
            mock_container = _make_container_mock(docker_available=False)
            mock_container_class.return_value = mock_container

            result = analyzer.analyze(sample_package_metadata)

            assert result.analyzer == "behavior"
            # Dynamic analysis returns empty when container unavailable,
            # which triggers fallback or returns minimal results
            assert isinstance(result.findings, list)
