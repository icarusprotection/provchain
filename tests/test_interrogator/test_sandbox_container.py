"""Tests for sandbox container"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from subprocess import CalledProcessError, TimeoutExpired

from provchain.interrogator.sandbox.container import SandboxContainer, check_docker_available


class TestCheckDockerAvailable:
    """Test cases for check_docker_available function"""

    def test_docker_available(self):
        """Test when Docker is available"""
        with patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result
            
            assert check_docker_available() is True
            mock_run.assert_called_once_with(
                ["docker", "--version"],
                capture_output=True,
                timeout=5,
            )

    def test_docker_not_available_file_not_found(self):
        """Test when Docker command is not found"""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError()
            
            assert check_docker_available() is False

    def test_docker_not_available_timeout(self):
        """Test when Docker command times out"""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = TimeoutExpired(["docker", "--version"], 5)
            
            assert check_docker_available() is False

    def test_docker_not_available_returncode_nonzero(self):
        """Test when Docker command returns non-zero exit code"""
        with patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.returncode = 1
            mock_run.return_value = mock_result
            
            assert check_docker_available() is False


class TestSandboxContainer:
    """Test cases for SandboxContainer"""

    def test_sandbox_container_init(self):
        """Test container initialization"""
        with patch('provchain.interrogator.sandbox.container.check_docker_available', return_value=True):
            container = SandboxContainer()
            
            assert container.image == "python:3.11-slim"
            assert container.container_id is None
            assert container.docker_available is True

    def test_sandbox_container_init_custom_image(self):
        """Test container initialization with custom image"""
        with patch('provchain.interrogator.sandbox.container.check_docker_available', return_value=True):
            container = SandboxContainer(image="python:3.12")
            
            assert container.image == "python:3.12"
            assert container.docker_available is True

    def test_sandbox_container_init_docker_unavailable(self):
        """Test container initialization when Docker is unavailable"""
        with patch('provchain.interrogator.sandbox.container.check_docker_available', return_value=False):
            container = SandboxContainer()
            
            assert container.docker_available is False

    def test_create_container_success(self):
        """Test successful container creation"""
        with patch('provchain.interrogator.sandbox.container.check_docker_available', return_value=True), \
             patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.stdout = "container-id-123\n"
            mock_run.return_value = mock_result
            
            container = SandboxContainer()
            container.create()
            
            assert container.container_id == "container-id-123"
            mock_run.assert_called_once()
            call_args = mock_run.call_args
            assert call_args[0][0][0] == "docker"
            assert call_args[0][0][1] == "create"
            assert "--network" in call_args[0][0]
            assert "none" in call_args[0][0]
            assert "--read-only" in call_args[0][0]

    def test_create_container_docker_unavailable(self):
        """Test container creation when Docker is unavailable"""
        with patch('provchain.interrogator.sandbox.container.check_docker_available', return_value=False):
            container = SandboxContainer()
            
            with pytest.raises(RuntimeError, match="Docker is not available"):
                container.create()

    def test_install_package_success(self):
        """Test successful package installation"""
        with patch('provchain.interrogator.sandbox.container.check_docker_available', return_value=True), \
             patch('subprocess.run') as mock_run:
            container = SandboxContainer()
            container.container_id = "container-id-123"
            
            container.install_package("requests", "2.31.0")
            
            mock_run.assert_called_once()
            call_args = mock_run.call_args
            assert call_args[0][0][0] == "docker"
            assert call_args[0][0][1] == "exec"
            assert call_args[0][0][2] == "container-id-123"
            assert "pip" in call_args[0][0]
            assert "install" in call_args[0][0]
            assert "requests==2.31.0" in call_args[0][0]

    def test_install_package_no_version(self):
        """Test package installation without version"""
        with patch('provchain.interrogator.sandbox.container.check_docker_available', return_value=True), \
             patch('subprocess.run') as mock_run:
            container = SandboxContainer()
            container.container_id = "container-id-123"
            
            container.install_package("requests")
            
            mock_run.assert_called_once()
            call_args = mock_run.call_args
            assert "requests" in call_args[0][0]
            assert "==" not in " ".join(call_args[0][0])

    def test_install_package_no_container(self):
        """Test package installation when container is not created"""
        with patch('provchain.interrogator.sandbox.container.check_docker_available', return_value=True):
            container = SandboxContainer()
            container.container_id = None
            
            with pytest.raises(RuntimeError, match="Container not created"):
                container.install_package("requests")

    def test_run_with_tracing_success(self):
        """Test successful command execution with tracing"""
        with patch('provchain.interrogator.sandbox.container.check_docker_available', return_value=True), \
             patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.stdout = "stdout output"
            mock_result.stderr = "stderr output"
            mock_run.return_value = mock_result
            
            container = SandboxContainer()
            container.container_id = "container-id-123"
            
            output = container.run_with_tracing(["python", "-c", "print('test')"])
            
            assert output == "stdout outputstderr output"
            mock_run.assert_called_once()
            call_args = mock_run.call_args
            assert call_args[0][0][0] == "docker"
            assert call_args[0][0][1] == "exec"
            assert "strace" in call_args[0][0]

    def test_run_with_tracing_no_container(self):
        """Test command execution when container is not created"""
        with patch('provchain.interrogator.sandbox.container.check_docker_available', return_value=True):
            container = SandboxContainer()
            container.container_id = None
            
            with pytest.raises(RuntimeError, match="Container not created"):
                container.run_with_tracing(["python", "-c", "print('test')"])

    def test_cleanup_with_container(self):
        """Test container cleanup when container exists"""
        with patch('provchain.interrogator.sandbox.container.check_docker_available', return_value=True), \
             patch('subprocess.run') as mock_run:
            container = SandboxContainer()
            container.container_id = "container-id-123"
            
            container.cleanup()
            
            assert container.container_id is None
            mock_run.assert_called_once()
            call_args = mock_run.call_args
            assert call_args[0][0][0] == "docker"
            assert call_args[0][0][1] == "rm"
            assert "-f" in call_args[0][0]
            assert "container-id-123" in call_args[0][0]

    def test_cleanup_no_container(self):
        """Test container cleanup when no container exists"""
        with patch('provchain.interrogator.sandbox.container.check_docker_available', return_value=True), \
             patch('subprocess.run') as mock_run:
            container = SandboxContainer()
            container.container_id = None
            
            container.cleanup()
            
            # Should not call docker rm
            mock_run.assert_not_called()

    def test_context_manager_docker_available(self):
        """Test context manager when Docker is available"""
        with patch('provchain.interrogator.sandbox.container.check_docker_available', return_value=True), \
             patch.object(SandboxContainer, 'create') as mock_create, \
             patch.object(SandboxContainer, 'cleanup') as mock_cleanup:
            container = SandboxContainer()
            
            with container as ctx:
                assert ctx is container
                mock_create.assert_called_once()
            
            mock_cleanup.assert_called_once()

    def test_context_manager_docker_unavailable(self):
        """Test context manager when Docker is unavailable"""
        with patch('provchain.interrogator.sandbox.container.check_docker_available', return_value=False), \
             patch.object(SandboxContainer, 'create') as mock_create, \
             patch.object(SandboxContainer, 'cleanup') as mock_cleanup:
            container = SandboxContainer()
            
            with container as ctx:
                assert ctx is container
                # Should not create container when Docker is unavailable
                mock_create.assert_not_called()
            
            mock_cleanup.assert_called_once()

