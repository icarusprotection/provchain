"""Docker container management for sandboxing"""

import subprocess
from typing import Any


def check_docker_available() -> bool:
    """Check if Docker is available"""
    try:
        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


class SandboxContainer:
    """Docker-based sandbox container"""

    def __init__(self, image: str = "python:3.11-slim"):
        self.image = image
        self.container_id: str | None = None
        self.docker_available = check_docker_available()

    def create(self) -> None:
        """Create isolated container"""
        if not self.docker_available:
            raise RuntimeError("Docker is not available")

        # Create container with network isolation
        cmd = [
            "docker",
            "create",
            "--network",
            "none",  # No network access
            "--read-only",  # Read-only root filesystem
            "--tmpfs",
            "/tmp",  # Temporary filesystem for /tmp
            self.image,
            "sleep",
            "3600",  # Keep container running
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        self.container_id = result.stdout.strip()

    def install_package(self, package_name: str, version: str | None = None) -> None:
        """Install package in container"""
        if not self.container_id:
            raise RuntimeError("Container not created")

        package_spec = f"{package_name}=={version}" if version else package_name
        cmd = [
            "docker",
            "exec",
            self.container_id,
            "pip",
            "install",
            package_spec,
        ]

        subprocess.run(cmd, capture_output=True, check=True)

    def run_with_tracing(self, command: list[str]) -> str:
        """Run command with system call tracing"""
        if not self.container_id:
            raise RuntimeError("Container not created")

        # Use strace to trace system calls
        trace_cmd = ["strace", "-f", "-e", "trace=network,file,process"] + command
        cmd = ["docker", "exec", self.container_id] + trace_cmd

        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout + result.stderr

    def cleanup(self) -> None:
        """Remove container"""
        if self.container_id:
            subprocess.run(
                ["docker", "rm", "-f", self.container_id],
                capture_output=True,
                check=False,
            )
            self.container_id = None

    def __enter__(self) -> "SandboxContainer":
        if self.docker_available:
            self.create()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.cleanup()
