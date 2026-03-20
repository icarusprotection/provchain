"""Docker container management for sandboxing"""

import logging
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


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
        """Create container with network access for pip install phase"""
        if not self.docker_available:
            raise RuntimeError("Docker is not available")

        # Create container with network access initially so pip install works.
        # Network isolation is applied later for the import-phase tracing.
        cmd = [
            "docker",
            "create",
            "--read-only",  # Read-only root filesystem
            "--tmpfs",
            "/tmp",  # Temporary filesystem for /tmp
            "--tmpfs",
            "/root/.cache",  # Pip cache
            self.image,
            "sleep",
            "3600",  # Keep container running
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        self.container_id = result.stdout.strip()
        logger.info("Created sandbox container %s", self.container_id[:12])

        # Start the container so exec commands work
        subprocess.run(
            ["docker", "start", self.container_id],
            capture_output=True,
            text=True,
            check=True,
        )
        logger.info("Started sandbox container %s", self.container_id[:12])

        # Install strace inside the container for tracing
        subprocess.run(
            ["docker", "exec", self.container_id, "apt-get", "update", "-qq"],
            capture_output=True,
            check=False,
        )
        subprocess.run(
            [
                "docker",
                "exec",
                self.container_id,
                "apt-get",
                "install",
                "-y",
                "-qq",
                "strace",
            ],
            capture_output=True,
            check=False,
        )

    def install_package(self, package_name: str, version: str | None = None) -> None:
        """Install package in container without tracing"""
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

        logger.info("Installing package %s in container", package_spec)
        subprocess.run(cmd, capture_output=True, check=True)

    def install_package_with_tracing(self, package_name: str, version: str | None = None) -> str:
        """Install package with strace tracing around pip install.

        Malicious packages often execute code during pip install via setup.py,
        so tracing the install phase catches attacks that only trigger at
        install time, not at import time.
        """
        if not self.container_id:
            raise RuntimeError("Container not created")

        package_spec = f"{package_name}=={version}" if version else package_name

        # Wrap the entire pip install in strace to capture setup.py execution
        trace_cmd = [
            "docker",
            "exec",
            self.container_id,
            "strace",
            "-f",  # Follow child processes (setup.py runs in subprocesses)
            "-e",
            "trace=network,file,process",
            "pip",
            "install",
            "--no-cache-dir",
            package_spec,
        ]

        logger.info("Installing package %s with tracing", package_spec)
        result = subprocess.run(trace_cmd, capture_output=True, text=True)
        return result.stdout + result.stderr

    def run_with_tracing(self, command: list[str]) -> str:
        """Run command with system call tracing and network isolation.

        This disconnects the container from the network first, so any network
        activity during import is clearly suspicious (not just dependency
        resolution).
        """
        if not self.container_id:
            raise RuntimeError("Container not created")

        # Disconnect network for import-phase tracing so any network
        # activity is clearly suspicious rather than benign DNS/HTTP
        # from pip dependency resolution.
        subprocess.run(
            ["docker", "network", "disconnect", "bridge", self.container_id],
            capture_output=True,
            check=False,  # May already be disconnected
        )
        logger.info("Disconnected network for import-phase tracing")

        # Use strace to trace system calls
        trace_cmd = ["strace", "-f", "-e", "trace=network,file,process"] + command
        cmd = ["docker", "exec", self.container_id] + trace_cmd

        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout + result.stderr

    def cleanup(self) -> None:
        """Remove container"""
        if self.container_id:
            logger.info("Removing sandbox container %s", self.container_id[:12])
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
