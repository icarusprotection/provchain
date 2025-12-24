"""System call tracing interface"""

from typing import Any


class SystemCallTracer:
    """Interface for system call tracing"""

    def parse_trace(self, trace_output: str) -> dict[str, Any]:
        """Parse strace output and extract system calls"""
        # Parse strace output
        # This is a simplified parser - production would need more robust parsing
        network_calls = []
        file_operations = []
        process_spawns = []

        for line in trace_output.split("\n"):
            if "socket" in line or "connect" in line:
                network_calls.append(line)
            elif "open" in line or "read" in line or "write" in line:
                file_operations.append(line)
            elif "execve" in line or "fork" in line:
                process_spawns.append(line)

        return {
            "network_calls": network_calls,
            "file_operations": file_operations,
            "process_spawns": process_spawns,
        }

    def analyze_behavior(self, trace_data: dict[str, Any]) -> list[str]:
        """Analyze trace data for suspicious behavior"""
        findings = []

        # Check for network connections
        if trace_data["network_calls"]:
            findings.append(f"Network activity detected: {len(trace_data['network_calls'])} calls")

        # Check for file system access outside package directory
        suspicious_paths = ["/etc", "/home", "/root", "/tmp"]
        for op in trace_data["file_operations"]:
            for path in suspicious_paths:
                if path in op:
                    findings.append(f"Suspicious file access: {op}")

        # Check for process spawning
        if trace_data["process_spawns"]:
            findings.append(
                f"Process spawning detected: {len(trace_data['process_spawns'])} spawns"
            )

        return findings
