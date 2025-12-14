"""Tests for system call tracer"""

import pytest

from provchain.interrogator.sandbox.tracer import SystemCallTracer


class TestSystemCallTracer:
    """Test cases for SystemCallTracer"""

    def test_tracer_init(self):
        """Test tracer initialization"""
        tracer = SystemCallTracer()
        assert tracer is not None

    def test_parse_trace_network_calls(self):
        """Test parsing trace output with network calls"""
        tracer = SystemCallTracer()
        
        trace_output = """
socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
"""
        
        result = tracer.parse_trace(trace_output)
        
        assert len(result["network_calls"]) == 2
        assert "socket" in result["network_calls"][0]
        assert "connect" in result["network_calls"][1]
        assert len(result["file_operations"]) == 0
        assert len(result["process_spawns"]) == 0

    def test_parse_trace_file_operations(self):
        """Test parsing trace output with file operations"""
        tracer = SystemCallTracer()
        
        trace_output = """
open("/etc/passwd", O_RDONLY) = 3
read(3, "root:x:0:0:root:/root:/bin/bash\n", 4096) = 33
write(1, "test", 4) = 4
"""
        
        result = tracer.parse_trace(trace_output)
        
        assert len(result["file_operations"]) == 3
        assert "open" in result["file_operations"][0]
        assert "read" in result["file_operations"][1]
        assert "write" in result["file_operations"][2]
        assert len(result["network_calls"]) == 0
        assert len(result["process_spawns"]) == 0

    def test_parse_trace_process_spawns(self):
        """Test parsing trace output with process spawns"""
        tracer = SystemCallTracer()
        
        trace_output = """
fork() = 12345
execve("/bin/sh", ["sh", "-c", "echo test"], [/* 20 vars */]) = 0
"""
        
        result = tracer.parse_trace(trace_output)
        
        assert len(result["process_spawns"]) == 2
        assert "fork" in result["process_spawns"][0]
        assert "execve" in result["process_spawns"][1]
        assert len(result["network_calls"]) == 0
        assert len(result["file_operations"]) == 0

    def test_parse_trace_mixed_operations(self):
        """Test parsing trace output with mixed operations"""
        tracer = SystemCallTracer()
        
        trace_output = """
socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
open("/tmp/file", O_WRONLY) = 4
fork() = 12345
connect(3, {sa_family=AF_INET}, 16) = 0
read(4, "data", 1024) = 4
execve("/bin/sh", ["sh"], []) = 0
"""
        
        result = tracer.parse_trace(trace_output)
        
        assert len(result["network_calls"]) == 2
        assert len(result["file_operations"]) == 2
        assert len(result["process_spawns"]) == 2

    def test_parse_trace_empty(self):
        """Test parsing empty trace output"""
        tracer = SystemCallTracer()
        
        result = tracer.parse_trace("")
        
        assert len(result["network_calls"]) == 0
        assert len(result["file_operations"]) == 0
        assert len(result["process_spawns"]) == 0

    def test_parse_trace_no_matches(self):
        """Test parsing trace output with no matching patterns"""
        tracer = SystemCallTracer()
        
        trace_output = """
getpid() = 12345
getuid() = 1000
clock_gettime(CLOCK_REALTIME, {tv_sec=1234567890, tv_nsec=0}) = 0
"""
        
        result = tracer.parse_trace(trace_output)
        
        assert len(result["network_calls"]) == 0
        assert len(result["file_operations"]) == 0
        assert len(result["process_spawns"]) == 0

    def test_analyze_behavior_network_activity(self):
        """Test behavior analysis with network activity"""
        tracer = SystemCallTracer()
        
        trace_data = {
            "network_calls": ["socket(...)", "connect(...)"],
            "file_operations": [],
            "process_spawns": [],
        }
        
        findings = tracer.analyze_behavior(trace_data)
        
        assert len(findings) == 1
        assert "Network activity" in findings[0]
        assert "2 calls" in findings[0]

    def test_analyze_behavior_suspicious_file_access(self):
        """Test behavior analysis with suspicious file access"""
        tracer = SystemCallTracer()
        
        trace_data = {
            "network_calls": [],
            "file_operations": ["open(\"/etc/passwd\", O_RDONLY) = 3"],
            "process_spawns": [],
        }
        
        findings = tracer.analyze_behavior(trace_data)
        
        assert len(findings) >= 1
        assert any("Suspicious file access" in f for f in findings)
        assert any("/etc" in f for f in findings)

    def test_analyze_behavior_multiple_suspicious_paths(self):
        """Test behavior analysis with multiple suspicious paths"""
        tracer = SystemCallTracer()
        
        trace_data = {
            "network_calls": [],
            "file_operations": [
                "open(\"/etc/passwd\", O_RDONLY) = 3",
                "read(\"/home/user/file\", ...) = 10",
                "write(\"/root/secret\", ...) = 5",
                "open(\"/tmp/temp\", O_WRONLY) = 4",
            ],
            "process_spawns": [],
        }
        
        findings = tracer.analyze_behavior(trace_data)
        
        # Should find suspicious access to /etc, /home, /root, /tmp
        assert len(findings) >= 4
        assert any("/etc" in f for f in findings)
        assert any("/home" in f for f in findings)
        assert any("/root" in f for f in findings)
        assert any("/tmp" in f for f in findings)

    def test_analyze_behavior_process_spawning(self):
        """Test behavior analysis with process spawning"""
        tracer = SystemCallTracer()
        
        trace_data = {
            "network_calls": [],
            "file_operations": [],
            "process_spawns": ["fork() = 12345", "execve(...) = 0"],
        }
        
        findings = tracer.analyze_behavior(trace_data)
        
        assert len(findings) == 1
        assert "Process spawning" in findings[0]
        assert "2 spawns" in findings[0]

    def test_analyze_behavior_all_suspicious(self):
        """Test behavior analysis with all types of suspicious activity"""
        tracer = SystemCallTracer()
        
        trace_data = {
            "network_calls": ["socket(...)", "connect(...)"],
            "file_operations": ["open(\"/etc/passwd\", O_RDONLY) = 3"],
            "process_spawns": ["fork() = 12345"],
        }
        
        findings = tracer.analyze_behavior(trace_data)
        
        # Should have network activity, suspicious file access, and process spawning
        assert len(findings) >= 3
        assert any("Network activity" in f for f in findings)
        assert any("Suspicious file access" in f for f in findings)
        assert any("Process spawning" in f for f in findings)

    def test_analyze_behavior_no_suspicious_activity(self):
        """Test behavior analysis with no suspicious activity"""
        tracer = SystemCallTracer()
        
        trace_data = {
            "network_calls": [],
            "file_operations": ["open(\"/usr/lib/python3.11/lib.py\", O_RDONLY) = 3"],
            "process_spawns": [],
        }
        
        findings = tracer.analyze_behavior(trace_data)
        
        # Should have no findings (file access to /usr/lib is not suspicious)
        assert len(findings) == 0

