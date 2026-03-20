"""Tests for system call tracer"""

import pytest

from provchain.interrogator.sandbox.tracer import SystemCallTracer, ClassifiedFinding


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
        assert len(result["process_spawns"]) == 0

    def test_parse_trace_file_operations(self):
        """Test parsing trace output with file operations"""
        tracer = SystemCallTracer()

        trace_output = """
open("/etc/passwd", O_RDONLY) = 3
read(3, "root:x:0:0:root:/root:/bin/bash\\n", 4096) = 33
write(1, "test", 4) = 4
"""

        result = tracer.parse_trace(trace_output)

        # All three are classified as file operations (open, read, write)
        assert len(result["file_operations"]) >= 2
        assert any("open" in op for op in result["file_operations"])
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

    def test_parse_trace_mixed_operations(self):
        """Test parsing trace output with mixed operations"""
        tracer = SystemCallTracer()

        trace_output = """
socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
open("/tmp/file", O_WRONLY) = 4
fork() = 12345
connect(3, {sa_family=AF_INET, sin_port=htons(80)}, 16) = 0
execve("/bin/sh", ["sh"], []) = 0
"""

        result = tracer.parse_trace(trace_output)

        assert len(result["network_calls"]) == 2
        assert len(result["file_operations"]) >= 1
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
        """Test behavior analysis classifies network activity"""
        tracer = SystemCallTracer()

        trace_output = """
socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}, 16) = 0
"""
        trace_data = tracer.parse_trace(trace_output)
        findings = tracer.analyze_behavior(trace_data)

        assert len(findings) >= 1
        assert any(f.category == "network" for f in findings)
        assert any(f.subcategory == "http_connection" for f in findings)

    def test_analyze_behavior_sensitive_file_access(self):
        """Test behavior analysis detects sensitive file access"""
        tracer = SystemCallTracer()

        trace_output = """
open("/etc/passwd", O_RDONLY) = 3
"""
        trace_data = tracer.parse_trace(trace_output)
        findings = tracer.analyze_behavior(trace_data)

        assert len(findings) >= 1
        assert any(f.subcategory == "sensitive_file_access" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_analyze_behavior_shell_execution(self):
        """Test behavior analysis detects shell execution"""
        tracer = SystemCallTracer()

        trace_output = """
execve("/bin/sh", ["sh", "-c", "malicious"], []) = 0
"""
        trace_data = tracer.parse_trace(trace_output)
        findings = tracer.analyze_behavior(trace_data)

        assert len(findings) >= 1
        assert any(f.subcategory == "shell_execution" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_analyze_behavior_suspicious_child_process(self):
        """Test behavior analysis detects suspicious child processes"""
        tracer = SystemCallTracer()

        trace_output = """
execve("/usr/bin/curl", ["curl", "http://evil.com"], []) = 0
"""
        trace_data = tracer.parse_trace(trace_output)
        findings = tracer.analyze_behavior(trace_data)

        assert len(findings) >= 1
        assert any(f.subcategory == "suspicious_child_process" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_analyze_behavior_no_suspicious_activity(self):
        """Test behavior analysis with no suspicious activity"""
        tracer = SystemCallTracer()

        trace_output = """
open("/usr/lib/python3.11/lib.py", O_RDONLY) = 3
"""
        trace_data = tracer.parse_trace(trace_output)
        findings = tracer.analyze_behavior(trace_data)

        # Standard library access should not produce sensitive file findings
        assert not any(f.subcategory == "sensitive_file_access" for f in findings)

    def test_analyze_behavior_raw_socket(self):
        """Test behavior analysis detects raw socket creation"""
        tracer = SystemCallTracer()

        trace_output = """
socket(AF_INET, SOCK_RAW, IPPROTO_RAW) = 3
"""
        trace_data = tracer.parse_trace(trace_output)
        findings = tracer.analyze_behavior(trace_data)

        assert any(f.subcategory == "raw_socket" for f in findings)

    def test_analyze_behavior_non_standard_port(self):
        """Test behavior analysis detects non-standard port connections"""
        tracer = SystemCallTracer()

        trace_output = """
connect(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("10.0.0.1")}, 16) = 0
"""
        trace_data = tracer.parse_trace(trace_output)
        findings = tracer.analyze_behavior(trace_data)

        assert any(f.subcategory == "non_standard_port" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_classify_risk_no_findings(self):
        """Test risk classification with no findings"""
        tracer = SystemCallTracer()
        assert tracer.classify_risk([]) == 0.0

    def test_classify_risk_with_findings(self):
        """Test risk classification with various findings"""
        tracer = SystemCallTracer()

        findings = [
            ClassifiedFinding(
                category="network",
                subcategory="http_connection",
                description="HTTP connection",
                severity="medium",
                evidence="connect(...)",
            ),
            ClassifiedFinding(
                category="file",
                subcategory="sensitive_file_access",
                description="Credential access",
                severity="critical",
                evidence="open(...)",
            ),
        ]

        risk = tracer.classify_risk(findings)
        assert risk > 0.0
        assert risk <= 10.0

    def test_classify_risk_diminishing_returns(self):
        """Test that repeated subcategories get diminished weight"""
        tracer = SystemCallTracer()

        single = [
            ClassifiedFinding(
                category="network",
                subcategory="http_connection",
                description="HTTP 1",
                severity="medium",
                evidence="connect(...)",
            ),
        ]
        doubled = single + [
            ClassifiedFinding(
                category="network",
                subcategory="http_connection",
                description="HTTP 2",
                severity="medium",
                evidence="connect(...)",
            ),
        ]

        risk_single = tracer.classify_risk(single)
        risk_doubled = tracer.classify_risk(doubled)

        # Second occurrence should add much less than the first
        assert risk_doubled > risk_single
        assert risk_doubled < risk_single * 2

    def test_install_phase_compiler_is_benign(self):
        """Test that compiler invocations during install are low severity"""
        tracer = SystemCallTracer()

        trace_output = """
execve("/usr/bin/gcc", ["gcc", "-O2", "ext.c"], []) = 0
"""
        trace_data = tracer.parse_trace(trace_output)

        install_findings = tracer.analyze_behavior(trace_data, is_install_phase=True)
        import_findings = tracer.analyze_behavior(trace_data, is_install_phase=False)

        # During install, compiler should be low severity
        assert any(f.severity == "low" for f in install_findings if f.subcategory == "compiler_invocation")
        # During import, compiler should be high severity
        assert any(f.severity == "high" for f in import_findings if f.subcategory == "compiler_invocation")
