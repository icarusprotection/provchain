"""System call tracing interface"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Regex to parse strace output lines, e.g.:
#   [pid 12345] openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3
#   connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = 0
STRACE_LINE_RE = re.compile(
    r"(?:\[pid\s+\d+\]\s+)?"  # Optional pid prefix
    r"(\w+)"  # Syscall name
    r"\(([^)]*(?:\{[^}]*\}[^)]*)*)\)"  # Arguments (handling nested braces)
    r"\s*=\s*(.+)"  # Return value
)

PORT_RE = re.compile(r"sin_port=htons\((\d+)\)")
ADDR_RE = re.compile(r'inet_addr\("([^"]+)"\)')
PATH_RE = re.compile(r'"([^"]*)"')


@dataclass
class SyscallEntry:
    """Parsed syscall from strace output"""

    name: str
    args: str
    return_value: str
    raw_line: str


@dataclass
class ClassifiedFinding:
    """A classified behavioral finding with severity"""

    category: str  # network, file, process
    subcategory: str  # e.g., dns_resolution, credential_access, shell_exec
    description: str
    severity: str  # low, medium, high, critical
    evidence: str  # raw strace line


@dataclass
class TraceResult:
    """Structured result from trace parsing and classification"""

    network_calls: list[SyscallEntry] = field(default_factory=list)
    file_operations: list[SyscallEntry] = field(default_factory=list)
    process_spawns: list[SyscallEntry] = field(default_factory=list)
    classified_findings: list[ClassifiedFinding] = field(default_factory=list)
    risk_score: float = 0.0


# Sensitive file paths that indicate credential/data theft
SENSITIVE_FILE_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    ".ssh/",
    ".aws/credentials",
    ".aws/config",
    ".env",
    ".netrc",
    ".git-credentials",
    ".gnupg/",
    ".config/gcloud",
    ".kube/config",
    ".docker/config.json",
    "/.bash_history",
    "/.zsh_history",
    # Browser data
    ".mozilla/",
    ".chrome/",
    ".config/google-chrome",
    ".config/chromium",
]

# System directories that should not be written to
SYSTEM_WRITE_PATHS = [
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/local/bin",
    "/bin",
    "/sbin",
    "/lib",
]

# Suspicious executables in execve calls
SUSPICIOUS_EXECUTABLES = [
    "/bin/sh",
    "/bin/bash",
    "/bin/dash",
    "/bin/zsh",
    "cmd.exe",
    "powershell",
    "pwsh",
]

SUSPICIOUS_CHILD_COMMANDS = [
    "curl",
    "wget",
    "nc",
    "ncat",
    "nmap",
    "telnet",
    "socat",
    "netcat",
]

# Compilers/toolchains that are benign during install
BENIGN_INSTALL_EXECUTABLES = [
    "gcc",
    "g++",
    "cc",
    "c++",
    "make",
    "cmake",
    "rustc",
    "cargo",
    "ld",
    "as",
    "ar",
]


class SystemCallTracer:
    """Interface for system call tracing with structured classification"""

    def _parse_line(self, line: str) -> SyscallEntry | None:
        """Parse a single strace output line into a SyscallEntry."""
        match = STRACE_LINE_RE.match(line.strip())
        if not match:
            return None
        return SyscallEntry(
            name=match.group(1),
            args=match.group(2),
            return_value=match.group(3).strip(),
            raw_line=line.strip(),
        )

    def parse_trace(self, trace_output: str) -> dict[str, Any]:
        """Parse strace output and extract system calls.

        Returns a dict for backward compatibility, but with properly
        parsed syscall entries.
        """
        network_calls: list[str] = []
        file_operations: list[str] = []
        process_spawns: list[str] = []
        parsed_entries: list[SyscallEntry] = []

        for line in trace_output.split("\n"):
            entry = self._parse_line(line)
            if entry is None:
                continue

            parsed_entries.append(entry)

            if entry.name in (
                "socket",
                "connect",
                "bind",
                "listen",
                "accept",
                "sendto",
                "recvfrom",
                "sendmsg",
                "recvmsg",
                "getsockname",
                "getpeername",
            ):
                network_calls.append(entry.raw_line)
            elif entry.name in (
                "openat",
                "open",
                "read",
                "write",
                "readlink",
                "stat",
                "lstat",
                "access",
                "unlink",
                "rename",
                "mkdir",
                "rmdir",
                "chmod",
                "chown",
            ):
                file_operations.append(entry.raw_line)
            elif entry.name in ("execve", "fork", "vfork", "clone", "clone3"):
                process_spawns.append(entry.raw_line)

        return {
            "network_calls": network_calls,
            "file_operations": file_operations,
            "process_spawns": process_spawns,
            "_parsed_entries": parsed_entries,
        }

    def classify_network(self, entries: list[SyscallEntry]) -> list[ClassifiedFinding]:
        """Classify network syscalls into subcategories."""
        findings: list[ClassifiedFinding] = []

        for entry in entries:
            if entry.name == "socket" and "SOCK_RAW" in entry.args:
                findings.append(
                    ClassifiedFinding(
                        category="network",
                        subcategory="raw_socket",
                        description="Raw socket creation detected",
                        severity="high",
                        evidence=entry.raw_line,
                    )
                )

            elif entry.name == "connect":
                port_match = PORT_RE.search(entry.args)
                addr_match = ADDR_RE.search(entry.args)
                port = int(port_match.group(1)) if port_match else None
                addr = addr_match.group(1) if addr_match else None

                if port == 53:
                    findings.append(
                        ClassifiedFinding(
                            category="network",
                            subcategory="dns_resolution",
                            description=f"DNS resolution to {addr or 'unknown'}",
                            severity="low",
                            evidence=entry.raw_line,
                        )
                    )
                elif port in (80, 443):
                    findings.append(
                        ClassifiedFinding(
                            category="network",
                            subcategory="http_connection",
                            description=f"HTTP{'S' if port == 443 else ''} connection to {addr or 'unknown'}:{port}",
                            severity="medium",
                            evidence=entry.raw_line,
                        )
                    )
                elif port is not None:
                    findings.append(
                        ClassifiedFinding(
                            category="network",
                            subcategory="non_standard_port",
                            description=f"Connection to non-standard port {addr or 'unknown'}:{port}",
                            severity="high",
                            evidence=entry.raw_line,
                        )
                    )

            elif entry.name in ("sendto", "sendmsg"):
                # Check for large data sends that may indicate exfiltration
                ret = entry.return_value.strip()
                try:
                    bytes_sent = int(ret)
                    if bytes_sent > 4096:
                        findings.append(
                            ClassifiedFinding(
                                category="network",
                                subcategory="data_exfiltration",
                                description=f"Large data send ({bytes_sent} bytes) may indicate exfiltration",
                                severity="high",
                                evidence=entry.raw_line,
                            )
                        )
                except ValueError:
                    pass

            elif entry.name == "write":
                # write() on a socket fd can also indicate data exfiltration,
                # but we can't reliably distinguish socket fds here; covered
                # by sendto/sendmsg above.
                pass

        return findings

    def classify_file_operations(self, entries: list[SyscallEntry]) -> list[ClassifiedFinding]:
        """Classify file operations into subcategories."""
        findings: list[ClassifiedFinding] = []

        for entry in entries:
            path_match = PATH_RE.search(entry.args)
            if not path_match:
                continue
            path = path_match.group(1)

            # Sensitive file reads
            for sensitive in SENSITIVE_FILE_PATHS:
                if sensitive in path:
                    findings.append(
                        ClassifiedFinding(
                            category="file",
                            subcategory="sensitive_file_access",
                            description=f"Access to sensitive file: {path}",
                            severity="critical",
                            evidence=entry.raw_line,
                        )
                    )
                    break

            # System modification (writes to system dirs)
            is_write = entry.name in ("write", "unlink", "rename", "chmod", "chown")
            if is_write or ("O_WRONLY" in entry.args or "O_RDWR" in entry.args):
                for sys_path in SYSTEM_WRITE_PATHS:
                    if path.startswith(sys_path):
                        findings.append(
                            ClassifiedFinding(
                                category="file",
                                subcategory="system_modification",
                                description=f"Write to system directory: {path}",
                                severity="critical",
                                evidence=entry.raw_line,
                            )
                        )
                        break

            # Home directory access
            if path.startswith("/home/") or path.startswith("/root/"):
                severity = "medium"
                # Writing executable files to home is more suspicious
                if "O_WRONLY" in entry.args or "O_RDWR" in entry.args:
                    severity = "high"
                findings.append(
                    ClassifiedFinding(
                        category="file",
                        subcategory="home_directory_access",
                        description=f"Home directory access: {path}",
                        severity=severity,
                        evidence=entry.raw_line,
                    )
                )

            # Temp file operations - benign unless writing executables
            if path.startswith("/tmp/") and ("O_WRONLY" in entry.args or "O_RDWR" in entry.args):
                if any(path.endswith(ext) for ext in (".sh", ".py", ".elf", ".so", ".bin")):
                    findings.append(
                        ClassifiedFinding(
                            category="file",
                            subcategory="temp_executable_write",
                            description=f"Executable written to temp directory: {path}",
                            severity="high",
                            evidence=entry.raw_line,
                        )
                    )

        return findings

    def classify_process_operations(
        self, entries: list[SyscallEntry], is_install_phase: bool = False
    ) -> list[ClassifiedFinding]:
        """Classify process operations into subcategories."""
        findings: list[ClassifiedFinding] = []

        for entry in entries:
            if entry.name != "execve":
                continue

            path_match = PATH_RE.search(entry.args)
            if not path_match:
                continue
            executable = path_match.group(1)
            exe_basename = executable.rsplit("/", 1)[-1] if "/" in executable else executable

            # Shell execution
            if executable in SUSPICIOUS_EXECUTABLES:
                findings.append(
                    ClassifiedFinding(
                        category="process",
                        subcategory="shell_execution",
                        description=f"Shell execution: {executable}",
                        severity="high",
                        evidence=entry.raw_line,
                    )
                )
                continue

            # Suspicious child commands (curl, wget, nc, etc.)
            if exe_basename in SUSPICIOUS_CHILD_COMMANDS:
                findings.append(
                    ClassifiedFinding(
                        category="process",
                        subcategory="suspicious_child_process",
                        description=f"Suspicious process spawned: {executable}",
                        severity="critical",
                        evidence=entry.raw_line,
                    )
                )
                continue

            # Compiler/toolchain invocation - benign during install
            if exe_basename in BENIGN_INSTALL_EXECUTABLES:
                if is_install_phase:
                    findings.append(
                        ClassifiedFinding(
                            category="process",
                            subcategory="compiler_invocation",
                            description=f"Compiler/toolchain during install: {executable}",
                            severity="low",
                            evidence=entry.raw_line,
                        )
                    )
                else:
                    # Compiler during import is unusual
                    findings.append(
                        ClassifiedFinding(
                            category="process",
                            subcategory="compiler_invocation",
                            description=f"Unexpected compiler invocation during import: {executable}",
                            severity="high",
                            evidence=entry.raw_line,
                        )
                    )

        return findings

    def analyze_behavior(
        self, trace_data: dict[str, Any], is_install_phase: bool = False
    ) -> list[ClassifiedFinding]:
        """Analyze trace data for suspicious behavior.

        Returns structured ClassifiedFinding objects with severity levels.
        The is_install_phase flag adjusts severity: some operations (like
        network access) are expected during install but suspicious during
        import.
        """
        parsed_entries: list[SyscallEntry] = trace_data.get("_parsed_entries", [])

        # Separate entries by category
        network_entries = [
            e
            for e in parsed_entries
            if e.name
            in (
                "socket",
                "connect",
                "bind",
                "listen",
                "accept",
                "sendto",
                "recvfrom",
                "sendmsg",
                "recvmsg",
            )
        ]
        file_entries = [
            e
            for e in parsed_entries
            if e.name
            in (
                "openat",
                "open",
                "read",
                "write",
                "readlink",
                "stat",
                "lstat",
                "access",
                "unlink",
                "rename",
                "mkdir",
                "rmdir",
                "chmod",
                "chown",
            )
        ]
        process_entries = [
            e for e in parsed_entries if e.name in ("execve", "fork", "vfork", "clone", "clone3")
        ]

        all_findings: list[ClassifiedFinding] = []
        all_findings.extend(self.classify_network(network_entries))
        all_findings.extend(self.classify_file_operations(file_entries))
        all_findings.extend(self.classify_process_operations(process_entries, is_install_phase))

        return all_findings

    def classify_risk(self, findings: list[ClassifiedFinding]) -> float:
        """Compute a numeric risk score (0.0-10.0) from classified findings."""
        severity_weights = {
            "low": 0.2,
            "medium": 0.8,
            "high": 2.0,
            "critical": 4.0,
        }

        score = 0.0
        # Track unique subcategories to avoid over-counting repeated syscalls
        seen_subcategories: set[str] = set()

        for finding in findings:
            weight = severity_weights.get(finding.severity, 0.5)
            if finding.subcategory not in seen_subcategories:
                # Full weight for first occurrence of each subcategory
                score += weight
                seen_subcategories.add(finding.subcategory)
            else:
                # Diminished weight for repeated subcategories
                score += weight * 0.1

        return min(score, 10.0)
