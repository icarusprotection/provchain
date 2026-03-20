"""Behavioral sandbox analyzer"""

import logging
import re
from pathlib import Path
from typing import Any

from provchain.data.models import AnalysisResult, Finding, PackageMetadata, RiskLevel
from provchain.interrogator.analyzers.base import BaseAnalyzer
from provchain.interrogator.sandbox.container import SandboxContainer
from provchain.interrogator.sandbox.tracer import ClassifiedFinding, SystemCallTracer

logger = logging.getLogger(__name__)

# Patterns for static fallback analysis when Docker is unavailable
STATIC_SUSPICIOUS_PATTERNS: list[tuple[str, str, str]] = [
    # (regex, description, severity)
    # Environment variable access for sensitive vars
    (
        r"""os\.environ\s*\[.*(?:SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL|AWS_|AZURE_|GCP_)""",
        "Access to sensitive environment variable",
        "high",
    ),
    (
        r"""os\.getenv\s*\(.*(?:SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL|AWS_|AZURE_|GCP_)""",
        "Access to sensitive environment variable via getenv",
        "high",
    ),
    # File system writes to user home
    (
        r"""(?:open|Path)\s*\(.*(?:expanduser|~/|/home/|/root/).*['\"]w""",
        "File write to user home directory",
        "medium",
    ),
    # Dynamic code loading
    (
        r"""importlib\.import_module\s*\([^'\"]+\)""",
        "Dynamic module import with variable argument",
        "medium",
    ),
    (
        r"""__import__\s*\([^'\"][^)]*\)""",
        "Dynamic __import__ with variable argument",
        "high",
    ),
    # Obfuscated code - long base64 strings
    (
        r"""['\"][A-Za-z0-9+/=]{100,}['\"]""",
        "Long base64-encoded string (possible obfuscated payload)",
        "high",
    ),
    (
        r"""base64\.b64decode\s*\(""",
        "Base64 decode operation",
        "medium",
    ),
    # Reverse shell patterns
    (
        r"""socket\.socket\(.*SOCK_STREAM\).*connect""",
        "TCP socket connect pattern (possible reverse shell)",
        "critical",
    ),
    (
        r"""subprocess\.(?:Popen|call|run)\s*\(\s*\[?\s*['\"](?:/bin/sh|/bin/bash|cmd\.exe|powershell)""",
        "Shell execution via subprocess",
        "high",
    ),
    (
        r"""os\.dup2\s*\(""",
        "File descriptor duplication (reverse shell indicator)",
        "critical",
    ),
    # Code execution from network data
    (
        r"""exec\s*\(\s*(?:requests|urllib|http)""",
        "Code execution from network-fetched data",
        "critical",
    ),
    (
        r"""eval\s*\(\s*(?:requests|urllib|http)""",
        "Eval of network-fetched data",
        "critical",
    ),
    # Compile/marshal for obfuscation
    (
        r"""marshal\.loads\s*\(""",
        "Marshal deserialization (code obfuscation technique)",
        "high",
    ),
    (
        r"""compile\s*\(\s*(?:base64|codecs|zlib)""",
        "Code compilation from encoded data",
        "critical",
    ),
]


def _severity_to_risk_level(severity: str) -> RiskLevel:
    """Convert string severity to RiskLevel enum."""
    mapping = {
        "low": RiskLevel.LOW,
        "medium": RiskLevel.MEDIUM,
        "high": RiskLevel.HIGH,
        "critical": RiskLevel.CRITICAL,
    }
    return mapping.get(severity, RiskLevel.MEDIUM)


def _findings_to_risk_score(classified: list[ClassifiedFinding]) -> float:
    """Compute risk score from classified findings."""
    tracer = SystemCallTracer()
    return tracer.classify_risk(classified)


class BehaviorAnalyzer(BaseAnalyzer):
    """Dynamic analysis in isolated container with static fallback"""

    name = "behavior"

    def __init__(self, docker_available: bool = False):
        self.docker_available = docker_available

    def _convert_classified_findings(
        self,
        classified: list[ClassifiedFinding],
        phase: str,
    ) -> list[Finding]:
        """Convert ClassifiedFinding objects to Finding model objects."""
        findings: list[Finding] = []
        # Group by subcategory to avoid duplicate findings
        seen: set[str] = set()

        for cf in classified:
            finding_key = f"{phase}_{cf.category}_{cf.subcategory}"
            if finding_key in seen:
                continue
            seen.add(finding_key)

            # Count how many findings share this subcategory
            count = sum(1 for f in classified if f.subcategory == cf.subcategory)

            phase_label = "during install" if phase == "install" else "during import"
            severity = _severity_to_risk_level(cf.severity)

            # Adjust severity context for install vs import phase
            description = cf.description
            if phase == "install" and cf.subcategory in (
                "dns_resolution",
                "http_connection",
                "compiler_invocation",
            ):
                description += (
                    f" ({count} occurrences {phase_label} - expected for dependency resolution)"
                )
                # Downgrade severity for expected install operations
                if severity == RiskLevel.MEDIUM:
                    severity = RiskLevel.LOW
            elif phase == "import" and cf.category == "network":
                description += (
                    f" ({count} occurrences {phase_label} - network during import is suspicious)"
                )
                # Upgrade severity for unexpected import-time network
                if severity == RiskLevel.MEDIUM:
                    severity = RiskLevel.HIGH

            findings.append(
                Finding(
                    id=f"behavior_{phase}_{cf.category}_{cf.subcategory}",
                    title=f"{cf.subcategory.replace('_', ' ').title()} {phase_label}",
                    description=description,
                    severity=severity,
                    evidence=[cf.evidence] if isinstance(cf.evidence, str) else cf.evidence,
                    remediation=self._remediation_for(cf.subcategory),
                )
            )

        return findings

    @staticmethod
    def _remediation_for(subcategory: str) -> str:
        """Return remediation advice for a finding subcategory."""
        remediations = {
            "raw_socket": "Raw sockets are rarely needed - review for network sniffing or packet injection",
            "dns_resolution": "Verify DNS targets are expected package registries",
            "http_connection": "Review outbound HTTP connections for data exfiltration",
            "non_standard_port": "Non-standard port connections are highly suspicious - investigate target",
            "data_exfiltration": "Large data transfers may indicate credential or data theft",
            "sensitive_file_access": "DO NOT INSTALL - package attempts to read credentials or sensitive data",
            "system_modification": "DO NOT INSTALL - package attempts to modify system binaries",
            "home_directory_access": "Review what data the package reads/writes in the home directory",
            "temp_executable_write": "Package writes executable to temp directory - possible dropper",
            "shell_execution": "Shell execution is suspicious - review spawned commands",
            "suspicious_child_process": "DO NOT INSTALL - package spawns network utilities (curl/wget/nc)",
            "compiler_invocation": "Compiler use during install may be legitimate for C extensions",
        }
        return remediations.get(
            subcategory, "Review this behavior for potential malicious activity"
        )

    def _run_dynamic_analysis(
        self, package_name: str, version: str | None
    ) -> tuple[list[Finding], float, float]:
        """Run full dynamic analysis in Docker sandbox.

        Returns (findings, risk_score, confidence).
        """
        findings: list[Finding] = []
        risk_score = 0.0
        tracer = SystemCallTracer()

        with SandboxContainer() as container:
            if not container.docker_available:
                return [], 0.0, 0.0

            # Phase 1: Install with tracing - catches setup.py malware
            logger.info("Phase 1: Tracing pip install for %s", package_name)
            install_trace = container.install_package_with_tracing(package_name, version)
            install_data = tracer.parse_trace(install_trace)
            install_classified = tracer.analyze_behavior(install_data, is_install_phase=True)
            install_findings = self._convert_classified_findings(install_classified, "install")
            findings.extend(install_findings)
            install_risk = tracer.classify_risk(install_classified)

            # Phase 2: Import with tracing and network isolation
            logger.info("Phase 2: Tracing import for %s", package_name)
            import_trace = container.run_with_tracing(["python", "-c", f"import {package_name}"])
            import_data = tracer.parse_trace(import_trace)
            import_classified = tracer.analyze_behavior(import_data, is_install_phase=False)
            import_findings = self._convert_classified_findings(import_classified, "import")
            findings.extend(import_findings)
            import_risk = tracer.classify_risk(import_classified)

            # Import-phase findings are weighted more heavily since they
            # represent runtime behavior, not build-time behavior
            risk_score = min(install_risk * 0.6 + import_risk * 1.0, 10.0)
            confidence = 0.8 if findings else 0.9

        return findings, risk_score, confidence

    def _run_static_fallback(
        self, package_name: str, version: str | None
    ) -> tuple[list[Finding], float, float]:
        """Static fallback analysis when Docker is unavailable.

        Downloads the source distribution and scans for suspicious runtime
        patterns that go beyond what InstallHookAnalyzer checks.

        Returns (findings, risk_score, confidence).
        """
        import tarfile
        import tempfile
        import zipfile

        from provchain.integrations.pypi import PyPIClient
        from provchain.utils.network import HTTPClient

        findings: list[Finding] = []
        risk_score = 0.0

        findings.append(
            Finding(
                id="behavior_static_fallback",
                title="Static fallback analysis (Docker unavailable)",
                description=(
                    "Docker is not available. Performing static analysis of "
                    "source code for suspicious runtime patterns. Install Docker "
                    "for full dynamic behavioral analysis."
                ),
                severity=RiskLevel.UNKNOWN,
                evidence=[],
                remediation="Install Docker to enable full sandbox behavioral analysis",
            )
        )

        try:
            with PyPIClient() as pypi:
                metadata = pypi.get_package_metadata(package_name, version)
                releases = metadata.get("releases", {}).get(version or "", [])

                # Find source distribution
                sdist = None
                for file_info in releases:
                    filename = file_info.get("filename", "")
                    if filename.endswith(".tar.gz") or filename.endswith(".zip"):
                        sdist = file_info
                        break

                if not sdist:
                    logger.warning(
                        "No source distribution found for %s - cannot perform static fallback",
                        package_name,
                    )
                    return findings, 0.0, 0.1

                sdist_url = sdist.get("url")
                if not sdist_url:
                    return findings, 0.0, 0.1

                with tempfile.TemporaryDirectory() as tmpdir:
                    tmp_path = Path(tmpdir)

                    # Download
                    with HTTPClient() as client:
                        response = client.get(sdist_url)
                        sdist_file = tmp_path / sdist["filename"]
                        sdist_file.write_bytes(response.content)

                    # Extract
                    extract_dir = tmp_path / "extracted"
                    extract_dir.mkdir()

                    if sdist_file.name.endswith(".tar.gz"):
                        with tarfile.open(sdist_file, "r:gz") as tar:
                            extract_path = extract_dir.resolve()

                            def safe_members(tar_file: Any) -> Any:
                                for member in tar_file.getmembers():
                                    member_path = Path(member.name)
                                    if member_path.is_absolute() or ".." in member_path.parts:
                                        continue
                                    resolved = (extract_path / member_path).resolve()
                                    try:
                                        resolved.relative_to(extract_path)
                                    except ValueError:
                                        continue
                                    yield member

                            tar.extractall(extract_dir, members=safe_members(tar))
                    elif sdist_file.name.endswith(".zip"):
                        with zipfile.ZipFile(sdist_file) as zipf:
                            extract_path = extract_dir.resolve()
                            for member in zipf.namelist():
                                member_path = Path(member)
                                if member_path.is_absolute() or ".." in member_path.parts:
                                    continue
                                resolved = (extract_path / member_path).resolve()
                                try:
                                    resolved.relative_to(extract_path)
                                except ValueError:
                                    continue
                                zipf.extract(member, extract_dir)

                    # Scan all Python files for suspicious patterns
                    python_files = list(extract_dir.rglob("*.py"))
                    logger.info("Static fallback: scanning %d Python files", len(python_files))

                    for py_file in python_files:
                        # Skip setup.py - already covered by InstallHookAnalyzer
                        if py_file.name == "setup.py":
                            continue

                        try:
                            content = py_file.read_text(encoding="utf-8", errors="ignore")
                        except Exception:
                            continue

                        relative_path = py_file.relative_to(extract_dir)

                        for pattern, description, severity in STATIC_SUSPICIOUS_PATTERNS:
                            matches = list(re.finditer(pattern, content, re.IGNORECASE | re.DOTALL))
                            if matches:
                                line_num = content[: matches[0].start()].count("\n") + 1
                                # Build safe ID
                                safe_desc = (
                                    description.lower()
                                    .replace(" ", "_")
                                    .replace("(", "")
                                    .replace(")", "")[:40]
                                )
                                risk_level = _severity_to_risk_level(severity)

                                findings.append(
                                    Finding(
                                        id=f"behavior_static_{safe_desc}",
                                        title=f"Suspicious runtime pattern: {description}",
                                        description=(
                                            f"Found {description} in {relative_path} at line {line_num} "
                                            f"({len(matches)} occurrence(s)). "
                                            "Detected via static analysis - Docker unavailable for dynamic confirmation."
                                        ),
                                        severity=risk_level,
                                        evidence=[
                                            f"File: {relative_path}",
                                            f"Line: {line_num}",
                                            f"Matches: {len(matches)}",
                                        ],
                                        remediation=(
                                            "Install Docker and re-run for dynamic behavioral confirmation. "
                                            f"Review {relative_path} around line {line_num}."
                                        ),
                                    )
                                )

                                severity_scores = {
                                    "low": 0.3,
                                    "medium": 0.8,
                                    "high": 1.5,
                                    "critical": 3.0,
                                }
                                risk_score += severity_scores.get(severity, 0.5)

        except Exception as e:
            logger.warning("Static fallback analysis failed: %s", e)
            findings.append(
                Finding(
                    id="behavior_static_fallback_failed",
                    title="Static fallback analysis failed",
                    description=f"Could not perform static fallback analysis: {e}",
                    severity=RiskLevel.UNKNOWN,
                    evidence=[str(e)],
                )
            )
            return findings, 0.0, 0.1

        # Static analysis has lower confidence than dynamic
        confidence = 0.4
        risk_score = min(risk_score, 10.0)

        return findings, risk_score, confidence

    def analyze(self, package_metadata: PackageMetadata) -> AnalysisResult:
        """Analyze package behavior in sandbox or via static fallback."""
        findings: list[Finding] = []
        risk_score = 0.0
        confidence = 0.0
        package_name = package_metadata.identifier.name
        version = package_metadata.identifier.version

        if self.docker_available:
            logger.info(
                "Running dynamic behavioral analysis for %s==%s",
                package_name,
                version,
            )
            try:
                findings, risk_score, confidence = self._run_dynamic_analysis(package_name, version)
            except Exception as e:
                logger.error("Dynamic behavioral analysis failed: %s", e)
                findings.append(
                    Finding(
                        id="behavior_analysis_failed",
                        title="Behavioral analysis failed",
                        description=f"Dynamic analysis failed: {e}. Falling back to static analysis.",
                        severity=RiskLevel.UNKNOWN,
                        evidence=[str(e)],
                    )
                )
                # Fall back to static analysis on Docker failure
                try:
                    static_findings, risk_score, confidence = self._run_static_fallback(
                        package_name, version
                    )
                    findings.extend(static_findings)
                except Exception as static_err:
                    logger.error("Static fallback also failed: %s", static_err)
                    confidence = 0.2
        else:
            logger.info(
                "Docker unavailable - running static fallback for %s==%s",
                package_name,
                version,
            )
            try:
                findings, risk_score, confidence = self._run_static_fallback(package_name, version)
            except Exception as e:
                logger.error("Static fallback analysis failed: %s", e)
                findings.append(
                    Finding(
                        id="behavior_static_fallback_failed",
                        title="Behavioral analysis unavailable",
                        description=(
                            f"Docker is not available and static fallback failed: {e}. "
                            "Install Docker for full behavioral analysis."
                        ),
                        severity=RiskLevel.UNKNOWN,
                        evidence=[str(e)],
                        remediation="Install Docker to enable behavioral sandbox analysis",
                    )
                )
                confidence = 0.0

        return AnalysisResult(
            analyzer=self.name,
            risk_score=min(risk_score, 10.0),
            confidence=confidence,
            findings=findings,
            raw_data={"docker_available": self.docker_available},
        )
