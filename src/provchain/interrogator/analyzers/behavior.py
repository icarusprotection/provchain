"""Behavioral sandbox analyzer"""

from provchain.data.models import AnalysisResult, Finding, PackageMetadata, RiskLevel
from provchain.interrogator.analyzers.base import BaseAnalyzer
from provchain.interrogator.sandbox.container import SandboxContainer
from provchain.interrogator.sandbox.tracer import SystemCallTracer


class BehaviorAnalyzer(BaseAnalyzer):
    """Dynamic analysis in isolated container"""

    name = "behavior"

    def __init__(self, docker_available: bool = False):
        self.docker_available = docker_available

    def analyze(self, package_metadata: PackageMetadata) -> AnalysisResult:
        """Analyze package behavior in sandbox"""
        findings = []
        risk_score = 0.0

        if not self.docker_available:
            # Docker not available, return result indicating it was skipped
            findings.append(
                Finding(
                    id="behavior_docker_unavailable",
                    title="Behavioral analysis skipped",
                    description="Docker is not available. Install Docker to enable behavioral analysis.",
                    severity=RiskLevel.UNKNOWN,
                    evidence=[],
                    remediation="Install Docker to enable behavioral sandbox analysis",
                )
            )
            confidence = 0.0
        else:
            # Run actual behavioral analysis
            try:
                package_name = package_metadata.identifier.name
                version = package_metadata.identifier.version
                
                with SandboxContainer() as container:
                    if container.docker_available:
                        # Install package in sandbox
                        try:
                            container.install_package(package_name, version)
                            
                            # Run package import with tracing
                            trace_output = container.run_with_tracing(
                                ["python", "-c", f"import {package_name}"]
                            )
                            
                            # Analyze trace
                            tracer = SystemCallTracer()
                            trace_data = tracer.parse_trace(trace_output)
                            behavior_findings = tracer.analyze_behavior(trace_data)
                            
                            # Convert to findings
                            if trace_data["network_calls"]:
                                risk_score += 3.0
                                findings.append(
                                    Finding(
                                        id="behavior_network_activity",
                                        title="Network activity detected during import",
                                        description=f"Package attempted {len(trace_data['network_calls'])} network operations during import",
                                        severity=RiskLevel.HIGH,
                                        evidence=trace_data["network_calls"][:5],  # First 5 as evidence
                                        remediation="Review network activity - package may be exfiltrating data",
                                    )
                                )
                            
                            if trace_data["process_spawns"]:
                                risk_score += 4.0
                                findings.append(
                                    Finding(
                                        id="behavior_process_spawning",
                                        title="Process spawning detected during import",
                                        description=f"Package spawned {len(trace_data['process_spawns'])} processes during import",
                                        severity=RiskLevel.HIGH,
                                        evidence=trace_data["process_spawns"][:5],
                                        remediation="Review process spawning - package may be executing arbitrary code",
                                    )
                                )
                            
                            if behavior_findings:
                                for finding_desc in behavior_findings:
                                    if "Suspicious file access" in finding_desc:
                                        risk_score += 2.0
                                        findings.append(
                                            Finding(
                                                id="behavior_suspicious_file_access",
                                                title="Suspicious file system access",
                                                description=finding_desc,
                                                severity=RiskLevel.MEDIUM,
                                                evidence=[finding_desc],
                                                remediation="Review file system access patterns",
                                            )
                                        )
                            
                            confidence = 0.8 if findings else 0.9
                        except Exception as e:
                            findings.append(
                                Finding(
                                    id="behavior_analysis_failed",
                                    title="Behavioral analysis failed",
                                    description=f"Failed to analyze package behavior: {e}",
                                    severity=RiskLevel.UNKNOWN,
                                    evidence=[str(e)],
                                )
                            )
                            confidence = 0.3
                    else:
                        findings.append(
                            Finding(
                                id="behavior_docker_unavailable",
                                title="Docker not available",
                                description="Docker is not available for sandbox analysis",
                                severity=RiskLevel.UNKNOWN,
                                evidence=[],
                            )
                        )
                        confidence = 0.0
            except Exception as e:
                findings.append(
                    Finding(
                        id="behavior_error",
                        title="Behavioral analysis error",
                        description=f"Error during behavioral analysis: {e}",
                        severity=RiskLevel.UNKNOWN,
                        evidence=[str(e)],
                    )
                )
                confidence = 0.2

        return AnalysisResult(
            analyzer=self.name,
            risk_score=min(risk_score, 10.0),
            confidence=confidence,
            findings=findings,
            raw_data={"docker_available": self.docker_available},
        )

