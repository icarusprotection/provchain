"""Enterprise API client helpers."""

from __future__ import annotations

from typing import Any

import httpx

from provchain.config import Config
from provchain.data.models import AnalysisResult, Finding, PackageIdentifier, RiskLevel, VetReport


def enterprise_enabled(config: Config | None = None) -> bool:
    """Return True when enterprise remote vetting is configured."""
    if config is None:
        config = Config()
    return bool(
        config.get("enterprise", "enabled", False)
        and config.get("enterprise", "api_url", "")
        and config.get("enterprise", "api_key", "")
    )


class EnterpriseClient:
    """Simple client for the ProvChain Enterprise backend."""

    def __init__(self, base_url: str, api_key: str, timeout: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    @classmethod
    def from_config(cls, config: Config | None = None) -> EnterpriseClient:
        if config is None:
            config = Config()
        if not enterprise_enabled(config):
            raise ValueError("Enterprise backend is not configured")
        return cls(
            base_url=str(config.get("enterprise", "api_url", "")),
            api_key=str(config.get("enterprise", "api_key", "")),
        )

    def _request(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            with httpx.Client(
                base_url=self.base_url,
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                response = client.post(
                    path,
                    json=payload,
                    headers={"X-API-Key": self.api_key},
                )
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict):
                    raise RuntimeError("Enterprise API returned a non-object response")
                return data
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text.strip()
            raise RuntimeError(
                f"Enterprise API request failed with {exc.response.status_code}: {detail}"
            ) from exc
        except httpx.RequestError as exc:
            raise RuntimeError(f"Could not reach enterprise backend: {exc}") from exc

    def vet_package(
        self,
        package_name: str,
        version: str | None = None,
        deep: bool = False,
    ) -> dict[str, Any]:
        return self._request(
            "/api/v1/vet/cli",
            {
                "package_name": package_name,
                "version": version,
                "deep": deep,
            },
        )

    def analyze_dependencies(
        self,
        package_name: str,
        version: str | None = None,
        deep: bool = False,
        max_depth: int = 4,
        max_nodes: int = 50,
    ) -> dict[str, Any]:
        return self._request(
            "/api/v1/dependencies/cli/analyze",
            {
                "package_name": package_name,
                "version": version,
                "deep": deep,
                "max_depth": max_depth,
                "max_nodes": max_nodes,
            },
        )

    def health(self) -> dict[str, Any]:
        try:
            with httpx.Client(
                base_url=self.base_url,
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                response = client.get("/health")
                response.raise_for_status()
                data = response.json()
                return data if isinstance(data, dict) else {}
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Could not verify enterprise backend health: {exc}") from exc


def _coerce_risk_level(value: str) -> RiskLevel:
    try:
        return RiskLevel(value)
    except ValueError:
        return RiskLevel.UNKNOWN


def remote_vet_response_to_report(response: dict[str, Any]) -> VetReport:
    """Convert an enterprise vet response into a local VetReport for formatters."""
    results: list[AnalysisResult] = []
    confidences: list[float] = []

    for result in response.get("results", []):
        findings = [
            Finding(
                id=finding.get("id", "unknown"),
                title=finding.get("title", "Finding"),
                description=finding.get("description", ""),
                severity=_coerce_risk_level(finding.get("severity", "unknown")),
                evidence=list(finding.get("evidence", [])),
                remediation=finding.get("remediation"),
            )
            for finding in result.get("findings", [])
        ]
        confidence = float(result.get("confidence", 0.0))
        confidences.append(confidence)
        results.append(
            AnalysisResult(
                analyzer=result.get("analyzer", "enterprise"),
                risk_score=float(result.get("risk_score", 0.0)),
                confidence=confidence,
                findings=findings,
            )
        )

    policy_violations = response.get("policy_violations", [])
    if policy_violations:
        violation_findings = [
            Finding(
                id=f"policy_{violation.get('rule_type', 'unknown')}",
                title=f"Enterprise policy: {violation.get('rule_type', 'unknown')}",
                description=violation.get("message", "Policy violation"),
                severity=(
                    RiskLevel.HIGH
                    if violation.get("action") == "block"
                    else RiskLevel.MEDIUM
                    if violation.get("action") == "warn"
                    else RiskLevel.LOW
                ),
                evidence=[],
            )
            for violation in policy_violations
        ]
        results.append(
            AnalysisResult(
                analyzer="enterprise_policy",
                risk_score=float(response.get("risk_score", 0.0)),
                confidence=1.0,
                findings=violation_findings,
            )
        )
        confidences.append(1.0)

    recommendations = list(response.get("recommendations", []))
    if response.get("blocked"):
        for reason in response.get("block_reasons", []):
            recommendations.append(f"Blocked by enterprise policy: {reason}")

    confidence = sum(confidences) / len(confidences) if confidences else 1.0
    return VetReport(
        package=PackageIdentifier(
            ecosystem="pypi",
            name=response.get("package_name", "unknown"),
            version=response.get("package_version", "unknown"),
        ),
        overall_risk=_coerce_risk_level(response.get("risk_level", "unknown")),
        risk_score=float(response.get("risk_score", 0.0)),
        confidence=confidence,
        results=results,
        recommendations=recommendations,
    )
