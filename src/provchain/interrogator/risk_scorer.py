"""Risk scoring algorithm"""

from dataclasses import dataclass

from provchain.data.models import AnalysisResult, RiskLevel, VetReport


@dataclass
class RiskScore:
    """Risk score breakdown"""

    total: float  # 0.0 - 10.0
    confidence: float  # 0.0 - 1.0
    breakdown: dict[str, float]
    flags: list[str]


class RiskScorer:
    """Weighted scoring system with configurable thresholds"""

    DEFAULT_WEIGHTS = {
        "typosquat": 3.0,  # High impact
        "maintainer": 2.0,  # Medium-high impact
        "metadata": 1.0,  # Lower impact
        "install_hooks": 2.5,  # High impact
        "vulnerability": 3.0,  # High impact - known CVEs
        "attack": 2.5,  # High impact - attack pattern detection
        "behavior": 3.0,  # High impact
    }

    THRESHOLDS = {
        "low": 2.0,
        "medium": 4.0,
        "high": 6.0,
        "critical": 8.0,
    }

    def __init__(self, weights: dict[str, float] | None = None):
        self.weights = weights or self.DEFAULT_WEIGHTS.copy()

    def calculate(self, results: list[AnalysisResult]) -> RiskScore:
        """Calculate weighted risk score from analysis results"""
        breakdown: dict[str, float] = {}
        total_score = 0.0
        total_confidence = 0.0
        flags: list[str] = []

        for result in results:
            analyzer_name = result.analyzer
            weight = self.weights.get(analyzer_name, 1.0)
            weighted_score = result.risk_score * weight
            breakdown[analyzer_name] = weighted_score
            total_score += weighted_score
            total_confidence += result.confidence

            # Check for critical findings
            for finding in result.findings:
                if finding.severity == RiskLevel.CRITICAL:
                    flags.append(f"CRITICAL: {finding.title}")

        # Normalize: use the higher of the weighted average and the
        # highest single analyzer score.  The weighted average alone
        # would dilute a serious finding (e.g. 14 known CVEs) when
        # every other analyzer reports 0.
        total_weight = sum(self.weights.get(r.analyzer, 1.0) for r in results)
        if total_weight > 0:
            weighted_avg = total_score / total_weight
        else:
            weighted_avg = 0.0

        max_single = max((r.risk_score for r in results), default=0.0)
        normalized_score = max(weighted_avg, max_single)

        # Average confidence
        avg_confidence = total_confidence / len(results) if results else 0.0

        return RiskScore(
            total=min(normalized_score, 10.0),
            confidence=avg_confidence,
            breakdown=breakdown,
            flags=flags,
        )

    def get_risk_level(self, score: float) -> RiskLevel:
        """Convert numeric score to risk level"""
        if score >= self.THRESHOLDS["critical"]:
            return RiskLevel.CRITICAL
        elif score >= self.THRESHOLDS["high"]:
            return RiskLevel.HIGH
        elif score >= self.THRESHOLDS["medium"]:
            return RiskLevel.MEDIUM
        elif score >= self.THRESHOLDS["low"]:
            return RiskLevel.LOW
        else:
            return RiskLevel.UNKNOWN

    def generate_recommendations(self, report: VetReport) -> list[str]:
        """Generate recommendations based on report"""
        recommendations = []

        if report.overall_risk == RiskLevel.CRITICAL:
            recommendations.append("DO NOT INSTALL - Critical security risks detected")
        elif report.overall_risk == RiskLevel.HIGH:
            recommendations.append("Review all findings before installing")
            recommendations.append("Consider using an alternative package if available")
        elif report.overall_risk == RiskLevel.MEDIUM:
            recommendations.append("Review findings and verify package legitimacy")
        else:
            recommendations.append("Package appears safe, but review findings")

        # Add specific recommendations based on findings
        for result in report.results:
            for finding in result.findings:
                if finding.remediation:
                    recommendations.append(f"{result.analyzer}: {finding.remediation}")

        return list(set(recommendations))  # Remove duplicates
