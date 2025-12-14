"""CVSS v3.1 scoring calculator"""

import re
from typing import Any

from provchain.data.models import CVSSScore, RiskLevel


class CVSSCalculator:
    """CVSS v3.1 score calculator"""

    # Base score metrics and their values
    ATTACK_VECTOR = {
        "N": 0.85,  # Network
        "A": 0.62,  # Adjacent Network
        "L": 0.55,  # Local
        "P": 0.20,  # Physical
    }

    ATTACK_COMPLEXITY = {
        "L": 0.77,  # Low
        "H": 0.44,  # High
    }

    PRIVILEGES_REQUIRED = {
        "N": 0.85,  # None
        "L": 0.62,  # Low
        "H": 0.27,  # High
    }

    PRIVILEGES_REQUIRED_SCOPE_CHANGED = {
        "N": 0.85,
        "L": 0.68,
        "H": 0.50,
    }

    USER_INTERACTION = {
        "N": 0.85,  # None
        "R": 0.62,  # Required
    }

    SCOPE = {
        "U": 1.0,  # Unchanged
        "C": 1.0,  # Changed (multiplier, not direct value)
    }

    IMPACT = {
        "N": 0.0,  # None
        "L": 0.22,  # Low
        "H": 0.56,  # High
    }

    # Temporal score metrics
    EXPLOIT_CODE_MATURITY = {
        "X": 1.0,  # Not Defined
        "U": 0.91,  # Unproven
        "P": 0.94,  # Proof-of-Concept
        "F": 0.97,  # Functional
        "H": 1.0,  # High
    }

    REMEDIATION_LEVEL = {
        "X": 1.0,  # Not Defined
        "O": 0.95,  # Official Fix
        "T": 0.96,  # Temporary Fix
        "W": 0.97,  # Workaround
        "U": 1.0,  # Unavailable
    }

    REPORT_CONFIDENCE = {
        "X": 1.0,  # Not Defined
        "U": 0.92,  # Unknown
        "R": 0.96,  # Reasonable
        "C": 1.0,  # Confirmed
    }

    @staticmethod
    def parse_vector(vector_string: str) -> dict[str, str]:
        """Parse CVSS vector string into metrics dictionary

        Args:
            vector_string: CVSS vector (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

        Returns:
            Dictionary of metric:value pairs
        """
        metrics = {}
        # Remove CVSS version prefix if present
        vector = vector_string.split("/")
        for component in vector:
            if ":" in component:
                key, value = component.split(":")
                metrics[key] = value
        return metrics

    @staticmethod
    def calculate_base_score(metrics: dict[str, str]) -> float:
        """Calculate CVSS v3.1 base score

        Args:
            metrics: Dictionary of CVSS metrics

        Returns:
            Base score (0.0 to 10.0)
        """
        # Extract metrics
        av = metrics.get("AV", "N")
        ac = metrics.get("AC", "L")
        pr = metrics.get("PR", "N")
        ui = metrics.get("UI", "N")
        s = metrics.get("S", "U")
        c = metrics.get("C", "N")
        i = metrics.get("I", "N")
        a = metrics.get("A", "N")

        # Get base values
        attack_vector = CVSSCalculator.ATTACK_VECTOR.get(av, 0.85)
        attack_complexity = CVSSCalculator.ATTACK_COMPLEXITY.get(ac, 0.77)
        user_interaction = CVSSCalculator.USER_INTERACTION.get(ui, 0.85)

        # Privileges required depends on scope
        if s == "C":  # Changed
            privileges_required = CVSSCalculator.PRIVILEGES_REQUIRED_SCOPE_CHANGED.get(pr, 0.85)
        else:  # Unchanged
            privileges_required = CVSSCalculator.PRIVILEGES_REQUIRED.get(pr, 0.85)

        # Impact values
        impact_conf = CVSSCalculator.IMPACT.get(c, 0.0)
        impact_integrity = CVSSCalculator.IMPACT.get(i, 0.0)
        impact_avail = CVSSCalculator.IMPACT.get(a, 0.0)

        # Calculate Impact Sub Score (ISS)
        iss = 1 - ((1 - impact_conf) * (1 - impact_integrity) * (1 - impact_avail))

        # Calculate Impact
        if s == "C":  # Changed scope
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:  # Unchanged scope
            impact = 6.42 * iss

        # Calculate Exploitability
        exploitability = 8.22 * attack_vector * attack_complexity * privileges_required * user_interaction

        # Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        elif s == "C":  # Changed scope
            base_score = min(1.08 * (impact + exploitability), 10.0)
        else:  # Unchanged scope
            base_score = min(impact + exploitability, 10.0)

        return round(base_score, 1)

    @staticmethod
    def calculate_temporal_score(base_score: float, metrics: dict[str, str]) -> float:
        """Calculate CVSS v3.1 temporal score

        Args:
            base_score: Base score
            metrics: Dictionary of CVSS metrics including temporal

        Returns:
            Temporal score (0.0 to 10.0)
        """
        e = metrics.get("E", "X")
        rl = metrics.get("RL", "X")
        rc = metrics.get("RC", "X")

        exploit_maturity = CVSSCalculator.EXPLOIT_CODE_MATURITY.get(e, 1.0)
        remediation_level = CVSSCalculator.REMEDIATION_LEVEL.get(rl, 1.0)
        report_confidence = CVSSCalculator.REPORT_CONFIDENCE.get(rc, 1.0)

        temporal_score = base_score * exploit_maturity * remediation_level * report_confidence
        return round(temporal_score, 1)

    @staticmethod
    def calculate_environmental_score(
        base_score: float, temporal_score: float | None, metrics: dict[str, str]
    ) -> float:
        """Calculate CVSS v3.1 environmental score

        Args:
            base_score: Base score
            temporal_score: Temporal score (if available)
            metrics: Dictionary of CVSS metrics including environmental

        Returns:
            Environmental score (0.0 to 10.0)
        """
        # Simplified environmental score calculation
        # Full implementation would consider modified base metrics
        if temporal_score is not None:
            return temporal_score
        return base_score

    @staticmethod
    def score_to_severity(score: float) -> RiskLevel:
        """Convert CVSS score to RiskLevel

        Args:
            score: CVSS score (0.0 to 10.0)

        Returns:
            RiskLevel enum value
        """
        if score >= 9.0:
            return RiskLevel.CRITICAL
        elif score >= 7.0:
            return RiskLevel.HIGH
        elif score >= 4.0:
            return RiskLevel.MEDIUM
        elif score > 0.0:
            return RiskLevel.LOW
        else:
            return RiskLevel.UNKNOWN

    @staticmethod
    def calculate_cvss_score(vector_string: str) -> CVSSScore:
        """Calculate complete CVSS score from vector string

        Args:
            vector_string: CVSS vector string

        Returns:
            CVSSScore model instance
        """
        metrics = CVSSCalculator.parse_vector(vector_string)

        base_score = CVSSCalculator.calculate_base_score(metrics)
        temporal_score = None
        environmental_score = None

        # Calculate temporal if temporal metrics present
        if any(key in metrics for key in ["E", "RL", "RC"]):
            temporal_score = CVSSCalculator.calculate_temporal_score(base_score, metrics)

        # Calculate environmental if environmental metrics present
        if any(key.startswith("M") for key in metrics.keys()):
            environmental_score = CVSSCalculator.calculate_environmental_score(
                base_score, temporal_score, metrics
            )

        severity = CVSSCalculator.score_to_severity(base_score)

        return CVSSScore(
            vector=vector_string,
            base_score=base_score,
            temporal_score=temporal_score,
            environmental_score=environmental_score,
            severity=severity,
            attack_vector=metrics.get("AV"),
            attack_complexity=metrics.get("AC"),
            privileges_required=metrics.get("PR"),
            user_interaction=metrics.get("UI"),
            scope=metrics.get("S"),
            confidentiality_impact=metrics.get("C"),
            integrity_impact=metrics.get("I"),
            availability_impact=metrics.get("A"),
        )

    @staticmethod
    def extract_cvss_from_vulnerability(vuln_data: dict[str, Any]) -> str | None:
        """Extract CVSS vector from vulnerability data

        Args:
            vuln_data: Vulnerability data from OSV or other source

        Returns:
            CVSS vector string or None if not found
        """
        # Check database_specific field
        if "database_specific" in vuln_data:
            db_specific = vuln_data["database_specific"]
            if "cvss_score" in db_specific:
                return db_specific["cvss_score"]
            if "cvss_vector" in db_specific:
                return db_specific["cvss_vector"]

        # Check severities field
        if "severity" in vuln_data:
            for severity in vuln_data["severity"]:
                if "score" in severity and "CVSS:3.1" in severity.get("type", ""):
                    return severity.get("score", "")

        # Check references for CVSS links
        if "references" in vuln_data:
            for ref in vuln_data["references"]:
                url = ref.get("url", "")
                if "cvss" in url.lower():
                    # Try to extract from URL or fetch
                    pass

        return None

