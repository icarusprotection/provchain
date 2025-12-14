"""Tests for CVSS scoring"""

import pytest

from provchain.data.models import RiskLevel
from provchain.interrogator.cvss import CVSSCalculator


def test_parse_vector():
    """Test parsing CVSS vector string"""
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    metrics = CVSSCalculator.parse_vector(vector)

    assert metrics["AV"] == "N"
    assert metrics["AC"] == "L"
    assert metrics["PR"] == "N"
    assert metrics["UI"] == "N"
    assert metrics["S"] == "U"
    assert metrics["C"] == "H"
    assert metrics["I"] == "H"
    assert metrics["A"] == "H"


def test_calculate_base_score():
    """Test calculating CVSS base score"""
    # Critical vulnerability (Log4j-like)
    metrics = {
        "AV": "N",
        "AC": "L",
        "PR": "N",
        "UI": "N",
        "S": "U",
        "C": "H",
        "I": "H",
        "A": "H",
    }

    score = CVSSCalculator.calculate_base_score(metrics)
    assert score >= 9.0  # Should be critical
    assert score <= 10.0


def test_score_to_severity():
    """Test converting score to severity"""
    assert CVSSCalculator.score_to_severity(9.5) == RiskLevel.CRITICAL
    assert CVSSCalculator.score_to_severity(7.5) == RiskLevel.HIGH
    assert CVSSCalculator.score_to_severity(5.0) == RiskLevel.MEDIUM
    assert CVSSCalculator.score_to_severity(2.0) == RiskLevel.LOW
    assert CVSSCalculator.score_to_severity(0.0) == RiskLevel.UNKNOWN


def test_calculate_cvss_score():
    """Test complete CVSS score calculation"""
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    cvss_score = CVSSCalculator.calculate_cvss_score(vector)

    assert cvss_score.vector == vector
    assert cvss_score.base_score >= 9.0
    assert cvss_score.severity == RiskLevel.CRITICAL
    assert cvss_score.attack_vector == "N"
    assert cvss_score.confidentiality_impact == "H"

