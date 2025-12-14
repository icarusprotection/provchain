"""Tests for risk scorer"""

import pytest
from datetime import datetime, timezone

from provchain.interrogator.risk_scorer import RiskScorer, RiskScore
from provchain.data.models import AnalysisResult, Finding, RiskLevel, VetReport, PackageIdentifier


@pytest.fixture
def sample_analysis_result():
    """Sample analysis result for testing"""
    return AnalysisResult(
        analyzer="typosquat",
        risk_score=2.0,
        confidence=0.8,
        findings=[],
    )


@pytest.fixture
def sample_vet_report():
    """Sample vet report for testing"""
    return VetReport(
        package=PackageIdentifier(ecosystem="pypi", name="test-package", version="1.0.0"),
        overall_risk=RiskLevel.MEDIUM,
        risk_score=4.0,
        confidence=0.8,
        results=[],
        recommendations=[],
    )


class TestRiskScorer:
    """Test cases for RiskScorer"""

    def test_risk_scorer_init_default(self):
        """Test risk scorer initialization with default weights"""
        scorer = RiskScorer()
        assert scorer.weights == RiskScorer.DEFAULT_WEIGHTS

    def test_risk_scorer_init_custom_weights(self):
        """Test risk scorer initialization with custom weights"""
        custom_weights = {"typosquat": 5.0, "maintainer": 3.0}
        scorer = RiskScorer(weights=custom_weights)
        assert scorer.weights == custom_weights

    def test_calculate_with_critical_findings(self, sample_analysis_result):
        """Test calculate with critical findings - covers line 58"""
        scorer = RiskScorer()
        
        # Add critical finding
        critical_finding = Finding(
            id="critical_test",
            title="Critical Security Issue",
            description="A critical security vulnerability",
            severity=RiskLevel.CRITICAL,
        )
        sample_analysis_result.findings.append(critical_finding)
        
        result = scorer.calculate([sample_analysis_result])
        
        assert len(result.flags) > 0
        assert any("CRITICAL" in flag for flag in result.flags)
        assert any("Critical Security Issue" in flag for flag in result.flags)

    def test_calculate_with_empty_results(self):
        """Test calculate with empty results - covers line 65"""
        scorer = RiskScorer()
        
        result = scorer.calculate([])
        
        assert result.total == 0.0
        assert result.confidence == 0.0
        assert len(result.breakdown) == 0
        assert len(result.flags) == 0

    def test_get_risk_level_critical(self):
        """Test get_risk_level with critical score - covers line 80"""
        scorer = RiskScorer()
        
        assert scorer.get_risk_level(8.0) == RiskLevel.CRITICAL
        assert scorer.get_risk_level(9.0) == RiskLevel.CRITICAL
        assert scorer.get_risk_level(10.0) == RiskLevel.CRITICAL

    def test_get_risk_level_high(self):
        """Test get_risk_level with high score - covers line 82"""
        scorer = RiskScorer()
        
        assert scorer.get_risk_level(6.0) == RiskLevel.HIGH
        assert scorer.get_risk_level(7.9) == RiskLevel.HIGH
        # Just below critical
        assert scorer.get_risk_level(7.99) == RiskLevel.HIGH

    def test_get_risk_level_medium(self):
        """Test get_risk_level with medium score - covers line 84"""
        scorer = RiskScorer()
        
        assert scorer.get_risk_level(4.0) == RiskLevel.MEDIUM
        assert scorer.get_risk_level(5.9) == RiskLevel.MEDIUM
        # Just below high
        assert scorer.get_risk_level(5.99) == RiskLevel.MEDIUM

    def test_get_risk_level_low(self):
        """Test get_risk_level with low score - covers line 86"""
        scorer = RiskScorer()
        
        assert scorer.get_risk_level(2.0) == RiskLevel.LOW
        assert scorer.get_risk_level(3.9) == RiskLevel.LOW
        # Just below medium
        assert scorer.get_risk_level(3.99) == RiskLevel.LOW

    def test_get_risk_level_unknown(self):
        """Test get_risk_level with unknown score"""
        scorer = RiskScorer()
        
        assert scorer.get_risk_level(0.0) == RiskLevel.UNKNOWN
        assert scorer.get_risk_level(1.9) == RiskLevel.UNKNOWN

    def test_generate_recommendations_critical(self, sample_vet_report):
        """Test generate_recommendations with critical risk - covers line 95"""
        scorer = RiskScorer()
        sample_vet_report.overall_risk = RiskLevel.CRITICAL
        
        recommendations = scorer.generate_recommendations(sample_vet_report)
        
        assert len(recommendations) > 0
        assert any("DO NOT INSTALL" in rec for rec in recommendations)
        assert any("Critical security risks" in rec for rec in recommendations)

    def test_generate_recommendations_high(self, sample_vet_report):
        """Test generate_recommendations with high risk - covers lines 97-98"""
        scorer = RiskScorer()
        sample_vet_report.overall_risk = RiskLevel.HIGH
        
        recommendations = scorer.generate_recommendations(sample_vet_report)
        
        assert len(recommendations) >= 2
        assert any("Review all findings" in rec for rec in recommendations)
        assert any("alternative package" in rec for rec in recommendations)

    def test_generate_recommendations_medium(self, sample_vet_report):
        """Test generate_recommendations with medium risk - covers line 100"""
        scorer = RiskScorer()
        sample_vet_report.overall_risk = RiskLevel.MEDIUM
        
        recommendations = scorer.generate_recommendations(sample_vet_report)
        
        assert len(recommendations) > 0
        assert any("Review findings" in rec for rec in recommendations)
        assert any("verify package legitimacy" in rec for rec in recommendations)

    def test_generate_recommendations_low(self, sample_vet_report):
        """Test generate_recommendations with low risk"""
        scorer = RiskScorer()
        sample_vet_report.overall_risk = RiskLevel.LOW
        
        recommendations = scorer.generate_recommendations(sample_vet_report)
        
        assert len(recommendations) > 0
        assert any("appears safe" in rec for rec in recommendations)

    def test_generate_recommendations_with_findings(self, sample_vet_report):
        """Test generate_recommendations includes finding remediations"""
        scorer = RiskScorer()
        sample_vet_report.overall_risk = RiskLevel.MEDIUM
        
        # Add result with finding that has remediation
        finding = Finding(
            id="test_finding",
            title="Test Finding",
            description="A test finding",
            severity=RiskLevel.MEDIUM,
            remediation="Fix this issue",
        )
        result = AnalysisResult(
            analyzer="typosquat",
            risk_score=2.0,
            confidence=0.8,
            findings=[finding],
        )
        sample_vet_report.results = [result]
        
        recommendations = scorer.generate_recommendations(sample_vet_report)
        
        # Should include both general recommendation and specific remediation
        assert len(recommendations) >= 2
        assert any("typosquat: Fix this issue" in rec for rec in recommendations)

    def test_generate_recommendations_removes_duplicates(self, sample_vet_report):
        """Test generate_recommendations removes duplicate recommendations"""
        scorer = RiskScorer()
        sample_vet_report.overall_risk = RiskLevel.MEDIUM
        
        # Add multiple results with same remediation
        finding1 = Finding(
            id="finding1",
            title="Finding 1",
            description="First finding",
            severity=RiskLevel.MEDIUM,
            remediation="Same remediation",
        )
        finding2 = Finding(
            id="finding2",
            title="Finding 2",
            description="Second finding",
            severity=RiskLevel.MEDIUM,
            remediation="Same remediation",
        )
        result1 = AnalysisResult(
            analyzer="typosquat",
            risk_score=2.0,
            confidence=0.8,
            findings=[finding1],
        )
        result2 = AnalysisResult(
            analyzer="maintainer",
            risk_score=1.0,
            confidence=0.7,
            findings=[finding2],
        )
        sample_vet_report.results = [result1, result2]
        
        recommendations = scorer.generate_recommendations(sample_vet_report)
        
        # Should have unique recommendations (duplicates removed)
        assert len(recommendations) == len(set(recommendations))

    def test_calculate_multiple_results(self):
        """Test calculate with multiple analysis results"""
        scorer = RiskScorer()
        
        result1 = AnalysisResult(
            analyzer="typosquat",
            risk_score=2.0,
            confidence=0.8,
            findings=[],
        )
        result2 = AnalysisResult(
            analyzer="maintainer",
            risk_score=1.5,
            confidence=0.9,
            findings=[],
        )
        
        risk_score = scorer.calculate([result1, result2])
        
        assert risk_score.total > 0.0
        assert risk_score.confidence > 0.0
        assert len(risk_score.breakdown) == 2
        assert "typosquat" in risk_score.breakdown
        assert "maintainer" in risk_score.breakdown

    def test_calculate_score_capped_at_10(self):
        """Test that calculated score is capped at 10.0"""
        scorer = RiskScorer()
        
        # Create multiple results with high risk scores and high weights
        # to potentially exceed 10.0 after normalization
        result1 = AnalysisResult(
            analyzer="typosquat",
            risk_score=10.0,  # Maximum allowed
            confidence=1.0,
            findings=[],
        )
        result2 = AnalysisResult(
            analyzer="behavior",
            risk_score=10.0,  # Maximum allowed
            confidence=1.0,
            findings=[],
        )
        
        risk_score = scorer.calculate([result1, result2])
        
        # Should be capped at 10.0 (though normalization should keep it <= 10)
        assert risk_score.total <= 10.0

