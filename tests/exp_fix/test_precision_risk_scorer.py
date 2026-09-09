"""
Tests for fp_sentinel.analysis.precision_risk_scorer module.
Target: >= 95% code coverage.
"""

import pytest
from unittest.mock import MagicMock

from fp_sentinel.analysis.chain_scorer import ChainRiskScorer, AssetContext
from fp_sentinel.analysis.precision_risk_scorer import (
    PrecisionRiskScorer,
    PrecisionRiskScore,
    BusinessCriticality,
    INDUSTRY_RISK_PROFILE,
    score_with_industry,
    prioritize_by_business_impact,
)
from fp_sentinel.devops.collaboration_hub import (
    SLAPolicy,
)


def _make_finding(rule_id="java-sql-injection", severity="HIGH", file_path="src/UserController.java", category="SQL_INJECTION"):
    """Create a mock Finding."""
    f = MagicMock()
    f.rule_id = rule_id
    f.severity = severity
    f.file_path = file_path
    f.category = category
    f.cvss = None
    return f


# ─────────────────────── BusinessCriticality Tests ───────────────────────

class TestBusinessCriticality:
    def test_default_score(self):
        biz = BusinessCriticality()
        score = biz.to_score()
        assert 0 <= score <= 1

    def test_revenue_related_boost(self):
        biz = BusinessCriticality(is_revenue_related=True)
        score = biz.to_score()
        assert score >= 0.3

    def test_user_facing_boost(self):
        biz = BusinessCriticality(is_user_facing=True)
        score = biz.to_score()
        assert score >= 0.2

    def test_compliance_required_boost(self):
        biz = BusinessCriticality(is_compliance_required=True)
        score = biz.to_score()
        assert score >= 0.15

    def test_user_count_scaling(self):
        biz_low = BusinessCriticality(user_impact_count=10)
        biz_high = BusinessCriticality(user_impact_count=10000000)
        assert biz_high.to_score() > biz_low.to_score()

    def test_sla_level_critical(self):
        biz = BusinessCriticality(sla_level="platinum")
        score = biz.to_score()
        assert score >= 0.1

    def test_sla_level_standard(self):
        biz = BusinessCriticality(sla_level="standard")
        score = biz.to_score()
        assert 0 <= score <= 1

    def test_data_classification_restricted(self):
        biz = BusinessCriticality(data_classification="restricted")
        score = biz.to_score()
        assert score >= 0.1

    def test_max_score(self):
        biz = BusinessCriticality(
            is_revenue_related=True,
            is_user_facing=True,
            is_compliance_required=True,
            user_impact_count=100000000,
            sla_level="platinum",
            data_classification="restricted",
        )
        score = biz.to_score()
        assert score <= 1.0
        assert score > 0.8

    def test_min_score(self):
        biz = BusinessCriticality(
            is_revenue_related=False,
            is_user_facing=False,
            is_compliance_required=False,
            user_impact_count=0,
            sla_level="basic",
            data_classification="public",
        )
        score = biz.to_score()
        assert score >= 0

    def test_score_is_rounded(self):
        biz = BusinessCriticality()
        score = biz.to_score()
        # Should be rounded to 4 decimal places
        assert score == round(score, 4)


# ─────────────────────── Industry Profile Tests ───────────────────────

class TestIndustryRiskProfile:
    def test_all_industries_present(self):
        expected = [
            "finance", "healthcare", "government", "internet",
            "industrial_ctrl", "energy", "telecom", "education",
            "transportation", "insurance", "securities",
        ]
        for ind in expected:
            assert ind in INDUSTRY_RISK_PROFILE

    def test_finance_has_highest_cvss_mult(self):
        fin_mult = INDUSTRY_RISK_PROFILE["finance"]["cvss_multiplier"]
        int_mult = INDUSTRY_RISK_PROFILE["internet"]["cvss_multiplier"]
        assert fin_mult >= int_mult

    def test_industrial_ctrl_has_high_multiplier(self):
        ics_mult = INDUSTRY_RISK_PROFILE["industrial_ctrl"]["cvss_multiplier"]
        assert ics_mult >= 1.1

    def test_education_has_lowest_multiplier(self):
        edu_mult = INDUSTRY_RISK_PROFILE["education"]["cvss_multiplier"]
        assert edu_mult <= 1.0

    def test_all_profiles_have_required_fields(self):
        required = ["cvss_multiplier", "business_weight", "compliance_weight",
                     "data_sensitivity_default", "critical_categories", "industry_factor"]
        for ind, profile in INDUSTRY_RISK_PROFILE.items():
            for field in required:
                assert field in profile, f"{ind} missing {field}"

    def test_critical_categories_nonempty(self):
        for ind, profile in INDUSTRY_RISK_PROFILE.items():
            assert len(profile["critical_categories"]) > 0


# ─────────────────────── PrecisionRiskScorer Tests ───────────────────────

class TestPrecisionRiskScorer:
    def test_init_default(self):
        scorer = PrecisionRiskScorer()
        assert scorer.industry == "internet"

    def test_init_finance(self):
        scorer = PrecisionRiskScorer(industry="finance")
        assert scorer.industry == "finance"

    def test_score_single_finding(self):
        finding = _make_finding(severity="CRITICAL")
        scorer = PrecisionRiskScorer(industry="internet")
        result = scorer.score_finding(finding)
        assert isinstance(result, PrecisionRiskScore)
        assert result.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

    def test_cvss_adjusted_with_multiplier(self):
        finding = _make_finding(severity="HIGH")
        base_scorer = PrecisionRiskScorer(industry="internet")
        fin_scorer = PrecisionRiskScorer(industry="finance")
        base_result = base_scorer.score_finding(finding)
        fin_result = fin_scorer.score_finding(finding)
        # Finance should have higher adjusted CVSS due to multiplier
        assert fin_result.cvss_adjusted >= base_result.cvss_adjusted

    def test_finance_category_boost(self):
        """SQL injection in finance should get category boost."""
        finding = _make_finding(rule_id="java-sql-injection", severity="HIGH")
        fin_scorer = PrecisionRiskScorer(industry="finance")
        result = fin_scorer.score_finding(finding)
        assert result.category_boost > 0

    def test_non_critical_category_no_boost(self):
        """Non-critical category shouldn't get boost."""
        finding = _make_finding(rule_id="debug-mode", severity="LOW", category="")
        fin_scorer = PrecisionRiskScorer(industry="finance")
        result = fin_scorer.score_finding(finding)
        # DEBUG_MODE not in finance critical_categories
        assert result.category_boost == 0

    def test_business_criticality_impact(self):
        finding = _make_finding(severity="HIGH")
        biz = BusinessCriticality(
            is_revenue_related=True,
            user_impact_count=1000000,
            sla_level="platinum",
        )
        scorer = PrecisionRiskScorer(industry="finance", business_criticality=biz)
        result = scorer.score_finding(finding)
        assert result.business_score > 0.3

    def test_score_findings_sorting(self):
        f1 = _make_finding(rule_id="java-sql-injection", severity="CRITICAL")
        f2 = _make_finding(rule_id="debug-mode-info", severity="LOW")
        scorer = PrecisionRiskScorer(industry="internet")
        results = scorer.score_findings([f1, f2])
        # Critical finding should be first (highest score)
        assert results[0].final_score >= results[-1].final_score

    def test_score_findings_with_ranking(self):
        findings = [
            _make_finding(severity="CRITICAL"),
            _make_finding(severity="HIGH"),
            _make_finding(severity="MEDIUM"),
        ]
        scorer = PrecisionRiskScorer(industry="internet")
        results = scorer.score_findings(findings)
        for i, r in enumerate(results):
            assert r.priority_rank == i + 1

    def test_sort_findings_by_risk(self):
        f1 = _make_finding(severity="CRITICAL")
        f2 = _make_finding(severity="LOW")
        scorer = PrecisionRiskScorer(industry="internet")
        pairs = scorer.sort_findings_by_risk([f1, f2])
        # Should return (finding, score) pairs
        assert len(pairs) == 2
        assert pairs[0][1].final_score >= pairs[1][1].final_score

    def test_severity_thresholds(self):
        scorer = PrecisionRiskScorer()
        assert scorer._score_to_severity(9.5) == "CRITICAL"
        assert scorer._score_to_severity(7.5) == "HIGH"
        assert scorer._score_to_severity(5.0) == "MEDIUM"
        assert scorer._score_to_severity(2.0) == "LOW"
        assert scorer._score_to_severity(0.5) == "INFO"

    def test_urgency_mapping(self):
        scorer = PrecisionRiskScorer()
        assert scorer._score_to_urgency(9.0, "CRITICAL") == "immediate"
        assert scorer._score_to_urgency(7.5, "HIGH") == "urgent"
        assert scorer._score_to_urgency(5.0, "MEDIUM") == "planned"
        assert scorer._score_to_urgency(2.0, "LOW") == "deferred"
        assert scorer._score_to_urgency(0.5, "INFO") == "track"

    def test_explicit_cvss_used(self):
        finding = _make_finding()
        finding.cvss = 8.5
        scorer = PrecisionRiskScorer(industry="internet")
        result = scorer.score_finding(finding)
        assert result.cvss_base == 8.5

    def test_invalid_cvss_ignored(self):
        finding = _make_finding(severity="HIGH")
        finding.cvss = "invalid"
        scorer = PrecisionRiskScorer(industry="internet")
        result = scorer.score_finding(finding)
        # Should fall back to severity-based CVSS
        assert result.cvss_base > 0

    def test_final_score_in_range(self):
        finding = _make_finding(severity="CRITICAL")
        for industry in INDUSTRY_RISK_PROFILE:
            scorer = PrecisionRiskScorer(industry=industry)
            result = scorer.score_finding(finding)
            assert 0 <= result.final_score <= 10

    def test_details_populated(self):
        finding = _make_finding()
        scorer = PrecisionRiskScorer(industry="finance")
        result = scorer.score_finding(finding)
        assert "industry" in result.details
        assert "profile" in result.details

    def test_temporal_adjustment_default(self):
        finding = _make_finding()
        scorer = PrecisionRiskScorer(industry="internet")
        result = scorer.score_finding(finding)
        assert result.temporal_adjustment == 1.0

    def test_asset_context_from_business(self):
        biz = BusinessCriticality(
            user_impact_count=50000,
            is_compliance_required=True,
        )
        scorer = PrecisionRiskScorer(industry="finance", business_criticality=biz)
        ctx = scorer._build_asset_context()
        assert ctx.user_count == 50000
        assert ctx.data_sensitivity == INDUSTRY_RISK_PROFILE["finance"]["data_sensitivity_default"]


# ─────────────────────── Convenience Function Tests ───────────────────────

class TestConvenienceFunctions:
    def test_score_with_industry(self):
        findings = [_make_finding(severity="CRITICAL")]
        results = score_with_industry(findings, industry="finance")
        assert len(results) > 0
        assert results[0].severity in ("CRITICAL", "HIGH")

    def test_score_with_industry_empty(self):
        results = score_with_industry([])
        assert results == []

    def test_prioritize_by_business_impact(self):
        findings = [
            _make_finding(severity="CRITICAL"),
            _make_finding(severity="LOW"),
        ]
        pairs = prioritize_by_business_impact(findings, industry="internet")
        assert len(pairs) == 2
        # Check format: (finding, score, severity)
        for item in pairs:
            assert len(item) == 3

    def test_prioritize_sorted(self):
        findings = [
            _make_finding(severity="CRITICAL"),
            _make_finding(severity="MEDIUM"),
            _make_finding(severity="LOW"),
        ]
        pairs = prioritize_by_business_impact(findings, industry="finance")
        scores = [p[1] for p in pairs]
        assert scores == sorted(scores, reverse=True)


# ─────────────────────── SLAPolicy Tests ───────────────────────

class TestSLAPolicy:
    def test_default_policy(self):
        policy = SLAPolicy()
        assert policy.critical_hours == 4.0
        assert policy.high_hours == 24.0
        assert policy.medium_hours == 72.0
        assert policy.low_hours == 168.0
        assert policy.escalation_threshold == 0.8

    def test_custom_policy(self):
        policy = SLAPolicy(critical_hours=2.0, escalation_threshold=0.75)
        assert policy.critical_hours == 2.0
        assert policy.escalation_threshold == 0.75


# ─────────────────────── Edge Cases ───────────────────────

class TestEdgeCases:
    def test_unknown_industry_defaults_to_internet(self):
        scorer = PrecisionRiskScorer(industry="unknown_industry_xyz")
        finding = _make_finding()
        result = scorer.score_finding(finding)
        assert result.final_score >= 0

    def test_empty_rule_id(self):
        finding = _make_finding(rule_id="")
        scorer = PrecisionRiskScorer(industry="internet")
        result = scorer.score_finding(finding)
        assert isinstance(result, PrecisionRiskScore)

    def test_none_severity_fallback(self):
        finding = MagicMock()
        finding.rule_id = "test"
        finding.severity = None
        finding.file_path = "test.java"
        finding.category = None
        finding.cvss = None
        scorer = PrecisionRiskScorer(industry="internet")
        result = scorer.score_finding(finding)
        assert result.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

    def test_cvss_out_of_range(self):
        finding = MagicMock()
        finding.rule_id = "test"
        finding.severity = "HIGH"
        finding.file_path = "test.java"
        finding.category = None
        finding.cvss = 15.0  # Out of range
        scorer = PrecisionRiskScorer(industry="internet")
        result = scorer.score_finding(finding)
        # Should fall back to severity-based
        assert result.cvss_base == ChainRiskScorer.DEFAULT_CVSS["HIGH"]
