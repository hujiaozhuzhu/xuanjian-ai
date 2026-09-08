"""
Tests for industry_benchmark models
"""
import pytest
from pydantic import ValidationError

from fp_sentinel.industry_benchmark.models import (
    BenchmarkDataset,
    BenchmarkMetadata,
    CategoryGap,
    ComplianceRequirement,
    CrossIndustryComparison,
    CrossIndustryReport,
    EnterpriseMetrics,
    GapAnalysisReport,
    GapItem,
    GapSeverity,
    Industry,
    IndustryMeta,
    IndustryRule,
    IndustryRuleSet,
    IndustryScenario,
    RepairCycle,
    RepairSuggestion,
    TopVulnerability,
    UpdatePolicy,
    UpdateRecord,
    UpdateSource,
    VulnTypeStats,
)


class TestIndustry:
    def test_all_industries_defined(self):
        assert len(Industry) == 11

    def test_enum_from_value(self):
        assert Industry("internet") == Industry.INTERNET
        with pytest.raises(ValueError):
            Industry("nonexistent")


class TestVulnTypeStats:
    def test_create(self):
        stats = VulnTypeStats(category="INJECTION", cwe="CWE-89", display_name="SQL", count=100, percentage=15.0)
        assert stats.count == 100
        assert stats.avg_severity == "MEDIUM"
        assert stats.trend == "stable"

    def test_extra_forbidden(self):
        with pytest.raises(ValidationError):
            VulnTypeStats(category="X", display_name="X", unknown_field="bad")

    def test_percentage_bounds(self):
        with pytest.raises(ValidationError):
            VulnTypeStats(category="X", display_name="X", percentage=101)


class TestRepairCycle:
    def test_defaults(self):
        rc = RepairCycle()
        assert rc.critical_days == 0.0

    def test_create(self):
        rc = RepairCycle(critical_days=3.0, high_days=7.0, medium_days=20.0, low_days=45.0, overall_avg_days=15.0)
        assert rc.critical_days == 3.0

    def test_days_non_negative(self):
        with pytest.raises(ValidationError):
            RepairCycle(critical_days=-1)


class TestTopVulnerability:
    def test_create(self):
        tv = TopVulnerability(rank=1, rule_id="SQL_INJ", category="INJECTION", cwe="CWE-89", display_name="SQL", occurrence_rate=10.0, severity="CRITICAL")
        assert tv.rank == 1
        assert tv.compliance_refs == []

    def test_rank_bounds(self):
        with pytest.raises(ValidationError):
            TopVulnerability(rank=0, rule_id="X", category="X", display_name="X")


class TestComplianceRequirement:
    def test_create(self):
        cr = ComplianceRequirement(ref_id="GB/T", standard="LP", section="8.1", description="Test")
        assert cr.mandatory is True
        assert cr.related_cwes == []


class TestIndustryScenario:
    def test_create(self):
        sc = IndustryScenario(scenario_id="SC-001", title="Test", description="Testing")
        assert sc.risk_level == "HIGH"
        assert sc.mitigations == []

    def test_full(self):
        sc = IndustryScenario(scenario_id="SC-002", title="Full", description="Full", related_categories=["INJECTION"], risk_level="CRITICAL", mitigations=["A", "B"])
        assert len(sc.mitigations) == 2


class TestBenchmarkMetadata:
    def test_create(self):
        bm = BenchmarkMetadata()
        assert bm.source == "xuanjian-builtin"
        assert bm.confidence == 0.95


class TestBenchmarkDataset:
    def test_get_vuln_category_map(self):
        ds = BenchmarkDataset(industry=Industry.INTERNET, metadata=BenchmarkMetadata(), vuln_distribution=[VulnTypeStats(category="A", display_name="A"), VulnTypeStats(category="B", display_name="B")])
        cmap = ds.get_vuln_category_map()
        assert "A" in cmap

    def test_get_top_n(self):
        ds = BenchmarkDataset(industry=Industry.INTERNET, metadata=BenchmarkMetadata(), top_vulnerabilities=[TopVulnerability(rank=3, rule_id="C", category="C", display_name="C"), TopVulnerability(rank=1, rule_id="A", category="A", display_name="A"), TopVulnerability(rank=2, rule_id="B", category="B", display_name="B")])
        top = ds.get_top_n(2)
        assert len(top) == 2
        assert top[0].rank == 1


class TestEnterpriseMetrics:
    def test_create(self):
        em = EnterpriseMetrics(industry=Industry.INTERNET)
        assert em.total_findings == 0

    def test_full(self):
        em = EnterpriseMetrics(project_name="P", industry=Industry.FINANCE, total_findings=100, avg_repair_days=7.5, scan_count=3, compliance_score=85.0)
        assert em.compliance_score == 85.0


class TestGapModels:
    def test_gap_item(self):
        gi = GapItem(category="density", industry_avg=100, enterprise_value=150, gap_ratio=0.5, severity=GapSeverity.HIGH)
        assert gi.severity == GapSeverity.HIGH

    def test_category_gap_defaults(self):
        cg = CategoryGap(category_name="test")
        assert cg.overall_severity == GapSeverity.ON_PAR
        assert cg.score == 50.0

    def test_gap_report(self):
        report = GapAnalysisReport(report_id="test", industry=Industry.INTERNET, overall_score=75.0)
        assert report.critical_gaps == []

    def test_gap_report_with_critical(self):
        report = GapAnalysisReport(report_id="t2", industry=Industry.INTERNET, category_gaps=[CategoryGap(category_name="test", items=[GapItem(category="x", industry_avg=1, enterprise_value=2, gap_ratio=1.0, severity=GapSeverity.CRITICAL)])])
        assert len(report.critical_gaps) == 1


class TestRepairSuggestion:
    def test_create(self):
        rs = RepairSuggestion(suggestion_id="S-001", title="Fix", target_categories=["INJECTION"])
        assert rs.priority == 5
        assert rs.effort == "medium"


class TestUpdateModels:
    def test_source(self):
        src = UpdateSource(source_id="test", name="Test")
        assert src.enabled is True

    def test_record(self):
        rec = UpdateRecord(record_id="R1", source_id="S1", industry=Industry.INTERNET)
        assert rec.success is True

    def test_policy(self):
        pol = UpdatePolicy()
        assert pol.auto_update is False
        assert pol.retention_days == 180


class TestIndustryMeta:
    def test_create(self):
        meta = IndustryMeta(industry=Industry.INTERNET, display_name="Internet", description="Test", key_tech_stacks=["Java"], risk_profile="Hi")
        assert meta.display_name == "Internet"

    def test_extra_forbidden(self):
        with pytest.raises(ValidationError):
            IndustryMeta(industry=Industry.INTERNET, display_name="X", unknown="bad")


class TestIndustryRuleModels:
    def test_rule(self):
        rule = IndustryRule(rule_id="R-001", industry=Industry.INTERNET, name="Test", category="INJECTION", pattern="p")
        assert rule.enabled is True

    def test_ruleset(self):
        rs = IndustryRuleSet(industry=Industry.INTERNET, rules=[
            IndustryRule(rule_id="R1", industry=Industry.INTERNET, name="R1", category="X"),
            IndustryRule(rule_id="R2", industry=Industry.INTERNET, name="R2", category="Y", enabled=False),
        ])
        assert len(rs.rules) == 2
        assert len(rs.enabled_rules) == 1
