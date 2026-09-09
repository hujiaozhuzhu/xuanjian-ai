"""
Tests for repair_advisor, industry_rules, comparison, updater
"""
import pytest

from fp_sentinel.industry_benchmark.repair_advisor import (
    RepairAdvisor,
    suggest_repairs_for_findings,
)
from fp_sentinel.industry_benchmark.industry_rules import (
    IndustryRuleEngine,
    get_industry_rule_set,
    list_industry_rules,
)
from fp_sentinel.industry_benchmark.comparison import (
    CrossIndustryAnalyzer,
    generate_cross_industry_report,
)
from fp_sentinel.industry_benchmark.updater import (
    BenchmarkUpdater,
    create_default_policy,
    create_aggressive_policy,
)
from fp_sentinel.industry_benchmark.models import Industry


class TestRepairAdvisor:
    def test_suggest_for_injection(self):
        advisor = RepairAdvisor()
        sugs = advisor.suggest_for_finding("INJECTION", "CRITICAL", "CWE-89", Industry.FINANCE)
        assert len(sugs) > 0

    def test_suggest_for_xss(self):
        advisor = RepairAdvisor()
        sugs = advisor.suggest_for_finding("XSS", "MEDIUM", "CWE-79", Industry.INTERNET)
        assert len(sugs) > 0

    def test_suggest_prioritized(self):
        advisor = RepairAdvisor()
        sugs = advisor.suggest_for_finding("INJECTION", "CRITICAL")
        if len(sugs) > 1:
            for i in range(len(sugs) - 1):
                assert sugs[i].priority <= sugs[i + 1].priority

    def test_suggest_for_industry(self):
        advisor = RepairAdvisor()
        sugs = advisor.suggest_for_industry(Industry.SECURITIES)
        assert len(sugs) > 0

    def test_suggest_for_each_new_industry(self):
        advisor = RepairAdvisor()
        new_inds = [Industry.GOVERNMENT, Industry.INDUSTRIAL_CTRL, Industry.HEALTHCARE,
                    Industry.EDUCATION, Industry.TELECOM, Industry.ENERGY,
                    Industry.TRANSPORTATION, Industry.INSURANCE, Industry.SECURITIES]
        for ind in new_inds:
            sugs = advisor.suggest_for_industry(ind)
            assert len(sugs) > 0, f"{ind.value} returned no suggestions"

    def test_suggest_for_scenarios(self):
        advisor = RepairAdvisor()
        scenario_sugs = advisor.suggest_for_scenarios(Industry.INTERNET)
        assert isinstance(scenario_sugs, dict)

    def test_suggest_repairs_for_findings_empty(self):
        sugs = suggest_repairs_for_findings([], Industry.INTERNET)
        assert len(sugs) == 0

    def test_suggest_repairs_for_findings(self):
        findings = [("INJECTION", "CRITICAL", "CWE-89"), ("XSS", "HIGH", "CWE-79")]
        sugs = suggest_repairs_for_findings(findings, Industry.INTERNET)
        assert len(sugs) > 0

    def test_set_benchmark(self):
        from fp_sentinel.industry_benchmark.builtin_data import build_benchmark_dataset
        advisor = RepairAdvisor()
        bench = build_benchmark_dataset(Industry.FINANCE)
        advisor.set_benchmark(bench)
        assert advisor._benchmark is not None


class TestIndustryRules:
    def test_get_rule_set_internet(self):
        rs = get_industry_rule_set(Industry.INTERNET)
        assert len(rs.rules) > 0
        assert rs.industry == Industry.INTERNET

    def test_get_rule_set_finance(self):
        rs = get_industry_rule_set(Industry.FINANCE)
        assert len(rs.rules) >= 4

    def test_get_rule_set_all_industries(self):
        engine = IndustryRuleEngine()
        for ind in Industry:
            rs = engine.get_rule_set(ind)
            assert len(rs.rules) >= 1, f"{ind.value} has no rules"

    def test_list_industry_rules(self):
        rules = list_industry_rules(Industry.INTERNET)
        assert len(rules) > 0

    def test_list_industry_rules_all(self):
        for ind in Industry:
            rules = list_industry_rules(ind)
            assert len(rules) >= 1, f"{ind.value} no rules"

    def test_engine_add_rule(self):
        from fp_sentinel.industry_benchmark.models import IndustryRule
        engine = IndustryRuleEngine()
        new_rule = IndustryRule(rule_id="CUSTOM-001", industry=Industry.INTERNET, name="Custom", category="X", pattern="p")
        engine.add_rule(Industry.INTERNET, new_rule)
        rs = engine.get_rule_set(Industry.INTERNET)
        assert any(r.rule_id == "CUSTOM-001" for r in rs.rules)

    def test_engine_enable_disable_rule(self):
        engine = IndustryRuleEngine()
        result = engine.enable_rule(Industry.INTERNET, "INET-API-AUTH-001", enabled=False)
        assert result is True
        rules = engine.get_rule_set(Industry.INTERNET).enabled_rules
        assert all(r.rule_id != "INET-API-AUTH-001" for r in rules)

    def test_enable_nonexistent_rule(self):
        engine = IndustryRuleEngine()
        result = engine.enable_rule(Industry.INTERNET, "NONEXISTENT", True)
        assert result is False

    def test_get_rules_for_tech(self):
        engine = IndustryRuleEngine()
        rules = engine.get_rules_for_tech(Industry.INTERNET, "Java")
        assert len(rules) > 0

    def test_count_rules(self):
        engine = IndustryRuleEngine()
        total = engine.count_rules()
        assert total > 10

    def test_rules_have_compliance_refs(self):
        engine = IndustryRuleEngine()
        has_compliance = False
        for ind in Industry:
            rules = engine.get_rule_set(ind).rules
            for r in rules:
                if r.compliance_refs:
                    has_compliance = True
                    break
        assert has_compliance


class TestCrossIndustry:
    def test_compare_dimension(self):
        analyzer = CrossIndustryAnalyzer()
        comp = analyzer.compare_dimension("avg_repair_days")
        assert len(comp.values) > 0
        assert "internet" in comp.values

    def test_compare_critical_ratio(self):
        analyzer = CrossIndustryAnalyzer()
        comp = analyzer.compare_dimension("critical_ratio")
        assert len(comp.values) > 0

    def test_compare_all_dimensions(self):
        analyzer = CrossIndustryAnalyzer()
        comps = analyzer.compare_all_dimensions()
        assert len(comps) >= 4

    def test_generate_report(self):
        analyzer = CrossIndustryAnalyzer()
        report = analyzer.generate_report()
        assert len(report.comparisons) > 0
        assert report.report_id.startswith("cross-")

    def test_generate_for_subset(self):
        analyzer = CrossIndustryAnalyzer()
        report = analyzer.generate_report(industries=[Industry.INTERNET, Industry.FINANCE])
        assert len(report.comparisons) > 0

    def test_generate_cross_industry_report(self):
        report = generate_cross_industry_report()
        assert len(report.comparisons) > 0

    def test_report_has_rankings(self):
        report = generate_cross_industry_report()
        assert len(report.industry_rankings) > 0

    def test_report_has_summary(self):
        report = generate_cross_industry_report()
        assert report.summary != ""


class TestUpdater:
    def test_default_policy(self):
        pol = create_default_policy()
        assert pol.auto_update is False
        assert pol.retention_days == 180

    def test_aggressive_policy(self):
        pol = create_aggressive_policy()
        assert pol.auto_update is True
        assert pol.interval_days == 7

    def test_import_builtin(self):
        updater = BenchmarkUpdater()
        rec = updater.import_builtin_data(Industry.INTERNET)
        assert rec.success is True
        assert rec.industry == Industry.INTERNET

    def test_import_all_builtin(self):
        updater = BenchmarkUpdater()
        records = updater.import_all_builtin()
        assert len(records) == 11

    def test_refresh_industry_no_external(self):
        """Without enabled sources, refresh falls back to builtin"""
        updater = BenchmarkUpdater()
        rec = updater.refresh_industry(Industry.GOVERNMENT)
        assert rec.success is True

    def test_refresh_with_external_source(self):
        from fp_sentinel.industry_benchmark.models import UpdateSource, UpdatePolicy
        pol = UpdatePolicy(auto_update=True, sources=[UpdateSource(source_id="ext1", name="External", enabled=True)])
        updater = BenchmarkUpdater(policy=pol)
        rec = updater.refresh_industry(Industry.INTERNET)
        # Should fail (external not implemented, S1)
        assert rec.success is False

    def test_policy_setter(self):
        updater = BenchmarkUpdater()
        new_pol = create_aggressive_policy()
        updater.policy = new_pol
        assert updater.policy.auto_update is True

    def test_cleanup_no_store(self):
        updater = BenchmarkUpdater()
        deleted = updater.cleanup_old_records()
        assert deleted == 0
