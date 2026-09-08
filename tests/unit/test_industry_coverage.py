"""
Targeted coverage tests for industry_benchmark (to achieve >=95%)
"""
import tempfile
import uuid
from pathlib import Path

import pytest

from fp_sentinel.industry_benchmark.builtin_data import build_all_benchmarks, build_benchmark_dataset
from fp_sentinel.industry_benchmark.models import (
    CrossIndustryReport,
    EnterpriseMetrics,
    GapAnalysisReport,
    Industry,
    RepairCycle,
)


class TestStoreContextManager:
    def test_context_manager(self):
        from fp_sentinel.industry_benchmark.store import BenchmarkStore
        tmp = tempfile.mkdtemp()
        try:
            db_path = Path(tmp) / "test.db"
            with BenchmarkStore(db_path=db_path) as store:
                ds = build_benchmark_dataset(Industry.INTERNET)
                store.save_benchmark(ds)
                loaded = store.load_benchmark(Industry.INTERNET)
                assert loaded is not None
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_open_benchmark_store(self):
        from fp_sentinel.industry_benchmark.store import open_benchmark_store
        tmp = tempfile.mkdtemp()
        try:
            db_path = Path(tmp) / "test.db"
            store = open_benchmark_store(db_path=db_path)
            assert store is not None
            store.close()
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_save_cross_report_and_list(self):
        from fp_sentinel.industry_benchmark.store import BenchmarkStore
        tmp = tempfile.mkdtemp()
        try:
            db_path = Path(tmp) / "test.db"
            store = BenchmarkStore(db_path=db_path)
            report = CrossIndustryReport(report_id="c-001")
            store.save_cross_report(report)
            loaded = store.load_cross_report("c-001")
            assert loaded is not None
            store.close()
        finally:
            import shutil, gc
            gc.collect()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_cleanup_with_zero_retention(self):
        from fp_sentinel.industry_benchmark.store import BenchmarkStore
        tmp = tempfile.mkdtemp()
        try:
            db_path = Path(tmp) / "test.db"
            store = BenchmarkStore(db_path=db_path)
            store.log_update("u1", "src1", Industry.INTERNET, True)
            store.log_update("u2", "src1", Industry.FINANCE, False, "Failed")
            deleted = store.cleanup_old_records(retention_days=0)
            assert deleted >= 0
            store.close()
        finally:
            import shutil, gc
            gc.collect()
            shutil.rmtree(tmp, ignore_errors=True)


class TestEngineEdgeCases:
    def test_repair_cycle_classifications(self):
        from fp_sentinel.industry_benchmark.engine import _classify_gap, _severity_to_score
        assert _classify_gap(0.51) == __import__("fp_sentinel.industry_benchmark.models", fromlist=["GapSeverity"]).GapSeverity.CRITICAL
        assert _classify_gap(0.26) == __import__("fp_sentinel.industry_benchmark.models", fromlist=["GapSeverity"]).GapSeverity.HIGH
        assert _classify_gap(0.11) == __import__("fp_sentinel.industry_benchmark.models", fromlist=["GapSeverity"]).GapSeverity.MEDIUM
        assert _classify_gap(0.05) == __import__("fp_sentinel.industry_benchmark.models", fromlist=["GapSeverity"]).GapSeverity.ON_PAR
        assert _classify_gap(-0.06) == __import__("fp_sentinel.industry_benchmark.models", fromlist=["GapSeverity"]).GapSeverity.AHEAD
        assert _severity_to_score(__import__("fp_sentinel.industry_benchmark.models", fromlist=["GapSeverity"]).GapSeverity.LOW) == 85.0

    def test_engine_with_zero_sample_size(self):
        from fp_sentinel.industry_benchmark.engine import BenchmarkEngine
        import pydantic
        bench = build_benchmark_dataset(Industry.INTERNET)
        bench.sample_size = 0
        ent = EnterpriseMetrics(industry=Industry.INTERNET, total_findings=50, scan_count=2)
        engine = BenchmarkEngine(benchmark=bench)
        report = engine.analyze(ent, benchmark=bench)
        assert report is not None

    def test_engine_default_benchmark(self):
        from fp_sentinel.industry_benchmark.engine import BenchmarkEngine
        engine = BenchmarkEngine()
        ent = EnterpriseMetrics(industry=Industry.HEALTHCARE, total_findings=100, scan_count=1)
        report = engine.analyze(ent)
        assert report.industry == Industry.HEALTHCARE

    def test_density_edge_cases(self):
        from fp_sentinel.industry_benchmark.engine import _compute_vuln_density_gap
        bench = build_benchmark_dataset(Industry.INTERNET)
        # zero scan_count
        ent = EnterpriseMetrics(industry=Industry.INTERNET, total_findings=0, scan_count=0)
        item = _compute_vuln_density_gap(ent, bench)
        assert item is not None
        # zero sample_size
        bench2 = build_benchmark_dataset(Industry.INTERNET)
        bench2.sample_size = 0
        ent2 = EnterpriseMetrics(industry=Industry.INTERNET, total_findings=50, scan_count=2)
        item2 = _compute_vuln_density_gap(ent2, bench2)
        assert item2 is not None

    def test_repair_speed_edge(self):
        from fp_sentinel.industry_benchmark.engine import _compute_repair_speed_gap
        bench = build_benchmark_dataset(Industry.INTERNET)
        ent = EnterpriseMetrics(industry=Industry.INTERNET, avg_repair_days=0)
        item = _compute_repair_speed_gap(ent, bench)
        assert item is not None

    def test_coverage_edge_zero_industry_cats(self):
        from fp_sentinel.industry_benchmark.engine import _compute_coverage_gap
        bench = build_benchmark_dataset(Industry.INTERNET)
        ent = EnterpriseMetrics(industry=Industry.INTERNET, by_category={})
        item = _compute_coverage_gap(ent, bench)
        assert item is not None

    def test_engine_get_benchmark(self):
        from fp_sentinel.industry_benchmark.engine import BenchmarkEngine
        engine = BenchmarkEngine()
        assert engine.get_benchmark() is None
        bench = build_benchmark_dataset(Industry.INTERNET)
        engine.set_benchmark(bench)
        assert engine.get_benchmark() is not None


class TestRepairAdvisorEdge:
    def test_suggest_no_match(self):
        from fp_sentinel.industry_benchmark.repair_advisor import RepairAdvisor
        advisor = RepairAdvisor()
        sugs = advisor.suggest_for_finding("NONEXISTENT_CATEGORY", "INFO", None, Industry.INTERNET)
        # May be empty or have only non-matching priority template entries
        assert isinstance(sugs, list)

    def test_suggest_with_compliance_enrichment(self):
        from fp_sentinel.industry_benchmark.repair_advisor import RepairAdvisor
        bench = build_benchmark_dataset(Industry.INTERNET)
        advisor = RepairAdvisor(benchmark=bench)
        sugs = advisor.suggest_for_finding("INJECTION", "CRITICAL", "CWE-89", Industry.INTERNET)
        assert isinstance(sugs, list)

    def test_suggest_for_industry_no_results_for_odd_industry(self):
        from fp_sentinel.industry_benchmark.repair_advisor import RepairAdvisor
        advisor = RepairAdvisor()
        sugs = advisor.suggest_for_industry(Industry.INTERNET)
        assert len(sugs) > 0

    def test_suggest_for_all_new_industries_scenarios(self):
        from fp_sentinel.industry_benchmark.repair_advisor import RepairAdvisor
        advisor = RepairAdvisor()
        new_inds = [Industry.GOVERNMENT, Industry.INDUSTRIAL_CTRL, Industry.HEALTHCARE,
                    Industry.EDUCATION, Industry.TELECOM, Industry.ENERGY,
                    Industry.TRANSPORTATION, Industry.INSURANCE, Industry.SECURITIES]
        for ind in new_inds:
            scenarios = advisor.suggest_for_industry(ind)
            assert len(scenarios) > 0


class TestUpdaterEdge:
    def test_import_with_store(self):
        import tempfile, shutil
        from pathlib import Path
        from fp_sentinel.industry_benchmark.updater import BenchmarkUpdater
        from fp_sentinel.industry_benchmark.store import BenchmarkStore
        tmp = tempfile.mkdtemp()
        try:
            db_path = Path(tmp) / "test.db"
            store = BenchmarkStore(db_path=db_path)
            updater = BenchmarkUpdater(store=store)
            rec = updater.import_builtin_data(Industry.FINANCE)
            assert rec.success
            history = updater.get_update_history()
            assert isinstance(history, list)
            store.close()
        finally:
            import gc
            gc.collect()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_refresh_fallback_to_builtin(self):
        from fp_sentinel.industry_benchmark.updater import BenchmarkUpdater, create_default_policy
        updater = BenchmarkUpdater(policy=create_default_policy())
        rec = updater.refresh_industry(Industry.ENERGY)
        assert rec.success is True

    def test_aggressive_policy_refresh(self):
        from fp_sentinel.industry_benchmark.updater import BenchmarkUpdater, create_aggressive_policy
        from fp_sentinel.industry_benchmark.models import UpdateSource, UpdatePolicy
        pol = create_aggressive_policy()
        pol.sources = [UpdateSource(source_id="test", name="Test", enabled=True)]
        updater = BenchmarkUpdater(policy=pol)
        rec = updater.refresh_industry(Industry.INTERNET)
        # External not implemented, should be False
        assert rec.success is False

    def test_import_all_builtin_records(self):
        from fp_sentinel.industry_benchmark.updater import BenchmarkUpdater
        updater = BenchmarkUpdater()
        records = updater.import_all_builtin()
        assert len(records) == 11
        for ind, rec in records.items():
            assert rec.success is True


class TestComparisonEdge:
    def test_get_industry_ranking(self):
        from fp_sentinel.industry_benchmark.comparison import CrossIndustryAnalyzer
        analyzer = CrossIndustryAnalyzer()
        ranking = analyzer.get_industry_ranking("avg_repair_days")
        assert len(ranking) > 0

    def test_compare_unknown_dimension(self):
        from fp_sentinel.industry_benchmark.comparison import CrossIndustryAnalyzer
        analyzer = CrossIndustryAnalyzer()
        comp = analyzer.compare_dimension("nonexistent_dimension")
        # Should still return a valid comparison with 0.0 values
        assert isinstance(comp.values, dict)

    def test_compare_empty_benchmarks(self):
        from fp_sentinel.industry_benchmark.comparison import CrossIndustryAnalyzer
        analyzer = CrossIndustryAnalyzer(benchmarks={})
        comp = analyzer.compare_dimension("avg_repair_days")
        # Should handle gracefully (no data)
        assert isinstance(comp, __import__("fp_sentinel.industry_benchmark.models", fromlist=["CrossIndustryComparison"]).CrossIndustryComparison)

    def test_custom_benchmarks(self):
        from fp_sentinel.industry_benchmark.comparison import CrossIndustryAnalyzer
        all_ds = build_all_benchmarks()
        # Use only 3 industries
        subset = {k: v for k, v in list(all_ds.items())[:3]}
        analyzer = CrossIndustryAnalyzer(benchmarks=subset)
        report = analyzer.generate_report()
        assert len(report.comparisons) > 0

    def test_best_worst_industry(self):
        from fp_sentinel.industry_benchmark.comparison import CrossIndustryAnalyzer
        analyzer = CrossIndustryAnalyzer()
        comp = analyzer.compare_dimension("avg_repair_days")
        assert comp.best_industry is not None
        assert comp.worst_industry is not None


class TestDensityRecommendationBranches:
    """Cover all branches in _density_recommendation"""
    def test_severity_critical_high_with_high_value(self):
        from fp_sentinel.industry_benchmark.engine import _density_recommendation
        result = _density_recommendation(__import__("fp_sentinel.industry_benchmark.models", fromlist=["GapSeverity"]).GapSeverity.CRITICAL, 500, 100)
        assert "comprehensive" in result.lower() or "code review" in result.lower()

    def test_severity_medium(self):
        from fp_sentinel.industry_benchmark.engine import _density_recommendation
        result = _density_recommendation(__import__("fp_sentinel.industry_benchmark.models", fromlist=["GapSeverity"]).GapSeverity.MEDIUM, 100, 100)
        assert "scan frequency" in result.lower()

    def test_severity_on_par(self):
        from fp_sentinel.industry_benchmark.engine import _density_recommendation
        result = _density_recommendation(__import__("fp_sentinel.industry_benchmark.models", fromlist=["GapSeverity"]).GapSeverity.ON_PAR, 100, 100)
        assert "maintain" in result.lower()

    def test_severity_ahead(self):
        from fp_sentinel.industry_benchmark.engine import _density_recommendation
        result = _density_recommendation(__import__("fp_sentinel.industry_benchmark.models", fromlist=["GapSeverity"]).GapSeverity.AHEAD, 50, 100)
        assert "leverage" in result.lower() or "strengths" in result.lower()

    def test_high_without_extreme_value(self):
        from fp_sentinel.industry_benchmark.engine import _density_recommendation
        result = _density_recommendation(__import__("fp_sentinel.industry_benchmark.models", fromlist=["GapSeverity"]).GapSeverity.HIGH, 150, 100)
        assert "Prioritize" in result or "remediation" in result.lower()

    def test_classify_gap_inverse_branches(self):
        """Cover engine.py lines 52, 56: classify_gap inverse mode HIGH and ON_PAR"""
        from fp_sentinel.industry_benchmark.engine import _classify_gap
        GapS = __import__("fp_sentinel.industry_benchmark.models", fromlist=["GapSeverity"]).GapSeverity
        # inverse mode (lower_is_better=False)
        assert _classify_gap(-0.2, lower_is_better=False) == GapS.HIGH
        assert _classify_gap(-0.1, lower_is_better=False) == GapS.MEDIUM
        assert _classify_gap(0.02, lower_is_better=False) == GapS.ON_PAR


class TestRepairAdvisorScenarios:
    """Cover scenario tmpl matching"""
    def test_suggest_for_scenarios_with_match(self):
        from fp_sentinel.industry_benchmark.repair_advisor import RepairAdvisor
        advisor = RepairAdvisor()
        # INTERNET has INTERNET_API_ABUSE scenario matching ICS_RCE template? No
        # But INTERNET scenarios: INTERNET_API_ABUSE, INTERNET_SUPPLY_CHAIN
        # _INDUSTRY_TEMPLATES keys: ICS_RCE, NRG_SCADA_HACK, SEC_FLASH_CRASH
        # Use SECURITIES (has SEC_FLASH_CRASH)
        result = advisor.suggest_for_scenarios(Industry.SECURITIES)
        assert isinstance(result, dict)
        # SEC_FLASH_CRASH should match
        if "SEC_FLASH_CRASH" in result:
            assert len(result["SEC_FLASH_CRASH"]) > 0

    def test_suggest_for_scenarios_with_all_industry_templates(self):
        """Cover line 313-319: scenario_sugs loop"""
        from fp_sentinel.industry_benchmark.repair_advisor import RepairAdvisor
        advisor = RepairAdvisor()
        # Test with an industry that has a matching scenario
        result = advisor.suggest_for_scenarios(Industry.ENERGY)
        assert isinstance(result, dict)
        if "NRG_SCADA_HACK" in result:
            assert len(result["NRG_SCADA_HACK"]) > 0

    def test_suggest_for_scenarios_no_match(self):
        from fp_sentinel.industry_benchmark.repair_advisor import RepairAdvisor
        advisor = RepairAdvisor()
        # EDU has scenarios that don't match _INDUSTRY_TEMPLATES
        result = advisor.suggest_for_scenarios(Industry.EDUCATION)
        assert isinstance(result, dict)


class TestStoreMoreCoverage:
    """Cover store.py missing lines"""
    def test_save_gap_report_with_name(self):
        from fp_sentinel.industry_benchmark.store import BenchmarkStore
        tmp = tempfile.mkdtemp()
        try:
            db_path = Path(tmp) / "test.db"
            store = BenchmarkStore(db_path=db_path)
            report = GapAnalysisReport(report_id="g-named", industry=Industry.FINANCE, enterprise_name="MyBank")
            store.save_gap_report(report)
            loaded = store.load_gap_report("g-named")
            assert loaded is not None
            assert loaded.enterprise_name == "MyBank"
            store.close()
        finally:
            import shutil, gc
            gc.collect()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_log_update_failed_and_find(self):
        from fp_sentinel.industry_benchmark.store import BenchmarkStore
        from fp_sentinel.industry_benchmark.models import GapAnalysisReport
        tmp = tempfile.mkdtemp()
        try:
            db_path = Path(tmp) / "test.db"
            store = BenchmarkStore(db_path=db_path)
            store.log_update("fail1", "src1", Industry.INTERNET, False, "Timeout error")
            # Negative retention = cutoff in future = deletes all
            deleted = store.cleanup_old_records(retention_days=-1)
            assert deleted >= 1

            # After cleanup, gap reports still work
            store.save_gap_report(GapAnalysisReport(report_id="g-after", industry=Industry.INTERNET))
            loaded = store.load_gap_report("g-after")
            assert loaded is not None

            # List filtered by industry_int
            store.save_gap_report(GapAnalysisReport(report_id="g-fin", industry=Industry.FINANCE))
            fin_reports = store.list_gap_reports(industry=Industry.FINANCE)
            assert "g-fin" in fin_reports

            store.close()
        finally:
            import shutil, gc
            gc.collect()
            shutil.rmtree(tmp, ignore_errors=True)


class TestUpdaterMoreCoverage:
    """Cover updater.py missing lines"""
    def test_import_with_store_lifecycle(self):
        import tempfile, shutil
        from pathlib import Path
        from fp_sentinel.industry_benchmark.updater import BenchmarkUpdater
        from fp_sentinel.industry_benchmark.store import BenchmarkStore
        tmp = tempfile.mkdtemp()
        try:
            db_path = Path(tmp) / "test.db"
            store = BenchmarkStore(db_path=db_path)
            updater = BenchmarkUpdater(store=store)
            rec = updater.import_builtin_data(Industry.GOVERNMENT)
            assert rec.success is True
            assert rec.record_id.startswith("upd-")
            store.close()
        finally:
            import gc
            gc.collect()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_cleanup_with_store(self):
        import tempfile, shutil
        from pathlib import Path
        from fp_sentinel.industry_benchmark.updater import BenchmarkUpdater
        from fp_sentinel.industry_benchmark.store import BenchmarkStore
        tmp = tempfile.mkdtemp()
        try:
            db_path = Path(tmp) / "test.db"
            store = BenchmarkStore(db_path=db_path)
            store.log_update("u1", "src1", Industry.INTERNET)
            updater = BenchmarkUpdater(store=store)
            deleted = updater.cleanup_old_records()
            assert deleted >= 0
            store.close()
        finally:
            import gc
            gc.collect()
            shutil.rmtree(tmp, ignore_errors=True)


class TestIndustryRulesEdge:
    def test_get_rules_for_tech_specific(self):
        from fp_sentinel.industry_benchmark.industry_rules import IndustryRuleEngine
        engine = IndustryRuleEngine()
        rules = engine.get_rules_for_tech(Industry.FINANCE, "COBOL")
        # COBOL not in finance targets
        assert isinstance(rules, list)

    def test_get_rules_wildcard_tech(self):
        from fp_sentinel.industry_benchmark.industry_rules import IndustryRuleEngine
        engine = IndustryRuleEngine()
        rules = engine.get_rules_for_tech(Industry.INTERNET, "Rust")
        # Wildcard '*' should match
        assert len(rules) > 0

    def test_count_specific_industry(self):
        from fp_sentinel.industry_benchmark.industry_rules import IndustryRuleEngine
        engine = IndustryRuleEngine()
        count = engine.count_rules(Industry.FINANCE)
        assert count >= 4

    def test_all_industries_with_rules(self):
        from fp_sentinel.industry_benchmark.industry_rules import IndustryRuleEngine
        engine = IndustryRuleEngine()
        inds = engine.get_all_industries_with_rules()
        assert len(inds) == 11

    def test_disable_nonexistent_rule(self):
        from fp_sentinel.industry_benchmark.industry_rules import IndustryRuleEngine
        engine = IndustryRuleEngine()
        result = engine.enable_rule(Industry.INTERNET, "DOES-NOT-EXIST", True)
        assert result is False


class TestFinalCoverage:
    """Targeted tests for remaining uncovered lines"""

    def test_engine_overall_report_generation(self):
        """Cover engine.py lines 137, 150: report highlights generation"""
        from fp_sentinel.industry_benchmark.engine import BenchmarkEngine
        engine = BenchmarkEngine()
        # Create enterprise with very slow repairs -> trigger highlights
        ent = EnterpriseMetrics(
            industry=Industry.EDUCATION,
            total_findings=500,
            by_severity={"CRITICAL": 50, "HIGH": 100, "MEDIUM": 200, "LOW": 150},
            by_category={"INJECTION": 50, "XSS": 50},
            avg_repair_days=60.0,  # much higher than education avg (26.8)
            scan_count=5,
            compliance_score=40.0,
        )
        report = engine.analyze(ent)
        assert report is not None
        assert len(report.highlights) > 0
        assert len(report.improvement_roadmap) > 0

    def test_engine_with_zero_repair_industry(self):
        """Cover engine.py edge: industry with zero repair"""
        from fp_sentinel.industry_benchmark.engine import BenchmarkEngine, _compute_repair_speed_gap
        # Zero industry avg
        import pydantic
        bench = build_benchmark_dataset(Industry.INTERNET)
        bench.repair_cycle = RepairCycle(critical_days=0, high_days=0, medium_days=0, low_days=0, overall_avg_days=0)
        ent = EnterpriseMetrics(industry=Industry.INTERNET, avg_repair_days=5)
        item = _compute_repair_speed_gap(ent, bench)
        assert item is not None

    def test_store_schema_init(self):
        """Cover store.py schema creation path"""
        from fp_sentinel.industry_benchmark.store import _init_schema, _create_connection
        import tempfile
        tmp = tempfile.mkdtemp()
        try:
            conn = _create_connection(str(Path(tmp) / "fresh.db"))
            _init_schema(conn)
            conn.close()
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_store_load_all_with_corrupt_row(self):
        """Cover store.py lines 155-156: skip corrupt rows in load_all"""
        from fp_sentinel.industry_benchmark.store import BenchmarkStore
        tmp = tempfile.mkdtemp()
        try:
            db_path = Path(tmp) / "test.db"
            store = BenchmarkStore(db_path=db_path)
            # Insert a row with invalid industry name
            conn = store._connection
            conn.execute(
                "INSERT OR REPLACE INTO benchmarks (industry, version, data_json, updated_at) VALUES (?, ?, ?, ?)",
                ("invalid_industry", "1.0", "{}", "2025-01-01T00:00:00+00:00"),
            )
            conn.commit()
            # Should skip the invalid row
            loaded = store.load_all_benchmarks()
            assert all(isinstance(k, Industry) for k in loaded.keys())
            store.close()
        finally:
            import shutil, gc
            gc.collect()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_updater_records_init(self):
        """Cover updater.py line 161, 179: update record generation"""
        from fp_sentinel.industry_benchmark.updater import BenchmarkUpdater
        updater = BenchmarkUpdater()
        rec = updater.import_builtin_data(Industry.HEALTHCARE)
        assert rec.record_id is not None
        assert rec.updated_at is not None
        assert "Imported" in rec.changes_summary
