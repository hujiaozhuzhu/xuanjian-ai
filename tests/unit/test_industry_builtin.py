"""
Consolidated tests for builtin_data, store, repair_advisor, industry_rules, comparison, updater
"""
import tempfile
from pathlib import Path

import pytest

from fp_sentinel.industry_benchmark.builtin_data import (
    build_all_benchmarks,
    build_benchmark_dataset,
    INDUSTRY_METADATA,
)
from fp_sentinel.industry_benchmark.models import Industry


class TestBuiltinDataSummary:
    """Verify all industries have complete data"""

    def test_each_industry_has_top_vulns(self):
        all_data = build_all_benchmarks()
        for ind, ds in all_data.items():
            assert len(ds.top_vulnerabilities) >= 5, f"{ind.value} top vulns too few"

    def test_each_industry_has_compliance(self):
        all_data = build_all_benchmarks()
        for ind, ds in all_data.items():
            assert len(ds.compliance_requirements) >= 1, f"{ind.value} no compliance"

    def test_each_industry_has_scenarios(self):
        all_data = build_all_benchmarks()
        for ind, ds in all_data.items():
            assert len(ds.industry_scenarios) >= 1, f"{ind.value} no scenarios"

    def test_each_industry_has_repair_cycle(self):
        all_data = build_all_benchmarks()
        for ind, ds in all_data.items():
            assert ds.repair_cycle.overall_avg_days > 0, f"{ind.value} no repair cycle"

    def test_each_industry_has_meta(self):
        for ind in Industry:
            assert ind in INDUSTRY_METADATA

    def test_scenarios_have_mitigations(self):
        all_data = build_all_benchmarks()
        for ind, ds in all_data.items():
            for sc in ds.industry_scenarios:
                assert len(sc.mitigations) >= 1, f"{ind.value}/{sc.scenario_id} no mitigations"

    def test_compliance_has_refs(self):
        all_data = build_all_benchmarks()
        for ind, ds in all_data.items():
            for cr in ds.compliance_requirements:
                assert cr.ref_id != "", f"{ind.value} compliance missing ref_id"


class TestStore:
    def test_temp_store(self):
        from fp_sentinel.industry_benchmark.store import BenchmarkStore
        tmp = tempfile.mkdtemp()
        try:
            db_path = Path(tmp) / "test.db"
            store = BenchmarkStore(db_path=db_path)
            ds = build_benchmark_dataset(Industry.INTERNET)
            store.save_benchmark(ds)
            loaded = store.load_benchmark(Industry.INTERNET)
            assert loaded is not None
            assert loaded.industry == Industry.INTERNET
        finally:
            import shutil, gc
            gc.collect()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_load_all(self):
        import shutil, gc
        from fp_sentinel.industry_benchmark.store import BenchmarkStore
        tmp = tempfile.mkdtemp()
        try:
            db_path = Path(tmp) / "test.db"
            store = BenchmarkStore(db_path=db_path)
            all_ds = build_all_benchmarks()
            for ind, ds in all_ds.items():
                store.save_benchmark(ds)
            loaded = store.load_all_benchmarks()
            assert len(loaded) == 11
            store.close()
        finally:
            gc.collect()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_list_industries(self):
        import shutil, gc
        from fp_sentinel.industry_benchmark.store import BenchmarkStore
        tmp = tempfile.mkdtemp()
        try:
            db_path = Path(tmp) / "test.db"
            store = BenchmarkStore(db_path=db_path)
            ds = build_benchmark_dataset(Industry.FINANCE)
            store.save_benchmark(ds)
            industries = store.list_stored_industries()
            assert Industry.FINANCE in industries
            store.close()
        finally:
            gc.collect()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_gap_report_save_load(self):
        import shutil, gc
        from fp_sentinel.industry_benchmark.store import BenchmarkStore
        from fp_sentinel.industry_benchmark.models import GapAnalysisReport
        tmp = tempfile.mkdtemp()
        try:
            db_path = Path(tmp) / "test.db"
            store = BenchmarkStore(db_path=db_path)
            report = GapAnalysisReport(report_id="g-test", industry=Industry.INTERNET, overall_score=80.0)
            store.save_gap_report(report)
            loaded = store.load_gap_report("g-test")
            assert loaded is not None
            assert loaded.overall_score == 80.0
            store.close()
        finally:
            gc.collect()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_gap_report_list(self):
        import shutil, gc
        from fp_sentinel.industry_benchmark.store import BenchmarkStore
        from fp_sentinel.industry_benchmark.models import GapAnalysisReport
        tmp = tempfile.mkdtemp()
        try:
            db_path = Path(tmp) / "test.db"
            store = BenchmarkStore(db_path=db_path)
            store.save_gap_report(GapAnalysisReport(report_id="g1", industry=Industry.INTERNET))
            store.save_gap_report(GapAnalysisReport(report_id="g2", industry=Industry.FINANCE))
            reports = store.list_gap_reports()
            assert "g1" in reports
            assert "g2" in reports
            store.close()
        finally:
            gc.collect()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_cross_report_save_load(self):
        import shutil, gc
        from fp_sentinel.industry_benchmark.store import BenchmarkStore
        from fp_sentinel.industry_benchmark.models import CrossIndustryReport
        tmp = tempfile.mkdtemp()
        try:
            db_path = Path(tmp) / "test.db"
            store = BenchmarkStore(db_path=db_path)
            report = CrossIndustryReport(report_id="c-test")
            store.save_cross_report(report)
            loaded = store.load_cross_report("c-test")
            assert loaded is not None
            store.close()
        finally:
            gc.collect()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_update_log(self):
        import shutil, gc
        from fp_sentinel.industry_benchmark.store import BenchmarkStore
        tmp = tempfile.mkdtemp()
        try:
            db_path = Path(tmp) / "test.db"
            store = BenchmarkStore(db_path=db_path)
            store.log_update("u1", "src1", Industry.INTERNET, True, "OK")
            store.close()
        finally:
            gc.collect()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_cleanup(self):
        import shutil, gc
        from fp_sentinel.industry_benchmark.store import BenchmarkStore
        tmp = tempfile.mkdtemp()
        try:
            db_path = Path(tmp) / "test.db"
            store = BenchmarkStore(db_path=db_path)
            store.log_update("u1", "src1", Industry.INTERNET, True, "OK")
            deleted = store.cleanup_old_records(retention_days=0)
            assert deleted >= 0
            store.close()
        finally:
            gc.collect()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_load_nonexistent_returns_none(self):
        import uuid
        from fp_sentinel.industry_benchmark.store import BenchmarkStore
        tmp = tempfile.mkdtemp()
        try:
            db_path = Path(tmp) / f"test_{uuid.uuid4().hex}.db"
            store = BenchmarkStore(db_path=db_path)
            assert store.load_benchmark(Industry.INTERNET) is None
            assert store.load_gap_report("nonexistent") is None
            assert store.load_cross_report("nonexistent") is None
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)
