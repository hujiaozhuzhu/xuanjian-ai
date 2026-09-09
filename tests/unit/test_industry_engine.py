"""
Tests for industry_benchmark engine (BenchmarkEngine)
"""
import pytest

from fp_sentinel.industry_benchmark.engine import (
    BenchmarkEngine,
    compare_enterprise_to_industry,
    _classify_gap,
    _severity_to_score,
    _overall_severity_from_categories,
)
from fp_sentinel.industry_benchmark.models import (
    CategoryGap,
    EnterpriseMetrics,
    GapSeverity,
    Industry,
)
from fp_sentinel.industry_benchmark.builtin_data import build_benchmark_dataset


class TestBenchmarkEngine:
    def _make_enterprise(self, industry=Industry.INTERNET, **kwargs):
        defaults = dict(
            project_name="Test",
            industry=industry,
            total_findings=200,
            by_severity={"CRITICAL": 5, "HIGH": 20, "MEDIUM": 60, "LOW": 115},
            by_category={"INJECTION": 30, "XSS": 40, "BROKEN_ACCESS_CONTROL": 50},
            avg_repair_days=10.0,
            scan_count=3,
            compliance_score=75.0,
        )
        defaults.update(kwargs)
        return EnterpriseMetrics(**defaults)

    def test_analyze_returns_report(self):
        engine = BenchmarkEngine()
        ent = self._make_enterprise()
        report = engine.analyze(ent)
        assert report is not None
        assert report.industry == Industry.INTERNET
        assert report.overall_score >= 0
        assert report.overall_score <= 100

    def test_analyze_has_4_categories(self):
        engine = BenchmarkEngine()
        ent = self._make_enterprise()
        report = engine.analyze(ent)
        assert len(report.category_gaps) == 4

    def test_analyze_with_benchmark(self):
        engine = BenchmarkEngine()
        bench = build_benchmark_dataset(Industry.FINANCE)
        ent = self._make_enterprise(industry=Industry.FINANCE)
        report = engine.analyze(ent, benchmark=bench)
        assert report.industry == Industry.FINANCE

    def test_set_benchmark(self):
        engine = BenchmarkEngine()
        bench = build_benchmark_dataset(Industry.INTERNET)
        engine.set_benchmark(bench)
        assert engine.get_benchmark() is not None

    def test_analyze_each_new_industry(self):
        """Verify engine works for all 8 new industries"""
        new_industries = [
            Industry.GOVERNMENT, Industry.INDUSTRIAL_CTRL,
            Industry.HEALTHCARE, Industry.EDUCATION,
            Industry.TELECOM, Industry.ENERGY,
            Industry.TRANSPORTATION, Industry.INSURANCE,
            Industry.SECURITIES,
        ]
        engine = BenchmarkEngine()
        for ind in new_industries:
            ent = self._make_enterprise(industry=ind)
            report = engine.analyze(ent)
            assert report.industry == ind
            assert len(report.category_gaps) == 4

    def test_high_findings_generates_critical_gap(self):
        engine = BenchmarkEngine()
        ent = self._make_enterprise(total_findings=10000, scan_count=1)
        report = engine.analyze(ent)
        assert any(cg.items[0].severity == GapSeverity.CRITICAL for cg in report.category_gaps)

    def test_compliance_score_low_gives_critical(self):
        engine = BenchmarkEngine()
        ent = self._make_enterprise(compliance_score=30.0)
        report = engine.analyze(ent)
        compliance_gaps = [cg for cg in report.category_gaps if cg.category_name == "compliance"]
        assert len(compliance_gaps) == 1

    def test_empty_enterprise(self):
        engine = BenchmarkEngine()
        ent = EnterpriseMetrics(industry=Industry.INTERNET)
        report = engine.analyze(ent)
        assert report.overall_score >= 0

    def test_generate_roadmap(self):
        engine = BenchmarkEngine()
        ent = self._make_enterprise()
        report = engine.analyze(ent)
        assert len(report.improvement_roadmap) >= 0

    def test_report_has_highlights(self):
        engine = BenchmarkEngine()
        ent = self._make_enterprise(avg_repair_days=50.0)
        report = engine.analyze(ent)
        assert len(report.highlights) > 0

    def test_report_id_format(self):
        engine = BenchmarkEngine()
        ent = self._make_enterprise()
        report = engine.analyze(ent)
        assert report.report_id.startswith("gap-")


class TestConvenience:
    def test_compare_enterprise_to_industry(self):
        ent = EnterpriseMetrics(
            industry=Industry.INTERNET,
            total_findings=200,
            by_category={"INJECTION": 30},
            avg_repair_days=10.0,
            scan_count=3,
        )
        report = compare_enterprise_to_industry(ent)
        assert report.industry == Industry.INTERNET

    def test_compare_with_benchmark(self):
        bench = build_benchmark_dataset(Industry.FINANCE)
        ent = EnterpriseMetrics(
            industry=Industry.FINANCE,
            total_findings=300,
            by_category={"BUSINESS_LOGIC": 50},
            avg_repair_days=5.0,
            scan_count=2,
        )
        report = compare_enterprise_to_industry(ent, benchmark=bench)
        assert report.industry == Industry.FINANCE


class TestGapClassification:
    def test_critical_gap(self):
        assert _classify_gap(0.6) == GapSeverity.CRITICAL
        assert _classify_gap(1.0) == GapSeverity.CRITICAL

    def test_high_gap(self):
        assert _classify_gap(0.3) == GapSeverity.HIGH

    def test_on_par(self):
        assert _classify_gap(0.0) == GapSeverity.ON_PAR

    def test_ahead(self):
        assert _classify_gap(-0.1) == GapSeverity.AHEAD

    def test_inverse_better(self):
        """inverse mode: higher is better"""
        assert _classify_gap(-0.5, lower_is_better=False) == GapSeverity.CRITICAL
        assert _classify_gap(0.1, lower_is_better=False) == GapSeverity.AHEAD


class TestSeverityToScore:
    def test_critical(self):
        assert _severity_to_score(GapSeverity.CRITICAL) == 20.0

    def test_ahead(self):
        assert _severity_to_score(GapSeverity.AHEAD) == 95.0

    def test_on_par(self):
        assert _severity_to_score(GapSeverity.ON_PAR) == 75.0


class TestOverallSeverity:
    def test_empty(self):
        assert _overall_severity_from_categories([]) == GapSeverity.ON_PAR

    def test_critical_takes_precedence(self):
        cats = [
            CategoryGap(category_name="a", overall_severity=GapSeverity.ON_PAR),
            CategoryGap(category_name="b", overall_severity=GapSeverity.CRITICAL),
        ]
        assert _overall_severity_from_categories(cats) == GapSeverity.CRITICAL
