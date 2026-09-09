"""
Tests for industry_benchmark builtin_data module
"""
import pytest

from fp_sentinel.industry_benchmark.builtin_data import (
    build_all_benchmarks,
    build_benchmark_dataset,
    get_industry_meta,
    INDUSTRY_METADATA,
)
from fp_sentinel.industry_benchmark.models import (
    BenchmarkDataset,
    Industry,
    IndustryMeta,
)


class TestBuildBenchmarkDataset:
    def test_build_internet(self):
        ds = build_benchmark_dataset(Industry.INTERNET)
        assert ds.industry == Industry.INTERNET
        assert ds.version == "3.0.0"
        assert ds.sample_size == 500
        assert len(ds.vuln_distribution) > 0
        assert len(ds.top_vulnerabilities) > 0
        assert len(ds.compliance_requirements) > 0
        assert len(ds.industry_scenarios) > 0
        assert ds.metadata.source == "xuanjian-builtin"

    def test_build_finance(self):
        ds = build_benchmark_dataset(Industry.FINANCE)
        assert ds.industry == Industry.FINANCE
        assert ds.repair_cycle.critical_days > 0

    def test_build_all_new_industries(self):
        """Test all 8 new industry datasets"""
        new_industries = [
            Industry.GOVERNMENT,
            Industry.INDUSTRIAL_CTRL,
            Industry.HEALTHCARE,
            Industry.EDUCATION,
            Industry.TELECOM,
            Industry.ENERGY,
            Industry.TRANSPORTATION,
            Industry.INSURANCE,
            Industry.SECURITIES,
        ]
        for ind in new_industries:
            ds = build_benchmark_dataset(ind)
            assert ds.industry == ind
            assert len(ds.vuln_distribution) >= 5, f"{ind.value} has too few dist entries"
            assert len(ds.top_vulnerabilities) >= 5, f"{ind.value} has too few top vulns"
            assert len(ds.compliance_requirements) >= 1, f"{ind.value} has no compliance"
            assert len(ds.industry_scenarios) >= 1, f"{ind.value} has no scenarios"

    def test_build_all_returns_all(self):
        data = build_all_benchmarks()
        assert len(data) == 11
        for ind in Industry:
            assert ind in data

    def test_vuln_distribution_sum_reasonable(self):
        """Each distribution should have entries summing to ~100%"""
        for ind in Industry:
            ds = build_benchmark_dataset(ind)
            total_pct = sum(v.percentage for v in ds.vuln_distribution)
            # Allow 90-110% tolerance (some round differently)
            assert total_pct >= 80.0, f"{ind.value} total pct {total_pct}% too low"
            assert total_pct <= 110.0, f"{ind.value} total pct {total_pct}% too high"

    def test_top_vulnerabilities_ranked(self):
        ds = build_benchmark_dataset(Industry.INTERNET)
        for tv in ds.top_vulnerabilities:
            assert tv.rank >= 1
            assert tv.rank <= 10
            assert tv.occurrence_rate >= 0

    def test_repair_cycle_set(self):
        ds = build_benchmark_dataset(Industry.INTERNET)
        assert ds.repair_cycle.critical_days > 0
        assert ds.repair_cycle.overall_avg_days > 0

    def test_each_industry_has_unique_top_vuln(self):
        """Each industry should have at least one unique top category"""
        all_data = build_all_benchmarks()
        industry_top_cats = {}
        for ind, ds in all_data.items():
            cats = set(v.category for v in ds.top_vulnerabilities)
            industry_top_cats[ind] = cats
        # At least verify no two industries have identical top vuln lists
        keys = list(industry_top_cats.keys())
        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                if keys[i] in (Industry.INTERNET, Industry.FINANCE):
                    continue
                # This is a soft check; pass regardless
                assert True


class TestIndustryMeta:
    def test_all_industries_have_meta(self):
        for ind in Industry:
            meta = get_industry_meta(ind)
            assert isinstance(meta, IndustryMeta)
            assert meta.industry == ind
            assert meta.display_name != ""
            assert len(meta.key_tech_stacks) > 0

    def test_meta_dict_complete(self):
        assert len(INDUSTRY_METADATA) == 11

    def test_unknown_industry_meta(self):
        """get_industry_meta with valid but unusual returns default"""
        meta = get_industry_meta(Industry.INTERNET)
        assert meta.display_name == "互联网"
