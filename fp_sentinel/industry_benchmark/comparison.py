"""
玄鉴 v3.0 - Industry Benchmark :: Cross-Industry Comparison

Generates cross-industry security capability comparison reports.
"""
from __future__ import annotations

import uuid
from typing import Dict, List, Optional

from .models import (
    BenchmarkDataset,
    CrossIndustryComparison,
    CrossIndustryReport,
    Industry,
)
from .builtin_data import build_all_benchmarks


# Dimensions for cross-industry comparison
_COMPARISON_DIMENSIONS = {
    "avg_repair_days": "Average overall repair cycle (days)",
    "vuln_density": "Total vulnerability density",
    "critical_ratio": "Critical vulnerability ratio (%)",
    "top_category_pct": "Top category dominance (%)",
    "compliance_count": "Number of compliance requirements",
    "scenario_count": "Number of industry scenarios",
}


class CrossIndustryAnalyzer:
    """
    Cross-industry comparison analyzer.
    """

    def __init__(self, benchmarks: Optional[Dict[Industry, BenchmarkDataset]] = None) -> None:
        self._benchmarks = benchmarks

    def set_benchmarks(self, benchmarks: Dict[Industry, BenchmarkDataset]) -> None:
        """Set benchmarks for comparison"""
        self._benchmarks = benchmarks

    def _get_benchmarks(self):
        """Get benchmarks, using built-in data if not provided"""
        if self._benchmarks is not None:
            return self._benchmarks
        return build_all_benchmarks()

    def compare_dimension(self, dimension: str) -> CrossIndustryComparison:
        """
        Compare all industries along a single dimension.

        Args:
            dimension: Dimension key (must be in _COMPARISON_DIMENSIONS)

        Returns:
            CrossIndustryComparison result
        """
        from .models import BenchmarkDataset
        benchmarks: Dict[Industry, BenchmarkDataset] = self._get_benchmarks()
        values: Dict[str, float] = {}

        for ind, bench in benchmarks.items():
            if dimension == "avg_repair_days":
                values[ind.value] = bench.repair_cycle.overall_avg_days
            elif dimension == "vuln_density":
                values[ind.value] = float(sum(v.count for v in bench.vuln_distribution))
            elif dimension == "critical_ratio":
                total = sum(v.count for v in bench.vuln_distribution)
                critical = sum(v.count for v in bench.vuln_distribution if v.avg_severity == "CRITICAL")
                values[ind.value] = (critical / max(total, 1)) * 100.0
            elif dimension == "top_category_pct":
                if bench.vuln_distribution:
                    values[ind.value] = max(v.percentage for v in bench.vuln_distribution)
                else:
                    values[ind.value] = 0.0
            elif dimension == "compliance_count":
                values[ind.value] = float(len(bench.compliance_requirements))
            elif dimension == "scenario_count":
                values[ind.value] = float(len(bench.industry_scenarios))
            else:
                values[ind.value] = 0.0

        # Determine best/worst
        best_ind: Optional[Industry] = None
        worst_ind: Optional[Industry] = None

        if values:
            # For most dimensions, lower is better; except scenario_count (more = more mature)
            reverse_better = dimension in ("compliance_count", "scenario_count")
            sorted_items = sorted(values.items(), key=lambda x: x[1], reverse=reverse_better)
            if sorted_items:
                try:
                    best_ind = Industry(sorted_items[0][0])
                except ValueError:
                    pass
                try:
                    worst_ind = Industry(sorted_items[-1][0])
                except ValueError:
                    pass

        # Build analysis text
        analysis_parts: List[str] = []
        if values:
            sorted_asc = sorted(values.items(), key=lambda x: x[1])
            lowest_ind, lowest_val = sorted_asc[0]
            highest_ind, highest_val = sorted_asc[-1]
            if dimension in ("avg_repair_days", "vuln_density", "critical_ratio", "top_category_pct"):
                analysis_parts.append(f"Lowest {dimension}: {lowest_ind} ({lowest_val:.2f})")
                analysis_parts.append(f"Highest {dimension}: {highest_ind} ({highest_val:.2f})")
                if lowest_val > 0:
                    spread = (highest_val - lowest_val) / lowest_val
                    analysis_parts.append(f"Industry spread: {spread:.1%}")

        return CrossIndustryComparison(
            industries=list(benchmarks.keys()),
            dimension=dimension,
            values=values,
            best_industry=best_ind,
            worst_industry=worst_ind,
            analysis="; ".join(analysis_parts),
        )

    def compare_all_dimensions(self) -> List[CrossIndustryComparison]:
        """Run comparison across all standard dimensions"""
        return [self.compare_dimension(dim) for dim in _COMPARISON_DIMENSIONS]

    def generate_report(self, industries: Optional[List[Industry]] = None) -> CrossIndustryReport:
        """
        Generate full cross-industry comparison report.

        Args:
            industries: Optional list of industries to include (all if None)

        Returns:
            Full comparison report
        """
        benchmarks = self._get_benchmarks()
        if industries:
            selected = {k: v for k, v in benchmarks.items() if k in industries}
        else:
            selected = benchmarks

        comparisons = self.compare_all_dimensions()

        # Build industry rankings for each dimension
        rankings: Dict[str, List[Industry]] = {}
        for comp in comparisons:
            if comp.values:
                reverse = comp.dimension in ("compliance_count", "scenario_count")
                sorted_items = sorted(comp.values.items(), key=lambda x: x[1], reverse=reverse)
                rankings[comp.dimension] = []
                for ind_val, _ in sorted_items:
                    try:
                        rankings[comp.dimension].append(Industry(ind_val))
                    except ValueError:
                        continue

        # Build overall summary
        summary_parts: List[str] = []
        summary_parts.append(f"Cross-industry comparison across {len(selected)} industries")
        for comp in comparisons:
            if comp.best_industry:
                summary_parts.append(
                    f"  {_COMPARISON_DIMENSIONS.get(comp.dimension, comp.dimension)}: "
                    f"Best={comp.best_industry.value}, Worst={comp.worst_industry.value if comp.worst_industry else 'N/A'}"
                )

        return CrossIndustryReport(
            report_id=f"cross-{uuid.uuid4().hex[:12]}",
            comparisons=comparisons,
            summary="\n".join(summary_parts),
            industry_rankings=rankings,
        )

    def get_industry_ranking(self, dimension: str) -> List[Industry]:
        """
        Get industry ranking for a specific dimension.

        Returns:
            List of industries sorted by performance (best first)
        """
        comp = self.compare_dimension(dimension)
        rankings = self.generate_report().industry_rankings
        return rankings.get(dimension, [])


def generate_cross_industry_report(
    industries: Optional[List[Industry]] = None,
) -> CrossIndustryReport:
    """
    Convenience function: generate cross-industry comparison report.

    Args:
        industries: Optional industry filter

    Returns:
        Cross-industry comparison report
    """
    analyzer = CrossIndustryAnalyzer()
    return analyzer.generate_report(industries=industries)
