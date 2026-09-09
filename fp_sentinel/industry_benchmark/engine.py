"""
玄鉴 v3.0 - Industry Benchmark :: Benchmark Engine

Core benchmarking engine: compares enterprise metrics against industry
averages and produces gap analysis reports.
"""
from __future__ import annotations

import uuid
from typing import List, Optional

from .models import (
    BenchmarkDataset,
    CategoryGap,
    EnterpriseMetrics,
    GapAnalysisReport,
    GapItem,
    GapSeverity,
    Industry,
)
from .builtin_data import build_benchmark_dataset


# Severity ordering for comparison
_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _classify_gap(gap_ratio: float, lower_is_better: bool = True) -> GapSeverity:
    """
    Classify gap severity based on ratio.

    Args:
        gap_ratio: (enterprise_value - industry_avg) / industry_avg
        lower_is_better: if True, positive gap_ratio means worse
    """
    if lower_is_better:
        if gap_ratio >= 0.5:
            return GapSeverity.CRITICAL
        elif gap_ratio >= 0.25:
            return GapSeverity.HIGH
        elif gap_ratio >= 0.1:
            return GapSeverity.MEDIUM
        elif gap_ratio >= -0.05:
            return GapSeverity.ON_PAR
        else:
            return GapSeverity.AHEAD
    else:
        # inverse: higher is better (e.g. compliance score)
        if gap_ratio <= -0.3:
            return GapSeverity.CRITICAL
        elif gap_ratio <= -0.15:
            return GapSeverity.HIGH
        elif gap_ratio <= -0.05:
            return GapSeverity.MEDIUM
        elif gap_ratio <= 0.05:
            return GapSeverity.ON_PAR
        else:
            return GapSeverity.AHEAD


def _compute_vuln_density_gap(enterprise: EnterpriseMetrics,
                               benchmark: BenchmarkDataset) -> GapItem:
    """Compare enterprise vulnerability density vs industry average"""
    if benchmark.sample_size <= 0 or enterprise.scan_count <= 0:
        return GapItem(
            category="vuln_density",
            industry_avg=0.0,
            enterprise_value=0.0,
            gap_ratio=0.0,
            severity=GapSeverity.ON_PAR,
            description="Insufficient data for density comparison",
            recommendation="Ensure benchmark dataset is available",
        )

    # Industry average findings per sample
    total_industry_findings = sum(v.count for v in benchmark.vuln_distribution)
    avg_findings = total_industry_findings / max(benchmark.sample_size, 1)

    # Enterprise density per scan
    enterprise_density = enterprise.total_findings / max(enterprise.scan_count, 1)

    if avg_findings > 0:
        gap_ratio = (enterprise_density - avg_findings) / avg_findings
    else:
        gap_ratio = 0.0

    severity = _classify_gap(gap_ratio, lower_is_better=True)

    description = (
        f"Enterprise vulnerability density: {enterprise_density:.1f} per scan, "
        f"Industry average: {avg_findings:.1f}, "
        f"Gap: {gap_ratio:+.1%}"
    )

    recommendation = _density_recommendation(severity, enterprise_density, avg_findings)

    return GapItem(
        category="vuln_density",
        industry_avg=avg_findings,
        enterprise_value=enterprise_density,
        gap_ratio=gap_ratio,
        severity=severity,
        description=description,
        recommendation=recommendation,
    )


def _density_recommendation(severity: GapSeverity, enterprise_val: float,
                             industry_avg: float) -> str:
    """Generate density-specific recommendation"""
    if severity in (GapSeverity.CRITICAL, GapSeverity.HIGH):
        actions = [
            "Prioritize critical and high vulnerability remediation",
            "Implement automated regression testing",
            "Enhance developer security training",
        ]
        if enterprise_val > industry_avg * 2:
            actions.append("Consider comprehensive security code review")
        return " | ".join(actions)
    elif severity == GapSeverity.MEDIUM:
        return "Increase scan frequency and improve pre-commit security checks"
    elif severity == GapSeverity.ON_PAR:
        return "Maintain current security practices and continue monitoring"
    else:
        return "Leverage security strengths to help industry peers"


def _compute_repair_speed_gap(enterprise: EnterpriseMetrics,
                               benchmark: BenchmarkDataset) -> GapItem:
    """Compare enterprise repair speed vs industry"""
    industry_avg = benchmark.repair_cycle.overall_avg_days
    enterprise_days = enterprise.avg_repair_days

    if industry_avg > 0:
        gap_ratio = (enterprise_days - industry_avg) / industry_avg
    else:
        gap_ratio = 0.0

    severity = _classify_gap(gap_ratio, lower_is_better=True)

    description = (
        f"Enterprise avg repair: {enterprise_days:.1f} days, "
        f"Industry avg: {industry_avg:.1f} days, "
        f"Gap: {gap_ratio:+.1%}"
    )

    if severity in (GapSeverity.CRITICAL, GapSeverity.HIGH):
        recommendation = "Establish SLA-based repair timelines, automate patch management"
    elif severity == GapSeverity.MEDIUM:
        recommendation = "Optimize repair workflow, increase dedicated security resources"
    elif severity == GapSeverity.ON_PAR:
        recommendation = "Maintain current repair efficiency"
    else:
        recommendation = "Fast repair turnaround; document best practices"

    return GapItem(
        category="repair_speed",
        industry_avg=industry_avg,
        enterprise_value=enterprise_days,
        gap_ratio=gap_ratio,
        severity=severity,
        description=description,
        recommendation=recommendation,
    )


def _compute_compliance_gap(enterprise: EnterpriseMetrics,
                             benchmark: BenchmarkDataset) -> GapItem:
    """Compare enterprise compliance score vs industry"""
    industry_compliance = 80.0  # Industry expected compliance score
    enterprise_score = enterprise.compliance_score

    gap_ratio = (enterprise_score - industry_compliance) / industry_compliance

    severity = _classify_gap(gap_ratio, lower_is_better=False)

    description = (
        f"Enterprise compliance: {enterprise_score:.1f}%, "
        f"Industry target: {industry_compliance:.1f}%, "
        f"Gap: {gap_ratio:+.1%}"
    )

    if severity in (GapSeverity.CRITICAL, GapSeverity.HIGH):
        refs = ", ".join(c.ref_id for c in benchmark.compliance_requirements[:3])
        recommendation = f"Immediate remediation needed. Key gaps: {refs}"
    elif severity == GapSeverity.MEDIUM:
        recommendation = "Address remaining compliance gaps per industry requirements"
    else:
        recommendation = "Good compliance posture; maintain and audit regularly"

    return GapItem(
        category="compliance",
        industry_avg=industry_compliance,
        enterprise_value=enterprise_score,
        gap_ratio=gap_ratio,
        severity=severity,
        description=description,
        recommendation=recommendation,
    )


def _compute_coverage_gap(enterprise: EnterpriseMetrics,
                           benchmark: BenchmarkDataset) -> GapItem:
    """Compare vulnerability category coverage"""
    industry_cats = set(benchmark.get_vuln_category_map().keys())
    enterprise_cats = set(enterprise.by_category.keys())

    if industry_cats:
        coverage = len(enterprise_cats & industry_cats) / len(industry_cats)
    else:
        coverage = 0.0

    gap_ratio = coverage - 0.8  # 80% coverage target

    severity = _classify_gap(-gap_ratio, lower_is_better=False)

    missing = industry_cats - enterprise_cats
    description = (
        f"Category coverage: {coverage:.0%}, "
        f"Missing categories: {len(missing)}"
    )

    if missing:
        recommendation = f"Expand scanning to cover: {', '.join(list(missing)[:5])}"
    else:
        recommendation = "Full category coverage achieved"

    return GapItem(
        category="coverage",
        industry_avg=0.8,
        enterprise_value=coverage,
        gap_ratio=gap_ratio,
        severity=severity,
        description=description,
        recommendation=recommendation,
    )


def _overall_severity_from_categories(categories: List[CategoryGap]) -> GapSeverity:
    """Derive overall severity from category gaps"""
    if not categories:
        return GapSeverity.ON_PAR
    
    severity_scores = {
        GapSeverity.CRITICAL: 5,
        GapSeverity.HIGH: 4,
        GapSeverity.MEDIUM: 3,
        GapSeverity.ON_PAR: 2,
        GapSeverity.LOW: 1,
        GapSeverity.AHEAD: 0,
    }
    
    max_score = max(
        severity_scores.get(c.overall_severity, 2) for c in categories
    )
    
    for sev, score in severity_scores.items():
        if score == max_score:
            return sev
    return GapSeverity.ON_PAR


class BenchmarkEngine:
    """
    Core engine for benchmark comparison and gap analysis.
    """

    def __init__(self, benchmark: Optional[BenchmarkDataset] = None) -> None:
        self._benchmark = benchmark

    def set_benchmark(self, benchmark: BenchmarkDataset) -> None:
        """Set benchmark dataset for comparison"""
        self._benchmark = benchmark

    def get_benchmark(self) -> Optional[BenchmarkDataset]:
        """Get current benchmark dataset"""
        return self._benchmark

    def analyze(
        self,
        enterprise: EnterpriseMetrics,
        benchmark: Optional[BenchmarkDataset] = None,
    ) -> GapAnalysisReport:
        """
        Perform full gap analysis of enterprise vs industry benchmark.

        Args:
            enterprise: Enterprise security metrics
            benchmark: Optional override benchmark

        Returns:
            Gap analysis report
        """
        bench = benchmark or self._benchmark
        if bench is None:
            bench = build_benchmark_dataset(enterprise.industry)

        categories: List[CategoryGap] = []

        # Vuln density gap
        density_item = _compute_vuln_density_gap(enterprise, bench)
        categories.append(CategoryGap(
            category_name="vulnerability_density",
            items=[density_item],
            overall_severity=density_item.severity,
            score=_severity_to_score(density_item.severity),
        ))

        # Repair speed gap
        repair_item = _compute_repair_speed_gap(enterprise, bench)
        categories.append(CategoryGap(
            category_name="repair_speed",
            items=[repair_item],
            overall_severity=repair_item.severity,
            score=_severity_to_score(repair_item.severity),
        ))

        # Compliance gap
        compliance_item = _compute_compliance_gap(enterprise, bench)
        categories.append(CategoryGap(
            category_name="compliance",
            items=[compliance_item],
            overall_severity=compliance_item.severity,
            score=_severity_to_score(compliance_item.severity),
        ))

        # Coverage gap
        coverage_item = _compute_coverage_gap(enterprise, bench)
        categories.append(CategoryGap(
            category_name="coverage",
            items=[coverage_item],
            overall_severity=coverage_item.severity,
            score=_severity_to_score(coverage_item.severity),
        ))

        # Overall score (average of category scores)
        overall_score = sum(c.score for c in categories) / max(len(categories), 1)
        overall_severity = _overall_severity_from_categories(categories)

        # Generate highlights
        highlights = _generate_highlights(enterprise, bench, categories)

        # Improvement roadmap
        roadmap = _generate_roadmap(categories)

        return GapAnalysisReport(
            report_id=f"gap-{uuid.uuid4().hex[:12]}",
            enterprise_name=enterprise.project_name,
            industry=enterprise.industry,
            overall_score=overall_score,
            overall_severity=overall_severity,
            category_gaps=categories,
            highlights=highlights,
            improvement_roadmap=roadmap,
        )


def _severity_to_score(severity: GapSeverity) -> float:
    """Convert severity to numeric score (higher = better)"""
    mapping = {
        GapSeverity.CRITICAL: 20.0,
        GapSeverity.HIGH: 40.0,
        GapSeverity.MEDIUM: 60.0,
        GapSeverity.ON_PAR: 75.0,
        GapSeverity.LOW: 85.0,
        GapSeverity.AHEAD: 95.0,
    }
    return mapping.get(severity, 50.0)


def _generate_highlights(enterprise: EnterpriseMetrics,
                          bench: BenchmarkDataset,
                          categories: List[CategoryGap]) -> List[str]:
    """Generate key findings"""
    highlights: List[str] = []

    # Critical/high gaps
    for cg in categories:
        for item in cg.items:
            if item.severity in (GapSeverity.CRITICAL, GapSeverity.HIGH):
                highlights.append(
                    f"{cg.category_name}: {item.description}"
                )

    # Top industry threats not yet addressed
    top_threats = bench.top_vulnerabilities[:3]
    if top_threats:
        threat_names = ", ".join(t.display_name for t in top_threats)
        highlights.append(f"Top industry threats to address: {threat_names}")

    # Overall posture
    if enterprise.avg_repair_days > 0 and bench.repair_cycle.overall_avg_days > 0:
        if enterprise.avg_repair_days > bench.repair_cycle.overall_avg_days:
            highlights.append(
                f"Repair speed ({enterprise.avg_repair_days:.1f}d) exceeds industry avg "
                f"({bench.repair_cycle.overall_avg_days:.1f}d)"
            )
        else:
            highlights.append(
                f"Repair speed ({enterprise.avg_repair_days:.1f}d) is better than industry avg "
                f"({bench.repair_cycle.overall_avg_days:.1f}d)"
            )

    return highlights


def _generate_roadmap(categories: List[CategoryGap]) -> List[str]:
    """Generate improvement roadmap"""
    roadmap: List[str] = []

    # Sort categories by severity (worst first)
    severity_order = {
        GapSeverity.CRITICAL: 0,
        GapSeverity.HIGH: 1,
        GapSeverity.MEDIUM: 2,
        GapSeverity.ON_PAR: 3,
        GapSeverity.LOW: 4,
        GapSeverity.AHEAD: 5,
    }
    sorted_cats = sorted(
        categories,
        key=lambda c: severity_order.get(c.overall_severity, 3),
    )

    for i, cg in enumerate(sorted_cats, 1):
        if cg.overall_severity in (GapSeverity.CRITICAL, GapSeverity.HIGH):
            for item in cg.items:
                if item.recommendation:
                    roadmap.append(f"[P{i}] {cg.category_name}: {item.recommendation}")
        elif cg.overall_severity == GapSeverity.MEDIUM:
            for item in cg.items:
                if item.recommendation:
                    roadmap.append(f"[P{i}] {cg.category_name}: {item.recommendation}")

    if not roadmap:
        roadmap.append("Maintain current security posture and continue monitoring")

    return roadmap


def compare_enterprise_to_industry(
    enterprise: EnterpriseMetrics,
    benchmark: Optional[BenchmarkDataset] = None,
) -> GapAnalysisReport:
    """
    Convenience function: compare enterprise to industry benchmark.

    Args:
        enterprise: Enterprise security metrics
        benchmark: Optional benchmark dataset

    Returns:
        Gap analysis report
    """
    engine = BenchmarkEngine(benchmark=benchmark)
    return engine.analyze(enterprise)
