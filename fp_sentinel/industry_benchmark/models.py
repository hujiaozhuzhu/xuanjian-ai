"""
玄鉴 v3.0 - Industry Benchmark Database :: Data Models

Defines all Pydantic data models for the industry benchmark system.

Security: S1/S2/S3/S5/S6/S7 compliant
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


# --- Industry Enum ---

class Industry(str, Enum):
    """Supported industries (v3.1, 14 industries including 3 new verticals)"""
    INTERNET = "internet"
    FINANCE = "finance"
    GOVERNMENT = "government"
    INDUSTRIAL_CTRL = "industrial_ctrl"
    HEALTHCARE = "healthcare"
    EDUCATION = "education"
    TELECOM = "telecom"
    ENERGY = "energy"
    TRANSPORTATION = "transportation"
    INSURANCE = "insurance"
    SECURITIES = "securities"
    # v3.1 new industries
    VIDEO_SURVEILLANCE = "video_surveillance"
    INSTANT_MESSAGING = "instant_messaging"
    IOT = "iot"


# --- Industry Metadata ---

class IndustryMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    industry: Industry = Field(..., description="Industry identifier")
    display_name: str = Field(..., description="Display name")
    description: str = Field("", description="Industry description")
    key_tech_stacks: List[str] = Field(default_factory=list, description="Key technology stacks")
    risk_profile: str = Field("", description="Risk profile summary")


# --- Vulnerability Type Statistics ---

class VulnTypeStats(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: str = Field(..., description="Vulnerability category key")
    cwe: Optional[str] = Field(None, description="CWE identifier")
    display_name: str = Field(..., description="Display name")
    count: int = Field(0, ge=0, description="Sample count")
    percentage: float = Field(0.0, ge=0.0, le=100.0, description="Percentage")
    avg_severity: str = Field("MEDIUM", description="Average severity")
    trend: str = Field("stable", description="Trend: rising/falling/stable")


# --- Repair Cycle ---

class RepairCycle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    critical_days: float = Field(0.0, ge=0, description="Critical avg repair days")
    high_days: float = Field(0.0, ge=0, description="High avg repair days")
    medium_days: float = Field(0.0, ge=0, description="Medium avg repair days")
    low_days: float = Field(0.0, ge=0, description="Low avg repair days")
    overall_avg_days: float = Field(0.0, ge=0, description="Overall avg repair days")


# --- Top Vulnerability Entry ---

class TopVulnerability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rank: int = Field(..., ge=1, le=100, description="Ranking")
    rule_id: str = Field(..., description="Rule identifier")
    category: str = Field(..., description="Vulnerability category")
    cwe: Optional[str] = Field(None, description="CWE identifier")
    display_name: str = Field(..., description="Display name")
    occurrence_rate: float = Field(0.0, ge=0.0, le=100.0, description="Occurrence rate %")
    severity: str = Field("MEDIUM", description="Severity level")
    description: str = Field("", description="Detailed description")
    compliance_refs: List[str] = Field(default_factory=list, description="Compliance references")


# --- Compliance Requirement ---

class ComplianceRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ref_id: str = Field(..., description="Reference ID")
    standard: str = Field(..., description="Standard name")
    section: str = Field("", description="Section/clause")
    description: str = Field("", description="Requirement description")
    related_cwes: List[str] = Field(default_factory=list, description="Related CWE IDs")
    mandatory: bool = Field(True, description="Is mandatory")


# --- Industry Scenario ---

class IndustryScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(..., description="Scenario unique ID")
    title: str = Field(..., description="Scenario title")
    description: str = Field("", description="Scenario description")
    related_categories: List[str] = Field(default_factory=list, description="Related vuln categories")
    risk_level: str = Field("HIGH", description="Risk level")
    mitigations: List[str] = Field(default_factory=list, description="Mitigation measures")


# --- Benchmark Metadata ---

class BenchmarkMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field("xuanjian-builtin", description="Data source")
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Generation timestamp ISO8601",
    )
    valid_until: Optional[str] = Field(None, description="Valid until timestamp")
    sample_period: str = Field("", description="Sample coverage period")
    confidence: float = Field(0.95, ge=0.0, le=1.0, description="Confidence level")
    notes: str = Field("", description="Notes")


# --- Benchmark Dataset ---

class BenchmarkDataset(BaseModel):
    model_config = ConfigDict(extra="ignore")

    industry: Industry = Field(..., description="Industry identifier")
    version: str = Field("3.0.0", description="Dataset version")
    sample_size: int = Field(0, ge=0, description="Sample size")
    vuln_distribution: List[VulnTypeStats] = Field(default_factory=list, description="Vulnerability distribution")
    repair_cycle: RepairCycle = Field(default_factory=RepairCycle, description="Repair cycle")
    top_vulnerabilities: List[TopVulnerability] = Field(default_factory=list, description="Top vulnerabilities")
    compliance_requirements: List[ComplianceRequirement] = Field(default_factory=list, description="Compliance requirements")
    industry_scenarios: List[IndustryScenario] = Field(default_factory=list, description="Industry scenarios")
    metadata: BenchmarkMetadata = Field(..., description="Benchmark metadata")

    def get_vuln_category_map(self) -> Dict[str, VulnTypeStats]:
        return {v.category: v for v in self.vuln_distribution}

    def get_top_n(self, n: int = 10) -> List[TopVulnerability]:
        return sorted(self.top_vulnerabilities, key=lambda x: x.rank)[:n]


# --- Enterprise Metrics ---

class EnterpriseMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_name: str = Field("", description="Project name")
    industry: Industry = Field(..., description="Industry")
    total_findings: int = Field(0, ge=0, description="Total findings")
    by_severity: Dict[str, int] = Field(default_factory=dict, description="By severity")
    by_category: Dict[str, int] = Field(default_factory=dict, description="By category")
    avg_repair_days: float = Field(0.0, ge=0, description="Avg repair days")
    scan_count: int = Field(0, ge=0, description="Scan count")
    compliance_score: float = Field(0.0, ge=0.0, le=100.0, description="Compliance score")
    tech_stacks: List[str] = Field(default_factory=list, description="Tech stacks")


# --- Gap Analysis ---

class GapSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    ON_PAR = "on_par"
    AHEAD = "ahead"


class GapItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: str = Field(..., description="Gap dimension")
    industry_avg: float = Field(0.0, description="Industry average")
    enterprise_value: float = Field(0.0, description="Enterprise value")
    gap_ratio: float = Field(0.0, description="Gap ratio")
    severity: GapSeverity = Field(GapSeverity.MEDIUM, description="Gap severity")
    description: str = Field("", description="Gap description")
    recommendation: str = Field("", description="Recommendation")


class CategoryGap(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category_name: str = Field(..., description="Category name")
    items: List[GapItem] = Field(default_factory=list, description="Gap items")
    overall_severity: GapSeverity = GapSeverity.ON_PAR
    score: float = Field(50.0, ge=0.0, le=100.0, description="Category score")


class GapAnalysisReport(BaseModel):
    model_config = ConfigDict(extra="ignore")

    report_id: str = Field(..., description="Report ID")
    enterprise_name: str = Field("", description="Enterprise name")
    industry: Industry = Field(..., description="Industry")
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Generation timestamp",
    )
    overall_score: float = Field(50.0, ge=0.0, le=100.0, description="Overall security score")
    overall_severity: GapSeverity = GapSeverity.ON_PAR
    category_gaps: List[CategoryGap] = Field(default_factory=list, description="Category gaps")
    highlights: List[str] = Field(default_factory=list, description="Key findings")
    improvement_roadmap: List[str] = Field(default_factory=list, description="Improvement roadmap")

    @property
    def critical_gaps(self) -> List[GapItem]:
        result: List[GapItem] = []
        for cg in self.category_gaps:
            result.extend([i for i in cg.items if i.severity in (GapSeverity.CRITICAL, GapSeverity.HIGH)])
        return result


# --- Repair Suggestion ---

class RepairSuggestion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    suggestion_id: str = Field(..., description="Suggestion ID")
    title: str = Field(..., description="Suggestion title")
    description: str = Field("", description="Description")
    target_categories: List[str] = Field(default_factory=list, description="Target categories")
    target_severities: List[str] = Field(default_factory=list, description="Target severities")
    effort: str = Field("medium", description="Effort level: low/medium/high")
    priority: int = Field(5, ge=1, le=10, description="Priority 1-10")
    compliance_refs: List[str] = Field(default_factory=list, description="Compliance references")
    industry_specific: bool = Field(False, description="Is industry-specific")
    code_example: str = Field("", description="Code example")
    reference_links: List[str] = Field(default_factory=list, description="Reference links")


# --- Cross-Industry Comparison ---

class CrossIndustryComparison(BaseModel):
    model_config = ConfigDict(extra="forbid")

    industries: List[Industry] = Field(default_factory=list, description="Industries compared")
    dimension: str = Field(..., description="Comparison dimension")
    values: Dict[str, float] = Field(default_factory=dict, description="Industry to metric value")
    best_industry: Optional[Industry] = Field(None, description="Best industry")
    worst_industry: Optional[Industry] = Field(None, description="Worst industry")
    analysis: str = Field("", description="Analysis conclusion")


class CrossIndustryReport(BaseModel):
    model_config = ConfigDict(extra="ignore")

    report_id: str = Field(..., description="Report ID")
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Generation timestamp",
    )
    comparisons: List[CrossIndustryComparison] = Field(default_factory=list, description="Comparisons")
    summary: str = Field("", description="Summary")
    industry_rankings: Dict[str, List[Industry]] = Field(default_factory=dict, description="Industry rankings")


# --- Update Records ---

class UpdateSource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(..., description="Source ID")
    name: str = Field(..., description="Source name")
    url: str = Field("", description="URL")
    description: str = Field("", description="Description")
    enabled: bool = Field(True, description="Is enabled")


class UpdateRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    record_id: str = Field(..., description="Record ID")
    source_id: str = Field(..., description="Source ID")
    industry: Industry = Field(..., description="Industry")
    updated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Update timestamp",
    )
    changes_summary: str = Field("", description="Changes summary")
    success: bool = Field(True, description="Success")


class UpdatePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    auto_update: bool = Field(False, description="Auto update")
    interval_days: int = Field(30, ge=1, description="Update interval days")
    retention_days: int = Field(180, ge=1, description="History retention days")
    sources: List[UpdateSource] = Field(default_factory=list, description="Data sources")


# --- Industry Rules ---

class IndustryRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(..., description="Rule ID")
    industry: Industry = Field(..., description="Applicable industry")
    name: str = Field(..., description="Rule name")
    category: str = Field(..., description="Vulnerability category")
    cwe: Optional[str] = Field(None, description="CWE")
    severity: str = Field("MEDIUM", description="Severity")
    pattern: str = Field("", description="Detection pattern")
    description: str = Field("", description="Rule description")
    tech_targets: List[str] = Field(default_factory=list, description="Target tech stacks")
    enabled: bool = Field(True, description="Is enabled")
    compliance_refs: List[str] = Field(default_factory=list, description="Compliance references")


class IndustryRuleSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    industry: Industry = Field(..., description="Industry")
    rules: List[IndustryRule] = Field(default_factory=list, description="Rules")
    version: str = Field("3.0.0", description="Rule set version")

    @property
    def enabled_rules(self) -> List[IndustryRule]:
        return [r for r in self.rules if r.enabled]
