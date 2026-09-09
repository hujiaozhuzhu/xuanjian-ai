"""
玄鉴 v3.0 - Industry Benchmark Module

Core capabilities:
- Industry benchmark data: vulnerability distribution, repair cycles, top vulns, compliance
- Enterprise benchmarking: compare enterprise to industry average, gap analysis
- Industry repair advice: targeted remediation based on industry characteristics
- Benchmark data update: manual/auto update from authoritative sources

Security: S1 (zero network in core), S2 (read-only), S3 (no file deletion),
          S5 (retention policy), S6 (no customer code leakage), S7 (fixed db path)

Path: fp_sentinel/industry_benchmark/
Knowledge Graph: knowledge_graph/modules/v3_industry_full/
"""

from .models import (
    Industry,
    VulnTypeStats,
    ComplianceRequirement,
    BenchmarkDataset,
    BenchmarkMetadata,
    IndustryMeta,
    IndustryScenario,
    TopVulnerability,
    RepairCycle,
    GapSeverity,
    GapItem,
    CategoryGap,
    GapAnalysisReport,
    EnterpriseMetrics,
    RepairSuggestion,
    CrossIndustryComparison,
    CrossIndustryReport,
    UpdateSource,
    UpdateRecord,
    UpdatePolicy,
    IndustryRule,
    IndustryRuleSet,
)
from .builtin_data import (
    build_benchmark_dataset,
    build_all_benchmarks,
    get_industry_meta,
    INDUSTRY_METADATA,
)
from .store import BenchmarkStore, open_benchmark_store
from .engine import BenchmarkEngine, compare_enterprise_to_industry
from .repair_advisor import RepairAdvisor, suggest_repairs_for_findings
from .industry_rules import (
    IndustryRuleEngine,
    get_industry_rule_set,
    list_industry_rules,
)
from .comparison import CrossIndustryAnalyzer, generate_cross_industry_report
from .updater import BenchmarkUpdater, create_default_policy

__all__ = [
    # Models
    "Industry",
    "VulnTypeStats",
    "ComplianceRequirement",
    "BenchmarkDataset",
    "BenchmarkMetadata",
    "IndustryMeta",
    "IndustryScenario",
    "TopVulnerability",
    "RepairCycle",
    "GapSeverity",
    "GapItem",
    "CategoryGap",
    "GapAnalysisReport",
    "EnterpriseMetrics",
    "RepairSuggestion",
    "CrossIndustryComparison",
    "CrossIndustryReport",
    "UpdateSource",
    "UpdateRecord",
    "UpdatePolicy",
    "IndustryRule",
    "IndustryRuleSet",
    # Data
    "build_benchmark_dataset",
    "build_all_benchmarks",
    "get_industry_meta",
    "INDUSTRY_METADATA",
    # Store
    "BenchmarkStore",
    "open_benchmark_store",
    # Engine
    "BenchmarkEngine",
    "compare_enterprise_to_industry",
    # Repair
    "RepairAdvisor",
    "suggest_repairs_for_findings",
    # Rules
    "IndustryRuleEngine",
    "get_industry_rule_set",
    "list_industry_rules",
    # Comparison
    "CrossIndustryAnalyzer",
    "generate_cross_industry_report",
    # Updater
    "BenchmarkUpdater",
    "create_default_policy",
]

__version__ = "3.1.0"
__red_lines__ = ["S1", "S2", "S3", "S5", "S6", "S7"]
