"""
玄鉴 v3.0 — 行业化基准数据库模块 (Industry Benchmark)

核心能力:
- 行业基准数据：内置互联网、金融两个行业漏洞基准（类型分布、修复周期、TOP10、合规要求）
- 企业安全对标：自动对比本企业与同行业平均水平，生成安全能力差距分析
- 行业修复建议：基于行业特性输出针对性修复方案，标注对应合规条款
- 基准数据更新：支持手动/自动从权威漏洞库拉取最新数据

安全红线:
- S1 零网络（更新器仅通过可注入的 HTTP 提供者访问外部数据，测试可 mock）
- S2 不修改被扫描代码（基准数据只读，不对目标代码做任何写入）
- S3 不删除文件（基准数据更新仅覆盖本模块自有数据库）
- S5 数据清理（更新历史保留周期可配置，默认 180 天）
- S6 基准数据不泄漏客户代码（仅存储统计聚合数据和行业基准信息）
- S7 数据库路径固定于 ~/.xuanjian/

模块路径: fp_sentinel/industry_benchmark/
知识图谱: knowledge_graph/modules/v3_industry/
"""

from .models import (
    Industry,
    VulnTypeStats,
    ComplianceRequirement,
    BenchmarkDataset,
    BenchmarkMetadata,
    GapSeverity,
    GapItem,
    CategoryGap,
    GapAnalysisReport,
    EnterpriseMetrics,
    RepairSuggestion,
    UpdateSource,
    UpdateRecord,
    UpdatePolicy,
)
from .builtin_data import (
    INTERNET_BENCHMARK_DATASET,
    FINANCE_BENCHMARK_DATASET,
    get_industry_dataset,
    list_supported_industries,
    TOP10_INTERNET_VULNS,
    TOP10_FINANCE_VULNS,
)
from .store import BenchmarkStore, open_benchmark_store
from .engine import BenchmarkEngine, compare_enterprise_to_industry
from .repair_advisor import RepairAdvisor, suggest_repairs_for_findings
from .updater import BenchmarkUpdater, create_default_policy

__all__ = [
    # 数据模型
    "Industry",
    "VulnTypeStats",
    "ComplianceRequirement",
    "BenchmarkDataset",
    "BenchmarkMetadata",
    "GapSeverity",
    "GapItem",
    "CategoryGap",
    "GapAnalysisReport",
    "EnterpriseMetrics",
    "RepairSuggestion",
    "UpdateSource",
    "UpdateRecord",
    "UpdatePolicy",
    # 内置数据
    "INTERNET_BENCHMARK_DATASET",
    "FINANCE_BENCHMARK_DATASET",
    "get_industry_dataset",
    "list_supported_industries",
    "TOP10_INTERNET_VULNS",
    "TOP10_FINANCE_VULNS",
    # 存储层
    "BenchmarkStore",
    "open_benchmark_store",
    # 对标引擎
    "BenchmarkEngine",
    "compare_enterprise_to_industry",
    # 修复建议
    "RepairAdvisor",
    "suggest_repairs_for_findings",
    # 更新器
    "BenchmarkUpdater",
    "create_default_policy",
]

__version__ = "3.0.0"
__red_lines__ = ["S1", "S2", "S3", "S5", "S6", "S7"]
