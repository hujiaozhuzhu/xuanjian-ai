"""
玄鉴 v3.1 — 行业基准模块 REST API 路由

FastAPI 路由组，统一挂载于 /api/industry/
所有端点纯本地操作，无网络传输。

路由清单：
  GET  /api/industry/list                        — 行业列表
  GET  /api/industry/{industry}/benchmark         — 行业基准详情
  POST /api/industry/gap-analysis                 — 差距分析
  GET  /api/industry/{industry}/rules             — 行业规则查询
  POST /api/industry/cross-compare                — 跨行业对比
  POST /api/industry/repair-suggestions           — 修复建议生成
  POST /api/industry/repair-suggestions/findings  — 基于发现生成修复建议
  GET  /api/industry/stats                        — 统计数据

安全红线：
- S1: 零网络请求（纯本地计算）
- S2: 只读操作（不修改源文件）
- S3: 不删除文件
- S5: 数据保留周期可配置
- S6: 不泄露客户代码
- S7: 数据库路径固定于 ~/.xuanjian/
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

industry_router = APIRouter(prefix="/api/industry", tags=["industry"])

# ─────────────────────────── 请求模型 ───────────────────────────

class GapAnalysisRequest(BaseModel):
    """差距分析请求"""
    model_config = ConfigDict(extra="ignore")

    enterprise_name: str = Field("", description="企业名称")
    industry: str = Field(..., description="行业标识")
    project_name: str = Field("", description="项目名称")
    total_findings: int = Field(0, ge=0, description="总发现数")
    by_severity: Dict[str, int] = Field(default_factory=dict, description="按严重度统计")
    by_category: Dict[str, int] = Field(default_factory=dict, description="按类别统计")
    avg_repair_days: float = Field(0.0, ge=0, description="平均修复天数")
    compliance_score: float = Field(50.0, ge=0.0, le=100.0, description="合规分数")
    tech_stacks: List[str] = Field(default_factory=list, description="技术栈")

    def to_enterprise_metrics(self):
        from .models import EnterpriseMetrics, Industry
        return EnterpriseMetrics(
            project_name=self.project_name,
            industry=Industry(self.industry),
            total_findings=self.total_findings,
            by_severity=self.by_severity,
            by_category=self.by_category,
            avg_repair_days=self.avg_repair_days,
            compliance_score=self.compliance_score,
            tech_stacks=self.tech_stacks,
        )


class CrossCompareRequest(BaseModel):
    """跨行业对比请求"""
    model_config = ConfigDict(extra="ignore")

    industries: List[str] = Field(default_factory=list, description="对比行业列表（空则全量）")
    dimensions: List[str] = Field(default_factory=list, description="对比维度（空则全量）")


class RepairSuggestionRequest(BaseModel):
    """修复建议请求"""
    model_config = ConfigDict(extra="ignore")

    industry: str = Field(..., description="行业标识")
    target_categories: List[str] = Field(default_factory=list, description="目标漏洞类别")
    target_severities: List[str] = Field(default_factory=list, description="目标严重度")
    max_suggestions: int = Field(20, ge=1, le=100, description="最大建议数")


class FindingsRepairRequest(BaseModel):
    """基于发现生成修复建议请求"""
    model_config = ConfigDict(extra="ignore")

    industry: str = Field(..., description="行业标识")
    findings: List[Dict[str, Any]] = Field(default_factory=list, description="发现列表")


# ─────────────────────────── 行业列表 API ───────────────────────────

@industry_router.get("/list")
async def list_industries():
    """
    获取支持的行业列表。

    Returns:
        行业元数据列表，包含行业标识、显示名称、描述、技术栈等
    """
    from .builtin_data import INDUSTRY_METADATA

    industries = []
    for industry, meta in INDUSTRY_METADATA.items():
        industries.append({
            "industry": industry.value if hasattr(industry, "value") else str(industry),
            "display_name": getattr(meta, "display_name", ""),
            "description": getattr(meta, "description", ""),
            "key_tech_stacks": getattr(meta, "key_tech_stacks", []),
            "risk_profile": getattr(meta, "risk_profile", ""),
        })

    return {
        "total": len(industries),
        "industries": industries,
        "version": "3.1.0",
    }


@industry_router.get("/{industry}/benchmark")
async def get_industry_benchmark(
    industry: str,
    include_scenarios: bool = Query(True, description="是否包含行业场景"),
    include_compliance: bool = Query(True, description="是否包含合规要求"),
):
    """
    获取指定行业的基准详情。

    Args:
        industry: 行业标识（如 finance, internet 等）
        include_scenarios: 是否包含行业场景
        include_compliance: 是否包含合规要求

    Returns:
        完整的行业基准数据集
    """
    from .models import Industry
    from .builtin_data import build_benchmark_dataset

    try:
        ind = Industry(industry)
    except ValueError:
        valid = [i.value for i in Industry]
        raise HTTPException(
            status_code=400,
            detail=f"未知行业: {industry}。有效值: {valid}"
        )

    dataset = build_benchmark_dataset(ind)
    result = dataset.model_dump()

    if not include_scenarios:
        result.pop("industry_scenarios", None)
    if not include_compliance:
        result.pop("compliance_requirements", None)

    return result


# ─────────────────────────── 差距分析 API ───────────────────────────

@industry_router.post("/gap-analysis")
async def gap_analysis(request: GapAnalysisRequest):
    """
    执行企业-行业差距分析。

    将企业的安全度量数据与行业基准进行比较，生成差距分析报告。
    包含各维度的差距评分、严重度和改进建议。

    Args:
        request: 差距分析请求，包含企业度量数据

    Returns:
        差距分析报告
    """
    from .engine import BenchmarkEngine

    try:
        metrics = request.to_enterprise_metrics()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    engine = BenchmarkEngine()
    report = engine.compare_enterprise_to_industry(metrics)

    return report.model_dump()


@industry_router.get("/{industry}/gap-analysis/sample")
async def gap_analysis_sample(industry: str):
    """
    获取示例差距分析（使用模拟企业数据）。

    Args:
        industry: 行业标识

    Returns:
        示例差距分析报告
    """
    from .models import Industry, EnterpriseMetrics
    from .engine import BenchmarkEngine

    try:
        ind = Industry(industry)
    except ValueError:
        valid = [i.value for i in Industry]
        raise HTTPException(status_code=400, detail=f"未知行业: {industry}。有效值: {valid}")

    sample_metrics = EnterpriseMetrics(
        project_name="Sample Enterprise",
        industry=ind,
        total_findings=150,
        by_severity={"CRITICAL": 10, "HIGH": 30, "MEDIUM": 60, "LOW": 50},
        by_category={"INJECTION": 40, "XSS": 25, "BROKEN_ACCESS_CONTROL": 20},
        avg_repair_days=12.5,
        compliance_score=72.0,
        tech_stacks=["Java", "Python", "React"],
    )

    engine = BenchmarkEngine()
    report = engine.compare_enterprise_to_industry(sample_metrics)

    return report.model_dump()


# ─────────────────────────── 行业规则查询 API ───────────────────────────

@industry_router.get("/{industry}/rules")
async def get_industry_rules(
    industry: str,
    category: Optional[str] = Query(None, description="按类别过滤"),
    severity: Optional[str] = Query(None, description="按严重度过滤"),
    enabled_only: bool = Query(True, description="仅启用的规则"),
):
    """
    查询行业专属扫描规则。

    Args:
        industry: 行业标识
        category: 漏洞类别过滤
        severity: 严重度过滤
        enabled_only: 仅返回启用的规则

    Returns:
        行业规则列表
    """
    from .models import Industry
    from .industry_rules import get_industry_rule_set

    try:
        ind = Industry(industry)
    except ValueError:
        valid = [i.value for i in Industry]
        raise HTTPException(status_code=400, detail=f"未知行业: {industry}。有效值: {valid}")

    rule_set = get_industry_rule_set(ind)
    rules = rule_set.rules

    if enabled_only:
        rules = [r for r in rules if r.enabled]
    if category:
        rules = [r for r in rules if r.category.lower() == category.lower()]
    if severity:
        rules = [r for r in rules if r.severity.lower() == severity.lower()]

    return {
        "industry": industry,
        "total_rules": len(rules),
        "rule_set_version": rule_set.version,
        "rules": [r.model_dump() for r in rules],
    }


@industry_router.get("/{industry}/rules/{rule_id}")
async def get_industry_rule_detail(industry: str, rule_id: str):
    """
    获取单条行业规则详情。

    Args:
        industry: 行业标识
        rule_id: 规则ID

    Returns:
        规则详情
    """
    from .models import Industry
    from .industry_rules import get_industry_rule_set

    try:
        ind = Industry(industry)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"未知行业: {industry}")

    rule_set = get_industry_rule_set(ind)
    rule = next((r for r in rule_set.rules if r.rule_id == rule_id), None)

    if not rule:
        raise HTTPException(status_code=404, detail=f"规则 {rule_id} 在 {industry} 行业中不存在")

    return rule.model_dump()


# ─────────────────────────── 跨行业对比 API ───────────────────────────

@industry_router.post("/cross-compare")
async def cross_industry_compare(request: CrossCompareRequest):
    """
    执行跨行业安全能力对比分析。

    支持按指定维度和行业进行多维度对比，生成排名和分析结论。

    Args:
        request: 跨行业对比请求

    Returns:
        跨行业对比报告
    """
    from .models import Industry
    from .comparison import CrossIndustryAnalyzer, generate_cross_industry_report

    analyzer = CrossIndustryAnalyzer()

    # 如果指定了行业，创建过滤后的分析器
    if request.industries:
        try:
            filter_inds = [Industry(i) for i in request.industries]
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"无效行业: {e}")

        from .builtin_data import build_all_benchmarks
        all_benchmarks = build_all_benchmarks()
        filtered = {k: v for k, v in all_benchmarks.items() if k in filter_inds}
        analyzer.set_benchmarks(filtered)

    if request.dimensions:
        report = generate_cross_industry_report(analyzer, dimensions=request.dimensions)
    else:
        report = generate_cross_industry_report(analyzer)

    return report.model_dump()


@industry_router.get("/cross-compare/dimensions")
async def list_comparison_dimensions():
    """
    获取支持的所有对比维度列表。

    Returns:
        维度标识和描述列表
    """
    from .comparison import CrossIndustryAnalyzer
    from .builtin_data import build_all_benchmarks
    from .models import CrossIndustryComparison

    # 复用 comparison 模块的维度定义
    _COMPARISON_DIMENSIONS = {
        "avg_repair_days": "平均整体修复周期（天）",
        "vuln_density": "漏洞密度",
        "critical_ratio": "严重漏洞占比（%）",
        "top_category_pct": "Top类别集中度（%）",
        "compliance_count": "合规要求数量",
        "scenario_count": "行业场景数量",
    }

    dimensions = [
        {"id": k, "description": v}
        for k, v in _COMPARISON_DIMENSIONS.items()
    ]

    return {"total": len(dimensions), "dimensions": dimensions}


# ─────────────────────────── 修复建议生成 API ───────────────────────────

@industry_router.post("/repair-suggestions")
async def generate_repair_suggestions(request: RepairSuggestionRequest):
    """
    生成行业修复建议。

    基于企业所在行业的特点，生成针对性的修复建议列表。

    Args:
        request: 修复建议生成请求

    Returns:
        修复建议列表，按优先级排序
    """
    from .models import Industry
    from .repair_advisor import RepairAdvisor

    try:
        ind = Industry(request.industry)
    except ValueError:
        valid = [i.value for i in Industry]
        raise HTTPException(status_code=400, detail=f"未知行业: {request.industry}。有效值: {valid}")

    advisor = RepairAdvisor()
    suggestions = advisor.generate_suggestions(
        industry=ind,
        target_categories=request.target_categories or None,
        target_severities=request.target_severities or None,
        max_suggestions=request.max_suggestions,
    )

    return {
        "industry": request.industry,
        "total": len(suggestions),
        "suggestions": [s.model_dump() for s in suggestions],
    }


@industry_router.post("/repair-suggestions/findings")
async def generate_repair_suggestions_for_findings(request: FindingsRepairRequest):
    """
    基于具体发现生成修复建议。

    根据行业上下文和发现列表，生成针对性的修复建议。

    Args:
        request: 含行业和发现列表的请求

    Returns:
        按发现分组的修复建议
    """
    from .models import Industry
    from .repair_advisor import suggest_repairs_for_findings

    try:
        ind = Industry(request.industry)
    except ValueError:
        valid = [i.value for i in Industry]
        raise HTTPException(status_code=400, detail=f"未知行业: {request.industry}。有效值: {valid}")

    suggestions_by_finding = suggest_repairs_for_findings(
        industry=ind,
        findings=request.findings,
    )

    # 转换为响应格式
    result = {}
    for finding_key, suggestions in suggestions_by_finding.items():
        result[finding_key] = [s.model_dump() for s in suggestions]

    return {
        "industry": request.industry,
        "total_findings": len(request.findings),
        "suggestions_by_finding": result,
    }


# ─────────────────────────── 统计 API ───────────────────────────

@industry_router.get("/stats")
async def industry_stats():
    """
    获取行业基准模块全局统计。

    Returns:
        统计数据
    """
    from .models import Industry
    from .builtin_data import build_all_benchmarks

    benchmarks = build_all_benchmarks()

    total_rules = 0
    total_scenarios = 0
    total_compliance = 0

    for ind, ds in benchmarks.items():
        from .industry_rules import get_industry_rule_set
        rule_set = get_industry_rule_set(ind)
        total_rules += len(rule_set.enabled_rules)
        total_scenarios += len(ds.industry_scenarios)
        total_compliance += len(ds.compliance_requirements)

    return {
        "version": "3.1.0",
        "total_industries": len(benchmarks),
        "total_rules": total_rules,
        "total_scenarios": total_scenarios,
        "total_compliance_requirements": total_compliance,
        "industries": [i.value for i in benchmarks.keys()],
    }
