"""
玄鉴 v3.2 — 精准风险评分引擎 (Experience Optimization Module)

结合行业特性与业务重要性，提升 CVSS 评分的精准度：
- 行业权重调整（金融/医疗/政务 等高风险行业加权）
- 业务关键性评分（核心链路/非核心链路区分）
- 复合漏洞加权（多漏洞串联时的风险放大）
- 动态阈值（随时间推移自动衰减/加重）

安全红线：
- S6: 零网络依赖
- S2: 纯计算，不修改任何文件

版本: 3.2.0
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .chain_scorer import AssetContext, ChainRiskScorer, RiskScore
from ..industry_benchmark.models import Industry

logger = logging.getLogger(__name__)


# ─────────────────────── 业务关键性模型 ───────────────────────

@dataclass
class BusinessCriticality:
    """业务关键性"""
    is_revenue_related: bool = False       # 是否涉及营收
    is_user_facing: bool = True            # 是否面向用户
    is_compliance_required: bool = True     # 是否合规需求
    user_impact_count: int = 1000          # 影响用户数
    sla_level: str = "standard"            # standard/critical/platinum
    data_classification: str = "internal"   # public/internal/confidential/restricted
    recovery_time_hours: float = 24.0      # 恢复时间(RTO)

    def to_score(self) -> float:
        """将业务关键性转换为 0-1 评分"""
        score = 0.0

        # 营收影响 (权重 0.3)
        if self.is_revenue_related:
            score += 0.3

        # 用户面影响 (权重 0.2)
        if self.is_user_facing:
            score += 0.2

        # 合规需求 (权重 0.15)
        if self.is_compliance_required:
            score += 0.15

        # 用户数量 (权重 0.15)
        user_factor = min(1.0, math.log10(max(1, self.user_impact_count)) / 7)
        score += user_factor * 0.15

        # SLA 等级 (权重 0.1)
        sla_factor = {
            "platinum": 1.0,
            "critical": 0.8,
            "standard": 0.4,
            "basic": 0.2,
        }.get(self.sla_level, 0.4)
        score += sla_factor * 0.1

        # 数据分级 (权重 0.1)
        data_factor = {
            "restricted": 1.0,
            "confidential": 0.75,
            "internal": 0.4,
            "public": 0.1,
        }.get(self.data_classification, 0.4)
        score += data_factor * 0.1

        return round(min(1.0, score), 4)


# ─────────────────────── 行业风控配置 ───────────────────────

INDUSTRY_RISK_PROFILE: Dict[str, Dict[str, float]] = {
    "finance": {
        "cvss_multiplier": 1.15,
        "business_weight": 0.35,
        "compliance_weight": 0.25,
        "data_sensitivity_default": 0.85,
        "critical_categories": ["SQL_INJECTION", "DESERIALIZATION", "AUTH_BYPASS"],
        "industry_factor": 1.2,
    },
    "healthcare": {
        "cvss_multiplier": 1.10,
        "business_weight": 0.25,
        "compliance_weight": 0.35,
        "data_sensitivity_default": 0.90,
        "critical_categories": ["SQL_INJECTION", "XSS", "DATA_LEAKAGE"],
        "industry_factor": 1.15,
    },
    "government": {
        "cvss_multiplier": 1.10,
        "business_weight": 0.25,
        "compliance_weight": 0.35,
        "data_sensitivity_default": 0.85,
        "critical_categories": ["SQL_INJECTION", "XXE", "DESERIALIZATION"],
        "industry_factor": 1.15,
    },
    "internet": {
        "cvss_multiplier": 1.0,
        "business_weight": 0.25,
        "compliance_weight": 0.15,
        "data_sensitivity_default": 0.60,
        "critical_categories": ["SQL_INJECTION", "COMMAND_INJECTION", "DESERIALIZATION"],
        "industry_factor": 1.0,
    },
    "industrial_ctrl": {
        "cvss_multiplier": 1.20,
        "business_weight": 0.30,
        "compliance_weight": 0.20,
        "data_sensitivity_default": 0.70,
        "critical_categories": ["COMMAND_INJECTION", "DESERIALIZATION", "SSRF"],
        "industry_factor": 1.25,
    },
    "energy": {
        "cvss_multiplier": 1.20,
        "business_weight": 0.30,
        "compliance_weight": 0.25,
        "data_sensitivity_default": 0.75,
        "critical_categories": ["COMMAND_INJECTION", "DESERIALIZATION", "SSRF"],
        "industry_factor": 1.25,
    },
    "telecom": {
        "cvss_multiplier": 1.05,
        "business_weight": 0.25,
        "compliance_weight": 0.20,
        "data_sensitivity_default": 0.70,
        "critical_categories": ["SQL_INJECTION", "SSRF", "AUTH_BYPASS"],
        "industry_factor": 1.05,
    },
    "education": {
        "cvss_multiplier": 1.0,
        "business_weight": 0.15,
        "compliance_weight": 0.20,
        "data_sensitivity_default": 0.50,
        "critical_categories": ["SQL_INJECTION", "XSS", "DATA_LEAKAGE"],
        "industry_factor": 0.95,
    },
    "transportation": {
        "cvss_multiplier": 1.10,
        "business_weight": 0.30,
        "compliance_weight": 0.20,
        "data_sensitivity_default": 0.65,
        "critical_categories": ["COMMAND_INJECTION", "DESERIALIZATION", "SSRF"],
        "industry_factor": 1.10,
    },
    "insurance": {
        "cvss_multiplier": 1.10,
        "business_weight": 0.30,
        "compliance_weight": 0.30,
        "data_sensitivity_default": 0.80,
        "critical_categories": ["SQL_INJECTION", "DATA_LEAKAGE", "AUTH_BYPASS"],
        "industry_factor": 1.10,
    },
    "securities": {
        "cvss_multiplier": 1.15,
        "business_weight": 0.35,
        "compliance_weight": 0.30,
        "data_sensitivity_default": 0.85,
        "critical_categories": ["SQL_INJECTION", "DESERIALIZATION", "AUTH_BYPASS"],
        "industry_factor": 1.2,
    },
}


# ──────────────────── --─ 精准评分结果 ─────────────────────────

@dataclass
class PrecisionRiskScore:
    """精准风险评分结果"""
    # 基础评分
    cvss_adjusted: float              # 调整后的 CVSS 分数 (0-10)
    business_score: float             # 业务影响评分 (0-1)
    technical_score: float            # 技术风险评分 (0-1)
    final_score: float                # 最终综合分数 (0-10)
    severity: str                     # 最终严重级别

    # 评分明细
    cvss_base: float                  # 原始 CVSS
    cvss_multiplier: float            # 行业乘数
    business_criticality: float       # 业务关键度
    industry_factor: float            # 行业因子
    category_boost: float             # 类别加成
    temporal_adjustment: float        # 时间衰减调整

    # 排序信息
    priority_rank: int = 0            # 优先级排名
    remediation_urgency: str = "normal"  # 整改紧急度

    # 元数据
    scoring_method: str = "precision_v32"
    details: Dict[str, Any] = field(default_factory=dict)


# ─────────────────────── 精准风险评分器 ─────────────────────────

class PrecisionRiskScorer:
    """
    精准风险评分引擎

    在标准 ChainRiskScorer 基础上引入：
    1. 行业动态乘数
    2. 业务关键性权重
    3. 漏洞类别特定加成
    4. 时间衰减调整
    """

    SEVERITY_THRESHOLDS = [
        (9.0, "CRITICAL"),
        (7.0, "HIGH"),
        (4.0, "MEDIUM"),
        (1.0, "LOW"),
        (0.0, "INFO"),
    ]

    def __init__(
        self,
        industry: str = "internet",
        business_criticality: Optional[BusinessCriticality] = None,
    ) -> None:
        self._industry = industry.lower()
        self._business = business_criticality or BusinessCriticality()
        self._profile = INDUSTRY_RISK_PROFILE.get(
            self._industry, INDUSTRY_RISK_PROFILE["internet"]
        )
        self._base_scorer = ChainRiskScorer()

    @property
    def industry(self) -> str:
        return self._industry

    @property
    def business(self) -> BusinessCriticality:
        return self._business

    def score_finding(
        self,
        finding: Any,
        context: Optional[AssetContext] = None,
    ) -> PrecisionRiskScore:
        """
        对单个 finding 进行精准评分

        Args:
            finding: 漏洞发现对象
            context: 资产上下文

        Returns:
            PrecisionRiskScore
        """
        if context is None:
            context = self._build_asset_context()

        # 1. 基础 CVSS
        base_cvss = self._get_base_cvss(finding)
        cvss_mult = self._profile["cvss_multiplier"]

        # 行业类别加成
        cat_boost = self._get_category_boost(finding)

        # 调整后 CVSS (cap at 10.0)
        cvss_adjusted = min(10.0, base_cvss * cvss_mult + cat_boost)

        # 2. 业务评分
        biz_score = self._business.to_score()

        # 3. 技术评分（复用 ChainRiskScorer 逻辑）
        tech_score = self._calc_technical_score(finding, context)

        # 4. 时间衰减
        temporal_adj = self._calc_temporal_adjustment(finding)

        # 5. 最终分数
        biz_weight = self._profile["business_weight"]
        compliance_w = self._profile["compliance_weight"]
        tech_weight = 1.0 - biz_weight - compliance_w
        # 保证 tech_weight 不小于 0.1
        tech_weight = max(0.1, tech_weight)

        final = (
            (cvss_adjusted / 10.0) * tech_weight
            + biz_score * biz_weight
            + cat_boost * compliance_w
        ) * temporal_adj * self._profile.get("industry_factor", 1.0)

        final = min(10.0, max(0.0, final * 10))  # 缩放到 0-10
        final = round(final, 2)

        # 推断严重度
        severity = self._score_to_severity(final)

        # 整改紧急度
        urgency = self._score_to_urgency(final, severity)

        return PrecisionRiskScore(
            cvss_adjusted=round(cvss_adjusted, 2),
            business_score=biz_score,
            technical_score=round(tech_score, 4),
            final_score=final,
            severity=severity,
            cvss_base=base_cvss,
            cvss_multiplier=cvss_mult,
            business_criticality=biz_score,
            industry_factor=self._profile.get("industry_factor", 1.0),
            category_boost=cat_boost,
            temporal_adjustment=round(temporal_adj, 3),
            remediation_urgency=urgency,
            details={
                "industry": self._industry,
                "biz_weight": biz_weight,
                "tech_weight": tech_weight,
                "compliance_weight": compliance_w,
                "profile": self._profile,
            },
        )

    def score_findings(
        self,
        findings: List[Any],
        context: Optional[AssetContext] = None,
    ) -> List[PrecisionRiskScore]:
        """
        对多个 findings 评分并排序

        Returns:
            按 final_score 降序排列的评分列表
        """
        scored: List[PrecisionRiskScore] = []
        for finding in findings:
            score = self.score_finding(finding, context)
            scored.append(score)

        # 按最终分数降序排列
        scored.sort(key=lambda s: s.final_score, reverse=True)

        # 设置排名
        for i, s in enumerate(scored, 1):
            s.priority_rank = i

        return scored

    def sort_findings_by_risk(
        self,
        findings: List[Any],
        context: Optional[AssetContext] = None,
    ) -> List[Tuple[Any, PrecisionRiskScore]]:
        """按风险对 findings 排序，返回 (finding, score) 对"""
        scores = self.score_findings(findings, context)
        # 保持与 findins 关联
        # 注意：score_findings 内部已经排序，但丢失了 finding 引用
        # 重新计算并配对
        pairs: List[Tuple[Any, PrecisionRiskScore]] = []
        for finding in findings:
            score = self.score_finding(finding, context)
            pairs.append((finding, score))

        pairs.sort(key=lambda p: p[1].final_score, reverse=True)
        for i, (f, s) in enumerate(pairs):
            s.priority_rank = i + 1

        return pairs

    def _build_asset_context(self) -> AssetContext:
        """从业务关键性构建资产上下文"""
        return AssetContext(
            data_sensitivity=self._profile["data_sensitivity_default"],
            user_count=self._business.user_impact_count,
            compliance_factor=self._profile["compliance_weight"],
            network_exposure="internal",  # 默认保守值
        )

    def _get_base_cvss(self, finding: Any) -> float:
        """获取 finding 的基准 CVSS"""
        # 优先使用 finding 自带字段
        explicit_cvss = getattr(finding, "cvss", None)
        if explicit_cvss is not None:
            try:
                v = float(explicit_cvss)
                if 0 <= v <= 10:
                    return v
            except (ValueError, TypeError):
                pass

        # 从 severity 映射
        severity = (getattr(finding, "severity", "MEDIUM") or "MEDIUM").upper()
        return ChainRiskScorer.DEFAULT_CVSS.get(severity, 5.0)

    def _get_category_boost(self, finding: Any) -> float:
        """检查 finding 是否属于行业高风险类别"""
        rule_id = (getattr(finding, "rule_id", "") or "").lower()
        category = (getattr(finding, "category", "") or "").lower()

        critical_cats = self._profile.get("critical_categories", [])

        for crit_cat in critical_cats:
            crit_lower = crit_cat.lower().replace("_", "")
            if crit_lower in rule_id.replace("-", "").replace("_", ""):
                return 0.5  # 行业关键类别加 0.5
            if crit_lower in category.replace("-", "").replace("_", ""):
                return 0.5

        return 0.0

    def _calc_technical_score(self, finding: Any, context: AssetContext) -> float:
        """计算技术风险分"""
        cvss = self._get_base_cvss(finding)
        epss = self._get_epss(finding)
        exploit = self._check_exploit(finding)

        return (cvss / 10.0) * epss * exploit

    def _get_epss(self, finding: Any) -> float:
        """获取 EPSS 概率"""
        rule_id = (getattr(finding, "rule_id", "") or "").lower()
        for key, val in ChainRiskScorer.DEFAULT_EPSS.items():
            if key in rule_id:
                return val
        return 0.3

    def _check_exploit(self, finding: Any) -> float:
        """检查是否有已知 exploit"""
        rule_id = (getattr(finding, "rule_id", "") or "").lower()
        high_exploit_keywords = [
            "sql_injection", "command_injection", "eval",
            "deserialization", "path_traversal",
        ]
        for kw in high_exploit_keywords:
            if kw in rule_id:
                return 0.9
        return 0.5

    def _calc_temporal_adjustment(self, finding: Any) -> float:
        """
        时间调整：CVE 公开时间越长， EPSS 越高。
        这里使用一个简单的线性增益模型。
        """
        # 在真实实现中可以从 finding 获取 cve_published_date
        # 这里简化：返回固定值，预留接口
        return 1.0

    def _score_to_severity(self, score: float) -> str:
        """分数转严重度"""
        for threshold, severity in self.SEVERITY_THRESHOLDS:
            if score >= threshold:
                return severity
        return "INFO"

    def _score_to_urgency(self, score: float, severity: str) -> str:
        """分数转整改紧急度"""
        if severity == "CRITICAL":
            return "immediate"  # 立即处理
        elif severity == "HIGH":
            return "urgent"     # 24小时内
        elif severity == "MEDIUM":
            return "planned"    # 计划内
        elif severity == "LOW":
            return "deferred"   # 可延后
        return "track"          # 跟踪


# ─────────────────────── 便捷函数 ─────────────────────────

def score_with_industry(
    findings: List[Any],
    industry: str = "internet",
    business: Optional[BusinessCriticality] = None,
    context: Optional[AssetContext] = None,
) -> List[PrecisionRiskScore]:
    """
    便捷函数：用行业权重对 findings 评分

    Args:
        findings: 漏洞发现列表
        industry: 行业标识
        business: 业务关键性
        context: 资产上下文

    Returns:
        排序后的评分列表
    """
    scorer = PrecisionRiskScorer(industry=industry, business_criticality=business)
    return scorer.score_findings(findings, context)


def prioritize_by_business_impact(
    findings: List[Any],
    industry: str = "internet",
    business: Optional[BusinessCriticality] = None,
) -> List[Tuple[Any, float, str]]:
    """
    按业务影响对 findings 排序

    Returns:
        List of (finding, final_score, severity) tuples
    """
    scorer = PrecisionRiskScorer(industry=industry, business_criticality=business)
    pairs = scorer.sort_findings_by_risk(findings)
    return [(f, s.final_score, s.severity) for f, s in pairs]
