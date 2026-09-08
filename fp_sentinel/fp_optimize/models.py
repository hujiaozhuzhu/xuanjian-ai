"""
玄鉴 v3.0 — 自适应误报引擎数据模型 (Adaptive FP Engine Models)

定义用户反馈、优化记录、代码风格特征等核心数据结构
版本: 3.0.0
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Literal
from enum import Enum
from datetime import datetime


# ─────────────────────── 枚举定义 ───────────────────────

class FeedbackType(str, Enum):
    """反馈类型"""
    FALSE_POSITIVE = "false_positive"   # 标记为误报
    TRUE_POSITIVE = "true_positive"     # 标记为真实漏洞
    UNSURE = "unsure"                   # 不确定


class FeedbackSource(str, Enum):
    """反馈来源"""
    MANUAL = "manual"                   # 用户手动标记
    AUTO_LEARNED = "auto_learned"       # 自动学习推断
    RULE_DERIVED = "rule_derived"       # 规则推导


class OptimizationStatus(str, Enum):
    """优化状态"""
    PENDING = "pending"                 # 待应用
    APPLIED = "applied"                 # 已应用
    ROLLED_BACK = "rolled_back"         # 已回滚
    REJECTED = "rejected"               # 已拒绝


# ─────────────────────── 反馈模型 ───────────────────────

class UserFeedback(BaseModel):
    """用户反馈记录"""
    id: Optional[str] = Field(None, description="反馈唯一ID")
    finding_id: str = Field(..., description="关联的发现ID")
    project_id: Optional[str] = Field(None, description="项目ID")
    feedback_type: FeedbackType = Field(..., description="反馈类型")
    source: FeedbackSource = Field(FeedbackSource.MANUAL, description="反馈来源")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="反馈置信度")
    reason: Optional[str] = Field(None, description="反馈原因/备注")
    marker: Optional[str] = Field(None, description="标记人")
    rule_id: Optional[str] = Field(None, description="关联规则ID")
    scanner: Optional[str] = Field(None, description="扫描工具")
    fingerprint: Optional[str] = Field(None, description="漏洞指纹")
    code_snippet: Optional[str] = Field(None, description="代码片段")
    file_path: Optional[str] = Field(None, description="文件路径")
    severity: Optional[str] = Field(None, description="严重程度")
    created_at: Optional[datetime] = Field(None, description="创建时间")


class FeedbackBatchRequest(BaseModel):
    """批量反馈请求"""
    feedbacks: List[Dict[str, Any]] = Field(..., description="反馈列表")


# ─────────────────────── 优化记录模型 ───────────────────────

class OptimizationRecord(BaseModel):
    """规则优化记录"""
    id: Optional[str] = Field(None, description="记录唯一ID")
    feedback_count: int = Field(0, description="触发优化的反馈样本数")
    status: OptimizationStatus = Field(OptimizationStatus.PENDING, description="优化状态")
    layer: Optional[str] = Field(None, description="目标层级 (L1/L2/L3)")
    rule_id: Optional[str] = Field(None, description="目标规则ID")
    adjustment_type: Optional[str] = Field(None, description="调整类型")
    old_value: Optional[float] = Field(None, description="调整前值")
    new_value: Optional[float] = Field(None, description="调整后值")
    fp_rate_before: Optional[float] = Field(None, description="优化前误报率")
    fp_rate_after: Optional[float] = Field(None, description="优化后误报率")
    description: Optional[str] = Field(None, description="优化描述")
    applied_at: Optional[datetime] = Field(None, description="应用时间")
    created_at: Optional[datetime] = Field(None, description="创建时间")


# ─────────────────────── 个性化模型 ───────────────────────

class CodeStyleProfile(BaseModel):
    """企业代码风格画像"""
    project_id: str = Field(..., description="项目ID")
    common_patterns: Dict[str, int] = Field(default_factory=dict, description="常见代码模式及出现次数")
    framework_hints: List[str] = Field(default_factory=list, description="检测到的框架特征")
    package_prefixes: List[str] = Field(default_factory=list, description="常用包前缀")
    security_patterns: Dict[str, int] = Field(default_factory=dict, description="安全编码模式统计")
    fp_prone_rules: Dict[str, float] = Field(default_factory=dict, description="容易误报的规则及FP概率")
    total_scans: int = Field(0, description="总扫描次数")
    total_findings: int = Field(0, description="总发现数")
    total_feedbacks: int = Field(0, description="总反馈数")
    current_fp_rate: float = Field(0.0, description="当前误报率 (0-1)")
    updated_at: Optional[datetime] = Field(None, description="最后更新时间")


# ─────────────────────── 统计模型 ───────────────────────

class FpRateTrendPoint(BaseModel):
    """误报率趋势数据点"""
    timestamp: datetime = Field(..., description="时间点")
    fp_rate: float = Field(..., description="误报率 (0-1)")
    total_findings: int = Field(0, description="总发现数")
    fp_count: int = Field(0, description="误报数")
    tp_count: int = Field(0, description="真实漏洞数")
    feedback_count: int = Field(0, description="反馈数")


class FeedbackStatistics(BaseModel):
    """反馈统计"""
    total_feedbacks: int = Field(0, description="总反馈数")
    fp_feedbacks: int = Field(0, description="误报反馈数")
    tp_feedbacks: int = Field(0, description="真实漏洞反馈数")
    unsure_feedbacks: int = Field(0, description="不确定反馈数")
    fp_rate: float = Field(0.0, description="当前误报率")
    target_fp_rate: float = Field(0.01, description="目标误报率 (1%)")
    fp_rate_trend: str = Field("stable", description="误报率趋势 (decreasing/stable/increasing)")
    optimization_count: int = Field(0, description="优化次数")
    last_optimization_at: Optional[datetime] = Field(None, description="最后优化时间")
    top_fp_rules: List[Dict[str, Any]] = Field(default_factory=list, description="高频误报规则TOP10")
    top_fp_files: List[Dict[str, Any]] = Field(default_factory=list, description="高频误报文件TOP10")


class OptimizationEffect(BaseModel):
    """优化效果统计"""
    optimization_id: str = Field(..., description="优化记录ID")
    fp_rate_before: float = Field(0.0, description="优化前误报率")
    fp_rate_after: float = Field(0.0, description="优化后误报率")
    absolute_improvement: float = Field(0.0, description="绝对改善 (百分点)")
    relative_improvement_pct: float = Field(0.0, description="相对改善百分比")
    sample_size: int = Field(0, description="样本量")
    is_effective: bool = Field(False, description="是否有效 (误报率下降)")


class DashboardData(BaseModel):
    """仪表板综合数据"""
    feedback_stats: FeedbackStatistics = Field(default_factory=FeedbackStatistics)
    trend_points: List[FpRateTrendPoint] = Field(default_factory=list)
    recent_optimizations: List[OptimizationEffect] = Field(default_factory=list)
    style_profile: Optional[CodeStyleProfile] = Field(None, description="代码风格画像")
