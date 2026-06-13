"""
数据模型定义

定义扫描结果、过滤结果等核心数据结构
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Literal
from enum import Enum


class Severity(str, Enum):
    """漏洞严重程度"""
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


class ScanTool(str, Enum):
    """支持的扫描工具"""
    SEMGREP = "semgrep"
    BANDIT = "bandit"
    GOSEC = "gosec"


class ScanResult(BaseModel):
    """扫描结果单条记录"""
    tool: ScanTool = Field(..., description="扫描工具")
    rule_id: str = Field(..., description="规则ID")
    file: str = Field(..., description="文件路径")
    line: int = Field(..., description="行号")
    column: Optional[int] = Field(None, description="列号")
    code: str = Field(..., description="问题代码片段")
    severity: Severity = Field(..., description="严重程度")
    message: str = Field(..., description="问题描述")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="额外元数据")


class FilterReason(BaseModel):
    """过滤原因"""
    filter_level: Literal["L1", "L2", "L3"] = Field(..., description="过滤层级")
    rule_name: str = Field(..., description="触发的规则名称")
    description: str = Field(..., description="详细描述")
    confidence: float = Field(..., description="置信度 0-1")


class FilterResult(BaseModel):
    """单条过滤结果"""
    original: ScanResult = Field(..., description="原始扫描结果")
    is_false_positive: bool = Field(..., description="是否为误报")
    confidence: float = Field(..., description="总体置信度 0-1")
    filter_reasons: List[FilterReason] = Field(default_factory=list, description="过滤原因列表")
    risk_score: float = Field(..., description="风险评分 0-10")
    recommendation: str = Field(..., description="处理建议")
    context_analysis: Optional[Dict[str, Any]] = Field(None, description="上下文分析详情")


class FilterStatistics(BaseModel):
    """过滤统计信息"""
    total: int = Field(..., description="总问题数")
    false_positives: int = Field(..., description="误报数")
    true_positives: int = Field(..., description="真实问题数")
    reduction_rate: str = Field(..., description="误报减少率")
    processing_time_ms: float = Field(..., description="处理时间(毫秒)")
    filter_level_stats: Dict[str, int] = Field(default_factory=dict, description="各层级过滤统计")


class FilterResponse(BaseModel):
    """过滤响应"""
    filtered_results: List[FilterResult] = Field(..., description="过滤后的结果")
    statistics: FilterStatistics = Field(..., description="统计信息")
    model_version: str = Field(default="1.0.0", description="模型版本")


class ContextAnalysisRequest(BaseModel):
    """上下文分析请求"""
    file_path: str = Field(..., description="文件路径")
    line_number: int = Field(..., description="行号")
    context_lines: int = Field(default=10, description="上下文行数")
    check_types: List[str] = Field(
        default=["dead_code", "security_guards", "input_validation"],
        description="检查类型"
    )


class ContextAnalysisResult(BaseModel):
    """上下文分析结果"""
    file_path: str = Field(..., description="文件路径")
    line_number: int = Field(..., description="行号")
    is_dead_code: bool = Field(default=False, description="是否为死代码")
    has_security_guards: bool = Field(default=False, description="是否有安全守卫")
    has_input_validation: bool = Field(default=False, description="是否有输入验证")
    data_flow_length: int = Field(default=0, description="数据流长度")
    complexity_score: float = Field(default=0.0, description="代码复杂度评分")
    context_features: Dict[str, Any] = Field(default_factory=dict, description="上下文特征")


class TrainingDataItem(BaseModel):
    """训练数据项"""
    features: Dict[str, Any] = Field(..., description="特征")
    is_false_positive: bool = Field(..., description="是否为误报")
    metadata: Optional[Dict[str, Any]] = Field(None, description="元数据")


class TrainingRequest(BaseModel):
    """训练请求"""
    training_data: List[TrainingDataItem] = Field(..., description="训练数据")
    model_type: Literal["random_forest", "gradient_boosting", "svm"] = Field(
        default="random_forest",
        description="模型类型"
    )
    validation_split: float = Field(default=0.2, description="验证集比例")
    feature_columns: Optional[List[str]] = Field(None, description="特征列名")


class TrainingResult(BaseModel):
    """训练结果"""
    model_path: str = Field(..., description="模型保存路径")
    accuracy: float = Field(..., description="准确率")
    precision: float = Field(..., description="精确率")
    recall: float = Field(..., description="召回率")
    f1_score: float = Field(..., description="F1分数")
    training_samples: int = Field(..., description="训练样本数")
    validation_samples: int = Field(..., description="验证样本数")