"""
数据模型定义

定义扫描结果、过滤结果等核心数据结构
支持 Pydantic v2，兼容 Python 3.10+
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Literal
from enum import Enum
from datetime import datetime


# ─────────────────────────── 枚举 ───────────────────────────

class Severity(str, Enum):
    """漏洞严重程度"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScanTool(str, Enum):
    """支持的扫描工具"""
    SEMGREP = "semgrep"
    BANDIT = "bandit"
    GOSEC = "gosec"
    FINDSECBUGS = "findsecbugs"
    SPOTBUGS = "spotbugs"
    MANUAL = "manual"


class Verdict(str, Enum):
    """判定结果"""
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"
    NEEDS_REVIEW = "needs_review"


class Language(str, Enum):
    """支持的编程语言"""
    JAVA = "java"
    PYTHON = "python"
    GO = "go"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    AUTO = "auto"


# ─────────────────────── 核心业务模型 ───────────────────────

class Finding(BaseModel):
    """代码安全发现（统一归一化模型）"""
    id: Optional[str] = Field(None, description="发现唯一ID")
    scanner: str = Field(..., description="来源扫描器名称")
    rule_id: str = Field(..., description="规则ID")
    severity: Severity = Field(..., description="严重程度")
    file_path: str = Field(..., description="文件路径")
    line_start: int = Field(..., description="起始行号")
    line_end: Optional[int] = Field(None, description="结束行号")
    code_snippet: str = Field("", description="问题代码片段")
    message: str = Field(..., description="问题描述")
    category: Optional[str] = Field(None, description="漏洞类别(如 SQL_INJECTION, XSS)")
    language: Optional[str] = Field(None, description="编程语言")
    fingerprint: Optional[str] = Field(None, description="结果指纹(用于去重)")
    cwe: Optional[str] = Field(None, description="CWE编号")
    owasp: Optional[str] = Field(None, description="OWASP分类")
    confidence: float = Field(0.0, description="扫描器置信度 0-1")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="额外元数据")
    created_at: Optional[datetime] = Field(None, description="创建时间")


class ScanResult(BaseModel):
    """扫描结果单条记录"""
    id: Optional[str] = Field(None, description="结果唯一ID")
    tool: ScanTool = Field(..., description="扫描工具")
    rule_id: str = Field(..., description="规则ID")
    file: str = Field(..., description="文件路径")
    line: int = Field(..., description="行号")
    column: Optional[int] = Field(None, description="列号")
    end_line: Optional[int] = Field(None, description="结束行号")
    code: str = Field("", description="问题代码片段")
    severity: Severity = Field(..., description="严重程度")
    message: str = Field(..., description="问题描述")
    cwe: Optional[str] = Field(None, description="CWE编号")
    owasp: Optional[str] = Field(None, description="OWASP分类")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="额外元数据")
    timestamp: Optional[str] = Field(None, description="扫描时间戳")


class FilterReason(BaseModel):
    """过滤原因"""
    filter_level: Literal["L1", "L2", "L3"] = Field(..., description="过滤层级")
    rule_name: str = Field(..., description="触发的规则名称")
    description: str = Field(..., description="详细描述")
    confidence: float = Field(..., description="置信度 0-1")


class FilterResult(BaseModel):
    """单条过滤结果"""
    id: Optional[str] = Field(None, description="结果唯一ID")
    original: ScanResult = Field(..., description="原始扫描结果")
    verdict: Verdict = Field(..., description="判定结果")
    confidence: float = Field(..., description="总体置信度 0-1")
    filter_reasons: List[FilterReason] = Field(default_factory=list, description="过滤原因列表")
    risk_score: float = Field(..., description="风险评分 0-10")
    recommendation: str = Field(..., description="处理建议")
    context_analysis: Optional[Dict[str, Any]] = Field(None, description="上下文分析详情")
    java_analysis: Optional[Dict[str, Any]] = Field(None, description="Java特定分析详情")

    @property
    def is_false_positive(self) -> bool:
        """是否被判定为误报"""
        return self.verdict in (Verdict.FALSE_POSITIVE, Verdict.LIKELY_FALSE_POSITIVE)


# ─────────────────────── 项目 / 仓库模型 ───────────────────────

class Project(BaseModel):
    """项目信息"""
    id: Optional[str] = Field(None, description="项目唯一ID")
    name: str = Field(..., description="项目名称")
    path: str = Field(..., description="项目路径")
    language: str = Field("auto", description="主要语言")
    description: Optional[str] = Field(None, description="项目描述")
    created_at: Optional[datetime] = Field(None, description="创建时间")
    updated_at: Optional[datetime] = Field(None, description="更新时间")


class FalsePositiveMark(BaseModel):
    """误报标记"""
    id: Optional[int] = Field(None, description="标记ID")
    finding_id: str = Field(..., description="关联的Finding ID")
    reason: str = Field(..., description="标记为误报的原因")
    marked_by: str = Field("manual", description="标记来源(manual/auto/rule)")
    scope: str = Field("instance", description="作用域(instance/rule/global)")
    confidence: float = Field(1.0, description="标记置信度 0-1")
    created_at: Optional[datetime] = Field(None, description="标记时间")


class ScanHistory(BaseModel):
    """扫描历史记录"""
    id: Optional[int] = Field(None, description="记录ID")
    scan_id: str = Field(..., description="扫描唯一ID(如UUID)")
    project_id: Optional[str] = Field(None, description="项目ID")
    project_path: str = Field(..., description="项目路径")
    scanner: str = Field(..., description="扫描器名称")
    language: Optional[str] = Field(None, description="扫描语言")
    total_findings: int = Field(0, description="总发现数")
    duration_seconds: float = Field(0.0, description="扫描耗时(秒)")
    status: str = Field("completed", description="扫描状态(completed/failed/cancelled)")
    error_message: Optional[str] = Field(None, description="错误信息")
    timestamp: Optional[datetime] = Field(None, description="扫描时间")


# ─────────────────────── 统计 / 配置模型 ───────────────────────

class FilterStatistics(BaseModel):
    """过滤统计信息"""
    total: int = Field(..., description="总问题数")
    false_positives: int = Field(..., description="误报数")
    likely_false_positives: int = Field(..., description="疑似误报数")
    true_positives: int = Field(..., description="真实问题数")
    needs_review: int = Field(..., description="待复核数")
    reduction_rate: str = Field(..., description="误报减少率")
    processing_time_ms: float = Field(..., description="处理时间(毫秒)")
    filter_level_stats: Dict[str, int] = Field(default_factory=dict, description="各层级过滤统计")


class FilterResponse(BaseModel):
    """过滤响应"""
    filtered_results: List[FilterResult] = Field(..., description="过滤后的结果")
    statistics: FilterStatistics = Field(..., description="统计信息")
    model_version: str = Field(default="0.1.0", description="模型版本")


class ContextAnalysisResult(BaseModel):
    """上下文分析结果"""
    file_path: str = Field(..., description="文件路径")
    line_number: int = Field(..., description="行号")
    is_dead_code: bool = Field(default=False, description="是否为死代码")
    has_security_guards: bool = Field(default=False, description="是否有安全守卫")
    has_input_validation: bool = Field(default=False, description="是否有输入验证")
    is_in_test: bool = Field(default=False, description="是否在测试代码中")
    is_in_debug_branch: bool = Field(default=False, description="是否在调试分支中")
    data_flow_length: int = Field(default=0, description="数据流长度")
    complexity_score: float = Field(default=0.0, description="代码复杂度评分")
    context_features: Dict[str, Any] = Field(default_factory=dict, description="上下文特征")


class JavaAnalysisResult(BaseModel):
    """Java特定分析结果"""
    uses_prepared_statement: bool = Field(default=False, description="是否使用PreparedStatement")
    uses_orm: bool = Field(default=False, description="是否使用ORM框架")
    uses_mybatis_hash: bool = Field(default=False, description="是否使用MyBatis #{}参数绑定")
    uses_mybatis_dollar: bool = Field(default=False, description="是否使用MyBatis ${}字符串替换")
    has_input_validation: bool = Field(default=False, description="是否有输入校验")
    has_url_whitelist: bool = Field(default=False, description="是否有URL白名单")
    has_command_whitelist: bool = Field(default=False, description="是否有命令白名单")
    uses_html_escape: bool = Field(default=False, description="是否使用HTML转义")
    response_type: Optional[str] = Field(None, description="响应类型(json/html)")
    is_constant_value: bool = Field(default=False, description="是否为常量值")
    framework_hints: List[str] = Field(default_factory=list, description="框架提示")
    confidence_adjustment: float = Field(default=0.0, description="置信度调整值")


class ProjectConfig(BaseModel):
    """项目配置"""
    name: str = Field(..., description="项目名称")
    path: str = Field(..., description="项目路径")
    language: Literal["java", "python", "go", "auto"] = Field(default="auto", description="主要语言")
    scanners: List[ScanTool] = Field(default_factory=lambda: [ScanTool.SEMGREP], description="扫描工具列表")
    ignore_paths: List[str] = Field(default_factory=list, description="忽略路径")
    custom_rules: List[str] = Field(default_factory=list, description="自定义规则文件")
    false_positive_rules: List[Dict[str, Any]] = Field(default_factory=list, description="误报规则")


class ProjectStats(BaseModel):
    """项目统计"""
    project_name: str = Field(..., description="项目名称")
    total_scans: int = Field(default=0, description="总扫描次数")
    total_findings: int = Field(default=0, description="总发现数")
    false_positives: int = Field(default=0, description="误报数")
    true_positives: int = Field(default=0, description="真实问题数")
    needs_review: int = Field(default=0, description="待复核数")
    last_scan_time: Optional[str] = Field(None, description="最后扫描时间")
    reduction_rate: str = Field(default="0%", description="误报减少率")


# ─────────────────────── ScanResult -> Finding 转换 ───────────────────────

def scan_result_to_finding(result: ScanResult) -> Finding:
    """将 ScanResult 转换为归一化的 Finding 模型"""
    return Finding(
        scanner=result.tool.value,
        rule_id=result.rule_id,
        severity=result.severity,
        file_path=result.file,
        line_start=result.line,
        line_end=result.end_line,
        code_snippet=result.code,
        message=result.message,
        category=result.metadata.get("category") if result.metadata else None,
        language=result.metadata.get("language") if result.metadata else None,
        fingerprint=result.id,
        cwe=result.cwe,
        owasp=result.owasp,
        confidence=result.metadata.get("confidence", 0.0) if result.metadata else 0.0,
        metadata=result.metadata,
    )
