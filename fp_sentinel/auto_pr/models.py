"""
玄鉴 v3.0 — 自动化修复模块数据模型

定义修复生成、验证、PR管理的核心数据结构

安全红线：
- S1: 不适用（纯数据模型）
- S2: 不修改源文件（模型仅描述修复建议）
- S3: 不删除文件
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


# ─────────────────────────── 枚举 ───────────────────────────

class VulnerabilityType(str, Enum):
    """漏洞类型枚举"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    HARDCODED_SECRET = "hardcoded_secret"
    JWT_WEAK = "jwt_weak"
    YAML_UNSAFE = "yaml_unsafe"
    PICKLE_DESERIALIZE = "pickle_deserialize"
    EVAL_INJECTION = "eval_injection"
    SSRF = "ssrf"
    WEAK_HASH = "weak_hash"
    ECB_MODE = "ecb_mode"
    DEBUG_EXPOSURE = "debug_exposure"
    OPEN_REDIRECT = "open_redirect"
    OS_COMMAND = "os_command"
    # v3.0: Java/PHP反序列化专项
    JAVA_NATIVE_DESERIALIZE = "java_native_deserialize"
    JAVA_FASTJSON_DESERIALIZE = "java_fastjson_deserialize"
    JAVA_JACKSON_DESERIALIZE = "java_jackson_deserialize"
    SHIRO_REMEMBERME = "shiro_rememberme"
    PHP_UNSERIALIZE = "php_unserialize"
    PHP_PHAR_DESERIALIZE = "php_phar_deserialize"
    OBJECT_INPUT_STREAM = "object_input_stream"
    GENERIC = "generic"


class FixStatus(str, Enum):
    """修复记录状态"""
    PENDING = "pending"           # 待处理
    GENERATING = "generating"     # 生成中
    READY = "ready"              # 修复代码已生成，待验证
    VALIDATING = "validating"    # 验证中
    VERIFIED = "verified"        # 验证通过
    VERIFICATION_FAILED = "verification_failed"  # 验证失败
    SUBMITTED = "submitted"      # 已提交PR
    MERGED = "merged"           # PR已合并
    CLOSED = "closed"           # 已关闭
    REJECTED = "rejected"       # 被拒绝


class VerificationStatus(str, Enum):
    """验证状态"""
    PASS = "pass"               # 通过
    WARN = "warn"               # 警告（有潜在风险但可接受）
    FAIL = "fail"               # 失败（引入新漏洞或未修复原漏洞）
    NOT_VERIFIED = "not_verified"  # 未验证


# ─────────────────────────── 修复相关模型 ───────────────────────────

class FixDiff(BaseModel):
    """修复Diff条目"""
    model_config = ConfigDict(extra="ignore")

    file_path: str = Field(..., description="文件路径")
    original_code: str = Field("", description="原始代码片段")
    fixed_code: str = Field(..., description="修复后代码片段")
    line_start: int = Field(1, description="起始行号")
    line_end: int = Field(1, description="结束行号")
    description: str = Field("", description="修复说明")


class FixPatch(BaseModel):
    """修复补丁"""
    model_config = ConfigDict(extra="ignore")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="补丁ID")
    finding_id: str = Field(..., description="关联的Finding ID")
    vuln_type: VulnerabilityType = Field(..., description="漏洞类型")
    title: str = Field("", description="修复标题")
    diffs: List[FixDiff] = Field(default_factory=list, description="修复Diff列表")
    effort_minutes: int = Field(0, description="预计工时(分钟)")
    reference_cve: str = Field("", description="参考CVE")
    incident_note: str = Field("", description="事故说明")
    confidence: float = Field(0.8, description="修复置信度")
    generic: bool = Field(False, description="是否为通用建议")
    custom_modifications: Dict[str, str] = Field(default_factory=dict, description="自定义修改")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class FixPreview(BaseModel):
    """修复预览（Diff预览用）"""
    model_config = ConfigDict(extra="ignore")

    finding_id: str = Field(..., description="Finding ID")
    rule_id: str = Field(..., description="规则ID")
    severity: str = Field("", description="严重度")
    file_path: str = Field("", description="文件路径")
    vuln_type: VulnerabilityType = Field(..., description="漏洞类型")
    unified_diff: str = Field("", description="Unified Diff文本")
    title: str = Field("", description="修复标题")
    effort_minutes: int = Field(0, description="预计工时")
    reference_cve: str = Field("", description="参考CVE")
    can_customize: bool = Field(True, description="是否支持自定义修改")


class FixVerificationResult(BaseModel):
    """修复验证结果"""
    model_config = ConfigDict(extra="ignore")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="验证ID")
    patch_id: str = Field(..., description="关联的补丁ID")
    finding_id: str = Field(..., description="关联的Finding ID")
    status: VerificationStatus = Field(default=VerificationStatus.NOT_VERIFIED, description="验证状态")
    original_vuln_resolved: bool = Field(False, description="原漏洞是否已修复")
    new_vulns_introduced: int = Field(0, description="引入的新漏洞数")
    syntax_valid: bool = Field(True, description="语法是否有效")
    security_check_passed: bool = Field(True, description="安全检查是否通过")
    details: List[str] = Field(default_factory=list, description="验证详情")
    warnings: List[str] = Field(default_factory=list, description="警告信息")
    verified_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─────────────────────────── PR相关模型 ───────────────────────────

class PullRequestRecord(BaseModel):
    """Pull Request 记录"""
    model_config = ConfigDict(extra="ignore")

    id: Optional[int] = Field(None, description="自增ID")
    pr_id: str = Field("", description="外部PR ID")
    pr_url: str = Field("", description="PR URL")
    pr_title: str = Field("", description="PR标题")
    provider: str = Field(..., description="平台: gitlab/github")
    project_id: str = Field("", description="项目ID")
    repository_url: str = Field("", description="仓库URL")
    branch: str = Field("", description="修复分支名")
    base_branch: str = Field("main", description="基准分支")
    status: str = Field("open", description="PR状态: open/merged/closed")
    patch_ids: List[str] = Field(default_factory=list, description="关联的补丁IDs")
    finding_ids: List[str] = Field(default_factory=list, description="关联的Finding IDs")
    ticket_ids: List[str] = Field(default_factory=list, description="关联的工单IDs")
    commit_hash: str = Field("", description="修复提交Hash")
    verification_id: str = Field("", description="验证结果ID")
    merge_commit_hash: str = Field("", description="合并后的commit hash")
    merged_by: str = Field("", description="合并人")
    merged_at: str = Field("", description="合并时间")
    description: str = Field("", description="PR详情描述")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─────────────────────────── 历史记录模型 ───────────────────────────

class FixRecord(BaseModel):
    """修复历史记录"""
    model_config = ConfigDict(extra="ignore")

    id: Optional[int] = Field(None, description="自增ID")
    finding_id: str = Field(..., description="关联的Finding ID")
    rule_id: str = Field("", description="规则ID")
    severity: str = Field("", description="严重度")
    file_path: str = Field("", description="文件路径")
    vuln_type: VulnerabilityType = Field(..., description="漏洞类型")
    status: FixStatus = Field(default=FixStatus.PENDING, description="修复状态")
    patch_id: str = Field("", description="关联的补丁ID")
    pr_id: str = Field("", description="关联的PR ID")
    pr_url: str = Field("", description="PR URL")
    fix_title: str = Field("", description="修复标题")
    fix_diff_summary: str = Field("", description="修复摘要")
    verification_status: VerificationStatus = Field(default=VerificationStatus.NOT_VERIFIED)
    effort_minutes: int = Field(0, description="预计工时")
    error_message: str = Field("", description="错误信息")
    project_id: str = Field("", description="项目ID")
    repository_url: str = Field("", description="仓库URL")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─────────────────────────── 配置模型 ───────────────────────────

class AutoPRConfig(BaseModel):
    """自动修复配置"""
    model_config = ConfigDict(extra="forbid")

    provider: str = Field(default="gitlab", description="Git平台: gitlab/github")
    base_url: str = Field(default="", description="API基础URL")
    api_token: str = Field(default="", description="API Token")
    project_id: str = Field(default="", description="项目ID")
    default_branch: str = Field(default="main", description="默认基准分支")
    fix_branch_prefix: str = Field(default="xuanjian-fix/", description="修复分支前缀")
    auto_verify: bool = Field(default=True, description="提交前自动验证")
    auto_submit_pr: bool = Field(default=False, description="验证通过后自动提交PR")
    auto_link_ticket: bool = Field(default=True, description="自动关联工单")
    verify_severity_threshold: str = Field(default="HIGH", description="最低验证严重度")
    max_fix_per_run: int = Field(default=50, description="单次最大修复数")
    timeout_seconds: int = Field(default=30, description="API请求超时")
    dry_run: bool = Field(default=False, description="仅生成不提交")


# ─────────────────────────── 统计模型 ───────────────────────────

class PRStats(BaseModel):
    """PR管理统计"""
    model_config = ConfigDict(extra="ignore")

    total_fixes: int = Field(default=0, description="总修复数")
    pending_fixes: int = Field(default=0, description="待处理数")
    verified_fixes: int = Field(default=0, description="验证通过数")
    failed_verifications: int = Field(default=0, description="验证失败数")
    submitted_prs: int = Field(default=0, description="已提交PR数")
    merged_prs: int = Field(default=0, description="已合并PR数")
    closed_prs: int = Field(default=0, description="已关闭PR数")
    avg_effort_minutes: float = Field(default=0.0, description="平均工时")
    by_vuln_type: Dict[str, int] = Field(default_factory=dict, description="按漏洞类型统计")
    by_severity: Dict[str, int] = Field(default_factory=dict, description="按严重度统计")
    by_provider: Dict[str, int] = Field(default_factory=dict, description="按平台统计")
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─────────────────────────── 操作请求模型 ───────────────────────────

class GenerateFixRequest(BaseModel):
    """生成修复请求"""
    model_config = ConfigDict(extra="ignore")

    finding_id: str = Field(..., description="Finding ID")
    rule_id: str = Field(..., description="规则ID")
    severity: str = Field("", description="严重度")
    file_path: str = Field("", description="文件路径")
    code_snippet: str = Field("", description="代码片段")
    message: str = Field("", description="漏洞描述")
    category: str = Field("", description="漏洞类别")
    language: str = Field("", description="编程语言")
    cwe: str = Field("", description="CWE编号")


class VerifyFixRequest(BaseModel):
    """验证修复请求"""
    model_config = ConfigDict(extra="ignore")

    patch_id: str = Field(..., description="补丁ID")
    finding_id: str = Field(..., description="Finding ID")
    original_code: str = Field("", description="原始代码")
    fixed_code: str = Field("", description="修复后代码")
    rule_id: str = Field("", description="规则ID")
    vuln_type: VulnerabilityType = Field(..., description="漏洞类型")


class SubmitPRRequest(BaseModel):
    """提交PR请求"""
    model_config = ConfigDict(extra="ignore")

    config: AutoPRConfig = Field(..., description="PR配置")
    patch_ids: List[str] = Field(..., description="补丁IDs")
    finding_ids: List[str] = Field(..., description="Finding IDs")
    title: str = Field("", description="PR标题")
    description: str = Field("", description="PR描述")
    ticket_ids: List[str] = Field(default_factory=list, description="关联工单IDs")
    labels: List[str] = Field(default_factory=list, description="PR标签")
