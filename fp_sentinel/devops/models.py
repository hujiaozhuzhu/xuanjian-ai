"""
玄鉴 v3.0 — DevSecOps 对接模块 (DevSecOps Integration)

数据模型定义：
- GitLab/Jira 对接：扫描结果自动同步为 Issue/工单，关联代码仓库与提交
- Pipeline 卡点：在 CI/CD 流水线中添加安全质量门，高危漏洞自动阻断
- 工单状态联动：漏洞修复后自动关闭工单、更新状态

安全红线：
- S1: 零网络（API 调用隔离到适配器层，测试可注入 mock HTTP client）
- S2: 不修改被扫描源代码（sync 仅对外发送 Issue，不写磁盘代码）
- S3: 不删除文件（工单联动仅调用外部 API，本地操作只增不改不删）
- S5: 数据清理（同步记录保留周期可配置，默认 90 天）
- S7: 数据库路径固定于 ~/.xuanjian/
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


# ─────────────────────────── 枚举 ───────────────────────────

class DevOpsProvider(str, Enum):
    """对接平台类型"""
    GITLAB = "gitlab"
    JIRA = "jira"
    GITHUB = "github"


class SyncDirection(str, Enum):
    """同步方向"""
    FINDING_TO_TICKET = "finding_to_ticket"   # 扫描发现 → 工单
    TICKET_TO_LOCAL = "ticket_to_local"       # 工单状态 → 本地


class SyncStatus(str, Enum):
    """同步记录状态"""
    PENDING = "pending"       # 待同步
    SYNCED = "synced"         # 同步成功
    FAILED = "failed"         # 同步失败
    SKIPPED = "skipped"       # 已跳过（去重/配置关闭）


class TicketStatus(str, Enum):
    """外部工单状态"""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    REOPENED = "reopened"


class PipelineGateVerdict(str, Enum):
    """Pipeline 卡点判定结果"""
    PASS = "pass"             # 通过
    WARN = "warn"             # 警告（有中危，可合并但告警）
    BLOCK = "block"           # 阻断（存在高危/严重漏洞）


class WebhookEventType(str, Enum):
    """Webhook 事件类型"""
    ISSUE_CLOSED = "issue_closed"
    ISSUE_REOPENED = "issue_reopened"
    MERGE_REQUEST = "merge_request"
    PIPELINE_STATUS = "pipeline_status"


# ─────────────────────────── 配置模型 ───────────────────────────

class DevOpsConfig(BaseModel):
    """DevOps 平台连接配置"""
    model_config = ConfigDict(extra="forbid")

    provider: DevOpsProvider = Field(..., description="平台类型")
    base_url: str = Field(..., description="API 基础 URL")
    api_token: str = Field("", description="API Token（建议通过环境变量注入）")
    project_id: str = Field("", description="GitLab/GitHub 项目 ID 或路径")
    jira_project_key: str = Field("", description="Jira 项目 Key")
    default_labels: List[str] = Field(default_factory=list, description="默认标签")
    # 卡点阈值配置
    block_on_critical: bool = Field(default=True, description="严重漏洞是否阻断")
    block_on_high: bool = Field(default=True, description="高危漏洞是否阻断")
    warn_on_medium: bool = Field(default=True, description="中危漏洞是否告警")
    warn_on_low: bool = Field(default=False, description="低危漏洞是否告警")
    max_findings_threshold: int = Field(default=0, description="最大允许发现数（0=不限制）")
    # 联动配置
    auto_close_on_resolve: bool = Field(default=True, description="漏洞修复后自动关闭工单")
    auto_link_commit: bool = Field(default=True, description="自动关联修复提交")
    sync_interval_minutes: int = Field(default=60, description="同步间隔（分钟）")
    # API 高级配置
    timeout_seconds: int = Field(default=30, description="API 请求超时(秒)")
    verify_ssl: bool = Field(default=True, description="是否校验 SSL")
    # 重试配置
    max_retries: int = Field(default=3, description="最大重试次数")
    retry_delay_seconds: float = Field(default=1.0, description="重试间隔秒")


# ─────────────────────────── 同步记录模型 ───────────────────────────

class FindingTicketMapping(BaseModel):
    """发现 ↔ 外部工单映射关系"""
    model_config = ConfigDict(extra="ignore")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="映射唯一 ID")
    finding_id: str = Field(..., description="玄鉴 Finding ID")
    finding_fingerprint: str = Field("", description="Finding 指纹（去重用）")
    provider: DevOpsProvider = Field(..., description="平台类型")
    ticket_id: str = Field(..., description="外部工单 ID")
    ticket_key: str = Field("", description="工单可读 Key（如 JIRA-123）")
    ticket_url: str = Field("", description="工单 URL")
    ticket_status: TicketStatus = Field(default=TicketStatus.OPEN, description="当前工单状态")
    project_id: str = Field("", description="关联项目 ID")
    repository_url: str = Field("", description="代码仓库 URL")
    commit_hash: str = Field("", description="触发同步的 commit hash")
    branch: str = Field("", description="关联分支")
    sync_status: SyncStatus = Field(default=SyncStatus.PENDING, description="同步状态")
    sync_direction: SyncDirection = Field(default=SyncDirection.FINDING_TO_TICKET, description="最新同步方向")
    severity: str = Field("", description="漏洞严重度")
    rule_id: str = Field("", description="规则 ID")
    title: str = Field("", description="工单标题缓存")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_sync_at: Optional[str] = Field(None, description="最后同步时间")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="额外元数据")


class SyncRecord(BaseModel):
    """同步操作流水记录"""
    model_config = ConfigDict(extra="ignore")

    id: Optional[int] = Field(None, description="自增 ID")
    mapping_id: str = Field(..., description="关联映射 ID")
    finding_id: str = Field(..., description="关联 Finding ID")
    provider: DevOpsProvider = Field(..., description="平台类型")
    sync_direction: SyncDirection = Field(..., description="同步方向")
    status: SyncStatus = Field(..., description="同步结果状态")
    ticket_id: str = Field("", description="外部工单 ID")
    ticket_key: str = Field("", description="工单 Key")
    request_payload: str = Field("", description="请求体 JSON 快照")
    response_summary: str = Field("", description="响应摘要")
    error_message: str = Field("", description="错误信息")
    attempt_count: int = Field(default=1, description="尝试次数")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─────────────────────────── Pipeline 卡点模型 ───────────────────────────

class FindingRef(BaseModel):
    """轻量化的发现引用（Pipeline 卡点评估用）"""
    model_config = ConfigDict(extra="ignore")

    id: str = Field("", description="发现 ID")
    severity: str = Field(..., description="严重度")
    rule_id: str = Field("", description="规则 ID")
    file_path: str = Field("", description="文件路径")
    line_start: int = Field(0, description="行号")
    message: str = Field("", description="描述")
    cwe: str = Field("", description="CWE")


class PipelineGateRequest(BaseModel):
    """Pipeline 卡点评估请求"""
    model_config = ConfigDict(extra="ignore")

    provider: DevOpsProvider = Field(..., description="平台类型")
    project_id: str = Field(..., description="项目 ID")
    repository_url: str = Field("", description="仓库 URL")
    commit_hash: str = Field("", description="提交 hash")
    branch: str = Field("", description="分支名")
    merge_request_id: str = Field("", description="合并请求 ID")
    findings: List[FindingRef] = Field(default_factory=list, description="发现列表")
    config: Optional[DevOpsConfig] = Field(None, description="卡点配置（可选，使用默认值）")


class FindingViolation(BaseModel):
    """单个发现违反卡点"""
    model_config = ConfigDict(extra="ignore")

    finding_id: str = Field("", description="发现 ID")
    severity: str = Field("", description="严重度")
    rule_id: str = Field("", description="规则 ID")
    file_path: str = Field("", description="文件路径")
    message: str = Field("", description="描述")
    violation_level: str = Field("", description="违反级别: block/warn")


class PipelineGateResult(BaseModel):
    """Pipeline 卡点评估结果"""
    model_config = ConfigDict(extra="ignore")

    verdict: PipelineGateVerdict = Field(..., description="判定结果")
    provider: DevOpsProvider = Field(..., description="平台类型")
    project_id: str = Field("", description="项目 ID")
    commit_hash: str = Field("", description="提交 hash")
    branch: str = Field("", description="分支名")
    total_findings: int = Field(0, description="总发现数")
    critical_count: int = Field(0, description="严重数")
    high_count: int = Field(0, description="高危数")
    medium_count: int = Field(0, description="中危数")
    low_count: int = Field(0, description="低危数")
    info_count: int = Field(0, description="信息数")
    violations: List[FindingViolation] = Field(default_factory=list, description="违反卡点的发现")
    warnings: List[FindingViolation] = Field(default_factory=list, description="告警发现")
    summary: str = Field("", description="摘要文本")
    suggested_actions: List[str] = Field(default_factory=list, description="建议操作")
    evaluated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─────────────────────────── Webhook 事件模型 ───────────────────────────

class WebhookPayload(BaseModel):
    """外部平台 Webhook 载荷"""
    model_config = ConfigDict(extra="ignore")

    event_type: WebhookEventType = Field(..., description="事件类型")
    provider: DevOpsProvider = Field(..., description="平台类型")
    payload: Dict[str, Any] = Field(default_factory=dict, description="原始载荷")
    signature: str = Field("", description="签名（用于校验）")
    received_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class TicketStatusChangeEvent(BaseModel):
    """工单状态变更事件"""
    model_config = ConfigDict(extra="ignore")

    provider: DevOpsProvider = Field(..., description="平台类型")
    ticket_id: str = Field(..., description="工单 ID")
    ticket_key: str = Field("", description="工单 Key")
    from_status: TicketStatus = Field(..., description="变更前状态")
    to_status: TicketStatus = Field(..., description="变更后状态")
    project_id: str = Field("", description="项目 ID")
    repository_url: str = Field("", description="仓库 URL")
    commit_hash: str = Field("", description="关联 commit")
    closed_by: str = Field("", description="关闭人")
    resolution: str = Field("", description="解决方式")
    raw_payload: Dict[str, Any] = Field(default_factory=dict, description="原始数据")
    received_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─────────────────────────── 同步结果模型 ───────────────────────────

class SyncFindingsRequest(BaseModel):
    """同步发现到外部平台请求"""
    model_config = ConfigDict(extra="ignore")

    provider: DevOpsProvider = Field(..., description="平台类型")
    project_id: str = Field(..., description="项目 ID")
    findings: List[FindingRef] = Field(default_factory=list, description="发现列表")
    repository_url: str = Field("", description="仓库 URL")
    commit_hash: str = Field("", description="提交 hash")
    branch: str = Field("", description="分支名")
    merge_request_id: str = Field("", description="合并请求 ID")
    config: Optional[DevOpsConfig] = Field(None, description="连接配置")
    dry_run: bool = Field(default=False, description="仅规划不同步")


class SyncResult(BaseModel):
    """同步结果"""
    model_config = ConfigDict(extra="ignore")

    status: SyncStatus = Field(..., description="同步状态")
    provider: DevOpsProvider = Field(..., description="平台类型")
    total_findings: int = Field(0, description="总发现数")
    created_count: int = Field(0, description="新建工单数")
    updated_count: int = Field(0, description="更新工单数")
    skipped_count: int = Field(0, description="跳过数")
    failed_count: int = Field(0, description="失败数")
    mappings: List[FindingTicketMapping] = Field(default_factory=list, description="映射列表")
    errors: List[str] = Field(default_factory=list, description="错误列表")
    dry_run: bool = Field(default=False, description="是否仅规划")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class TicketCloseRequest(BaseModel):
    """关闭工单请求"""
    model_config = ConfigDict(extra="ignore")

    provider: DevOpsProvider = Field(..., description="平台类型")
    ticket_id: str = Field(..., description="工单 ID")
    resolution: str = Field("fixed", description="解决方式")
    comment: str = Field("", description="关闭备注")
    commit_hash: str = Field("", description="关联修复提交")


class DevOpsStats(BaseModel):
    """DevOps 模块运营统计"""
    model_config = ConfigDict(extra="ignore")

    total_mappings: int = Field(default=0, description="总映射数")
    open_tickets: int = Field(default=0, description="打开工单数")
    resolved_tickets: int = Field(default=0, description="已解决工单数")
    closed_tickets: int = Field(default=0, description="已关闭工单数")
    in_progress_tickets: int = Field(default=0, description="处理中工单数")
    total_syncs: int = Field(default=0, description="总同步次数")
    successful_syncs: int = Field(default=0, description="成功同步次数")
    failed_syncs: int = Field(default=0, description="失败同步次数")
    pending_syncs: int = Field(default=0, description="待同步次数")
    total_evaluations: int = Field(default=0, description="卡点评估次数")
    pass_count: int = Field(default=0, description="通过次数")
    warn_count: int = Field(default=0, description="告警次数")
    block_count: int = Field(default=0, description="阻断次数")
    by_provider: Dict[str, int] = Field(default_factory=dict, description="按平台分组统计")
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class TicketLinkRequest(BaseModel):
    """关联修复提交到工单请求"""
    model_config = ConfigDict(extra="ignore")

    provider: DevOpsProvider = Field(..., description="平台类型")
    ticket_id: str = Field(..., description="工单 ID")
    commit_hash: str = Field(..., description="修复提交 hash")
    branch: str = Field("", description="修复分支")
    comment: str = Field("", description="备注")
    close_after_link: bool = Field(default=True, description="关联后是否关闭工单")
    resolution: str = Field("fixed", description="解决方式")


class BatchSyncFindingsRequest(BaseModel):
    """批量同步发现到外部平台请求"""
    model_config = ConfigDict(extra="ignore")

    provider: DevOpsProvider = Field(..., description="平台类型")
    project_id: str = Field(..., description="项目 ID")
    findings: List[FindingRef] = Field(default_factory=list, description="发现列表")
    repository_url: str = Field("", description="仓库 URL")
    commit_hash: str = Field("", description="提交 hash")
    branch: str = Field("", description="分支名")
    merge_request_id: str = Field("", description="合并请求 ID")
    config: Optional[DevOpsConfig] = Field(None, description="连接配置")
    dry_run: bool = Field(default=False, description="仅规划不同步")
    auto_close_resolved: bool = Field(default=True, description="已修复发现自动关闭工单")


# ─────────────────────────── 工具函数 ───────────────────────────

def severity_rank(severity: str) -> int:
    """严重度转数值（越大越严重）"""
    return {
        "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "": 0,
    }.get(severity.upper() if severity else "", 0)
