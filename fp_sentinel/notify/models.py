"""
企业通知模块 — 数据模型 (Pydantic v2)

定义通知渠道、推送规则、推送记录等核心数据结构。
支持飞书/钉钉/企业微信 Webhook 方式对接企业内部IM。

安全约束：
- S1 (仅内部 IM)：webhook URL 必须是企业内部域名，禁止外网请求
- S2 (禁止修改代码)：仅推送通知，不修改任何代码
- S4 (禁止真实攻击)：仅送达通知消息，无攻击性载荷
- S7 (路径白名单)：仅使用配置的 webhook URL，不做其他网络调用
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ─────────────────────────── 枚举 ───────────────────────────

class IMChannelType(str, Enum):
    """支持的 IM 渠道类型（Webhook 方式）"""
    FEISHU = "feishu"
    DINGTALK = "dingtalk"
    WECHAT_WORK = "wechat_work"


class NotifyEvent(str, Enum):
    """触发通知的事件类型"""
    NEW_CRITICAL = "new_critical"       # 新增 CRITICAL 漏洞
    NEW_HIGH = "new_high"               # 新增 HIGH 漏洞
    STATUS_CHANGED = "status_changed"   # 漏洞状态变更
    SCAN_COMPLETED = "scan_completed"   # 扫描完成
    DAILY_DIGEST = "daily_digest"       # 每日摘要


class NotifyFrequency(str, Enum):
    """推送频率控制"""
    REALTIME = "realtime"     # 实时推送
    HOURLY = "hourly"         # 每小时聚合
    DAILY = "daily"           # 每日聚合
    WEEKLY = "weekly"         # 每周聚合


class NotifyStatus(str, Enum):
    """推送状态"""
    PENDING = "pending"       # 待发送
    SENT = "sent"             # 已发送
    FAILED = "failed"         # 发送失败
    SUPPRESSED = "suppressed" # 被频率控制抑制


# ─────────────────────── 核心业务模型 ───────────────────────

class IMChannel(BaseModel):
    """IM 通知渠道（Webhook 配置）"""
    model_config = ConfigDict(extra="forbid")

    id: Optional[str] = Field(None, description="渠道唯一 ID")
    name: str = Field(..., description="渠道名称", min_length=1, max_length=64)
    channel_type: IMChannelType = Field(..., description="IM 渠道类型")
    webhook_url: str = Field(..., description="Webhook URL（必须为企业内部地址）", max_length=2048)
    secret: Optional[str] = Field(None, description="签名密钥（钉钉/企业微信可选）", max_length=256)
    enabled: bool = Field(True, description="是否启用")
    timeout_seconds: int = Field(10, ge=1, le=60, description="HTTP 超时秒数")
    created_at: Optional[datetime] = Field(None, description="创建时间")
    updated_at: Optional[datetime] = Field(None, description="更新时间")

    @field_validator("webhook_url")
    @classmethod
    def validate_internal_url(cls, v: str) -> str:
        """验证 Webhook URL 为企业内部地址（安全红线 S1）"""
        blocked_domains = [
            "hooks.slack.com", "discord.com/api/webhooks",
            "api.telegram.org", "oapi.dingtalk.com",
            "qyapi.weixin.qq.com",
        ]
        for domain in blocked_domains:
            if domain in v.lower():
                raise ValueError(
                    f"禁止将通知外发至公网 IM 服务: {domain}。"
                    f"仅允许配置企业内部 IM 服务器 Webhook。"
                )
        if not v.startswith(("http://", "https://")):
            raise ValueError("Webhook URL 必须以 http:// 或 https:// 开头")
        return v


class NotifyRule(BaseModel):
    """通知推送规则"""
    model_config = ConfigDict(extra="forbid")

    id: Optional[str] = Field(None, description="规则唯一 ID")
    name: str = Field(..., description="规则名称", min_length=1, max_length=64)
    enabled: bool = Field(True, description="是否启用")
    # 触发条件
    min_severity: str = Field("HIGH", description="最低触发严重度 (CRITICAL/HIGH/MEDIUM/LOW)")
    events: List[NotifyEvent] = Field(
        default_factory=lambda: [NotifyEvent.NEW_CRITICAL, NotifyEvent.NEW_HIGH],
        description="触发事件类型",
    )
    # 接收人配置
    channels: List[str] = Field(default_factory=list, description="关联的渠道 ID 列表")
    # 频率控制
    frequency: NotifyFrequency = Field(NotifyFrequency.REALTIME, description="推送频率")
    # 可选过滤：仅当规则 ID 匹配时触发
    rule_id_patterns: List[str] = Field(
        default_factory=list,
        description="规则 ID 前缀匹配（空=全部）",
    )
    # 可选过滤：仅当文件路径匹配时触发
    path_patterns: List[str] = Field(
        default_factory=list,
        description="文件路径前缀匹配（空=全部）",
    )
    suppress_duplicates_minutes: int = Field(
        60, ge=0, le=1440,
        description="抑制重复推送的分钟数",
    )
    created_at: Optional[datetime] = Field(None, description="创建时间")
    updated_at: Optional[datetime] = Field(None, description="更新时间")


class NotifyRecord(BaseModel):
    """通知推送记录"""
    model_config = ConfigDict(extra="ignore")

    id: Optional[str] = Field(None, description="记录唯一 ID")
    channel_id: Optional[str] = Field(None, description="推送渠道 ID")
    rule_id: Optional[str] = Field(None, description="命中规则 ID")
    event: Optional[NotifyEvent] = Field(None, description="触发事件")
    finding_id: Optional[str] = Field(None, description="关联的漏洞 finding ID")
    status: NotifyStatus = Field(NotifyStatus.PENDING, description="推送状态")
    title: str = Field("", description="通知标题", max_length=200)
    content: str = Field("", description="通知内容", max_length=4000)
    error_message: Optional[str] = Field(None, description="发送失败原因")
    retry_count: int = Field(0, ge=0, le=5, description="重试次数")
    created_at: Optional[datetime] = Field(None, description="创建时间")
    sent_at: Optional[datetime] = Field(None, description="发送时间")


class NotificationPayload(BaseModel):
    """通知消息体（序列化后发送至 IM Webhook）"""
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., description="消息标题", max_length=200)
    content: str = Field(..., description="消息正文", max_length=4000)
    severity: str = Field("HIGH", description="严重程度")
    timestamp: Optional[str] = Field(None, description="ISO8601 时间戳")

    # 漏洞详情（可选）
    rule_id: Optional[str] = Field(None, description="规则 ID", max_length=200)
    file_path: Optional[str] = Field(None, description="文件路径", max_length=500)
    line_start: Optional[int] = Field(None, description="起始行号")
    message: Optional[str] = Field(None, description="漏洞描述", max_length=500)
    category: Optional[str] = Field(None, description="漏洞分类", max_length=64)
    cwe: Optional[str] = Field(None, description="CWE 编号", max_length=32)

    # 变更详情（状态变更时使用）
    status_from: Optional[str] = Field(None, description="原状态", max_length=32)
    status_to: Optional[str] = Field(None, description="新状态", max_length=32)


class ChannelTestResult(BaseModel):
    """渠道连通性测试结果"""
    model_config = ConfigDict(extra="forbid")

    success: bool = Field(..., description="是否连通")
    channel_type: IMChannelType = Field(..., description="渠道类型")
    status_code: Optional[int] = Field(None, description="HTTP 状态码")
    latency_ms: float = Field(0.0, description="延迟毫秒")
    message: str = Field("", description="测试结果信息")


# ─────────────────────── 工具函数 ───────────────────────

def severity_rank(severity: str) -> int:
    """严重度优先级映射（数字越大越严重）"""
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(severity.upper(), 0)


def event_to_display(event: NotifyEvent) -> str:
    """事件类型中文显示"""
    return {
        NotifyEvent.NEW_CRITICAL: "新增 CRITICAL 漏洞",
        NotifyEvent.NEW_HIGH: "新增 HIGH 漏洞",
        NotifyEvent.STATUS_CHANGED: "漏洞状态变更",
        NotifyEvent.SCAN_COMPLETED: "扫描完成",
        NotifyEvent.DAILY_DIGEST: "每日摘要推送",
    }.get(event, event.value)


def status_to_display(status: NotifyStatus) -> str:
    """推送状态中文显示"""
    return {
        NotifyStatus.PENDING: "待发送",
        NotifyStatus.SENT: "已发送",
        NotifyStatus.FAILED: "发送失败",
        NotifyStatus.SUPPRESSED: "已抑制",
    }.get(status, status.value)
