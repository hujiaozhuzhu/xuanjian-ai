"""
玄鉴 v3.1.0 — 企业通知模块 (Enterprise Notification Module)

通过 Webhook 方式将高危漏洞自动推送到企业内部 IM 工具。
支持飞书 / 钉钉 / 企业微信，自定义推送规则、频率、接收人，支持状态变更通知。

安全红线：S1 (仅内部 IM) / S2 (禁止修改代码) / S4 (禁止真实攻击) / S7 (路径白名单)
"""

__version__ = "3.1.0"

from .models import (
    ChannelTestResult,
    IMChannel,
    IMChannelType,
    NotificationPayload,
    NotifyEvent,
    NotifyFrequency,
    NotifyRecord,
    NotifyRule,
    NotifyStatus,
    severity_rank,
    event_to_display,
    status_to_display,
)
from .store import NotifyStore, open_store, default_notify_db_path
from .webhook import (
    get_adapter,
    send_notification,
    check_channel,
    DingTalkWebhookAdapter,
    FeishuWebhookAdapter,
    WeChatWorkWebhookAdapter,
    WebhookAdapter,
)
from .engine import (
    NotifyEngine,
    match_rule,
    match_rules,
    process_findings,
    notify_status_change,
)

__all__ = [
    "IMChannel",
    "IMChannelType",
    "NotificationPayload",
    "NotifyEvent",
    "NotifyFrequency",
    "NotifyRecord",
    "NotifyRule",
    "NotifyStatus",
    "ChannelTestResult",
    "NotifyStore",
    "NotifyEngine",
    "WebhookAdapter",
    "FeishuWebhookAdapter",
    "DingTalkWebhookAdapter",
    "WeChatWorkWebhookAdapter",
    "severity_rank",
    "event_to_display",
    "status_to_display",
    "match_rule",
    "match_rules",
    "process_findings",
    "notify_status_change",
    "open_store",
    "default_notify_db_path",
    "get_adapter",
    "send_notification",
    "check_channel",
]

__version__ = "2.5.0"
