"""
玄鉴 v3.1 — 全局事件总线

支持9种事件类型：
- scan_progress: 扫描进度事件
- finding_new: 新发现漏洞事件
- scan_completed: 扫描完成事件
- system_status: 系统状态变更事件
- fed_round: 联邦训练轮次事件
- fed_completed: 联邦训练完成事件
- pr_status: PR状态变更事件
- pipeline_gate: 流水线门控事件
- webhook_event: Webhook回调事件

特性：
- 异步事件发布/订阅
- WebSocket推送支持
- 事件类型安全枚举
- 内置事件历史（最近N条）
- 支持事件过滤和订阅

安全红线：
- 事件数据不含敏感信息（如API Token、密码）
- 事件历史可配置保留周期
"""

from .event_bus import (
    EventBus,
    EventType,
    Event,
    EventSeverity,
    publish_event,
    subscribe,
    get_event_history,
    create_event_bus,
)

__all__ = [
    "EventBus",
    "EventType",
    "Event",
    "EventSeverity",
    "publish_event",
    "subscribe",
    "get_event_history",
    "create_event_bus",
]

__version__ = "3.1.0"
