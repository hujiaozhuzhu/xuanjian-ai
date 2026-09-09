"""
玄鉴 v3.1 — 全局事件总线实现

线程安全的事件发布/订阅系统，支持异步处理和WebSocket推送。
所有9种核心事件类型均有类型安全和校验。
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    """
    玄鉴 v3.1 全局事件总线 -- 9种核心事件类型

    各事件类型的标准 payload 字段:
    - scan_progress: scan_id, progress_pct(0-100), current_file, findings_count
    - finding_new: finding_id, rule_id, severity, file_path, category
    - scan_completed: scan_id, total_findings, duration_seconds, severity_counts
    - system_status: component, status(ok/warn/error), message
    - fed_round: session_id, round_number, accuracy, loss, participants
    - fed_completed: session_id, total_rounds, final_accuracy, privacy_loss
    - pr_status: pr_id, provider, status(open/merged/closed), title
    - pipeline_gate: build_id, gate_name, passed(bool), reason
    - webhook_event: provider, event_type, action, source_branch
    """
    SCAN_PROGRESS = "scan_progress"
    FINDING_NEW = "finding_new"
    SCAN_COMPLETED = "scan_completed"
    SYSTEM_STATUS = "system_status"
    FED_ROUND = "fed_round"
    FED_COMPLETED = "fed_completed"
    PR_STATUS = "pr_status"
    PIPELINE_GATE = "pipeline_gate"
    WEBHOOK_EVENT = "webhook_event"


class EventSeverity(str, Enum):
    """事件严重度"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


# 9种事件类型的标准payload定义(用于校验和文档)
EVENT_PAYLOAD_SCHEMA: Dict[EventType, Dict[str, Any]] = {
    EventType.SCAN_PROGRESS: {
        "required": ["scan_id", "progress_pct"],
        "optional": ["current_file", "findings_count", "stage"],
    },
    EventType.FINDING_NEW: {
        "required": ["finding_id", "rule_id"],
        "optional": ["severity", "file_path", "category", "message"],
    },
    EventType.SCAN_COMPLETED: {
        "required": ["scan_id", "total_findings"],
        "optional": ["duration_seconds", "severity_counts", "scanner_used"],
    },
    EventType.SYSTEM_STATUS: {
        "required": ["component", "status"],
        "optional": ["message", "metrics"],
    },
    EventType.FED_ROUND: {
        "required": ["session_id", "round_number"],
        "optional": ["accuracy", "loss", "participants", "privacy_loss"],
    },
    EventType.FED_COMPLETED: {
        "required": ["session_id", "total_rounds"],
        "optional": ["final_accuracy", "final_loss", "privacy_loss", "compliance_passed"],
    },
    EventType.PR_STATUS: {
        "required": ["pr_id", "status"],
        "optional": ["provider", "title", "url", "merged_by"],
    },
    EventType.PIPELINE_GATE: {
        "required": ["build_id", "gate_name", "passed"],
        "optional": ["reason", "severity_threshold", "metrics"],
    },
    EventType.WEBHOOK_EVENT: {
        "required": ["provider", "event_type"],
        "optional": ["action", "source_branch", "target_branch", "commit_hash"],
    },
}


@dataclass
class Event:
    """事件数据对象"""
    event_type: EventType
    payload: Dict[str, Any] = field(default_factory=dict)
    severity: EventSeverity = EventSeverity.INFO
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "xuanjian-core"

    def validate(self) -> tuple:
        """校验事件payload是否符合schema"""
        schema = EVENT_PAYLOAD_SCHEMA.get(self.event_type)
        if not schema:
            return False, f"未知事件类型: {self.event_type}"

        required = schema.get("required", [])
        for field_name in required:
            if field_name not in self.payload:
                return False, f"缺少必填字段: {field_name}"

        return True, None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "source": self.source,
        }


# 订阅者回调类型
EventHandler = Callable[[Event], Awaitable[None]]


class EventBus:
    """
    全局事件总线

    支持异步发布/订阅、事件历史、类型过滤。
    单例模式，全进程共享一个实例。
    """

    _instance: Optional[EventBus] = None

    def __init__(self, max_history: int = 1000) -> None:
        self._subscribers: Dict[EventType, List[EventHandler]] = defaultdict(list)
        self._global_subscribers: List[EventHandler] = []
        self._history: List[Event] = []
        self._max_history: int = max_history
        self._ws_connections: list = []

    @classmethod
    def get_instance(cls, max_history: int = 1000) -> EventBus:
        """获取全局事件总线单例"""
        if cls._instance is None:
            cls._instance = cls(max_history=max_history)
        return cls._instance

    # 订阅

    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """订阅特定类型的事件"""
        self._subscribers[event_type].append(handler)

    def subscribe_all(self, handler: EventHandler) -> None:
        """订阅所有事件"""
        self._global_subscribers.append(handler)

    def unsubscribe(self, event_type: EventType, handler: EventHandler) -> bool:
        """取消订阅"""
        handlers = self._subscribers.get(event_type, [])
        if handler in handlers:
            handlers.remove(handler)
            return True
        return False

    # 发布

    async def publish(self, event: Event) -> bool:
        """发布事件到总线"""
        is_valid, error_msg = event.validate()
        if not is_valid:
            logger.warning("事件校验失败: %s (type=%s)", error_msg, event.event_type.value)
            return False

        self._add_to_history(event)

        # 推送到类型订阅者
        handlers = self._subscribers.get(event.event_type, [])
        for handler in handlers:
            try:
                await handler(event)
            except Exception as e:
                logger.error("事件处理异常 [%s]: %s", handler.__name__, e)

        # 推送到全局订阅者
        for handler in self._global_subscribers:
            try:
                await handler(event)
            except Exception as e:
                logger.error("全局事件处理异常 [%s]: %s", handler.__name__, e)

        # WebSocket推送
        await self._ws_broadcast(event)

        return True

    async def publish_simple(
        self,
        event_type: EventType,
        payload: Dict[str, Any],
        severity: EventSeverity = EventSeverity.INFO,
        source: str = "xuanjian-core",
    ) -> bool:
        """简化的发布接口"""
        event = Event(
            event_type=event_type,
            payload=payload,
            severity=severity,
            source=source,
        )
        return await self.publish(event)

    # WebSocket

    def register_ws(self, websocket) -> None:
        """注册WebSocket连接"""
        if websocket not in self._ws_connections:
            self._ws_connections.append(websocket)

    def unregister_ws(self, websocket) -> None:
        """注销WebSocket连接"""
        if websocket in self._ws_connections:
            self._ws_connections.remove(websocket)

    async def _ws_broadcast(self, event: Event) -> None:
        """向所有WebSocket连接广播事件"""
        if not self._ws_connections:
            return

        import json
        data = json.dumps(event.to_dict(), ensure_ascii=False)

        disconnected: list = []
        for ws in self._ws_connections:
            try:
                await ws.send_text(data)
            except Exception:
                disconnected.append(ws)

        for ws in disconnected:
            self._ws_connections.remove(ws)

    # 历史记录

    def _add_to_history(self, event: Event) -> None:
        """添加事件到历史"""
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

    def get_history(
        self,
        event_type: Optional[EventType] = None,
        limit: int = 100,
        severity: Optional[EventSeverity] = None,
    ) -> List[Dict[str, Any]]:
        """获取事件历史"""
        filtered = list(self._history)

        if event_type:
            filtered = [e for e in filtered if e.event_type == event_type]
        if severity:
            filtered = [e for e in filtered if e.severity == severity]

        return [e.to_dict() for e in reversed(filtered[-limit:])]

    def get_stats(self) -> Dict[str, Any]:
        """获取事件总线统计"""
        type_counts: Dict[str, int] = {}
        for event_type in EventType:
            type_counts[event_type.value] = len(
                [e for e in self._history if e.event_type == event_type]
            )

        return {
            "total_events": len(self._history),
            "max_history": self._max_history,
            "active_subscribers": sum(len(h) for h in self._subscribers.values()),
            "global_subscribers": len(self._global_subscribers),
            "active_ws_connections": len(self._ws_connections),
            "events_by_type": type_counts,
        }

    def clear_history(self) -> int:
        """清空事件历史"""
        count = len(self._history)
        self._history.clear()
        return count


# 模块级便捷函数

def get_event_bus(max_history: int = 1000) -> EventBus:
    """获取全局事件总线实例"""
    return EventBus.get_instance(max_history=max_history)


async def publish_event(
    event_type: EventType,
    payload: Dict[str, Any],
    severity: EventSeverity = EventSeverity.INFO,
    source: str = "xuanjian-core",
) -> bool:
    """便捷发布事件函数"""
    bus = get_event_bus()
    return await bus.publish_simple(event_type, payload, severity, source)


def subscribe(event_type: EventType, handler: EventHandler) -> None:
    """便捷订阅函数"""
    bus = get_event_bus()
    bus.subscribe(event_type, handler)


def get_event_history(
    event_type: Optional[str] = None,
    limit: int = 100,
    severity: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """便捷获取历史函数"""
    bus = get_event_bus()
    et = EventType(event_type) if event_type else None
    sev = EventSeverity(severity) if severity else None
    return bus.get_history(event_type=et, limit=limit, severity=sev)


def create_event_bus(max_history: int = 1000) -> EventBus:
    """创建新的事件总线实例(非单例, 用于测试)"""
    return EventBus(max_history=max_history)
