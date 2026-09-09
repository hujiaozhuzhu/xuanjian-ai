"""
玄鉴 v3.1 — 事件总线 REST API 路由

FastAPI 路由组，挂载于 /api/events/
提供事件查询、发布和WebSocket实时推送。

路由清单：
  GET  /api/events/types           — 事件类型列表
  GET  /api/events/history          — 事件历史查询
  GET  /api/events/stats            — 事件总线统计
  POST /api/events/publish          — 发布事件（内部调用）
  WS   /api/events/ws               — WebSocket实时推送

安全红线：
- 发布事件需校验payload格式和敏感信息过滤
- WebSocket连接需认证
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

events_router = APIRouter(prefix="/api/events", tags=["events"])

# ─────────────────────────── 请求模型 ───────────────────────────

class PublishEventRequest(BaseModel):
    """发布事件请求"""
    model_config = ConfigDict(extra="ignore")

    event_type: str = Field(..., description="事件类型")
    payload: Dict[str, Any] = Field(default_factory=dict, description="事件负载")
    severity: str = Field("info", description="严重度: debug/info/warning/error/critical")
    source: str = Field("api", description="事件来源")

    def to_event(self):
        from .event_bus import Event, EventType, EventSeverity
        try:
            et = EventType(self.event_type)
        except ValueError:
            valid = [t.value for t in EventType]
            raise ValueError(f"无效事件类型: {self.event_type}。有效值: {valid}")
        try:
            sev = EventSeverity(self.severity)
        except ValueError:
            sev = EventSeverity.INFO

        return Event(event_type=et, payload=self.payload, severity=sev, source=self.source)


# 敏感字段列表（自动过滤）
_SENSITIVE_FIELDS = {"token", "api_token", "secret", "password", "private_key", "credential"}


def _sanitize_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """过滤payload中的敏感信息"""
    if not isinstance(payload, dict):
        return payload

    sanitized = {}
    for k, v in payload.items():
        if k.lower() in _SENSITIVE_FIELDS:
            sanitized[k] = "***REDACTED***"
        elif isinstance(v, dict):
            sanitized[k] = _sanitize_payload(v)
        else:
            sanitized[k] = v
    return sanitized


# ─────────────────────────── 事件类型 API ───────────────────────────

@events_router.get("/types")
async def list_event_types():
    """
    获取所有支持的事件类型及说明。

    Returns:
        9种事件类型的定义和payload schema
    """
    from .event_bus import EventType, EVENT_PAYLOAD_SCHEMA

    types = []
    for et in EventType:
        schema = EVENT_PAYLOAD_SCHEMA.get(et, {})
        types.append({
            "type": et.value,
            "required_fields": schema.get("required", []),
            "optional_fields": schema.get("optional", []),
        })

    return {
        "total": len(types),
        "types": types,
        "version": "3.1.0",
    }


# ─────────────────────────── 事件历史 API ───────────────────────────

@events_router.get("/history")
async def get_history(
    event_type: Optional[str] = Query(None, description="事件类型过滤"),
    severity: Optional[str] = Query(None, description="严重度过滤"),
    limit: int = Query(50, ge=1, le=500, description="返回数量限制"),
):
    """
    查询事件历史。

    Args:
        event_type: 事件类型过滤
        severity: 严重度过滤
        limit: 数量限制

    Returns:
        事件列表（倒序）
    """
    from .event_bus import get_event_history

    history = get_event_history(
        event_type=event_type,
        limit=limit,
        severity=severity,
    )

    return {
        "total": len(history),
        "filters": {"event_type": event_type, "severity": severity},
        "events": history,
    }


# ─────────────────────────── 事件统计 API ───────────────────────────

@events_router.get("/stats")
async def get_event_stats():
    """
    获取事件总线统计信息。

    Returns:
        事件统计数据
    """
    from .event_bus import get_event_bus

    bus = get_event_bus()
    return bus.get_stats()


# ─────────────────────────── 发布事件 API ───────────────────────────

@events_router.post("/publish")
async def publish_event_api(request: PublishEventRequest):
    """
    发布事件到总线。

    自动过滤敏感信息，需符合事件类型的payload schema。

    Args:
        request: 发布事件请求

    Returns:
        发布结果
    """
    from .event_bus import publish_event, EventType, EventSeverity

    try:
        et = EventType(request.event_type)
    except ValueError:
        valid = [t.value for t in EventType]
        raise HTTPException(status_code=400, detail=f"无效事件类型: {request.event_type}。有效值: {valid}")

    sev = EventSeverity.INFO
    try:
        sev = EventSeverity(request.severity)
    except ValueError:
        pass

    # 过滤敏感信息
    safe_payload = _sanitize_payload(request.payload)

    success = await publish_event(
        event_type=et,
        payload=safe_payload,
        severity=sev,
        source=request.source,
    )

    if not success:
        raise HTTPException(status_code=400, detail="事件校验失败，请检查payload格式")

    return {
        "status": "published",
        "event_type": request.event_type,
        "source": request.source,
    }


# ─────────────────────────── WebSocket 实时推送 ───────────────────────────

@events_router.websocket("/ws")
async def events_websocket(websocket: WebSocket):
    """
    WebSocket实时事件推送。

    支持按事件类型过滤订阅。
    """
    from .event_bus import get_event_bus

    await websocket.accept()
    bus = get_event_bus()
    bus.register_ws(websocket)

    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong", "timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        bus.unregister_ws(websocket)
