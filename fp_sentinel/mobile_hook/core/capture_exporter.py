# -*- coding: utf-8 -*-
"""CaptureExporter —— 抓包事件导出器（HAR / JSONL / Summary）。

将捕获的抓包事件（CaptureEvent）导出为标准 HAR 1.2 格式、
JSONL（含完整 callstack）或 Markdown 摘要，供后续关联分析与报告生成。

零外部依赖：仅依赖 Python 标准库（json / datetime / collections）。

用法::

    from fp_sentinel.mobile_hook.core.capture_exporter import (
        CaptureEvent, CaptureExporter, export_events,
    )
    events = [{"timestamp": 1234567890.0, "protocol": "http", ...}]
    path = export_events(events, "./output/capture.har", "har")
"""

from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TypedDict


# ─────────────────────────────────────────────────────────────
# 数据模型
# ─────────────────────────────────────────────────────────────

class CaptureEvent(TypedDict):
    """抓包事件 —— 单次 Hook 捕获的最小信息单元。"""
    timestamp: float                      # Unix 时间戳（秒，浮点）
    protocol: str                         # "http" / "native" / "socket"
    source: str                           # "frida" / "static"
    method: str                           # 被调用的方法/函数名
    args: List[Any]                       # 参数列表（序列化安全值）
    retval: Any                           # 返回值（序列化安全值）
    callstack: List[str]                  # 调用栈（类#方法 列表，栈顶在前）


# ─────────────────────────────────────────────────────────────
# 导出器
# ─────────────────────────────────────────────────────────────

class CaptureExporter:
    """接受 CaptureEvent list，导出为各种标准格式。"""

    def __init__(self, events: List[Dict[str, Any]], page_title: str = "fp-sentinel capture"):
        """
        :param events: CaptureEvent 字典列表（允许缺失字段，内部做防御性处理）
        :param page_title: HAR log.pages[0].title
        """
        self._events: List[Dict[str, Any]]
        self._events = list(events) if events else []
        self._page_title = page_title

    # ─────────────────────── HAR 1.2 ───────────────────────

    def to_har(self) -> Dict[str, Any]:
        """按 HAR 1.2 规范组装 log.entries。

        包含 request.method/headers/body + response.status/headers/content + timings，
        必填项 pageref、startedDateTime（ISO8601）均已填充。
        """
        page_id = "page_1"
        entries: List[Dict[str, Any]] = []

        for i, evt in enumerate(self._events):
            started = self._iso8601(evt.get("timestamp", 0.0))
            protocol = str(evt.get("protocol", "http"))
            method = str(evt.get("method", "UNKNOWN"))
            args = evt.get("args", [])
            retval = evt.get("retval")
            callstack = evt.get("callstack", [])
            source = str(evt.get("source", "static"))

            # Request 部分
            request_body = self._serialize_args(args)
            req_headers = [
                {"name": "x-fs-source", "value": source},
                {"name": "x-fs-protocol", "value": protocol},
            ]
            if callstack:
                req_headers.append({
                    "name": "x-fs-callstack",
                    "value": " -> ".join(callstack[:8]),
                })

            request_block: Dict[str, Any] = {
                "method": _har_method(method, protocol),
                "url": _har_url(method, protocol, args),
                "httpVersion": "HTTP/1.1",
                "headers": req_headers,
                "queryString": [],
                "cookies": [],
                "headersSize": -1,
                "bodySize": len(request_body),
                "postData": {
                    "mimeType": "application/x-www-form-urlencoded",
                    "text": request_body,
                } if request_body else None,
            }

            # Response 部分
            resp_body = self._serialize_retval(retval)
            response_block: Dict[str, Any] = {
                "status": 200 if protocol == "http" else 0,
                "statusText": "OK" if protocol == "http" else "",
                "httpVersion": "HTTP/1.1",
                "headers": [
                    {"name": "x-fs-source", "value": source},
                ],
                "cookies": [],
                "content": {
                    "size": len(resp_body),
                    "mimeType": "text/plain",
                    "text": resp_body,
                },
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": len(resp_body),
            }

            # timings
            timings: Dict[str, int] = {
                "send": 0,
                "wait": 1,
                "receive": 0,
            }

            entry: Dict[str, Any] = {
                "pageref": page_id,
                "startedDateTime": started,
                "time": 1,
                "request": request_block,
                "response": response_block,
                "cache": {},
                "timings": timings,
                "serverIPAddress": "",
                "comment": f"#{i} {protocol}:{method}",
            }
            if request_block.get("postData") is None:
                del request_block["postData"]
            entries.append(entry)

        return {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "fp-sentinel",
                    "version": "4.0.0",
                },
                "browser": {
                    "name": "fp-sentinel mobile_hook",
                    "version": "4.0.0",
                },
                "pages": [
                    {
                        "startedDateTime": entries[0]["startedDateTime"] if entries else self._iso8601(0.0),
                        "id": page_id,
                        "title": self._page_title,
                        "pageTimings": {
                            "onContentLoad": -1,
                            "onLoad": -1,
                        },
                    }
                ],
                "entries": entries,
            }
        }

    # ─────────────────────── JSONL ───────────────────────

    def to_jsonl(self) -> str:
        """每行一条 JSON，含完整 callstack（供后续关联分析）。"""
        lines: List[str] = []
        for evt in self._events:
            record = {
                "timestamp": evt.get("timestamp", 0.0),
                "datetime": self._iso8601(evt.get("timestamp", 0.0)),
                "protocol": str(evt.get("protocol", "http")),
                "source": str(evt.get("source", "static")),
                "method": str(evt.get("method", "")),
                "args": _safe_json_value(evt.get("args", [])),
                "retval": _safe_json_value(evt.get("retval")),
                "callstack": list(evt.get("callstack", [])),
            }
            lines.append(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
        return "\n".join(lines) + "\n" if lines else ""

    # ─────────────────────── Markdown 摘要 ───────────────────────

    def to_summary(self) -> str:
        """Markdown 摘要：# 事件数量 / 按 protocol 分类 / TOP 高频 method。"""
        total = len(self._events)
        proto_counter: Counter = Counter()
        method_counter: Counter = Counter()
        for evt in self._events:
            proto_counter[str(evt.get("protocol", "unknown"))] += 1
            method_counter[str(evt.get("method", "(empty)"))] += 1

        lines: List[str] = [
            "# fp-sentinel 捕获事件摘要",
            "",
            f"**事件总数**: {total}",
            "",
        ]

        # 按 protocol 分类
        lines.append("## 按 Protocol 分类")
        lines.append("")
        lines.append("| Protocol | 数量 | 占比 |")
        lines.append("|----------|------|------|")
        for proto, count in proto_counter.most_common():
            pct = (count / total * 100) if total else 0.0
            lines.append(f"| {proto} | {count} | {pct:.1f}% |")
        lines.append("")

        # TOP 高频 method
        lines.append("## TOP 高频 Method")
        lines.append("")
        lines.append("| Rank | Method | 次数 | Protocol |")
        lines.append("|------|--------|------|----------|")
        top_methods = method_counter.most_common(20)
        for rank, (method, count) in enumerate(top_methods, 1):
            # 找出该方法最常见的 protocol
            proto_for_method: Counter = Counter()
            for evt in self._events:
                if evt.get("method") == method:
                    proto_for_method[str(evt.get("protocol", "unknown"))] += 1
            top_proto = proto_for_method.most_common(1)
            proto_str = top_proto[0][0] if top_proto else "-"
            lines.append(f"| {rank} | `{method}` | {count} | {proto_str} |")
        lines.append("")

        return "\n".join(lines)

    # ─────────────────────── 内部工具 ───────────────────────

    @staticmethod
    def _iso8601(ts: float) -> str:
        """将 Unix 时间戳转为 ISO8601 字符串（UTC）。"""
        try:
            dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"
        except (OSError, ValueError, OverflowError):
            return "1970-01-01T00:00:00.000Z"

    @staticmethod
    def _serialize_args(args: Any) -> str:
        """将 args 列表安全序列化为字符串（用于 HAR postData.text）。"""
        if not args:
            return ""
        try:
            if isinstance(args, list):
                parts = []
                for a in args:
                    parts.append(_safe_str(a))
                return "&".join(parts)
            return _safe_str(args)
        except Exception:
            return str(args)[:2048]

    @staticmethod
    def _serialize_retval(retval: Any) -> str:
        """将 retval 安全序列化为字符串（用于 HAR content.text）。"""
        if retval is None:
            return ""
        try:
            return _safe_str(retval)
        except Exception:
            return str(retval)[:2048]


# ─────────────────────────────────────────────────────────────
# 公共入口
# ─────────────────────────────────────────────────────────────

def export_events(
    events: List[Dict[str, Any]],
    out_path: str,
    format: str,
    page_title: str = "fp-sentinel capture",
) -> str:
    """公共入口：将事件列表导出为指定格式文件。

    :param events: CaptureEvent 字典列表
    :param out_path: 输出文件路径
    :param format: "har" / "jsonl" / "summary"
    :param page_title: HAR 页面标题
    :return: 实际写入的文件路径
    :raises ValueError: format 不在支持列表中
    """
    fmt = format.strip().lower()
    if fmt not in ("har", "jsonl", "summary"):
        raise ValueError(
            f"不支持的导出格式: {format!r}，可选: har / jsonl / summary"
        )

    exporter = CaptureExporter(events, page_title=page_title)

    if fmt == "har":
        content_dict = exporter.to_har()
        content = json.dumps(content_dict, ensure_ascii=False, indent=2)
    elif fmt == "jsonl":
        content = exporter.to_jsonl()
    else:
        content = exporter.to_summary()

    out_path = os.path.abspath(out_path)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return out_path


# ─────────────────────────────────────────────────────────────
# 辅助
# ─────────────────────────────────────────────────────────────

def _har_method(method: str, protocol: str) -> str:
    """根据 protocol 推断 HAR request.method。"""
    if protocol == "http":
        http_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
        if method.upper() in http_methods:
            return method.upper()
        return "GET"
    return "CALL"


def _har_url(method: str, protocol: str, args: Any) -> str:
    """构造 HAR request.url（尽量从 args[0] 提取 URL 信息）。"""
    if protocol == "http" and isinstance(args, list) and args:
        first = args[0]
        if isinstance(first, str) and first.startswith(("http://", "https://")):
            return first
    return f"fs://{protocol}/{method}" if protocol != "http" else "fs://http/unknown"


def _safe_json_value(val: Any) -> Any:
    """确保值可被 json.dumps 安全序列化。"""
    if val is None or isinstance(val, (bool, int, float, str)):
        return val
    if isinstance(val, (list, tuple)):
        return [_safe_json_value(v) for v in val]
    if isinstance(val, dict):
        return {str(k): _safe_json_value(v) for k, v in val.items()}
    try:
        json.dumps(val)
        return val
    except (TypeError, ValueError):
        return str(val)


def _safe_str(val: Any) -> str:
    """将任意值转为安全字符串。"""
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    try:
        return json.dumps(val, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(val)
