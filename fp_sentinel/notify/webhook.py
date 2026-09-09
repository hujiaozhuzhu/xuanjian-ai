"""
企业通知模块 — IM Webhook 适配器

将通知消息格式化为飞书/钉钉/企业微信 Webhook JSON 格式，并发送 HTTP POST。
所有请求通过 httpx 异步发送，支持超时与签名（钉钉/企业微信可选）。

安全约束：
- S1 (仅内部 IM)：URL 由 IMChannel.create() 时校验，禁止外网域名
- S2 (禁止修改代码)：仅发 HTTP POST，不触碰本地文件
- S4 (禁止真实攻击)：仅发送通知文本，无攻击载荷
- SSL 校验默认开启
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
import urllib.parse
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

import httpx

from .models import (
    ChannelTestResult,
    IMChannel,
    IMChannelType,
    NotificationPayload,
)

logger = logging.getLogger(__name__)


def _current_timestamp_s() -> int:
    return int(time.time())


class WebhookAdapter(ABC):
    """Webhook 适配器抽象基类"""

    @abstractmethod
    def format_payload(self, payload: NotificationPayload) -> Dict[str, Any]:
        """将 NotificationPayload 格式化为目标 IM 的 JSON body"""
        ...

    def content_type(self) -> str:
        return "application/json"

    def sign(self, secret: str, timestamp_s: Optional[int] = None) -> Dict[str, str]:
        """可选签名（钉钉/企业微信需要）—— 基类返回空 dict"""
        return {}


class FeishuWebhookAdapter(WebhookAdapter):
    """
    飞书 Webhook 适配器
    支持富文本消息（post）格式，按严重程度使用不同颜色标签。
    """

    def format_payload(self, payload: NotificationPayload) -> Dict[str, Any]:
        color = {
            "CRITICAL": "red", "HIGH": "orange",
            "MEDIUM": "yellow", "LOW": "blue", "INFO": "grey",
        }.get(payload.severity.upper(), "grey")

        body_lines: list[str] = [payload.content]
        if payload.rule_id:
            body_lines.append(f"规则: {payload.rule_id}")
        if payload.file_path:
            loc = payload.file_path
            if payload.line_start:
                loc += f":{payload.line_start}"
            body_lines.append(f"位置: {loc}")
        if payload.category:
            body_lines.append(f"分类: {payload.category}")
        if payload.cwe:
            body_lines.append(f"CWE: {payload.cwe}")
        if payload.message:
            body_lines.append(f"描述: {payload.message}")
        if payload.status_from and payload.status_to:
            body_lines.append(f"状态: {payload.status_from} → {payload.status_to}")

        post_body = {
            "zh_cn": {
                "title": payload.title,
                "content": [[{"tag": "text", "text": "\n".join(body_lines)}]],
            }
        }

        return {
            "msg_type": "post",
            "content": {"post": post_body},
        }


class DingTalkWebhookAdapter(WebhookAdapter):
    """
    钉钉 Webhook 适配器
    支持 markdown 消息，可选加签。
    """

    def format_payload(self, payload: NotificationPayload) -> Dict[str, Any]:
        title = f"### {payload.title}"
        lines: list[str] = [title, "---", payload.content]

        meta_parts: list[str] = []
        if payload.severity:
            meta_parts.append(f"**严重度**: {payload.severity}")
        if payload.rule_id:
            meta_parts.append(f"**规则**: `{payload.rule_id}`")
        if payload.file_path:
            loc = payload.file_path
            if payload.line_start:
                loc += f":L{payload.line_start}"
            meta_parts.append(f"**位置**: `{loc}`")
        if payload.category:
            meta_parts.append(f"**分类**: {payload.category}")
        if payload.cwe:
            meta_parts.append(f"**CWE**: {payload.cwe}")
        if payload.status_from and payload.status_to:
            meta_parts.append(f"**状态**: {payload.status_from} → {payload.status_to}")
        if payload.message:
            meta_parts.append(f"**描述**: {payload.message}")

        if meta_parts:
            lines.append("")
            lines.extend(meta_parts)

        if payload.timestamp:
            lines.append("")
            lines.append(f"> 时间: {payload.timestamp}")

        return {
            "msgtype": "markdown",
            "markdown": {
                "title": payload.title,
                "text": "\n".join(lines),
            },
        }

    def sign(self, secret: str, timestamp_s: Optional[int] = None) -> Dict[str, str]:
        """钉钉加签"""
        import base64 as _b64
        ts = str(timestamp_s or _current_timestamp_s())
        string_to_sign = f"{ts}\n{secret}"
        hmac_code = hmac.new(
            secret.encode("utf-8"),
            string_to_sign.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).digest()
        sign_val = urllib.parse.quote_plus(_b64.b64encode(hmac_code))
        return {"timestamp": ts, "sign": sign_val}


class WeChatWorkWebhookAdapter(WebhookAdapter):
    """
    企业微信 Webhook 适配器
    支持 markdown 消息（每条最大 4096 字节，超长截断）。
    """

    MAX_MARKDOWN_BYTES = 4096

    def format_payload(self, payload: NotificationPayload) -> Dict[str, Any]:
        color = {
            "CRITICAL": "warning", "HIGH": "warning",
            "MEDIUM": "comment", "LOW": "info", "INFO": "info",
        }.get(payload.severity.upper(), "info")

        lines: list[str] = [
            f"<font color=\"{color}\">{payload.title}</font>",
            payload.content,
        ]

        meta_parts: list[str] = []
        if payload.severity:
            meta_parts.append(
                f"<font color=\"{color}\">严重度: {payload.severity}</font>"
            )
        if payload.rule_id:
            meta_parts.append(f"规则: {payload.rule_id}")
        if payload.file_path:
            loc = payload.file_path
            if payload.line_start:
                loc += f":L{payload.line_start}"
            meta_parts.append(f"位置: {loc}")
        if payload.category:
            meta_parts.append(f"分类: {payload.category}")
        if payload.cwe:
            meta_parts.append(f"CWE: {payload.cwe}")
        if payload.status_from and payload.status_to:
            meta_parts.append(
                f"状态: {payload.status_from} → {payload.status_to}"
            )
        if payload.message:
            meta_parts.append(f"描述: {payload.message}")
        if payload.timestamp:
            meta_parts.append(f"时间: {payload.timestamp}")

        if meta_parts:
            lines.extend(["", *meta_parts])

        md_text = "\n".join(lines)
        while len(md_text.encode("utf-8")) > self.MAX_MARKDOWN_BYTES:
            lines = lines[:-1]
            md_text = "\n".join(lines) + "\n...(截断)"

        return {
            "msgtype": "markdown",
            "markdown": {"content": md_text},
        }


def get_adapter(channel_type: IMChannelType) -> WebhookAdapter:
    """工厂函数：根据渠道类型返回对应适配器"""
    return {
        IMChannelType.FEISHU: FeishuWebhookAdapter,
        IMChannelType.DINGTALK: DingTalkWebhookAdapter,
        IMChannelType.WECHAT_WORK: WeChatWorkWebhookAdapter,
    }[channel_type]()


def _ssl_verify() -> bool:
    ssl_env = os.environ.get("XUANJIAN_NOTIFY_VERIFY_SSL", "")
    return ssl_env not in ("0", "false", "False", "FALSE", "no")


async def send_notification(
    channel: IMChannel,
    payload: NotificationPayload,
    http_client: Optional[httpx.AsyncClient] = None,
) -> ChannelTestResult:
    """
    向指定渠道发送通知消息

    Args:
        channel: IM 渠道配置
        payload: 通知消息体
        http_client: 可选的 httpx 客户端（用于测试注入）

    Returns:
        ChannelTestResult: 发送结果
    """
    adapter = get_adapter(channel.channel_type)
    body = adapter.format_payload(payload)
    headers: Dict[str, str] = {"Content-Type": adapter.content_type()}

    url = channel.webhook_url
    if channel.secret and channel.channel_type == IMChannelType.DINGTALK:
        sign_params = adapter.sign(channel.secret)
        separator = "&" if "?" in url else "?"
        query = "&".join(f"{k}={v}" for k, v in sign_params.items())
        url = f"{url}{separator}{query}"

    t0 = time.monotonic()

    client_owned = http_client is None
    if client_owned:
        http_client = httpx.AsyncClient(
            timeout=channel.timeout_seconds, verify=_ssl_verify()
        )

    try:
        response = await http_client.post(url, json=body, headers=headers)
        latency_ms = (time.monotonic() - t0) * 1000.0
        success = 200 <= response.status_code < 300
        err_msg = ""
        if not success:
            err_msg = f"HTTP {response.status_code}: {response.text[:200]}"
        else:
            try:
                resp_json = response.json()
                if isinstance(resp_json, dict) and "errcode" in resp_json:
                    if resp_json["errcode"] != 0:
                        success = False
                        err_msg = f"业务错误: {resp_json.get('errmsg', '')}"
            except Exception:
                pass

        return ChannelTestResult(
            success=success,
            channel_type=channel.channel_type,
            status_code=response.status_code,
            latency_ms=round(latency_ms, 1),
            message=err_msg if err_msg else "发送成功",
        )
    except httpx.HTTPError as e:
        latency_ms = (time.monotonic() - t0) * 1000.0
        return ChannelTestResult(
            success=False,
            channel_type=channel.channel_type,
            status_code=None,
            latency_ms=round(latency_ms, 1),
            message=f"HTTP 错误: {e}",
        )
    except Exception as e:
        latency_ms = (time.monotonic() - t0) * 1000.0
        return ChannelTestResult(
            success=False,
            channel_type=channel.channel_type,
            status_code=None,
            latency_ms=round(latency_ms, 1),
            message=f"未知错误: {e}",
        )
    finally:
        if client_owned and http_client:
            await http_client.aclose()


async def check_channel(
    channel: IMChannel,
    http_client: Optional[httpx.AsyncClient] = None,
) -> ChannelTestResult:
    """测试渠道连通性 —— 发送一条测试消息"""
    test_payload = NotificationPayload(
        title="玄鉴通知模块 — 连通性测试",
        content="这是一条测试通知。如果您的 IM 收到了此消息，说明通知渠道配置正确。",
        severity="INFO",
    )
    return await send_notification(channel, test_payload, http_client=http_client)
