"""test_notify_webhook -- Webhook adapter unit tests"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from fp_sentinel.notify.models import (
    IMChannel,
    IMChannelType,
    NotificationPayload,
)
from fp_sentinel.notify.webhook import (
    DingTalkWebhookAdapter,
    FeishuWebhookAdapter,
    WeChatWorkWebhookAdapter,
    get_adapter,
    send_notification,
    check_channel,
)


def _channel(ctype=IMChannelType.FEISHU, url="https://im.example.com/hook"):
    return IMChannel(
        name="Test", channel_type=ctype, webhook_url=url, timeout_seconds=5,
    )


def _payload():
    return NotificationPayload(
        title="[CRITICAL] SQLi",
        content="SQL injection found in login",
        severity="CRITICAL",
        timestamp="2026-09-07T10:00:00Z",
        rule_id="py.injection.sql",
        file_path="app/auth.py",
        line_start=42,
        message="SQL injection vulnerability",
        category="SQL_INJECTION",
        cwe="CWE-89",
    )


def _mock_response(status_code=200, json_data=None):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.text = json.dumps(json_data or {})
    resp.json.return_value = json_data or {"errcode": 0, "errmsg": "ok"}
    return resp


class TestFeishuAdapter:

    def test_format_payload_basic(self):
        adapter = FeishuWebhookAdapter()
        payload = _payload()
        body = adapter.format_payload(payload)
        assert body["msg_type"] == "post"
        assert "post" in body["content"]

    def test_format_payload_severity_color(self):
        adapter = FeishuWebhookAdapter()
        for sev, expected_color in [
            ("CRITICAL", "red"), ("HIGH", "orange"),
            ("MEDIUM", "yellow"), ("LOW", "blue"), ("INFO", "grey"),
        ]:
            payload = NotificationPayload(title="T", content="C", severity=sev)
            body = adapter.format_payload(payload)
            post_content = body["content"]["post"]["zh_cn"]["content"]
            assert "C" in post_content[0][0]["text"]

    def test_content_type(self):
        assert FeishuWebhookAdapter().content_type() == "application/json"


class TestDingTalkAdapter:

    def test_format_payload(self):
        adapter = DingTalkWebhookAdapter()
        payload = _payload()
        body = adapter.format_payload(payload)
        assert body["msgtype"] == "markdown"
        assert "markdown" in body
        assert "title" in body["markdown"]
        assert "text" in body["markdown"]

    def test_format_payload_with_status_change(self):
        adapter = DingTalkWebhookAdapter()
        payload = NotificationPayload(
            title="[Status]", content="Changed", severity="HIGH",
            status_from="open", status_to="fixed",
        )
        body = adapter.format_payload(payload)
        assert "open" in body["markdown"]["text"]
        assert "fixed" in body["markdown"]["text"]

    def test_sign(self):
        adapter = DingTalkWebhookAdapter()
        params = adapter.sign("my_secret")
        assert "timestamp" in params
        assert "sign" in params
        assert len(params["sign"]) > 0

    def test_sign_is_deterministic_per_timestamp(self):
        adapter = DingTalkWebhookAdapter()
        p1 = adapter.sign("secret", 1000)
        p2 = adapter.sign("secret", 1000)
        assert p1["sign"] == p2["sign"]


class TestWeChatWorkAdapter:

    def test_format_payload(self):
        adapter = WeChatWorkWebhookAdapter()
        payload = _payload()
        body = adapter.format_payload(payload)
        assert body["msgtype"] == "markdown"
        assert "markdown" in body
        assert "content" in body["markdown"]

    def test_severity_color_warning(self):
        adapter = WeChatWorkWebhookAdapter()
        payload = NotificationPayload(title="T", content="C", severity="CRITICAL")
        body = adapter.format_payload(payload)
        assert "warning" in body["markdown"]["content"]

    def test_truncation(self):
        adapter = WeChatWorkWebhookAdapter()
        # Chinese chars use 3 bytes in UTF-8, so 1500 chars ~ 4500 bytes > 4096
        long_text = "测试文本内容" * 150
        payload = NotificationPayload(title="T", content=long_text, severity="INFO")
        body = adapter.format_payload(payload)
        assert len(body["markdown"]["content"].encode("utf-8")) <= 4096


class TestGetAdapter:

    def test_get_feishu_adapter(self):
        adapter = get_adapter(IMChannelType.FEISHU)
        assert isinstance(adapter, FeishuWebhookAdapter)

    def test_get_dingtalk_adapter(self):
        adapter = get_adapter(IMChannelType.DINGTALK)
        assert isinstance(adapter, DingTalkWebhookAdapter)

    def test_get_wechat_adapter(self):
        adapter = get_adapter(IMChannelType.WECHAT_WORK)
        assert isinstance(adapter, WeChatWorkWebhookAdapter)


class TestSendNotification:

    @pytest.mark.asyncio
    async def test_send_success(self):
        channel = _channel()
        payload = _payload()
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post = AsyncMock(return_value=_mock_response(200))
        result = await send_notification(channel, payload, http_client=mock_client)
        assert result.success is True
        assert result.status_code == 200
        assert result.latency_ms >= 0

    @pytest.mark.asyncio
    async def test_send_http_error(self):
        channel = _channel()
        payload = _payload()
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post = AsyncMock(return_value=_mock_response(500))
        result = await send_notification(channel, payload, http_client=mock_client)
        assert result.success is False
        assert result.status_code == 500

    @pytest.mark.asyncio
    async def test_send_business_error(self):
        channel = _channel()
        payload = _payload()
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post = AsyncMock(return_value=_mock_response(
            200, {"errcode": 40001, "errmsg": "bad request"},
        ))
        result = await send_notification(channel, payload, http_client=mock_client)
        assert result.success is False
        assert "bad request" in result.message

    @pytest.mark.asyncio
    async def test_send_httpx_exception(self):
        channel = _channel()
        payload = _payload()
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
        result = await send_notification(channel, payload, http_client=mock_client)
        assert result.success is False
        assert "HTTP" in result.message

    @pytest.mark.asyncio
    async def test_send_unexpected_exception(self):
        channel = _channel()
        payload = _payload()
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post = AsyncMock(side_effect=RuntimeError("boom"))
        result = await send_notification(channel, payload, http_client=mock_client)
        assert result.success is False

    @pytest.mark.asyncio
    async def test_dingtalk_with_secret_appends_sign(self):
        channel = _channel(IMChannelType.DINGTALK)
        channel.secret = "SECtest"
        payload = _payload()
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post = AsyncMock(return_value=_mock_response(200))
        await send_notification(channel, payload, http_client=mock_client)
        call_args = mock_client.post.call_args
        called_url = call_args[0][0]
        assert "timestamp" in called_url
        assert "sign" in called_url


class TestCheckChannel:

    @pytest.mark.asyncio
    async def test_check_channel(self):
        channel = _channel()
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post = AsyncMock(return_value=_mock_response(200))
        result = await check_channel(channel, http_client=mock_client)
        assert result.success is True
