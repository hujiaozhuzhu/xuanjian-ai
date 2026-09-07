"""test_notify_webhook_extra -- Extra webhook adapter edge case tests"""

from __future__ import annotations

import os
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
    send_notification,
)
from fp_sentinel.notify.webhook import _ssl_verify


def _payload():
    return NotificationPayload(
        title="Test", content="Content", severity="HIGH",
    )


def _mock_response(status_code=200, json_data=None, is_json=True):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.text = "ok"
    if is_json:
        resp.json.return_value = json_data or {"errcode": 0, "errmsg": "ok"}
    else:
        resp.json.side_effect = ValueError("not json")
    return resp


def _channel(ctype=IMChannelType.FEISHU, url="https://im.example.com/hook"):
    return IMChannel(name="T", channel_type=ctype, webhook_url=url, timeout_seconds=5)


class TestWebhookEdgeCases:

    def test_feishu_payload_with_all_fields(self):
        adapter = FeishuWebhookAdapter()
        payload = NotificationPayload(
            title="T", content="C", severity="CRITICAL",
            rule_id="py.injection.sql", file_path="app/db.py",
            line_start=42, message="SQLi", category="SQL_INJECTION",
            cwe="CWE-89", status_from="open", status_to="fixed",
        )
        body = adapter.format_payload(payload)
        assert body["msg_type"] == "post"

    def test_feishu_payload_with_unknown_severity(self):
        adapter = FeishuWebhookAdapter()
        payload = NotificationPayload(title="T", content="C", severity="UNKNOWN")
        body = adapter.format_payload(payload)
        assert body["content"]["post"]["zh_cn"]["title"] == "T"

    def test_feishu_content_type(self):
        assert FeishuWebhookAdapter().content_type() == "application/json"

    def test_dingtalk_content_type(self):
        assert DingTalkWebhookAdapter().content_type() == "application/json"

    def test_wechat_content_type(self):
        assert WeChatWorkWebhookAdapter().content_type() == "application/json"

    def test_dingtalk_sign_different_timestamps(self):
        adapter = DingTalkWebhookAdapter()
        p1 = adapter.sign("secret", 1000)
        p2 = adapter.sign("secret", 1001)
        assert p1["sign"] != p2["sign"]

    def test_wechat_work_unknown_severity(self):
        adapter = WeChatWorkWebhookAdapter()
        payload = NotificationPayload(title="T", content="C", severity="UNKNOWN")
        body = adapter.format_payload(payload)
        assert "info" in body["markdown"]["content"]

    def test_wechat_work_short_text(self):
        adapter = WeChatWorkWebhookAdapter()
        payload = NotificationPayload(title="T", content="Short", severity="INFO")
        body = adapter.format_payload(payload)
        assert not body["markdown"]["content"].endswith("...(截断)")

    @pytest.mark.asyncio
    async def test_send_response_not_json(self):
        """Handle response.json() raising ValueError gracefully"""
        channel = _channel()
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post = AsyncMock(return_value=_mock_response(200, is_json=False))
        result = await send_notification(channel, _payload(), http_client=mock_client)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_send_response_non_dict_json(self):
        """Handle response.json() returning non-dict (e.g. list)"""
        channel = _channel()
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post = AsyncMock(return_value=_mock_response(200, json_data=[1, 2, 3]))
        result = await send_notification(channel, _payload(), http_client=mock_client)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_send_no_secret_no_sign(self):
        """feishu channel without secret should not append sign params"""
        channel = _channel(IMChannelType.FEISHU)
        channel.secret = None
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post = AsyncMock(return_value=_mock_response(200))
        await send_notification(channel, _payload(), http_client=mock_client)
        call_args = mock_client.post.call_args
        called_url = call_args[0][0]
        assert "sign" not in called_url

    def test_ssl_verify_env_true(self):
        with patch.dict(os.environ, {"XUANJIAN_NOTIFY_VERIFY_SSL": ""}):
            assert _ssl_verify() is True

    def test_ssl_verify_env_false(self):
        for val in ["0", "false", "False", "FALSE", "no"]:
            with patch.dict(os.environ, {"XUANJIAN_NOTIFY_VERIFY_SSL": val}):
                assert _ssl_verify() is False
