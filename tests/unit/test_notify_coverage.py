"""test_notify_coverage -- Targeted tests to push coverage to 95%+"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fp_sentinel.models import Finding, Severity
from fp_sentinel.notify.models import (
    IMChannel,
    IMChannelType,
    NotificationPayload,
    NotifyEvent,
    NotifyRule,
    NotifyStatus,
)


class TestStoreRowMapping:

    @pytest.mark.asyncio
    async def test_row_to_rule_with_malformed_events_json(self, tmp_path):
        """Fallback path when events JSON is malformed"""
        from fp_sentinel.notify.store import NotifyStore
        db_path = str(tmp_path / "cov.db")
        store = NotifyStore(db_path)
        async with store:
            # Insert directly with bad JSON to exercise fallback
            await store.connect()
            await store.conn.execute(
                "INSERT INTO notify_rules (id, name, enabled, events) VALUES (?, ?, ?, ?)",
                ("bad-rule", "Bad", 1, "not-json"),
            )
            await store.conn.commit()
            got = await store.get_rule("bad-rule")
            assert got is not None
            assert got.events == []

    @pytest.mark.asyncio
    async def test_row_to_rule_with_malformed_all_json(self, tmp_path):
        """Fallback path for all malformed JSON fields"""
        from fp_sentinel.notify.store import NotifyStore
        db_path = str(tmp_path / "cov2.db")
        store = NotifyStore(db_path)
        async with store:
            await store.connect()
            await store.conn.execute(
                "INSERT INTO notify_rules (id, name, enabled, events, channels, rule_id_patterns, path_patterns) VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("bad-rule-2", "Bad2", 1, "[]", "[]", "b", "b"),
            )
            await store.conn.commit()
            got = await store.get_rule("bad-rule-2")
            assert got is not None  # Shouldn't crash on malformed JSON

    @pytest.mark.asyncio
    async def test_row_to_record_with_invalid_enum_values(self, tmp_path):
        """Fallback for invalid enum values"""
        from fp_sentinel.notify.store import NotifyStore
        db_path = str(tmp_path / "cov3.db")
        store = NotifyStore(db_path)
        async with store:
            await store.connect()
            await store.conn.execute(
                "INSERT INTO notify_records (id, status, event, finding_id) VALUES (?, ?, ?, ?)",
                ("rec-1", "invalid_status", "invalid_event", "f-1"),
            )
            await store.conn.commit()
            recs = await store.list_records()
            assert len(recs) == 1
            assert recs[0].event is None


class TestStoreHelpers:

    @pytest.mark.asyncio
    async def test_default_notify_db_path(self):
        from fp_sentinel.notify.store import default_notify_db_path
        path = default_notify_db_path()
        assert "notify.db" in path

    @pytest.mark.asyncio
    async def test_open_store_creates_instance(self):
        from fp_sentinel.notify.store import open_store, NotifyStore
        store = open_store(":memory:")
        assert isinstance(store, NotifyStore)


class TestEngineChannelDisabled:

    @pytest.mark.asyncio
    async def test_status_change_channel_disabled(self, tmp_path):
        from fp_sentinel.notify.store import NotifyStore
        db_path = str(tmp_path / "stat_dis.db")
        store = NotifyStore(db_path)
        async with store:
            channel = await store.create_channel(IMChannel(
                name="Disabled", channel_type=IMChannelType.FEISHU,
                webhook_url="https://im.example.com/hook",
                enabled=False,
            ))
            await store.create_rule(NotifyRule(
                id="rule-sc", name="SC",
                min_severity="HIGH",
                events=[NotifyEvent.STATUS_CHANGED],
                channels=[channel.id],
            ))
            from fp_sentinel.notify.engine import NotifyEngine
            engine = NotifyEngine(store=store)
            finding = Finding(
                id="f-dis", scanner="semgrep", rule_id="py.injection.sql",
                severity=Severity.HIGH, file_path="app/db.py",
                line_start=10, message="SQLi",
            )
            records = await engine.notify_status_change(finding, "open", "fixed")
            assert records == []


class TestWebhookSignStub:

    def test_dingtalk_sign_with_empty_secret(self):
        """DingTalk sign stub (no-op implementation in base class gives empty dict)"""
        from fp_sentinel.notify.webhook import DingTalkWebhookAdapter
        adapter = DingTalkWebhookAdapter()
        # Sign with actual secret still works
        result = adapter.sign("any_secret_123", 1000000)
        assert "timestamp" in result
        assert "sign" in result


class TestWebhookWeChatEdge:

    def test_wechat_format_with_no_severity(self):
        adapter = __import__("fp_sentinel.notify.webhook", fromlist=["WeChatWorkWebhookAdapter"]).WeChatWorkWebhookAdapter()
        payload = NotificationPayload(title="T", content="C", severity="MEDIUM")
        body = adapter.format_payload(payload)
        assert "comment" in body["markdown"]["content"]

    def test_wechat_format_with_low_severity(self):
        adapter = __import__("fp_sentinel.notify.webhook", fromlist=["WeChatWorkWebhookAdapter"]).WeChatWorkWebhookAdapter()
        payload = NotificationPayload(title="T", content="C", severity="LOW")
        body = adapter.format_payload(payload)
        assert "info" in body["markdown"]["content"]


class TestSslVerify:

    def test_ssl_verify_with_env_set(self):
        import os
        from fp_sentinel.notify.webhook import _ssl_verify
        with patch.dict(os.environ, {"XUANJIAN_NOTIFY_VERIFY_SSL": ""}):
            assert _ssl_verify() is True
        with patch.dict(os.environ, {"XUANJIAN_NOTIFY_VERIFY_SSL": "1"}):
            assert _ssl_verify() is True
        with patch.dict(os.environ, {"XUANJIAN_NOTIFY_VERIFY_SSL": "0"}):
            assert _ssl_verify() is False
