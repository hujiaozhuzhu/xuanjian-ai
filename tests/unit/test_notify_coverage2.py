"""test_notify_coverage2 -- Target remaining partial branches"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fp_sentinel.models import Finding, Severity


class TestEngineContextManager:

    @pytest.mark.asyncio
    async def test_engine_owns_store_lifecycle(self):
        with patch("fp_sentinel.notify.engine.open_store") as mock_open:
            mock_store = AsyncMock()
            mock_store.list_rules.return_value = []
            mock_open.return_value = mock_store
            from fp_sentinel.notify.engine import NotifyEngine
            engine = NotifyEngine()
            async with engine:
                _ = engine.store
            mock_store.__aenter__.assert_called_once()
            mock_store.__aexit__.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_findings_convenience_with_patched_store(self, tmp_path):
        from fp_sentinel.notify.store import NotifyStore
        from fp_sentinel.notify.models import (
            IMChannel, IMChannelType, NotifyEvent, NotifyRule,
        )
        mem_store = NotifyStore(":memory:")
        async with mem_store:
            ch = await mem_store.create_channel(IMChannel(
                name="Ch", channel_type=IMChannelType.FEISHU,
                webhook_url="https://im.example.com/hook",
            ))
            await mem_store.create_rule(NotifyRule(
                id="r1", name="R1", min_severity="HIGH",
                events=[NotifyEvent.NEW_HIGH], channels=[ch.id],
            ))
            with patch("fp_sentinel.notify.engine.send_notification") as mock_send:
                mock_send.return_value = MagicMock(
                    success=True, status_code=200, latency_ms=1.0, message="OK",
                )
                from fp_sentinel.notify.engine import NotifyEngine
                engine = NotifyEngine(store=mem_store)
                records = await engine.process_findings([
                    Finding(
                        id="f1", scanner="semgrep", rule_id="py.injection.sql",
                        severity=Severity.HIGH, file_path="app/db.py",
                        line_start=10, message="SQLi",
                    ),
                ])
                assert len(records) >= 1


class TestWebhookHmac:

    def test_dingtalk_sign_generates_valid_hmac(self):
        from fp_sentinel.notify.webhook import DingTalkWebhookAdapter
        adapter = DingTalkWebhookAdapter()
        result = adapter.sign("test_secret_key", 1234567890)
        assert result["timestamp"] == "1234567890"
        assert len(result["sign"]) > 10


class TestStoreGetNone:

    @pytest.mark.asyncio
    async def test_get_channel_returns_none(self, tmp_path):
        from fp_sentinel.notify.store import NotifyStore
        db_path = str(tmp_path / "gc.db")
        store = NotifyStore(db_path)
        async with store:
            got = await store.get_channel("nonexistent")
            assert got is None
