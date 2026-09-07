"""test_notify_engine_extra -- Extra NotifyEngine edge case tests"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fp_sentinel.models import Finding, Severity
from fp_sentinel.notify.engine import (
    NotifyEngine,
    match_rule,
    notify_status_change,
    process_findings,
)
from fp_sentinel.notify.models import (
    IMChannel,
    IMChannelType,
    NotifyEvent,
    NotifyStatus,
    NotifyRule,
)


def _finding(severity=Severity.HIGH, rule_id="py.injection.sql",
             file_path="app/db.py", message="SQLi found",
             finding_id="f-001"):
    return Finding(
        id=finding_id, scanner="semgrep", rule_id=rule_id,
        severity=severity, file_path=file_path, line_start=10,
        message=message, category="SQL_INJECTION", cwe="CWE-89",
    )


def _rule(name="R", min_severity="HIGH", events=None, channels=None,
          enabled=True, rule_id_patterns=None, path_patterns=None):
    return NotifyRule(
        id="rule-001", name=name, min_severity=min_severity,
        events=events or [NotifyEvent.NEW_CRITICAL, NotifyEvent.NEW_HIGH],
        channels=channels or [], enabled=enabled,
        rule_id_patterns=rule_id_patterns or [],
        path_patterns=path_patterns or [],
    )


class TestEngineEdgeCases:

    @pytest.mark.asyncio
    async def test_engine_no_matching_rules(self, tmp_path):
        from fp_sentinel.notify.store import NotifyStore
        db_path = str(tmp_path / "ne.db")
        store = NotifyStore(db_path)
        async with store:
            channel = await store.create_channel(IMChannel(
                name="Ch", channel_type=IMChannelType.FEISHU,
                webhook_url="https://im.example.com/hook",
            ))
            # Create a rule that won't match (min_severity=CRITICAL but finding is HIGH)
            await store.create_rule(_rule(
                min_severity="CRITICAL",
                channels=[channel.id],
            ))
            engine = NotifyEngine(store=store)
            finding = _finding(severity=Severity.HIGH)
            records = await engine.process_findings([finding])
            assert records == []

    @pytest.mark.asyncio
    async def test_engine_channel_disabled_skipped(self, tmp_path):
        from fp_sentinel.notify.store import NotifyStore
        db_path = str(tmp_path / "ne2.db")
        store = NotifyStore(db_path)
        async with store:
            channel = await store.create_channel(IMChannel(
                name="Ch", channel_type=IMChannelType.FEISHU,
                webhook_url="https://im.example.com/hook",
                enabled=False,
            ))
            await store.create_rule(_rule(channels=[channel.id]))
            engine = NotifyEngine(store=store)
            finding = _finding()
            records = await engine.process_findings([finding])
            assert records == []

    @pytest.mark.asyncio
    async def test_engine_channel_not_found(self, tmp_path):
        from fp_sentinel.notify.store import NotifyStore
        db_path = str(tmp_path / "ne3.db")
        store = NotifyStore(db_path)
        async with store:
            await store.create_rule(_rule(channels=["nonexistent-ch-id"]))
            engine = NotifyEngine(store=store)
            finding = _finding()
            records = await engine.process_findings([finding])
            assert records == []

    @pytest.mark.asyncio
    async def test_engine_send_failure_handled(self, tmp_path):
        from fp_sentinel.notify.store import NotifyStore
        db_path = str(tmp_path / "ne4.db")
        store = NotifyStore(db_path)
        async with store:
            channel = await store.create_channel(IMChannel(
                name="Ch", channel_type=IMChannelType.FEISHU,
                webhook_url="https://im.example.com/hook",
            ))
            await store.create_rule(_rule(channels=[channel.id]))
            with patch("fp_sentinel.notify.engine.send_notification") as mock_send:
                mock_send.return_value = MagicMock(
                    success=False, status_code=500, latency_ms=0,
                    message="Server Error",
                )
                engine = NotifyEngine(store=store)
                finding = _finding()
                records = await engine.process_findings([finding])
                assert len(records) >= 1
                assert records[0].status == NotifyStatus.FAILED
                assert "Server Error" in records[0].error_message

    @pytest.mark.asyncio
    async def test_engine_send_exception_handled(self, tmp_path):
        from fp_sentinel.notify.store import NotifyStore
        db_path = str(tmp_path / "ne5.db")
        store = NotifyStore(db_path)
        async with store:
            channel = await store.create_channel(IMChannel(
                name="Ch", channel_type=IMChannelType.FEISHU,
                webhook_url="https://im.example.com/hook",
            ))
            await store.create_rule(_rule(channels=[channel.id]))
            with patch("fp_sentinel.notify.engine.send_notification") as mock_send:
                mock_send.side_effect = TimeoutError("Connection timed out")
                engine = NotifyEngine(store=store)
                finding = _finding()
                records = await engine.process_findings([finding])
                assert len(records) >= 1
                assert records[0].status == NotifyStatus.FAILED
                assert "timed out" in records[0].error_message

    @pytest.mark.asyncio
    async def test_engine_status_change_no_matching_rules(self, tmp_path):
        from fp_sentinel.notify.store import NotifyStore
        db_path = str(tmp_path / "ne6.db")
        store = NotifyStore(db_path)
        async with store:
            await store.create_rule(_rule(
                events=[NotifyEvent.NEW_HIGH],  # No STATUS_CHANGED
            ))
            engine = NotifyEngine(store=store)
            finding = _finding()
            records = await engine.notify_status_change(finding, "open", "fixed")
            assert records == []

    @pytest.mark.asyncio
    async def test_engine_status_change_severity_below_min(self, tmp_path):
        from fp_sentinel.notify.store import NotifyStore
        db_path = str(tmp_path / "ne7.db")
        store = NotifyStore(db_path)
        async with store:
            channel = await store.create_channel(IMChannel(
                name="Ch", channel_type=IMChannelType.FEISHU,
                webhook_url="https://im.example.com/hook",
            ))
            await store.create_rule(_rule(
                min_severity="CRITICAL",
                events=[NotifyEvent.STATUS_CHANGED],
                channels=[channel.id],
            ))
            engine = NotifyEngine(store=store)
            finding = _finding(severity=Severity.HIGH)
            records = await engine.notify_status_change(finding, "open", "fixed")
            assert records == []

    @pytest.mark.asyncio
    async def test_engine_status_change_path_no_match(self, tmp_path):
        from fp_sentinel.notify.store import NotifyStore
        db_path = str(tmp_path / "ne8.db")
        store = NotifyStore(db_path)
        async with store:
            channel = await store.create_channel(IMChannel(
                name="Ch", channel_type=IMChannelType.FEISHU,
                webhook_url="https://im.example.com/hook",
            ))
            await store.create_rule(_rule(
                events=[NotifyEvent.STATUS_CHANGED],
                channels=[channel.id],
                path_patterns=["src/main/"],
            ))
            engine = NotifyEngine(store=store)
            finding = _finding(file_path="app/controllers/auth.py")
            records = await engine.notify_status_change(finding, "open", "fixed")
            assert records == []

    @pytest.mark.asyncio
    async def test_engine_store_not_entered_raises(self):
        engine = NotifyEngine()
        with pytest.raises(RuntimeError):
            _ = engine.store


class TestConvenienceFunctions:

    @pytest.mark.asyncio
    async def test_process_findings_convenience(self, tmp_path):
        with patch("fp_sentinel.notify.engine.NotifyEngine") as MockEngine:
            mock_instance = AsyncMock()
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_instance.process_findings.return_value = []
            MockEngine.return_value = mock_instance
            records = await process_findings([])
            assert records == []

    @pytest.mark.asyncio
    async def test_notify_status_change_convenience(self, tmp_path):
        with patch("fp_sentinel.notify.engine.NotifyEngine") as MockEngine:
            mock_instance = AsyncMock()
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_instance.notify_status_change.return_value = []
            MockEngine.return_value = mock_instance
            records = await notify_status_change(
                _finding(), "open", "in_progress",
            )
            assert records == []
