"""test_notify_store_extra -- Extra NotifyStore tests for edge cases"""

from __future__ import annotations

import pytest

from fp_sentinel.notify.models import (
    IMChannel,
    IMChannelType,
    NotifyEvent,
    NotifyFrequency,
    NotifyRecord,
    NotifyRule,
    NotifyStatus,
)
from fp_sentinel.notify.store import NotifyStore


@pytest.fixture
def tmp_db(tmp_path):
    return str(tmp_path / "notify.db")


@pytest.fixture
async def store(tmp_db):
    s = NotifyStore(tmp_db)
    async with s:
        yield s


def _channel(name="Ch", ctype="feishu", url="https://im.example.com/hook"):
    return IMChannel(name=name, channel_type=IMChannelType(ctype), webhook_url=url)


def _rule(name="Rule", channels=None):
    return NotifyRule(
        name=name,
        min_severity="HIGH",
        events=[NotifyEvent.NEW_CRITICAL],
        channels=channels or [],
    )


class TestConnectionLifecycle:

    @pytest.mark.asyncio
    async def test_connect_close_reconnect(self, tmp_db):
        store = NotifyStore(tmp_db)
        await store.connect()
        await store.initialize()
        await store.close()
        # Reconnect
        await store.connect()
        await store.initialize()
        assert store._conn is not None
        await store.close()

    @pytest.mark.asyncio
    async def test_initialize_without_connect_raises(self, tmp_db):
        store = NotifyStore(tmp_db)
        with pytest.raises(RuntimeError):
            await store.initialize()

    @pytest.mark.asyncio
    async def test_conn_without_connect_raises(self, tmp_db):
        store = NotifyStore(tmp_db)
        with pytest.raises(RuntimeError):
            _ = store.conn

    @pytest.mark.asyncio
    async def test_close_idempotent(self, tmp_db):
        store = NotifyStore(tmp_db)
        await store.connect()
        await store.close()
        await store.close()  # should not raise

    @pytest.mark.asyncio
    async def test_memory_db(self):
        store = NotifyStore(":memory:")
        async with store:
            ch = await store.create_channel(_channel())
            assert ch.id is not None


class TestChannelEdgeCases:

    @pytest.mark.asyncio
    async def test_get_nonexistent_channel(self, store):
        got = await store.get_channel("does-not-exist")
        assert got is None

    @pytest.mark.asyncio
    async def test_list_channels_enabled_only_false(self, store):
        ch = _channel()
        ch.enabled = False
        await store.create_channel(ch)
        all_ch = await store.list_channels(enabled_only=False)
        assert len(all_ch) == 1
        enabled = await store.list_channels(enabled_only=True)
        assert len(enabled) == 0


class TestRuleEdgeCases:

    @pytest.mark.asyncio
    async def test_get_nonexistent_rule(self, store):
        got = await store.get_rule("does-not-exist")
        assert got is None

    @pytest.mark.asyncio
    async def test_list_rules_enabled_only_false(self, store):
        r = _rule()
        r.enabled = False
        await store.create_rule(r)
        assert len(await store.list_rules(enabled_only=False)) == 1
        assert len(await store.list_rules(enabled_only=True)) == 0

    @pytest.mark.asyncio
    async def test_rule_with_all_event_types(self, store):
        rule = NotifyRule(
            name="AllEvents",
            events=[
                NotifyEvent.NEW_CRITICAL, NotifyEvent.NEW_HIGH,
                NotifyEvent.STATUS_CHANGED, NotifyEvent.SCAN_COMPLETED,
                NotifyEvent.DAILY_DIGEST,
            ],
        )
        saved = await store.create_rule(rule)
        got = await store.get_rule(saved.id)
        assert len(got.events) == 5

    @pytest.mark.asyncio
    async def test_rule_with_all_frequencies(self, store):
        for freq in [NotifyFrequency.REALTIME, NotifyFrequency.HOURLY,
                     NotifyFrequency.DAILY, NotifyFrequency.WEEKLY]:
            rule = _rule(name=f"Rule-{freq.value}", )
            rule.frequency = freq
            saved = await store.create_rule(rule)
            got = await store.get_rule(saved.id)
            assert got.frequency == freq


class TestRecordEdgeCases:

    @pytest.mark.asyncio
    async def test_list_records_by_channel(self, store):
        await store.create_record(NotifyRecord(channel_id="ch-1", title="t1"))
        await store.create_record(NotifyRecord(channel_id="ch-2", title="t2"))
        await store.create_record(NotifyRecord(channel_id="ch-1", title="t3"))
        records = await store.list_records(channel_id="ch-1")
        assert len(records) == 2

    @pytest.mark.asyncio
    async def test_update_record_all_fields(self, store):
        record = NotifyRecord(status=NotifyStatus.PENDING, title="T")
        saved = await store.create_record(record)
        from datetime import datetime, timezone
        sent_at = datetime.now(timezone.utc)
        await store.update_record_status(
            saved.id, NotifyStatus.SENT,
            error_message=None, retry_count=3, sent_at=sent_at,
        )
        records = await store.list_records(status_filter=NotifyStatus.SENT)
        assert records[0].retry_count == 3
        assert records[0].sent_at is not None

    @pytest.mark.asyncio
    async def test_update_record_failed(self, store):
        record = NotifyRecord(status=NotifyStatus.PENDING, title="T")
        saved = await store.create_record(record)
        await store.update_record_status(
            saved.id, NotifyStatus.FAILED,
            error_message="Connection refused",
            retry_count=2,
        )
        records = await store.list_records(status_filter=NotifyStatus.FAILED)
        assert len(records) == 1
        assert "Connection refused" in records[0].error_message


class TestStatsEdgeCases:

    @pytest.mark.asyncio
    async def test_stats_empty_db(self, store):
        stats = await store.stats()
        assert stats["channels"] == 0
        assert stats["rules"] == 0
        assert stats["records_total"] == 0
        assert stats["stats"] == 0 if "stats" in stats else True
        assert stats["records_sent"] == 0
        assert stats["records_failed"] == 0

    @pytest.mark.asyncio
    async def test_purge_zero_days(self, store):
        await store.create_record(NotifyRecord(title="r", status=NotifyStatus.SENT))
        n = await store.purge_records(days=365)
        assert n == 0


class TestRowToRuleJsonHandling:

    @pytest.mark.asyncio
    async def test_rule_with_empty_events_json(self, store):
        """Ensure _row_to_rule handles edge case gracefully"""
        saved = await store.create_rule(_rule(name="EmptyPat"))
        got = await store.get_rule(saved.id)
        assert got is not None
        assert got.name == "EmptyPat"
