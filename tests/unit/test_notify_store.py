"""test_notify_store -- NotifyStore unit tests"""

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


def _channel(name="TestChannel", ctype="feishu",
             url="https://im.example.com/hook"):
    return IMChannel(name=name, channel_type=IMChannelType(ctype), webhook_url=url)


def _rule(name="TestRule", channels=None):
    return NotifyRule(
        name=name,
        min_severity="HIGH",
        events=[NotifyEvent.NEW_CRITICAL, NotifyEvent.NEW_HIGH],
        channels=channels or [],
        frequency=NotifyFrequency.REALTIME,
    )


class TestChannelCRUD:

    @pytest.mark.asyncio
    async def test_create_and_get(self, store):
        saved = await store.create_channel(_channel())
        assert saved.id is not None
        got = await store.get_channel(saved.id)
        assert got is not None
        assert got.name == "TestChannel"

    @pytest.mark.asyncio
    async def test_list_channels(self, store):
        await store.create_channel(_channel(name="Ch1"))
        await store.create_channel(_channel(name="Ch2", url="https://im.example.com/h2"))
        channels = await store.list_channels()
        assert len(channels) == 2

    @pytest.mark.asyncio
    async def test_update_channel(self, store):
        saved = await store.create_channel(_channel(name="OldName"))
        saved.name = "NewName"
        await store.update_channel(saved)
        got = await store.get_channel(saved.id)
        assert got.name == "NewName"

    @pytest.mark.asyncio
    async def test_update_channel_requires_id(self, store):
        ch = _channel()
        ch.id = None
        with pytest.raises(ValueError):
            await store.update_channel(ch)

    @pytest.mark.asyncio
    async def test_delete_channel(self, store):
        saved = await store.create_channel(_channel())
        ok = await store.delete_channel(saved.id)
        assert ok is True
        got = await store.get_channel(saved.id)
        assert got is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self, store):
        ok = await store.delete_channel("nonexistent")
        assert ok is False


class TestRuleCRUD:

    @pytest.mark.asyncio
    async def test_create_and_get(self, store):
        saved = await store.create_rule(_rule())
        assert saved.id is not None
        got = await store.get_rule(saved.id)
        assert got is not None
        assert got.name == "TestRule"

    @pytest.mark.asyncio
    async def test_list_rules(self, store):
        await store.create_rule(_rule(name="R1"))
        await store.create_rule(_rule(name="R2"))
        rules = await store.list_rules()
        assert len(rules) == 2

    @pytest.mark.asyncio
    async def test_update_rule(self, store):
        saved = await store.create_rule(_rule(name="Old"))
        saved.name = "New"
        await store.update_rule(saved)
        got = await store.get_rule(saved.id)
        assert got.name == "New"

    @pytest.mark.asyncio
    async def test_delete_rule(self, store):
        saved = await store.create_rule(_rule())
        ok = await store.delete_rule(saved.id)
        assert ok is True
        got = await store.get_rule(saved.id)
        assert got is None


class TestNotifyRecords:

    @pytest.mark.asyncio
    async def test_create_record(self, store):
        record = NotifyRecord(
            channel_id="ch-001",
            rule_id="r-001",
            event=NotifyEvent.NEW_CRITICAL,
            finding_id="f-123",
            status=NotifyStatus.PENDING,
            title="[CRITICAL] SQLi",
            content="Found",
        )
        saved = await store.create_record(record)
        assert saved.id is not None

    @pytest.mark.asyncio
    async def test_update_record_status(self, store):
        record = NotifyRecord(status=NotifyStatus.PENDING, title="T")
        saved = await store.create_record(record)
        await store.update_record_status(saved.id, NotifyStatus.SENT)
        records = await store.list_records(status_filter=NotifyStatus.SENT)
        assert len(records) == 1

    @pytest.mark.asyncio
    async def test_list_records_by_status(self, store):
        await store.create_record(NotifyRecord(status=NotifyStatus.PENDING, title="P"))
        await store.create_record(NotifyRecord(status=NotifyStatus.SENT, title="S"))
        pending = await store.list_records(status_filter=NotifyStatus.PENDING)
        assert len(pending) == 1

    @pytest.mark.asyncio
    async def test_list_records_limit(self, store):
        for i in range(10):
            await store.create_record(NotifyRecord(title=f"R{i}"))
        records = await store.list_records(limit=5)
        assert len(records) == 5

    @pytest.mark.asyncio
    async def test_count_recent_by_finding(self, store):
        await store.create_record(NotifyRecord(finding_id="f-001", status=NotifyStatus.SENT))
        await store.create_record(NotifyRecord(finding_id="f-001", status=NotifyStatus.PENDING))
        await store.create_record(NotifyRecord(finding_id="f-002", status=NotifyStatus.SENT))
        assert await store.count_recent_by_finding("f-001", 60) == 2
        assert await store.count_recent_by_finding("f-002", 60) == 1
        assert await store.count_recent_by_finding("f-999", 60) == 0

    @pytest.mark.asyncio
    async def test_purge_records(self, store):
        await store.create_record(NotifyRecord(title="keep", status=NotifyStatus.SENT))
        n = await store.purge_records(days=1)
        assert n == 0
        remaining = await store.list_records()
        assert len(remaining) == 1

    @pytest.mark.asyncio
    async def test_stats(self, store):
        ch = await store.create_channel(_channel())
        await store.create_rule(_rule(channels=[ch.id]))
        await store.create_record(NotifyRecord(status=NotifyStatus.SENT))
        stats = await store.stats()
        assert stats["channels"] == 1
        assert stats["rules"] == 1
        assert stats["records_total"] == 1
        assert stats["records_sent"] == 1
