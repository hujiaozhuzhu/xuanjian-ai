"""
test_notify_models -- Notification module data model unit tests
"""

from __future__ import annotations

import pytest

from fp_sentinel.notify.models import (
    ChannelTestResult,
    IMChannel,
    IMChannelType,
    NotificationPayload,
    NotifyEvent,
    NotifyFrequency,
    NotifyRecord,
    NotifyRule,
    NotifyStatus,
    event_to_display,
    severity_rank,
    status_to_display,
)


class TestIMChannel:

    def test_create_valid_channel(self):
        ch = IMChannel(
            name="Test Channel",
            channel_type=IMChannelType.FEISHU,
            webhook_url="https://im.example.com/webhook/abc123",
        )
        assert ch.name == "Test Channel"
        assert ch.channel_type == IMChannelType.FEISHU
        assert ch.enabled is True
        assert ch.timeout_seconds == 10

    def test_blocked_domains_rejected(self):
        """S1 redline: block external IM services"""
        for bad_url in [
            "https://hooks.slack.com/services/xxx",
            "https://discord.com/api/webhooks/123/abc",
            "https://api.telegram.org/bot123/sendMessage",
            "https://oapi.dingtalk.com/robot/send?access_token=xxx",
            "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx",
        ]:
            with pytest.raises(ValueError):
                IMChannel(
                    name="bad",
                    channel_type=IMChannelType.FEISHU,
                    webhook_url=bad_url,
                )

    def test_invalid_scheme_rejected(self):
        with pytest.raises(ValueError):
            IMChannel(
                name="bad",
                channel_type=IMChannelType.FEISHU,
                webhook_url="ftp://example.com/webhook",
            )

    def test_with_secret(self):
        ch = IMChannel(
            name="DingTalk",
            channel_type=IMChannelType.DINGTALK,
            webhook_url="https://im.example.com/dingtalk/yyy",
            secret="SEC123456",
        )
        assert ch.secret == "SEC123456"

    def test_model_forbid_extra(self):
        with pytest.raises(Exception):
            IMChannel(
                name="x",
                channel_type=IMChannelType.FEISHU,
                webhook_url="https://im.example.com/hook",
                unknown_field="bad",
            )

    def test_timeout_range(self):
        with pytest.raises(ValueError):
            IMChannel(
                name="x",
                channel_type=IMChannelType.FEISHU,
                webhook_url="https://im.example.com/hook",
                timeout_seconds=0,
            )
        with pytest.raises(ValueError):
            IMChannel(
                name="x",
                channel_type=IMChannelType.FEISHU,
                webhook_url="https://im.example.com/hook",
                timeout_seconds=120,
            )


class TestNotifyRule:

    def test_create_valid_rule(self):
        rule = NotifyRule(name="High Severity Alert")
        assert rule.name == "High Severity Alert"
        assert rule.enabled is True
        assert rule.min_severity == "HIGH"
        assert NotifyEvent.NEW_CRITICAL in rule.events
        assert NotifyEvent.NEW_HIGH in rule.events
        assert rule.frequency == NotifyFrequency.REALTIME

    def test_with_custom_events(self):
        rule = NotifyRule(
            name="Status Change Notify",
            events=[NotifyEvent.STATUS_CHANGED, NotifyEvent.SCAN_COMPLETED],
        )
        assert NotifyEvent.STATUS_CHANGED in rule.events
        assert NotifyEvent.SCAN_COMPLETED in rule.events

    def test_with_channels(self):
        rule = NotifyRule(
            name="Bound Channels",
            channels=["ch-001", "ch-002"],
        )
        assert len(rule.channels) == 2

    def test_with_patterns(self):
        rule = NotifyRule(
            name="Filter Rule",
            rule_id_patterns=["py.injection.sql", "py.command-injection"],
            path_patterns=["src/main/java/", "app/controllers/"],
        )
        assert len(rule.rule_id_patterns) == 2
        assert len(rule.path_patterns) == 2

    def test_suppress_duplicates_range(self):
        with pytest.raises(ValueError):
            NotifyRule(name="x", suppress_duplicates_minutes=-1)
        with pytest.raises(ValueError):
            NotifyRule(name="x", suppress_duplicates_minutes=2000)


class TestNotifyRecord:

    def test_create_pending_record(self):
        record = NotifyRecord(
            channel_id="ch-001",
            rule_id="rule-001",
            event=NotifyEvent.NEW_CRITICAL,
            finding_id="f-123",
            status=NotifyStatus.PENDING,
            title="[CRITICAL] SQLi",
            content="Found vulnerability",
        )
        assert record.status == NotifyStatus.PENDING
        assert record.retry_count == 0

    def test_create_sent_record(self):
        record = NotifyRecord(
            status=NotifyStatus.SENT,
            title="Sent OK",
        )
        assert record.status == NotifyStatus.SENT

    def test_create_failed_record(self):
        record = NotifyRecord(
            status=NotifyStatus.FAILED,
            error_message="HTTP 500",
            retry_count=2,
        )
        assert record.status == NotifyStatus.FAILED
        assert record.retry_count == 2

    def test_ignore_extra(self):
        record = NotifyRecord(
            status=NotifyStatus.PENDING,
            title="test",
            unknown_field="ignored",
        )
        assert record.status == NotifyStatus.PENDING


class TestNotificationPayload:

    def test_create_basic(self):
        p = NotificationPayload(
            title="SQLi Found",
            content="SQL injection detected, please fix immediately",
            severity="CRITICAL",
        )
        assert p.title == "SQLi Found"
        assert p.severity == "CRITICAL"

    def test_create_full(self):
        p = NotificationPayload(
            title="[CRITICAL] Test",
            content="Content ABC",
            severity="HIGH",
            timestamp="2026-09-07T10:00:00Z",
            rule_id="py.injection.sql",
            file_path="app/db.py",
            line_start=42,
            message="SQL injection found",
            category="SQL_INJECTION",
            cwe="CWE-89",
            status_from="open",
            status_to="fixed",
        )
        assert p.rule_id == "py.injection.sql"
        assert p.status_from == "open"
        assert p.status_to == "fixed"

    def test_model_forbid_extra(self):
        with pytest.raises(Exception):
            NotificationPayload(
                title="x",
                content="y",
                unknown_field="bad",
            )


class TestChannelTestResult:

    def test_success_result(self):
        r = ChannelTestResult(
            success=True,
            channel_type=IMChannelType.FEISHU,
            status_code=200,
            latency_ms=150.5,
            message="OK",
        )
        assert r.success is True
        assert r.status_code == 200

    def test_failure_result(self):
        r = ChannelTestResult(
            success=False,
            channel_type=IMChannelType.DINGTALK,
            status_code=500,
            latency_ms=0.0,
            message="HTTP 500: Internal Server Error",
        )
        assert r.success is False


class TestUtilityFunctions:

    def test_severity_rank(self):
        assert severity_rank("CRITICAL") == 4
        assert severity_rank("HIGH") == 3
        assert severity_rank("MEDIUM") == 2
        assert severity_rank("LOW") == 1
        assert severity_rank("INFO") == 0
        assert severity_rank("UNKNOWN") == 0
        assert severity_rank("critical") == 4

    def test_event_to_display(self):
        assert event_to_display(NotifyEvent.NEW_CRITICAL) == "新增 CRITICAL 漏洞"
        assert event_to_display(NotifyEvent.NEW_HIGH) == "新增 HIGH 漏洞"
        assert event_to_display(NotifyEvent.STATUS_CHANGED) == "漏洞状态变更"
        assert event_to_display(NotifyEvent.SCAN_COMPLETED) == "扫描完成"
        assert event_to_display(NotifyEvent.DAILY_DIGEST) == "每日摘要推送"

    def test_status_to_display(self):
        assert status_to_display(NotifyStatus.PENDING) == "待发送"
        assert status_to_display(NotifyStatus.SENT) == "已发送"
        assert status_to_display(NotifyStatus.FAILED) == "发送失败"
        assert status_to_display(NotifyStatus.SUPPRESSED) == "已抑制"
