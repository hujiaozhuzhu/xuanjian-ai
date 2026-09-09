"""test_notify_engine -- Notification engine unit tests"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fp_sentinel.models import Finding, Severity
from fp_sentinel.notify.engine import (
    NotifyEngine,
    _event_title,
    _prefix_matches,
    match_rule,
    match_rules,
    process_findings,
)
from fp_sentinel.notify.models import (
    IMChannel,
    IMChannelType,
    NotificationPayload,
    NotifyEvent,
    NotifyRecord,
    NotifyRule,
    NotifyStatus,
)


def _finding(severity=Severity.HIGH, rule_id="py.injection.sql",
             file_path="app/db.py", message="SQL injection found",
             finding_id="f-001", category="SQL_INJECTION", cwe="CWE-89"):
    return Finding(
        id=finding_id,
        scanner="semgrep",
        rule_id=rule_id,
        severity=severity,
        file_path=file_path,
        line_start=10,
        message=message,
        category=category,
        cwe=cwe,
    )


def _rule(name="TestRule", min_severity="HIGH",
          events=None, channels=None, enabled=True,
          rule_id_patterns=None, path_patterns=None,
          suppress_duplicates_minutes=0):
    return NotifyRule(
        id="rule-001",
        name=name,
        min_severity=min_severity,
        events=events or [NotifyEvent.NEW_CRITICAL, NotifyEvent.NEW_HIGH],
        channels=channels or [],
        enabled=enabled,
        rule_id_patterns=rule_id_patterns or [],
        path_patterns=path_patterns or [],
        suppress_duplicates_minutes=suppress_duplicates_minutes,
    )


class TestPrefixMatches:

    def test_empty_patterns_match_all(self):
        assert _prefix_matches("anything", []) is True

    def test_single_pattern_match(self):
        assert _prefix_matches("py.injection.sql", ["py."]) is True

    def test_single_pattern_no_match(self):
        assert _prefix_matches("js.xss.innerhtml", ["py."]) is False

    def test_multiple_patterns(self):
        assert _prefix_matches("app/db.py", ["src/", "app/"]) is True

    def test_exact_prefix(self):
        assert _prefix_matches("src/main/java/Foo.java", ["src/main/java/"]) is True


class TestMatchRule:

    def test_rule_disabled_no_match(self):
        rule = _rule(enabled=False)
        finding = _finding()
        assert match_rule(rule, finding, NotifyEvent.NEW_HIGH) is False

    def test_severity_below_min_no_match(self):
        rule = _rule(min_severity="CRITICAL")
        finding = _finding(severity=Severity.HIGH)
        assert match_rule(rule, finding, NotifyEvent.NEW_HIGH) is False

    def test_severity_equal_min_match(self):
        rule = _rule(min_severity="HIGH")
        finding = _finding(severity=Severity.HIGH)
        assert match_rule(rule, finding, NotifyEvent.NEW_HIGH) is True

    def test_severity_above_min_match(self):
        rule = _rule(min_severity="HIGH")
        finding = _finding(severity=Severity.CRITICAL)
        assert match_rule(rule, finding, NotifyEvent.NEW_CRITICAL) is True

    def test_event_not_in_rule_no_match(self):
        rule = _rule(events=[NotifyEvent.NEW_CRITICAL])
        finding = _finding(severity=Severity.HIGH)
        assert match_rule(rule, finding, NotifyEvent.NEW_HIGH) is False

    def test_rule_id_pattern_no_match(self):
        rule = _rule(rule_id_patterns=["js.xss"])
        finding = _finding(rule_id="py.injection.sql")
        assert match_rule(rule, finding, NotifyEvent.NEW_HIGH) is False

    def test_rule_id_pattern_match(self):
        rule = _rule(rule_id_patterns=["py.injection"])
        finding = _finding(rule_id="py.injection.sql")
        assert match_rule(rule, finding, NotifyEvent.NEW_HIGH) is True

    def test_path_pattern_no_match(self):
        rule = _rule(path_patterns=["src/main/"])
        finding = _finding(file_path="app/db.py")
        assert match_rule(rule, finding, NotifyEvent.NEW_HIGH) is False

    def test_path_pattern_match(self):
        rule = _rule(path_patterns=["app/"])
        finding = _finding(file_path="app/db.py")
        assert match_rule(rule, finding, NotifyEvent.NEW_HIGH) is True

    def test_full_match(self):
        rule = _rule(
            min_severity="HIGH",
            events=[NotifyEvent.NEW_HIGH],
            rule_id_patterns=["py."],
            path_patterns=["app/"],
        )
        finding = _finding(
            severity=Severity.HIGH,
            rule_id="py.injection.sql",
            file_path="app/db.py",
        )
        assert match_rule(rule, finding, NotifyEvent.NEW_HIGH) is True

    def test_string_severity_finding(self):
        """Finding with string severity (not enum) should also work"""
        rule = _rule(min_severity="HIGH")
        finding = _finding(severity=Severity.HIGH)
        finding.severity = "HIGH"  # force string
        assert match_rule(rule, finding, NotifyEvent.NEW_HIGH) is True


class TestMatchRules:

    def test_no_rules(self):
        assert match_rules([], _finding(), NotifyEvent.NEW_HIGH) == []

    def test_multiple_matches(self):
        rules = [_rule(name="R1"), _rule(name="R2")]
        finding = _finding()
        matched = match_rules(rules, finding, NotifyEvent.NEW_HIGH)
        assert len(matched) == 2

    def test_partial_match(self):
        rules = [
            _rule(name="Match", min_severity="HIGH"),
            _rule(name="NoMatch", min_severity="CRITICAL"),
        ]
        finding = _finding(severity=Severity.HIGH)
        matched = match_rules(rules, finding, NotifyEvent.NEW_HIGH)
        assert len(matched) == 1
        assert matched[0].name == "Match"


class TestEventTitle:

    def test_critical_title(self):
        finding = _finding(severity=Severity.CRITICAL, message="SQLi found")
        title = _event_title(finding, NotifyEvent.NEW_CRITICAL)
        assert "[CRITICAL]" in title
        assert "SQLi found" in title

    def test_high_title(self):
        finding = _finding(severity=Severity.HIGH, message="SQLi found")
        title = _event_title(finding, NotifyEvent.NEW_HIGH)
        assert "[HIGH]" in title

    def test_status_change_title(self):
        finding = _finding()
        title = _event_title(finding, NotifyEvent.STATUS_CHANGED)
        assert "状态变更" in title


class TestNotifyEngine:

    @pytest.mark.asyncio
    async def test_engine_with_injected_store(self, tmp_path):
        from fp_sentinel.notify.store import NotifyStore
        db_path = str(tmp_path / "test_notify.db")
        store = NotifyStore(db_path)
        async with store:
            # Create channel
            channel = await store.create_channel(IMChannel(
                name="Ch1", channel_type=IMChannelType.FEISHU,
                webhook_url="https://im.example.com/hook",
            ))
            # Create rule
            rule = await store.create_rule(_rule(
                channels=[channel.id],
                min_severity="HIGH",
            ))
            # Mock send_notification to avoid real HTTP
            with patch("fp_sentinel.notify.engine.send_notification") as mock_send:
                mock_send.return_value = MagicMock(
                    success=True, status_code=200, latency_ms=10.0, message="OK",
                )
                engine = NotifyEngine(store=store)
                findings = [_finding()]
                records = await engine.process_findings(findings)
                assert len(records) >= 1
                assert any(r.status == NotifyStatus.SENT for r in records)

    @pytest.mark.asyncio
    async def test_engine_suppresses_duplicates(self, tmp_path):
        from fp_sentinel.notify.store import NotifyStore
        db_path = str(tmp_path / "test_notify2.db")
        store = NotifyStore(db_path)
        async with store:
            channel = await store.create_channel(IMChannel(
                name="Ch1", channel_type=IMChannelType.FEISHU,
                webhook_url="https://im.example.com/hook",
            ))
            rule = await store.create_rule(_rule(
                channels=[channel.id],
                min_severity="HIGH",
                suppress_duplicates_minutes=60,
            ))
            with patch("fp_sentinel.notify.engine.send_notification") as mock_send:
                mock_send.return_value = MagicMock(
                    success=True, status_code=200, latency_ms=10.0, message="OK",
                )
                engine = NotifyEngine(store=store)
                finding = _finding(finding_id="f-dup-001")
                # First call: sends normally
                records1 = await engine.process_findings([finding])
                assert len(records1) >= 1
                # Second call: should be suppressed
                records2 = await engine.process_findings([finding])
                assert any(r.status == NotifyStatus.SUPPRESSED for r in records2)

    @pytest.mark.asyncio
    async def test_engine_notify_status_change(self, tmp_path):
        from fp_sentinel.notify.store import NotifyStore
        db_path = str(tmp_path / "test_notify3.db")
        store = NotifyStore(db_path)
        async with store:
            channel = await store.create_channel(IMChannel(
                name="Ch1", channel_type=IMChannelType.FEISHU,
                webhook_url="https://im.example.com/hook",
            ))
            rule = await store.create_rule(NotifyRule(
                id="rule-sc",
                name="StatusChange",
                min_severity="HIGH",
                events=[NotifyEvent.STATUS_CHANGED],
                channels=[channel.id],
            ))
            with patch("fp_sentinel.notify.engine.send_notification") as mock_send:
                mock_send.return_value = MagicMock(
                    success=True, status_code=200, latency_ms=10.0, message="OK",
                )
                engine = NotifyEngine(store=store)
                finding = _finding(severity=Severity.HIGH)
                records = await engine.notify_status_change(
                    finding, "open", "in_progress",
                )
                assert len(records) >= 1
                assert records[0].event == NotifyEvent.STATUS_CHANGED

    @pytest.mark.asyncio
    async def test_engine_empty_findings(self, tmp_path):
        from fp_sentinel.notify.store import NotifyStore
        db_path = str(tmp_path / "test_notify4.db")
        store = NotifyStore(db_path)
        async with store:
            engine = NotifyEngine(store=store)
            records = await engine.process_findings([])
            assert records == []

    @pytest.mark.asyncio
    async def test_engine_no_matching_severity(self, tmp_path):
        from fp_sentinel.notify.store import NotifyStore
        db_path = str(tmp_path / "test_notify5.db")
        store = NotifyStore(db_path)
        async with store:
            channel = await store.create_channel(IMChannel(
                name="Ch1", channel_type=IMChannelType.FEISHU,
                webhook_url="https://im.example.com/hook",
            ))
            rule = await store.create_rule(_rule(
                channels=[channel.id],
                min_severity="CRITICAL",
            ))
            engine = NotifyEngine(store=store)
            finding = _finding(severity=Severity.MEDIUM)
            records = await engine.process_findings([finding])
            assert records == []
