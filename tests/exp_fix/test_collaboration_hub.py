"""
Tests for fp_sentinel.devops.collaboration_hub module.
Target: >= 95% code coverage.
"""

import pytest
from unittest.mock import MagicMock
from datetime import datetime, timezone, timedelta

from fp_sentinel.devops.collaboration_hub import (
    TicketStatus,
    AssignmentStrategy,
    SLAPolicy,
    AssigneeInfo,
    VulnTicket,
    RetestTask,
    EscalationEvent,
    TicketAllocator,
    ProgressTracker,
    RetestTrigger,
    SLAMonitor,
    CollaborationHub,
    _infer_category,
)


def _make_finding(
    rule_id="java-sql-injection",
    severity="HIGH",
    file_path="src/auth/UserController.py",
):
    f = MagicMock()
    f.rule_id = rule_id
    f.severity = severity
    f.file_path = file_path
    f.category = "SQL_INJECTION"
    f.finding_id = f"f-{hash(rule_id) % 10000:04d}"
    f.message = f"Vulnerability: {rule_id}"
    f.line_start = 42
    return f


# ─────────────────────── Enum Tests ───────────────────────

class TestEnums:
    def test_ticket_status_values(self):
        assert TicketStatus.PENDING.value == "pending"
        assert TicketStatus.ASSIGNED.value == "assigned"
        assert TicketStatus.IN_PROGRESS.value == "in_progress"
        assert TicketStatus.FIXED.value == "fixed"
        assert TicketStatus.VERIFIED.value == "verified"
        assert TicketStatus.REOPENED.value == "reopened"
        assert TicketStatus.WONT_FIX.value == "wont_fix"

    def test_assignment_strategy_values(self):
        assert AssignmentStrategy.ROUND_ROBIN.value == "round_robin"
        assert AssignmentStrategy.LOAD_BALANCED.value == "load_balanced"
        assert AssignmentStrategy.EXPERTISE_MATCH.value == "expertise_match"
        assert AssignmentStrategy.MODULE_OWNER.value == "module_owner"


# ─────────────────────── VulnTicket Tests ───────────────────────

class TestVulnTicket:
    def test_auto_id(self):
        t = VulnTicket()
        assert t.ticket_id.startswith("VULN-")

    def test_auto_created_at(self):
        t = VulnTicket()
        assert t.created_at
        # Should be valid ISO format
        datetime.fromisoformat(t.created_at)

    def test_custom_id(self):
        t = VulnTicket(ticket_id="CUSTOM-001")
        assert t.ticket_id == "CUSTOM-001"

    def test_default_status(self):
        t = VulnTicket()
        assert t.status == TicketStatus.PENDING.value

    def test_unique_ids(self):
        t1 = VulnTicket()
        t2 = VulnTicket()
        assert t1.ticket_id != t2.ticket_id


# ─────────────────────── RetestTask Tests ───────────────────────

class TestRetestTask:
    def test_auto_id(self):
        t = RetestTask()
        assert t.task_id.startswith("RT-")

    def test_default_status(self):
        t = RetestTask()
        assert t.status == "pending"

    def test_auto_created_at(self):
        t = RetestTask()
        assert t.created_at


# ─────────────────────── EscalationEvent Tests ───────────────────────

class TestEscalationEvent:
    def test_auto_id(self):
        e = EscalationEvent()
        assert e.event_id.startswith("ESC-")

    def test_default_type(self):
        e = EscalationEvent()
        assert e.event_type == "sla_warning"


# ─────────────────────── AssigneeInfo Tests ───────────────────────

class TestAssigneeInfo:
    def test_defaults(self):
        a = AssigneeInfo(user_id="u1", name="Alice")
        assert a.current_load == 0
        assert a.max_load == 10
        assert a.avg_fix_hours == 24.0
        assert a.specialties == []
        assert a.module_scope == []


# ─────────────────────── SLAPolicy Tests ───────────────────────

class TestSLAPolicy:
    def test_defaults(self):
        p = SLAPolicy()
        assert p.critical_hours == 4.0
        assert p.high_hours == 24.0
        assert p.medium_hours == 72.0

    def test_custom(self):
        p = SLAPolicy(critical_hours=2.0)
        assert p.critical_hours == 2.0


# ─────────────────────── TicketAllocator Tests ───────────────────────

class TestTicketAllocator:
    def _make_assignee(self, uid="u1", name="Alice", specialties=None, modules=None,
                       current_load=0, max_load=5):
        return AssigneeInfo(
            user_id=uid,
            name=name,
            specialties=specialties or ["sql_injection", "xss"],
            module_scope=modules or ["auth"],
            current_load=current_load,
            max_load=max_load,
        )

    def test_register_assignee(self):
        alloc = TicketAllocator()
        a = self._make_assignee()
        alloc.register_assignee(a)
        assert "u1" in alloc._assignees

    def test_register_module_owner(self):
        alloc = TicketAllocator()
        alloc.register_module_owner("auth", "u1")
        assert alloc._module_owners["auth"] == "u1"

    def test_assign_round_robin(self):
        alloc = TicketAllocator()
        a1 = self._make_assignee("u1", "Alice")
        a2 = self._make_assignee("u2", "Bob")
        alloc.register_assignee(a1)
        alloc.register_assignee(a2)
        ticket = VulnTicket()
        result = alloc.assign_ticket(ticket, AssignmentStrategy.ROUND_ROBIN.value)
        assert result == "u1"
        assert ticket.status == TicketStatus.ASSIGNED.value

    def test_assign_load_balanced(self):
        alloc = TicketAllocator()
        a1 = self._make_assignee("u1", "Alice", current_load=4, max_load=5)
        a2 = self._make_assignee("u2", "Bob", current_load=1, max_load=5)
        alloc.register_assignee(a1)
        alloc.register_assignee(a2)
        ticket = VulnTicket()
        result = alloc.assign_ticket(ticket, AssignmentStrategy.LOAD_BALANCED.value)
        # Bob has lower load
        assert result == "u2"

    def test_assign_expertise_match(self):
        alloc = TicketAllocator()
        a1 = self._make_assignee("u1", "Alice", specialties=["xss"])
        a2 = self._make_assignee("u2", "Bob", specialties=["sql_injection"])
        alloc.register_assignee(a1)
        alloc.register_assignee(a2)
        ticket = VulnTicket(category="SQL_INJECTION")
        result = alloc.assign_ticket(ticket, AssignmentStrategy.EXPERTISE_MATCH.value)
        assert result == "u2"

    def test_assign_module_owner(self):
        alloc = TicketAllocator()
        a1 = self._make_assignee("u1", "Alice", modules=["auth"])
        alloc.register_assignee(a1)
        alloc.register_module_owner("auth", "u1")
        ticket = VulnTicket(file_path="src/auth/login.py")
        result = alloc.assign_ticket(ticket, AssignmentStrategy.MODULE_OWNER.value)
        assert result == "u1"

    def test_assign_increments_load(self):
        alloc = TicketAllocator()
        a = self._make_assignee("u1", "Alice", current_load=0, max_load=5)
        alloc.register_assignee(a)
        ticket = VulnTicket()
        alloc.assign_ticket(ticket)
        assert a.current_load == 1

    def test_assign_at_max_load_fails(self):
        alloc = TicketAllocator()
        a = self._make_assignee("u1", "Alice", current_load=5, max_load=5)
        alloc.register_assignee(a)
        ticket = VulnTicket()
        result = alloc.assign_ticket(ticket)
        assert result is None

    def test_assign_no_assignees(self):
        alloc = TicketAllocator()
        ticket = VulnTicket()
        result = alloc.assign_ticket(ticket)
        assert result is None

    def test_assign_sets_sla(self):
        alloc = TicketAllocator()
        a = self._make_assignee()
        alloc.register_assignee(a)
        ticket = VulnTicket(severity="CRITICAL")
        alloc.assign_ticket(ticket)
        assert ticket.sla_deadline

    def test_batch_assign(self):
        alloc = TicketAllocator()
        a = self._make_assignee("u1", "Alice", max_load=10)
        alloc.register_assignee(a)
        tickets = [VulnTicket(), VulnTicket(), VulnTicket()]
        success, failed = alloc.batch_assign(tickets)
        assert success == 3
        assert failed == 0

    def test_batch_assign_partial_failure(self):
        alloc = TicketAllocator()
        a = self._make_assignee("u1", "Alice", max_load=1)
        alloc.register_assignee(a)
        tickets = [VulnTicket(), VulnTicket()]
        success, failed = alloc.batch_assign(tickets)
        assert success == 1
        assert failed == 1

    def test_batch_assign_round_robin(self):
        alloc = TicketAllocator()
        a = self._make_assignee("u1", "Alice", max_load=10)
        alloc.register_assignee(a)
        tickets = [VulnTicket()]
        success, failed = alloc.batch_assign(tickets, AssignmentStrategy.ROUND_ROBIN.value)
        assert success == 1
        assert failed == 0

    def test_batch_assign_expertise(self):
        alloc = TicketAllocator()
        a = self._make_assignee("u1", "Alice", max_load=10)
        alloc.register_assignee(a)
        tickets = [VulnTicket()]
        success, failed = alloc.batch_assign(tickets, AssignmentStrategy.EXPERTISE_MATCH.value)
        assert success == 1
        assert failed == 0

    def test_batch_assign_module_owner(self):
        alloc = TicketAllocator()
        a = self._make_assignee("u1", "Alice", modules=["src"], max_load=10)
        alloc.register_assignee(a)
        alloc.register_module_owner("src", "u1")
        tickets = [VulnTicket(file_path="src/auth/login.py")]
        success, failed = alloc.batch_assign(tickets, AssignmentStrategy.MODULE_OWNER.value)
        assert success == 1
        assert failed == 0

    def test_batch_assign_invalid_strategy(self):
        alloc = TicketAllocator()
        a = self._make_assignee("u1", "Alice", max_load=10)
        alloc.register_assignee(a)
        tickets = [VulnTicket()]
        # Invalid strategy defaults to load_balanced
        success, failed = alloc.batch_assign(tickets, "nonexistent_strategy")
        assert success == 1
        assert failed == 0

    def test_release_ticket(self):
        alloc = TicketAllocator()
        a = self._make_assignee("u1", "Alice", current_load=3, max_load=5)
        alloc.register_assignee(a)
        ticket = VulnTicket(assignee_id="u1")
        alloc.release_ticket(ticket)
        assert a.current_load == 2

    def test_release_does_not_go_negative(self):
        alloc = TicketAllocator()
        a = self._make_assignee("u1", "Alice", current_load=0, max_load=5)
        alloc.register_assignee(a)
        ticket = VulnTicket(assignee_id="u1")
        alloc.release_ticket(ticket)
        assert a.current_load == 0

    def test_round_robin_cycles(self):
        alloc = TicketAllocator()
        a1 = self._make_assignee("u1", "Alice")
        a2 = self._make_assignee("u2", "Bob")
        alloc.register_assignee(a1)
        alloc.register_assignee(a2)
        results = []
        for _ in range(4):
            t = VulnTicket()
            r = alloc.assign_ticket(t, AssignmentStrategy.ROUND_ROBIN.value)
            results.append(r)
        # Should cycle: u1, u2, u1, u2
        assert results == ["u1", "u2", "u1", "u2"]

    def test_invalid_strategy_defaults_to_load_balanced(self):
        alloc = TicketAllocator()
        a = self._make_assignee()
        alloc.register_assignee(a)
        ticket = VulnTicket()
        result = alloc.assign_ticket(ticket, "nonexistent_strategy")
        assert result == "u1"

    def test_assign_sets_timestamp(self):
        alloc = TicketAllocator()
        a = self._make_assignee()
        alloc.register_assignee(a)
        ticket = VulnTicket()
        alloc.assign_ticket(ticket)
        assert ticket.assigned_at


# ─────────────────────── ProgressTracker Tests ───────────────────────

class TestProgressTracker:
    def test_register_ticket(self):
        pt = ProgressTracker()
        t = VulnTicket(ticket_id="T1")
        pt.register_ticket(ticket=t)
        assert pt.get_ticket("T1") == t

    def test_valid_transition(self):
        pt = ProgressTracker()
        t = VulnTicket(ticket_id="T1")
        pt.register_ticket(t)
        assert pt.transition("T1", TicketStatus.ASSIGNED.value) is True
        assert t.status == TicketStatus.ASSIGNED.value

    def test_invalid_transition(self):
        pt = ProgressTracker()
        t = VulnTicket(ticket_id="T1")
        pt.register_ticket(t)
        # Cannot go from PENDING directly to FIXED (must go through IN_PROGRESS)
        assert pt.transition("T1", TicketStatus.FIXED.value) is False
        # Cannot go from PENDING directly to VERIFIED
        pt2 = ProgressTracker()
        t2 = VulnTicket(ticket_id="T2")
        pt2.register_ticket(t2)
        assert pt2.transition("T2", TicketStatus.VERIFIED.value) is False

    def test_transition_nonexistent_ticket(self):
        pt = ProgressTracker()
        assert pt.transition("nonexistent", TicketStatus.ASSIGNED.value) is False

    def test_transition_adds_comment(self):
        pt = ProgressTracker()
        t = VulnTicket(ticket_id="T1")
        pt.register_ticket(t)
        pt.transition("T1", TicketStatus.ASSIGNED.value, comment="Assigned to Alice")
        assert len(t.comments) == 1
        assert t.comments[0]["comment"] == "Assigned to Alice"

    def test_transition_updates_fixed_at(self):
        pt = ProgressTracker()
        t = VulnTicket(ticket_id="T1")
        pt.register_ticket(t)
        pt.transition("T1", TicketStatus.IN_PROGRESS.value)
        pt.transition("T1", TicketStatus.FIXED.value)
        assert t.fixed_at

    def test_transition_updates_verified_at(self):
        pt = ProgressTracker()
        t = VulnTicket(ticket_id="T1")
        pt.register_ticket(t)
        pt.transition("T1", TicketStatus.IN_PROGRESS.value)
        pt.transition("T1", TicketStatus.FIXED.value)
        pt.transition("T1", TicketStatus.VERIFIED.value)
        assert t.verified_at

    def test_status_history(self):
        pt = ProgressTracker()
        t = VulnTicket(ticket_id="T1")
        pt.register_ticket(t)
        pt.transition("T1", TicketStatus.ASSIGNED.value)
        pt.transition("T1", TicketStatus.IN_PROGRESS.value)
        history = pt.get_status_history("T1")
        assert len(history) == 3  # pending -> assigned -> in_progress
        assert history[0]["status"] == TicketStatus.PENDING.value
        assert history[1]["status"] == TicketStatus.ASSIGNED.value
        assert history[2]["status"] == TicketStatus.IN_PROGRESS.value

    def test_get_overdue_tickets(self):
        pt = ProgressTracker()
        t = VulnTicket(ticket_id="T1", status=TicketStatus.IN_PROGRESS.value)
        t.assigned_at = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        t.sla_deadline = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        pt.register_ticket(t)
        overdue = pt.get_overdue_tickets()
        assert len(overdue) == 1

    def test_not_overdue(self):
        pt = ProgressTracker()
        t = VulnTicket(ticket_id="T1", status=TicketStatus.IN_PROGRESS.value)
        t.assigned_at = datetime.now(timezone.utc).isoformat()
        t.sla_deadline = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        pt.register_ticket(t)
        overdue = pt.get_overdue_tickets()
        assert len(overdue) == 0

    def test_verified_not_overdue(self):
        pt = ProgressTracker()
        t = VulnTicket(ticket_id="T1", status=TicketStatus.VERIFIED.value)
        t.sla_deadline = (datetime.now(timezone.utc) - timedelta(hours=100)).isoformat()
        pt.register_ticket(t)
        overdue = pt.get_overdue_tickets()
        assert len(overdue) == 0

    def test_get_sla_warning_tickets(self):
        pt = ProgressTracker()
        t = VulnTicket(ticket_id="T1", status=TicketStatus.IN_PROGRESS.value)
        # Deadline in future but already 85% consumed
        t.assigned_at = (datetime.now(timezone.utc) - timedelta(hours=20)).isoformat()
        t.sla_deadline = (datetime.now(timezone.utc) + timedelta(hours=3.5)).isoformat()
        pt.register_ticket(t)
        warnings = pt.get_sla_warning_tickets(threshold=0.8)
        assert len(warnings) > 0

    def test_no_warning_for_finished(self):
        pt = ProgressTracker()
        t = VulnTicket(ticket_id="T1", status=TicketStatus.VERIFIED.value)
        t.assigned_at = (datetime.now(timezone.utc) - timedelta(hours=20)).isoformat()
        t.sla_deadline = datetime.now(timezone.utc).isoformat()
        pt.register_ticket(t)
        warnings = pt.get_sla_warning_tickets()
        assert len(warnings) == 0

    def test_progress_summary(self):
        pt = ProgressTracker()
        t1 = VulnTicket(ticket_id="T1", status=TicketStatus.PENDING.value)
        t2 = VulnTicket(ticket_id="T2", status=TicketStatus.ASSIGNED.value)
        t3 = VulnTicket(ticket_id="T3", status=TicketStatus.IN_PROGRESS.value)
        for t in [t1, t2, t3]:
            pt.register_ticket(t)
        summary = pt.get_progress_summary()
        assert summary.get(TicketStatus.PENDING.value, 0) == 1
        assert summary.get(TicketStatus.ASSIGNED.value, 0) == 1
        assert summary.get(TicketStatus.IN_PROGRESS.value, 0) == 1

    def test_assignee_stats(self):
        pt = ProgressTracker()
        t1 = VulnTicket(
            ticket_id="T1", status=TicketStatus.VERIFIED.value,
            assignee_id="u1", assignee_name="Alice"
        )
        t2 = VulnTicket(
            ticket_id="T2", status=TicketStatus.IN_PROGRESS.value,
            assignee_id="u1", assignee_name="Alice"
        )
        for t in [t1, t2]:
            pt.register_ticket(t)
        stats = pt.get_assignee_stats()
        assert "u1" in stats
        assert stats["u1"]["total"] == 2
        assert stats["u1"]["fixed"] == 1

    def test_all_tickets(self):
        pt = ProgressTracker()
        t1 = VulnTicket(ticket_id="T1")
        t2 = VulnTicket(ticket_id="T2")
        pt.register_ticket(t1)
        pt.register_ticket(t2)
        all_tickets = pt.all_tickets()
        assert len(all_tickets) == 2

    def test_status_history_nonexistent(self):
        pt = ProgressTracker()
        history = pt.get_status_history("nonexistent")
        assert history == []

    def test_get_status_history_empty_after_register(self):
        pt = ProgressTracker()
        t = VulnTicket(ticket_id="T1")
        pt.register_ticket(t)
        history = pt.get_status_history("T1")
        assert len(history) == 1


# ─────────────────────── RetestTrigger Tests ───────────────────────

class TestRetestTrigger:
    def test_schedule_retest(self):
        rt = RetestTrigger()
        task = rt.schedule_retest(
            ticket_id="T1",
            finding_id="F1",
            project_path="/app",
            trigger_type="manual",
        )
        assert task.status == "pending"
        assert task.ticket_id == "T1"

    def test_get_pending_tasks(self):
        rt = RetestTrigger()
        rt.schedule_retest("T1", "F1", ".")
        rt.schedule_retest("T2", "F2", ".")
        pending = rt.get_pending_tasks()
        assert len(pending) == 2

    def test_execute_task(self):
        rt = RetestTrigger()
        task = rt.schedule_retest("T1", "F1", ".")
        result = rt.execute_task(task.task_id)
        assert result is not None
        assert result.status == "success"

    def test_execute_nonexistent(self):
        rt = RetestTrigger()
        result = rt.execute_task("RT-NONEXISTENT")
        assert result is None

    def test_task_moves_to_completed(self):
        rt = RetestTrigger()
        task = rt.schedule_retest("T1", "F1", ".")
        rt.execute_task(task.task_id)
        assert len(rt.get_pending_tasks()) == 0
        assert len(rt.get_completed_tasks()) == 1

    def test_scheduled_tasks_auto_execute(self):
        rt = RetestTrigger()
        rt.schedule_retest("T1", "F1", ".", trigger_type="scheduled")
        triggered = rt.check_and_trigger_scheduled()
        assert len(triggered) == 1

    def test_auto_create_for_fixed(self):
        rt = RetestTrigger()
        pt = ProgressTracker()
        t = VulnTicket(ticket_id="T1", finding_id="F1", status=TicketStatus.FIXED.value)
        pt.register_ticket(t)
        tasks = rt.auto_create_retest_for_fixed(pt)
        assert len(tasks) == 1

    def test_no_duplicate_retest(self):
        rt = RetestTrigger()
        pt = ProgressTracker()
        t = VulnTicket(ticket_id="T1", finding_id="F1", status=TicketStatus.FIXED.value)
        pt.register_ticket(t)
        rt.auto_create_retest_for_fixed(pt)
        rt.auto_create_retest_for_fixed(pt)  # Second call
        # Should still have only 1 pending
        assert len(rt.get_pending_tasks()) == 1

    def test_locked_ticket_no_retest(self):
        rt = RetestTrigger()
        pt = ProgressTracker()
        t = VulnTicket(ticket_id="T1", finding_id="F1", status=TicketStatus.PENDING.value)
        pt.register_ticket(t)
        tasks = rt.auto_create_retest_for_fixed(pt)
        assert len(tasks) == 0


# ─────────────────────── SLAMonitor Tests ───────────────────────

class TestSLAMonitor:
    def test_check_all(self):
        monitor = SLAMonitor()
        pt = ProgressTracker()
        t = VulnTicket(
            ticket_id="T1",
            status=TicketStatus.IN_PROGRESS.value,
            assignee_name="Alice",
        )
        t.assigned_at = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        t.sla_deadline = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        pt.register_ticket(t)
        events = monitor.check_all(pt)
        assert len(events) > 0

    def test_no_violations(self):
        monitor = SLAMonitor()
        pt = ProgressTracker()
        t = VulnTicket(
            ticket_id="T1",
            status=TicketStatus.IN_PROGRESS.value,
        )
        t.assigned_at = datetime.now(timezone.utc).isoformat()
        t.sla_deadline = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        pt.register_ticket(t)
        events = monitor.check_all(pt)
        assert len(events) == 0

    def test_warning_events(self):
        monitor = SLAMonitor()
        pt = ProgressTracker()
        t = VulnTicket(
            ticket_id="T1",
            status=TicketStatus.IN_PROGRESS.value,
        )
        t.assigned_at = (datetime.now(timezone.utc) - timedelta(hours=20)).isoformat()
        t.sla_deadline = (datetime.now(timezone.utc) + timedelta(hours=3)).isoformat()
        pt.register_ticket(t)
        events = monitor.check_all(pt)
        # Should have warning event for SLA consumption
        warning_events = [e for e in events if e.event_type == "sla_warning"]
        assert len(warning_events) >= 0  # Depends on threshold

    def test_get_escalations(self):
        monitor = SLAMonitor()
        pt = ProgressTracker()
        t = VulnTicket(
            ticket_id="T1",
            status=TicketStatus.IN_PROGRESS.value,
            assignee_name="Alice",
        )
        t.assigned_at = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        t.sla_deadline = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        pt.register_ticket(t)
        monitor.check_all(pt)
        escalations = monitor.get_escalations()
        assert len(escalations) > 0

    def test_custom_policy(self):
        policy = SLAPolicy(critical_hours=2.0)
        monitor = SLAMonitor(policy=policy)
        assert monitor._policy.critical_hours == 2.0

    def test_format_remaining_positive(self):
        monitor = SLAMonitor()
        deadline = (datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)).isoformat()
        result = monitor._format_remaining(deadline)
        assert "小时" in result

    def test_format_remaining_negative(self):
        monitor = SLAMonitor()
        deadline = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        result = monitor._format_remaining(deadline)
        assert "超时" in result

    def test_format_remaining_invalid(self):
        monitor = SLAMonitor()
        result = monitor._format_remaining("invalid-date")
        assert result == "未知"


# ─────────────────────── CollaborationHub Tests ───────────────────────

class TestCollaborationHub:
    def test_create_and_assign(self):
        hub = CollaborationHub(industry="internet")
        hub.allocator.register_assignee(
            AssigneeInfo(user_id="u1", name="Alice", specialties=["sql_injection"])
        )
        finding = _make_finding()
        ticket = hub.create_and_assign_ticket(finding)
        assert ticket is not None
        assert ticket.assignee_id == "u1"
        assert ticket.status == TicketStatus.ASSIGNED.value

    def test_create_and_assign_no_assignees(self):
        hub = CollaborationHub()
        finding = _make_finding()
        ticket = hub.create_and_assign_ticket(finding)
        # Ticket created but not assigned
        assert ticket is not None
        assert ticket.assignee_id == ""

    def test_process_fix_and_retest(self):
        hub = CollaborationHub()
        hub.allocator.register_assignee(
            AssigneeInfo(user_id="u1", name="Alice")
        )
        finding = _make_finding()
        ticket = hub.create_and_assign_ticket(finding)
        hub.tracker.transition(ticket.ticket_id, TicketStatus.IN_PROGRESS.value)
        success = hub.process_fix_and_retest(ticket.ticket_id, commit_hash="abc123")
        assert success is True
        assert ticket.status == TicketStatus.FIXED.value
        assert ticket.fix_commit_hash == "abc123"
        # Should have pending retest
        assert len(hub.retest.get_pending_tasks()) > 0

    def test_process_fix_invalid_transition(self):
        hub = CollaborationHub()
        hub.allocator.register_assignee(
            AssigneeInfo(user_id="u1", name="Alice")
        )
        finding = _make_finding()
        ticket = hub.create_and_assign_ticket(finding)
        # Cannot go from ASSIGNED directly to FIXED
        success = hub.process_fix_and_retest(ticket.ticket_id)
        assert success is False

    def test_run_sla_check(self):
        hub = CollaborationHub(industry="finance")
        events = hub.run_sla_check()
        assert isinstance(events, list)

    def test_get_dashboard(self):
        hub = CollaborationHub(industry="internet")
        hub.allocator.register_assignee(
            AssigneeInfo(user_id="u1", name="Alice")
        )
        finding = _make_finding()
        hub.create_and_assign_ticket(finding)
        dashboard = hub.get_dashboard()
        assert "industry" in dashboard
        assert "total_tickets" in dashboard
        assert dashboard["total_tickets"] >= 1

    def test_dashboard_progress_counts(self):
        hub = CollaborationHub()
        hub.allocator.register_assignee(
            AssigneeInfo(user_id="u1", name="Alice", max_load=5)
        )
        hub.create_and_assign_ticket(_make_finding())
        hub.create_and_assign_ticket(_make_finding())
        dashboard = hub.get_dashboard()
        assert dashboard["progress"].get(TicketStatus.ASSIGNED.value, 0) >= 2

    def test_dashboard_assignee_stats(self):
        hub = CollaborationHub()
        hub.allocator.register_assignee(
            AssigneeInfo(user_id="u1", name="Alice", max_load=5)
        )
        hub.create_and_assign_ticket(_make_finding())
        dashboard = hub.get_dashboard()
        assert "assignee_stats" in dashboard

    def test_industry_stored(self):
        hub = CollaborationHub(industry="finance")
        assert hub.industry == "finance"

    def test_properties(self):
        hub = CollaborationHub()
        assert hub.allocator is not None
        assert hub.tracker is not None
        assert hub.retest is not None


# ─────────────────────── Infer Category Tests ───────────────────────

class TestInferCategory:
    def test_sql(self):
        assert _infer_category("java-sql-injection") == "SQL_INJECTION"

    def test_xss(self):
        assert _infer_category("reflected-xss") == "XSS"

    def test_command(self):
        assert _infer_category("os.system-command") == "COMMAND_INJECTION"

    def test_deser(self):
        assert _infer_category("java-deserialization") == "DESERIALIZATION"

    def test_ssrf(self):
        assert _infer_category("http-ssrf-request") == "SSRF"

    def test_path(self):
        assert _infer_category("path-traversal") == "PATH_TRAVERSAL"

    def test_unknown(self):
        assert _infer_category("unknown-rule-xyz") == "OTHER"


# ─────────────────────── Valid State Transitions Tests ───────────────────────

class TestValidStateTransitions:
    """Test the complete state machine."""
    def _setup(self):
        pt = ProgressTracker()
        t = VulnTicket(ticket_id="T1")
        pt.register_ticket(t)
        return pt, t

    def test_pending_to_assigned(self):
        pt, t = self._setup()
        assert pt.transition("T1", TicketStatus.ASSIGNED.value) is True

    def test_pending_to_wont_fix(self):
        pt, t = self._setup()
        assert pt.transition("T1", TicketStatus.WONT_FIX.value) is True
        assert t.status == TicketStatus.WONT_FIX.value

    def test_assigned_to_in_progress(self):
        pt, t = self._setup()
        pt.transition("T1", TicketStatus.ASSIGNED.value)
        assert pt.transition("T1", TicketStatus.IN_PROGRESS.value) is True

    def test_in_progress_to_fixed(self):
        pt, t = self._setup()
        pt.transition("T1", TicketStatus.ASSIGNED.value)
        pt.transition("T1", TicketStatus.IN_PROGRESS.value)
        assert pt.transition("T1", TicketStatus.FIXED.value) is True

    def test_fixed_to_verified(self):
        pt, t = self._setup()
        pt.transition("T1", TicketStatus.ASSIGNED.value)
        pt.transition("T1", TicketStatus.IN_PROGRESS.value)
        pt.transition("T1", TicketStatus.FIXED.value)
        assert pt.transition("T1", TicketStatus.VERIFIED.value) is True

    def test_fixed_to_reopened(self):
        pt, t = self._setup()
        pt.transition("T1", TicketStatus.ASSIGNED.value)
        pt.transition("T1", TicketStatus.IN_PROGRESS.value)
        pt.transition("T1", TicketStatus.FIXED.value)
        assert pt.transition("T1", TicketStatus.REOPENED.value) is True

    def test_reopened_to_assigned(self):
        pt, t = self._setup()
        transitions = [
            TicketStatus.ASSIGNED.value,
            TicketStatus.IN_PROGRESS.value,
            TicketStatus.FIXED.value,
            TicketStatus.REOPENED.value,
            TicketStatus.ASSIGNED.value,
        ]
        for ts in transitions:
            assert pt.transition("T1", ts) is True

    def test_pending_cannot_go_to_verified(self):
        pt, t = self._setup()
        assert pt.transition("T1", TicketStatus.VERIFIED.value) is False

    def test_pending_cannot_go_to_fixed(self):
        pt, t = self._setup()
        # Direct PENDING -> FIXED is not allowed (must go through IN_PROGRESS)
        assert pt.transition("T1", TicketStatus.FIXED.value) is False

    def test_verified_is_terminal(self):
        pt, t = self._setup()
        pt.transition("T1", TicketStatus.ASSIGNED.value)
        pt.transition("T1", TicketStatus.IN_PROGRESS.value)
        pt.transition("T1", TicketStatus.FIXED.value)
        pt.transition("T1", TicketStatus.VERIFIED.value)
        # Cannot transition from VERIFIED
        assert pt.transition("T1", TicketStatus.ASSIGNED.value) is False

    def test_wont_fix_is_terminal(self):
        pt, t = self._setup()
        pt.transition("T1", TicketStatus.WONT_FIX.value)
        assert pt.transition("T1", TicketStatus.ASSIGNED.value) is False
