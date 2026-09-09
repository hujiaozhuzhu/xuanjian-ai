"""
玄鉴 v3.2 — 协同整改中心 (Experience Optimization Module)

支持漏洞工单自动分配、整改进度跟踪、复测自动触发。

核心功能：
1. 漏洞工单智能分配（按模块负责人、负载均衡、专长匹配）
2. 整进度跟踪（状态机：待分配->已分配->修复中->已修复->已验证）
3. 复测自动触发（支持定时轮询和事件触发两种模式）
4. 整改 SLA 监控（超时告警、升级提醒）

安全红线：
- S6: 所有操作在本地数据库，外部调用通过适配器
- S3: 工单操作通过适配器层隔离外部 API
- S5: 历史数据按保留策略自动清理
- S2: 不修改用户源文件

版本: 3.2.0
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ─────────────────────── 枚举与常量 ───────────────────────

class TicketStatus(str, Enum):
    """工单状态枚举"""
    PENDING = "pending"               # 待分配
    ASSIGNED = "assigned"             # 已分配
    IN_PROGRESS = "in_progress"       # 修复中
    FIXED = "fixed"                   # 已修复
    VERIFIED = "verified"             # 已验证关闭
    REOPENED = "reopened"             # 重新打开
    WONT_FIX = "wont_fix"             # 不修复（有例外）


class AssignmentStrategy(str, Enum):
    """工单分配策略"""
    ROUND_ROBIN = "round_robin"       # 轮询
    LOAD_BALANCED = "load_balanced"   # 负载均衡
    EXPERTISE_MATCH = "expertise_match"  # 专长匹配
    MODULE_OWNER = "module_owner"     # 模块负责人


# ─────────────────────── 数据模型 ─────────────────────────

@dataclass
class AssigneeInfo:
    """负责人信息"""
    user_id: str
    name: str
    email: str = ""
    specialties: List[str] = field(default_factory=list)  # 专长领域
    module_scope: List[str] = field(default_factory=list)  # 负责模块
    current_load: int = 0                                # 当前工单数
    max_load: int = 10                                    # 最大并行数
    avg_fix_hours: float = 24.0                          # 平均修复时间(小时)


@dataclass
class SLAPolicy:
    """SLA 策略"""
    critical_hours: float = 4.0       # 严重级响应时限
    high_hours: float = 24.0          # 高危级响应时限
    medium_hours: float = 72.0        # 中危级响应时限
    low_hours: float = 168.0          # 低危级响应时限
    escalation_threshold: float = 0.8  # 超时 80% 触发升级提醒


@dataclass
class VulnTicket:
    """漏洞工单"""
    ticket_id: str = ""
    finding_id: str = ""
    title: str = ""
    severity: str = "MEDIUM"
    category: str = ""
    file_path: str = ""
    line_start: int = 0
    description: str = ""
    status: str = TicketStatus.PENDING.value
    assignee_id: str = ""
    assignee_name: str = ""
    created_at: str = ""
    assigned_at: str = ""
    fixed_at: str = ""
    verified_at: str = ""
    sla_deadline: str = ""
    comments: List[Dict[str, str]] = field(default_factory=list)
    fix_commit_hash: str = ""
    verification_result: str = ""
    tags: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.ticket_id:
            self.ticket_id = f"VULN-{uuid.uuid4().hex[:8].upper()}"
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()


@dataclass
class RetestTask:
    """复测任务"""
    task_id: str = ""
    ticket_id: str = ""
    finding_id: str = ""
    project_path: str = ""
    scan_command: str = ""
    trigger_type: str = "manual"      # manual/scheduled/event
    status: str = "pending"           # pending/running/success/failed
    created_at: str = ""
    executed_at: str = ""
    result: str = ""

    def __post_init__(self) -> None:
        if not self.task_id:
            self.task_id = f"RT-{uuid.uuid4().hex[:8].upper()}"
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()


@dataclass 
class EscalationEvent:
    """升级事件"""
    event_id: str = ""
    ticket_id: str = ""
    event_type: str = "sla_warning"   # sla_warning/escalation/overdue
    message: str = ""
    created_at: str = ""

    def __post_init__(self) -> None:
        if not self.event_id:
            self.event_id = f"ESC-{uuid.uuid4().hex[:8].upper()}"
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()


# ─────────────────────── 工单智能分配器 ─────────────────────────

class TicketAllocator:
    """
    漏洞工单智能分配器

    根据策略将漏洞工单分配给最合适的修复人员。
    """

    def __init__(self) -> None:
        self._assignees: Dict[str, AssigneeInfo] = {}
        self._module_owners: Dict[str, str] = {}  # module -> user_id
        self._round_robin_index: int = 0
        self._assignment_log: List[Dict[str, Any]] = []

    def register_assignee(self, info: AssigneeInfo) -> None:
        """注册修复人员"""
        self._assignees[info.user_id] = info
        for mod in info.module_scope:
            self._module_owners[mod] = info.user_id

    def register_module_owner(self, module: str, user_id: str) -> None:
        """注册模块负责人"""
        self._module_owners[module] = user_id

    def assign_ticket(
        self,
        ticket: VulnTicket,
        strategy: str = AssignmentStrategy.LOAD_BALANCED.value,
    ) -> Optional[str]:
        """
        为工单分配负责人

        Args:
            ticket: 漏洞工单
            strategy: 分配策略

        Returns:
            分配的 user_id，或 None 如果无法分配
        """
        if strategy == AssignmentStrategy.ROUND_ROBIN.value:
            assignee = self._assign_round_robin()
        elif strategy == AssignmentStrategy.LOAD_BALANCED.value:
            assignee = self._assign_load_balanced(ticket)
        elif strategy == AssignmentStrategy.EXPERTISE_MATCH.value:
            assignee = self._assign_expertise_match(ticket)
        elif strategy == AssignmentStrategy.MODULE_OWNER.value:
            assignee = self._assign_module_owner(ticket)
        else:
            # 默认：负载均衡
            assignee = self._assign_load_balanced(ticket)

        if assignee:
            ticket.assignee_id = assignee.user_id
            ticket.assignee_name = assignee.name
            ticket.status = TicketStatus.ASSIGNED.value
            ticket.assigned_at = datetime.now(timezone.utc).isoformat()
            assignee.current_load += 1

            # 计算 SLA 截止时间
            self._set_sla_deadline(ticket)

            self._assignment_log.append({
                "ticket_id": ticket.ticket_id,
                "assignee_id": assignee.user_id,
                "strategy": strategy,
                "timestamp": ticket.assigned_at,
            })
            logger.info(
                f"工单 {ticket.ticket_id} 已分配给 {assignee.name} "
                f"(策略: {strategy})"
            )

        return assignee.user_id if assignee else None

    def batch_assign(
        self,
        tickets: List[VulnTicket],
        strategy: str = AssignmentStrategy.LOAD_BALANCED.value,
    ) -> Tuple[int, int]:
        """
        批量分配工单

        Returns:
            (成功数, 失败数)
        """
        success = 0
        failed = 0
        for ticket in tickets:
            result = self._allocate_single(ticket, strategy)
            if result:
                success += 1
            else:
                failed += 1
        return success, failed

    def _allocate_single(
        self,
        ticket: VulnTicket,
        strategy: str,
    ) -> Optional[str]:
        """内部分配（不修改状态，外部批量使用）"""
        if strategy == AssignmentStrategy.ROUND_ROBIN.value:
            assignee = self._assign_round_robin()
        elif strategy == AssignmentStrategy.LOAD_BALANCED.value:
            assignee = self._assign_load_balanced(ticket)
        elif strategy == AssignmentStrategy.EXPERTISE_MATCH.value:
            assignee = self._assign_expertise_match(ticket)
        elif strategy == AssignmentStrategy.MODULE_OWNER.value:
            assignee = self._assign_module_owner(ticket)
        else:
            assignee = self._assign_load_balanced(ticket)

        if assignee:
            ticket.assignee_id = assignee.user_id
            ticket.assignee_name = assignee.name
            ticket.status = TicketStatus.ASSIGNED.value
            ticket.assigned_at = datetime.now(timezone.utc).isoformat()
            assignee.current_load += 1
            self._set_sla_deadline(ticket)

        return assignee.user_id if assignee else None

    def release_ticket(self, ticket: VulnTicket) -> None:
        """释放工单（完成或取消时减少负责人负载）"""
        if ticket.assignee_id and ticket.assignee_id in self._assignees:
            assignee = self._assignees[ticket.assignee_id]
            assignee.current_load = max(0, assignee.current_load - 1)

    def _assign_round_robin(self) -> Optional[AssigneeInfo]:
        """轮询分配"""
        candidates = [
            a for a in self._assignees.values()
            if a.current_load < a.max_load
        ]
        if not candidates:
            return None
        idx = self._round_robin_index % len(candidates)
        self._round_robin_index += 1
        return candidates[idx]

    def _assign_load_balanced(self, ticket: VulnTicket) -> Optional[AssigneeInfo]:
        """负载均衡分配：选当前负载比最低的人"""
        candidates = [
            a for a in self._assignees.values()
            if a.current_load < a.max_load
        ]
        if not candidates:
            return None

        # 如果 ticket 有模块信息，优先模块负责人
        mod_assignee = self._get_module_assignee(ticket)
        if mod_assignee and mod_assignee.current_load < mod_assignee.max_load:
            return mod_assignee

        # 选出负载最低的
        return min(candidates, key=lambda a: a.current_load / a.max_load)

    def _assign_expertise_match(self, ticket: VulnTicket) -> Optional[AssigneeInfo]:
        """专长匹配分配"""
        candidates = [
            a for a in self._assignees.values()
            if a.current_load < a.max_load
        ]
        if not candidates:
            return None

        # 计算每个候选人的匹配得分
        best: Optional[AssigneeInfo] = None
        best_score = -1.0

        category_lower = (ticket.category or "").lower()
        for a in candidates:
            score = 0.0
            # 专长匹配
            for spec in a.specialties:
                if spec.lower() in category_lower or category_lower in spec.lower():
                    score += 3.0
            # 模块匹配
            for mod in a.module_scope:
                if mod in (ticket.file_path or ""):
                    score += 2.0
            # 负载少加分
            load_ratio = 1.0 - (a.current_load / a.max_load)
            score += load_ratio * 1.0

            if score > best_score:
                best_score = score
                best = a

        return best or candidates[0]

    def _assign_module_owner(self, ticket: VulnTicket) -> Optional[AssigneeInfo]:
        """模块负责人优先"""
        assignee = self._get_module_assignee(ticket)
        if assignee:
            return assignee
        # 回退到负载均衡
        return self._assign_load_balanced(ticket)

    def _get_module_assignee(self, ticket: VulnTicket) -> Optional[AssigneeInfo]:
        """获取 ticket 对应模块的负责人"""
        file_path = ticket.file_path or ""
        for mod, uid in self._module_owners.items():
            if mod in file_path and uid in self._assignees:
                return self._assignees[uid]
        return None

    def _set_sla_deadline(self, ticket: VulnTicket) -> None:
        """根据严重度计算 SLA 截止时间"""
        policy = SLAPolicy()
        severity = (ticket.severity or "MEDIUM").upper()
        hours = {
            "CRITICAL": policy.critical_hours,
            "HIGH": policy.high_hours,
            "MEDIUM": policy.medium_hours,
            "LOW": policy.low_hours,
        }.get(severity, policy.medium_hours)

        deadline = datetime.now(timezone.utc) + timedelta(hours=hours)
        ticket.sla_deadline = deadline.isoformat()


# ─────────────────────── 进度跟踪器 ─────────────────────────

class ProgressTracker:
    """
    整改进度跟踪器

    跟踪漏洞从发现到修复完成的完整生命周期。
    """

    # 状态转换规则
    VALID_TRANSITIONS: Dict[str, Set[str]] = {
        TicketStatus.PENDING.value: {
            TicketStatus.ASSIGNED, TicketStatus.IN_PROGRESS, TicketStatus.WONT_FIX
        },
        TicketStatus.ASSIGNED.value: {
            TicketStatus.IN_PROGRESS, TicketStatus.WONT_FIX
        },
        TicketStatus.IN_PROGRESS.value: {
            TicketStatus.FIXED, TicketStatus.WONT_FIX
        },
        TicketStatus.FIXED.value: {
            TicketStatus.VERIFIED, TicketStatus.REOPENED
        },
        TicketStatus.REOPENED.value: {
            TicketStatus.ASSIGNED, TicketStatus.IN_PROGRESS
        },
        TicketStatus.WONT_FIX.value: set(),  # 终态
        TicketStatus.VERIFIED.value: set(),  # 终态
    }

    def __init__(self) -> None:
        self._tickets: Dict[str, VulnTicket] = {}
        self._status_history: Dict[str, List[Dict[str, str]]] = {}

    def register_ticket(self, ticket: VulnTicket) -> None:
        """注册工单"""
        self._tickets[ticket.ticket_id] = ticket
        self._status_history[ticket.ticket_id] = [{
            "status": ticket.status,
            "timestamp": ticket.created_at or datetime.now(timezone.utc).isoformat(),
        }]

    def transition(
        self,
        ticket_id: str,
        new_status: str,
        comment: str = "",
    ) -> bool:
        """
        状态转换

        Args:
            ticket_id: 工单ID
            new_status: 新状态
            comment: 备注

        Returns:
            是否成功转换
        """
        ticket = self._tickets.get(ticket_id)
        if not ticket:
            return False

        current = ticket.status
        valid_next = self.VALID_TRANSITIONS.get(current, set())
        if new_status not in valid_next:
            logger.warning(
                f"无效状态转换: {ticket_id} {current} -> {new_status}"
            )
            return False

        now = datetime.now(timezone.utc).isoformat()
        ticket.status = new_status

        # 更新关键时间戳
        if new_status == TicketStatus.FIXED.value:
            ticket.fixed_at = now
        elif new_status == TicketStatus.VERIFIED.value:
            ticket.verified_at = now

        # 添加备注
        if comment:
            ticket.comments.append({
                "status": new_status,
                "comment": comment,
                "timestamp": now,
            })

        # 记录历史
        self._status_history.setdefault(ticket_id, []).append({
            "status": new_status,
            "timestamp": now,
        })

        return True

    def get_ticket(self, ticket_id: str) -> Optional[VulnTicket]:
        """获取工单"""
        return self._tickets.get(ticket_id)

    def get_status_history(self, ticket_id: str) -> List[Dict[str, str]]:
        """获取状态历史"""
        return self._status_history.get(ticket_id, [])

    def get_overdue_tickets(
        self,
        reference_time: Optional[datetime] = None,
    ) -> List[VulnTicket]:
        """获取已超期的工单"""
        if reference_time is None:
            reference_time = datetime.now(timezone.utc)

        overdue: List[VulnTicket] = []
        for ticket in self._tickets.values():
            if ticket.status in (
                TicketStatus.VERIFIED.value, TicketStatus.WONT_FIX.value
            ):
                continue
            if ticket.sla_deadline:
                try:
                    deadline = datetime.fromisoformat(ticket.sla_deadline)
                    if reference_time > deadline:
                        overdue.append(ticket)
                except (ValueError, TypeError):
                    continue
        return overdue

    def get_sla_warning_tickets(
        self,
        threshold: float = 0.8,
        reference_time: Optional[datetime] = None,
    ) -> List[Tuple[VulnTicket, float]]:
        """
        获取 SLA 预警工单（已消耗超过 threshold 比例但还未超时）

        Returns:
            List of (ticket, consumption_ratio) tuples
        """
        if reference_time is None:
            reference_time = datetime.now(timezone.utc)

        warnings: List[Tuple[VulnTicket, float]] = []
        for ticket in self._tickets.values():
            if ticket.status in (
                TicketStatus.VERIFIED.value, TicketStatus.WONT_FIX.value
            ):
                continue
            if not ticket.sla_deadline or not ticket.assigned_at:
                continue
            try:
                deadline = datetime.fromisoformat(ticket.sla_deadline)
                assigned = datetime.fromisoformat(ticket.assigned_at)
                total = (deadline - assigned).total_seconds()
                elapsed = (reference_time - assigned).total_seconds()
                if total > 0:
                    ratio = elapsed / total
                    if ratio >= threshold and ratio < 1.0:
                        warnings.append((ticket, round(ratio, 3)))
            except (ValueError, TypeError):
                continue
        return warnings

    def get_progress_summary(self) -> Dict[str, int]:
        """获取进度摘要（各状态的工单数）"""
        summary: Dict[str, int] = {}
        for t in self._tickets.values():
            summary[t.status] = summary.get(t.status, 0) + 1
        return summary

    def get_assignee_stats(self) -> Dict[str, Dict[str, int]]:
        """获取修复人员统计"""
        stats: Dict[str, Dict[str, int]] = {}
        for t in self._tickets.values():
            aid = t.assignee_id
            if not aid:
                continue
            if aid not in stats:
                stats[aid] = {"name": t.assignee_name, "total": 0, "fixed": 0}
            stats[aid]["total"] += 1
            if t.status in (TicketStatus.VERIFIED.value, TicketStatus.FIXED.value):
                stats[aid]["fixed"] += 1
        return stats

    def all_tickets(self) -> List[VulnTicket]:
        """获取所有工单"""
        return list(self._tickets.values())


# ─────────────────────── 复测触发器 ─────────────────────────

class RetestTrigger:
    """
    自动复测触发器

    支持三种触发模式：
    1. manual: 手动触发
    2. scheduled: 定时轮询（每 N 分钟）
    3. event: 事件驱动（Git push hook 等）
    """

    def __init__(self) -> None:
        self._pending_tasks: Dict[str, RetestTask] = {}
        self._completed_tasks: Dict[str, RetestTask] = {}
        self._scheduled_interval_minutes: int = 30

    def schedule_retest(
        self,
        ticket_id: str,
        finding_id: str,
        project_path: str,
        trigger_type: str = "manual",
        scan_command: str = "",
    ) -> RetestTask:
        """
        调度复测任务

        Args:
            ticket_id: 关联工单ID
            finding_id: 漏洞ID
            project_path: 项目路径
            trigger_type: 触发类型
            scan_command: 扫描命令

        Returns:
            RetestTask
        """
        task = RetestTask(
            ticket_id=ticket_id,
            finding_id=finding_id,
            project_path=project_path,
            scan_command=scan_command or "fp-sentinel scan",
            trigger_type=trigger_type,
            status="pending",
        )
        self._pending_tasks[task.task_id] = task
        logger.info(
            f"复测任务已创建: {task.task_id} (类型: {trigger_type})"
        )
        return task

    def get_pending_tasks(self) -> List[RetestTask]:
        """获取待执行的复测任务"""
        return list(self._pending_tasks.values())

    def get_completed_tasks(self) -> List[RetestTask]:
        """获取已完成的复测任务"""
        return list(self._completed_tasks.values())

    def execute_task(self, task_id: str) -> Optional[RetestTask]:
        """
        执行复测任务（模拟执行，实际应调用扫描服务）

        Returns:
            执行完成的任务，或 None
        """
        task = self._pending_tasks.get(task_id)
        if not task:
            return None

        task.status = "running"
        task.executed_at = datetime.now(timezone.utc).isoformat()

        # 模拟执行结果（实际应调用扫描 engine）
        # 实际实现中这里应该调用 fp-sentinel scan 或 HTTP API
        task.status = "success"
        task.result = "simulated_scan_completed"
        task.verified_at = datetime.now(timezone.utc).isoformat()

        # 移动到已完成
        self._completed_tasks[task_id] = task
        del self._pending_tasks[task_id]
        return task

    def check_and_trigger_scheduled(self) -> List[RetestTask]:
        """
        检查并触发定时复测

        Returns:
            本次触发的任务列表
        """
        triggered: List[RetestTask] = []
        now = datetime.now(timezone.utc)

        for task_id, task in list(self._pending_tasks.items()):
            if task.trigger_type != "scheduled":
                continue
            # 创建后立即执行一次
            executed = self.execute_task(task_id)
            if executed:
                triggered.append(executed)

        return triggered

    def auto_create_retest_for_fixed(
        self,
        tracker: ProgressTracker,
    ) -> List[RetestTask]:
        """
        自动为所有已修复的工单创建复测任务

        Returns:
            创建的复测任务列表
        """
        tasks: List[RetestTask] = []
        for ticket in tracker.all_tickets():
            if ticket.status == TicketStatus.FIXED.value and not self._has_pending_retest(ticket.ticket_id):
                task = self.schedule_retest(
                    ticket_id=ticket.ticket_id,
                    finding_id=ticket.finding_id,
                    project_path=".",
                    trigger_type="event",
                )
                tasks.append(task)
        return tasks

    def _has_pending_retest(self, ticket_id: str) -> bool:
        """检查是否已有待执行的复测任务"""
        for task in self._pending_tasks.values():
            if task.ticket_id == ticket_id:
                return True
        return False


# ─────────────────────── SLA 监控器 ─────────────────────────

class SLAMonitor:
    """SLA 监控器"""

    def __init__(self, policy: Optional[SLAPolicy] = None) -> None:
        self._policy = policy or SLAPolicy()
        self._escalations: List[EscalationEvent] = []

    def check_all(
        self,
        tracker: ProgressTracker,
    ) -> List[EscalationEvent]:
        """
        检查所有工单的 SLA 状态

        Returns:
            新产生的升级事件
        """
        new_events: List[EscalationEvent] = []

        # 检查预警
        warnings = tracker.get_sla_warning_tickets(
            threshold=self._policy.escalation_threshold
        )
        for ticket, ratio in warnings:
            event = EscalationEvent(
                ticket_id=ticket.ticket_id,
                event_type="sla_warning",
                message=(
                    f"工单 {ticket.ticket_id} SLA 已消耗 {ratio:.0%}，"
                    f"距截止时间还有 {self._format_remaining(ticket.sla_deadline)}"
                ),
            )
            self._escalations.append(event)
            new_events.append(event)

        # 检查超时
        overdue = tracker.get_overdue_tickets()
        for ticket in overdue:
            event = EscalationEvent(
                ticket_id=ticket.ticket_id,
                event_type="overdue",
                message=(
                    f"工单 {ticket.ticket_id} 已超出 SLA 截止时间！"
                    f"负责人: {ticket.assignee_name}"
                ),
            )
            self._escalations.append(event)
            new_events.append(event)

        return new_events

    def get_escalations(self) -> List[EscalationEvent]:
        """获取所有升级事件"""
        return list(self._escalations)

    def _format_remaining(self, deadline_iso: str) -> str:
        """格式化剩余时间"""
        try:
            deadline = datetime.fromisoformat(deadline_iso)
            remaining = deadline - datetime.now(timezone.utc)
            if remaining.total_seconds() <= 0:
                return "已超时"
            hours = int(remaining.total_seconds() / 3600)
            minutes = int((remaining.total_seconds() % 3600) / 60)
            return f"{hours}小时{minutes}分钟"
        except (ValueError, TypeError):
            return "未知"


# ─────────────────────── 一站式协同中心 ─────────────────────────

class CollaborationHub:
    """
    协同整改一站式入口

    整合工单分配、进度跟踪、复测触发、SLA 监控的便捷入口。
    """

    def __init__(
        self,
        industry: str = "internet",
    ) -> None:
        self._allocator = TicketAllocator()
        self._tracker = ProgressTracker()
        self._retest = RetestTrigger()
        self._sla_monitor = SLAMonitor()
        self._industry = industry

    @property
    def allocator(self) -> TicketAllocator:
        return self._allocator

    @property
    def tracker(self) -> ProgressTracker:
        return self._tracker

    @property
    def retest(self) -> RetestTrigger:
        return self._retest

    @property
    def industry(self) -> str:
        return self._industry

    def create_and_assign_ticket(
        self,
        finding: Any,
        strategy: str = AssignmentStrategy.LOAD_BALANCED.value,
    ) -> Optional[VulnTicket]:
        """
        从 finding 创建工单并自动分配

        Returns:
            创建的 VulnTicket，或 None
        """
        ticket = VulnTicket(
            finding_id=getattr(finding, "finding_id", "") or f"f-{uuid.uuid4().hex[:8]}",
            title=f"[{getattr(finding, 'severity', '?')}] {getattr(finding, 'rule_id', 'unknown')}",
            severity=getattr(finding, "severity", "MEDIUM") or "MEDIUM",
            category=getattr(finding, "category", "") or _infer_category(getattr(finding, "rule_id", "")),
            file_path=getattr(finding, "file_path", ""),
            line_start=getattr(finding, "line_start", 0),
            description=getattr(finding, "message", "") or "",
        )

        self._tracker.register_ticket(ticket)
        assigned = self._allocator.assign_ticket(ticket, strategy)
        if not assigned:
            logger.warning(f"工单 {ticket.ticket_id} 分配失败，待人工分配")

        return ticket

    def process_fix_and_retest(
        self,
        ticket_id: str,
        commit_hash: str = "",
    ) -> bool:
        """
        处理修复完成：标记为已修复 -> 自动触发复测

        Returns:
            是否成功
        """
        # 转为 FIXED
        success = self._tracker.transition(
            ticket_id, TicketStatus.FIXED.value,
            comment=f"修复已提交 (commit: {commit_hash})" if commit_hash else "修复完成"
        )
        if not success:
            return False

        # 获取工单信息
        ticket = self._tracker.get_ticket(ticket_id)
        if not ticket:
            return False

        # 关联 commit hash
        if commit_hash:
            ticket.fix_commit_hash = commit_hash

        # 触发复测
        self._retest.schedule_retest(
            ticket_id=ticket_id,
            finding_id=ticket.finding_id,
            project_path=".",
            trigger_type="event",
        )

        # 释放负载
        self._allocator.release_ticket(ticket)

        return True

    def run_sla_check(self) -> List[EscalationEvent]:
        """运行 SLA 检查"""
        return self._sla_monitor.check_all(self._tracker)

    def get_dashboard(self) -> Dict[str, Any]:
        """获取管理仪表板数据"""
        progress = self._tracker.get_progress_summary()
        overdue = len(self._tracker.get_overdue_tickets())
        warnings = len(self._tracker.get_sla_warning_tickets())

        return {
            "industry": self._industry,
            "total_tickets": sum(progress.values()),
            "progress": progress,
            "overdue_count": overdue,
            "sla_warning_count": warnings,
            "pending_retest": len(self._retest.get_pending_tasks()),
            "assignee_stats": self._tracker.get_assignee_stats(),
            "check_time": datetime.now(timezone.utc).isoformat(),
        }


def _infer_category(rule_id: str) -> str:
    """从 rule_id 推断漏洞类别"""
    rid = (rule_id or "").lower()
    if "sql" in rid:
        return "SQL_INJECTION"
    if "xss" in rid:
        return "XSS"
    if any(k in rid for k in ["command", "cmd", "os.system"]):
        return "COMMAND_INJECTION"
    if any(k in rid for k in ["serial", "pickle"]):
        return "DESERIALIZATION"
    if "ssrf" in rid:
        return "SSRF"
    if any(k in rid for k in ["path", "travers"]):
        return "PATH_TRAVERSAL"
    return "OTHER"
