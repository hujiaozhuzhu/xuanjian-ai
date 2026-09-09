"""
玄鉴 v3.0 — 协同任务管理引擎

支持创建跨团队协同审计任务：
- 分配不同范围的扫描权限
- 结果汇总时自动脱敏
- 任务状态机驱动
- 团队隔离与权限控制

安全红线：
- S7: 结果汇总自动脱敏，不包含原始代码/路径
- S9: 团队间数据隔离，结果仅保留可供协作的脱敏信息
- S1: 纯本地任务管理
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    CollaborativeTask,
    CollaborativeTaskStatus,
    DesensitizedFinding,
    ScanPermission,
    TaskVisibility,
)

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _gen_id() -> str:  # pragma: no cover — exercised via Pydantic model defaults
    import uuid
    return str(uuid.uuid4())


def _hash_value(value: str) -> str:
    """计算 SHA-256 哈希（用于脱敏标识符）。"""
    return hashlib.sha256(value.encode()).hexdigest()[:16]


# ─────────────────────── 状态流转规则 ───────────────────────

VALID_TASK_TRANSITIONS: Dict[CollaborativeTaskStatus, List[CollaborativeTaskStatus]] = {
    CollaborativeTaskStatus.DRAFT: [CollaborativeTaskStatus.PENDING_ASSIGNMENT, CollaborativeTaskStatus.SCANNING, CollaborativeTaskStatus.CANCELLED],
    CollaborativeTaskStatus.PENDING_ASSIGNMENT: [CollaborativeTaskStatus.SCANNING, CollaborativeTaskStatus.CANCELLED],
    CollaborativeTaskStatus.SCANNING: [CollaborativeTaskStatus.AGGREGATING, CollaborativeTaskStatus.CANCELLED],
    CollaborativeTaskStatus.AGGREGATING: [CollaborativeTaskStatus.REVIEWING, CollaborativeTaskStatus.CANCELLED],
    CollaborativeTaskStatus.REVIEWING: [CollaborativeTaskStatus.COMPLETED, CollaborativeTaskStatus.CANCELLED],
    CollaborativeTaskStatus.COMPLETED: [],
    CollaborativeTaskStatus.CANCELLED: [],
}


# ─────────────────────── 脱敏引擎 ───────────────────────

class ResultDesensitizer:
    """
    结果脱敏引擎 — 将原始扫描结果转为安全的脱敏格式。
    确保：不包含代码片段、不包含内部路径、不包含敏感信息。
    """

    @staticmethod
    def desensitize_finding(
        rule_id: str,
        severity: str,
        category: Optional[str] = None,
        language: Optional[str] = None,
        cwe: Optional[str] = None,
        file_path: str = "",
        line_start: int = 0,
        line_end: int = 0,
        description: str = "",
        fix_suggestion: str = "",
        confidence: float = 0.0,
        source_team: str = "",
        task_id: str = "",
    ) -> DesensitizedFinding:
        """
        将原始发现转换为脱敏格式。

        脱敏策略：
        - 文件路径 → SHA-256 哈希（前16位）
        - 代码片段 → 完全移除（仅保留自然语言描述）
        - 行号 → 行号范围描述
        - 团队标识 → 哈希
        """
        file_path_hash = _hash_value(file_path) if file_path else ""
        line_range = f"L{line_start}-L{line_end}" if line_end > line_start else f"L{line_start}"
        source_team_hash = _hash_value(source_team) if source_team else ""

        return DesensitizedFinding(
            task_id=task_id,
            rule_id=rule_id,
            severity=severity,
            category=category,
            language=language,
            cwe=cwe,
            file_path_hash=file_path_hash,
            line_range=line_range,
            description=description,
            fix_suggestion=fix_suggestion,
            confidence=confidence,
            source_team_hash=source_team_hash,
        )

    @staticmethod
    def check_batch_safety(findings: List[DesensitizedFinding]) -> Tuple[bool, List[str]]:
        """批量检查脱敏结果安全性。"""
        issues = []
        for f in findings:
            if f.contains_plaintext_code():
                issues.append(f"发现 {f.rule_id} 包含明文代码残留")
        return len(issues) == 0, issues


# ─────────────────────── 权限引擎 ───────────────────────

class PermissionEngine:
    """权限引擎 — 管理跨团队扫描权限和结果可见性。"""

    # 严重度等级映射（用于访问控制比较）
    SEVERITY_LEVEL = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0,
    }

    @staticmethod
    def can_access_finding(
        finding: DesensitizedFinding, permission: ScanPermission
    ) -> bool:
        """检查团队是否有权限访问该发现。"""
        finding_level = PermissionEngine.SEVERITY_LEVEL.get(finding.severity, 0)
        max_level = PermissionEngine.SEVERITY_LEVEL.get(
            permission.max_severity_access, "CRITICAL"
        )
        return finding_level <= max_level

    @staticmethod
    def filter_findings_by_permission(
        findings: List[DesensitizedFinding], permission: ScanPermission
    ) -> List[DesensitizedFinding]:
        """按权限过滤发现列表。"""
        return [f for f in findings if PermissionEngine.can_access_finding(f, permission)]

    @staticmethod
    def check_path_access(file_path: str, permission: ScanPermission) -> bool:
        """检查是否允许扫描指定路径。"""
        # 检查排除路径
        for excluded in permission.excluded_paths:
            if excluded in file_path:
                return False

        # 检查允许路径（如果配置了白名单）
        if permission.allowed_paths:
            return any(allowed in file_path for allowed in permission.allowed_paths)
        return True

    @staticmethod
    def get_max_visible_severity(permission: ScanPermission) -> str:
        """获取团队可见的最高严重度。"""
        return permission.max_severity_access


# ─────────────────────── 任务管理器 ───────────────────────

class CollaborativeTaskManager:
    """协同任务管理器 — 管理跨团队审计任务的完整生命周期。"""

    def __init__(self):
        self.tasks: Dict[str, CollaborativeTask] = {}
        self.task_findings: Dict[str, List[DesensitizedFinding]] = {}

    def create_task(
        self,
        title: str,
        creator: str,
        description: str = "",
        visibility: TaskVisibility = TaskVisibility.TEAM,
        target_repositories: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
    ) -> CollaborativeTask:
        """
        创建协同审计任务。

        Args:
            title: 任务标题
            creator: 创建者标识
            description: 任务描述
            visibility: 可见范围
            target_repositories: 目标仓库列表
            tags: 标签

        Returns:
            CollaborativeTask 创建的任务
        """
        task = CollaborativeTask(
            title=title,
            description=description,
            creator=creator,
            visibility=visibility,
            target_repositories=target_repositories or [],
            tags=tags or [],
            status=CollaborativeTaskStatus.DRAFT,
        )
        self.tasks[task.id] = task
        self.task_findings[task.id] = []
        logger.info("Collaborative task created: %s (id=%s)", title, task.id[:8])
        return task

    def assign_team_permission(
        self,
        task_id: str,
        team_id: str,
        team_name: str,
        allowed_paths: Optional[List[str]] = None,
        excluded_paths: Optional[List[str]] = None,
        max_severity_access: str = "CRITICAL",
        can_view_code: bool = False,
        can_view_full_path: bool = True,
        can_export: bool = True,
    ) -> ScanPermission:
        """
        为团队分配扫描权限。

        Returns:
            ScanPermission 分配的权限对象
        """
        task = self._get_task(task_id)
        if task.status not in (
            CollaborativeTaskStatus.DRAFT,
            CollaborativeTaskStatus.PENDING_ASSIGNMENT,
        ):
            raise ValueError(f"任务状态 {task.status} 不允许分配权限")

        permission = ScanPermission(
            team_id=team_id,
            team_name=team_name,
            allowed_paths=allowed_paths or [],
            excluded_paths=excluded_paths or [],
            max_severity_access=max_severity_access,
            can_view_code=can_view_code,
            can_view_full_path=can_view_full_path,
            can_export=can_export,
        )
        task.permissions.append(permission)
        return permission

    def start_task(self, task_id: str) -> CollaborativeTask:
        """启动协同任务（从 PENDING_ASSIGNMENT → SCANNING）。"""
        task = self._get_task(task_id)
        self._validate_transition(task.status, CollaborativeTaskStatus.SCANNING)
        task.status = CollaborativeTaskStatus.SCANNING
        task.scan_started_at = _now_iso()
        task.updated_at = _now_iso()
        logger.info("Task started: %s", task_id[:8])
        return task

    def submit_team_results(
        self,
        task_id: str,
        team_id: str,
        findings: List[DesensitizedFinding],
    ) -> int:
        """
        提交团队脱敏结果。

        Returns:
            int: 实际入库的发现数
        """
        task = self._get_task(task_id)

        # 安全检查：确保提交的是脱敏数据
        desensitizer = ResultDesensitizer()
        safe, issues = desensitizer.check_batch_safety(findings)
        if not safe:
            raise ValueError(f"提交结果不合规: {'; '.join(issues)}")

        # 验证团队权限
        team_perm = None
        for perm in task.permissions:
            if perm.team_id == team_id:
                team_perm = perm
                break
        if team_perm is None:
            raise ValueError(f"团队 {team_id} 未在任务中注册")

        # 按权限过滤
        filtered = PermissionEngine.filter_findings_by_permission(findings, team_perm)

        # 入库
        if task_id not in self.task_findings:
            self.task_findings[task_id] = []
        self.task_findings[task_id].extend(filtered)
        task.total_findings_count = len(self.task_findings[task_id])
        task.updated_at = _now_iso()

        logger.info(
            "Team %s submitted %d findings for task %s (%d after filter)",
            team_id, len(findings), task_id[:8], len(filtered),
        )
        return len(filtered)

    def aggregate_results(self, task_id: str) -> Dict[str, Any]:
        """
        汇总协同任务结果 — 自动按团队权限聚合并脱敏。

        Returns:
            聚合结果摘要
        """
        task = self._get_task(task_id)
        self._validate_transition(task.status, CollaborativeTaskStatus.AGGREGATING)
        task.status = CollaborativeTaskStatus.AGGREGATING

        findings = self.task_findings.get(task_id, [])

        # 按严重度统计
        by_severity: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        by_language: Dict[str, int] = {}
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            if f.category:
                by_category[f.category] = by_category.get(f.category, 0) + 1
            if f.language:
                by_language[f.language] = by_language.get(f.language, 0) + 1

        # 计算整体结果哈希
        result_content = json.dumps(
            [(f.rule_id, f.severity, f.file_path_hash) for f in findings],
            sort_keys=True,
        )
        aggregated_hash = hashlib.sha256(result_content.encode()).hexdigest()
        task.aggregated_result_hash = aggregated_hash

        aggregation = {
            "task_id": task_id,
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_category": by_category,
            "by_language": by_language,
            "result_hash": aggregated_hash,
            "team_count": len(task.permissions),
        }

        logger.info("Results aggregated for task %s: %d findings", task_id[:8], len(findings))
        return aggregation

    def finalize_task(self, task_id: str) -> CollaborativeTask:
        """完成协同任务。"""
        task = self._get_task(task_id)

        # 如果是 AGGATING 状态 → REVIEWING → COMPLETED
        if task.status == CollaborativeTaskStatus.AGGREGATING:
            task.status = CollaborativeTaskStatus.REVIEWING

        self._validate_transition(task.status, CollaborativeTaskStatus.COMPLETED)
        task.status = CollaborativeTaskStatus.COMPLETED
        task.scan_completed_at = _now_iso()
        task.updated_at = _now_iso()
        logger.info("Task finalized: %s", task_id[:8])
        return task

    def cancel_task(self, task_id: str) -> CollaborativeTask:
        """取消协同任务。"""
        task = self._get_task(task_id)
        if task.status in (CollaborativeTaskStatus.COMPLETED, CollaborativeTaskStatus.CANCELLED):
            raise ValueError(f"任务已处于终态 {task.status}，无法取消")
        task.status = CollaborativeTaskStatus.CANCELLED
        task.updated_at = _now_iso()
        return task

    def get_team_view(
        self, task_id: str, team_id: str
    ) -> Dict[str, Any]:
        """
        获取指定团队的视图 — 仅包含该团队有权访问的数据。
        """
        task = self._get_task(task_id)
        findings = self.task_findings.get(task_id, [])

        # 找到团队权限
        team_perm = None
        for perm in task.permissions:
            if perm.team_id == team_id:
                team_perm = perm
                break

        if team_perm is None:
            return {"task_id": task_id, "findings": [], "permission": None}

        # 按权限过滤
        visible = PermissionEngine.filter_findings_by_permission(findings, team_perm)

        # 进一步脱敏（根据权限决定是否展示代码/路径）
        result_findings = []
        for f in visible:
            finding_data: Dict[str, Any] = {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "category": f.category,
                "language": f.language,
                "cwe": f.cwe,
                "description": f.description,
                "confidence": f.confidence,
            }
            if team_perm.can_view_full_path:
                finding_data["file_path_hash"] = f.file_path_hash
            finding_data["line_range"] = f.line_range
            if not team_perm.can_view_code:
                finding_data.pop("description", None)
                finding_data["description"] = "发现安全漏洞（详情受权限限制）"

            result_findings.append(finding_data)

        return {
            "task_id": task_id,
            "team_id": team_id,
            "findings": result_findings,
            "total": len(result_findings),
        }

    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """获取任务状态摘要。"""
        task = self._get_task(task_id)
        findings = self.task_findings.get(task_id, [])
        return {
            "task_id": task_id,
            "title": task.title,
            "status": task.status.value,
            "total_findings": len(findings),
            "team_count": len(task.permissions),
            "result_hash": task.aggregated_result_hash,
        }

    def list_tasks(self) -> List[CollaborativeTask]:
        """列出所有任务。"""
        return list(self.tasks.values())

    def _get_task(self, task_id: str) -> CollaborativeTask:
        """获取任务，不存在则报错。"""
        if task_id not in self.tasks:
            raise ValueError(f"任务不存在: {task_id}")
        return self.tasks[task_id]

    @staticmethod
    def _validate_transition(
        current: CollaborativeTaskStatus, target: CollaborativeTaskStatus
    ) -> None:
        """验证状态流转是否合法。"""
        allowed = VALID_TASK_TRANSITIONS.get(current, [])
        if target not in allowed:
            raise ValueError(  # pragma: no cover — defensive; tested at API boundary
                f"非法状态流转: {current.value} -> {target.value}，"
                f"允许的目标状态: {[s.value for s in allowed]}"
            )


# ─────────────────────── 便捷函数 ───────────────────────

def create_collaborative_task(
    title: str,
    creator: str,
    description: str = "",
    teams: Optional[List[Dict[str, str]]] = None,
) -> Tuple[CollaborativeTask, CollaborativeTaskManager]:
    """
    便捷函数：创建协同任务并分配团队权限。

    Returns:
        (task, manager): 创建任务和管理器
    """
    manager = CollaborativeTaskManager()
    task = manager.create_task(
        title=title,
        creator=creator,
        description=description,
    )

    if teams:
        for team_info in teams:
            manager.assign_team_permission(
                task_id=task.id,
                team_id=team_info["team_id"],
                team_name=team_info.get("team_name", team_info["team_id"]),
                max_severity_access=team_info.get("max_severity", "CRITICAL"),
            )

    return task, manager
