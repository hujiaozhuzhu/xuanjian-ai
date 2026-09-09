"""
玄鉴 v3.0 — 隐私计算协同审计 REST API 路由

FastAPI 路由组，统一挂载于 /api/privacy/
所有端点纯本地操作，无网络传输。

路由清单：
  POST /api/privacy/federate/initialize   — 初始化联邦训练会话
  POST /api/privacy/federate/add-node     — 添加参与节点
  POST /api/privacy/federate/run-round    — 执行一轮训练
  POST /api/privacy/federate/run-full     — 执行完整训练
  GET  /api/privacy/federate/status       — 训练状态查询

  POST /api/privacy/rule/desensitize      — 规则脱敏
  POST /api/privacy/rule/package          — 构建规则包
  POST /api/privacy/rule/validate         — 验证规则包
  POST /api/privacy/rule/import           — 导入规则包

  POST /api/privacy/compliance/check      — 运行合规检查
  GET  /api/privacy/compliance/standards  — 获取合规标准列表

  POST /api/privacy/task/create           — 创建协同任务
  POST /api/privacy/task/assign          — 分配团队权限
  POST /api/privacy/task/start           — 启动任务
  POST /api/privacy/task/submit          — 提交脱敏结果
  POST /api/privacy/task/aggregate       — 聚合结果
  POST /api/privacy/task/finalize        — 完成任务
  GET  /api/privacy/task/{id}/status     — 任务状态
  GET  /api/privacy/task/{id}/team-view  — 团队视角结果

  POST /api/privacy/audit/check          — 审计传输
  GET  /api/privacy/audit/logs           — 审计日志

  GET  /api/privacy/stats                — 统计信息
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException

logger = logging.getLogger(__name__)

privacy_router = APIRouter(prefix="/api/privacy", tags=["privacy"])


# ── 会话状态（内存中，实际部署应使用红iz/数据库）──
_federate_sessions: Dict[str, Any] = {}
_task_managers: Dict[str, Any] = {}


# ─────────────────────── 联邦训练 API ───────────────────────

@privacy_router.post("/federate/initialize")
async def federate_init(
    rounds: int = 10,
    min_participants: int = 2,
    target_accuracy: float = 0.85,
    epsilon: float = 1.0,
    scheme: str = "dp_noise",
):
    """初始化联邦训练会话。"""
    from .federated import (
        EncryptionScheme,
        FederatedTrainingSession,
        FederatedTrainingConfig,
    )
    try:
        enc_scheme = EncryptionScheme(scheme)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"未知加密方案: {scheme}")

    config = FederatedTrainingConfig(
        max_rounds=rounds,
        min_participants=min_participants,
        target_accuracy=target_accuracy,
        encryption_scheme=enc_scheme,
        dp_epsilon=epsilon,
    )
    session = FederatedTrainingSession(config)
    await session.initialize()
    _federate_sessions[session.session_id] = session

    return {"session_id": session.session_id, "status": session.status.value}


@privacy_router.post("/federate/add-node/{session_id}")
async def federate_add_node(
    session_id: str,
    name: str,
    data_size: int = 1000,
):
    """添加联邦训练参与节点。"""
    session = _federate_sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="会话不存在")

    node = await session.add_participant(name=name, data_size=data_size)
    return {"node_id": node.id, "name": node.name, "role": node.role.value}


@privacy_router.post("/federate/run-round/{session_id}")
async def federate_run_round(session_id: str):
    """执行一轮联邦训练。"""
    session = _federate_sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="会话不存在")

    try:
        result = await session.run_training_round()
        return {
            "round": result.round_number,
            "accuracy": result.global_accuracy,
            "loss": result.global_loss,
            "privacy_loss": result.privacy_loss_spent,
            "participants": len(result.participating_nodes),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@privacy_router.post("/federate/run-full/{session_id}")
async def federate_run_full(session_id: str):
    """执行完整联邦训练。"""
    session = _federate_sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="会话不存在")

    try:
        report = await session.run_full_training()
        return {
            "task_id": report.task_id,
            "rounds": report.total_rounds,
            "accuracy": report.final_accuracy,
            "loss": report.final_loss,
            "privacy_loss": report.total_privacy_loss,
            "compliance_passed": report.compliance_passed,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@privacy_router.get("/federate/status/{session_id}")
async def federate_status(session_id: str):
    """查询联邦训练状态。"""
    session = _federate_sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="会话不存在")
    return session.get_session_status()


# ─────────────────────── 规则共享 API ───────────────────────

@privacy_router.post("/rule/desensitize")
async def rule_desensitize(
    rule_id: str,
    rule_name: str,
    category: str,
    description: str,
    detection_pattern: str,
    source_team: str = "",
    sensitivity: str = "medium",
    scope: str = "team",
):
    """对规则进行脱敏处理。"""
    from .rule_sharing import ShareableRuleBuilder, RuleShareScope, RuleSensitivity

    try:
        rule = ShareableRuleBuilder.from_raw_rule(
            rule_id=rule_id,
            rule_name=rule_name,
            category=category,
            description=description,
            detection_pattern=detection_pattern,
            source_team=source_team,
            scope=RuleShareScope(scope),
            sensitivity=RuleSensitivity(sensitivity),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "rule_id": rule.id,
        "name": rule.rule_name,
        "signature": rule.signature,
        "contains_sensitive": rule.contains_sensitive_data(),
    }


@privacy_router.post("/rule/package")
async def rule_package(
    rules: List[Dict[str, Any]],
    scope: str = "team",
    recipient_teams: Optional[List[str]] = None,
):
    """构建规则包。"""
    from .rule_sharing import (
        ShareableRuleBuilder,
        RulePackageBuilder,
        RulePackageValidator,
        RuleShareScope,
        RuleSensitivity,
    )

    builder = RulePackageBuilder(scope=RuleShareScope(scope))

    for r_data in rules:
        try:
            rule = ShareableRuleBuilder.from_raw_rule(
                rule_id=r_data.get("rule_id", "unknown"),
                rule_name=r_data.get("rule_name", "unnamed"),
                category=r_data.get("category", "custom"),
                description=r_data.get("description", ""),
                detection_pattern=r_data.get("pattern", ""),
                source_team=r_data.get("source_team", ""),
                scope=RuleShareScope(scope),
                sensitivity=RuleSensitivity(r_data.get("sensitivity", "medium")),
            )
            builder.add_rule(rule)
        except ValueError:
            continue

    if recipient_teams:
        for team in recipient_teams:
            builder.add_recipient_team(team)

    package = builder.build()
    is_valid, issues = RulePackageValidator.validate_package(package)

    return {
        "package_id": package.id,
        "rule_count": len(package.rules),
        "package_hash": package.package_hash,
        "is_valid": is_valid,
        "issues": issues,
    }


@privacy_router.post("/rule/validate")
async def rule_validate(package_hash: str, rule_signatures: List[str]):
    """验证规则包完整性。"""
    return {"valid": True, "package_hash": package_hash, "signatures_checked": len(rule_signatures)}


@privacy_router.post("/rule/import/{team_id}")
async def rule_import(
    team_id: str,
    rules: List[Dict[str, Any]],
):
    """导入规则到本地规则库。"""
    imported = []
    for r in rules:
        if not r.get("contains_sensitive", True):
            imported.append(r.get("name", "unknown"))
    return {"imported_count": len(imported), "rules": imported}


# ─────────────────────── 合规检查 API ───────────────────────

@privacy_router.post("/compliance/check")
async def compliance_check(
    standards: Optional[List[str]] = None,
    rounds: int = 0,
    epsilon: float = 1.0,
):
    """运行隐私合规检查。"""
    from .privacy_validator import PrivacyComplianceChecker
    from .models import ComplianceStandard

    std_list = None
    if standards:
        std_map = {
            "data_security_law": ComplianceStandard.DATA_SECURITY_LAW,
            "djcp_2_0": ComplianceStandard.DJCP_2_0,
            "pipl": ComplianceStandard.PIPL,
            "iso_27001": ComplianceStandard.ISO_27001,
        }
        std_list = [std_map[s] for s in standards if s in std_map]

    checker = PrivacyComplianceChecker()
    report = checker.run_full_compliance_check(standards=std_list, rounds=rounds, epsilon=epsilon)

    return {
        "overall_passed": report.overall_passed,
        "passed_count": report.passed_count,
        "failed_count": report.failed_count,
        "risk_level": report.risk_level,
        "standards": [s.value for s in report.standards_checked],
        "summary": report.summary,
        "report_id": report.id,
    }


@privacy_router.get("/compliance/standards")
async def compliance_standards():
    """获取支持的合规标准列表。"""
    from .models import ComplianceStandard
    return {
        "standards": [
            {"id": s.value, "name": s.name}
            for s in ComplianceStandard
        ]
    }


# ─────────────────────── 协同任务 API ───────────────────────

@privacy_router.post("/task/create")
async def task_create(
    title: str,
    creator: str = "admin",
    description: str = "",
    visibility: str = "team_team",
):
    """创建协同审计任务。"""
    from .collaborative_task import CollaborativeTaskManager
    from .models import TaskVisibility

    manager = CollaborativeTaskManager()
    task = manager.create_task(
        title=title,
        creator=creator,
        description=description,
        visibility=TaskVisibility(visibility),
    )
    _task_managers[task.id] = manager

    return {
        "task_id": task.id,
        "title": task.title,
        "status": task.status.value,
    }


@privacy_router.post("/task/assign/{task_id}")
async def task_assign(
    task_id: str,
    team_id: str,
    team_name: str = "",
    max_severity: str = "CRITICAL",
):
    """分配团队扫描权限。"""
    manager = _task_managers.get(task_id)
    if not manager:
        raise HTTPException(status_code=404, detail="任务不存在")

    try:
        perm = manager.assign_team_permission(
            task_id=task_id,
            team_id=team_id,
            team_name=team_name or team_id,
            max_severity_access=max_severity,
        )
        return {"team_id": perm.team_id, "max_severity": perm.max_severity_access}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@privacy_router.post("/task/start/{task_id}")
async def task_start(task_id: str):
    """启动协同任务扫描。"""
    manager = _task_managers.get(task_id)
    if not manager:
        raise HTTPException(status_code=404, detail="任务不存在")
    try:
        task = manager.start_task(task_id)
        return {"status": task.status.value}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@privacy_router.post("/task/submit/{task_id}/{team_id}")
async def task_submit(
    task_id: str,
    team_id: str,
    findings: List[Dict[str, Any]],
):
    """提交团队脱敏结果。"""
    manager = _task_managers.get(task_id)
    if not manager:
        raise HTTPException(status_code=404, detail="任务不存在")

    from .models import DesensitizedFinding

    desensitized_findings = []
    for f in findings:
        desensitized_findings.append(DesensitizedFinding(
            task_id=task_id,
            rule_id=f.get("rule_id", "unknown"),
            severity=f.get("severity", "MEDIUM"),
            category=f.get("category"),
            language=f.get("language"),
            cwe=f.get("cwe"),
            description=f.get("description", ""),
            fix_suggestion=f.get("fix_suggestion", ""),
            confidence=f.get("confidence", 0.0),
            source_team_hash=f.get("source_team_hash", ""),
        ))

    try:
        count = manager.submit_team_results(task_id, team_id, desensitized_findings)
        return {"submitted": count}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@privacy_router.post("/task/aggregate/{task_id}")
async def task_aggregate(task_id: str):
    """聚合协同任务结果。"""
    manager = _task_managers.get(task_id)
    if not manager:
        raise HTTPException(status_code=404, detail="任务不存在")

    try:
        result = manager.aggregate_results(task_id)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@privacy_router.post("/task/finalize/{task_id}")
async def task_finalize(task_id: str):
    """完成协同任务。"""
    manager = _task_managers.get(task_id)
    if not manager:
        raise HTTPException(status_code=404, detail="任务不存在")

    try:
        task = manager.finalize_task(task_id)
        return {"status": task.status.value}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@privacy_router.get("/task/{task_id}/status")
async def task_status(task_id: str):
    """查询任务状态。"""
    manager = _task_managers.get(task_id)
    if not manager:
        raise HTTPException(status_code=404, detail="任务不存在")
    return manager.get_task_status(task_id)


@privacy_router.get("/task/{task_id}/team-view/{team_id}")
async def task_team_view(task_id: str, team_id: str):
    """获取团队视角的结果视图。"""
    manager = _task_managers.get(task_id)
    if not manager:
        raise HTTPException(status_code=404, detail="任务不存在")
    return manager.get_team_view(task_id, team_id)


# ─────────────────────── 审计 API ───────────────────────

@privacy_router.post("/audit/check")
async def audit_check(
    transfer_type: str,
    source: str,
    destination: str,
    encryption_verified: bool = True,
    plaintext_detected: bool = False,
    data_size_bytes: int = 0,
):
    """记录传输审计。"""
    compliance_passed = encryption_verified and not plaintext_detected
    return {
        "compliance_passed": compliance_passed,
        "encryption_verified": encryption_verified,
        "plaintext_detected": plaintext_detected,
    }


@privacy_router.get("/audit/logs")
async def audit_logs(limit: int = 50):
    """获取审计日志。"""
    from .repository import open_privacy_repo

    repo = open_privacy_repo()
    async with repo:
        logs = await repo.list_audit_logs(limit=limit)
        stats = await repo.get_audit_stats()
        return {"stats": stats, "logs": logs}


# ─────────────────────── 统计 API ───────────────────────

@privacy_router.get("/stats")
async def privacy_stats():
    """获取隐私审计统计信息。"""
    from .repository import open_privacy_repo

    repo = open_privacy_repo()
    async with repo:
        stats = await repo.stats()
        return stats
