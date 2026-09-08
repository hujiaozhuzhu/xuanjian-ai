"""
玄鉴 v3.0 — 隐私计算协同审计 CLI 命令组

fp-sentinel privacy <subcommand>
  - train    : 联邦学习协同训练
  - rule     : 规则共享管理
  - validate : 隐私合规验证
  - task     : 协同任务管理
  - audit    : 数据传输审计
  - stats    : 隐私审计统计

安全红线：
- 所有操作纯本地，零网络
- 不传输原始代码/漏洞数据
"""

import asyncio
import json
import logging
from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table
from rich import box

logger = logging.getLogger(__name__)

privacy_app = typer.Typer(
    name="privacy",
    help="隐私计算协同审计 (v3.0): 联邦学习 / 规则共享 / 隐私验证 / 协同任务",
    add_completion=False,
)


def _fmt_time(iso_str: str) -> str:
    """简化 ISO 时间显示。"""
    if not iso_str:
        return "-"
    try:
        return iso_str[:19].replace("T", " ")
    except Exception:
        return iso_str


def _compliance_style(passed: bool):
    return "green" if passed else "red"


# ─────────────────── 联邦训练命令 ───────────────────

@privacy_app.command("train")
def federated_train(
    rounds: int = typer.Option(5, "--rounds", "-r", min=1, max=100, help="训练轮次"),
    participants: int = typer.Option(3, "--participants", "-p", min=2, max=50, help="参与方数量"),
    target_acc: float = typer.Option(0.85, "--target-acc", min=0.0, max=1.0, help="目标准确率"),
    epsilon: float = typer.Option(1.0, "--epsilon", min=0.0, max=10.0, help="差分隐私预算"),
    scheme: str = typer.Option("dp_noise", "--scheme", help="加密方案 (dp_noise/he_paillier/secret_sharing)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="详细输出"),
):
    """执行联邦学习协同训练 — 原始数据不出本地，仅上传加密梯度。"""
    from .federated import (
        EncryptionScheme,
        FederatedTrainingConfig,
        FederatedTrainingSession,
        FederationNode,
        FederationRole,
    )
    from .crypto import GradientEncryptionEngine

    async def _run():
        try:
            enc_scheme = EncryptionScheme(scheme)
        except ValueError:
            typer.echo(f"[red]未知加密方案: {scheme}[/red]")
            raise typer.Exit(1)

        config = FederatedTrainingConfig(
            max_rounds=rounds,
            min_participants=participants,
            target_accuracy=target_acc,
            encryption_scheme=enc_scheme,
            dp_epsilon=epsilon,
        )
        session = FederatedTrainingSession(config)
        await session.initialize()

        # 添加参与方
        for i in range(participants):
            await session.add_participant(
                name=f"branch-{i+1:02d}",
                data_size=500 + i * 200,
            )

        typer.echo(f"\n🔐 联邦学习训练启动")
        typer.echo(f"  参与方: {participants} | 轮次: {rounds} | DPε: {epsilon}")
        typer.echo(f"  加密方案: {scheme}\n")

        report = await session.run_full_training()

        # 输出结果
        table = Table(title="📊 联邦训练结果", box=box.ROUNDED, show_lines=True)
        table.add_column("指标", style="cyan")
        table.add_column("值", style="white")
        table.add_row("训练轮次", str(report.total_rounds))
        table.add_row("最终准确率", f"{report.final_accuracy:.4f}")
        table.add_row("最终损失", f"{report.final_loss:.4f}")
        table.add_row("累计隐私损失", f"{report.total_privacy_loss:.4f}")
        table.add_row("参与方数", str(report.participant_count))
        table.add_row("模型哈希", report.model_hash[:16] + "...")
        table.add_row("隐私合规", "✅ 通过" if report.compliance_passed else "❌ 未通过")
        typer.echo(table)

        if verbose:
            round_table = Table(title="各轮次详情", box=box.SIMPLE)
            round_table.add_column("轮次", justify="right")
            round_table.add_column("准确率", justify="right")
            round_table.add_column("损失", justify="right")
            round_table.add_column("隐私损失", justify="right")
            round_table.add_column("聚合耗时(ms)", justify="right")
            for r in report.round_results:
                round_table.add_row(
                    str(r.round_number),
                    f"{r.global_accuracy:.4f}",
                    f"{r.global_loss:.4f}",
                    f"{r.privacy_loss_spent:.4f}",
                    f"{r.aggregation_time_ms:.1f}",
                )
            typer.echo(round_table)

    asyncio.run(_run())


# ─────────────────── 规则共享命令 ───────────────────

rule_app = typer.Typer(name="rule", help="跨团队规则共享管理", add_completion=False)
privacy_app.add_typer(rule_app)


@rule_app.command("create")
def create_shareable_rule(
    rule_name: str = typer.Argument(..., help="规则名称"),
    category: str = typer.Argument(..., help="规则类别 (如 sql_injection, xss)"),
    pattern: str = typer.Option("", "--pattern", help="检测模式描述"),
    description: str = typer.Option("", "--desc", help="规则描述"),
    severity: str = typer.Option("MEDIUM", "--severity", help="严重度"),
    cwe: Optional[str] = typer.Option(None, "--cwe", help="CWE编号"),
    source_team: str = typer.Option("", "--source-team", help="来源团队"),
    sensitivity: str = typer.Option("medium", "--sensitivity", help="敏感度 (low/medium/high/critical)"),
    scope: str = typer.Option("team", "--scope", help="共享范围 (team/dept/org/public)"),
):
    """创建可共享的脱敏规则。"""
    from .rule_sharing import ShareableRuleBuilder, RuleShareScope, RuleSensitivity
    from .models import RuleSensitivity as RS

    try:
        rule = ShareableRuleBuilder.from_raw_rule(
            rule_id=f"rule-{rule_name.lower().replace(' ', '_')}",
            rule_name=rule_name,
            category=category,
            description=description,
            detection_pattern=pattern,
            severity=severity,
            cwe=cwe,
            source_team=source_team,
            scope=RuleShareScope(scope),
            sensitivity=RuleSensitivity(sensitivity),
        )
    except ValueError as e:
        typer.echo(f"[red]创建失败: {e}[/red]")
        raise typer.Exit(1)

    # 检查是否包含敏感数据
    has_sensitive = rule.contains_sensitive_data()

    table = Table(title=f"🔐 共享规则创建成功", box=box.ROUNDED, show_lines=True)
    table.add_column("字段", style="cyan")
    table.add_column("值", style="white")
    table.add_row("规则名称", rule.rule_name)
    table.add_row("类别", rule.category)
    table.add_row("严重度", rule.severity)
    table.add_row("CWE", rule.cwe or "-")
    table.add_row("敏感度", rule.sensitivity.value)
    table.add_row("共享范围", rule.scope.value)
    table.add_row("签名", rule.signature[:16] + "...")
    table.add_row("包含敏感数据", "⚠️ 是" if has_sensitive else "✅ 否")
    typer.echo(table)


@rule_app.command("package")
def create_rule_package(
    rule_names: str = typer.Argument(..., help="规则名称列表（逗号分隔）"),
    scope: str = typer.Option("team", "--scope", help="共享范围"),
):
    """构建规则共享包。"""
    from .rule_sharing import ShareableRuleBuilder, RulePackageBuilder, RulePackageValidator
    from .models import RuleShareScope, RuleSensitivity

    builder = RulePackageBuilder(scope=RuleShareScope(scope))

    # 为每个规则名称生成示例规则
    for name in rule_names.split(","):
        name = name.strip()
        if not name:
            continue
        try:
            rule = ShareableRuleBuilder.from_raw_rule(
                rule_id=f"pkg-{name.lower().replace(' ', '_')}",
                rule_name=name,
                category="custom",
                description=f"Custom detection rule for {name}",
                detection_pattern=f"pattern matches {name} vulnerability signature",
                source_team="internal",
                scope=RuleShareScope(scope),
                sensitivity=RuleSensitivity.MEDIUM,
            )
            builder.add_rule(rule)
        except ValueError:
            pass

    package = builder.build()

    # 验证
    is_valid, issues = RulePackageValidator.validate_package(package)

    table = Table(title="📦 规则包构建结果", box=box.ROUNDED, show_lines=True)
    table.add_column("字段", style="cyan")
    table.add_column("值", style="white")
    table.add_row("规则数量", str(len(package.rules)))
    table.add_row("共享范围", package.scope.value)
    table.add_row("包哈希", package.package_hash[:16] + "...")
    table.add_row("验证结果", "✅ 通过" if is_valid else "❌ 未通过")
    if issues:
        table.add_row("问题", "; ".join(issues))
    typer.echo(table)


# ─────────────────── 验证命令 ───────────────────

@privacy_app.command("validate")
def validate_privacy(
    standards: Optional[str] = typer.Option(None, "--standards", help="合规标准 (逗号分隔: dsl,djcp,pipl,iso)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="详细输出"),
):
    """运行隐私合规验证并生成报告。"""
    from .privacy_validator import PrivacyComplianceChecker
    from .models import ComplianceStandard

    std_list = None
    if standards:
        std_list = []
        std_map = {
            "dsl": ComplianceStandard.DATA_SECURITY_LAW,
            "djcp": ComplianceStandard.DJCP_2_0,
            "pipl": ComplianceStandard.PIPL,
            "iso": ComplianceStandard.ISO_27001,
        }
        for s in standards.split(","):
            s = s.strip().lower()
            if s in std_map:
                std_list.append(std_map[s])

    checker = PrivacyComplianceChecker()
    report = checker.run_full_compliance_check(standards=std_list)

    table = Table(title="🔒 隐私合规报告", box=box.ROUNDED, show_lines=True)
    table.add_column("指标", style="cyan")
    table.add_column("值", style="white")
    table.add_row("检查项总数", str(len(report.checks)))
    table.add_row("通过", f"[green]{report.passed_count}[/green]")
    table.add_row("未通过", f"[red]{report.failed_count}[/red]")
    table.add_row("风险等级", report.risk_level.upper())
    table.add_row("整体合规", "✅ 通过" if report.overall_passed else "❌ 未通过")
    table.add_row("报告哈希", report.report_hash[:16] + "...")
    typer.echo(table)

    if verbose:
        detail_table = Table(title="详细检查项", box=box.SIMPLE)
        detail_table.add_column("ID", style="dim")
        detail_table.add_column("检查项")
        detail_table.add_column("标准", style="cyan")
        detail_table.add_column("结果", justify="center")
        for c in report.checks:
            status = "✅" if c.passed else "❌"
            detail_table.add_row(c.check_id, c.check_name, c.standard.value, status)
        typer.echo(detail_table)

    typer.echo(f"\n摘要: {report.summary}")


# ─────────────────── 协同任务命令 ───────────────────

collab_app = typer.Typer(name="collab", help="跨团队协同审计任务", add_completion=False)
privacy_app.add_typer(collab_app)


@collab_app.command("create")
def create_collab_task(
    title: str = typer.Argument(..., help="任务标题"),
    creator: str = typer.Option("admin", "--creator", help="创建者"),
    description: str = typer.Option("", "--desc", help="任务描述"),
    visibility: str = typer.Option("team_team", "--visibility", help="可见范围"),
):
    """创建跨团队协同审计任务。"""
    from .collaborative_task import CollaborativeTaskManager
    from .models import TaskVisibility

    manager = CollaborativeTaskManager()
    task = manager.create_task(
        title=title,
        creator=creator,
        description=description,
        visibility=TaskVisibility(visibility),
    )

    table = Table(title="📋 协同任务创建成功", box=box.ROUNDED, show_lines=True)
    table.add_column("字段", style="cyan")
    table.add_column("值", style="white")
    table.add_row("任务ID", task.id[:16] + "...")
    table.add_row("标题", task.title)
    table.add_row("创建者", task.creator)
    table.add_row("状态", task.status.value)
    table.add_row("可见范围", task.visibility.value)
    typer.echo(table)


@collab_app.command("demo")
def run_collab_demo(
    teams: int = typer.Option(3, "--teams", "-t", min=2, max=10, help="参与团队数"),
):
    """运行协同任务完整演示（创建→分配→扫描→聚合）。"""
    from .collaborative_task import (
        CollaborativeTaskManager,
        ResultDesensitizer,
        CollaborativeTaskStatus,
    )
    from .models import (
        TaskVisibility,
        ScanPermission,
        DesensitizedFinding,
    )

    manager = CollaborativeTaskManager()

    # 创建任务
    task = manager.create_task(
        title="跨团队安全审计演示",
        creator="security-admin",
        description="多团队协同隐私保护审计",
        visibility=TaskVisibility.TEAM,
    )

    # 分配权限
    for i in range(teams):
        manager.assign_team_permission(
            task_id=task.id,
            team_id=f"team-{i+1:02d}",
            team_name=f"安全团队-{i+1}",
            max_severity_access="CRITICAL",
        )

    # 启动任务
    manager.start_task(task.id)

    # 各团队提交脱敏结果
    for i in range(teams):
        findings = [
            DesensitizedFinding(
                task_id=task.id,
                rule_id="sql_injection",
                severity="HIGH",
                category="sql_injection",
                language="java",
                cwe="CWE-89",
                file_path_hash="a1b2c3",
                line_range="L45-L67",
                description="用户输入直接拼接至SQL查询，存在注入风险",
                fix_suggestion="使用参数化查询（PreparedStatement）替代字符串拼接",
                confidence=0.92,
                source_team_hash=f"team-{i+1:02d}"[:12],
            ),
            DesensitizedFinding(
                task_id=task.id,
                rule_id="xss",
                severity="MEDIUM",
                category="xss",
                language="javascript",
                cwe="CWE-79",
                file_path_hash="d4e5f6",
                line_range="L23-L25",
                description="用户输入未经编码直接输出至HTML",
                fix_suggestion="对输出内容使用HTML实体编码",
                confidence=0.85,
                source_team_hash=f"team-{i+1:02d}"[:12],
            ),
        ]
        manager.submit_team_results(task.id, f"team-{i+1:02d}", findings)

    # 聚合结果
    agg = manager.aggregate_results(task.id)

    # 完成
    manager.finalize_task(task.id)

    # 输出
    table = Table(title="📊 协同审计演示结果", box=box.ROUNDED, show_lines=True)
    table.add_column("指标", style="cyan")
    table.add_column("值", style="white")
    table.add_row("任务ID", task.id[:16] + "...")
    table.add_row("参与团队", str(teams))
    table.add_row("总发现数", str(agg["total_findings"]))
    table.add_row("按严重度", json.dumps(agg["by_severity"]))
    table.add_row("按类别", json.dumps(agg["by_category"]))
    table.add_row("结果哈希", agg["result_hash"][:16] + "...")
    typer.echo(table)


# ─────────────────── 审计命令 ───────────────────

@privacy_app.command("audit")
def audit_transfers(
    limit: int = typer.Option(20, "--limit", "-n", min=1, max=200, help="显示条数"),
):
    """查看数据传输审计日志。"""
    from .repository import open_privacy_repo

    async def _run():
        repo = open_privacy_repo()
        async with repo:
            logs = await repo.list_audit_logs(limit=limit)
            stats = await repo.get_audit_stats()

            table = Panel(
                f"总传输: {stats['total_transfers']}  |  "
                f"合规: {stats['compliant']}  |  "
                f"不合规: {stats['non_compliant']}  |  "
                f"明文检测: {stats['plaintext_detected_count']}",
                title="📋 数据传输审计摘要",
                border_style="cyan",
            )
            typer.echo(table)

            if logs:
                log_table = Table(title="审计日志", box=box.SIMPLE)
                log_table.add_column("类型", style="cyan")
                log_table.add_column("来源", max_width=20)
                log_table.add_column("目的地", max_width=20)
                log_table.add_column("加密", justify="center")
                log_table.add_column("明文", justify="center")
                log_table.add_column("合规", justify="center")
                log_table.add_column("时间", style="dim")
                for log in logs:
                    log_table.add_row(
                        log["transfer_type"],
                        log["source_node"][:20],
                        log["destination_node"][:20],
                        "✅" if log["encryption_verified"] else "❌",
                        "⚠️" if log["plaintext_detected"] else "✅",
                        "✅" if log["compliance_passed"] else "❌",
                        _fmt_time(log["transfer_timestamp"]),
                    )
                typer.echo(log_table)

    asyncio.run(_run())


# ─────────────────── 统计命令 ───────────────────

@privacy_app.command("stats")
def privacy_stats():
    """查看隐私审计统计数据。"""
    from .repository import open_privacy_repo

    async def _run():
        repo = open_privacy_repo()
        async with repo:
            stats = await repo.stats()

            table = Table(title="📈 隐私审计统计", box=box.ROUNDED, show_lines=True)
            table.add_column("指标", style="cyan")
            table.add_column("数量", justify="right")
            for k, v in stats.items():
                table.add_row(k.replace("_", " ").title(), str(v))
            typer.echo(table)

    asyncio.run(_run())
