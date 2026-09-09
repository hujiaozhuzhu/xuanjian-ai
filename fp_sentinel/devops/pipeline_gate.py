"""
DevSecOps 对接模块 — Pipeline 卡点引擎

在 GitLab CI / GitHub Actions 流水线中嵌入安全质量门：
- 基于 findings 列表按严重度和阈值配置计算判定结果
- PASS / WARN / BLOCK 三级输出
- 支持自定义阈值：严重/高危阻断、中危/低危告警
- 支持最大发现数阈值

安全红线：
- S1: 不涉及网络，纯本地评估逻辑
- S2: 不修改被扫描代码
- 可测试性：无外部依赖，pure function 风格便于单测
"""

from __future__ import annotations

import logging
from typing import List, Optional

from .models import (
    DevOpsConfig,
    DevOpsProvider,
    FindingRef,
    FindingViolation,
    PipelineGateRequest,
    PipelineGateResult,
    PipelineGateVerdict,
    severity_rank,
)

logger = logging.getLogger(__name__)

# 默认空配置（当 request 未传入 config 时使用）
_DEFAULT_CONFIG = DevOpsConfig(
    provider=DevOpsProvider.GITLAB,
    base_url="",
    project_id="",
)


def evaluate_gate(
    request: PipelineGateRequest,
) -> PipelineGateResult:
    """
    评估 Pipeline 卡点

    根据 findings 列表与 config 配置的阈值计算最终判定。
    BLOCK > WARN > PASS 优先级：任一阻断条件命中即 BLOCK，
    无阻断但有告警条件命中则 WARN，两者都无则 PASS。

    Args:
        request: Pipeline 卡点评估请求

    Returns:
        PipelineGateResult 完整评估判定
    """
    config = request.config or _DEFAULT_CONFIG
    findings = request.findings or []

    # 按严重度分组
    counter = _count_by_severity(findings)
    violations: List[FindingViolation] = []
    warnings: List[FindingViolation] = []

    # 逐条判定
    for finding in findings:
        level = _evaluate_finding(finding, config)
        if level == "block":
            violations.append(FindingViolation(
                finding_id=finding.id,
                severity=finding.severity,
                rule_id=finding.rule_id,
                file_path=finding.file_path,
                message=finding.message,
                violation_level="block",
            ))
        elif level == "warn":
            warnings.append(FindingViolation(
                finding_id=finding.id,
                severity=finding.severity,
                rule_id=finding.rule_id,
                file_path=finding.file_path,
                message=finding.message,
                violation_level="warn",
            ))

    # 检查最大发现数阈值
    if config.max_findings_threshold > 0 and len(findings) > config.max_findings_threshold:
        violations.append(FindingViolation(
            finding_id="",
            severity="HIGH",
            rule_id="gate.max_findings",
            file_path="",
            message=(
                f"发现总数 {len(findings)} 超过阈值 {config.max_findings_threshold}"
            ),
            violation_level="block",
        ))

    # 最终判定
    if violations:
        verdict = PipelineGateVerdict.BLOCK
    elif warnings:
        verdict = PipelineGateVerdict.WARN
    else:
        verdict = PipelineGateVerdict.PASS

    summary = _build_summary(verdict, counter, violations, warnings)
    suggested_actions = _build_suggestions(verdict, violations, warnings)

    return PipelineGateResult(
        verdict=verdict,
        provider=request.provider,
        project_id=request.project_id,
        commit_hash=request.commit_hash,
        total_findings=len(findings),
        critical_count=counter.get("CRITICAL", 0),
        high_count=counter.get("HIGH", 0),
        medium_count=counter.get("MEDIUM", 0),
        low_count=counter.get("LOW", 0),
        info_count=counter.get("INFO", 0),
        violations=violations,
        warnings=warnings,
        summary=summary,
        suggested_actions=suggested_actions,
    )


def _evaluate_finding(finding: FindingRef, config: DevOpsConfig) -> str:
    """
    单条 finding 的卡点判定
    返回 "block" / "warn" / "ok"
    """
    sev = (finding.severity or "").upper()
    rank = severity_rank(sev)

    # 阻断条件
    if config.block_on_critical and severity_rank("CRITICAL") <= rank:
        return "block"
    if config.block_on_high and severity_rank("HIGH") <= rank:
        return "block"

    # 告警条件
    if config.warn_on_medium and severity_rank("MEDIUM") <= rank:
        return "warn"
    if config.warn_on_low and severity_rank("LOW") <= rank:
        return "warn"

    return "ok"


def _count_by_severity(findings: List[FindingRef]) -> dict:
    """按严重度分组计数"""
    counter: dict = {}
    for f in findings:
        sev = (f.severity or "INFO").upper()
        counter[sev] = counter.get(sev, 0) + 1
    return counter


def _build_summary(
    verdict: PipelineGateVerdict,
    counter: dict,
    violations: List[FindingViolation],
    warnings: List[FindingViolation],
) -> str:
    """生成评估摘要"""
    parts = [f"Pipeline 卡点判定: {verdict.value.upper()}"]
    if counter:
        sev_desc = ", ".join(f"{k}:{v}" for k, v in sorted(counter.items()))
        parts.append(f"发现分布: {sev_desc}")
    if violations:
        parts.append(f"阻断项: {len(violations)}")
    if warnings:
        parts.append(f"告警项: {len(warnings)}")
    return " | ".join(parts)


def _build_suggestions(
    verdict: PipelineGateVerdict,
    violations: List[FindingViolation],
    warnings: List[FindingViolation],
) -> List[str]:
    """生成建议操作列表"""
    actions: List[str] = []
    if verdict == PipelineGateVerdict.BLOCK:
        actions.append("存在高危/严重漏洞，请先修复后再合并")
        if violations:
            rule_ids = list(set(v.rule_id for v in violations if v.rule_id))[:5]
            if rule_ids:
                actions.append(f"优先修复规则: {', '.join(rule_ids)}")
    elif verdict == PipelineGateVerdict.WARN:
        actions.append("存在中低危漏洞，建议修复后合并")
        if warnings:
            actions.append(f"共 {len(warnings)} 项告警，可权衡后决定")
    else:
        actions.append("安全质量门通过，可以合并")
    return actions


def format_gate_output(result: PipelineGateResult, output_format: str = "text") -> str:
    """格式化 Pipeline 卡点输出（用于 CLI / CI 脚本输出）"""
    if output_format == "json":
        import json
        return json.dumps(result.model_dump(), ensure_ascii=False, indent=2)

    # text 格式
    lines = [
        "=" * 60,
        "  玄鉴 v3.0 Pipeline 安全卡点",
        "=" * 60,
        f"  判定结果: {result.verdict.value.upper()}",
        f"  项目: {result.project_id}",
        f"  提交: {result.commit_hash[:10] if result.commit_hash else 'N/A'}",
        "-" * 60,
        f"  总计发现: {result.total_findings}",
        f"    CRITICAL: {result.critical_count}",
        f"    HIGH:     {result.high_count}",
        f"    MEDIUM:   {result.medium_count}",
        f"    LOW:      {result.low_count}",
        f"    INFO:     {result.info_count}",
        "-" * 60,
    ]

    if result.violations:
        lines.append(f"  阻断项 ({len(result.violations)}):")
        for v in result.violations[:10]:
            lines.append(f"    - [{v.severity}] {v.rule_id} @ {v.file_path}")
        if len(result.violations) > 10:
            lines.append(f"    ... 共 {len(result.violations)} 项")

    if result.warnings:
        lines.append(f"  告警项 ({len(result.warnings)}):")
        for w in result.warnings[:5]:
            lines.append(f"    - [{w.severity}] {w.rule_id} @ {w.file_path}")
        if len(result.warnings) > 5:
            lines.append(f"    ... 共 {len(result.warnings)} 项")

    if result.suggested_actions:
        lines.append("-" * 60)
        for action in result.suggested_actions:
            lines.append(f"  > {action}")

    lines.append("=" * 60)
    return "\n".join(lines)


def gate_exit_code(result: PipelineGateResult) -> int:
    """Pipeline 卡点判定结果转 exit code（CI 脚本用）"""
    if result.verdict == PipelineGateVerdict.BLOCK:
        return 1
    return 0
