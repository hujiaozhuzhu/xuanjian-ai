"""
A5. 攻防报告生成器（Markdown）

章节固定（计划表 A5）：
  ① 攻击面总览（ASCII 路径图）
  ② 已验证漏洞表（漏洞/位置/利用难度/验证状态/影响）
  ③ 攻击路径详情（步骤 + PoC 代码块 + 被攻破概率）
  ④ 需人工确认
  ⑤ 修复优先级（按概率排序 + 预计工时）
  ⑥ 安全声明（"PoC 仅用于防御验证" + 生成时间 + 30 天清理提示）

S7：报告文件只写入白名单目录（resolve 后必须落在允许根内）。
本模块零网络。
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from ..attack.chain_orchestrator import AttackChainReport
from ..attack.exploitability import ExploitabilityResult
from ..attack.poc_templates import PocInstance
from ..attack.target_validator import VerifyResult, VerifyStatus

logger = logging.getLogger(__name__)


class ReportPathError(Exception):
    """报告输出路径越界（S7 白名单校验失败）"""


# ─────────────────────── S7 白名单校验 ───────────────────────

def resolve_output_path(
    output_dir: str,
    filename: str,
    allowed_roots: Optional[List[str]] = None,
) -> Path:
    """
    校验并解析报告输出路径。

    规则（S7）：
    - resolve 后必须在 allowed_roots 内（默认: cwd 与 output_dir 自身）
    - 拒绝路径穿越（../ 逃逸）

    Returns:
        Path: 允许的最终文件路径

    Raises:
        ReportPathError: 路径越界
    """
    out = Path(output_dir).resolve()
    candidate = Path(filename)
    # A filename argument must remain a filename. Absolute paths and drive/root
    # prefixes must never be allowed to replace the configured output directory.
    if candidate.is_absolute() or candidate.anchor:
        raise ReportPathError(
            f"[S7 安全红线] 报告文件名必须是相对路径: {filename}"
        )
    target = (out / candidate).resolve()

    roots = [Path(r).resolve() for r in (allowed_roots or [])] if allowed_roots else []
    if not roots:
        roots = [out]
    # 允许 cwd 作为兜底白名单根
    roots.append(Path.cwd().resolve())

    if not any(
        target == root or root in target.parents for root in roots
    ) or any(part == ".." for part in candidate.parts):
        raise ReportPathError(
            f"[S7 安全红线] 报告输出路径越界: {target} 不在允许目录内 {roots}"
        )
    return target


def write_report(content: str, output_dir: str, filename: str) -> Path:
    """白名单校验后写入报告文件（仅写入 --output 目录）"""
    path = resolve_output_path(output_dir, filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


# ─────────────────────── 报告生成 ───────────────────────

STATUS_LABEL = {
    VerifyStatus.VERIFIED_LOCAL.value: "verified_local（Docker 靶场）",
    VerifyStatus.SIMULATED.value: "simulated（特征匹配模拟）",
    VerifyStatus.MANUAL_REQUIRED.value: "manual_required（需人工确认）",
}

_DIFFICULTY_LABEL = {
    "EASY": "低", "MEDIUM": "中", "HARD": "高", "VERY_HARD": "极高",
}


def _effort_minutes(probability: float, difficulty: str) -> int:
    """修复工时估计：概率越高、难度越低越优先（分钟）"""
    base = {"EASY": 30, "MEDIUM": 60, "HARD": 120, "VERY_HARD": 240}.get(difficulty, 60)
    if probability >= 70:
        return base
    if probability >= 40:
        return base * 2
    return base * 4


def _ascii_path_diagram(chain_report: AttackChainReport) -> str:
    """① 攻击面总览 ASCII 路径图"""
    lines: List[str] = []
    if not chain_report.paths:
        lines.append("（未发现多点攻击路径 —— 漏洞以单点形式存在，见②⑤）")
        return "\n".join(lines)

    for idx, path in enumerate(chain_report.paths[:8], 1):
        lines.append(f"[路径 {idx}] 严重度 {path.severity}  被攻破概率 {path.probability}%")
        prev_file = None
        for step in path.steps:
            if prev_file is not None and step.file_path == prev_file:
                connector = "    ↓ 同文件数据流"
            else:
                connector = "    ↓ 跨模块调用"
            if step.step_number > 1:
                lines.append(connector)
            lines.append(
                f"    [步骤 {step.step_number}] {step.vuln_type}"
                f"  ({Path(step.file_path).name}:{step.line})"
                f"  难度:{_DIFFICULTY_LABEL.get(step.difficulty, step.difficulty)}"
                f"  概率:{step.probability}%"
            )
            prev_file = step.file_path
        lines.append("")
    return "\n".join(lines).rstrip()


def _verified_table(
    findings: List[Any],
    verify_results: List[VerifyResult],
    exploit_results: List[ExploitabilityResult],
) -> str:
    """② 已验证漏洞表"""
    header = (
        "| # | 漏洞类型 | 位置 | 利用难度 | 被攻破概率 | 验证状态 | 验证方式 |\n"
        "|---|---------|------|---------|-----------|---------|---------|"
    )
    rows = []
    for i, (f, vr, er) in enumerate(zip(findings, verify_results, exploit_results), 1):
        rule = getattr(f, "rule_id", "?")
        fp = Path(getattr(f, "file_path", "?")).name
        line = getattr(f, "line_start", 0)
        rows.append(
            f"| {i} | {rule} | {fp}:{line} "
            f"| {_DIFFICULTY_LABEL.get(_diff_from_severity(er.severity), '中')} "
            f"| {er.probability}% | {STATUS_LABEL.get(vr.status.value, vr.status.value)} "
            f"| {vr.method} |"
        )
    return header + "\n" + "\n".join(rows) + "\n"


def _diff_from_severity(severity: str) -> str:
    return {
        "CRITICAL": "EASY", "HIGH": "MEDIUM",
        "MEDIUM": "HARD", "LOW": "VERY_HARD",
    }.get(severity, "MEDIUM")


def _path_details(
    chain_report: AttackChainReport,
    poc_map: Dict[str, PocInstance],
) -> str:
    """③ 攻击路径详情：步骤 + PoC 代码块 + 概率"""
    if not chain_report.paths:
        return "（无多点攻击路径）\n"

    blocks = []
    for idx, path in enumerate(chain_report.paths[:6], 1):
        lines = [f"### 路径 {idx}: {path.name}", ""]
        lines.append(f"- 严重度: {path.severity}")
        lines.append(f"- 整链被攻破概率: **{path.probability}%**")
        lines.append("")
        for step in path.steps:
            poc = poc_map.get(step.vuln_type)
            lines.append(f"**步骤 {step.step_number}** — {step.vuln_type} "
                         f"({Path(step.file_path).name}:{step.line})，难度 {_DIFFICULTY_LABEL.get(step.difficulty, step.difficulty)}")
            if poc is not None:
                lines.append("")
                lines.append("```text")
                lines.append(poc.rendered)
                lines.append("```")
                if poc.reference_cve:
                    lines.append(f"参考案例: {poc.reference_cve}")
            lines.append("")
        if path.remediation:
            lines.append("链路修复建议: " + "；".join(sorted(set(path.remediation))))
            lines.append("")
        blocks.append("\n".join(lines))
    return "\n".join(blocks)


def _manual_section(verify_results: List[VerifyResult], findings: List[Any]) -> str:
    """④ 需人工确认"""
    rows = []
    for f, vr in zip(findings, verify_results):
        if vr.status == VerifyStatus.MANUAL_REQUIRED:
            rows.append(
                f"- `{getattr(f, 'rule_id', '?')}` @ "
                f"{getattr(f, 'file_path', '?')}:{getattr(f, 'line_start', 0)} — {vr.evidence}"
            )
    if not rows:
        return "（无需人工确认项 —— 全部完成模拟验证）\n"
    return "\n".join(rows) + "\n"


def _fix_priority(
    exploit_results: List[ExploitabilityResult],
    findings: List[Any],
) -> str:
    """⑤ 修复优先级（按概率排序 + 预计工时）"""
    items = sorted(
        zip(exploit_results, findings),
        key=lambda pair: pair[0].probability,
        reverse=True,
    )
    header = (
        "| 优先级 | 漏洞 | 位置 | 概率 | 预计工时 |\n"
        "|-------|------|------|------|---------|"
    )
    rows = []
    for i, (er, f) in enumerate(items[:15], 1):
        if er.probability <= 0:
            continue
        difficulty = _diff_from_severity(er.severity)
        minutes = _effort_minutes(er.probability, difficulty)
        hours = f"{minutes // 60}h{minutes % 60:02d}m" if minutes >= 60 else f"{minutes}m"
        rows.append(
            f"| P{i} | {er.rule_id} | {Path(er.file_path).name}:{er.line} "
            f"| {er.probability}% | {hours} |"
        )
    if not rows:
        return header + "\n| - | （全部为 theoretical，无活跃风险） | - | - | - |\n"
    return header + "\n" + "\n".join(rows) + "\n"


def generate_attack_report(
    project: str,
    findings: List[Any],
    chain_report: AttackChainReport,
    verify_results: Optional[List[VerifyResult]] = None,
    exploit_results: Optional[List[ExploitabilityResult]] = None,
    poc_map: Optional[Dict[str, PocInstance]] = None,
    generated_at: Optional[str] = None,
) -> str:
    """
    生成 Markdown 攻防报告（⑥ 章节固定）。

    Args:
        project: 项目名
        findings: Finding 列表
        chain_report: 攻击链编排结果
        verify_results: 每条 finding 的验证结果（与 findings 对齐）
        exploit_results: 每条 finding 的可利用性结果（与 findings 对齐）
        poc_map: {漏洞类型: PocInstance}
    """
    findings = list(findings or [])
    verify_results = verify_results or []
    exploit_results = exploit_results or []
    poc_map = poc_map or {}
    now = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 补齐对齐长度
    while len(verify_results) < len(findings):
        verify_results.append(VerifyResult(
            status=VerifyStatus.MANUAL_REQUIRED, method="fallback",
            evidence="缺少验证结果"))
    while len(exploit_results) < len(findings):
        from ..attack.exploitability import assess
        exploit_results.append(assess(findings[len(exploit_results)]))

    status_counts: Dict[str, int] = {}
    for vr in verify_results:
        status_counts[vr.status.value] = status_counts.get(vr.status.value, 0) + 1
    status_line = "、".join(
        f"{STATUS_LABEL.get(k, k)} ×{v}" for k, v in sorted(status_counts.items())
    ) or "无"

    sections = []
    sections.append(f"# 玄鉴攻防审计报告 — {project}\n")
    sections.append(f"> 生成时间: {now}  |  玄鉴 fp-sentinel v2.2.0")
    sections.append(f"> 验证状态分布: {status_line}\n")

    sections.append("## ① 攻击面总览\n")
    sections.append("```text")
    sections.append(_ascii_path_diagram(chain_report))
    sections.append("```\n")

    sections.append("## ② 已验证漏洞表\n")
    if findings:
        sections.append(_verified_table(findings, verify_results, exploit_results))
    else:
        sections.append("（本次扫描未发现漏洞）\n")

    sections.append("## ③ 攻击路径详情\n")
    sections.append(_path_details(chain_report, poc_map))

    sections.append("## ④ 需人工确认\n")
    sections.append(_manual_section(verify_results, findings))

    sections.append("## ⑤ 修复优先级\n")
    sections.append(_fix_priority(exploit_results, findings))

    sections.append("## ⑥ 安全声明\n")
    sections.append(
        "- **PoC 仅用于防御验证**：本报告所有 PoC 均为教科书级标准 payload，"
        "仅用于验证漏洞可达性与培训演练，严禁用于任何未授权测试。\n"
        "- 所有验证默认为特征匹配模拟（simulated），零网络请求；"
        "本地目标白名单校验（仅 127.0.0.1/localhost）强制开启。\n"
        f"- **30 天数据清理**：依据 S5 红线，PoC 与攻防数据保留 30 天，"
        f"到期请执行 `fp-sentinel attack-purge` 清理。"
    )

    return "\n".join(sections) + "\n"
