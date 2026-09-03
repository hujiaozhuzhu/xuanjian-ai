"""
A6-2. 合规报告增强（Markdown）

- 趋势表：本次/上次/变化 —— 数据源 FindingRepo.list_findings + fingerprint 对比
  （新增 / 修复 / 遗留），无历史数据时显示"首期基线"
- "需关注"列表按 ROI 排序（修复成本 ↑ 严重度 ↑）
- Diff 建议块（复用 fix_advisor，绝不修改用户源文件 —— S2）
本模块零网络。
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..database.repositories import FindingRepo, ScanHistoryRepo
from .fix_advisor import suggest_fix

logger = logging.getLogger(__name__)

# ROI 排序用严重度权重
_SEVERITY_WEIGHT = {"CRITICAL": 100, "HIGH": 60, "MEDIUM": 30, "LOW": 10, "INFO": 1}


def _sev_of(f: Any) -> str:
    sev = getattr(f, "severity", "MEDIUM")
    return getattr(sev, "value", None) or str(sev)


def _fp_of(f: Any) -> str:
    return getattr(f, "fingerprint", None) or ""


async def compute_trend(
    finding_repo: FindingRepo,
    history_repo: ScanHistoryRepo,
    project_path: str,
    current_scan_id: Optional[str] = None,
    current_findings: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    """
    计算 本次/上次 趋势对比（fingerprint 机制）。

    Returns:
        {
          "is_baseline": bool,
          "current": {"total": int, "by_severity": {...}},
          "previous": {"total": int, "by_severity": {...}},
          "new": [Finding], "fixed": [Finding], "remaining": [Finding],
          "previous_scan_id": str|None, "previous_time": str|None,
        }
    """
    # 本次 findings：未持久化扫描由调用方显式传入，避免把空集合误报为“全部已修复”。
    if current_findings is None:
        current_findings = await finding_repo.list_findings(
            scan_id=current_scan_id, limit=10000
        ) if current_scan_id else []

    # 上一次扫描：在数据库中先按项目过滤，再按 timestamp、id 倒序返回。按当前扫描
    # 在该稳定顺序中的位置取下一条记录，避免同一时间精度下的扫描被错误排除。
    project_histories = await history_repo.list_history(
        project_path=project_path, limit=200
    )
    prev_scan_id = None
    prev_time = None

    if current_scan_id:
        for index, history in enumerate(project_histories):
            if history.scan_id == current_scan_id:
                if index + 1 < len(project_histories):
                    previous = project_histories[index + 1]
                    prev_scan_id = previous.scan_id
                    prev_time = str(previous.timestamp)
                break
    elif project_histories:
        previous = project_histories[0]
        prev_scan_id = previous.scan_id
        prev_time = str(previous.timestamp)

    previous_findings: List[Any] = []
    if prev_scan_id:
        previous_findings = await finding_repo.list_findings(
            scan_id=prev_scan_id, limit=10000
        )

    cur_fps = {_fp_of(f) for f in current_findings if _fp_of(f)}
    prev_fps = {_fp_of(f) for f in previous_findings if _fp_of(f)}

    new_findings = [f for f in current_findings if _fp_of(f) and _fp_of(f) not in prev_fps]
    fixed_findings = [f for f in previous_findings if _fp_of(f) and _fp_of(f) not in cur_fps]
    remaining = [f for f in current_findings if _fp_of(f) and _fp_of(f) in prev_fps]

    def _by_sev(fs: list) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in fs:
            out[_sev_of(f)] = out.get(_sev_of(f), 0) + 1
        return out

    return {
        "is_baseline": prev_scan_id is None,
        "current": {"total": len(current_findings), "by_severity": _by_sev(current_findings)},
        "previous": {"total": len(previous_findings), "by_severity": _by_sev(previous_findings)},
        "new": new_findings,
        "fixed": fixed_findings,
        "remaining": remaining,
        "previous_scan_id": prev_scan_id,
        "previous_time": prev_time,
    }


def _delta(cur: int, prev: int) -> str:
    d = cur - prev
    if d > 0:
        return f"+{d}"
    if d < 0:
        return str(d)
    return "0"


def _trend_table(trend: Dict[str, Any]) -> str:
    """趋势表：本次/上次/变化"""
    cur = trend["current"]
    prev = trend["previous"]

    if trend["is_baseline"]:
        lines = [
            "| 指标 | 本次 | 上次 | 变化 |",
            "|------|------|------|------|",
            f"| 总发现数 | {cur['total']} | - | 首期基线 |",
        ]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            lines.append(
                f"| {sev} | {cur['by_severity'].get(sev, 0)} | - | 首期基线 |"
            )
        return "\n".join(lines) + "\n"

    lines = [
        "| 指标 | 本次 | 上次 | 变化 |",
        "|------|------|------|------|",
        f"| 总发现数 | {cur['total']} | {prev['total']} | {_delta(cur['total'], prev['total'])} |",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        c = cur["by_severity"].get(sev, 0)
        p = prev["by_severity"].get(sev, 0)
        lines.append(f"| {sev} | {c} | {p} | {_delta(c, p)} |")
    return "\n".join(lines) + "\n"


def _roi_sort_key(pair: Tuple[Any, "object"]):
    """ROI 排序：修复成本(工时)↑ 严重度↑ —— 先修低工时高危"""
    finding, sug = pair
    return (-_SEVERITY_WEIGHT.get(_sev_of(finding), 0), sug.effort_minutes)


def _attention_section(findings: List[Any], limit: int = 10) -> str:
    """需关注列表（ROI 排序）+ Diff 建议块"""
    pairs = [(f, suggest_fix(f)) for f in findings]
    pairs.sort(key=_roi_sort_key)

    lines = []
    diff_blocks = []
    for i, (f, sug) in enumerate(pairs[:limit], 1):
        fp = Path(getattr(f, "file_path", "?")).name
        line = getattr(f, "line_start", 0)
        hours = f"{sug.effort_minutes}min"
        lines.append(
            f"| {i} | {_sev_of(f)} | {sug.title} | {fp}:{line} | {hours} |"
            f" {sug.reference_cve or '-'} |"
        )
        diff_blocks.append(
            f"#### {i}. {sug.title} — {fp}:{line}\n"
            f"- 参考案例: {sug.reference_cve or 'N/A'}\n"
            f"- 预计工时: {sug.effort_minutes} 分钟\n"
            f"- 事故背景: {sug.incident_note}\n"
            "```diff\n" + sug.diff + "\n```"
        )

    header = (
        "| ROI | 严重度 | 漏洞 | 位置 | 修复成本 | 参考 CVE |\n"
        "|-----|--------|------|------|---------|----------|"
    )
    body = header + "\n" + ("\n".join(lines) if lines else "| - | - | （无待修复项） | - | - | - |")
    diff_section = "\n\n".join(diff_blocks) if diff_blocks else "（无 Diff 建议）"
    return body, diff_section


def generate_compliance_report(
    project: str,
    project_path: str,
    trend: Dict[str, Any],
    findings: List[Any],
    generated_at: Optional[str] = None,
) -> str:
    """
    生成 Markdown 合规摘要。

    Args:
        project: 项目名
        project_path: 项目路径
        trend: compute_trend() 的结果
        findings: 本次 findings 列表
    """
    now = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    new_n = len(trend["new"])
    fixed_n = len(trend["fixed"])
    remain_n = len(trend["remaining"])

    sections = []
    sections.append(f"# 玄鉴合规审计摘要 — {project}\n")
    sections.append(f"> 生成时间: {now}  |  项目路径: {project_path}  |  玄鉴 fp-sentinel v2.2.0\n")

    sections.append("## ① 趋势对比\n")
    sections.append(_trend_table(trend))
    if trend["is_baseline"]:
        sections.append("*无历史扫描数据，本次结果记录为首期基线。*\n")
    else:
        sections.append(
            f"指纹对比: 新增 **{new_n}**、已修复 **{fixed_n}**、遗留 **{remain_n}**\n"
        )

    sections.append("## ② 需关注（按 ROI 排序：高危优先、低成本先修）\n")
    attention, diff_section = _attention_section(findings)
    sections.append(attention + "\n")

    sections.append("## ③ Diff 修复建议\n")
    sections.append("*以下建议仅为 diff 字符串示意，玄鉴不会修改您的源文件。*\n")
    sections.append(diff_section + "\n")

    sections.append("## ④ 声明\n")
    sections.append(
        "- 本报告由玄鉴 fp-sentinel 自动生成，仅用于防御性安全审计与合规自查。\n"
        "- 修复建议以 diff 字符串形式给出，工具承诺不修改任何用户源文件（S2）。\n"
        "- 报告文件仅写入 --output 指定的白名单目录（S7）。"
    )

    return "\n".join(sections) + "\n"
