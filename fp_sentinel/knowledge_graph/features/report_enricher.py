"""
报告知识增强器 —— 将查询插件召回的知识图谱命中结果嵌入扫描输出

将 (a) 查询插件产出的 {finding_id -> [KnowledgeMatch]} 转换为：
1) Finding.metadata["knowledge_graph"] 注入（供下游报告/归档使用）；
   由于 Finding.metadata 是 dict，可被 report JSON / SARIF 透出；
2) 一段「⑦ 知识图谱参考」Markdown 小节，追加到合规/攻防报告末尾，
   包含每条命中的规则 / 文件 / 修复标题 / 参考 CVE / 事故说明。

本模块只进行字符串拼接，零网络、零写入（S2）。
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Dict, List

from ..models import KnowledgeMatch


def _dedup(matches: List[KnowledgeMatch]) -> List[KnowledgeMatch]:
    """按 reference_cve + rule_id 去重，保留相似度最高的"""
    best: "OrderedDict[str, KnowledgeMatch]" = OrderedDict()
    for m in matches:
        key = f"{m.reference_cve or ''}|{m.rule_id}"
        exist = best.get(key)
        if exist is None or m.similarity >= exist.similarity:
            best[key] = m
    return list(best.values())


def inject_finding_metadata(
    finding_metadata: Dict,
    matches: List[KnowledgeMatch],
) -> None:
    """把命中的知识图谱结果写入 Finding.metadata（原地）。无匹配则不写。"""
    if not matches:
        return
    items = _dedup(matches)
    finding_metadata["knowledge_graph"] = {
        "hits": len(items),
        "matches": [m.model_dump() for m in items[:5]],
    }


def build_reference_section(
    matches_by_finding: Dict[str, List[KnowledgeMatch]],
    top_k: int = 5,
) -> str:
    """
    构建「⑦ 知识图谱参考」章节。

    Args:
        matches_by_finding: {finding_id -> matches}
        top_k: 最多展示的命中条数
    """
    flat: List[KnowledgeMatch] = []
    for items in matches_by_finding.values():
        flat.extend(items)
    if not flat:
        return ""

    items = sorted(_dedup(flat), key=lambda m: m.similarity, reverse=True)[:top_k]

    lines: List[str] = [
        "⑦ 知识图谱参考\n",
        "> 基于已归档历史扫描记录 + 内置修复建议映射，由匹配插件自动召回，仅代表相似性参考。\n",
        "| # | 规则 | 文件:行 | 修复建议 | 参考 CVE | 相似度 |",
        "|---|------|--------|---------|---------|-------|",
    ]
    for i, m in enumerate(items, 1):
        loc = f"{m.file_path or '-'}:{m.line_start or 0}"
        lines.append(
            f"| {i} | `{m.rule_id}` `{m.category or ''}` | {loc} "
            f"| {m.fix_title or '-'} | {m.reference_cve or '-'} "
            f"| {m.similarity:.2f} |"
        )

    # 详情区：折叠 diff 避免报告过长
    lines.append("")
    for i, m in enumerate(items, 1):
        if not (m.fix_diff or m.incident_note or m.reference_cve):
            continue
        lines.append(f"#### {i}. {m.fix_title or m.rule_id} `{m.reference_cve or ''}`")
        if m.incident_note:
            lines.append(f"- 事故说明: {m.incident_note}")
        if m.reference_cve:
            lines.append(f"- 参考案例: {m.reference_cve}")
        if m.fix_diff:
            summary = m.fix_diff.strip().splitlines()
            head = summary[:12]
            lines.append("<details><summary>修复 diff 示例</summary>")
            lines.append("")
            lines.append("```diff")
            lines.append("\n".join(head))
            if len(summary) > 12:
                lines.append(f"...({len(summary) - 12} 行省略)")
            lines.append("```")
            lines.append("")
            lines.append("</details>")
        lines.append("")

    return "\n".join(lines)


def append_reference_to_report(report_md: str, reference_section: str) -> str:
    """将参考章节追加到报告末尾；无章节则原样返回。"""
    if not reference_section:
        return report_md
    if report_md.endswith("\n"):
        return report_md + "\n" + reference_section + "\n"
    return report_md + "\n\n" + reference_section + "\n"


def summarize(matches_by_finding: Dict[str, List[KnowledgeMatch]]) -> Dict[str, int]:
    """生成统计信息供归档 snapshot 使用：召回数 / CVE 命中数 / 匹配 finding 数。"""
    flat: List[KnowledgeMatch] = []
    for items in matches_by_finding.values():
        flat.extend(items)
    items = _dedup(flat)
    cve_hits = sum(1 for m in items if m.reference_cve)
    return {
        "knowledge_hits": len(items),
        "cve_hits": cve_hits,
        "findings_with_match": sum(1 for v in matches_by_finding.values() if v),
    }
