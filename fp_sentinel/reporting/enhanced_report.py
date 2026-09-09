"""
玄鉴 v3.2 — 增强审计报告生成器 (Experience Optimization Module)

扩展标准审计报告，增加：
- 架构图可视化（ASCII/SVG 自适应）
- 攻击路径图（交互式 SVG）
- 风险热力图内联（基于现有 heatmap 模块增强）
- 行业基准对比图
- 整改进度时间线

安全红线：
- S1: 所有 PoC 仅限制 localhost
- S2: 不修改用户源文件
- S5: 报告数据 30 天清理
- S7: 输出路径白名单校验

版本: 3.2.0
"""

from __future__ import annotations

import html
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .attack_report import (
    STATUS_LABEL,
    _DIFFICULTY_LABEL,
    _ascii_path_diagram,
    _attack_thinking_section,
    _attack_chain_thinking_section,
    _verified_table,
    _path_details,
    _poc_and_exp_section,
    _potential_issues_section,
    _manual_section,
    _fix_priority,
    _security_statement_section,
    resolve_output_path,
    write_report,
    ReportPathError,
)
from ..attack.chain_orchestrator import AttackChainReport
from ..attack.exploitability import ExploitabilityResult
from ..attack.poc_templates import PocInstance
from ..attack.target_validator import VerifyResult, VerifyStatus
from ..visualization.heatmap import (
    VulnerabilityHeatmap,
    HeatmapInput,
    ChartTheme,
    OutputFormat,
)
from ..visualization.models import SEVERITY_WEIGHT

logger = logging.getLogger(__name__)


# ─────────────────────── 数据结构 ───────────────────────

@dataclass
class ArchitectureNode:
    """架构图节点"""
    name: str
    node_type: str  # entry/service/db/external
    tech_stack: str = ""
    exposure: str = "internal"  # internal/dmz/public
    risk_level: str = "MEDIUM"
    connections: List[str] = field(default_factory=list)


@dataclass
class ArchitectureDiagram:
    """系统架构图"""
    nodes: List[ArchitectureNode] = field(default_factory=list)
    edges: List[Tuple[str, str, str]] = field(default_factory=list)  # (from, to, protocol)

    def add_node(self, node: ArchitectureNode) -> None:
        self.nodes.append(node)

    def add_edge(self, source: str, target: str, protocol: str = "HTTP") -> None:
        self.edges.append((source, target, protocol))


@dataclass
class AttackPathStep:
    """攻击路径步骤（用于可视化）"""
    step_number: int
    vuln_type: str
    source_module: str
    target_module: str
    probability: float
    difficulty: str


@dataclass
class EnhancedReportConfig:
    """增强报告配置"""
    include_arch_diagram: bool = True
    include_attack_svg: bool = True
    include_heatmap: bool = True
    include_risk_trend: bool = True
    include_industry_comparison: bool = True
    theme: str = "dark"
    output_format: str = "markdown"  # markdown/html


# ─────────────────────── ASCII 架构图生成 ───────────────────────

def _render_ascii_arch(diagram: ArchitectureDiagram) -> str:
    """渲染 ASCII 架构图"""
    if not diagram.nodes:
        return "（未提供架构数据）"

    lines: List[str] = []

    # 按类型分组
    entries = [n for n in diagram.nodes if n.node_type == "entry"]
    services = [n for n in diagram.nodes if n.node_type == "service"]
    dbs = [n for n in diagram.nodes if n.node_type == "db"]
    externals = [n for n in diagram.nodes if n.node_type == "external"]

    def _node_label(node: ArchitectureNode) -> str:
        risk_marker = {
            "CRITICAL": "[!!!]", "HIGH": "[!!]", "MEDIUM": "[!]", "LOW": "[.]", "INFO": "[i]"
        }.get(node.risk_level, "")
        tech = f" [{node.tech_stack}]" if node.tech_stack else ""
        return f"{node.name}{tech} {risk_marker}"

    # 渲染架构图
    if entries:
        lines.append("+-- 入口层 " + "-" * 50)
        for node in entries:
            lines.append(f"|  [{node.risk_level:8s}] {_node_label(node)}")
        lines.append("+" + "-" * 56)

    if services:
        lines.append("")
        lines.append("+-- 服务层 " + "-" * 50)
        for node in services:
            lines.append(f"|  [{node.risk_level:8s}] {_node_label(node)}")
        lines.append("+" + "-" * 56)

    if dbs:
        lines.append("")
        lines.append("+-- 数据层 " + "-" * 50)
        for node in dbs:
            lines.append(f"|  [{node.risk_level:8s}] {_node_label(node)}")
        lines.append("+" + "-" * 56)

    if externals:
        lines.append("")
        lines.append("+-- 外部依赖 " + "-" * 48)
        for node in externals:
            lines.append(f"|  [{node.risk_level:8s}] {_node_label(node)}")
        lines.append("+" + "-" * 56)

    # 渲染连接关系
    if diagram.edges:
        lines.append("")
        lines.append("数据流:")
        for src, tgt, proto in diagram.edges:
            lines.append(f"  {src} --[{proto}]--> {tgt}")

    return "\n".join(lines)


# ─────────────────────── SVG 攻击路径可视化 ───────────────────────

def _render_attack_path_svg(
    chain_report: AttackChainReport,
    width: int = 900,
    height_factor: int = 120,
) -> str:
    """
    渲染攻击路径 SVG 交互式图表

    输出自包含 SVG，支持 hover 高亮，无外部依赖。
    """
    paths = chain_report.paths
    if not paths:
        return "<!-- 无攻击路径 -->"

    num_paths = min(len(paths), 8)
    height = 100 + num_paths * height_factor

    svg_parts: List[str] = []
    svg_parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'style="max-width:100%;background:#0d1117;font-family:monospace;font-size:12px">'
    )
    svg_parts.append(
        '<style>'
        '.path-title { fill: #e94560; font-weight: bold; font-size: 13px; }'
        '.step-box { stroke: #30363d; stroke-width: 1; rx: 6; }'
        '.step-label { fill: #c9d1d9; font-size: 11px; }'
        '.step-prob { fill: #58a6ff; font-size: 10px; }'
        '.arrow { stroke: #8b949e; stroke-width: 1.5; fill: none; marker-end: url(#arrowhead); }'
        '.prob-badge { fill: #1a1a2e; stroke: #58a6ff; stroke-width: 1; rx: 8; }'
        '.prob-text { fill: #58a6ff; font-size: 9px; text-anchor: middle; }'
        '</style>'
    )
    svg_parts.append(
        '<defs>'
        '<marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">'
        '<polygon points="0 0, 8 3, 0 6" fill="#8b949e"/>'
        '</marker>'
        '</defs>'
    )

    y_offset = 30
    for idx, path in enumerate(paths[:num_paths]):
        prob = path.probability
        # 颜色基于概率：高概率偏红，低概率偏蓝
        if prob >= 70:
            color = "#e94560"
        elif prob >= 40:
            color = "#ffa657"
        else:
            color = "#58a6ff"

        # 路径标题
        svg_parts.append(
            f'<text x="20" y="{y_offset}" class="path-title">'
            f'路径 {idx + 1}: {html.escape(path.name)} '
            f'(概率 {prob}%)</text>'
        )

        x_offset = 60
        step_y = y_offset + 30

        for step_idx, step in enumerate(path.steps):
            box_w = 130
            box_h = 50
            box_x = x_offset + step_idx * 170

            # 步骤框
            svg_parts.append(
                f'<rect x="{box_x}" y="{step_y}" width="{box_w}" height="{box_h}" '
                f'class="step-box" fill="{color}20" stroke="{color}"/>'
            )
            # 步骤名
            label = step.vuln_type[:14]
            svg_parts.append(
                f'<text x="{box_x + 8}" y="{step_y + 18}" class="step-label">'
                f'{html.escape(label)}</text>'
            )
            # 位置
            loc = f"{Path(step.file_path).name}:{step.line}"
            svg_parts.append(
                f'<text x="{box_x + 8}" y="{step_y + 34}" class="step-prob">'
                f'{html.escape(loc[:20])}</text>'
            )
            # 难度
            svg_parts.append(
                f'<text x="{box_x + 8}" y="{step_y + 46}" class="step-prob">'
                f'难度: {_DIFFICULTY_LABEL.get(step.difficulty, step.difficulty)}</text>'
            )

            # 箭头连接
            if step_idx < len(path.steps) - 1:
                arrow_x1 = box_x + box_w + 2
                arrow_x2 = box_x + 168
                svg_parts.append(
                    f'<line x1="{arrow_x1}" y1="{step_y + box_h // 2}" '
                    f'x2="{arrow_x2}" y2="{step_y + box_h // 2}" class="arrow"/>'
                )

        # 整体概率标记
        badge_x = x_offset + len(path.steps) * 170 + 10
        svg_parts.append(
            f'<rect x="{badge_x}" y="{step_y + 10}" width="60" height="30" '
            f'class="prob-badge"/>'
        )
        svg_parts.append(
            f'<text x="{badge_x + 30}" y="{step_y + 30}" class="prob-text">'
            f'{prob}%</text>'
        )

        y_offset += height_factor

    svg_parts.append('</svg>')
    return "\n".join(svg_parts)


# ─────────────────────── 风险热力图内联 ───────────────────────

def _build_inline_heatmap(
    findings: List[Any],
    modules: Optional[List[str]] = None,
) -> str:
    """
    基于 findings 构建内联热力图（ASCII 表格，可嵌入 Markdown）

    对每个模块按漏洞类型统计严重度，输出风险矩阵。
    """
    if not findings:
        return "（无漏洞数据）"

    # 聚合数据
    matrix: Dict[Tuple[str, str], Dict[str, int]] = {}
    mod_set: set = set()
    vuln_set: set = set()

    for f in findings:
        mod = getattr(f, "module", None) or getattr(f, "file_path", "unknown")
        mod = Path(mod).parent.name or Path(mod).stem
        rule = getattr(f, "rule_id", "unknown")
        sev = getattr(f, "severity", "MEDIUM") or "MEDIUM"

        # 简化漏洞类型
        vuln_type = _simplify_vuln_type(rule)
        mod_set.add(mod)
        vuln_set.add(vuln_type)

        key = (mod, vuln_type)
        if key not in matrix:
            matrix[key] = {}
        matrix[key][sev] = matrix[key].get(sev, 0) + 1

    if modules:
        mod_set = mod_set.intersection(set(modules))

    sorted_modules = sorted(mod_set)[:10]  # 限制宽度
    sorted_vulns = sorted(vuln_set)[:12]

    if not sorted_modules or not sorted_vulns:
        return "（模块数据不足）"

    # 计算每个格子的风险值
    def _cell_risk(sev_counts: Dict[str, int]) -> float:
        if not sev_counts:
            return 0.0
        total = sum(sev_counts.values())
        weighted = sum(SEVERITY_WEIGHT.get(s, 0.1) * c for s, c in sev_counts.items())
        return round(weighted / total * 10, 1)

    # 确定列宽
    col_w = 10
    header = "| 模块".ljust(col_w)
    for vt in sorted_vulns:
        header += f" | {vt[:col_w - 1]:>{col_w - 1}}"
    header += " |"

    sep = "|" + "-" * (col_w + 1)
    for _ in sorted_vulns:
        sep += "|" + "-" * (col_w + 1)
    sep += "|"

    rows = []
    for mod in sorted_modules:
        row = f"| {mod[:col_w - 1]:<{col_w - 1}}"
        for vt in sorted_vulns:
            sev_counts = matrix.get((mod, vt), {})
            if sev_counts:
                risk = _cell_risk(sev_counts)
                total_c = sum(sev_counts.values())
                if risk >= 7:
                    cell = f" {total_c}({risk})"
                elif risk >= 4:
                    cell = f" {total_c}({risk})"
                else:
                    cell = f" {total_c}({risk})"
            else:
                cell = " -"
            row += f" | {cell:>{col_w - 1}}"
        row += " |"
        rows.append(row)

    return "\n".join([header, sep] + rows)


def _simplify_vuln_type(rule_id: str) -> str:
    """简化漏洞类型标签"""
    rid = (rule_id or "").lower()
    if "sql" in rid:
        return "SQLi"
    if "xss" in rid or "innerhtml" in rid:
        return "XSS"
    if "command" in rid or "cmd" in rid or "os.system" in rid:
        return "CMDi"
    if "eval" in rid or "function" in rid:
        return "Eval"
    if "path" in rid or "travers" in rid:
        return "PathT"
    if "ssrf" in rid:
        return "SSRF"
    if "serial" in rid or "pickle" in rid or "yaml" in rid:
        return "Deser"
    if "secret" in rid or "hardcod" in rid:
        return "Secret"
    if "jwt" in rid:
        return "JWT"
    if "redirect" in rid:
        return "Redir"
    if "md5" in rid or "sha1" in rid or "ecb" in rid:
        return "Crypto"
    if "debug" in rid:
        return "Debug"
    if "xxe" in rid:
        return "XXE"
    if "upload" in rid:
        return "Upload"
    return "Other"


# ─────────────────────── 行业基准对比 ───────────────────────

def _render_industry_benchmark_comparison(
    findings: List[Any],
    industry: str = "internet",
) -> str:
    """
    渲染行业基准对比段

    基于 findings 计算企业指标，然后对比行业基准。
    """
    from ..industry_benchmark.builtin_data import build_benchmark_dataset
    from ..industry_benchmark.models import (
        Industry,
        EnterpriseMetrics,
        GapSeverity,
    )
    from ..industry_benchmark.engine import BenchmarkEngine

    try:
        ind = Industry(industry)
    except ValueError:
        ind = Industry.INTERNET

    dataset = build_benchmark_dataset(ind)

    # 从 findings 快速汇总企业级指标
    total_findings = len(findings)
    by_severity: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    for f in findings:
        sev = (getattr(f, "severity", "MEDIUM") or "MEDIUM").upper()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        cat = getattr(f, "category", None) or _simplify_vuln_type(
            getattr(f, "rule_id", "")
        )
        by_category[cat] = by_category.get(cat, 0) + 1

    enterprise = EnterpriseMetrics(
        project_name="current-scan",
        industry=ind,
        total_findings=total_findings,
        by_severity=by_severity,
        by_category=by_category,
        scan_count=1,
    )

    engine = BenchmarkEngine(dataset)
    report = engine.analyze(enterprise)

    lines: List[str] = []
    lines.append(f"> 行业: {dataset.industry.value} | 样本量: {dataset.sample_size}")
    lines.append(f"> 综合评分: {report.overall_score:.1f}/100 | 级别: {report.overall_severity.value}\n")

    lines.append("| 维度 | 企业值 | 行业均值 | 差距 |")
    lines.append("|------|--------|----------|------|")

    for cat in report.category_gaps:
        for item in cat.items:
            if item.gap_ratio > 0.1:
                direction = "高于均值"
            elif item.gap_ratio < -0.05:
                direction = "优于均值"
            else:
                direction = "持平"
            lines.append(
                f"| {item.category} | {item.enterprise_value:.1f} | "
                f"{item.industry_avg:.1f} | {direction} |"
            )

    if report.highlights:
        lines.append("")
        lines.append("**关键发现**:")
        for hl in report.highlights[:5]:
            lines.append(f"  - {hl}")

    return "\n".join(lines)


# ─────────────────────── 整改进度时间线 ───────────────────────

def _render_fix_timeline_section(
    findings: List[Any],
    exploit_results: Optional[List[ExploitabilityResult]] = None,
) -> str:
    """渲染整改进度时间线（按优先级排列）"""
    if not findings:
        return "（无待整改项）\n"

    exploit_results = exploit_results or []

    # 补齐长度
    while len(exploit_results) < len(findings):
        from ..attack.exploitability import assess
        exploit_results.append(assess(findings[len(exploit_results)]))

    # 按概率排序
    paired = sorted(
        zip(exploit_results, findings),
        key=lambda p: p[0].probability,
        reverse=True,
    )

    lines: List[str] = []
    lines.append("")
    for i, (er, f) in enumerate(paired[:15], 1):
        prob = er.probability
        # 确定阶段
        if prob >= 70:
            phase = "P0 - 立即可利用"
            icon = "[!!!]"
        elif prob >= 40:
            phase = "P1 - 高优先级"
            icon = "[!!]"
        elif prob >= 10:
            phase = "P2 - 中优先级"
            icon = "[!]"
        else:
            phase = "P3 - 低优先级"
            icon = "[.]"

        rule = getattr(f, "rule_id", "?")
        loc = f"{Path(getattr(f, 'file_path', '?')).name}:{getattr(f, 'line_start', 0)}"

        lines.append(f"{icon} **{i}. {rule}** @ `{loc}`")
        lines.append(f"   - {phase} (概率: {prob}%)")

        # 时间线进度条
        progress = min(100, int(prob))
        bar_len = 20
        filled = int(bar_len * progress / 100)
        bar = "#" * filled + "-" * (bar_len - filled)
        lines.append(f"   - 风险进度: [{bar}] {progress}%")
        lines.append("")

    return "\n".join(lines)


# ─────────────────────── 增强报告生成主函数 ───────────────────────

def generate_enhanced_report(
    project: str,
    findings: List[Any],
    chain_report: AttackChainReport,
    verify_results: Optional[List[VerifyResult]] = None,
    exploit_results: Optional[List[ExploitabilityResult]] = None,
    poc_map: Optional[Dict[str, PocInstance]] = None,
    architecture: Optional[ArchitectureDiagram] = None,
    industry: str = "internet",
    config: Optional[EnhancedReportConfig] = None,
    generated_at: Optional[str] = None,
) -> str:
    """
    生成增强版安全审计报告（14 章节）。

    新增章节：
      - 系统架构图（含节点风险标注）
      - 攻击路径 SVG 可视化
      - 风险热力图矩阵
      - 整改进度时间线
      - 行业基准对比

    保留原 10 章节，追加 4 个增强章节。

    Args:
        project: 项目名称
        findings: 漏洞发现列表
        chain_report: 攻击链编排结果
        verify_results: 验证结果
        exploit_results: 可利用性结果
        poc_map: PoC 模板映射
        architecture: 系统架构图数据
        industry: 行业标识（用于基准对比）
        config: 增强报告配置
        generated_at: 生成时间戳

    Returns:
        完整 Markdown 文档
    """
    findings = list(findings or [])
    verify_results = verify_results or []
    exploit_results = exploit_results or []
    poc_map = poc_map or {}
    config = config or EnhancedReportConfig()
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
        f"{STATUS_LABEL.get(k, k)} x{v}" for k, v in sorted(status_counts.items())
    ) or "无"

    sections: List[str] = []
    sections.append(f"# 玄鉴增强安全审计报告 ? {project}\n")
    sections.append(f"> 生成时间: {now}  |  玄鉴 fp-sentinel v3.2")
    sections.append(f"> 验证状态: {status_line}")
    sections.append(f"> 增强模块: 架构图 / 攻击路径 / 热力图 / 行业基准\n")

    # --- 增强章节 1: 系统架构图 ---
    if config.include_arch_diagram:
        sections.append("## ? 系统架构（风险标注）\n")
        if architecture and architecture.nodes:
            sections.append("```text")
            sections.append(_render_ascii_arch(architecture))
            sections.append("```\n")
        else:
            # 自动从 findings 推断
            auto_diagram = _infer_architecture_from_findings(findings)
            sections.append("```text")
            sections.append(_render_ascii_arch(auto_diagram))
            sections.append("```\n")

    # --- 原章节 1: 攻击面总览 ---
    sections.append("## 1. 攻击面总览\n")
    sections.append("```text")
    sections.append(_ascii_path_diagram(chain_report))
    sections.append("```\n")

    # --- 增强章节 2: 攻击路径可视化 ---
    if config.include_attack_svg:
        sections.append("## ? 攻击路径可视化\n")
        svg = _render_attack_path_svg(chain_report)
        if svg and "<!-- 无" not in svg:
            sections.append(svg)
            sections.append("")

    # --- 原章节 2-4 ---
    sections.append("## 2. 攻防思路\n")
    sections.append(_attack_thinking_section(findings, exploit_results, chain_report))

    sections.append("## 3. 已验证漏洞表\n")
    if findings:
        sections.append(_verified_table(findings, verify_results, exploit_results))
    else:
        sections.append("（本次扫描未发现漏洞）\n")

    sections.append("## 4. 攻击路径详情\n")
    sections.append(_path_details(chain_report, poc_map))

    # --- 增强章节 3: 风险热力图 ---
    if config.include_heatmap:
        sections.append("## ? 风险热力图矩阵\n")
        sections.append("> 纵轴: 模块 / 横轴: 漏洞类型 / 内: 数量(风险评分)\n")
        sections.append(_build_inline_heatmap(findings))
        sections.append("")

    # --- 原章节 5-7 ---
    sections.append("## 5. 本地验证 PoC/EXP\n")
    sections.append(_poc_and_exp_section(poc_map, chain_report))

    sections.append("## 6. 可能的问题\n")
    sections.append(_potential_issues_section(findings, verify_results, exploit_results))

    sections.append("## 7. 攻击链串联思路\n")
    sections.append(_attack_chain_thinking_section(chain_report))

    # --- 增强章节 4: 整改进度时间线 ---
    sections.append("## ? 整改进度时间线\n")
    sections.append(_render_fix_timeline_section(findings, exploit_results))

    # --- 原章节 8-10 ---
    sections.append("## 8. 需人工确认\n")
    sections.append(_manual_section(verify_results, findings))

    sections.append("## 9. 修复优先级\n")
    sections.append(_fix_priority(exploit_results, findings))

    # --- 增强章节 5: 行业基准对比 ---
    if config.include_industry_comparison:
        sections.append("## ? 行业基准对比\n")
        try:
            comparison_md = _render_industry_benchmark_comparison(findings, industry)
            sections.append(comparison_md)
        except Exception as e:
            logger.warning(f"行业基准对比生成失败（回退）: {e}")
            sections.append(f"（行业基准对比生成异常: {type(e).__name__}）\n")
        sections.append("")

    sections.append("## 10. 安全声明\n")
    sections.append(_security_statement_section(now))

    return "\n".join(sections) + "\n"


def _infer_architecture_from_findings(findings: List[Any]) -> ArchitectureDiagram:
    """从 findings 自动推断系统架构"""
    diagram = ArchitectureDiagram()

    modules: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        fp = getattr(f, "file_path", "unknown")
        parent = Path(fp).parent.name or "root"
        sev = getattr(f, "severity", "MEDIUM") or "MEDIUM"
        rule = getattr(f, "rule_id", "")

        if parent not in modules:
            modules[parent] = {"risk": sev, "rules": set()}
        modules[parent]["rules"].add(rule)

        # 更新最高风险
        sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        if sev_order.get(sev, 0) > sev_order.get(modules[parent]["risk"], 0):
            modules[parent]["risk"] = sev

    # 创建节点
    for mod, info in sorted(modules.items()):
        node_type = "service"
        if any(k in mod.lower() for k in ("route", "controller", "api", "view")):
            node_type = "entry"
        elif any(k in mod.lower() for k in ("model", "db", "repository", "dao")):
            node_type = "db"
        elif any(k in mod.lower() for k in ("config", "middleware", "lib")):
            node_type = "external"

        diagram.add_node(ArchitectureNode(
            name=mod,
            node_type=node_type,
            risk_level=info["risk"],
        ))

    # 创建边（从模块间依赖推断）
    mod_names = sorted(modules.keys())
    for i in range(len(mod_names) - 1):
        diagram.add_edge(mod_names[i], mod_names[i + 1], "call")

    return diagram


# ─────────────────────── 便捷导出函数 ───────────────────────

def write_enhanced_report(
    content: str,
    output_dir: str,
    filename: str,
) -> Path:
    """
    白名单校验后写入增强版报告

    Returns:
        写入的文件路径
    """
    return write_report(content, output_dir, filename)


def generate_and_write_enhanced_report(
    project: str,
    findings: List[Any],
    chain_report: AttackChainReport,
    output_dir: str,
    filename: str = "enhanced_report.md",
    **kwargs: Any,
) -> Path:
    """生成并写入增强报告（一站式便捷函数）"""
    content = generate_enhanced_report(
        project=project,
        findings=findings,
        chain_report=chain_report,
        **kwargs,
    )
    return write_enhanced_report(content, output_dir, filename)
