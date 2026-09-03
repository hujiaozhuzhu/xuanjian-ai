"""
A3. 攻击链编排器

复用 analysis.chain_discovery.VulnerabilityGraph 把合规 findings 聚合为攻击路径：
- 入口 = 暴露 HTTP 路由或含用户输入特征的漏洞（XSS/SSRF/重定向/SSTI/提示词注入等）
- 汇聚点 = SQL 注入/命令注入/eval/路径遍历/反序列化等高危 sink
- 边 = 同文件数据流（按行序相邻）+ 同目录弱依赖
- 单点漏洞 → 直接评分；多点同项目 → 生成 A→B→C 路径（每步标注类型/位置/难度）

本模块零网络、零文件写入。
"""

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from enum import Enum

from pydantic import BaseModel, Field

from ..analysis.chain_discovery import (
    AttackChain,
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
    VulnerabilityGraph,
)
from .exploitability import ExploitabilityResult, assess

logger = logging.getLogger(__name__)


# ─────────────────────── 入口 / 汇聚点特征 ───────────────────────

_ENTRY_RULE_PATTERNS = [
    "xss", "ssrf", "open-redirect", "ssti", "prompt-injection",
    "idor", "csrf", "xxe", "nosql",
]

_SINK_RULE_PATTERNS = [
    "sql-injection", "sql.injection", "command-injection", "command.injection",
    "cmd-injection", "eval", "path-traversal", "path.traversal",
    "deserialization", "deser", "pickle", "yaml", "injection.command",
    "injection.sql",
]

_ENTRY_PATH_PATTERNS = ["routes/", "controllers/", "handlers/", "api/", "views/", "pages/"]


def _rule_of(finding: Any) -> str:
    rid = getattr(finding, "rule_id", None)
    if rid is None and isinstance(finding, dict):
        rid = finding.get("rule_id", "")
    return (rid or "").lower()


def _file_of(finding: Any) -> str:
    fp = getattr(finding, "file_path", None)
    if fp is None and isinstance(finding, dict):
        fp = finding.get("file_path", "")
    return fp or ""


def _line_of(finding: Any) -> int:
    ln = getattr(finding, "line_start", None)
    if ln is None and isinstance(finding, dict):
        ln = finding.get("line_start", 0) or 0
    return int(ln or 0)


def _is_entry(finding: Any) -> bool:
    rid = _rule_of(finding)
    if any(p in rid for p in _ENTRY_RULE_PATTERNS):
        return True
    return any(p in _file_of(finding).replace("\\", "/") for p in _ENTRY_PATH_PATTERNS)


def _is_sink(finding: Any) -> bool:
    rid = _rule_of(finding)
    return any(p in rid for p in _SINK_RULE_PATTERNS)


def _node_id(finding: Any) -> str:
    return f"{_file_of(finding)}:{_line_of(finding)}:{_rule_of(finding)}"


def node_id(finding: Any) -> str:
    """公开：finding 的图节点 ID（与 exploit_results 键一致）"""
    return _node_id(finding)


def _difficulty_of(severity: str) -> str:
    return {
        "CRITICAL": "EASY", "HIGH": "MEDIUM",
        "MEDIUM": "HARD", "LOW": "VERY_HARD", "INFO": "UNKNOWN",
    }.get(severity, "MEDIUM")


# ─────────────────────── 输出模型（pydantic，兼容 models.py 风格） ───────────────────────

class ChainStep(BaseModel):
    """攻击路径单步"""
    step_number: int
    vuln_type: str = Field(..., description="漏洞类型（规则 ID）")
    file_path: str
    line: int
    difficulty: str = "MEDIUM"
    probability: float = 0.0  # 该步被攻破概率 0-100


class ChainPath(BaseModel):
    """多点攻击路径 A→B→C"""
    id: str
    name: str
    steps: List[ChainStep] = Field(default_factory=list)
    severity: str = "MEDIUM"
    probability: float = 0.0   # 整条路径被攻破概率（各步乘积后放大，0-100）
    remediation: List[str] = Field(default_factory=list)


class SinglePoint(BaseModel):
    """单点漏洞（未形成路径，直接评分）"""
    rule_id: str
    file_path: str
    line: int
    severity: str
    probability: float = 0.0
    reachability: str = "unknown"
    difficulty: str = "MEDIUM"


class AttackChainReport(BaseModel):
    """攻击链编排报告"""
    project: str = ""
    generated_at: Optional[str] = None
    paths: List[ChainPath] = Field(default_factory=list)
    single_points: List[SinglePoint] = Field(default_factory=list)
    total_findings: int = 0
    entry_count: int = 0
    sink_count: int = 0

    @property
    def path_count(self) -> int:
        return len(self.paths)

    @property
    def max_probability(self) -> float:
        probs = [p.probability for p in self.paths] + [
            s.probability for s in self.single_points
        ]
        return max(probs) if probs else 0.0


# ─────────────────────── 编排 ───────────────────────

def _build_graph(findings: List[Any]) -> VulnerabilityGraph:
    """把 findings 建为 VulnerabilityGraph（复用 chain_discovery 模型）"""
    graph = VulnerabilityGraph()

    for f in findings:
        node = GraphNode(
            id=_node_id(f),
            node_type=NodeType.VULNERABILITY,
            label=f"{_rule_of(f)} @ {_file_of(f)}:{_line_of(f)}",
            file_path=_file_of(f),
            line_number=_line_of(f),
            rule_id=_rule_of(f),
            severity=str(getattr(f, "severity", "MEDIUM")).split(".")[-1],
            cwe=getattr(f, "cwe", "") or "",
        )
        graph.add_node(node)

    # 同文件数据流边：按行序相邻（窗口 4）
    by_file: Dict[str, List[Any]] = defaultdict(list)
    for f in findings:
        by_file[_file_of(f)].append(f)

    for file_path, group in by_file.items():
        ordered = sorted(group, key=_line_of)
        for i in range(len(ordered)):
            for j in range(i + 1, min(i + 4, len(ordered))):
                # 源(入口类) → 汇(高危类) 才建立数据流边
                if _is_entry(ordered[i]) or _is_sink(ordered[j]):
                    graph.add_edge(GraphEdge(
                        source=_node_id(ordered[i]),
                        target=_node_id(ordered[j]),
                        edge_type=EdgeType.DATA_FLOW,
                        weight=1.0,
                    ))

    # 同目录弱依赖边（跨文件，权重 0.3）
    by_dir: Dict[str, List[Any]] = defaultdict(list)
    for f in findings:
        by_dir[str(Path(_file_of(f)).parent)].append(f)

    for dir_path, group in by_dir.items():
        files = sorted({_file_of(f) for f in group})
        for i in range(len(files)):
            for j in range(i + 1, len(files)):
                g1 = [f for f in group if _file_of(f) == files[i]][:3]
                g2 = [f for f in group if _file_of(f) == files[j]][:3]
                for f1 in g1:
                    for f2 in g2:
                        graph.add_edge(GraphEdge(
                            source=_node_id(f1),
                            target=_node_id(f2),
                            edge_type=EdgeType.DEPENDENCY,
                            weight=0.3,
                        ))
    return graph


def _infer_severity(score: float) -> str:
    if score >= 0.8:
        return "CRITICAL"
    if score >= 0.6:
        return "HIGH"
    if score >= 0.4:
        return "MEDIUM"
    return "LOW"


_REMEDIATION = {
    "xss": "输出转义 / textContent 赋值",
    "sql": "参数化查询",
    "command": "参数数组执行 + 白名单",
    "eval": "移除 eval，改用安全解析",
    "path": "realpath 后校验基准目录",
    "ssrf": "URL 白名单",
    "deser": "改用 json/safe_load",
}


def _remediation_for(rule_id: str) -> List[str]:
    rid = rule_id.lower()
    return [v for k, v in _REMEDIATION.items() if k in rid] or ["按规则建议修复"]


def orchestrate(
    findings: List[Any],
    project: str = "",
    exploit_results: Optional[Dict[str, ExploitabilityResult]] = None,
) -> AttackChainReport:
    """
    把合规 findings 编排为攻击路径报告。

    Args:
        findings: Finding 列表（models.Finding 或兼容对象）
        project: 项目名
        exploit_results: 预计算的可达性结果 {node_id: ExploitabilityResult}（可选）

    Returns:
        AttackChainReport
    """
    findings = list(findings or [])
    if not findings:
        return AttackChainReport(project=project, generated_at=_now())

    graph = _build_graph(findings)
    entries = [n for n in graph.nodes.values() if _is_entry(_find_finding(findings, n.id))]
    sinks = [n for n in graph.nodes.values() if _is_sink(_find_finding(findings, n.id))]

    prob_map: Dict[str, float] = {}
    if exploit_results:
        for nid, er in exploit_results.items():
            prob_map[nid] = er.probability

    paths: List[ChainPath] = []
    nodes_in_paths = set()

    for entry in entries:
        for sink in sinks:
            if entry.id == sink.id:
                continue
            for raw_path in graph.find_all_paths(entry.id, sink.id, max_depth=5):
                if len(raw_path) < 2:
                    continue
                steps = []
                product = 1.0
                for i, nid in enumerate(raw_path):
                    node = graph.nodes[nid]
                    prob = prob_map.get(nid, 0.0)
                    product *= (prob / 100.0) if prob > 0 else 0.3
                    steps.append(ChainStep(
                        step_number=i + 1,
                        vuln_type=node.rule_id,
                        file_path=node.file_path,
                        line=node.line_number,
                        difficulty=_difficulty_of(node.severity),
                        probability=prob,
                    ))
                    nodes_in_paths.add(nid)

                sev = _infer_severity(
                    sum((s.probability or 0) for s in steps) / len(steps) / 100.0
                )
                chain_prob = round(max(5.0, product * 100.0), 1)
                chain_prob = min(100.0, chain_prob)

                remediation = []
                for s in steps:
                    remediation.extend(_remediation_for(s.vuln_type))

                paths.append(ChainPath(
                    id=f"PATH-{uuid.uuid4().hex[:8]}",
                    name=" → ".join(
                        f"{s.vuln_type}@{Path(s.file_path).name}:{s.line}"
                        for s in steps
                    ),
                    steps=steps,
                    severity=sev,
                    probability=chain_prob,
                    remediation=list(dict.fromkeys(remediation)),
                ))

    # 去重（同起终点保留概率最高的一条）
    best: Dict[tuple, ChainPath] = {}
    for p in paths:
        key = (p.steps[0].vuln_type, p.steps[-1].vuln_type,
               p.steps[0].file_path, p.steps[-1].file_path)
        if key not in best or p.probability > best[key].probability:
            best[key] = p
    paths = sorted(best.values(), key=lambda p: p.probability, reverse=True)[:20]

    # 单点：未进入任何路径的 findings 直接评分
    single_points: List[SinglePoint] = []
    for f in findings:
        nid = _node_id(f)
        if nid in nodes_in_paths:
            continue
        sev = str(getattr(f, "severity", "MEDIUM")).split(".")[-1]
        er = exploit_results.get(nid) if exploit_results else None
        single_points.append(SinglePoint(
            rule_id=_rule_of(f),
            file_path=_file_of(f),
            line=_line_of(f),
            severity=sev,
            probability=er.probability if er else 0.0,
            reachability=er.reachability if er else "unknown",
            difficulty=_difficulty_of(sev),
        ))

    single_points.sort(key=lambda s: s.probability, reverse=True)

    return AttackChainReport(
        project=project,
        generated_at=_now(),
        paths=paths,
        single_points=single_points[:50],
        total_findings=len(findings),
        entry_count=len(entries),
        sink_count=len(sinks),
    )


def _find_finding(findings: List[Any], node_id: str) -> Any:
    for f in findings:
        if _node_id(f) == node_id:
            return f
    return findings[0] if findings else None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# 供报告生成器复用：AttackChain（旧模型）兼容视图
def to_legacy_chains(report: AttackChainReport) -> List[Dict[str, Any]]:
    """将 ChainPath 列表转为 dict 视图（便于 SARIF/JSON 输出）"""
    return [p.model_dump() for p in report.paths]
