"""
V3.0 GNN-based Attack Chain Reasoning Engine

基于图神经网络推理自动组合单点漏洞形成完整攻击路径。

核心能力：
- 图注意力网络(GAT)风格的推理：漏洞节点间通过注意力权重传播影响
- 多跳路径发现：超越简单 BFS，通过消息传递发现深层因果链
- 攻击链可视化图谱：输出 Mermaid / DOT / JSON Graph / ASCII 四种格式
- 最终风险评估：整链概率 × 影响面 × 可达性综合评分

安全红线：
- 零网络：纯数学计算（numpy 可选，纯 Python 回退）
- 零修改：输入 findings 只读
- 纯本地推理：不依赖外部模型服务

复用：
- analysis/chain_discovery.VulnerabilityGraph（图数据结构）
- attack/chain_orchestrator.orchestrate（基础路径编排）
- attack/exploitability.assess（概率评分）
"""

import logging
import math
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from ..analysis.chain_discovery import (
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
    VulnerabilityGraph,
)
from .exploitability import ExploitabilityResult
from .chain_orchestrator import (
    AttackChainReport,
    ChainPath,
    ChainStep,
    SinglePoint,
    _build_graph,
    _find_finding,
    _is_entry,
    _is_sink,
    _node_id,
    _file_of,
    _line_of,
    _rule_of,
)

logger = logging.getLogger(__name__)

# ─────────────────────── 常量 ───────────────────────

# 漏洞类型间的因果关联强度（专家知识图）
# key=(from_type_pattern, to_type_pattern) -> 关联强度 0-1
_RULE_TRANSITION_STRENGTH: Dict[Tuple[str, str], float] = {
    # 信息收集 → 注入类
    ("xss", "sql-injection"): 0.3,
    ("xss", "command-injection"): 0.4,
    ("xss", "eval"): 0.5,
    ("ssrf", "sql-injection"): 0.3,
    ("ssrf", "command-injection"): 0.4,
    ("ssrf", "deserialization"): 0.3,
    ("open-redirect", "ssrf"): 0.2,
    ("path-traversal", "deserialization"): 0.3,
    # 认证绕过 → 提权类
    ("jwt", "sql-injection"): 0.2,
    ("idor", "sql-injection"): 0.4,
    ("idor", "path-traversal"): 0.3,
    # 注入类 → 高危 sink
    ("sql-injection", "command-injection"): 0.3,
    ("ssti", "command-injection"): 0.5,
    ("ssti", "eval"): 0.4,
    ("nosql-injection", "command-injection"): 0.2,
    # 反序列化通杀（Java原生/Fastjson/Jackson/Shiro/PHP POP链/XClass免杀）
    ("deserialization", "command-injection"): 0.75,
    ("deserialization", "sql-injection"): 0.3,
    ("deserialization", "eval"): 0.5,
    ("deserialization", "ssrf"): 0.3,
    ("deserialization", "path-traversal"): 0.2,
    # XXE
    ("xxe", "ssrf"): 0.4,
    ("xxe", "path-traversal"): 0.3,
}

# 影响面权重
_IMPACT_WEIGHT = {
    "sql-injection": 0.9,
    "sql_injection": 0.9,
    "command-injection": 0.95,
    "command_injection": 0.95,
    "eval": 0.9,
    "deserialization": 0.85,
    "deser": 0.85,
    "ssrf": 0.7,
    "path-traversal": 0.6,
    "path_traversal": 0.6,
    "xss": 0.5,
    "ssti": 0.8,
    "xxe": 0.75,
    "pickle": 0.85,
    "yaml": 0.8,
    "jwt": 0.6,
    "nosql-injection": 0.7,
    "nosql_injection": 0.7,
    "open-redirect": 0.3,
    "idor": 0.5,
}


def _normalize_rule_for_transition(rule_id: str) -> str:
    """提取规则 ID 中的标准漏洞类型名称"""
    rid = rule_id.lower()
    # 优先匹配更具体的模式
    specific_keys = (
        # Java 反序列化
        "objectinputstream-readobject", "object-input-stream",
        "fastjson-parseobject", "fastjson-parse",
        "jackson-defaulttyping", "jackson-readvalue",
        "shiro-rememberme", "shiro-hardcoded-key", "shiro-aes-cbc",
        # PHP 反序列化
        "php-unserialize", "php-phar", "php-magic-method-pop",
        "php-system-with-user-input",
        # XSS
        "xss", "php-xss",
    )
    for key in specific_keys:
        if key in rid:
            # 映射到标准分类
            if key.startswith(("objectinputstream", "object-input-stream")):
                return "deserialization"
            if key.startswith(("fastjson",)):
                return "deserialization"
            if key.startswith(("jackson",)):
                return "deserialization"
            if key.startswith(("shiro",)):
                return "deserialization"
            if key.startswith(("php-unserialize", "php-phar", "php-magic-method-pop")):
                return "deserialization"
            if key == "php-system-with-user-input":
                return "command-injection"
            return key
    # 通用匹配
    generic_keys = (
        "sql-injection", "command-injection", "path-traversal", "deserialization",
        "open-redirect", "nosql-injection", "ssrf", "ssti", "xxe",
        "eval", "pickle", "yaml", "jwt", "idor",
    )
    for key in generic_keys:
        if key in rid:
            return key
    return rid


def _transition_strength(from_rule: str, to_rule: str) -> float:
    """查两条规则间的因果关联强度"""
    f = _normalize_rule_for_transition(from_rule)
    t = _normalize_rule_for_transition(to_rule)
    return _RULE_TRANSITION_STRENGTH.get((f, t), 0.0)


# ─────────────────────── 推理结果模型 ───────────────────────

class ReasoningNode(BaseModel):
    """GNN 推理后的节点"""
    id: str
    rule_id: str
    file_path: str
    line: int
    severity: str
    node_role: str  # entry / intermediate / sink / isolated
    attention_score: float = 0.0   # GAT 注意力权重 0-1
    propagated_risk: float = 0.0   # 传播后的风险值 0-100


class ReasoningEdge(BaseModel):
    """推理后的边"""
    source: str
    target: str
    edge_type: str
    attention_weight: float = 0.0  # GAT 注意力权重
    transition_strength: float = 0.0  # 因果关联强度
    effective_weight: float = 0.0   # 综合权重 = attention × transition


class InferredChain(BaseModel):
    """GNN 推理出的攻击链"""
    id: str = Field(default_factory=lambda: f"CHAIN-{uuid.uuid4().hex[:8]}")
    name: str = ""
    nodes: List[ReasoningNode] = Field(default_factory=list)
    edges: List[ReasoningEdge] = Field(default_factory=list)
    severity: str = "MEDIUM"
    chain_probability: float = 0.0   # 整链概率 0-100
    impact_score: float = 0.0        # 影响面评分 0-1
    reachability_score: float = 0.0  # 可达性 0-1
    overall_risk: float = 0.0        # 综合风险 0-100
    remediation: List[str] = Field(default_factory=list)


class VisualizationGraph(BaseModel):
    """可视化图谱数据"""
    nodes: List[Dict[str, Any]] = Field(default_factory=list)
    edges: List[Dict[str, Any]] = Field(default_factory=list)
    chains: List[str] = Field(default_factory=list)  # chain IDs


class ReasoningReport(BaseModel):
    """GNN 推理报告"""
    project: str = ""
    generated_at: Optional[str] = None
    chains: List[InferredChain] = Field(default_factory=list)
    isolated_findings: List[ReasoningNode] = Field(default_factory=list)
    visualization: VisualizationGraph = Field(default_factory=VisualizationGraph)
    total_findings: int = 0
    iterations: int = 0
    convergence_delta: float = 0.0


# ─────────────────────── GNN 推理核心 ───────────────────────

def _compute_attention(
    graph: VulnerabilityGraph,
    exploit_map: Dict[str, float],
) -> Dict[Tuple[str, str], float]:
    """
    图注意力风格的消息传递：
    - 每个节点根据其 neighbors 的 risk 值和边权重计算注意力权重
    - 使用 softmax 归一化（纯 Python 实现）

    Returns:
        {(src, dst): attention_weight}
    """
    attention: Dict[Tuple[str, str], float] = {}

    for edge in graph.edges:
        src_id = edge.source
        dst_id = edge.target

        # 源节点的风险值
        src_risk = exploit_map.get(src_id, 0.3) / 100.0

        # 因果关联强度
        src_node = graph.nodes.get(src_id)
        dst_node = graph.nodes.get(dst_id)
        if src_node is None or dst_node is None:
            continue

        trans = _transition_strength(src_node.rule_id, dst_node.rule_id)

        # 综合注意力 = 边权重 × (因果强度 + 基础连接强度) × 源风险
        base_connection = 0.1  # 基础连接强度（避免零值）
        attn = edge.weight * (trans + base_connection) * (src_risk + 0.1)
        attention[(src_id, dst_id)] = max(0.01, attn)

    # softmax 归一化：对每个源节点的出边注意力归一化
    out_sums: Dict[str, float] = defaultdict(float)
    for (src, _), w in attention.items():
        out_sums[src] += w

    normalized: Dict[Tuple[str, str], float] = {}
    for (src, dst), w in attention.items():
        total = out_sums.get(src, 1.0)
        normalized[(src, dst)] = w / total if total > 0 else 0.0

    return normalized


def _risk_propagation(
    graph: VulnerabilityGraph,
    exploit_map: Dict[str, float],
    attention: Dict[Tuple[str, str], float],
    iterations: int = 3,
    decay: float = 0.7,
) -> Tuple[Dict[str, float], float]:
    """
    风险传播迭代：
    - 每轮迭代：risk[node] = original_risk + Σ(attention[src→node] × risk[src] × decay)
    - 收敛条件：最大 delta < 0.001

    Returns:
        (propagated_risk_map, final_delta)
    """
    # 初始风险
    risk: Dict[str, float] = {}
    for nid in graph.nodes:
        risk[nid] = exploit_map.get(nid, 0.0)

    final_delta = 0.0
    for it in range(iterations):
        new_risk: Dict[str, float] = dict(risk)
        max_delta = 0.0

        for nid, node in graph.nodes.items():
            incoming = 0.0
            for (src, dst), w in attention.items():
                if dst == nid:
                    incoming += w * risk[src] * decay

            updated = risk[nid] + incoming
            updated = min(100.0, updated)  # 上限 100
            new_risk[nid] = updated
            max_delta = max(max_delta, abs(updated - risk[nid]))

        risk = new_risk
        final_delta = max_delta

        if max_delta < 0.001:
            break

    return risk, final_delta


def _classify_node_role(
    graph: VulnerabilityGraph,
    nid: str,
) -> str:
    """分类节点角色：entry / sink / intermediate / isolated"""
    node = graph.nodes.get(nid)
    if node is None:
        return "isolated"

    has_out = bool(graph.adjacency.get(nid))
    has_in = bool(graph.reverse_adjacency.get(nid))

    is_entry = _is_entry(_DummyFinding(node.rule_id, node.file_path, node.line_number))
    is_sink = _is_sink(_DummyFinding(node.rule_id, node.file_path, node.line_number))

    if is_entry and not has_in:
        return "entry"
    elif is_sink and not has_out:
        return "sink"
    elif has_in and has_out:
        return "intermediate"
    elif is_entry and has_out:
        return "entry"
    elif is_sink and has_in:
        return "sink"
    else:
        return "isolated"


class _DummyFinding:
    """用于复用 _is_entry/_is_sink 的轻量对象"""
    def __init__(self, rule_id: str, file_path: str, line: int):
        self.rule_id = rule_id
        self.file_path = file_path
        self.line_start = line


# ─────────────────────── 推理主入口 ───────────────────────

def reason(
    findings: List[Any],
    project: str = "",
    exploit_results: Optional[Dict[str, ExploitabilityResult]] = None,
    propagation_iterations: int = 3,
) -> ReasoningReport:
    """
    GNN 风格攻击链推理。

    Args:
        findings: Finding 列表
        project: 项目名
        exploit_results: 预计算的概率结果 {node_id: ExploitabilityResult}
        propagation_iterations: 最大传播迭代次数

    Returns:
        ReasoningReport
    """
    findings = list(findings or [])
    if not findings:
        return ReasoningReport(project=project, generated_at=_now())

    # 1. 构建图
    graph = _build_graph(findings)

    # 2. 准备概率映射
    exploit_map: Dict[str, float] = {}
    if exploit_results:
        for nid, er in exploit_results.items():
            exploit_map[nid] = er.probability
    else:
        for f in findings:
            nid = _node_id(f)
            severity = str(getattr(f, "severity", "MEDIUM")).split(".")[-1]
            # 用 severity 做基础概率估算
            base_prob = {"CRITICAL": 80.0, "HIGH": 60.0, "MEDIUM": 40.0, "LOW": 20.0}.get(severity, 30.0)
            exploit_map[nid] = base_prob

    # 3. 图注意力计算
    attention = _compute_attention(graph, exploit_map)

    # 4. 风险传播
    propagated, convergence = _risk_propagation(
        graph, exploit_map, attention, iterations=propagation_iterations
    )

    # 5. 节点角色分类
    node_roles: Dict[str, str] = {}
    for nid in graph.nodes:
        node_roles[nid] = _classify_node_role(graph, nid)

    # 6. 构建推理节点
    reasoning_nodes: Dict[str, ReasoningNode] = {}
    for nid, node in graph.nodes.items():
        role = node_roles[nid]
        # 节点自身的注意力得分：作为目标节点的入边注意力均值
        in_attentions = [w for (s, d), w in attention.items() if d == nid]
        node_attn = sum(in_attentions) / len(in_attentions) if in_attentions else 0.0

        reasoning_nodes[nid] = ReasoningNode(
            id=nid,
            rule_id=node.rule_id,
            file_path=node.file_path,
            line=node.line_number,
            severity=node.severity,
            node_role=role,
            attention_score=round(node_attn, 4),
            propagated_risk=round(propagated.get(nid, 0.0), 2),
        )

    # 7. 发现推理链：按注意力权重 + 风险传播值综合排序路径
    entries = [nid for nid, role in node_roles.items() if role in ("entry",)]
    sinks = [nid for nid, role in node_roles.items() if role in ("sink",)]

    chains: List[InferredChain] = []
    used_nodes: Set[str] = set()

    for entry_id in entries:
        for sink_id in sinks:
            if entry_id == sink_id:
                continue
            paths = graph.find_all_paths(entry_id, sink_id, max_depth=5)
            if not paths:
                continue
            # 选综合权重最高的路径
            best_path = None
            best_score = -1.0
            for path in paths:
                score = sum(propagated.get(nid, 0.0) for nid in path) / len(path)
                # 加上边注意力加成
                edge_bonus = 0.0
                for i in range(len(path) - 1):
                    edge_bonus += attention.get((path[i], path[i + 1]), 0.0) * 50
                score += edge_bonus / max(1, len(path) - 1)
                if score > best_score:
                    best_score = score
                    best_path = path

            if best_path is None or len(best_path) < 2:
                continue

            # 构建 InferredChain
            chain_nodes = [reasoning_nodes[nid] for nid in best_path]
            chain_edges = []
            for i in range(len(best_path) - 1):
                src = best_path[i]
                dst = best_path[i + 1]
                attn_w = attention.get((src, dst), 0.0)
                node_src = graph.nodes[src]
                node_dst = graph.nodes[dst]
                trans = _transition_strength(node_src.rule_id, node_dst.rule_id)
                chain_edges.append(ReasoningEdge(
                    source=src,
                    target=dst,
                    edge_type="data_flow",
                    attention_weight=round(attn_w, 4),
                    transition_strength=round(trans, 4),
                    effective_weight=round(attn_w * (trans + 0.1), 4),
                ))

            # 链综合概率：各步传播风险乘积经 attention 加权
            chain_prob = 100.0
            for n in chain_nodes:
                chain_prob *= (n.propagated_risk / 100.0) if n.propagated_risk > 0 else 0.5
            chain_prob = max(5.0, min(100.0, chain_prob))

            # 影响面：取路径中 sink 节点的影响权重
            sink_node = graph.nodes[sink_id]
            impact = 0.0
            for key, weight in _IMPACT_WEIGHT.items():
                if key in sink_node.rule_id.lower():
                    impact = weight
                    break
            if impact == 0.0:
                impact = 0.5

            # 可达性：路径越短越高，乘以因果强度均分
            reach = 1.0 / len(best_path)
            avg_trans = sum(e.transition_strength for e in chain_edges) / max(1, len(chain_edges))
            reach = min(1.0, reach * (1.0 + avg_trans))

            overall = chain_prob * 0.4 + impact * 100 * 0.3 + reach * 100 * 0.3

            sev = _infer_severity(overall)

            remediation = set()
            for n in chain_nodes:
                for key, fix in _REMEDIATION_MAP.items():
                    if key in n.rule_id.lower():
                        remediation.add(fix)

            chains.append(InferredChain(
                nodes=chain_nodes,
                edges=chain_edges,
                severity=sev,
                chain_probability=round(chain_prob, 2),
                impact_score=round(impact, 4),
                reachability_score=round(reach, 4),
                overall_risk=round(overall, 2),
                name=" → ".join(f"{Path(n.file_path).name}:{n.line}" for n in chain_nodes),
                remediation=list(remediation) or ["按规则建议修复"],
            ))

            for nid in best_path:
                used_nodes.add(nid)

    # 去重：同起终点保留 overall 最高的分组
    best_chains: Dict[tuple, InferredChain] = {}
    for c in chains:
        key = (c.nodes[0].rule_id, c.nodes[-1].rule_id,
               c.nodes[0].file_path, c.nodes[-1].file_path)
        if key not in best_chains or c.overall_risk > best_chains[key].overall_risk:
            best_chains[key] = c
    chains = sorted(best_chains.values(), key=lambda c: c.overall_risk, reverse=True)[:20]

    # 隔离节点
    isolated = [
        reasoning_nodes[nid]
        for nid in graph.nodes
        if nid not in used_nodes
    ]
    isolated.sort(key=lambda n: n.propagated_risk, reverse=True)

    return ReasoningReport(
        project=project,
        generated_at=_now(),
        chains=chains,
        isolated_findings=isolated[:50],
        total_findings=len(findings),
        iterations=propagation_iterations,
        convergence_delta=round(convergence, 6),
    )


# ─────────────────────── 可视化输出 ───────────────────────

def _infer_severity(score: float) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


_REMEDIATION_MAP = {
    "xss": "输出 HTML 转义 / textContent 赋值",
    "sql": "参数化查询 / 预编译语句",
    "command": "参数数组执行 + 命令白名单",
    "eval": "移除 eval()，改用安全解析",
    "path": "realpath 后校验基准目录",
    "ssrf": "URL 白名单 + 禁止回环",
    "deser": "改用 json/safe_load",
    "jwt": "使用 >=256bit 随机密钥",
    "nosql": "类型强校验 + 禁用嵌套操作符",
    "ssti": "避免用户输入参与模板编译",
    "xxe": "禁用 DTD/外部实体解析",
}


def to_mermaid(report: ReasoningReport) -> str:
    """
    输出 Mermaid 流程图格式的攻击链可视化。
    可直接粘贴到支持 Mermaid 的 Markdown 渲染器。
    """
    lines = ["```mermaid", "flowchart LR"]

    node_defs: Set[str] = set()
    for chain in report.chains:
        for node in chain.nodes:
            safe_id = node.id.replace(":", "_").replace("/", "_").replace(".", "_")
            label = f"{node.rule_id}<br/>{Path(node.file_path).name}:{node.line}"
            sev_color = {
                "CRITICAL": "#ff0000", "HIGH": "#ff6600",
                "MEDIUM": "#ffcc00", "LOW": "#00cc00",
            }.get(node.severity, "#999999")
            lines.append(f'    {safe_id}["{label}"]')
            lines.append(f'    style {safe_id} fill:{sev_color},color:#fff')
            node_defs.add(safe_id)

    # 边
    for chain in report.chains:
        for i in range(len(chain.nodes) - 1):
            src = chain.nodes[i].id.replace(":", "_").replace("/", "_").replace(".", "_")
            dst = chain.nodes[i + 1].id.replace(":", "_").replace("/", "_").replace(".", "_")
            edge = chain.edges[i] if i < len(chain.edges) else None
            weight = edge.effective_weight if edge else 0.5
            label = f"{weight:.2f}"
            lines.append(f"    {src} -->|{label}| {dst}")

    # 孤立节点样式
    for node in report.isolated_findings[:10]:
        safe_id = node.id.replace(":", "_").replace("/", "_").replace(".", "_")
        if safe_id not in node_defs:
            label = f"{node.rule_id}<br/>{Path(node.file_path).name}:{node.line}"
            lines.append(f'    {safe_id}["{label}"]')
            lines.append(f"    style {safe_id} fill:#cccccc,color:#333")
            node_defs.add(safe_id)

    lines.append("```")
    return "\n".join(lines)


def to_dot(report: ReasoningReport) -> str:
    """输出 Graphviz DOT 格式"""
    lines = ["digraph AttackChains {"]
    lines.append("    rankdir=LR;")
    lines.append('    node [shape=box, style="filled,rounded", fontname="sans-serif"];')

    seen: Set[str] = set()
    for chain in report.chains:
        for node in chain.nodes:
            safe_id = _safe(node.id)
            if safe_id in seen:
                continue
            sev_color = {
                "CRITICAL": "#e74c3c", "HIGH": "#e67e22",
                "MEDIUM": "#f1c40f", "LOW": "#2ecc71",
            }.get(node.severity, "#95a5a6")
            label = f"{node.rule_id} | {Path(node.file_path).name}:{node.line}\\n风险:{node.propagated_risk}"
            lines.append(f'    {safe_id} [label="{label}", fillcolor="{sev_color}", fontcolor={"#fff" if node.severity in ("CRITICAL", "HIGH") else "#333"}];')
            seen.add(safe_id)

        for i in range(len(chain.nodes) - 1):
            src = _safe(chain.nodes[i].id)
            dst = _safe(chain.nodes[i + 1].id)
            edge = chain.edges[i] if i < len(chain.edges) else None
            w = edge.effective_weight if edge else 0.5
            lines.append(f'    {src} -> {dst} [label="{w:.2f}", penwidth={max(1, w * 4)}];')

    for node in report.isolated_findings[:10]:
        safe_id = _safe(node.id)
        if safe_id in seen:
            continue
        label = f"{node.rule_id}\\n{Path(node.file_path).name}:{node.line}"
        lines.append(f'    {safe_id} [label="{label}", fillcolor="#bdc3c7", fontcolor="#333"];')
        seen.add(safe_id)

    lines.append("}")
    return "\n".join(lines)


def to_json_graph(report: ReasoningReport) -> Dict[str, Any]:
    """输出 JSON Graph 格式（兼容 Cytoscape.js / D3.js）"""
    nodes = []
    seen: Set[str] = set()

    for chain in report.chains:
        for node in chain.nodes:
            if node.id in seen:
                continue
            nodes.append({
                "data": {
                    "id": node.id,
                    "label": f"{node.rule_id}",
                    "file": node.file_path,
                    "line": node.line,
                    "severity": node.severity,
                    "role": node.node_role,
                    "attention": node.attention_score,
                    "propagated_risk": node.propagated_risk,
                }
            })
            seen.add(node.id)

    edges = []
    for chain in chain_iter(report):
        for edge in chain.edges:
            edges.append({
                "data": {
                    "source": edge.source,
                    "target": edge.target,
                    "type": edge.edge_type,
                    "attention": edge.attention_weight,
                    "transition": edge.transition_strength,
                    "weight": edge.effective_weight,
                }
            })

    return {"nodes": nodes, "edges": edges}


def chain_iter(report: ReasoningReport):
    """遍历 chains 的辅助生成器（兼容可迭代）"""
    for c in report.chains:
        yield c


def to_ascii(report: ReasoningReport, width: int = 60) -> str:
    """输出 ASCII 攻击链可视化"""
    lines = []
    lines.append("=" * width)
    lines.append("  攻击链可视化图谱（GNN 推理）")
    lines.append("=" * width)

    if not report.chains:
        lines.append("  [无攻击链]")
        for node in report.isolated_findings[:10]:
            lines.append(f"  ○ {node.rule_id} @ {Path(node.file_path).name}:{node.line} (风险:{node.propagated_risk})")
        lines.append("=" * width)
        return "\n".join(lines)

    for idx, chain in enumerate(report.chains, 1):
        lines.append(f"\n  链 #{idx} [{chain.severity}] 整体风险: {chain.overall_risk} | 概率: {chain.chain_probability}% | 影响面: {chain.impact_score}")
        lines.append("  " + "-" * (width - 4))

        for i, node in enumerate(chain.nodes):
            role_icon = {
                "entry": "▶", "sink": "◆",
                "intermediate": "○", "isolated": "◇",
            }.get(node.node_role, "·")
            risk_bar = "█" * int(node.propagated_risk / 10) + "░" * (10 - int(node.propagated_risk / 10))
            lines.append(f"  {role_icon} [{node.severity:>8}] {node.rule_id}")
            lines.append(f"    @ {Path(node.file_path).name}:{node.line}")
            lines.append(f"    风险: [{risk_bar}] {node.propagated_risk}  注意力: {node.attention_score}")

            if i < len(chain.edges):
                e = chain.edges[i]
                lines.append(f"    ↓ 因果关联: {e.transition_strength}  注意力: {e.attention_weight}  综合: {e.effective_weight}")

        if chain.remediation:
            lines.append(f"    修复: {'; '.join(chain.remediation[:2])}")

    if report.isolated_findings:
        lines.append(f"\n  [单点漏洞 {len(report.isolated_findings)} 个]")
        for node in report.isolated_findings[:10]:
            lines.append(f"  ◇ {node.rule_id} @ {Path(node.file_path).name}:{node.line} (风险:{node.propagated_risk})")
        if len(report.isolated_findings) > 10:
            lines.append(f"  ... 其余 {len(report.isolated_findings) - 10} 个")

    lines.append("\n" + "=" * width)
    return "\n".join(lines)


def _safe(s: str) -> str:
    """将节点 ID 转为 DOT 安全标识"""
    return s.replace(":", "_").replace("/", "_").replace(".", "_").replace("-", "_")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
