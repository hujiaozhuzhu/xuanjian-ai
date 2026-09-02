"""
攻击链自动发现引擎

基于图论分析漏洞关系，自动发现入口点→敏感汇聚点的攻击路径
"""

import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class NodeType(str, Enum):
    """节点类型"""
    ENTRY_POINT = "entry_point"       # 入口点（用户输入、API端点）
    VULNERABILITY = "vulnerability"    # 漏洞节点
    SENSITIVE_SINK = "sensitive_sink"  # 敏感汇聚点
    AUTH_CHECK = "auth_check"         # 认证/授权检查
    DATA_TRANSFORM = "data_transform" # 数据转换


class EdgeType(str, Enum):
    """边类型"""
    DATA_FLOW = "data_flow"           # 数据流
    CONTROL_FLOW = "control_flow"     # 控制流
    PERMISSION = "permission"         # 权限关系
    NETWORK = "network"               # 网络关系
    DEPENDENCY = "dependency"         # 依赖关系


class SinkType(str, Enum):
    """敏感汇聚点类型"""
    DATABASE = "database"
    FILE_SYSTEM = "file_system"
    COMMAND_EXEC = "command_exec"
    NETWORK_REQUEST = "network_request"
    AUTH_TOKEN = "auth_token"
    USER_DATA = "user_data"
    ADMIN_API = "admin_api"


@dataclass
class GraphNode:
    """图节点"""
    id: str
    node_type: NodeType
    label: str
    file_path: str = ""
    line_number: int = 0
    rule_id: str = ""
    severity: str = "MEDIUM"
    cwe: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        return self.id == other.id


@dataclass
class GraphEdge:
    """图边"""
    source: str
    target: str
    edge_type: EdgeType
    weight: float = 1.0
    label: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackStep:
    """攻击步骤"""
    step_number: int
    node: GraphNode
    action: str
    description: str
    difficulty: str = "MEDIUM"
    exploitability: float = 0.5


@dataclass
class AttackChain:
    """攻击链"""
    id: str
    name: str
    severity: str
    cvss: float
    steps: List[AttackStep]
    entry_point: GraphNode
    sensitive_sink: GraphNode
    total_difficulty: float
    impact_score: float
    reachability_score: float
    overall_score: float
    remediation: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity,
            "cvss": self.cvss,
            "steps": [
                {
                    "step": s.step_number,
                    "action": s.action,
                    "description": s.description,
                    "file": s.node.file_path,
                    "line": s.node.line_number,
                    "difficulty": s.difficulty,
                }
                for s in self.steps
            ],
            "entry_point": self.entry_point.label,
            "sensitive_sink": self.sensitive_sink.label,
            "scores": {
                "total_difficulty": self.total_difficulty,
                "impact": self.impact_score,
                "reachability": self.reachability_score,
                "overall": self.overall_score,
            },
            "remediation": self.remediation,
        }


class VulnerabilityGraph:
    """漏洞关系图"""

    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self.adjacency: Dict[str, List[str]] = defaultdict(list)
        self.reverse_adjacency: Dict[str, List[str]] = defaultdict(list)

    def add_node(self, node: GraphNode):
        """添加节点"""
        self.nodes[node.id] = node

    def add_edge(self, edge: GraphEdge):
        """添加边"""
        self.edges.append(edge)
        self.adjacency[edge.source].append(edge.target)
        self.reverse_adjacency[edge.target].append(edge.source)

    def get_successors(self, node_id: str) -> List[str]:
        """获取后继节点"""
        return self.adjacency.get(node_id, [])

    def get_predecessors(self, node_id: str) -> List[str]:
        """获取前驱节点"""
        return self.reverse_adjacency.get(node_id, [])

    def find_all_paths(
        self,
        start: str,
        end: str,
        max_depth: int = 6,
    ) -> List[List[str]]:
        """查找所有路径（限制深度的DFS）"""
        paths = []
        self._dfs(start, end, [], paths, set(), max_depth)
        return paths

    def _dfs(
        self,
        current: str,
        target: str,
        path: List[str],
        paths: List[List[str]],
        visited: Set[str],
        max_depth: int,
    ):
        """深度优先搜索"""
        if len(path) > max_depth:
            return

        if current == target:
            paths.append(path + [current])
            return

        if current in visited:
            return

        visited.add(current)
        path.append(current)

        for neighbor in self.adjacency.get(current, []):
            self._dfs(neighbor, target, path, paths, visited.copy(), max_depth)

        path.pop()


class AttackChainDiscovery:
    """攻击链自动发现引擎"""

    # 入口点模式
    ENTRY_POINT_PATTERNS = {
        "user_input": [
            r"req\.(body|query|params|headers)",
            r"request\.(form|args|json)",
            r"document\.getElementById.*\.value",
            r"\.value\s*$",
        ],
        "url": [
            r"window\.location\.(href|search|hash)",
            r"req\.(url|path|originalUrl)",
            r"URLSearchParams",
        ],
        "api_endpoint": [
            r"(app|router)\.(get|post|put|delete|patch)\s*\(",
            r"@app\.route",
            r"@(Get|Post|Put|Delete)Mapping",
        ],
        "file_upload": [
            r"multer",
            r"multipart",
            r"file\.upload",
            r"FormData",
        ],
        "websocket": [
            r"WebSocket",
            r"socket\.on",
            r"io\.on",
        ],
    }

    # 敏感汇聚点模式
    SENSITIVE_SINK_PATTERNS = {
        SinkType.DATABASE: [
            r"(query|execute|run)\s*\(",
            r"\.(find|insert|update|delete|aggregate)\s*\(",
            r"(SELECT|INSERT|UPDATE|DELETE)\s+",
        ],
        SinkType.FILE_SYSTEM: [
            r"(readFile|writeFile|unlink|mkdir)\s*\(",
            r"fs\.",
            r"open\s*\(",
        ],
        SinkType.COMMAND_EXEC: [
            r"(exec|spawn|execSync|spawnSync)\s*\(",
            r"child_process",
            r"os\.system",
            r"subprocess",
        ],
        SinkType.NETWORK_REQUEST: [
            r"(fetch|axios|request|http\.get)\s*\(",
            r"urllib",
            r"requests\.(get|post)",
        ],
        SinkType.AUTH_TOKEN: [
            r"jwt\.sign",
            r"jwt\.decode",
            r"token\s*=",
            r"session\s*\[",
        ],
        SinkType.USER_DATA: [
            r"user\.(password|email|ssn|credit_card)",
            r"SELECT.*FROM.*users",
            r"\.personal_data",
        ],
        SinkType.ADMIN_API: [
            r"/admin/",
            r"/api/admin",
            r"@admin_only",
            r"require.*admin",
        ],
    }

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.max_path_length = self.config.get("max_path_length", 6)
        self.max_chains = self.config.get("max_chains", 50)

    def discover_chains(
        self,
        findings: List[Any],
        source_code_index: Dict[str, str] = None,
    ) -> List[AttackChain]:
        """
        发现攻击链

        Args:
            findings: 漏洞发现列表
            source_code_index: 源码索引 {file_path: content}

        Returns:
            攻击链列表，按评分排序
        """
        # 1. 构建漏洞关系图
        graph = self._build_graph(findings)

        # 2. 识别入口点和汇聚点
        entry_points = self._find_entry_points(graph)
        sensitive_sinks = self._find_sensitive_sinks(graph)

        logger.info(
            f"Found {len(entry_points)} entry points, "
            f"{len(sensitive_sinks)} sensitive sinks"
        )

        # 3. 发现路径
        chains = []
        for entry in entry_points:
            for sink in sensitive_sinks:
                paths = graph.find_all_paths(
                    entry.id, sink.id, self.max_path_length
                )
                for path in paths:
                    if self._is_feasible_path(graph, path):
                        chain = self._build_chain(graph, path, entry, sink)
                        if chain:
                            chains.append(chain)

        # 4. 去重和排序
        chains = self._deduplicate_chains(chains)
        chains.sort(key=lambda c: c.overall_score, reverse=True)

        logger.info(f"Discovered {len(chains)} attack chains")
        return chains[:self.max_chains]

    def _build_graph(self, findings: List[Any]) -> VulnerabilityGraph:
        """构建漏洞关系图"""
        graph = VulnerabilityGraph()

        for finding in findings:
            # 创建漏洞节点
            node_id = f"{finding.file}:{finding.line}:{finding.rule_id}"
            node = GraphNode(
                id=node_id,
                node_type=NodeType.VULNERABILITY,
                label=f"{finding.rule_id} at {finding.file}:{finding.line}",
                file_path=finding.file,
                line_number=finding.line,
                rule_id=finding.rule_id,
                severity=getattr(finding, 'severity', 'MEDIUM'),
                cwe=getattr(finding, 'cwe', ''),
            )
            graph.add_node(node)

        # 建立边关系（基于文件内数据流和跨文件调用）
        self._build_data_flow_edges(graph, findings)
        self._build_file_proximity_edges(graph, findings)

        return graph

    def _build_data_flow_edges(
        self, graph: VulnerabilityGraph, findings: List[Any]
    ):
        """构建数据流边"""
        # 同文件内的漏洞可能存在数据流关系
        file_findings = defaultdict(list)
        for finding in findings:
            file_findings[finding.file].append(finding)

        for file_path, file_nodes in file_findings.items():
            # 按行号排序
            sorted_nodes = sorted(file_nodes, key=lambda f: f.line)
            for i in range(len(sorted_nodes)):
                for j in range(i + 1, min(i + 5, len(sorted_nodes))):
                    source_id = f"{sorted_nodes[i].file}:{sorted_nodes[i].line}:{sorted_nodes[i].rule_id}"
                    target_id = f"{sorted_nodes[j].file}:{sorted_nodes[j].line}:{sorted_nodes[j].rule_id}"

                    # 检查是否有数据流关系
                    if self._has_data_flow_relation(
                        sorted_nodes[i], sorted_nodes[j]
                    ):
                        edge = GraphEdge(
                            source=source_id,
                            target=target_id,
                            edge_type=EdgeType.DATA_FLOW,
                            weight=1.0,
                        )
                        graph.add_edge(edge)

    def _build_file_proximity_edges(
        self, graph: VulnerabilityGraph, findings: List[Any]
    ):
        """构建文件邻近边（同目录下的文件可能有调用关系）"""
        from pathlib import Path

        dir_files = defaultdict(list)
        for finding in findings:
            dir_path = str(Path(finding.file).parent)
            dir_files[dir_path].append(finding)

        for dir_path, dir_findings in dir_files.items():
            # 不同文件但在同一目录下
            file_groups = defaultdict(list)
            for f in dir_findings:
                file_groups[f.file].append(f)

            files = list(file_groups.keys())
            for i in range(len(files)):
                for j in range(i + 1, len(files)):
                    # 建立弱连接
                    for f1 in file_groups[files[i]][:3]:
                        for f2 in file_groups[files[j]][:3]:
                            id1 = f"{f1.file}:{f1.line}:{f1.rule_id}"
                            id2 = f"{f2.file}:{f2.line}:{f2.rule_id}"
                            edge = GraphEdge(
                                source=id1,
                                target=id2,
                                edge_type=EdgeType.DEPENDENCY,
                                weight=0.3,
                            )
                            graph.add_edge(edge)

    def _has_data_flow_relation(self, finding1, finding2) -> bool:
        """检查两个漏洞是否有数据流关系"""
        # 简化版本：基于规则类型推断
        source_rules = {"js.xss.innerhtml", "js.injection.eval", "js.node.ssrf"}
        sink_rules = {"js.node.sql-injection", "js.node.command-injection", "js.injection.eval"}

        if finding1.rule_id in source_rules and finding2.rule_id in sink_rules:
            return True
        if finding1.rule_id in sink_rules and finding2.rule_id in source_rules:
            return True

        return False

    def _find_entry_points(self, graph: VulnerabilityGraph) -> List[GraphNode]:
        """识别入口点"""
        entry_points = []
        for node in graph.nodes.values():
            if self._is_entry_point(node):
                entry_points.append(node)
        return entry_points

    def _is_entry_point(self, node: GraphNode) -> bool:
        """判断是否为入口点"""
        # 基于规则ID判断
        entry_rule_patterns = [
            "xss", "injection", "ssrf", "open-redirect",
            "prompt-injection", "user-input",
        ]
        for pattern in entry_rule_patterns:
            if pattern in node.rule_id.lower():
                return True

        # 基于文件路径判断
        entry_path_patterns = [
            "routes/", "controllers/", "handlers/",
            "api/", "pages/", "components/",
        ]
        for pattern in entry_path_patterns:
            if pattern in node.file_path:
                return True

        return False

    def _find_sensitive_sinks(self, graph: VulnerabilityGraph) -> List[GraphNode]:
        """识别敏感汇聚点"""
        sinks = []
        for node in graph.nodes.values():
            if self._is_sensitive_sink(node):
                sinks.append(node)
        return sinks

    def _is_sensitive_sink(self, node: GraphNode) -> bool:
        """判断是否为敏感汇聚点"""
        sink_rule_patterns = [
            "sql-injection", "command-injection", "path-traversal",
            "nosql-injection", "eval", "ssrf",
        ]
        for pattern in sink_rule_patterns:
            if pattern in node.rule_id.lower():
                return True
        return False

    def _is_feasible_path(self, graph: VulnerabilityGraph, path: List[str]) -> bool:
        """判断路径是否可行"""
        if len(path) < 2:
            return False

        # 检查是否有权限检查阻断
        for node_id in path:
            node = graph.nodes.get(node_id)
            if node and "auth" in node.rule_id.lower():
                return False  # 有认证检查，路径被阻断

        return True

    def _build_chain(
        self,
        graph: VulnerabilityGraph,
        path: List[str],
        entry: GraphNode,
        sink: GraphNode,
    ) -> Optional[AttackChain]:
        """构建攻击链"""
        steps = []
        for i, node_id in enumerate(path):
            node = graph.nodes.get(node_id)
            if not node:
                continue

            step = AttackStep(
                step_number=i + 1,
                node=node,
                action=self._infer_action(node),
                description=f"利用 {node.rule_id} at {node.file_path}:{node.line_number}",
                difficulty=self._estimate_difficulty(node),
                exploitability=self._estimate_exploitability(node),
            )
            steps.append(step)

        if not steps:
            return None

        # 计算评分
        total_difficulty = sum(s.exploitability for s in steps) / len(steps)
        impact_score = self._calculate_impact(sink)
        reachability = self._calculate_reachability(graph, path)
        overall_score = self._calculate_overall_score(
            total_difficulty, impact_score, reachability
        )

        # 生成攻击链ID
        chain_id = f"CHAIN-{'-'.join(path[:3])}"

        # 推断严重级别
        severity = self._infer_severity(overall_score)

        return AttackChain(
            id=chain_id,
            name=f"{entry.label} → {sink.label}",
            severity=severity,
            cvss=min(overall_score * 10, 10.0),
            steps=steps,
            entry_point=entry,
            sensitive_sink=sink,
            total_difficulty=total_difficulty,
            impact_score=impact_score,
            reachability_score=reachability,
            overall_score=overall_score,
            remediation=self._generate_remediation(steps),
        )

    def _infer_action(self, node: GraphNode) -> str:
        """推断攻击动作"""
        action_map = {
            "xss": "注入恶意脚本",
            "injection": "注入恶意代码",
            "eval": "执行任意代码",
            "sql": "注入SQL语句",
            "command": "执行系统命令",
            "ssrf": "伪造服务端请求",
            "path-traversal": "遍历文件路径",
            "prompt-injection": "注入恶意提示词",
        }
        for key, action in action_map.items():
            if key in node.rule_id.lower():
                return action
        return "利用漏洞"

    def _estimate_difficulty(self, node: GraphNode) -> str:
        """估计利用难度"""
        severity_difficulty = {
            "CRITICAL": "EASY",
            "HIGH": "MEDIUM",
            "MEDIUM": "HARD",
            "LOW": "VERY_HARD",
        }
        return severity_difficulty.get(node.severity, "MEDIUM")

    def _estimate_exploitability(self, node: GraphNode) -> float:
        """估计可利用性 (0-1)"""
        severity_score = {
            "CRITICAL": 0.9,
            "HIGH": 0.7,
            "MEDIUM": 0.5,
            "LOW": 0.3,
            "INFO": 0.1,
        }
        return severity_score.get(node.severity, 0.5)

    def _calculate_impact(self, sink: GraphNode) -> float:
        """计算影响分数"""
        sink_impact = {
            "sql-injection": 0.9,
            "command-injection": 0.95,
            "eval": 0.85,
            "path-traversal": 0.7,
            "ssrf": 0.8,
            "prompt-injection": 0.6,
        }
        for key, impact in sink_impact.items():
            if key in sink.rule_id.lower():
                return impact
        return 0.5

    def _calculate_reachability(
        self, graph: VulnerabilityGraph, path: List[str]
    ) -> float:
        """计算可达性分数"""
        # 基于路径长度和边权重
        if len(path) <= 1:
            return 1.0

        total_weight = 0.0
        for i in range(len(path) - 1):
            for edge in graph.edges:
                if edge.source == path[i] and edge.target == path[i + 1]:
                    total_weight += edge.weight
                    break

        # 路径越短、权重越高，可达性越高
        length_factor = 1.0 / len(path)
        weight_factor = total_weight / (len(path) - 1) if len(path) > 1 else 1.0

        return min(1.0, length_factor * 0.4 + weight_factor * 0.6)

    def _calculate_overall_score(
        self, difficulty: float, impact: float, reachability: float
    ) -> float:
        """计算综合评分"""
        # 加权平均
        return difficulty * 0.3 + impact * 0.4 + reachability * 0.3

    def _infer_severity(self, score: float) -> str:
        """推断严重级别"""
        if score >= 0.8:
            return "CRITICAL"
        elif score >= 0.6:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_remediation(self, steps: List[AttackStep]) -> Dict[str, Any]:
        """生成修复建议"""
        vulnerabilities = set()
        for step in steps:
            vulnerabilities.add(step.node.rule_id)

        remediation_suggestions = {
            "js.xss.innerhtml": "使用 textContent 或 DOMPurify.sanitize()",
            "js.injection.eval": "避免使用 eval()，使用安全的替代方案",
            "js.node.sql-injection": "使用参数化查询或 ORM",
            "js.node.command-injection": "避免拼接命令，使用白名单验证",
            "js.node.ssrf": "验证 URL 白名单",
            "js.aigc.prompt-injection-concat": "使用模板引擎，避免直接拼接用户输入",
        }

        suggestions = []
        for vuln in vulnerabilities:
            if vuln in remediation_suggestions:
                suggestions.append(remediation_suggestions[vuln])

        return {
            "priority": "P0" if any("CRITICAL" in s.difficulty for s in steps) else "P1",
            "effort": f"{len(steps) * 2}小时",
            "suggestions": suggestions,
        }

    def _deduplicate_chains(self, chains: List[AttackChain]) -> List[AttackChain]:
        """去重"""
        seen = set()
        unique = []
        for chain in chains:
            key = (chain.entry_point.id, chain.sensitive_sink.id)
            if key not in seen:
                seen.add(key)
                unique.append(chain)
        return unique
