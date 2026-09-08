"""
V3.0 AI Pentest - Attack Chain Reasoner Tests
"""
import pytest
from fp_sentinel.models import Finding, Severity
from fp_sentinel.attack.v3_ai_pentest.attack_chain_reasoner import (
    AttackChainReasoner,
    ChainReasoningReport,
    ReasoningChain,
    VisualizationFormat,
    to_mermaid,
    to_dot,
    to_json_graph,
    to_ascii,
    to_html,
    _multi_head_attention,
    _compute_centrality,
    _infer_difficulty,
    _generate_attack_scenario,
    _REMEDIATION_MAP,
)
from fp_sentinel.analysis.chain_discovery import VulnerabilityGraph, GraphNode, NodeType


def _f(rule_id, line, code, severity=Severity.HIGH, file_path="app.py"):
    return Finding(scanner="test", rule_id=rule_id, severity=severity,
                   file_path=file_path, line_start=line, code_snippet=code)


class TestMultiHeadAttention:
    def test_multi_head_returns_correct_structure(self):
        graph = VulnerabilityGraph()
        n1 = GraphNode(id="a", node_type=NodeType.VULNERABILITY, label="xss",
                       file_path="app.py", line_number=10, rule_id="xss")
        n2 = GraphNode(id="b", node_type=NodeType.VULNERABILITY, label="sqli",
                       file_path="app.py", line_number=20, rule_id="sql-injection")
        graph.add_node(n1); graph.add_node(n2)
        from fp_sentinel.analysis.chain_discovery import GraphEdge, EdgeType
        graph.add_edge(GraphEdge(source="a", target="b", edge_type=EdgeType.DATA_FLOW))
        per_head, avg = _multi_head_attention(graph, {"a": 50.0, "b": 30.0}, num_heads=4)
        assert len(per_head) == 4
        assert ("a", "b") in avg
        assert avg[("a", "b")] > 0

    def test_softmax_normalization(self):
        graph = VulnerabilityGraph()
        n1 = GraphNode(id="a", node_type=NodeType.VULNERABILITY, label="xss",
                       file_path="app.py", line_number=10, rule_id="xss")
        n2 = GraphNode(id="b", node_type=NodeType.VULNERABILITY, label="sqli",
                       file_path="app.py", line_number=20, rule_id="sql-injection")
        n3 = GraphNode(id="c", node_type=NodeType.VULNERABILITY, label="cmd",
                       file_path="app.py", line_number=30, rule_id="command-injection")
        graph.add_node(n1); graph.add_node(n2); graph.add_node(n3)
        from fp_sentinel.analysis.chain_discovery import GraphEdge, EdgeType
        graph.add_edge(GraphEdge(source="a", target="b", edge_type=EdgeType.DATA_FLOW))
        graph.add_edge(GraphEdge(source="a", target="c", edge_type=EdgeType.DATA_FLOW))
        per_head, avg = _multi_head_attention(graph, {"a": 50.0, "b": 30.0, "c": 20.0})
        assert len(per_head) == 4
        sum_a = avg.get(("a", "b"), 0) + avg.get(("a", "c"), 0)
        assert abs(sum_a - 1.0) < 0.01

    def test_empty_graph(self):
        graph = VulnerabilityGraph()
        per_head, avg = _multi_head_attention(graph, {}, num_heads=4)
        assert avg == {}
        assert all(h == {} for h in per_head.values())


class TestComputeCentrality:
    def test_hub_node(self):
        graph = VulnerabilityGraph()
        for i in range(5):
            n = GraphNode(id=f"n{i}", node_type=NodeType.VULNERABILITY, label=f"v{i}",
                          file_path="app.py", line_number=i*10, rule_id=f"rule-{i}")
            graph.add_node(n)
        from fp_sentinel.analysis.chain_discovery import GraphEdge, EdgeType
        for i in range(1, 5):
            graph.add_edge(GraphEdge(source="n0", target=f"n{i}", edge_type=EdgeType.DATA_FLOW))
        cent = _compute_centrality(graph)
        assert cent["n0"] == 1.0
        assert all(cent[f"n{i}"] < 1.0 for i in range(1, 5))

    def test_empty(self):
        graph = VulnerabilityGraph()
        cent = _compute_centrality(graph)
        assert cent == {}


class TestInferDifficulty:
    def test_easy(self):
        chain = ReasoningChain(nodes=[])
        result = _infer_difficulty(chain)
        # empty chain defaults
        assert result in ("EASY", "MEDIUM", "HARD", "EXTREME")


class TestAttackChainReasoner:
    def test_reason_simple_chain(self):
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
            _f("py.injection.command", 30, "os.system(cmd)"),
        ]
        reasoner = AttackChainReasoner()
        report = reasoner.reason(findings, project="test")
        assert report.total_findings == 3
        assert len(report.chains) >= 1
        assert report.attention_heads == 4

    def test_reason_empty_findings(self):
        reasoner = AttackChainReasoner()
        report = reasoner.reason([])
        assert report.total_findings == 0
        assert len(report.chains) == 0

    def test_reason_single_finding(self):
        findings = [_f("py.crypto.weak_hash", 5, "hashlib.md5(x)")]
        reasoner = AttackChainReasoner()
        report = reasoner.reason(findings)
        assert report.total_findings == 1
        assert len(report.chains) == 0
        assert len(report.isolated_findings) == 1

    def test_chain_properties(self):
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
        ]
        reasoner = AttackChainReasoner()
        report = reasoner.reason(findings)
        if report.chains:
            chain = report.chains[0]
            assert chain.overall_risk > 0
            assert 0 < chain.chain_probability <= 100
            assert chain.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            assert len(chain.remediation) > 0

    def test_chains_sorted_by_risk(self):
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
            _f("py.injection.command", 30, "os.system(cmd)"),
        ]
        reasoner = AttackChainReasoner()
        report = reasoner.reason(findings)
        risks = [c.overall_risk for c in report.chains]
        assert risks == sorted(risks, reverse=True)

    def test_graph_stats(self):
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
        ]
        reasoner = AttackChainReasoner()
        report = reasoner.reason(findings)
        assert report.graph_stats["total_nodes"] == 2

    def test_custom_attention_heads(self):
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
        ]
        reasoner = AttackChainReasoner(attention_heads=8)
        report = reasoner.reason(findings)
        assert report.attention_heads == 8

    def test_node_roles(self):
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
        ]
        reasoner = AttackChainReasoner()
        report = reasoner.reason(findings)
        for chain in report.chains:
            for node in chain.nodes:
                assert node.node_role in ("entry", "intermediate", "sink", "isolated")


class TestVisualizationExports:
    def _make_report(self):
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
        ]
        return AttackChainReasoner().reason(findings)

    def test_to_mermaid(self):
        report = self._make_report()
        mermaid = to_mermaid(report)
        assert "flowchart LR" in mermaid

    def test_to_dot(self):
        report = self._make_report()
        dot = to_dot(report)
        assert dot.startswith("digraph AttackChains")

    def test_to_json_graph(self):
        report = self._make_report()
        jg = to_json_graph(report)
        assert "nodes" in jg and "edges" in jg

    def test_to_ascii(self):
        report = self._make_report()
        ascii_art = to_ascii(report)
        assert len(ascii_art) > 0

    def test_to_html(self):
        report = self._make_report()
        html = to_html(report)
        assert "<!DOCTYPE html>" in html

    def test_empty_report_vis(self):
        report = ChainReasoningReport()
        assert to_ascii(report) is not None
        assert to_mermaid(report) is not None


class TestVisualizationFormat:
    def test_enum(self):
        assert VisualizationFormat.MERMAID.value == "mermaid"
        assert VisualizationFormat.HTML.value == "html"
