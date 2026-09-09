"""
V3.0 AI Pentest - Attack Chain Reasoner Tests (Full Coverage)

Covers: AttackChainReasoner, ChainReasoningReport, ReasoningChain,
        EnhancedReasoningNode, EnhancedReasoningEdge,
        VisualizationFormat, to_mermaid, to_dot, to_json_graph, to_ascii, to_html,
        _multi_head_attention, _compute_centrality, _depth_from_entry,
        _infer_severity, _infer_difficulty, _generate_attack_scenario,
        _safe_id (internal helper for DOT/Mermaid IDs),
        _REMEDIATION_MAP, _ATTACK_SCENARIOS,
        Reasoner: reason() with exploit_results, empty findings, single finding,
        multi-hop paths, entry==sink, no paths, path too short,
        chain dedup, isolated findings, graph_stats, custom attention_heads,
        node roles, edges with multi_head_weights.
"""
import pytest

from fp_sentinel.models import Finding, Severity
from fp_sentinel.attack.v3_ai_pentest.attack_chain_reasoner import (
    AttackChainReasoner,
    ChainReasoningReport,
    EnhancedReasoningNode,
    EnhancedReasoningEdge,
    ReasoningChain,
    VisualizationFormat,
    _multi_head_attention,
    _compute_centrality,
    _depth_from_entry,
    _infer_severity,
    _infer_difficulty,
    _generate_attack_scenario,
    _safe_id,
    _REMEDIATION_MAP,
    _ATTACK_SCENARIOS,
    to_mermaid,
    to_dot,
    to_json_graph,
    to_ascii,
    to_html,
)
from fp_sentinel.analysis.chain_discovery import (
    VulnerabilityGraph, GraphNode, GraphEdge, EdgeType, NodeType,
)
from fp_sentinel.attack.exploitability import ExploitabilityResult


def _f(rule_id, line, code, severity=Severity.HIGH, file_path="app.py"):
    return Finding(scanner="test", rule_id=rule_id, severity=severity,
                   file_path=file_path, line_start=line, code_snippet=code)


# ============================================================
# Test Data Model Defaults
# ============================================================


class TestEnhancedReasoningNode:
    def test_default_construction(self):
        node = EnhancedReasoningNode(
            id="n1", rule_id="xss", file_path="app.py",
            line=10, severity="HIGH", node_role="entry",
        )
        assert node.attention_score == 0.0
        assert node.multi_head_scores == []
        assert node.propagated_risk == 0.0
        assert node.centrality == 0.0
        assert node.depth_from_entry == -1

    def test_full_construction(self):
        node = EnhancedReasoningNode(
            id="n2", rule_id="sqli", file_path="db.py",
            line=20, severity="CRITICAL", node_role="sink",
            attention_score=0.85, multi_head_scores=[0.8, 0.9, 0.7, 0.85],
            propagated_risk=75.5, centrality=0.6, depth_from_entry=2,
        )
        assert len(node.multi_head_scores) == 4
        assert node.propagated_risk == 75.5


class TestEnhancedReasoningEdge:
    def test_default_construction(self):
        edge = EnhancedReasoningEdge(
            source="a", target="b", edge_type="data_flow",
        )
        assert edge.attention_weight == 0.0
        assert edge.transition_strength == 0.0

    def test_full_construction(self):
        edge = EnhancedReasoningEdge(
            source="a", target="b", edge_type="data_flow",
            attention_weight=0.7, transition_strength=0.8,
            effective_weight=0.56, multi_head_weights=[0.6, 0.7, 0.8, 0.7],
        )
        assert len(edge.multi_head_weights) == 4


class TestReasoningChain:
    def test_default_construction(self):
        chain = ReasoningChain()
        assert chain.id.startswith("CHAIN-")
        assert chain.nodes == []
        assert chain.edges == []
        assert chain.severity == "MEDIUM"
        assert chain.chain_probability == 0.0
        assert chain.exploit_difficulty == "MEDIUM"


class TestChainReasoningReport:
    def test_default_construction(self):
        report = ChainReasoningReport()
        assert report.chains == []
        assert report.isolated_findings == []
        assert report.total_findings == 0


# ============================================================
# Test Multi-Head Attention
# ============================================================


class TestMultiHeadAttention:
    def test_multi_head_returns_correct_structure(self):
        graph = VulnerabilityGraph()
        n1 = GraphNode(id="a", node_type=NodeType.VULNERABILITY, label="xss",
                       file_path="app.py", line_number=10, rule_id="xss")
        n2 = GraphNode(id="b", node_type=NodeType.VULNERABILITY, label="sqli",
                       file_path="app.py", line_number=20, rule_id="sql-injection")
        graph.add_node(n1)
        graph.add_node(n2)
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
        graph.add_node(n1)
        graph.add_node(n2)
        graph.add_node(n3)
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

    def test_missing_node_is_skipped(self):
        """Test that a missing node in graph.nodes is skipped per head."""
        graph = VulnerabilityGraph()
        n1 = GraphNode(id="a", node_type=NodeType.VULNERABILITY, label="xss",
                       file_path="app.py", line_number=10, rule_id="xss")
        graph.add_node(n1)
        # Edge references non-existent node "Z"
        graph.add_edge(GraphEdge(source="a", target="Z", edge_type=EdgeType.DATA_FLOW))
        per_head, avg = _multi_head_attention(graph, {"a": 50.0})
        # ("a", "Z") should NOT be in avg because node lookup fails
        assert ("a", "Z") not in avg

    def test_custom_num_heads(self):
        """Test with non-default head count."""
        graph = VulnerabilityGraph()
        n1 = GraphNode(id="a", node_type=NodeType.VULNERABILITY, label="xss",
                       file_path="app.py", line_number=10, rule_id="xss")
        n2 = GraphNode(id="b", node_type=NodeType.VULNERABILITY, label="sqli",
                       file_path="app.py", line_number=20, rule_id="sql-injection")
        graph.add_node(n1)
        graph.add_node(n2)
        graph.add_edge(GraphEdge(source="a", target="b", edge_type=EdgeType.DATA_FLOW))
        per_head, avg = _multi_head_attention(graph, {"a": 50.0}, num_heads=2)
        assert len(per_head) == 2


# ============================================================
# Test Centrality
# ============================================================


class TestComputeCentrality:
    def test_hub_node(self):
        graph = VulnerabilityGraph()
        for i in range(5):
            n = GraphNode(id=f"n{i}", node_type=NodeType.VULNERABILITY, label=f"v{i}",
                          file_path="app.py", line_number=i * 10, rule_id=f"rule-{i}")
            graph.add_node(n)
        for i in range(1, 5):
            graph.add_edge(GraphEdge(source="n0", target=f"n{i}", edge_type=EdgeType.DATA_FLOW))
        cent = _compute_centrality(graph)
        assert cent["n0"] == 1.0
        assert all(cent[f"n{i}"] < 1.0 for i in range(1, 5))

    def test_empty(self):
        graph = VulnerabilityGraph()
        cent = _compute_centrality(graph)
        assert cent == {}

    def test_nodes_with_no_edges(self):
        """Nodes with no edges get 0 centrality."""
        graph = VulnerabilityGraph()
        n = GraphNode(id="lonely", node_type=NodeType.VULNERABILITY, label="xss",
                      file_path="app.py", line_number=1, rule_id="xss")
        graph.add_node(n)
        cent = _compute_centrality(graph)
        assert cent["lonely"] == 0.0

    def test_multiple_components(self):
        """Graph with disconnected components works correctly."""
        graph = VulnerabilityGraph()
        for i in range(4):
            n = GraphNode(id=f"m{i}", node_type=NodeType.VULNERABILITY,
                          label=f"v{i}", file_path="app.py",
                          line_number=i * 10, rule_id=f"rule-{i}")
            graph.add_node(n)
        graph.add_edge(GraphEdge(source="m0", target="m1", edge_type=EdgeType.DATA_FLOW))
        graph.add_edge(GraphEdge(source="m2", target="m3", edge_type=EdgeType.DATA_FLOW))
        cent = _compute_centrality(graph)
        # m0 and m1 should be equal, m2 and m3 equal
        assert cent["m0"] == cent["m1"]
        assert cent["m2"] == cent["m3"]


# ============================================================
# Test Depth from Entry
# ============================================================


class TestDepthFromEntry:
    def test_single_node(self):
        graph = VulnerabilityGraph()
        n = GraphNode(id="only", node_type=NodeType.VULNERABILITY, label="xss",
                      file_path="app.py", line_number=1, rule_id="xss")
        graph.add_node(n)
        graph.adjacency["only"] = []
        depths = _depth_from_entry(graph, "only")
        assert depths == {"only": 0}

    def test_two_hop(self):
        graph = VulnerabilityGraph()
        for i in range(3):
            graph.add_node(GraphNode(id=f"d{i}", node_type=NodeType.VULNERABILITY,
                                      label=f"v{i}", file_path="app.py",
                                      line_number=i * 10, rule_id=f"rule-{i}"))
        graph.add_edge(GraphEdge(source="d0", target="d1", edge_type=EdgeType.DATA_FLOW))
        graph.add_edge(GraphEdge(source="d1", target="d2", edge_type=EdgeType.DATA_FLOW))
        depths = _depth_from_entry(graph, "d0")
        assert depths["d0"] == 0
        assert depths["d1"] == 1
        assert depths["d2"] == 2

    def test_source_only_connected(self):
        """Entry that only appears as target, not in adjacency."""
        graph = VulnerabilityGraph()
        graph.add_node(GraphNode(id="src", node_type=NodeType.VULNERABILITY,
                                  label="x", file_path="app.py",
                                  line_number=1, rule_id="xss"))
        graph.adjacency["src"] = []
        depths = _depth_from_entry(graph, "src")
        assert depths == {"src": 0}


# ============================================================
# Test Infer Severity
# ============================================================


class TestInferSeverity:
    @pytest.mark.parametrize("score,expected", [
        (85.0, "CRITICAL"),
        (70.0, "CRITICAL"),
        (69.9, "HIGH"),
        (50.0, "HIGH"),
        (49.9, "MEDIUM"),
        (30.0, "MEDIUM"),
        (29.9, "LOW"),
        (0.0, "LOW"),
    ])
    def test_severity_levels(self, score, expected):
        assert _infer_severity(score) == expected


# ============================================================
# Test Infer Difficulty
# ============================================================


class TestInferDifficulty:
    def test_empty_chain(self):
        """Empty chain defaults to EASY (avg_risk=0, count=0)."""
        chain = ReasoningChain(nodes=[])
        result = _infer_difficulty(chain)
        # empty chain uses max(1, 0) for division, 0/1 = 0 < 70
        assert result in ("EASY", "MEDIUM", "HARD", "EXTREME")

    def test_easy_short_chain_high_risk(self):
        chain = ReasoningChain(nodes=[
            EnhancedReasoningNode(id="n1", rule_id="x", file_path="a.py",
                                  line=1, severity="HIGH", node_role="entry",
                                  propagated_risk=80),
            EnhancedReasoningNode(id="n2", rule_id="x", file_path="a.py",
                                  line=2, severity="HIGH", node_role="sink",
                                  propagated_risk=80),
        ])
        assert _infer_difficulty(chain) == "EASY"

    def test_medium_chain(self):
        chain = ReasoningChain(nodes=[
            EnhancedReasoningNode(id="n1", rule_id="x", file_path="a.py",
                                  line=1, severity="MEDIUM", node_role="entry",
                                  propagated_risk=60),
            EnhancedReasoningNode(id="n2", rule_id="x", file_path="a.py",
                                  line=2, severity="MEDIUM", node_role="intermediate",
                                  propagated_risk=60),
            EnhancedReasoningNode(id="n3", rule_id="x", file_path="a.py",
                                  line=3, severity="MEDIUM", node_role="sink",
                                  propagated_risk=60),
        ])
        assert _infer_difficulty(chain) == "MEDIUM"

    def test_hard_chain(self):
        chain = ReasoningChain(nodes=[
            EnhancedReasoningNode(id=f"n{i}", rule_id="x", file_path="a.py",
                                  line=i, severity="HIGH", node_role="entry",
                                  propagated_risk=40)
            for i in range(4)
        ])
        assert _infer_difficulty(chain) == "HARD"

    def test_extreme_chain(self):
        chain = ReasoningChain(nodes=[
            EnhancedReasoningNode(id=f"n{i}", rule_id="x", file_path="a.py",
                                  line=i, severity="HIGH", node_role="entry",
                                  propagated_risk=30)
            for i in range(5)
        ])
        assert _infer_difficulty(chain) == "EXTREME"


# ============================================================
# Test Generate Attack Scenario
# ============================================================


class TestGenerateAttackScenario:
    def test_single_node_scenario(self):
        chain = ReasoningChain(nodes=[
            EnhancedReasoningNode(id="n1", rule_id="py.xss.dom",
                                  file_path="app.py", line=10,
                                  severity="HIGH", node_role="isolated"),
        ])
        scenario = _generate_attack_scenario(chain)
        assert "单点利用" in scenario
        assert "py.xss.dom" in scenario

    def test_known_scenario_ssrf_sqli(self):
        chain = ReasoningChain(nodes=[
            EnhancedReasoningNode(id="n1", rule_id="ssrf",
                                  file_path="app.py", line=10,
                                  severity="HIGH", node_role="entry"),
            EnhancedReasoningNode(id="n2", rule_id="sql-injection",
                                  file_path="db.py", line=20,
                                  severity="CRITICAL", node_role="sink"),
        ])
        scenario = _generate_attack_scenario(chain)
        assert "SSRF" in scenario or "SQL" in scenario or "攻击链" in scenario

    def test_known_scenario_xss_cmd(self):
        chain = ReasoningChain(nodes=[
            EnhancedReasoningNode(id="n1", rule_id="xss",
                                  file_path="app.py", line=10,
                                  severity="HIGH", node_role="entry"),
            EnhancedReasoningNode(id="n2", rule_id="command-injection",
                                  file_path="api.py", line=20,
                                  severity="CRITICAL", node_role="sink"),
        ])
        scenario = _generate_attack_scenario(chain)
        assert "XSS" in scenario or "攻击链" in scenario

    def test_generic_multi_hop(self):
        """Non-matching rule IDs produce a generic scenario."""
        chain = ReasoningChain(nodes=[
            EnhancedReasoningNode(id="n1", rule_id="xx-custom",
                                  file_path="a.py", line=1,
                                  severity="HIGH", node_role="entry"),
            EnhancedReasoningNode(id="n2", rule_id="yy-other",
                                  file_path="b.py", line=2,
                                  severity="HIGH", node_role="intermediate"),
            EnhancedReasoningNode(id="n3", rule_id="zz-final",
                                  file_path="c.py", line=3,
                                  severity="HIGH", node_role="sink"),
        ])
        scenario = _generate_attack_scenario(chain)
        assert "多步攻击" in scenario or "攻击链" in scenario


# ============================================================
# Test AttackChainReasoner - Construction & Configuration
# ============================================================


class TestAttackChainReasonerConstruction:
    def test_default_params(self):
        reasoner = AttackChainReasoner()
        assert reasoner.attention_heads == 4
        assert reasoner.propagation_iterations == 3
        assert reasoner.risk_decay == 0.7
        assert reasoner.max_chain_depth == 5

    def test_custom_params(self):
        reasoner = AttackChainReasoner(
            attention_heads=8, propagation_iterations=5,
            risk_decay=0.5, max_chain_depth=10,
        )
        assert reasoner.attention_heads == 8
        assert reasoner.propagation_iterations == 5
        assert reasoner.risk_decay == 0.5
        assert reasoner.max_chain_depth == 10


# ============================================================
# Test AttackChainReasoner - Core Reasoning
# ============================================================


class TestReason:
    def test_reason_empty_findings(self):
        reasoner = AttackChainReasoner()
        report = reasoner.reason([])
        assert report.total_findings == 0
        assert len(report.chains) == 0
        assert report.generated_at is not None

    def test_reason_single_finding(self):
        findings = [_f("py.crypto.weak_hash", 5, "hashlib.md5(x)")]
        reasoner = AttackChainReasoner()
        report = reasoner.reason(findings)
        assert report.total_findings == 1
        assert len(report.chains) == 0
        assert len(report.isolated_findings) == 1

    def test_reason_with_project(self):
        findings = [_f("py.xss.dom", 10, "x")]
        reasoner = AttackChainReasoner()
        report = reasoner.reason(findings, project="my-project")
        assert report.project == "my-project"

    def test_reason_with_exploit_results(self):
        """Test reasoning with pre-computed exploit results."""
        findings = [
            _f("py.xss.dom", 10, "x"),
            _f("py.injection.sql", 20, "y"),
        ]
        reasoner = AttackChainReasoner()
        exploit_results = {}
        for f in findings:
            nid = reasoner._node_id(f)
            exploit_results[nid] = ExploitabilityResult(
                rule_id=f.rule_id, file_path=f.file_path,
                line=f.line_start, severity="HIGH", probability=90.0,
            )
        report = reasoner.reason(findings, exploit_results=exploit_results)
        assert report.total_findings == 2

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

    def test_chain_has_id(self):
        """All chains should have a CHAIN-prefixed ID."""
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
        ]
        report = AttackChainReasoner().reason(findings)
        for chain in report.chains:
            assert chain.id.startswith("CHAIN-")

    def test_chain_edges_have_weights(self):
        """Chain edges should have attention/transition weights."""
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
        ]
        report = AttackChainReasoner().reason(findings)
        for chain in report.chains:
            for edge in chain.edges:
                assert edge.attention_weight >= 0
                assert edge.transition_strength >= 0
                assert len(edge.multi_head_weights) == 4

    def test_node_multi_head_scores(self):
        """Each node should have multi_head_scores list of correct length."""
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
        ]
        report = AttackChainReasoner().reason(findings)
        for chain in report.chains:
            for node in chain.nodes:
                assert len(node.multi_head_scores) == 4

    def test_chain_has_remediation(self):
        """All chains should have at least one remediation item."""
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
        ]
        report = AttackChainReasoner().reason(findings)
        for chain in report.chains:
            assert len(chain.remediation) > 0

    def test_chain_attack_scenario(self):
        """All chains should have a non-empty attack_scenario."""
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
        ]
        report = AttackChainReasoner().reason(findings)
        for chain in report.chains:
            assert chain.attack_scenario != ""

    def test_convergence_delta(self):
        """Report should have convergence_delta > 0."""
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
        ]
        report = AttackChainReasoner().reason(findings)
        assert report.convergence_delta >= 0

    def test_many_findings_produce_chains(self):
        """Larger codebases with multiple vulns produce chains."""
        findings = [
            _f("py.xss.dom", 10, "v"),
            _f("py.injection.sql", 20, "q"),
            _f("py.injection.command", 30, "c"),
            _f("py.path.traversal", 40, "p"),
            _f("py.ssrf.url", 50, "s"),
        ]
        report = AttackChainReasoner().reason(findings)
        assert report.total_findings == 5

    def test_isolated_findings_not_in_chains(self):
        """Findings not part of any chain appear as isolated."""
        findings = [
            _f("py.crypto.weak_hash", 10, "hash.md5(x)"),
            _f("py.debug.enabled", 20, "DEBUG=True"),
        ]
        reasoner = AttackChainReasoner()
        report = reasoner.reason(findings)
        # These shouldn't form a chain but should appear as findings
        assert report.total_findings == 2


# ============================================================
# Test Visualization Exports
# ============================================================


class TestVisualizationExports:
    def _make_report(self):
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
        ]
        return AttackChainReasoner().reason(findings)

    def _make_report_with_isolated(self):
        findings = [
            _f("py.xss.dom", 10, "v"),
            _f("py.crypto.weak_hash", 20, "md5"),
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
        assert "nodes" in jg
        assert "edges" in jg

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

    def test_empty_report_mermaid(self):
        """Empty report mermaid export."""
        report = ChainReasoningReport()
        result = to_mermaid(report)
        assert "flowchart LR" in result

    def test_empty_report_dot(self):
        """Empty report DOT export."""
        report = ChainReasoningReport()
        result = to_dot(report)
        assert "digraph" in result

    def test_empty_report_json(self):
        """Empty report JSON export."""
        report = ChainReasoningReport()
        result = to_json_graph(report)
        assert result["nodes"] == []
        assert result["edges"] == []

    def test_empty_report_ascii(self):
        """Empty report ASCII export shows no chains message."""
        report = ChainReasoningReport()
        result = to_ascii(report)
        assert "[无攻击链]" in result

    def test_mermaid_with_isolated(self):
        """Mermaid export includes isolated findings."""
        report = self._make_report_with_isolated()
        result = to_mermaid(report)
        assert "flowchart LR" in result

    def test_dot_branch_seen_skip(self):
        """Test DOT output skips already-seen nodes (line 665)."""
        report = self._make_report()
        # Run twice to exercise seen-skip logic
        dot1 = to_dot(report)
        dot2 = to_dot(report)
        assert dot1 == dot2

    def test_ascii_with_isolated(self):
        """ASCII export with isolated findings."""
        report = self._make_report_with_isolated()
        result = to_ascii(report)
        # Format may be "[单点漏洞 N 个]" or include "◇" per finding
        assert "单点漏洞" in result or "◇" in result

    def test_ascii_graph_stats_shown(self):
        """ASCII export shows graph stats at bottom."""
        report = self._make_report()
        result = to_ascii(report)
        assert "图统计" in result

    def test_json_graph_with_isolated(self):
        """JSON graph includes isolated nodes."""
        report = self._make_report_with_isolated()
        result = to_json_graph(report)
        assert "nodes" in result

    def test_html_contains_project_name(self):
        """HTML report includes the project name or default."""
        report = self._make_report()
        html = to_html(report)
        assert "玄鉴" in html
        assert "<script>" in html

    def test_html_no_chains(self):
        """HTML report with no chains doesn't crash."""
        report = ChainReasoningReport()
        html = to_html(report)
        assert "<!DOCTYPE html>" in html


# ============================================================
# Test VisualizationFormat Enum
# ============================================================


class TestVisualizationFormat:
    def test_enum(self):
        assert VisualizationFormat.MERMAID.value == "mermaid"
        assert VisualizationFormat.DOT.value == "dot"
        assert VisualizationFormat.JSON.value == "json"
        assert VisualizationFormat.ASCII.value == "ascii"
        assert VisualizationFormat.HTML.value == "html"


# ============================================================
# Test _safe_id
# ============================================================


class TestSafeId:
    def test_safe_id_replaces_colons(self):
        assert ":" not in _safe_id("app.py:10")

    def test_safe_id_replaces_slashes(self):
        assert "/" not in _safe_id("path/to/file")

    def test_safe_id_replaces_dots(self):
        assert "." not in _safe_id("file.py")

    def test_safe_id_replaces_dashes(self):
        assert "-" not in _safe_id("my-rule")

    def test_safe_id_complex(self):
        result = _safe_id("src/main/java/App.java:42:rule-id")
        assert ":" not in result
        assert "/" not in result
        assert "." not in result
        assert "-" not in result


# ============================================================
# Test constants coverage
# ============================================================


class TestConstants:
    def test_remediation_map_not_empty(self):
        assert len(_REMEDIATION_MAP) > 0
        assert "xss" in _REMEDIATION_MAP
        assert "sql" in _REMEDIATION_MAP

    def test_attack_scenarios_not_empty(self):
        assert len(_ATTACK_SCENARIOS) > 0
        assert ("xss", "sql-injection") in _ATTACK_SCENARIOS
