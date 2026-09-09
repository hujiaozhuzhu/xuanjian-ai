"""
Tests for fp_sentinel.reporting.enhanced_report module.
Target: >= 95% code coverage.
"""

import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

from fp_sentinel.reporting.enhanced_report import (
    ArchitectureDiagram,
    ArchitectureNode,
    EnhancedReportConfig,
    AttackPathStep,
    _render_ascii_arch,
    _render_attack_path_svg,
    _build_inline_heatmap,
    _render_fix_timeline_section,
    _render_industry_benchmark_comparison,
    _infer_architecture_from_findings,
    _simplify_vuln_type,
    generate_enhanced_report,
    write_enhanced_report,
    generate_and_write_enhanced_report,
)
from fp_sentinel.attack.chain_orchestrator import AttackChainReport
from fp_sentinel.attack.target_validator import VerifyResult, VerifyStatus


# ─────────────────────── Fixtures ───────────────────────

def _make_finding(
    rule_id="sql_injection",
    severity="HIGH",
    file_path="src/auth/login.py",
    line_start=42,
    code_snippet="query = 'SELECT * FROM users WHERE id = ' + user_id",
    category="SQL_INJECTION",
    probability=75,
    finding_id=None,
):
    """Create a mock Finding object."""
    f = MagicMock()
    f.rule_id = rule_id
    f.severity = severity
    f.file_path = file_path
    f.line_start = line_start
    f.code_snippet = code_snippet
    f.category = category
    f.finding_id = finding_id or f"f-{hash(rule_id + file_path) % 10000:04d}"
    f.message = f"Vulnerability found: {rule_id}"
    f.probability = probability
    f.module = Path(file_path).parent.name or "root"
    return f


def _make_exploit_result(rule_id="sql_injection", probability=75, severity="HIGH", file_path="src/auth/login.py", line=42):
    """Create a mock ExploitabilityResult."""
    er = MagicMock()
    er.rule_id = rule_id
    er.probability = probability
    er.severity = severity
    er.reachability = "reachable"
    er.file_path = file_path
    er.line = line
    return er


def _make_chain_report(paths=None, single_points=None):
    """Create a mock AttackChainReport."""
    cr = MagicMock(spec=AttackChainReport)
    cr.paths = paths or []
    cr.single_points = single_points or []
    cr.path_count = len(cr.paths)
    cr.max_probability = 0.0
    if cr.paths:
        cr.max_probability = max(p.probability for p in cr.paths)
    return cr


def _make_chain_path(name="Test Path", probability=75, severity="HIGH"):
    """Create a mock AttackChainPath."""
    path = MagicMock()
    path.name = name
    path.probability = probability
    path.severity = severity
    path.remediation = ["fix auth", "add validation"]

    step1 = MagicMock()
    step1.step_number = 1
    step1.vuln_type = "sql_injection"
    step1.file_path = "src/auth/login.py"
    step1.line = 42
    step1.difficulty = "MEDIUM"
    step1.probability = 80
    step1.node = None

    step2 = MagicMock()
    step2.step_number = 2
    step2.vuln_type = "xss"
    step2.file_path = "src/web/views.py"
    step2.line = 100
    step2.difficulty = "EASY"
    step2.probability = 60
    step2.node = None

    path.steps = [step1, step2]
    return path


# ─────────────────────── Architecture Tests ───────────────────────

class TestArchitectureDiagram:
    def test_empty_diagram(self):
        diagram = ArchitectureDiagram()
        result = _render_ascii_arch(diagram)
        assert result == "（未提供架构数据）"

    def test_add_node(self):
        diagram = ArchitectureDiagram()
        node = ArchitectureNode(name="api", node_type="service", risk_level="HIGH")
        diagram.add_node(node)
        assert len(diagram.nodes) == 1
        assert diagram.nodes[0].name == "api"

    def test_add_edge(self):
        diagram = ArchitectureDiagram()
        diagram.add_edge("client", "api", "HTTP")
        assert len(diagram.edges) == 1
        assert diagram.edges[0] == ("client", "api", "HTTP")

    def test_render_with_tech_stack(self):
        diagram = ArchitectureDiagram()
        diagram.add_node(ArchitectureNode(
            name="api", node_type="service", tech_stack="FastAPI", risk_level="CRITICAL"
        ))
        result = _render_ascii_arch(diagram)
        assert "api" in result
        assert "FastAPI" in result
        assert "CRITICAL" in result

    def test_render_all_node_types(self):
        diagram = ArchitectureDiagram()
        diagram.add_node(ArchitectureNode(name="gateway", node_type="entry", risk_level="HIGH"))
        diagram.add_node(ArchitectureNode(name="auth", node_type="service", risk_level="CRITICAL"))
        diagram.add_node(ArchitectureNode(name="users_db", node_type="db", risk_level="MEDIUM"))
        diagram.add_node(ArchitectureNode(name="redis", node_type="external", risk_level="LOW"))
        diagram.add_edge("gateway", "auth", "HTTP")
        diagram.add_edge("auth", "users_db", "TCP")
        result = _render_ascii_arch(diagram)
        assert "入口层" in result
        assert "服务层" in result
        assert "数据层" in result
        assert "外部依赖" in result
        assert "gateway" in result
        assert "auth" in result
        assert "users_db" in result
        assert "redis" in result

    def test_render_with_risk_markers(self):
        diagram = ArchitectureDiagram()
        diagram.add_node(ArchitectureNode(name="s1", node_type="service", risk_level="CRITICAL"))
        diagram.add_node(ArchitectureNode(name="s2", node_type="service", risk_level="HIGH"))
        diagram.add_node(ArchitectureNode(name="s3", node_type="service", risk_level="MEDIUM"))
        diagram.add_node(ArchitectureNode(name="s4", node_type="service", risk_level="LOW"))
        diagram.add_node(ArchitectureNode(name="s5", node_type="service", risk_level="INFO"))
        result = _render_ascii_arch(diagram)
        assert "[!!!]" in result
        assert "[!!]" in result
        assert "[!]" in result
        assert "[.]" in result
        assert "[i]" in result


# ─────────────────────── SVG Attack Path Tests ───────────────────────

class TestAttackPathSVG:
    def test_empty_paths(self):
        cr = _make_chain_report(paths=[])
        result = _render_attack_path_svg(cr)
        assert "<!-- 无" in result

    def test_single_path(self):
        path = _make_chain_path(name="RCE Chain", probability=80)
        cr = _make_chain_report(paths=[path])
        result = _render_attack_path_svg(cr)
        assert "RCE Chain" in result
        assert "80%" in result
        assert "svg" in result.lower()
        assert "RCE Chain" in result

    def test_multiple_paths(self):
        p1 = _make_chain_path("Path1", 80)
        p2 = _make_chain_path("Path2", 50)
        cr = _make_chain_report(paths=[p1, p2])
        result = _render_attack_path_svg(cr)
        assert "Path1" in result
        assert "Path2" in result

    def test_path_with_arrows(self):
        path = _make_chain_path()
        cr = _make_chain_report(paths=[path])
        result = _render_attack_path_svg(cr)
        # Should contain line elements for arrows
        assert "line" in result.lower()

    def test_probability_color_coding(self):
        high_path = _make_chain_path("High", 80)
        mid_path = _make_chain_path("Mid", 50)
        low_path = _make_chain_path("Low", 20)
        cr = _make_chain_report(paths=[high_path, mid_path, low_path])
        result = _render_attack_path_svg(cr)
        # High probability should use critical color
        assert "#e94560" in result  # Critical color

    def test_max_paths_limit(self):
        paths = [_make_chain_path(f"P{i}", 70) for i in range(10)]
        cr = _make_chain_report(paths=paths)
        result = _render_attack_path_svg(cr)
        # Should still render (limited to 8)
        assert "svg" in result.lower()

    def test_custom_dimensions(self):
        path = _make_chain_path()
        cr = _make_chain_report(paths=[path])
        result = _render_attack_path_svg(cr, width=1200, height_factor=150)
        assert 'viewBox="0 0 1200' in result


# ─────────────────────── Heatmap Tests ───────────────────────

class TestInlineHeatmap:
    def test_empty_findings(self):
        result = _build_inline_heatmap([])
        assert result == "（无漏洞数据）"

    def test_single_finding(self):
        findings = [_make_finding()]
        result = _build_inline_heatmap(findings)
        # Should have table structure
        assert "|" in result
        assert "SQLi" in result

    def test_multiple_categories(self):
        findings = [
            _make_finding(rule_id="sql_injection", category="SQL_INJECTION"),
            _make_finding(rule_id="xss", category="XSS", file_path="src/web/views.py"),
            _make_finding(rule_id="cmd_injection", category="COMMAND_INJECTION", file_path="src/api/exec.py"),
        ]
        result = _build_inline_heatmap(findings)
        assert "SQLi" in result
        assert "XSS" in result
        assert "CMDi" in result

    def test_risk_scores_shown(self):
        findings = [
            _make_finding(severity="CRITICAL"),
            _make_finding(severity="CRITICAL"),
            _make_finding(severity="HIGH"),
        ]
        result = _build_inline_heatmap(findings)
        # Should contain numeric risk values
        assert "(" in result  # Risk scores shown in parens

    def test_module_filter(self):
        findings = [
            _make_finding(file_path="src/auth/login.py"),
            _make_finding(file_path="src/web/views.py"),
        ]
        result = _build_inline_heatmap(findings, modules=["auth"])
        assert "auth" in result
        # "web" should be filtered out
        assert "web" not in result


class TestSimplifyVulnType:
    def test_sql(self):
        assert _simplify_vuln_type("java-sql-injection") == "SQLi"

    def test_xss(self):
        assert _simplify_vuln_type("js-xss-innerhtml") == "XSS"

    def test_command(self):
        assert _simplify_vuln_type("python-os.system") == "CMDi"

    def test_eval(self):
        assert _simplify_vuln_type("js-eval-exec") == "Eval"

    def test_path_traversal(self):
        assert _simplify_vuln_type("path-traversal") == "PathT"

    def test_ssrf(self):
        assert _simplify_vuln_type("ssrf-http-request") == "SSRF"

    def test_deserialization(self):
        assert _simplify_vuln_type("java-deserialization") == "Deser"

    def test_hardcoded_secret(self):
        assert _simplify_vuln_type("hardcoded-api-key") == "Secret"

    def test_jwt(self):
        assert _simplify_vuln_type("jwt-weak-key") == "JWT"

    def test_redirect(self):
        assert _simplify_vuln_type("open-redirect") == "Redir"

    def test_crypto(self):
        assert _simplify_vuln_type("weak-hash-md5") == "Crypto"

    def test_debug(self):
        assert _simplify_vuln_type("debug-mode-enabled") == "Debug"

    def test_xxe(self):
        assert _simplify_vuln_type("xxe-xml-parsing") == "XXE"

    def test_upload(self):
        assert _simplify_vuln_type("file-upload-unsafe") == "Upload"

    def test_unknown(self):
        assert _simplify_vuln_type("custom-rule-xyz") == "Other"


# ─────────────────────── Fix Timeline Tests ───────────────────────

class TestFixTimeline:
    def test_empty(self):
        result = _render_fix_timeline_section([])
        assert "无待整改项" in result

    def test_priority_ordering(self):
        f1 = _make_finding(rule_id="sql_injection")  # prob 75
        f2 = _make_finding(rule_id="xss", probability=30)
        er1 = _make_exploit_result(rule_id="sql_injection", probability=75)
        er2 = _make_exploit_result(rule_id="xss", probability=30)
        result = _render_fix_timeline_section([f1, f2], [er1, er2])
        # Higher probability should come first
        sql_pos = result.find("sql_injection")
        xss_pos = result.find("xss")
        assert sql_pos < xss_pos

    def test_progress_bar(self):
        f = _make_finding()
        er = _make_exploit_result(probability=75)
        result = _render_fix_timeline_section([f], [er])
        assert "#" in result  # Progress bar uses #
        assert "风险进度" in result

    def test_p0_marker(self):
        f = _make_finding()
        er = _make_exploit_result(probability=85)
        result = _render_fix_timeline_section([f], [er])
        assert "[!!!]" in result
        assert "P0" in result

    def test_p1_marker(self):
        f = _make_finding()
        er = _make_exploit_result(probability=50)
        result = _render_fix_timeline_section([f], [er])
        assert "[!!]" in result
        assert "P1" in result

    def test_p2_marker(self):
        f = _make_finding()
        er = _make_exploit_result(probability=20)
        result = _render_fix_timeline_section([f], [er])
        assert "[!]" in result
        assert "P2" in result

    def test_p3_marker(self):
        f = _make_finding()
        er = _make_exploit_result(probability=5)
        result = _render_fix_timeline_section([f], [er])
        assert "[.]" in result
        assert "P3" in result


# ─────────────────────── Industry Benchmark Tests ───────────────────────

class TestIndustryBenchmarkComparison:
    def test_with_findings(self):
        findings = [_make_finding()]
        result = _render_industry_benchmark_comparison(findings, "internet")
        # Should produce some markdown
        assert isinstance(result, str)

    def test_fallback_on_invalid_industry(self):
        findings = [_make_finding()]
        # Invalid industry should fallback to internet
        result = _render_industry_benchmark_comparison(findings, "nonexistent_industry")
        assert isinstance(result, str)

    def test_empty_findings(self):
        result = _render_industry_benchmark_comparison([], "internet")
        assert isinstance(result, str)


# ─────────────────────── Architecture Inference Tests ───────────────────────

class TestInferArchitecture:
    def test_from_findings(self):
        findings = [
            _make_finding(file_path="controllers/auth.py"),
            _make_finding(file_path="services/user.py"),
            _make_finding(file_path="models/db.py"),
            _make_finding(file_path="config/settings.py"),
        ]
        diagram = _infer_architecture_from_findings(findings)
        assert len(diagram.nodes) > 0

    def test_node_types_assigned(self):
        findings = [_make_finding(file_path="controllers/auth.py")]
        diagram = _infer_architecture_from_findings(findings)
        assert diagram.nodes[0].node_type == "entry"

    def test_detects_db(self):
        findings = [_make_finding(file_path="models/database.py")]
        diagram = _infer_architecture_from_findings(findings)
        assert diagram.nodes[0].node_type == "db"

    def test_detects_external(self):
        findings = [_make_finding(file_path="middleware/auth.py")]
        diagram = _infer_architecture_from_findings(findings)
        assert diagram.nodes[0].node_type == "external"

    def test_generates_edges(self):
        findings = [
            _make_finding(file_path="src/a/module1.py"),
            _make_finding(file_path="src/b/module2.py"),
        ]
        diagram = _infer_architecture_from_findings(findings)
        assert len(diagram.edges) > 0

    def test_empty_findings(self):
        diagram = _infer_architecture_from_findings([])
        assert len(diagram.nodes) == 0


# ─────────────────────── Report Generation Tests ───────────────────────

class TestGenerateEnhancedReport:
    def test_basic_report(self):
        findings = [_make_finding()]
        cr = _make_chain_report(paths=[_make_chain_path()])
        report = generate_enhanced_report(
            project="test-project",
            findings=findings,
            chain_report=cr,
        )
        assert "test-project" in report
        assert "增强安全审计报告" in report

    def test_report_with_empty_findings(self):
        cr = _make_chain_report()
        report = generate_enhanced_report(
            project="empty-proj",
            findings=[],
            chain_report=cr,
        )
        assert "empty-proj" in report

    def test_report_with_arch_diagram(self):
        findings = [_make_finding()]
        cr = _make_chain_report()
        arch = ArchitectureDiagram()
        arch.add_node(ArchitectureNode(name="api", node_type="service", risk_level="HIGH"))
        report = generate_enhanced_report(
            project="arch-proj",
            findings=findings,
            chain_report=cr,
            architecture=arch,
        )
        assert "api" in report

    def test_report_with_svg_paths(self):
        findings = [_make_finding()]
        cr = _make_chain_report(paths=[_make_chain_path()])
        report = generate_enhanced_report(
            project="svg-proj",
            findings=findings,
            chain_report=cr,
        )
        assert "svg" in report.lower()

    def test_report_with_heatmap(self):
        findings = [
            _make_finding(rule_id="sql_injection", category="SQL_INJECTION"),
            _make_finding(rule_id="xss", category="XSS", file_path="src/web/v.py"),
        ]
        cr = _make_chain_report()
        report = generate_enhanced_report(
            project="heatmap-proj",
            findings=findings,
            chain_report=cr,
        )
        assert "热力图" in report

    def test_report_config_disabled_features(self):
        findings = [_make_finding()]
        cr = _make_chain_report(paths=[_make_chain_path()])
        config = EnhancedReportConfig(
            include_arch_diagram=False,
            include_attack_svg=False,
            include_heatmap=False,
            include_risk_trend=False,
            include_industry_comparison=False,
        )
        report = generate_enhanced_report(
            project="minimal-proj",
            findings=findings,
            chain_report=cr,
            config=config,
        )
        assert "minimal-proj" in report

    def test_report_with_industry(self):
        findings = [_make_finding()]
        cr = _make_chain_report()
        report = generate_enhanced_report(
            project="finance-proj",
            findings=findings,
            chain_report=cr,
            industry="finance",
        )
        assert "finance-proj" in report

    def test_report_with_verify_results(self):
        findings = [_make_finding()]
        cr = _make_chain_report()
        vr = [VerifyResult(status=VerifyStatus.VERIFIED_LOCAL, method="docker", evidence="found")]
        report = generate_enhanced_report(
            project="verify-proj",
            findings=findings,
            chain_report=cr,
            verify_results=vr,
        )
        assert "verify-proj" in report

    def test_security_statement_present(self):
        findings = [_make_finding()]
        cr = _make_chain_report()
        report = generate_enhanced_report(
            project="secure-proj",
            findings=findings,
            chain_report=cr,
        )
        assert "安全声明" in report
        assert "防御验证" in report

    def test_report_idempotent(self):
        """Same input should produce same report."""
        findings = [_make_finding()]
        cr = _make_chain_report()
        now = "2025-01-01 00:00:00 UTC"
        r1 = generate_enhanced_report("test", findings, cr, generated_at=now)
        r2 = generate_enhanced_report("test", findings, cr, generated_at=now)
        assert r1 == r2


# ─────────────────────── Write Report Tests ───────────────────────

class TestWriteEnhancedReport:
    def test_write_to_allowed_dir(self, tmp_path):
        content = "# Test Report"
        result = write_enhanced_report(content, str(tmp_path), "test.md")
        assert result.exists()
        assert result.read_text() == content

    def test_path_traversal_blocked(self, tmp_path):
        from fp_sentinel.reporting.attack_report import ReportPathError
        with pytest.raises(ReportPathError):
            write_enhanced_report("bad", str(tmp_path), "../../../etc/passwd")

    def test_generate_and_write(self, tmp_path):
        findings = [_make_finding()]
        cr = _make_chain_report()
        result = generate_and_write_enhanced_report(
            project="full-proj",
            findings=findings,
            chain_report=cr,
            output_dir=str(tmp_path),
        )
        assert result.exists()
        assert "full-proj" in result.read_text()


# ─────────────────────── EnhancedReportConfig Tests ───────────────────────

class TestEnhancedReportConfig:
    def test_defaults(self):
        config = EnhancedReportConfig()
        assert config.include_arch_diagram is True
        assert config.include_attack_svg is True
        assert config.include_heatmap is True
        assert config.theme == "dark"
        assert config.output_format == "markdown"

    def test_custom_config(self):
        config = EnhancedReportConfig(
            include_arch_diagram=False,
            theme="light",
        )
        assert config.include_arch_diagram is False
        assert config.include_heatmap is True
        assert config.theme == "light"
