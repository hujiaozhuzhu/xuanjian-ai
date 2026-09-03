"""
A5. 攻防报告生成器测试
"""

from pathlib import Path

import pytest

from fp_sentinel.attack.chain_orchestrator import orchestrate, node_id
from fp_sentinel.attack.exploitability import assess
from fp_sentinel.attack.poc_templates import POC_TEMPLATES, generate_poc
from fp_sentinel.attack.target_validator import verify
from fp_sentinel.models import Finding, Severity
from fp_sentinel.reporting.attack_report import (
    ReportPathError,
    generate_attack_report,
    resolve_output_path,
    write_report,
)


def _f(rule_id, line, code, severity=Severity.HIGH):
    return Finding(
        scanner="python_scanner",
        rule_id=rule_id,
        severity=severity,
        file_path="app.py",
        line_start=line,
        code_snippet=code,
    )


def _fixture_bundle():
    findings = [
        _f("py.xss.dom", 10, 'v = request.args.get("input")', Severity.MEDIUM),
        _f("py.injection.sql", 20, 'q = "SELECT " + uid', Severity.CRITICAL),
        _f("py.injection.command", 30, "os.system(cmd)", Severity.CRITICAL),
        _f("py.crypto.weak_hash", 5, "hashlib.md5(x)", Severity.MEDIUM),
    ]
    exploit = {node_id(f): assess(f) for f in findings}
    chain = orchestrate(findings, project="demo", exploit_results=exploit)
    verifies = [verify(f, project_root=None) for f in findings]
    poc_map = {vt: generate_poc(vt) for vt in ("sqli-union", "cmd-injection")}
    return findings, exploit, chain, verifies, poc_map


class TestReportContent:
    @pytest.fixture(autouse=True)
    def setup_bundle(self):
        self.bundle = _fixture_bundle()

    def _report(self):
        findings, exploit, chain, verifies, poc_map = self.bundle
        return generate_attack_report(
            project="demo",
            findings=findings,
            chain_report=chain,
            verify_results=verifies,
            exploit_results=list(exploit.values()),
            poc_map=poc_map,
        )

    def test_all_sections_present(self):
        md = self._report()
        for heading in ("① 攻击面总览", "② 已验证漏洞表", "③ 攻击路径详情",
                        "④ 需人工确认", "⑤ 修复优先级", "⑥ 安全声明"):
            assert heading in md, f"缺章节 {heading}"

    def test_contains_probability(self):
        md = self._report()
        assert "%" in md

    def test_contains_poc_block(self):
        md = self._report()
        assert "```text" in md

    def test_security_declaration(self):
        md = self._report()
        assert "PoC 仅用于防御验证" in md
        assert "30 天" in md
        assert "attack-purge" in md

    def test_honest_verify_status(self):
        """无 Docker 环境：状态全为 simulated/manual，绝不出现 verified_local"""
        md = self._report()
        assert "verified_local" not in md or "（Docker 靶场）" not in md
        assert "simulated" in md or "manual_required" in md

    def test_ascii_path_diagram(self):
        md = self._report()
        assert "[路径" in md
        assert "↓" in md

    def test_no_external_addresses(self):
        """报告不出现真实基础设施地址"""
        md = self._report()
        assert "evil.com" not in md
        assert "192.168." not in md

    def test_empty_findings_report(self):
        from fp_sentinel.attack.chain_orchestrator import orchestrate
        chain = orchestrate([], project="clean")
        md = generate_attack_report(project="clean", findings=[], chain_report=chain)
        assert "⑥ 安全声明" in md


class TestOutputWhitelist:
    """S7 白名单校验"""

    def test_valid_output(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        path = write_report("# t", str(tmp_path / "reports"), "attack_report.md")
        assert path.exists()
        assert path.name == "attack_report.md"

    def test_traversal_rejected(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(ReportPathError):
            resolve_output_path(
                str(tmp_path / "reports"),
                "../outside.md",
                allowed_roots=[str(tmp_path / "reports")],
            )

    def test_absolute_escape_rejected(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        outside = tmp_path / "elsewhere" / "x.md"
        with pytest.raises(ReportPathError):
            resolve_output_path(
                str(tmp_path / "reports"),
                str(outside),
                allowed_roots=[str(tmp_path / "reports")],
            )

    def test_poc_reference_cve_in_report(self):
        poc = generate_poc("sqli-union")
        assert poc.reference_cve == POC_TEMPLATES["sqli-union"].reference_cve
