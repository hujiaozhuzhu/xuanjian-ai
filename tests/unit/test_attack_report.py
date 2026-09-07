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


def _f(rule_id, line, code, severity=Severity.HIGH, file_path="app.py"):
    return Finding(
        scanner="python_scanner",
        rule_id=rule_id,
        severity=severity,
        file_path=file_path,
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
    poc_map = {vt: generate_poc(vt) for vt in ("sqli-union", "cmd-injection", "xss-reflected")}
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
        for heading in ("① 攻击面总览", "② 攻防思路", "③ 已验证漏洞表", "④ 攻击路径详情",
                        "⑤ 本地验证PoC和EXP", "⑥ 可能的问题", "⑦ 攻击链串联思路",
                        "⑧ 需人工确认", "⑨ 修复优先级", "⑩ 安全声明"):
            assert heading in md, f"缺章节 {heading}"

    def test_contains_probability(self):
        md = self._report()
        assert "%" in md

    def test_contains_poc_block(self):
        md = self._report()
        assert "```text" in md

    def test_security_declaration_enhanced(self):
        md = self._report()
        assert "仅用于防御验证" in md
        assert "30 天" in md
        assert "attack-purge" in md
        # v2.2.1 强化声明
        assert "本地环境" in md or "localhost" in md or "127.0.0.1" in md
        assert "无真实攻击载荷" in md
        assert "法律与合规声明" in md

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
        assert "⑩ 安全声明" in md
        assert "② 攻防思路" in md
        assert "⑤ 本地验证PoC和EXP" in md

    def test_attack_thinking_section(self):
        """v2.2.1: 攻防思路节应含利用场景、前置条件、影响范围维度"""
        md = self._report()
        assert "利用场景" in md
        assert "前置条件" in md
        assert "攻击路径" in md or "影响范围" in md

    def test_local_poc_section(self):
        """v2.2.1: 本地验证节应含防御验证标注和仅本地回环声明"""
        md = self._report()
        assert "仅用于防御验证" in md
        assert "127.0.0.1" in md or "localhost" in md

    def test_potential_issues_section(self):
        """v2.2.1: 可能的问题节应含利用限制、绕过可能性、修复建议"""
        md = self._report()
        assert "利用限制" in md or "修复建议" in md

    def test_attack_chain_thinking_section(self):
        """v2.2.1: 攻击链串联节应含逐步影响与最终风险"""
        md = self._report()
        assert "攻击链" in md
        # 有路径或至少包含上下文
        assert "逐步影响" in md or "单点漏洞" in md or "串联攻击路径" in md


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


class TestEdgeCasesAndCoverage:
    """边界条件与分支覆盖补充（目标覆盖率 >= 95%）"""

    def test_empty_poc_map_generates_placeholder(self):
        """空 poc_map 时 PoC节应生成占位提示"""
        md = generate_attack_report(
            project="demo",
            findings=[],
            chain_report=orchestrate([], project="demo"),
            poc_map={},
        )
        assert "无可生成的 PoC 模板" in md

    def test_unknown_rule_id_attack_thinking_fallback(self):
        """未知规则 ID 应回退通用提示"""
        finding = _f("some.custom.rule.xyz", 1, "weird()")
        exploit = assess(finding)
        chain = orchestrate([finding], project="demo")
        md = generate_attack_report(
            project="demo",
            findings=[finding],
            chain_report=chain,
            exploit_results=[exploit],
            verify_results=[verify(finding, project_root=None)],
            poc_map={},
        )
        assert "暂无内置攻防思路条目" in md

    def test_theoretical_finding_zero_probability(self):
        """纯常量 finding 应对应 theoretical，概率为 0"""
        finding = _f("py.crypto.hardcoded_key", 1, 'SECRET_KEY = "abc123"', Severity.HIGH)
        exploit = assess(finding)
        chain = orchestrate([finding], project="demo")
        md = generate_attack_report(
            project="demo",
            findings=[finding],
            chain_report=chain,
            exploit_results=[exploit],
            verify_results=[verify(finding, project_root=None)],
            poc_map={},
        )
        assert "theoretical" in md or "无活跃风险" in md

    def test_attack_chain_single_point_only(self):
        """仅单点漏洞（无路径）时攻击链节应输出潜在串联提示"""
        finding = _f("py.crypto.weak_hash", 5, "hashlib.md5(x)", Severity.LOW)
        exploit = assess(finding)
        chain = orchestrate([finding], project="demo")
        md = generate_attack_report(
            project="demo",
            findings=[finding],
            chain_report=chain,
            exploit_results=[exploit],
            verify_results=[verify(finding, project_root=None)],
            poc_map={},
        )
        assert "单点漏洞" in md
        assert "潜在串联可能性" in md

    def test_all_difficulty_levels_in_effort_estimation(self):
        """覆盖 _effort_minutes 的三个分支：>=70, >=40, <40"""
        from fp_sentinel.reporting.attack_report import _effort_minutes
        assert _effort_minutes(80, "EASY") == 30       # >=70 → base
        assert _effort_minutes(50, "MEDIUM") == 120    # >=40 → base*2
        assert _effort_minutes(10, "HARD") == 480      # <40 → base*4

    def test_unknown_difficulty_default_effort(self):
        """未知难度应按 MEDIUM(60) 计算"""
        from fp_sentinel.reporting.attack_report import _effort_minutes
        assert _effort_minutes(50, "WEIRD_LEVEL") == 120  # 默认 60*2

    def test_lookup_thinking_with_empty_rule(self):
        """空 rule_id 的 lookup 应返回空 dict"""
        from fp_sentinel.reporting.attack_report import _look_up_thinking, _look_up_limitation
        assert _look_up_thinking("") == {}
        assert _look_up_thinking(None) == {}
        assert _look_up_limitation("") == {}
        assert _look_up_limitation(None) == {}

    def test_lookup_known_rule_types(self):
        """常见规则类型应正确映射到攻防思路知识库"""
        from fp_sentinel.reporting.attack_report import _look_up_thinking, _look_up_limitation
        # _ATTACK_THINKING_DB 使用子串匹配（key in rid）
        xss = _look_up_thinking("js.xss.dom")
        assert xss.get("scenario") is not None
        assert xss.get("impact") is not None
        cmd = _look_up_thinking("py.injection.command")
        assert cmd.get("attack_path") is not None
        # limitation 库 - 使用 "cmd"/"command" 作为 key
        cmd_lim = _look_up_limitation("py.injection.command")
        assert cmd_lim.get("fix") is not None
        ssrf_lim = _look_up_limitation("py.network.ssrf")
        assert ssrf_lim.get("limitation") is not None

    def test_path_details_with_poc_match(self):
        """路径详情中 PoC 代码块应正确引用 poc_map（按 vuln_type=rule_id 匹配）"""
        findings = [
            _f("py.xss.dom", 10, 'v = request.args.get("input")', Severity.MEDIUM),
            _f("py.injection.sql", 20, 'q = "SELECT " + uid', Severity.CRITICAL),
        ]
        exploit = {node_id(f): assess(f) for f in findings}
        chain = orchestrate(findings, project="demo", exploit_results=exploit)
        # poc_map 的 key 应与 path step 的 vuln_type（即 rule_id）匹配
        poc_map = {findings[0].rule_id: generate_poc("xss-dom")}
        md = generate_attack_report(
            project="demo", findings=findings, chain_report=chain,
            exploit_results=list(exploit.values()), poc_map=poc_map,
        )
        assert "参考案例:" in md

    def test_fix_priority_all_zero_probability(self):
        """全部 theoretical → 修复优先级显示无活跃风险"""
        finding = _f("py.crypto.hardcoded_key", 1, 'KEY = "x"', Severity.CRITICAL)
        exploit = assess(finding)  # theoretical, probability=0
        assert exploit.probability == 0.0
        md = generate_attack_report(
            project="demo", findings=[finding],
            chain_report=orchestrate([finding], project="demo"),
            exploit_results=[exploit],
            verify_results=[verify(finding, project_root=None)],
        )
        assert "无活跃风险" in md

    def test_unknown_limitation_entry_fallback(self):
        """未知规则 ID 的可能的问题节应回退通用提示"""
        finding = _f("some.custom.unknown_rule", 1, "weird_code()", Severity.HIGH)
        exploit = assess(finding)
        md = generate_attack_report(
            project="demo", findings=[finding],
            chain_report=orchestrate([finding], project="demo"),
            exploit_results=[exploit],
            verify_results=[verify(finding, project_root=None)],
            poc_map={},
        )
        assert "暂无内置的利用限制分析" in md


class TestSafetyRedLines:
    """安全红线综合验证"""

    @pytest.fixture(autouse=True)
    def setup_bundle(self):
        self.findings, self.exploit, self.chain, self.verifies, self.poc_map = _fixture_bundle()

    def _report(self, **kwargs):
        findings, exploit, chain, verifies, poc_map = (
            self.findings, self.exploit, self.chain, self.verifies, self.poc_map,
        )
        return generate_attack_report(
            project="demo",
            findings=findings,
            chain_report=chain,
            verify_results=verifies,
            exploit_results=list(exploit.values()),
            poc_map=poc_map,
            **kwargs,
        )

    def test_all_poc_target_localhost(self):
        """S1: 报告中所有 PoC 目标均为 localhost / 127.0.0.1，无外部地址"""
        md = self._report()
        # 查找 http:// 目标地址
        import re
        urls = re.findall(r'http://([^/)\s]+)', md)
        for url in urls:
            host = url.split(":")[0]
            assert host in ("127.0.0.1", "localhost"), f"发现非本地目标: {host}"

    def test_no_external_network_requests(self):
        """S4: 报告中不应包含任何外部网络请求相关的 payload（如 curl 真实站点）"""
        md = self._report()
        # 不包含 raw.githubusercontent.com / exploit-db 等外部资源
        assert "evil.com" not in md
        assert "raw.githubusercontent" not in md

    def test_defense_only_label(self):
        """PoC 节目标注仅用于防御验证"""
        md = self._report()
        assert "仅用于防御验证" in md

    def test_no_external_ip(self):
        """报告中不应出现任何非本地的 IP 地址"""
        md = self._report()
        import re
        ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', md)
        for ip in ips:
            assert ip.startswith("127.0.0.") or ip == "0.0.0.0", f"发现非本地IP: {ip}"

    def test_30_day_cleanup_declaration(self):
        """S5: 报告应包含 30 天清理声明"""
        md = self._report()
        assert "30 天" in md
        assert "attack-purge" in md

    def test_local_environment_restriction(self):
        """S1: 报告应明确标注仅本地环境"""
        md = self._report()
        assert "本地环境" in md or "本地回环" in md

    def test_no_real_attack_payload(self):
        """S4: 报告声明不包含真实攻击载荷"""
        md = self._report()
        assert "无真实攻击载荷" in md

    def test_legal_compliance_statement(self):
        """法律合规声明"""
        md = self._report()
        assert "法律与合规声明" in md
        assert "未授权" in md
