"""
A3. 攻击链编排测试
"""

from fp_sentinel.attack.chain_orchestrator import orchestrate, node_id
from fp_sentinel.attack.exploitability import assess
from fp_sentinel.models import Finding, Severity


def _f(rule_id, line, code, severity=Severity.HIGH, file_path="app.py"):
    return Finding(
        scanner="python_scanner",
        rule_id=rule_id,
        severity=severity,
        file_path=file_path,
        line_start=line,
        code_snippet=code,
    )


class TestChainOrchestration:
    def test_multi_point_generates_path(self):
        """多点同项目 → 生成 A→B→C 路径"""
        findings = [
            _f("py.xss.dom", 10, 'v = request.args.get("input")'),
            _f("py.injection.sql", 20, 'q = "SELECT " + uid'),
            _f("py.injection.command", 30, "os.system(cmd)"),
        ]
        exploit = {node_id(f): assess(f) for f in findings}
        report = orchestrate(findings, project="demo", exploit_results=exploit)
        assert report.path_count >= 1
        path = report.paths[0]
        assert len(path.steps) >= 2
        # 步骤按 A→B→C 编号
        assert [s.step_number for s in path.steps] == list(range(1, len(path.steps) + 1))
        assert 0 < path.probability <= 100

    def test_entry_and_sink_classification(self):
        findings = [
            _f("py.xss.dom", 10, 'v = request.args.get("input")'),
            _f("py.injection.sql", 20, 'q = "SELECT " + uid'),
        ]
        report = orchestrate(findings, exploit_results={})
        assert report.entry_count >= 1
        assert report.sink_count >= 1

    def test_single_point_scored(self):
        """无法成链的单点漏洞直接评分"""
        findings = [
            _f("py.crypto.weak_hash", 5, "hashlib.md5(x)"),
        ]
        exploit = {node_id(findings[0]): assess(findings[0])}
        report = orchestrate(findings, exploit_results=exploit)
        assert report.path_count == 0
        assert len(report.single_points) == 1
        sp = report.single_points[0]
        assert sp.rule_id == "py.crypto.weak_hash"
        assert sp.probability >= 0

    def test_empty_findings(self):
        report = orchestrate([], project="empty")
        assert report.path_count == 0
        assert report.total_findings == 0

    def test_paths_sorted_by_probability(self):
        findings = [
            _f("py.xss.dom", 10, 'v = request.args.get("input")'),
            _f("py.injection.sql", 20, 'q = "SELECT " + uid'),
            _f("py.injection.command", 30, "os.system(cmd)"),
        ]
        exploit = {node_id(f): assess(f) for f in findings}
        report = orchestrate(findings, exploit_results=exploit)
        probs = [p.probability for p in report.paths]
        assert probs == sorted(probs, reverse=True)

    def test_step_location_info(self):
        findings = [
            _f("py.xss.dom", 10, 'v = request.args.get("input")'),
            _f("py.injection.sql", 20, 'q = "SELECT " + uid'),
        ]
        report = orchestrate(findings, exploit_results={})
        if report.paths:
            step = report.paths[0].steps[0]
            assert step.file_path == "app.py"
            assert step.line > 0
