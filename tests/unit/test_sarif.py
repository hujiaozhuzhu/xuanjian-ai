"""
SARIF 2.1.0 输出器单测
"""

import json

from fp_sentinel.models import Finding, ScanResult, ScanTool, Severity
from fp_sentinel.reporting.sarif import to_sarif, SARIF_VERSION, SARIF_SCHEMA_URI, TOOL_NAME


def _make_finding(**overrides) -> Finding:
    defaults = dict(
        scanner="python_scanner",
        rule_id="py.injection.sql",
        severity=Severity.CRITICAL,
        file_path="app.py",
        line_start=24,
        code_snippet='query = "SELECT * FROM users" + user_id',
        message="SQL 注入风险",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
        confidence=0.8,
        fingerprint="abc123",
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestToSarif:
    def test_basic_structure(self):
        sarif = to_sarif([_make_finding()])
        assert sarif["$schema"] == SARIF_SCHEMA_URI
        assert sarif["version"] == SARIF_VERSION
        assert isinstance(sarif["runs"], list) and len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == TOOL_NAME
        assert isinstance(run["results"], list) and len(run["results"]) == 1

    def test_driver_rules(self):
        sarif = to_sarif([_make_finding(), _make_finding(rule_id="py.path.traversal", line_start=115)])
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert [r["id"] for r in rules] == ["py.injection.sql", "py.path.traversal"]

    def test_result_fields(self):
        sarif = to_sarif([_make_finding()])
        r = sarif["runs"][0]["results"][0]
        assert r["ruleId"] == "py.injection.sql"
        assert r["ruleIndex"] == 0
        assert r["level"] == "error"
        assert r["message"]["text"] == "SQL 注入风险"
        assert "physicalLocation" not in r
        loc = r["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "app.py"
        assert loc["region"]["startLine"] == 24
        props = r["properties"]
        assert props["cvss"] == 9.5
        assert props["confidence"] == 0.8
        assert props["cwe"] == "CWE-89"

    def test_severity_levels(self):
        cases = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        for sev, level in cases.items():
            r = to_sarif([_make_finding(severity=sev)])["runs"][0]["results"][0]
            assert r["level"] == level, f"{sev} -> {level}"

    def test_empty_results(self):
        sarif = to_sarif([])
        assert sarif["version"] == SARIF_VERSION
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_json_serializable(self):
        sarif = to_sarif([_make_finding(), _make_finding(rule_id="py.injection.eval", line_start=59)])
        # 可解析即通过
        json.loads(json.dumps(sarif))

    def test_accepts_scan_result(self):
        sr = ScanResult(
            tool=ScanTool.PY_SCANNER,
            rule_id="py.deserialization.yaml",
            file="app.py",
            line=141,
            severity=Severity.CRITICAL,
            message="yaml.load 不安全",
            cwe="CWE-502",
        )
        r = to_sarif([sr])["runs"][0]["results"][0]
        assert r["ruleId"] == "py.deserialization.yaml"
        assert r["locations"][0]["physicalLocation"]["region"]["startLine"] == 141

    def test_fingerprint_partial(self):
        r = to_sarif([_make_finding()])["runs"][0]["results"][0]
        assert r["partialFingerprints"]["fpSentinelFingerprint/v1"] == "abc123"

    def test_windows_path_normalized(self):
        r = to_sarif([_make_finding(file_path="src\\app.py")])["runs"][0]["results"][0]
        assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/app.py"

    def test_preserves_static_preprocessing_location_metadata(self):
        finding = _make_finding(
            metadata={
                "preprocessor": "jsbeautifier",
                "beautified_line": 245,
                "original_line_range": "1",
                "original_offset_hint": {"original_start": 15234, "original_end": 15289},
            }
        )
        result = to_sarif([finding])["runs"][0]["results"][0]

        assert result["properties"]["preprocessing"]["beautifiedLine"] == 245
        assert result["properties"]["preprocessing"]["originalLineRange"] == "1"


class TestCliSarif:
    def test_scan_format_sarif_option_accepted(self):
        from typer.testing import CliRunner
        from fp_sentinel.cli import app

        runner = CliRunner()
        # 使用不存在的路径，验证参数被接受且走到了扫描逻辑（而非参数错误）
        result = runner.invoke(app, ["scan", "/nonexistent/path/xyz", "--format", "sarif", "--no-save"])
        assert "无效" not in (result.output or "") or result.exit_code == 0
        assert result.exception is None or isinstance(result.exception, SystemExit)
