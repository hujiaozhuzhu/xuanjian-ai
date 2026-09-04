"""
Semgrep 扫描器测试
"""

from unittest.mock import patch

from fp_sentinel.scanners.semgrep_scanner import SemgrepScanner
from fp_sentinel.models import ScanTool


class TestSemgrepScanner:
    """Semgrep扫描器测试"""

    def test_create_scanner(self):
        scanner = SemgrepScanner()
        assert scanner is not None

    def test_scanner_type(self):
        scanner = SemgrepScanner()
        assert scanner.get_tool_type() == ScanTool.SEMGREP

    def test_missing_semgrep_is_reported_without_raising(self):
        with patch("fp_sentinel.scanners.semgrep_scanner.shutil.which", return_value=None):
            scanner = SemgrepScanner()

        assert scanner.available is False
        assert "fp-sentinel[scanners]" in scanner.unavailable_reason

    def test_scanner_default_config(self):
        scanner = SemgrepScanner()
        assert scanner.timeout == 300
        assert scanner.max_memory == 512
        assert scanner.jobs == 2

    def test_scanner_custom_config(self):
        config = {"timeout": 600, "max_memory": 1024, "jobs": 4}
        scanner = SemgrepScanner(config)
        assert scanner.timeout == 600
        assert scanner.max_memory == 1024
        assert scanner.jobs == 4

    def test_build_command_basic(self):
        scanner = SemgrepScanner()
        cmd = scanner._build_command("/tmp/test", "javascript", None, None)
        assert "semgrep" in cmd[0]
        assert "--json" in cmd

    def test_build_command_with_rulesets(self):
        scanner = SemgrepScanner()
        cmd = scanner._build_command("/tmp/test", "javascript", ["p/javascript"], None)
        assert "--config" in cmd
        assert "p/javascript" in cmd

    def test_build_command_with_config_files(self):
        scanner = SemgrepScanner()
        cmd = scanner._build_command("/tmp/test", "javascript", None, ["/tmp/rules.yaml"])
        assert "--config" in cmd
        assert "/tmp/rules.yaml" in cmd

    def test_build_command_java(self):
        scanner = SemgrepScanner()
        cmd = scanner._build_command("/tmp/test", "java", None, None)
        assert "semgrep" in cmd[0]
        assert "p/java" in cmd

    def test_build_command_javascript_uses_javascript_rules(self):
        scanner = SemgrepScanner()
        cmd = scanner._build_command("/tmp/test", "javascript", None, None)
        assert "p/javascript" in cmd
        assert "p/python" not in cmd

    def test_generate_id(self):
        scanner = SemgrepScanner()
        id1 = scanner._generate_id("semgrep", "js.xss.innerhtml", "app.js", 10)
        assert isinstance(id1, str)
        assert len(id1) > 0

    def test_generate_id_deterministic(self):
        scanner = SemgrepScanner()
        id1 = scanner._generate_id("semgrep", "js.xss.innerhtml", "app.js", 10)
        id2 = scanner._generate_id("semgrep", "js.xss.innerhtml", "app.js", 10)
        assert id1 == id2
