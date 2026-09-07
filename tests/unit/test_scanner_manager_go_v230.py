"""
玄鉴 v2.3.0 ScannerManager Go 支持单元测试

覆盖:
- C1: Go 语言自动检测 (go.mod, main.go)
- C2: GoScanner 注册和选择
- C3: ScannerManager 对 Go 项目的端到端扫描
- C4: 不影响其他语言检测
"""

import asyncio
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from fp_sentinel.scanners.manager import ScannerManager
from fp_sentinel.models import ScanTool


class TestGoLanguageDetection:
    """Go 语言自动检测测试"""

    def setup_method(self):
        self.manager = ScannerManager()

    def test_detect_go_by_go_mod(self):
        """go.mod 文件检测为 Go 语言"""
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "go.mod").write_text("module example.com/app\ngo 1.21\n")
            assert self.manager._detect_language(tmp) == "go"

    def test_detect_go_single_file(self):
        """单个 .go 文件检测"""
        with tempfile.TemporaryDirectory() as tmp:
            go_file = Path(tmp, "main.go")
            go_file.write_text("package main\nfunc main() {}\n")
            assert self.manager._detect_language(str(go_file)) == "go"

    def test_detect_go_by_extension_count(self):
        """按扩展名统计检测 Go 项目"""
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "main.go").write_text("package main\n")
            Path(tmp, "utils.go").write_text("package main\n")
            assert self.manager._detect_language(tmp) == "go"


class TestGoScannerSelection:
    """Go 扫描器选择测试"""

    def setup_method(self):
        self.manager = ScannerManager()

    def test_go_selects_semgrep(self):
        """Go 语言应选择 Semgrep"""
        scanners = self.manager._select_scanners("go")
        assert ScanTool.SEMGREP in scanners

    def test_go_selects_go_scanner(self):
        """Go 语言应选择 GoScanner"""
        scanners = self.manager._select_scanners("go")
        assert ScanTool.GO_SCANNER in scanners

    def test_go_scanner_in_available_scanners(self):
        """GoScanner 应在可用扫描器列表中"""
        available = self.manager.get_available_scanners()
        assert "go_scanner" in available

    def test_java_scanners_unaffected(self):
        """Java 扫描器不受 Go 变更影响"""
        scanners = self.manager._select_scanners("java")
        assert ScanTool.SEMGREP in scanners
        assert ScanTool.FINDSECBUGS in scanners

    def test_python_scanners_unaffected(self):
        """Python 扫描器不受 Go 变更影响"""
        scanners = self.manager._select_scanners("python")
        assert ScanTool.SEMGREP in scanners
        assert ScanTool.BANDIT in scanners

    def test_js_scanners_unaffected(self):
        """JS 扫描器不受 Go 变更影响"""
        scanners = self.manager._select_scanners("javascript")
        assert ScanTool.SEMGREP in scanners


class TestScannerManagerGoConfig:
    """扫描器配置测试"""

    def test_go_scanner_enabled_by_default(self):
        """Go Scanner 默认启用"""
        manager = ScannerManager()
        assert ScanTool.GO_SCANNER in manager.scanners

    def test_go_scanner_disabled_via_config(self):
        """可通过配置禁用 Go Scanner"""
        manager = ScannerManager({"go_scanner": {"enabled": False}})
        assert ScanTool.GO_SCANNER not in manager.scanners

    def test_scanner_only_config_for_go(self):
        """scanner-only 配置格式支持 Go"""
        manager = ScannerManager({"semgrep": {"enabled": True}, "go_scanner": {"enabled": True}})
        assert ScanTool.GO_SCANNER in manager.scanners

    def test_app_config_shape_for_go(self):
        """应用完整配置格式支持 Go"""
        manager = ScannerManager({
            "scanners": {
                "go_scanner": {"enabled": True, "check_hardcoded_secrets": False}
            }
        })
        assert ScanTool.GO_SCANNER in manager.scanners


class TestGoEndToEndScan:
    """Go 项目端到端扫描测试"""

    def test_scan_detects_language_auto(self):
        """扫描时自动检测 Go 语言"""
        with tempfile.TemporaryDirectory() as tmp:
            go_mod = Path(tmp, "go.mod")
            go_mod.write_text("module test\ngo 1.21\n")
            manager = ScannerManager()
            detected = manager._detect_language(tmp)
            assert detected == "go"

    def test_select_scanners_for_go_project(self):
        """为 Go 项目选择正确的扫描器"""
        manager = ScannerManager()
        scanners = manager._select_scanners("go")
        assert ScanTool.GO_SCANNER in scanners
        assert ScanTool.SEMGREP in scanners

    def test_go_scanner_tool_type(self):
        """GoScanner 返回正确的工具类型"""
        from fp_sentinel.scanners.go_scanner import GoScanner
        scanner = GoScanner()
        assert scanner.get_tool_type() == ScanTool.GO_SCANNER

    def test_scan_go_file_returns_results(self):
        """扫描Go文件应返回结果列表"""
        with tempfile.TemporaryDirectory() as tmp:
            go_file = Path(tmp, "main.go")
            go_file.write_text(
                'package main\n'
                'var apiKey = "AKIAIOSFODNN7EXAMPLE"\n'
                'func main() {}\n',
                encoding="utf-8",
            )
            from fp_sentinel.scanners.go_scanner import GoScanner
            scanner = GoScanner()
            results = asyncio.run(scanner.scan(str(go_file)))
            assert isinstance(results, list)
            assert len(results) >= 1

    def test_scan_go_file_severity_valid(self):
        """扫描结果的严重程度是有效的枚举值"""
        with tempfile.TemporaryDirectory() as tmp:
            go_file = Path(tmp, "main.go")
            go_file.write_text(
                'package main\nimport "os/exec"\n'
                'func run(c string){ exec.Command("sh","-c",c).Run() }\n',
                encoding="utf-8",
            )
            from fp_sentinel.scanners.go_scanner import GoScanner
            scanner = GoScanner()
            results = asyncio.run(scanner.scan(str(go_file)))
            for r in results:
                assert r.severity.value in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


class TestGoModDetectionPriority:
    """go.mod 语言检测优先级测试"""

    def test_go_mod_beats_extension_count(self):
        """go.mod 优先于扩展名统计"""
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "go.mod").write_text("module app\n")
            Path(tmp, "main.py").write_text("print(1)\n")
            manager = ScannerManager()
            assert manager._detect_language(tmp) == "go"

    def test_go_single_file_with_py_around(self):
        """单个Go文件扫描不受其他文件干扰"""
        with tempfile.TemporaryDirectory() as tmp:
            go_file = Path(tmp, "server.go")
            go_file.write_text("package main\nfunc main(){}\n")
            manager = ScannerManager()
            assert manager._detect_language(str(go_file)) == "go"
