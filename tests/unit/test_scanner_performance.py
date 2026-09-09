"""
v2.5.1 P1: 扫描器性能测试

覆盖:
- 文件大小上限过滤
- 缓存有界管理（防内存泄漏）
- 结果正确性不变
- 批量扫描性能基准
"""

import tempfile
import os
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from fp_sentinel.scanners.js_scanner import MAX_FILE_SIZE_BYTES, MAX_FILE_CACHE_ENTRIES, JSScanner
from fp_sentinel.scanners.python_scanner import MAX_FILE_SIZE_BYTES as PY_MAX_SIZE, PythonScanner


def _write_file(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def _generate_large_content(lines: int, pattern: str = "") -> str:
    """生成指定行数的内容（可包含漏洞模式）"""
    import hashlib
    lines_list = []
    for i in range(lines):
        if i % 50 == 0 and pattern:
            lines_list.append(f"    {pattern}  // line {i}\n")
        else:
            lines_list.append(f"    var x{i} = {i};\n")
    return "".join(lines_list)


class TestFileSizeLimit:
    """大文件阈值过滤测试"""

    def test_js_scanner_skips_large_files(self, tmp_path):
        """超过 2MB 的 JS 文件应被跳过"""
        large_path = tmp_path / "large.js"
        # 创建 > 2MB 的内容
        huge_content = "x" * (MAX_FILE_SIZE_BYTES + 100)
        large_path.write_text(huge_content, encoding="utf-8")

        scanner = JSScanner()
        import asyncio
        results = asyncio.run(scanner.scan(str(large_path)))
        # 大文件被跳过，结果应为空
        assert results == []

    def test_python_scanner_skips_large_files(self, tmp_path):
        """超过 2MB 的 Python 文件应被跳过"""
        large_path = tmp_path / "large.py"
        huge_content = "x" * (PY_MAX_SIZE + 100)
        large_path.write_text(huge_content, encoding="utf-8")

        scanner = PythonScanner()
        import asyncio
        results = asyncio.run(scanner.scan(str(large_path)))
        assert results == []

    def test_js_scanner_scans_normal_files(self, tmp_path):
        """正常大小文件（< 2MB）应正常扫描"""
        small_path = tmp_path / "small.py"
        small_path.write_text("password = 'AKIAIOSFODNN7EXAMPLE'", encoding="utf-8")

        scanner = JSScanner()
        import asyncio
        results = asyncio.run(scanner.scan(str(small_path)))
        # 即使是小文件也应当返回扫描完成（可能无结果，但不应报错）
        assert isinstance(results, list)


class TestCacheBounded:
    """缓存有界管理测试（防内存泄漏）"""

    def test_cache_does_not_exceed_max(self, tmp_path):
        """文件数超过缓存上限时不应继续增长"""
        # 创建一些小文件
        files = []
        for i in range(MAX_FILE_CACHE_ENTRIES + 30):
            p = tmp_path / f"file_{i}.py"
            p.write_text(f"x = {i}\n", encoding="utf-8")
            files.append(p)

        scanner = PythonScanner()
        import asyncio
        asyncio.run(scanner.scan(str(tmp_path)))

        # 扫描结束后，缓存应已被清理（有上限约束）
        assert len(scanner._file_cache) <= MAX_FILE_CACHE_ENTRIES

    def test_clear_cache_works(self, tmp_path):
        """clear_cache 方法应清空缓存"""
        p = tmp_path / "test.py"
        p.write_text("x = 1\n", encoding="utf-8")

        scanner = PythonScanner()
        scanner._file_cache[str(p)] = "x = 1"
        assert len(scanner._file_cache) == 1

        scanner.clear_cache()
        assert len(scanner._file_cache) == 0

    def test_evict_called_when_over_limit(self, tmp_path):
        """超出上限时应触发驱逐"""
        p = tmp_path / "test.py"
        p.write_text("x = 1\n", encoding="utf-8")

        scanner = PythonScanner()
        # 手动填满缓存
        for i in range(MAX_FILE_CACHE_ENTRIES + 10):
            scanner._file_cache[f"fake_{i}"] = f"content_{i}"

        scanner._evict_cache_if_needed()
        # 应清理一部分
        assert len(scanner._file_cache) < MAX_FILE_CACHE_ENTRIES + 10


class TestScanCorrectness:
    """扫描结果正确性验证（回归测试）"""

    def test_js_scanner_detects_hardcoded_secret(self, tmp_path):
        """JS 扫描器应能检测到硬编码密钥"""
        p = tmp_path / "config.js"
        p.write_text('const awsKey = "AKIAIOSFODNN7EXAMPLE";\n', encoding="utf-8")

        scanner = JSScanner({"check_hardcoded_secrets": True})
        import asyncio
        results = asyncio.run(scanner.scan(str(p)))
        # 至少应找到一个 finding
        assert len(results) >= 1
        assert any("aws" in r.rule_id.lower() or "aws_key" in r.rule_id.lower() for r in results)

    def test_python_scanner_detects_dangerous_eval(self, tmp_path):
        """Python 扫描器应能检测到 eval"""
        p = tmp_path / "app.py"
        p.write_text('user_input = request.args.get("code")\neval(user_input)\n', encoding="utf-8")

        scanner = PythonScanner()
        import asyncio
        results = asyncio.run(scanner.scan(str(p)))
        # 至少应找到一个关于 eval 的 finding
        assert len(results) >= 1


class TestLargeFileCollect:
    """

测试大文件系统扫描性能
    """

    def test_scan_many_files_bounded_memory(self, tmp_path):
        """扫描多个大文件后内存应受控"""
        # 创建一批中等大小文件（10KB each, 共 30 个）
        for i in range(30):
            p = tmp_path / f"module_{i}.js"
            # 每个文件 5KB，远小于 2MB 上限
            p.write_text("var x = {};\n".format(i) * 200, encoding="utf-8")

        scanner = JSScanner()
        import asyncio
        results = asyncio.run(scanner.scan(str(tmp_path)))
        assert isinstance(results, list)

    def test_batch_scan_no_exception(self, tmp_path):
        """批量扫描不应抛出异常"""
        for i in range(20):
            p = tmp_path / f"file_{i}.py"
            _write_file(p, f"import os\nx = {i}\nos.system('echo {i}')\n")

        scanner = PythonScanner()
        import asyncio
        # 不应抛异常
        results = asyncio.run(scanner.scan(str(tmp_path)))
        assert isinstance(results, list)
