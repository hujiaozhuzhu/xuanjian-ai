"""
JS 扫描器单元测试

覆盖文件遍历、规则匹配、位置定位、结果格式化
"""

import pytest
from pathlib import Path
from fp_sentinel.scanners.js_scanner import JSScanner


class TestJSScanner:
    """JS 扫描器测试"""

    def setup_method(self):
        self.scanner = JSScanner()

    def test_scanner_type(self):
        from fp_sentinel.models import ScanTool
        assert self.scanner.get_tool_type() == ScanTool.JS_SCANNER

    def test_collect_js_files(self, tmp_path):
        """测试JS文件收集"""
        # 创建测试文件
        (tmp_path / "app.js").write_text("const x = 1;")
        (tmp_path / "app.ts").write_text("const x: number = 1;")
        (tmp_path / "app.py").write_text("x = 1")  # 不应收集
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "dep.js").write_text("// skip")  # 不应收集

        files = self.scanner._collect_js_files(tmp_path)
        file_names = [f.name for f in files]

        assert "app.js" in file_names
        assert "app.ts" in file_names
        assert "app.py" not in file_names
        assert "dep.js" not in file_names  # node_modules 被跳过

    @pytest.mark.asyncio
    async def test_scan_vulnerable_file(self, tmp_path):
        """扫描包含漏洞的文件"""
        vuln_code = """
const userInput = req.query.input;
element.innerHTML = userInput;
eval(userInput);
exec("ls " + userInput);
"""
        vuln_file = tmp_path / "vuln.js"
        vuln_file.write_text(vuln_code)

        results = await self.scanner.scan(str(tmp_path))
        rule_ids = {r.rule_id for r in results}

        # 应该检出 innerHTML 和 eval
        assert any("xss" in r or "innerHTML" in r for r in rule_ids)
        assert any("eval" in r or "injection" in r for r in rule_ids)

    @pytest.mark.asyncio
    async def test_scan_safe_file(self, tmp_path):
        """扫描安全文件"""
        safe_code = """
element.textContent = userInput;
const data = JSON.parse(userInput);
const el = document.createElement("div");
"""
        safe_file = tmp_path / "safe.js"
        safe_file.write_text(safe_code)

        results = await self.scanner.scan(str(tmp_path))
        # 安全代码不应检出或仅检出低危
        high_severity = [r for r in results if r.severity.value in ("CRITICAL", "HIGH")]
        assert len(high_severity) == 0

    @pytest.mark.asyncio
    async def test_scan_empty_dir(self, tmp_path):
        """扫描空目录"""
        results = await self.scanner.scan(str(tmp_path))
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_scan_nonexistent_path(self):
        """扫描不存在的路径"""
        results = await self.scanner.scan("/nonexistent/path")
        assert len(results) == 0

    def test_read_file(self, tmp_path):
        """测试文件读取"""
        test_file = tmp_path / "test.js"
        test_file.write_text("const x = 1;")

        content = self.scanner._read_file(test_file)
        assert content == "const x = 1;"

    def test_read_file_cached(self, tmp_path):
        """测试文件缓存"""
        test_file = tmp_path / "test.js"
        test_file.write_text("const x = 1;")

        content1 = self.scanner._read_file(test_file)
        content2 = self.scanner._read_file(test_file)
        assert content1 == content2

    def test_match_file_pattern(self):
        """测试文件模式匹配"""
        assert self.scanner._match_file_pattern("test.js", "*.js")
        assert self.scanner._match_file_pattern("app.test.js", "*test*")
        assert not self.scanner._match_file_pattern("app.py", "*.js")

    def test_calculate_entropy(self):
        """测试信息熵计算"""
        # 高熵字符串（随机）
        high_entropy = self.scanner._calculate_entropy("aB3dEf7hI9kLmNoP")
        # 低熵字符串（重复）
        low_entropy = self.scanner._calculate_entropy("aaaaaaaaaa")
        assert high_entropy > low_entropy

    def test_check_false_positive_indicators(self):
        """测试误报指标检查"""
        assert self.scanner._check_false_positive_indicators(
            'element.innerHTML = DOMPurify.sanitize(input)',
            ["DOMPurify", "sanitize"]
        )
        assert not self.scanner._check_false_positive_indicators(
            'element.innerHTML = userInput',
            ["DOMPurify", "sanitize"]
        )
