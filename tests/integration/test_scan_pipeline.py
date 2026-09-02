"""
集成测试: 扫描 → 降噪 → 报告 完整链路
"""

import pytest
import asyncio
from fp_sentinel.scanners.js_scanner import JSScanner
from fp_sentinel.filters.noise_reducer import NoisePipeline
from fp_sentinel.models import ScanResult, Severity


class TestScanPipeline:
    """扫描流水线集成测试"""

    @pytest.mark.asyncio
    async def test_scan_and_deduplicate(self, tmp_path):
        """扫描 → 降噪 → 去重"""
        # 创建包含漏洞的文件
        vuln_code = """
const userInput = req.query.input;
element.innerHTML = userInput;
eval(userInput);
eval("1+1");
"""
        vuln_file = tmp_path / "vuln.js"
        vuln_file.write_text(vuln_code)

        # 扫描
        scanner = JSScanner()
        findings = await scanner.scan(str(tmp_path))
        assert len(findings) > 0

        # 降噪
        pipeline = NoisePipeline(enable_l1=True, enable_l2=True, enable_l3=True)
        filtered = await pipeline.process(findings)

        # 常量表达式应该被过滤
        code_snippets = [getattr(f, 'code_snippet', '') or getattr(f, 'code', '') for f in filtered]
        # eval("1+1") 应该被L1过滤
        assert not any('eval("1+1")' in c for c in code_snippets)

    @pytest.mark.asyncio
    async def test_scan_safe_file_no_findings(self, tmp_path):
        """扫描安全文件应无高危发现"""
        safe_code = """
element.textContent = userInput;
const data = JSON.parse(userInput);
const el = document.createElement("div");
"""
        safe_file = tmp_path / "safe.js"
        safe_file.write_text(safe_code)

        scanner = JSScanner()
        findings = await scanner.scan(str(tmp_path))

        # 过滤高危
        high_findings = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(high_findings) == 0

    @pytest.mark.asyncio
    async def test_scan_mixed_files(self, tmp_path):
        """扫描混合文件（漏洞+安全）"""
        vuln_file = tmp_path / "vuln.js"
        vuln_file.write_text('eval(userInput);')

        safe_file = tmp_path / "safe.js"
        safe_file.write_text('element.textContent = userInput;')

        scanner = JSScanner()
        findings = await scanner.scan(str(tmp_path))

        # 应该有发现
        assert len(findings) > 0

        # 降噪后应该减少
        pipeline = NoisePipeline()
        filtered = await pipeline.process(findings)
        assert len(filtered) <= len(findings)
