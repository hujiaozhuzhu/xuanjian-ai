"""
集成测试: 红队生成 → 扫描验证 → 收敛判定
"""

import pytest
import asyncio
from fp_sentinel.redteam.generator import RedTeamGenerator
from fp_sentinel.redteam.adversarial_loop import AdversarialLoop, ScanSimulator
from fp_sentinel.scanners.js_scanner import JSScanner


class TestRedTeamIntegration:
    """红队集成测试"""

    @pytest.mark.asyncio
    async def test_generate_and_evaluate(self):
        """生成绕过用例 → 评估检出"""
        generator = RedTeamGenerator()

        # 生成绕过用例
        result = await generator.generate_bypasses(
            rule_id="js.injection.eval",
            description="eval() 执行任意代码",
            pattern=r"\beval\s*\(",
            count=10,
        )
        assert result.total_cases == 10

        # 评估
        simulator = ScanSimulator()
        eval_result = await simulator.evaluate_cases("js.injection.eval", result.cases)
        assert eval_result["total"] == 10
        assert eval_result["detected"] + eval_result["missed"] == 10

    @pytest.mark.asyncio
    async def test_adversarial_loop_convergence(self):
        """对抗循环收敛测试"""
        loop = AdversarialLoop()

        result = await loop.run(
            rule_id="js.injection.eval",
            description="eval() 执行任意代码",
            pattern=r"\beval\s*\(",
            count_per_round=5,
        )

        assert result.total_rounds >= 1
        assert result.final_detection_rate >= 0
        assert len(result.rounds) >= 1

    @pytest.mark.asyncio
    async def test_scan_js_vuln_app(self, tmp_path):
        """扫描JS靶场应用"""
        # 创建简化版靶场
        vuln_code = """
const userInput = req.query.input;
element.innerHTML = userInput;
eval(userInput);
exec("ls " + userInput);
"""
        vuln_file = tmp_path / "app.js"
        vuln_file.write_text(vuln_code)

        scanner = JSScanner()
        findings = await scanner.scan(str(tmp_path))

        rule_ids = {f.rule_id for f in findings}
        # 应该检出多种漏洞
        assert len(rule_ids) >= 2
