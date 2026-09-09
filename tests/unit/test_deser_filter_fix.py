"""
P2-Fix 回归测试: java_deser_jackson 误报修复

验证原则:
1. 使用 ObjectMapper + readValue 但无 enableDefaultTyping → 应被标记为误报
2. 使用 ObjectMapper + enableDefaultTyping → 不应被误报抑制
3. 代码排除模式(code_exclude_pattern)功能正确
"""

import pytest

from fp_sentinel.filters.rule_filter import RuleFilter
from fp_sentinel.models import ScanResult, ScanTool, Severity


def _make_result(code: str, rule_id: str = "java.deserialization.sink") -> ScanResult:
    return ScanResult(
        tool=ScanTool.SEMGREP,
        rule_id=rule_id,
        file="src/main/java/Controller.java",
        line=42,
        code=code,
        severity=Severity.HIGH,
        message="deserialization detected",
    )


class TestCodeExcludePattern:
    """P2-Fix: code_exclude_pattern 字段测试"""

    @pytest.fixture
    def rf(self):
        return RuleFilter({"enabled": True})

    @pytest.mark.asyncio
    async def test_jackson_safe_usage_suppressed(self, rf):
        """纯 ObjectMapper.readValue 无 enableDefaultTyping → 误报"""
        code = "ObjectMapper om = new ObjectMapper(); JsonNode node = om.readValue(data, JsonNode.class);"
        result = _make_result(code)
        fr = await rf.filter(result)
        assert fr.is_false_positive, "纯 ObjectMapper+readValue 应被标记误报"

    @pytest.mark.asyncio
    async def test_jackson_default_typing_not_suppressed(self, rf):
        """ObjectMapper + enableDefaultTyping → 不应被抑制"""
        code = "ObjectMapper om = new ObjectMapper(); om.enableDefaultTyping(); JsonNode node = om.readValue(data, JsonNode.class);"
        result = _make_result(code, rule_id="java.enableDefaultTyping")
        fr = await rf.filter(result)
        assert not fr.is_false_positive, (
            "enableDefaultTyping 存在时不应被 java_deser_jackson 误报规则抑制"
        )

    @pytest.mark.asyncio
    async def test_convert_value_without_default_typing_suppressed(self, rf):
        """convertValue 无 enableDefaultTyping → 误报"""
        code = "MyObj obj = om.convertValue(jsonMap, MyObj.class);"
        result = _make_result(code)
        fr = await rf.filter(result)
        assert fr.is_false_positive, "纯 convertValue 应被标记误报"

    @pytest.mark.asyncio
    async def test_code_exclude_pattern_generic(self):
        """通用 code_exclude_pattern 字段测试"""
        rf_custom = RuleFilter({
            "enabled": True,
            "custom_rules": [{
                "name": "test_exclude_rule",
                "rule_id_pattern": r"test\.sink",
                "code_pattern": r"DangerousSink",
                "code_exclude_pattern": r"SafetyGuard",
                "reason": "有 SafetyGuard 时不标记误报",
                "confidence": 0.8,
            }],
        })

        # 有 DangerousSink 无 SafetyGuard → 标记误报
        code1 = "DangerousSink.process(data);"
        result = _make_result(code1, rule_id="test.sink")
        fr1 = await rf_custom.filter(result)
        assert fr1.is_false_positive, "无 SafetyGuard 时应标记误报"

        # 有 DangerousSink AND SafetyGuard → 不被抑制
        code2 = "SafetyGuard.wrap(DangerousSink.process(data));"
        result2 = _make_result(code2, rule_id="test.sink")
        fr2 = await rf_custom.filter(result2)
        assert not fr2.is_false_positive, "有 SafetyGuard 时不应被抑制"


class TestDeserializationExploitability:
    """利用性评分改进测试: 反序列化用户输入模式检测"""

    def test_php_post_detected_as_input(self):
        from fp_sentinel.attack.exploitability import detect_user_input

        assert detect_user_input("$_POST['data']")
        assert detect_user_input("$_GET['id']")
        assert detect_user_input("$_COOKIE['session']")

    def test_java_requestbody_detected_as_input(self):
        from fp_sentinel.attack.exploitability import detect_user_input

        assert detect_user_input("@RequestBody String data")
        assert detect_user_input("@CookieValue String user")

    def test_python_request_data_detected(self):
        from fp_sentinel.attack.exploitability import detect_user_input

        assert detect_user_input("request.data")
        assert detect_user_input("request.get_data()")

    def test_php_unserialize_reachable(self):
        from fp_sentinel.attack.exploitability import assess, ReachabilityLevel
        from fp_sentinel.models import Finding, Severity

        finding = Finding(
            scanner="semgrep",
            rule_id="php-unserialize-user-input",
            severity=Severity.HIGH,
            file_path="vuln5.php",
            line_start=67,
            code_snippet="$obj = unserialize(base64_decode($_POST['data']));",
        )
        result = assess(finding, network_exposure="public")
        assert result.reachability == ReachabilityLevel.REACHABLE.value
        assert result.has_user_input is True
        assert result.probability > 0

    def test_java_readobject_reachable(self):
        from fp_sentinel.attack.exploitability import assess, ReachabilityLevel
        from fp_sentinel.models import Finding, Severity

        finding = Finding(
            scanner="semgrep",
            rule_id="java-objectInputStream-readObject",
            severity=Severity.HIGH,
            file_path="Vuln1Controller.java",
            line_start=36,
            code_snippet="@RequestBody String data",
        )
        result = assess(finding, network_exposure="public")
        assert result.reachability == ReachabilityLevel.REACHABLE.value
        assert result.has_user_input is True
