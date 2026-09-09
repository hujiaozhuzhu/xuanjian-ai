"""
R1-Fix 回归测试: 攻防报告反序列化知识库增强

验证:
1. 细分反序列化类型的攻防思路可被正确检索
2. _look_up_thinking 优先匹配更具体的键
3. _look_up_limitation 优先匹配更具体的键
4. 反序列化报告端到端生成包含 PoC 内容
"""


class TestAttackThinkingDB:
    """攻防思路知识库细分类测试"""

    def test_deser_java_native_thinking(self):
        from fp_sentinel.reporting.attack_report import _look_up_thinking

        entry = _look_up_thinking("java-objectInputStream-readObject")
        assert entry, "应检索到 Java 原生反序列化攻防思路"
        assert "ObjectInputStream.readObject()" in entry.get("attack_path", "")

    def test_deser_java_fastjson_thinking(self):
        from fp_sentinel.reporting.attack_report import _look_up_thinking

        entry = _look_up_thinking("java-fastjson-parseObject")
        assert entry, "应检索到 Fastjson 反序列化攻防思路"
        assert "@type" in entry.get("attack_path", "")

    def test_deser_java_shiro_thinking(self):
        from fp_sentinel.reporting.attack_report import _look_up_thinking

        entry = _look_up_thinking("java-shiro-default-key")
        assert entry, "应检索到 Shiro 反序列化攻防思路"
        assert "kPH+bIxk5D2deZiIxcaaaA==" in entry.get("attack_path", "")

    def test_deser_java_jackson_thinking(self):
        from fp_sentinel.reporting.attack_report import _look_up_thinking

        entry = _look_up_thinking("java-jackson-enableDefaultTyping")
        assert entry, "应检索到 Jackson 反序列化攻防思路"
        assert "enableDefaultTyping" in entry.get("attack_path", "")

    def test_deser_php_pop_thinking(self):
        from fp_sentinel.reporting.attack_report import _look_up_thinking

        entry = _look_up_thinking("php-unserialize-user-input")
        assert entry, "应检索到 PHP POP 链反序列化攻防思路"
        assert "unserialize" in entry.get("attack_path", "")

    def test_deser_python_pickle_thinking(self):
        from fp_sentinel.reporting.attack_report import _look_up_thinking

        entry = _look_up_thinking("python-pickle-loads-untrusted")
        assert entry, "应检索到 Python pickle 反序列化攻防思路"
        assert "__reduce__" in entry.get("attack_path", "")

    def test_priority_longer_key(self):
        """优先匹配更具体的键"""
        from fp_sentinel.reporting.attack_report import _look_up_thinking

        # deser-java-native (长键) 应优先于 deser (短键)
        entry = _look_up_thinking("deser-java-native")
        assert entry["impact"].endswith("持久化后门"), (
            f"应匹配到具体的 Java Native 反序列化条目，实际: {entry}"
        )


class TestLimitationDB:
    """利用限制/防御绕过知识库测试"""

    def test_deser_java_native_limitation(self):
        from fp_sentinel.reporting.attack_report import _look_up_limitation

        entry = _look_up_limitation("java-objectInputStream-readObject")
        assert entry, "应检索到 Java 原生反序列化防御限制"
        assert "ObjectInputFilter" in entry.get("fix", "")

    def test_deser_php_phar_limitation(self):
        from fp_sentinel.reporting.attack_report import _look_up_limitation

        entry = _look_up_limitation("php-phar-metadata-deserialization")
        assert entry, "应检索到 Phar 反序列化防御限制"
        assert "phar.readonly" in entry.get("fix", "")


class TestEndToEndAttackReport:
    """端到端报告生成测试"""

    def test_report_contains_deser_content(self):
        from fp_sentinel.attack.chain_orchestrator import AttackChainReport
        from fp_sentinel.attack.exploitability import assess
        from fp_sentinel.attack.poc_templates import generate_poc
        from fp_sentinel.attack.target_validator import VerifyResult, VerifyStatus
        from fp_sentinel.models import Finding, Severity
        from fp_sentinel.reporting.attack_report import generate_attack_report

        findings = [
            Finding(
                scanner="semgrep",
                rule_id="java-objectInputStream-readObject",
                severity=Severity.HIGH,
                file_path="Vuln1NativeDeserializationController.java",
                line_start=36,
                code_snippet="@RequestBody String data\nbyte[] bytes = Base64.getDecoder().decode(data);",
            ),
            Finding(
                scanner="semgrep",
                rule_id="php-unserialize-user-input",
                severity=Severity.CRITICAL,
                file_path="vuln5.php",
                line_start=67,
                code_snippet="$obj = unserialize(base64_decode($_POST['data']));",
            ),
        ]

        chain_report = AttackChainReport(
            project="test-deserialization-lab",
            paths=[],
            single_points=[],
        )

        verify_results = [
            VerifyResult(status=VerifyStatus.SIMULATED, method="pattern_match", evidence="test")
            for _ in findings
        ]
        exploit_results = [assess(f) for f in findings]

        poc_map = {
            "deser-java-native": generate_poc("deser-java-native"),
            "deser-php-pop": generate_poc("deser-php-pop"),
        }

        report = generate_attack_report(
            project="test-deserialization-lab",
            findings=findings,
            chain_report=chain_report,
            verify_results=verify_results,
            exploit_results=exploit_results,
            poc_map=poc_map,
            generated_at="2026-09-08 00:00:00 UTC",
        )

        assert report, "报告应生成"
        assert "ysoserial" in report, "报告应引用 ysoserial"
        assert "ObjectInputStream" in report, "报告应提及 ObjectInputStream"
        assert "POP" in report, "报告应提及 POP 链"
        assert "⑩ 安全声明" in report, "报告应包含安全声明章节"
        # R1-Fix: 攻防思路应包含细分类型内容
        assert "CommonsCollections" in report or "gadget" in report, "攻防思路应提及 gadget chain"
        assert "ObjectInputFilter" in report or "白名单" in report, "修复建议应提及 ObjectInputFilter"
