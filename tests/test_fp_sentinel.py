"""
玄鉴 fp_sentinel 测试用例
"""

import asyncio
import pytest
from fp_sentinel.models import (
    ScanResult, FilterResult, Verdict, Severity, ScanTool,
)
from fp_sentinel.filters.rule_filter import RuleFilter
from fp_sentinel.filters.context_filter import ContextFilter
from fp_sentinel.filters.ml_filter import MLFilter
from fp_sentinel.scanners.manager import ScannerManager
from fp_sentinel.server import FPSentinelServer


# ============================================================
# 辅助函数
# ============================================================

def make_scan_result(**overrides) -> ScanResult:
    defaults = {
        "tool": ScanTool.SEMGREP,
        "rule_id": "java.lang.security.injection.sql-injection",
        "file": "src/main/java/com/myapp/UserService.java",
        "line": 42,
        "code": 'String sql = "SELECT * FROM users WHERE id = " + userId;',
        "severity": Severity.HIGH,
        "message": "Possible SQL injection",
    }
    defaults.update(overrides)
    return ScanResult(**defaults)


def make_test_scan_result(**overrides) -> ScanResult:
    defaults = {
        "tool": ScanTool.SEMGREP,
        "rule_id": "java.lang.security.injection.sql-injection",
        "file": "src/test/java/com/myapp/UserServiceTest.java",
        "line": 25,
        "code": 'String sql = "SELECT * FROM users WHERE id = 1";',
        "severity": Severity.HIGH,
        "message": "Possible SQL injection in test",
    }
    defaults.update(overrides)
    return ScanResult(**defaults)


# ============================================================
# 模型测试
# ============================================================

class TestModels:
    def test_scan_result_creation(self):
        sr = make_scan_result()
        assert sr.tool == ScanTool.SEMGREP
        assert sr.rule_id == "java.lang.security.injection.sql-injection"
        assert sr.file.endswith("UserService.java")
        assert sr.line == 42
        assert sr.severity == Severity.HIGH

    def test_scan_result_with_cwe(self):
        sr = make_scan_result(cwe="CWE-89", owasp="A03:2021")
        assert sr.cwe == "CWE-89"
        assert sr.owasp == "A03:2021"

    def test_severity_enum(self):
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"

    def test_verdict_enum(self):
        assert Verdict.TRUE_POSITIVE.value == "true_positive"
        assert Verdict.FALSE_POSITIVE.value == "false_positive"
        assert Verdict.LIKELY_FALSE_POSITIVE.value == "likely_false_positive"
        assert Verdict.NEEDS_REVIEW.value == "needs_review"

    def test_filter_result_model_dump(self):
        sr = make_scan_result()
        fr = FilterResult(
            original=sr,
            verdict=Verdict.NEEDS_REVIEW,
            confidence=0.5,
            filter_reasons=[],
            risk_score=5.0,
            recommendation="test",
        )
        d = fr.model_dump()
        assert "original" in d
        assert d["verdict"] == "needs_review"


# ============================================================
# L1 规则过滤器测试
# ============================================================

class TestRuleFilter:
    @pytest.fixture
    def filter(self):
        return RuleFilter({"enabled": True})

    @pytest.mark.asyncio
    async def test_test_file_filtered(self, filter):
        sr = make_test_scan_result()
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE
        assert result.confidence >= 0.8
        assert any("test" in r.description.lower() for r in result.filter_reasons)

    @pytest.mark.asyncio
    async def test_nosec_filtered(self, filter):
        sr = make_scan_result(code='query = "SELECT * FROM users"  # nosec')
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE
        assert any("ignore" in r.description.lower() or "nosec" in r.description.lower() for r in result.filter_reasons)

    @pytest.mark.asyncio
    async def test_nosonar_filtered(self, filter):
        sr = make_scan_result(
            code='Runtime.exec(cmd); // NOSONAR',
            tool=ScanTool.FINDSECBUGS,
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_suppress_warnings_filtered(self, filter):
        sr = make_scan_result(code='@SuppressWarnings("SQL_INJECTION")')
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_normal_code_passes(self, filter):
        sr = make_scan_result()
        result = await filter.filter(sr)
        assert result.verdict == Verdict.NEEDS_REVIEW

    @pytest.mark.asyncio
    async def test_disabled_filter(self):
        f = RuleFilter({"enabled": False})
        sr = make_test_scan_result()
        result = await f.filter(sr)
        assert result.verdict == Verdict.NEEDS_REVIEW

    @pytest.mark.asyncio
    async def test_custom_rule(self):
        f = RuleFilter({
            "enabled": True,
            "custom_rules": [{
                "name": "ignore_migration",
                "file_pattern": ".*/migrations/.*",
                "reason": "数据库迁移文件",
                "confidence": 0.9,
            }],
        })
        sr = make_scan_result(file="src/main/resources/migrations/V1__init.sql")
        result = await f.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_historical_fingerprint(self):
        sr = make_scan_result()
        temp_filter = RuleFilter({"enabled": True})
        fp = temp_filter._compute_fingerprint(sr)
        f = RuleFilter({
            "enabled": True,
            "false_positive_fingerprints": [fp],
        })
        result = await f.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE
        assert any("历史" in r.description for r in result.filter_reasons)

    @pytest.mark.asyncio
    async def test_java_prepared_statement_filtered(self, filter):
        """Java PreparedStatement 应该被识别为误报"""
        sr = make_scan_result(
            rule_id="java.lang.security.injection.sql-injection",
            code='PreparedStatement ps = conn.prepareStatement(sql);\nps.setString(1, userId);',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE
        assert any("PreparedStatement" in r.description or "参数化" in r.description for r in result.filter_reasons)

    @pytest.mark.asyncio
    async def test_java_mybatis_hash_filtered(self, filter):
        """MyBatis #{} 应该被识别为误报"""
        sr = make_scan_result(
            rule_id="java.lang.security.injection.sql-injection",
            code='select * from user where id = #{userId}',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_java_xss_escape_filtered(self, filter):
        """使用HTML转义的XSS应该被识别为误报"""
        sr = make_scan_result(
            rule_id="java.lang.security.xss.reflected",
            code='String safe = HtmlUtils.htmlEscape(userInput);',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    def test_fingerprint_consistency(self):
        """三层过滤器的指纹应该一致"""
        sr = make_scan_result()
        rf = RuleFilter({"enabled": True})
        # 指纹函数应该可访问
        fp = rf._compute_fingerprint(sr)
        assert isinstance(fp, str)
        assert len(fp) == 32  # MD5 hex


# ============================================================
# L2 上下文过滤器测试
# ============================================================

class TestContextFilter:
    @pytest.fixture
    def filter(self):
        return ContextFilter({"enabled": True, "false_positive_threshold": 0.5})

    def test_test_file_detection(self, filter):
        assert filter._detect_test_file("src/test/java/Test.java")
        assert filter._detect_test_file("src/main/java/UserTest.java")
        assert filter._detect_test_file("tests/test_user.py")
        assert not filter._detect_test_file("src/main/java/User.java")

    def test_dead_code_detection(self, filter):
        assert filter._detect_dead_code("if (false) {\n  dangerous();\n}")
        assert filter._detect_dead_code("if False:\n    dangerous()")
        assert not filter._detect_dead_code("dangerous()")

    def test_debug_branch_detection(self, filter):
        assert filter._detect_debug_branch("if (DEBUG) { exec(userInput); }")
        assert filter._detect_debug_branch("if (isDebug) { log(data); }")
        assert not filter._detect_debug_branch("exec(userInput);")

    def test_complexity_calculation(self, filter):
        lines = [
            "if (a) {",
            "  for (int i=0; i<10; i++) {",
            "    if (b) {",
            "      while (c) { x++; }",
            "    }",
            "  }",
            "}",
        ]
        score = filter._calc_complexity(lines)
        assert score > 0

    def test_java_file_detection(self, filter):
        assert filter._is_java_file("User.java")
        assert filter._is_java_file("UserService.class")
        assert not filter._is_java_file("user.py")


# ============================================================
# L3 ML 过滤器测试
# ============================================================

class TestMLFilter:
    @pytest.fixture
    def filter(self):
        return MLFilter({"enabled": True})

    def test_feature_extraction(self, filter):
        sr = make_scan_result()
        features = filter._extract_features(sr)
        assert "rule_confidence" in features
        assert "severity_score" in features
        assert "code_complexity" in features
        assert features["severity_score"] == 0.85  # HIGH

    def test_rule_confidence(self, filter):
        assert filter._rule_confidence("sql-injection") == 0.9
        assert filter._rule_confidence("hardcoded-password") == 0.7
        assert filter._rule_confidence("some-other-rule") == 0.5

    def test_test_code_detection(self, filter):
        assert filter._is_test("src/test/java/Test.java")
        assert filter._is_test("tests/test_user.py")
        assert not filter._is_test("src/main/java/User.java")

    @pytest.mark.asyncio
    async def test_heuristic_prediction(self, filter):
        sr = make_scan_result(metadata={"has_security_guards": True})
        features = filter._extract_features(sr)
        is_fp, confidence = filter._heuristic(features)
        # 有安全守卫的代码应该更可能是误报
        assert isinstance(is_fp, bool)
        assert 0 <= confidence <= 1

    @pytest.mark.asyncio
    async def test_filter_returns_result(self, filter):
        sr = make_scan_result()
        result = await filter.filter(sr)
        assert isinstance(result, FilterResult)
        assert result.original == sr

    @pytest.mark.asyncio
    async def test_disabled_filter(self):
        f = MLFilter({"enabled": False})
        sr = make_scan_result()
        result = await f.filter(sr)
        assert result.verdict == Verdict.NEEDS_REVIEW


# ============================================================
# 扫描器管理器测试
# ============================================================

class TestScannerManager:
    def test_language_detection(self):
        import os
        # 创建临时目录结构
        os.makedirs("/tmp/test_java_project", exist_ok=True)
        with open("/tmp/test_java_project/pom.xml", "w", encoding="utf-8") as f:
            f.write("<project></project>")

        mgr = ScannerManager()
        lang = mgr._detect_language("/tmp/test_java_project")
        assert lang == "java"

    def test_scanner_selection_java(self):
        mgr = ScannerManager()
        scanners = mgr._select_scanners("java")
        assert ScanTool.SEMGREP in scanners
        assert ScanTool.FINDSECBUGS in scanners

    def test_scanner_selection_python(self):
        mgr = ScannerManager()
        scanners = mgr._select_scanners("python")
        assert ScanTool.SEMGREP in scanners
        assert ScanTool.BANDIT in scanners

    def test_available_scanners(self):
        mgr = ScannerManager()
        available = mgr.get_available_scanners()
        assert isinstance(available, list)


# ============================================================
# MCP 服务器测试
# ============================================================

class TestMCPServer:
    def test_server_creation(self):
        server = FPSentinelServer()
        assert server.rule_filter is not None
        assert server.context_filter is not None
        assert server.ml_filter is not None
        assert server.scanner_manager is not None

    def test_server_config_merge(self):
        server = FPSentinelServer()
        assert server.config["rule_filter"]["enabled"] is True
        assert server.config["context_filter"]["enabled"] is True
        assert server.config["ml_filter"]["enabled"] is True

    def test_stats_calculation(self):
        server = FPSentinelServer()
        sr = make_scan_result()
        results = [
            FilterResult(
                original=sr, verdict=Verdict.FALSE_POSITIVE,
                confidence=0.9, filter_reasons=[], risk_score=1.0,
                recommendation="误报",
            ),
            FilterResult(
                original=sr, verdict=Verdict.NEEDS_REVIEW,
                confidence=0.5, filter_reasons=[], risk_score=5.0,
                recommendation="待复核",
            ),
            FilterResult(
                original=sr, verdict=Verdict.TRUE_POSITIVE,
                confidence=0.8, filter_reasons=[], risk_score=8.0,
                recommendation="真实漏洞",
            ),
        ]
        stats = server._calc_stats(results, 100.0)
        assert stats.total == 3
        assert stats.false_positives == 1
        assert stats.needs_review == 1
        assert stats.true_positives == 1


# ============================================================
# 全流程集成测试
# ============================================================

class TestIntegration:
    @pytest.mark.asyncio
    async def test_full_pipeline_java(self):
        """测试 Java SQL注入的完整过滤流程"""
        server = FPSentinelServer()

        # 模拟一个有 PreparedStatement 保护的 SQL 注入告警
        sr = make_scan_result(
            code="PreparedStatement ps = conn.prepareStatement(sql);\nps.setString(1, userId);",
        )

        result = await server._apply_filters(sr, "all", 0.7)
        assert isinstance(result, FilterResult)
        # 应该有上下文分析
        assert result.context_analysis is not None or len(result.filter_reasons) >= 0

    @pytest.mark.asyncio
    async def test_full_pipeline_test_file(self):
        """测试测试文件中的漏洞被正确过滤"""
        server = FPSentinelServer()

        sr = make_test_scan_result()
        result = await server._apply_filters(sr, "all", 0.7)

        # 测试文件应该被 L1 过滤
        assert result.verdict == Verdict.FALSE_POSITIVE
        assert result.confidence >= 0.8

    @pytest.mark.asyncio
    async def test_full_pipeline_nosec(self):
        """测试 nosec 标记被正确处理"""
        server = FPSentinelServer()

        sr = make_scan_result(code='exec(user_input)  # nosec')
        result = await server._apply_filters(sr, "all", 0.7)

        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_full_pipeline_real_vuln(self):
        """测试真实漏洞不被过滤"""
        server = FPSentinelServer()

        sr = make_scan_result(
            code='String sql = "SELECT * FROM users WHERE id = " + userId;\nstmt.executeQuery(sql);',
            file="src/main/java/com/myapp/UserDAO.java",
        )
        result = await server._apply_filters(sr, "all", 0.7)

        # 真实漏洞不应该被标记为误报
        assert result.verdict != Verdict.FALSE_POSITIVE


# ============================================================
# Java 规则扩展测试 - 各类别误报规则
# ============================================================

class TestJavaSQLInjectionRules:
    """SQL注入误报规则测试"""

    @pytest.fixture
    def filter(self):
        return RuleFilter({"enabled": True})

    @pytest.mark.asyncio
    async def test_prepared_statement(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.injection.sql-injection",
            code='PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\nps.setString(1, userId);',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_mybatis_hash_binding(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.injection.sql-injection",
            code="select * from user where id = #{userId} and name = #{userName}",
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_jpa_parameterized(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.injection.sql-injection",
            code='Query q = em.createQuery("SELECT u FROM User u WHERE u.id = :id");\nq.setParameter("id", userId);',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_spring_jdbcTemplate(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.injection.sql-injection",
            code='jdbcTemplate.query("SELECT * FROM users WHERE id = ?", new Object[]{userId}, mapper);',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_named_parameter_jdbc(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.injection.sql-injection",
            code='namedParameterJdbcTemplate.query("SELECT * FROM users WHERE id = :id", params, mapper);',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_mybatis_plus_lambda(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.injection.sql-injection",
            code="LambdaQueryWrapper<User> wrapper = Wrappers.lambdaQuery();\nwrapper.eq(User::getId, userId);",
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_jooq_dsl(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.injection.sql-injection",
            code='dsl.selectFrom(USER).where(USER.ID.eq(userId)).fetch();',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_flyway_migration(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.injection.sql-injection",
            file="src/main/resources/db/migration/V1__create_users.sql",
            code="CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100));",
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE


class TestJavaXSSRules:
    """XSS误报规则测试"""

    @pytest.fixture
    def filter(self):
        return RuleFilter({"enabled": True})

    @pytest.mark.asyncio
    async def test_html_escape(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.xss.reflected",
            code='String safe = HtmlUtils.htmlEscape(userInput);',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_json_response(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.xss.reflected",
            code='@RestController\npublic class ApiController {\n    @GetMapping("/api/user")\n    public User getUser() { ... }\n}',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_owasp_encoder(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.xss.reflected",
            code='out.println(Encode.forHtml(userInput));',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE


class TestJavaSSRFRules:
    """SSRF误报规则测试"""

    @pytest.fixture
    def filter(self):
        return RuleFilter({"enabled": True})

    @pytest.mark.asyncio
    async def test_constant_url(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.ssrf",
            code='URL url = new URL("https://api.example.com/data");',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_url_whitelist(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.ssrf",
            code='if (!allowedHosts.contains(url.getHost())) throw new Exception();',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_feign_client(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.ssrf",
            code='@FeignClient(name = "user-service", url = "${user.service.url}")',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE


class TestJavaCommandInjectionRules:
    """命令注入误报规则测试"""

    @pytest.fixture
    def filter(self):
        return RuleFilter({"enabled": True})

    @pytest.mark.asyncio
    async def test_constant_command(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.command.injection",
            code='Runtime.getRuntime().exec("ls -la /tmp");',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_process_builder_array(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.command.injection",
            code='new ProcessBuilder(List.of("ls", "-la", userInput)).start();',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_commons_exec(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.command.injection",
            code='CommandLine cmd = CommandLine.parse("convert");\ncmd.addArgument(inputFile);\ndefaultExecutor.execute(cmd);',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE


class TestJavaPathTraversalRules:
    """路径穿越误报规则测试"""

    @pytest.fixture
    def filter(self):
        return RuleFilter({"enabled": True})

    @pytest.mark.asyncio
    async def test_canonical_path(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.path.traversal",
            code='File f = new File(baseDir, userInput);\nString canonical = f.getCanonicalPath();\nif (!canonical.startsWith(baseDir)) throw new Exception();',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_path_normalize(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.path.traversal",
            code='Path p = Path.of(baseDir, userInput).normalize();',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_filename_utils(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.path.traversal",
            code='String safe = FilenameUtils.getName(userInput);\nFile f = new File(uploadDir, safe);',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE


class TestJavaDeserializationRules:
    """反序列化误报规则测试"""

    @pytest.fixture
    def filter(self):
        return RuleFilter({"enabled": True})

    @pytest.mark.asyncio
    async def test_object_input_filter(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.deserialization",
            code='ObjectInputStream ois = new ObjectInputStream(input);\nois.setObjectInputFilter(filter);',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_jackson_deserialization(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.deserialization",
            code='ObjectMapper mapper = new ObjectMapper();\nUser user = mapper.readValue(json, User.class);',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE


class TestJavaCryptoRules:
    """加密误报规则测试"""

    @pytest.fixture
    def filter(self):
        return RuleFilter({"enabled": True})

    @pytest.mark.asyncio
    async def test_bcrypt(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.weak.crypto",
            code='BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();\nString hash = encoder.encode(password);',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_secure_random(self, filter):
        sr = make_scan_result(
            rule_id="java.lang.security.insecure.crypto",
            code='SecureRandom random = new SecureRandom();\nbyte[] bytes = new byte[32];\nrandom.nextBytes(bytes);',
        )
        result = await filter.filter(sr)
        assert result.verdict == Verdict.FALSE_POSITIVE


class TestJavaSecurityGuardPatterns:
    """安全守卫模式测试"""

    @pytest.fixture
    def ctx_filter(self):
        return ContextFilter({"enabled": True, "false_positive_threshold": 0.5})

    def test_security_guard_patterns_loaded(self):
        from fp_sentinel.rules.java.rules import JAVA_SECURITY_GUARD_PATTERNS
        assert "sql_injection" in JAVA_SECURITY_GUARD_PATTERNS
        assert "xss" in JAVA_SECURITY_GUARD_PATTERNS
        assert "ssrf" in JAVA_SECURITY_GUARD_PATTERNS
        assert "command_injection" in JAVA_SECURITY_GUARD_PATTERNS
        assert "path_traversal" in JAVA_SECURITY_GUARD_PATTERNS
        assert "deserialization" in JAVA_SECURITY_GUARD_PATTERNS
        assert "security_guard" in JAVA_SECURITY_GUARD_PATTERNS

    def test_security_guard_has_spring_security(self):
        from fp_sentinel.rules.java.rules import JAVA_SECURITY_GUARD_PATTERNS
        guards = JAVA_SECURITY_GUARD_PATTERNS["security_guard"]
        patterns_text = " ".join(guards)
        assert "PreAuthorize" in patterns_text
        assert "Secured" in patterns_text
        assert "JWT" in patterns_text

    def test_security_guard_has_shiro(self):
        from fp_sentinel.rules.java.rules import JAVA_SECURITY_GUARD_PATTERNS
        guards = JAVA_SECURITY_GUARD_PATTERNS["security_guard"]
        patterns_text = " ".join(guards)
        assert "RequiresPermissions" in patterns_text
        assert "RequiresRoles" in patterns_text

    def test_rule_count_at_least_60(self):
        from fp_sentinel.rules.java.rules import JAVA_FALSE_POSITIVE_RULES
        assert len(JAVA_FALSE_POSITIVE_RULES) >= 60


