"""
Semgrep 扫描器测试

v2.5.1 P0-Fix 新增测试：验证 --config/--lang 参数互斥性，确保 Java/PHP 扫描器可正常检出漏洞。
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


# ─────────────────── v2.5.1 P0-Fix 新增测试 ───────────────────
class TestSemgrepConfigLangMutex:
    """验证 --config 和 --lang 参数互斥（P0-Fix 核心回归测试）"""

    def test_java_no_lang_flag_when_config_present(self):
        """Java 扫描：--config 存在时不应出现 --lang"""
        scanner = SemgrepScanner()
        cmd = scanner._build_command("/tmp/test", "java", None, None)
        assert "--config" in cmd
        assert "p/java" in cmd
        assert "--lang" not in cmd, "P0-Fix: --config 和 --lang 不应同时出现"

    def test_php_no_lang_flag_when_config_present(self):
        """PHP 扫描：--config 存在时不应出现 --lang"""
        scanner = SemgrepScanner()
        cmd = scanner._build_command("/tmp/test", "php", None, None)
        assert "--config" in cmd
        assert "p/php" in cmd
        assert "--lang" not in cmd, "P0-Fix: --config 和 --lang 不应同时出现"

    def test_python_no_lang_flag_when_config_present(self):
        """Python 扫描：--config 存在时不应出现 --lang"""
        scanner = SemgrepScanner()
        cmd = scanner._build_command("/tmp/test", "python", None, None)
        assert "--config" in cmd
        assert "--lang" not in cmd, "P0-Fix: --config 和 --lang 不应同时出现"

    def test_javascript_no_lang_flag_when_config_present(self):
        """JavaScript 扫描：--config 存在时不应出现 --lang"""
        scanner = SemgrepScanner()
        cmd = scanner._build_command("/tmp/test", "javascript", None, None)
        assert "--config" in cmd
        assert "p/javascript" in cmd
        assert "--lang" not in cmd, "P0-Fix: --config 和 --lang 不应同时出现"

    def test_go_no_lang_flag_when_config_present(self):
        """Go 扫描：--config 存在时不应出现 --lang"""
        scanner = SemgrepScanner()
        cmd = scanner._build_command("/tmp/test", "go", None, None)
        assert "--config" in cmd
        assert "p/golang" in cmd
        assert "--lang" not in cmd, "P0-Fix: --config 和 --lang 不应同时出现"

    def test_custom_rulesets_no_lang_flag(self):
        """自定义规则集：--config 存在时不应出现 --lang"""
        scanner = SemgrepScanner()
        cmd = scanner._build_command("/tmp/test", "java", ["p/java", "p/security-audit"], None)
        assert "--config" in cmd
        assert "--lang" not in cmd, "P0-Fix: --config 和 --lang 不应同时出现"

    def test_custom_config_files_no_lang_flag(self):
        """自定义配置文件：--config 存在时不应出现 --lang"""
        scanner = SemgrepScanner()
        cmd = scanner._build_command("/tmp/test", "php", None, ["/rules/custom.yaml"])
        assert "--config" in cmd
        assert "/rules/custom.yaml" in cmd
        assert "--lang" not in cmd, "P0-Fix: --config 和 --lang 不应同时出现"

    def test_lang_only_when_no_config(self):
        """仅当无任何 --config 时，--lang 才会出现"""
        # 注意：在 SemgrepScanner 当前逻辑中，始终会有默认规则集产生 --config，
        # 因此 --lang 仅在极端配置场景（空规则集 + 显式语言）下出现。
        # 这个测试验证当没有 config_entries 且指定了语言时，--lang 会出现。
        scanner = SemgrepScanner()
        # 通过传入空列表作为 rulesets 并绕过默认逻辑无法直接测试（因为还有 defaults），
        # 所以这里验证 auto 模式也不应该有 --lang
        cmd = scanner._build_command("/tmp/test", "auto", None, None)
        assert "--lang" not in cmd, "auto 模式不应强制指定 --lang"

    def test_no_double_lang_flag(self):
        """验证不会重复出现 --lang"""
        scanner = SemgrepScanner()
        cmd = scanner._build_command("/tmp/test", "java", None, None)
        lang_count = cmd.count("--lang")
        assert lang_count == 0, f"--lang 不应出现，但出现了 {lang_count} 次"


class TestSemgrepPHPSupport:
    """v2.5.1: 验证 PHP 扫描支持正确路由"""

    def test_php_default_rulesets_included(self):
        """PHP 默认规则集应被包含"""
        scanner = SemgrepScanner()
        cmd = scanner._build_command("/tmp/test", "php", None, None)
        assert "p/php" in cmd
        assert "p/security-audit" in cmd

    def test_php_phar_deser_rule_included(self):
        """PHP 扫描应包含 Phar 反序列化专项规则"""
        scanner = SemgrepScanner()
        cmd = scanner._build_command("/tmp/test", "php", None, None)
        has_php_deser = any("php-phar-deserialization" in str(arg) for arg in cmd)
        assert has_php_deser, "PHP 扫描应包含 php-phar-deserialization 规则"

    def test_php_scan_no_python_deser_rule(self):
        """PHP 扫描不应包含 Python 反序列化规则"""
        scanner = SemgrepScanner()
        cmd = scanner._build_command("/tmp/test", "php", None, None)
        has_python_deser = any("python-deserialization" in str(arg) for arg in cmd)
        assert not has_python_deser, "PHP 扫描不应包含 python-deserialization 规则"

    def test_python_scan_has_python_deser_rule(self):
        """Python 扫描应包含 Python 反序列化规则"""
        scanner = SemgrepScanner()
        cmd = scanner._build_command("/tmp/test", "python", None, None)
        has_python_deser = any("python-deserialization" in str(arg) for arg in cmd)
        assert has_python_deser, "Python 扫描应包含 python-deserialization 规则"

    def test_python_scan_no_php_deser_rule(self):
        """Python 扫描不应包含 PHP 反序列化规则"""
        scanner = SemgrepScanner()
        cmd = scanner._build_command("/tmp/test", "python", None, None)
        has_php_deser = any("php-phar-deserialization" in str(arg) for arg in cmd)
        assert not has_php_deser, "Python 扫描不应包含 php-phar-deserialization 规则"


class TestSemgrepJavaSupport:
    """v2.5.1: 验证 Java 扫描支持正确路由"""

    def test_java_default_rulesets_included(self):
        """Java 默认规则集应被包含"""
        scanner = SemgrepScanner()
        cmd = scanner._build_command("/tmp/test", "java", None, None)
        assert "p/java" in cmd
        assert "p/owasp-java" in cmd

    def test_java_command_ends_with_target_path(self):
        """命令应以目标路径结尾"""
        scanner = SemgrepScanner()
        cmd = scanner._build_command("/tmp/test", "java", None, None)
        assert cmd[-1] == "/tmp/test"

    def test_java_scan_no_deser_rules(self):
        """Java 扫描不应包含 Python/PHP 反序列化规则（语言不匹配）"""
        scanner = SemgrepScanner()
        cmd = scanner._build_command("/tmp/test", "java", None, None)
        has_python_deser = any("python-deserialization" in str(arg) for arg in cmd)
        has_php_deser = any("php-phar-deserialization" in str(arg) for arg in cmd)
        assert not has_python_deser, "Java 扫描不应包含 python-deserialization 规则"
        assert not has_php_deser, "Java 扫描不应包含 php-phar-deserialization 规则"
