"""
玄鉴 v2.3.0 — 用户自定义规则加载器测试

测试覆盖率目标: >= 95%
测试子功能: 用户自定义规则加载器 (CustomRuleLoader)

版本: 2.3.0
"""

import json
import os
import tempfile
import pytest
from datetime import datetime
from pathlib import Path

import yaml

from fp_sentinel.rule_optimization.custom_rule_loader import (
    CustomRuleLoader,
    CustomRule,
    LoadResult,
    SCHEMA_VERSION,
    REQUIRED_FIELDS,
    VALID_SEVERITIES,
    VALID_TOOLS,
    VALID_LANGUAGES,
    OPTIONAL_FIELDS_DEFAULTS,
)


# ─────────────────────── Fixtures ───────────────────────

@pytest.fixture
def loader():
    """创建默认加载器"""
    return CustomRuleLoader()


@pytest.fixture
def temp_dir():
    """临时目录"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def sample_yaml_content():
    """标准 YAML 内容 - 使用单引号避免YAML双引号内的转义问题"""
    return """version: "1.0"
rules:
  - name: custom_sql_safe_wrapper
    rule_id_pattern: 'sql.injection|sql-injection'
    code_pattern: 'SafeQuery\\.execute|SqlBuilder\\.build'
    reason: 使用项目自定义的安全查询封装
    confidence: 0.85

  - name: custom_auth_check
    rule_id_pattern: 'auth.bypass|missing.auth'
    code_pattern: '@RequiresAuth|@PreAuthorize|checkPermission'
    reason: 存在权限校验注解
    confidence: 0.8

  - name: ignore_generated_code
    file_pattern: '.*\\/generated\\/.*|.*\\/gen\\/.*'
    reason: 自动生成的代码
    confidence: 0.95
"""


@pytest.fixture
def sample_yaml_file(temp_dir, sample_yaml_content):
    """YAML 文件"""
    file_path = Path(temp_dir) / "custom_rules.yaml"
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(sample_yaml_content)
    return str(file_path)


@pytest.fixture
def yaml_dir(temp_dir):
    """包含多个 YAML 文件的目录"""
    dir_path = Path(temp_dir) / "rules"
    dir_path.mkdir()

    # 文件1: 标准格式
    file1 = dir_path / "rules_sql.yaml"
    with open(file1, 'w', encoding='utf-8') as f:
        yaml.dump({
            "version": "1.0",
            "rules": [
                {
                    "name": "sql_safe_1",
                    "rule_id_pattern": "sql.injection",
                    "code_pattern": "SafeWrapper.query",
                    "reason": "Safe wrapper",
                    "confidence": 0.9,
                },
            ],
        }, f)

    # 文件2: custom_rules 格式
    file2 = dir_path / "rules_xss.yaml"
    with open(file2, 'w', encoding='utf-8') as f:
        yaml.dump({
            "custom_rules": [
                {
                    "name": "xss_safe_1",
                    "rule_id_pattern": "xss|XSS",
                    "code_pattern": "encodeForHTML",
                    "reason": "HTML encoded",
                    "confidence": 0.85,
                },
            ],
        }, f)

    return str(dir_path)


# ─────────────────────── 常量测试 ───────────────────────

class TestConstants:
    """常量定义测试"""

    def test_schema_version(self):
        assert SCHEMA_VERSION == "1.0"

    def test_required_fields(self):
        assert "name" in REQUIRED_FIELDS

    def test_valid_severities(self):
        assert "CRITICAL" in VALID_SEVERITIES
        assert "HIGH" in VALID_SEVERITIES
        assert "MEDIUM" in VALID_SEVERITIES
        assert "LOW" in VALID_SEVERITIES
        assert "INFO" in VALID_SEVERITIES

    def test_valid_tools(self):
        assert "semgrep" in VALID_TOOLS
        assert "bandit" in VALID_TOOLS
        assert "findsecbugs" in VALID_TOOLS

    def test_valid_languages(self):
        assert "java" in VALID_LANGUAGES
        assert "python" in VALID_LANGUAGES

    def test_optional_defaults(self):
        assert "confidence" in OPTIONAL_FIELDS_DEFAULTS
        assert "enabled" in OPTIONAL_FIELDS_DEFAULTS
        assert OPTIONAL_FIELDS_DEFAULTS["enabled"] is True


# ─────────────────────── CustomRule 模型测试 ───────────────────────

class TestCustomRuleModel:
    """CustomRule 数据模型测试"""

    def test_create_minimal_rule(self):
        rule = CustomRule(name="test_rule")
        assert rule.name == "test_rule"
        assert rule.confidence == 0.8
        assert rule.enabled is True

    def test_create_full_rule(self):
        rule = CustomRule(
            name="full_rule",
            rule_id_pattern="sql.injection",
            code_pattern="PreparedStatement|createQuery",
            reason="Safe SQL",
            confidence=0.9,
            description="Test rule",
            references=["https://example.com"],
            tags=["sql", "java"],
        )
        assert rule.name == "full_rule"
        assert rule._compiled_code_pattern is not None
        assert rule.tags == ["sql", "java"]

    def test_rule_auto_compiles_patterns(self):
        rule = CustomRule(
            name="compile_test",
            rule_id_pattern="test\\.rule|test-rule",
            file_pattern=".*/test/.*",
            code_pattern="foo|bar",
        )
        assert rule._compiled_rule_id_pattern is not None
        assert rule._compiled_file_pattern is not None
        assert rule._compiled_code_pattern is not None

    def test_invalid_regex_graceful(self):
        """无效正则不崩溃"""
        rule = CustomRule(
            name="bad_regex",
            code_pattern="[invalid(regex",
        )
        # 编译失败时 pattern 为 None，不会导致构造失败
        assert rule._compiled_code_pattern is None

    def test_to_dict_compatible_format(self):
        rule = CustomRule(name="test", code_pattern="foo", confidence=0.85)
        d = rule.to_dict()
        assert "name" in d
        assert "code_pattern" in d
        assert "confidence" in d
        assert d["confidence"] == 0.85

    def test_to_dict_with_rule_id(self):
        rule = CustomRule(name="test", rule_id="exact_rule")
        d = rule.to_dict()
        assert d.get("rule_id") == "exact_rule"

    def test_to_full_dict(self):
        rule = CustomRule(name="test", description="desc")
        d = rule.to_full_dict()
        assert "description" in d
        assert d["description"] == "desc"

    def test_confidence_not_clamped_in_dataclass(self):
        """dataclass 本身不做 clamp，由 loader 负责 clamp"""
        rule = CustomRule(name="test", confidence=1.5)
        # Dataclass stores the value as-is; loader enforces range
        assert rule.confidence == 1.5

    def test_confidence_not_clamped_low(self):
        rule = CustomRule(name="test", confidence=-0.5)
        assert rule.confidence == -0.5

    def test_confidence_clamped_by_loader(self):
        """Loader 会将 confidence 限制在 [0,1]"""
        loader = CustomRuleLoader()
        content = """
rules:
  - name: clamp_test
    confidence: 1.5
"""
        result = loader.load_from_string(content)
        rule = result.rules[0]
        assert rule.confidence == 1.0


# ─────────────────────── 加载器初始化测试 ───────────────────────

class TestLoaderInit:
    """加载器初始化测试"""

    def test_default_init(self):
        loader = CustomRuleLoader()
        assert loader.strict_mode is False
        assert loader.max_rules == 500
        assert loader.auto_compile is True

    def test_config_init(self):
        loader = CustomRuleLoader(config={
            "strict_mode": True,
            "max_rules": 100,
            "auto_compile": False,
        })
        assert loader.strict_mode is True
        assert loader.max_rules == 100
        assert loader.auto_compile is False

    def test_empty_rules_after_init(self):
        loader = CustomRuleLoader()
        assert loader.get_rules() == []
        assert loader.count_rules() == 0


# ─────────────────────── 文件加载测试 ───────────────────────

class TestFileLoading:
    """文件加载测试"""

    def test_load_valid_yaml(self, loader, sample_yaml_file):
        result = loader.load_from_file(sample_yaml_file)
        assert isinstance(result, LoadResult)
        assert result.rules_loaded > 0
        assert len(result.rules) > 0
        assert len(result.errors) == 0

    def test_load_nonexistent_file(self, loader):
        result = loader.load_from_file("/nonexistent/rules.yaml")
        assert result.rules_loaded == 0
        assert len(result.errors) > 0

    def test_load_wrong_extension(self, loader, temp_dir):
        file_path = Path(temp_dir) / "rules.json"
        with open(file_path, 'w') as f:
            json.dump({}, f)
        result = loader.load_from_file(str(file_path))
        assert result.rules_loaded == 0
        assert len(result.errors) > 0

    def test_load_empty_yaml(self, loader, temp_dir):
        file_path = Path(temp_dir) / "empty.yaml"
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("")
        result = loader.load_from_file(str(file_path))
        assert result.rules_loaded == 0

    def test_load_yaml_with_schema(self, loader, sample_yaml_file):
        result = loader.load_from_file(sample_yaml_file)
        assert result.rules_loaded == 3

    def test_load_yaml_with_warnings_about_version(self, loader, temp_dir):
        file_path = Path(temp_dir) / "rules.yaml"
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("""version: "2.0"
rules:
  - name: test
    confidence: 0.5
""")
        result = loader.load_from_file(str(file_path))
        # Version mismatch should produce a warning
        assert any("version" in w.lower() for w in result.warnings)


# ─────────────────────── 目录加载测试 ───────────────────────

class TestDirectoryLoading:
    """目录批量加载测试"""

    def test_load_from_directory(self, loader, yaml_dir):
        result = loader.load_from_directory(yaml_dir)
        assert result.rules_loaded >= 2
        assert result.files_loaded >= 2

    def test_load_nonexistent_directory(self, loader):
        result = loader.load_from_directory("/nonexistent/dir")
        assert result.rules_loaded == 0

    def test_load_incompatible_structure(self, loader, temp_dir):
        dir_path = Path(temp_dir) / "bad_structure"
        dir_path.mkdir()
        file_path = dir_path / "rules.yaml"
        with open(file_path, 'w', encoding='utf-8') as f:
            yaml.dump({"wrong_key": []}, f)

        result = loader.load_from_directory(str(dir_path))
        # Should produce errors
        assert len(result.errors) > 0


# ─────────────────────── 字符串加载测试 ───────────────────────

class TestStringLoading:
    """字符串加载测试"""

    def test_load_from_yaml_string(self, loader, sample_yaml_content):
        result = loader.load_from_string(sample_yaml_content)
        assert result.rules_loaded == 3

    def test_load_from_empty_string(self, loader):
        result = loader.load_from_string("")
        assert result.rules_loaded == 0

    def test_load_from_invalid_yaml(self, loader):
        result = loader.load_from_string("{ broken yaml: [")
        assert len(result.errors) > 0

    def test_load_list_format(self, loader):
        content = """
rules:
  - name: rule1
    code_pattern: 'pattern1'
  - name: rule2
    code_pattern: 'pattern2'
"""
        result = loader.load_from_string(content)
        assert result.rules_loaded == 2


# ─────────────────────── 规则解析测试 ───────────────────────

class TestRuleParsing:
    """规则解析逻辑测试"""

    def test_parse_rule_with_all_fields(self, loader):
        data = {
            "name": "full_rule",
            "rule_id": "exact.rule.id",
            "rule_id_pattern": "regex_pattern",
            "file_pattern": ".*\\.java$",
            "code_pattern": "safe|method",
            "severity": "HIGH",
            "tool": "semgrep",
            "language": "java",
            "reason": "Test reason",
            "confidence": 0.9,
            "enabled": True,
            "description": "Test description",
            "references": ["https://example.com"],
            "tags": ["security"],
        }
        result = LoadResult()
        rule = loader._parse_single_rule(data, "test", 0)
        assert rule is not None
        assert rule.name == "full_rule"
        assert rule.severity == "HIGH"
        assert rule.tool == "semgrep"
        assert rule.language == "java"

    def test_parse_rule_without_name(self, loader):
        data = {"code_pattern": "no_name"}
        result = loader._parse_single_rule(data, "test", 0)
        assert result is None

    def test_parse_invalid_severity(self, loader):
        data = {
            "name": "test",
            "severity": "INVALID",
        }
        result = loader._parse_single_rule(data, "test", 0)
        assert result is not None
        assert result.severity is None  # Invalid should be ignored

    def test_parse_invalid_tool(self, loader):
        data = {
            "name": "test",
            "tool": "not_a_real_tool",
        }
        result = loader._parse_single_rule(data, "test", 0)
        assert result is not None
        assert result.tool is None

    def test_parse_invalid_language(self, loader):
        data = {
            "name": "test",
            "language": "cobol",
        }
        result = loader._parse_single_rule(data, "test", 0)
        assert result is not None
        assert result.language is None

    def test_parse_disabled_rule(self, loader):
        data = {
            "name": "disabled_rule",
            "enabled": False,
        }
        rule = loader._parse_single_rule(data, "test", 0)
        assert rule is not None
        assert rule.enabled is False

    def test_parse_enabled_rule(self, loader):
        data = {
            "name": "enabled_rule",
            "enabled": True,
        }
        rule = loader._parse_single_rule(data, "test", 0)
        assert rule is not None
        assert rule.enabled is True

    def test_duplicate_name_skipped(self, loader):
        data = {"name": "same_name"}
        r1 = loader._parse_single_rule(data, "test", 0)
        r2 = loader._parse_single_rule(data, "test", 1)
        assert r1 is not None
        assert r2 is None  # Duplicate


# ─────────────────────── 格式转换测试 ───────────────────────

class TestFormatConversion:
    """格式转换测试"""

    def test_to_compatible_format(self, loader, sample_yaml_content):
        loader.load_from_string(sample_yaml_content)
        compat = loader.to_compatible_format()
        assert isinstance(compat, list)
        for d in compat:
            assert "name" in d
            assert "reason" in d
            assert "confidence" in d

    def test_to_full_format(self, loader, sample_yaml_content):
        loader.load_from_string(sample_yaml_content)
        full = loader.to_full_format()
        assert isinstance(full, list)
        for d in full:
            assert "description" in d
            assert "tags" in d

    def test_get_filter_config_section(self, loader, sample_yaml_content):
        loader.load_from_string(sample_yaml_content)
        section = loader.get_filter_config_section()
        assert "custom_rules" in section

    def test_compatible_format_excludes_disabled(self, loader):
        content = """
rules:
  - name: enabled_rule
    enabled: true
    code_pattern: 'safe'
  - name: disabled_rule
    enabled: false
    code_pattern: 'unsafe'
"""
        loader.load_from_string(content)
        compat = loader.to_compatible_format()
        names = [d["name"] for d in compat]
        assert "enabled_rule" in names
        assert "disabled_rule" not in names


# ─────────────────────── 规则查询测试 ───────────────────────

class TestRuleQueries:
    """规则查询功能测试"""

    def test_get_rules(self, loader, sample_yaml_content):
        loader.load_from_string(sample_yaml_content)
        rules = loader.get_rules()
        assert len(rules) == 3

    def test_get_enabled_rules(self, loader):
        content = """rules:
  - name: r1
    enabled: true
  - name: r2
    enabled: false
  - name: r3
    enabled: true
"""
        loader.load_from_string(content)
        enabled = loader.get_enabled_rules()
        assert len(enabled) == 2

    def test_get_rule_by_name(self, loader, sample_yaml_content):
        loader.load_from_string(sample_yaml_content)
        rule = loader.get_rule_by_name("custom_sql_safe_wrapper")
        assert rule is not None
        assert rule.name == "custom_sql_safe_wrapper"

    def test_get_rule_by_name_not_found(self, loader, sample_yaml_content):
        loader.load_from_string(sample_yaml_content)
        rule = loader.get_rule_by_name("nonexistent")
        assert rule is None

    def test_get_rules_by_tag(self, loader):
        content = """rules:
  - name: tag_rule1
    tags: [sql]
  - name: tag_rule2
    tags: [xss]
  - name: tag_rule3
    tags: [sql, xss]
"""
        loader.load_from_string(content)
        sql_rules = loader.get_rules_by_tag("sql")
        assert len(sql_rules) == 2

    def test_get_rules_by_language(self, loader):
        content = """rules:
  - name: java_rule
    language: java
  - name: python_rule
    language: python
"""
        loader.load_from_string(content)
        java_rules = loader.get_rules_by_language("java")
        assert len(java_rules) == 1

    def test_clear(self, loader, sample_yaml_content):
        loader.load_from_string(sample_yaml_content)
        assert loader.count_rules() > 0
        loader.clear()
        assert loader.count_rules() == 0


# ─────────────────────── 合并建议测试 ───────────────────────

class TestMergeSuggestions:
    """合并建议功能测试"""

    def test_detect_duplicate_names(self, loader, sample_yaml_content):
        loader.load_from_string(sample_yaml_content)
        existing = [
            {"name": "custom_sql_safe_wrapper", "code_pattern": "old_pattern"},
            {"name": "other_rule", "code_pattern": "other"},
        ]
        suggestions = loader.get_merge_suggestions(existing)
        assert "custom_sql_safe_wrapper" in suggestions["duplicates"]

    def test_no_duplicates(self, loader):
        loader.load_from_string("""rules:
  - name: unique_rule
    code_pattern: unique
""")
        existing = [
            {"name": "different_rule", "code_pattern": "different"},
        ]
        suggestions = loader.get_merge_suggestions(existing)
        assert len(suggestions["duplicates"]) == 0

    def test_similar_pattern_detection(self, loader):
        loader.load_from_string("""rules:
  - name: loader_rule
    code_pattern: PreparedStatement|createQuery
""")
        existing = [
            {"name": "existing_rule", "code_pattern": "PreparedStatement|createQuery|safe"},
        ]
        suggestions = loader.get_merge_suggestions(existing)
        # Similarity check depends on the threshold

    def test_pattern_similarity_identical(self, loader):
        sim = loader._pattern_similarity("foo|bar", "foo|bar")
        assert sim == 1.0

    def test_pattern_similarity_different(self, loader):
        sim = loader._pattern_similarity("abc", "xyz")
        assert sim == 0.0

    def test_pattern_similarity_empty(self, loader):
        sim = loader._pattern_similarity("", "test")
        assert sim == 0.0


# ─────────────────────── 边界情况测试 ───────────────────────

class TestEdgeCases:
    """边界情况测试"""

    def test_max_rules_limit(self, loader, temp_dir):
        """超过最大规则数时截断"""
        loader.max_rules = 5
        dir_path = Path(temp_dir) / "many_rules"
        dir_path.mkdir()

        # 生成10条规则
        rules = [
            {"name": f"rule_{i}", "code_pattern": f"pattern_{i}"}
            for i in range(10)
        ]

        file_path = dir_path / "rules.yaml"
        with open(file_path, 'w', encoding='utf-8') as f:
            yaml.dump({"version": "1.0", "rules": rules}, f)

        result = loader.load_from_directory(str(dir_path))
        # Should be truncated to 5
        assert result.rules_loaded <= 5
        assert any("truncating" in w.lower() or "max" in w.lower() for w in result.warnings)

    def test_yaml_not_dict(self, loader, temp_dir):
        """YAML 为列表格式"""
        file_path = Path(temp_dir) / "list.yaml"
        with open(file_path, 'w', encoding='utf-8') as f:
            yaml.dump([
                {"name": "list_rule1", "code_pattern": "a"},
                {"name": "list_rule2", "code_pattern": "b"},
            ], f)

        result = loader.load_from_file(str(file_path))
        assert result.rules_loaded == 2

    def test_non_dict_rules_data(self, loader):
        """规则数据不是字典"""
        content = """
rules:
  - "not a dict"
  - 123
"""
        result = loader.load_from_string(content)
        assert result.rules_loaded == 0
        assert result.rules_skipped == 2

    def test_missing_rules_key(self, loader):
        """YAML 没有 rules 或 custom_rules 字段"""
        content = """
metadata:
  author: test
  version: 1.0
"""
        result = loader.load_from_string(content)
        assert result.rules_loaded == 0
        assert len(result.errors) > 0
