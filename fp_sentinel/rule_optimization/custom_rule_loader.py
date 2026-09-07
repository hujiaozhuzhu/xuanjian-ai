"""
玄鉴 v2.3.0 — 用户自定义规则加载器 (Custom Rule Loader)

功能：支持用户通过 YAML 文件导入自定义扫描规则，自动兼容现有扫描器逻辑。
     加载的规则与内置 Java/Python/JS 规则统一处理，支持路径白名单、
     代码匹配、规则ID匹配、文件匹配等多种过滤维度。

设计原则：
- 向后兼容：自定义规则与现有 RuleFilter.custom_rules 完全兼容
- 安全隔离：自定义规则不影响内置规则
- 格式验证：YAML schema 验证，防止无效规则导致运行时错误
- 优先级控制：内置规则优先，用户规则次之

版本: 2.3.0
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)


# ─────────────────────── 常量定义 ───────────────────────

# YAML schema 版本
SCHEMA_VERSION = "1.0"

# 必填字段
REQUIRED_FIELDS = ["name"]

# 可选字段及其默认值
OPTIONAL_FIELDS_DEFAULTS: Dict[str, Any] = {
    "rule_id": None,
    "rule_id_pattern": None,
    "file_pattern": None,
    "code_pattern": None,
    "severity": None,
    "tool": None,
    "language": None,
    "reason": "自定义规则",
    "confidence": 0.8,
    "enabled": True,
    "description": "",
    "references": [],
    "tags": [],
}

# 合法的 severity 值
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

# 合法的 tool 值
VALID_TOOLS = {
    "semgrep", "bandit", "gosec", "findsecbugs", "spotbugs",
    "js_scanner", "python_scanner", "eslint_security", "manual",
}

# 合法的语言值
VALID_LANGUAGES = {"java", "python", "go", "javascript", "typescript", "auto"}


# ─────────────────────── 数据模型 ───────────────────────

@dataclass
class CustomRule:
    """单条自定义规则"""
    name: str
    rule_id: Optional[str] = None
    rule_id_pattern: Optional[str] = None
    file_pattern: Optional[str] = None
    code_pattern: Optional[str] = None
    severity: Optional[str] = None
    tool: Optional[str] = None
    language: Optional[str] = None
    reason: str = "自定义规则"
    confidence: float = 0.8
    enabled: bool = True
    description: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    # 编译后的正则（运行时填充）
    _compiled_rule_id_pattern: Optional[re.Pattern] = field(default=None, repr=False)
    _compiled_file_pattern: Optional[re.Pattern] = field(default=None, repr=False)
    _compiled_code_pattern: Optional[re.Pattern] = field(default=None, repr=False)

    def __post_init__(self):
        """初始化时编译正则表达式"""
        if self.rule_id_pattern:
            try:
                self._compiled_rule_id_pattern = re.compile(self.rule_id_pattern, re.IGNORECASE)
            except re.error as e:
                logger.warning(f"Invalid rule_id_pattern in '{self.name}': {e}")

        if self.file_pattern:
            try:
                self._compiled_file_pattern = re.compile(self.file_pattern)
            except re.error as e:
                logger.warning(f"Invalid file_pattern in '{self.name}': {e}")

        if self.code_pattern:
            try:
                self._compiled_code_pattern = re.compile(self.code_pattern)
            except re.error as e:
                logger.warning(f"Invalid code_pattern in '{self.name}': {e}")

    def to_dict(self) -> Dict[str, Any]:
        """转为字典（兼容 RuleFilter.custom_rules 格式）"""
        result: Dict[str, Any] = {
            "name": self.name,
            "reason": self.reason,
            "confidence": self.confidence,
        }
        if self.rule_id:
            result["rule_id"] = self.rule_id
        if self.rule_id_pattern:
            result["rule_id_pattern"] = self.rule_id_pattern
        if self.file_pattern:
            result["file_pattern"] = self.file_pattern
        if self.code_pattern:
            result["code_pattern"] = self.code_pattern
        if self.severity:
            result["severity"] = self.severity
        if self.tool:
            result["tool"] = self.tool
        return result

    def to_full_dict(self) -> Dict[str, Any]:
        """转为完整字典（用于导出）"""
        return {
            "name": self.name,
            "rule_id": self.rule_id,
            "rule_id_pattern": self.rule_id_pattern,
            "file_pattern": self.file_pattern,
            "code_pattern": self.code_pattern,
            "severity": self.severity,
            "tool": self.tool,
            "language": self.language,
            "reason": self.reason,
            "confidence": self.confidence,
            "enabled": self.enabled,
            "description": self.description,
            "references": self.references,
            "tags": self.tags,
        }


@dataclass
class LoadResult:
    """加载结果"""
    rules: List[CustomRule] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    files_loaded: int = 0
    rules_loaded: int = 0
    rules_skipped: int = 0


# ─────────────────────── 核心加载器 ───────────────────────

class CustomRuleLoader:
    """
    自定义规则加载器

    支持从 YAML 文件加载自定义规则，自动验证和编译。

    使用方式:
        loader = CustomRuleLoader()
        result = loader.load_from_file("custom_rules.yaml")
        compatible_rules = loader.to_compatible_format(result.rules)
        # 兼容 RuleFilter.custom_rules 格式
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化加载器

        Args:
            config: 可选配置
                - strict_mode: 是否严格模式（格式错误时跳过整文件）
                - max_rules: 单文件最大规则数
                - auto_compile: 是否自动编译正则（默认 True）
        """
        self.config = config or {}
        self.strict_mode = self.config.get("strict_mode", False)
        self.max_rules = self.config.get("max_rules", 500)
        self.auto_compile = self.config.get("auto_compile", True)

        # 已加载的规则
        self._rules: List[CustomRule] = []
        self._rule_names: set = set()  # 用于去重

        # 加载历史
        self._load_history: List[LoadResult] = []

    # ─────────────── 加载方法 ───────────────

    def load_from_file(self, file_path: str) -> LoadResult:
        """
        从单个 YAML 文件加载规则

        Args:
            file_path: YAML 文件路径

        Returns:
            LoadResult 包含加载的规则和错误信息
        """
        result = LoadResult()
        path = Path(file_path)

        if not path.exists():
            result.errors.append(f"File not found: {file_path}")
            return result

        if not path.suffix.lower() in ('.yaml', '.yml'):
            result.errors.append(f"Not a YAML file: {file_path}")
            return result

        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if data is None:
                result.warnings.append(f"Empty YAML file: {file_path}")
                return result

            result.files_loaded = 1
            self._parse_yaml_data(data, result, source=str(path))

        except yaml.YAMLError as e:
            result.errors.append(f"YAML parse error in {file_path}: {e}")
        except Exception as e:
            result.errors.append(f"Failed to load {file_path}: {e}")

        self._load_history.append(result)
        self._rules.extend(result.rules)
        logger.info(
            f"Loaded {result.rules_loaded} custom rules from {file_path} "
            f"(skipped: {result.rules_skipped}, errors: {len(result.errors)})"
        )
        return result

    def load_from_directory(self, dir_path: str) -> LoadResult:
        """
        从目录下批量加载 YAML 文件

        Args:
            dir_path: 目录路径（递归搜索 .yaml/.yml 文件）

        Returns:
            综合加载结果
        """
        result = LoadResult()
        path = Path(dir_path)

        if not path.exists():
            result.errors.append(f"Directory not found: {dir_path}")
            return result

        if not path.is_dir():
            result.errors.append(f"Not a directory: {dir_path}")
            return result

        yaml_files = list(path.rglob("*.yaml")) + list(path.rglob("*.yml"))
        if not yaml_files:
            result.warnings.append(f"No YAML files found in: {dir_path}")
            return result

        for yaml_file in yaml_files:
            sub_result = self.load_from_file(str(yaml_file))
            result.errors.extend(sub_result.errors)
            result.warnings.extend(sub_result.warnings)
            result.files_loaded += sub_result.files_loaded
            result.rules_loaded += sub_result.rules_loaded
            result.rules_skipped += sub_result.rules_skipped

        self._rules.extend(result.rules)
        return result

    def load_from_string(self, yaml_content: str) -> LoadResult:
        """
        从 YAML 字符串加载规则

        Args:
            yaml_content: YAML 格式字符串

        Returns:
            LoadResult
        """
        result = LoadResult()

        try:
            data = yaml.safe_load(yaml_content)
            if data is None:
                result.warnings.append("Empty YAML content")
                return result

            result.files_loaded = 1
            self._parse_yaml_data(data, result, source="<string>")

        except yaml.YAMLError as e:
            result.errors.append(f"YAML parse error: {e}")

        self._load_history.append(result)
        self._rules.extend(result.rules)
        return result

    # ─────────────── 解析逻辑 ───────────────

    def _parse_yaml_data(
        self, data: Any, result: LoadResult, source: str = "<unknown>"
    ) -> None:
        """解析 YAML 数据"""
        # 支持两种格式：
        # 格式一: {"version": "1.0", "rules": [...]}
        # 格式二: {"custom_rules": [...]}  (兼容现有配置格式)
        # 格式三: 顶层直接是列表 [...]

        rules_data: List[Dict[str, Any]] = []

        if isinstance(data, dict):
            # 检查版本字段
            if "version" in data:
                version = data.get("version")
                if version != SCHEMA_VERSION:
                    result.warnings.append(
                        f"Schema version mismatch: expected {SCHEMA_VERSION}, got {version}"
                    )

            # 提取规则列表
            if "rules" in data and isinstance(data["rules"], list):
                rules_data = data["rules"]
            elif "custom_rules" in data and isinstance(data["custom_rules"], list):
                rules_data = data["custom_rules"]
            else:
                result.errors.append(
                    f"Unable to find rules list in {source}. "
                    f"Expected 'rules' or 'custom_rules' key."
                )
                return

        elif isinstance(data, list):
            rules_data = data
        else:
            result.errors.append(f"Unsupported YAML structure in {source}")
            return

        # 检查规则数量限制
        if len(rules_data) > self.max_rules:
            result.warnings.append(
                f"Rules exceed max limit ({self.max_rules}), "
                f"truncating from {len(rules_data)}"
            )
            rules_data = rules_data[: self.max_rules]

        # 解析每条规则
        for idx, rule_data in enumerate(rules_data):
            if not isinstance(rule_data, dict):
                result.errors.append(
                    f"Rule #{idx} in {source} is not a dict, skipping"
                )
                result.rules_skipped += 1
                continue

            parsed = self._parse_single_rule(rule_data, source, idx)
            if parsed:
                if parsed.enabled:
                    result.rules.append(parsed)
                    result.rules_loaded += 1
                else:
                    result.rules_skipped += 1
            else:
                result.rules_skipped += 1

    def _parse_single_rule(
        self,
        data: Dict[str, Any],
        source: str,
        index: int,
    ) -> Optional[CustomRule]:
        """解析单条规则数据"""
        # 验证必填字段
        if "name" not in data:
            logger.warning(f"Rule #{index} in {source} missing 'name' field, skipping")
            return None

        name = data["name"]

        # 名称去重
        if name in self._rule_names:
            logger.debug(f"Duplicate rule name '{name}', keeping first")
            return None

        # 验证可选字段类型
        severity = data.get("severity")
        if severity and isinstance(severity, str):
            if severity.upper() not in VALID_SEVERITIES:
                logger.warning(
                    f"Rule '{name}' has invalid severity '{severity}', ignoring"
                )
                severity = None

        tool = data.get("tool")
        if tool and isinstance(tool, str):
            if tool.lower() not in VALID_TOOLS:
                logger.warning(
                    f"Rule '{name}' has invalid tool '{tool}', ignoring"
                )
                tool = None

        language = data.get("language")
        if language and isinstance(language, str):
            if language.lower() not in VALID_LANGUAGES:
                logger.warning(
                    f"Rule '{name}' has invalid language '{language}', ignoring"
                )
                language = None

        # 验证 confidence 范围
        confidence = float(data.get("confidence", 0.8))
        confidence = max(0.0, min(1.0, confidence))

        # 创建规则对象
        rule = CustomRule(
            name=name,
            rule_id=data.get("rule_id"),
            rule_id_pattern=data.get("rule_id_pattern"),
            file_pattern=data.get("file_pattern"),
            code_pattern=data.get("code_pattern"),
            severity=severity.upper() if severity else None,
            tool=tool.lower() if tool else None,
            language=language.lower() if language else None,
            reason=data.get("reason", "自定义规则"),
            confidence=confidence,
            enabled=bool(data.get("enabled", True)),
            description=data.get("description", ""),
            references=data.get("references", []),
            tags=data.get("tags", []),
        )

        self._rule_names.add(name)
        return rule

    # ─────────────── 兼容格式转换 ───────────────

    def to_compatible_format(
        self, rules: Optional[List[CustomRule]] = None
    ) -> List[Dict[str, Any]]:
        """
        将自定义规则转换为 RuleFilter 兼容格式

        Args:
            rules: 指定规则列表，不传则使用全部已加载规则

        Returns:
            兼容 RuleFilter.custom_rules 的字典列表
        """
        target = rules or self._rules
        return [rule.to_dict() for rule in target if rule.enabled]

    def to_full_format(
        self, rules: Optional[List[CustomRule]] = None
    ) -> List[Dict[str, Any]]:
        """
        导出为完整格式（含所有字段）

        Args:
            rules: 指定规则列表，不传则使用全部已加载规则

        Returns:
            完整字典列表
        """
        target = rules or self._rules
        return [rule.to_full_dict() for rule in target]

    # ─────────────── 规则查询 ───────────────

    def get_rules(self) -> List[CustomRule]:
        """获取全部已加载规则"""
        return list(self._rules)

    def get_enabled_rules(self) -> List[CustomRule]:
        """获取已启用的规则"""
        return [r for r in self._rules if r.enabled]

    def get_rule_by_name(self, name: str) -> Optional[CustomRule]:
        """按名称查找规则"""
        for rule in self._rules:
            if rule.name == name:
                return rule
        return None

    def get_rules_by_tag(self, tag: str) -> List[CustomRule]:
        """按标签查找规则"""
        return [r for r in self._rules if tag in r.tags]

    def get_rules_by_language(self, language: str) -> List[CustomRule]:
        """按语言筛选规则"""
        return [r for r in self._rules if r.language == language]

    def count_rules(self) -> int:
        """已加载规则总数"""
        return len(self._rules)

    def clear(self) -> None:
        """清除所有已加载规则"""
        self._rules.clear()
        self._rule_names.clear()
        self._load_history.clear()

    # ─────────────── 集成方法 ───────────────

    def get_filter_config_section(self) -> Dict[str, Any]:
        """
        生成可直接写入 xuanjian.yaml 的配置片段

        Returns:
            配置字典，对应 filters.rule_filter.custom_rules
        """
        return {
            "custom_rules": self.to_compatible_format()
        }

    def get_merge_suggestions(
        self, existing_rules: List[Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        """
        分析自定义规则与已有规则的重复/冲突建议

        Args:
            existing_rules: 已有的规则列表

        Returns:
            包含 'duplicates'(重复名), 'similar_patterns'(相似模式),
            'conflicts'(冲突) 的字典
        """
        suggestions: Dict[str, List[str]] = {
            "duplicates": [],
            "similar_patterns": [],
            "conflicts": [],
        }

        existing_names = {r.get("name", "") for r in existing_rules}
        existing_patterns = {
            r.get("code_pattern", "") for r in existing_rules if "code_pattern" in r
        }

        for rule in self._rules:
            # 检查名称重复
            if rule.name in existing_names:
                suggestions["duplicates"].append(rule.name)

            # 检查模式相似性
            if rule.code_pattern:
                for existing_pat in existing_patterns:
                    if existing_pat and self._pattern_similarity(
                        rule.code_pattern, existing_pat
                    ) > 0.8:
                        suggestions["similar_patterns"].append(
                            f"{rule.name} ~ existing ({rule.code_pattern})"
                        )

        return suggestions

    def _pattern_similarity(self, p1: str, p2: str) -> float:
        """简单模式相似度计算"""
        # 使用最长公共子序列的简化版本
        if not p1 or not p2:
            return 0.0
        if p1 == p2:
            return 1.0
        # 基于字符集合的Jaccard相似度
        set1 = set(p1.split('|'))
        set2 = set(p2.split('|'))
        if not set1 or not set2:
            return 0.0
        intersection = set1 & set2
        union = set1 | set2
        return len(intersection) / len(union)
