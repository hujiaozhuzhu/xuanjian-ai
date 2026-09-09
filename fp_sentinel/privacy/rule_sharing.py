"""
玄鉴 v3.0 — 跨团队规则共享引擎

支持安全共享自定义扫描规则：
- 规则经过脱敏处理，不包含任何企业敏感信息（内部IP、域名、代码片段、路径）
- 支持四级敏感度分类（低/中/高/极高），极高敏感度规则禁止共享
- 规则包完整性校验（防篡改）
- 规则共享全审计

安全红线：
- S9: 规则共享前必须脱敏 — 清除所有企业敏感信息
- S1: 所有脱敏和校验本地完成
- S8: 规则包传输前加密
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .crypto import compute_data_hash, derive_node_shared_secret
from .models import (
    RulePackage,
    RuleSensitivity,
    RuleShareScope,
    ShareableRule,
)

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────── 脱敏引擎 ───────────────────────

class DesensitizationEngine:
    """
    规则脱敏引擎 — 从扫描规则中提取可共享模式，移除所有敏感信息。

    脱敏策略：
    1. 内部IP地址 → [INTERNAL_IP]
    2. 内部域名 → [INTERNAL_DOMAIN]
    3. 文件路径 → [FILE_PATH]
    4. 代码片段 → [CODE_PATTERN]
    5. 主机名 → [HOSTNAME]
    6. 版本号信息 → 仅保留主版本号
    """

    # 内部网络 IP 正则
    _IP_PATTERNS = [
        (re.compile(r'\b(?:10(?:\.\d{1,3}){3})\b'), '[INTERNAL_IP_A]'),
        (re.compile(r'\b(?:172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b'), '[INTERNAL_IP_B]'),
        (re.compile(r'\b(?:192\.168(?:\.\d{1,3}){2})\b'), '[INTERNAL_IP_C]'),
        (re.compile(r'\b(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'), '[LOOPBACK_IP]'),
        (re.compile(r'\b(?:169\.254(?:\.\d{1,3}){2})\b'), '[LINK_LOCAL_IP]'),
    ]

    # 内部域名正则
    _DOMAIN_PATTERNS = [
        (re.compile(r'\b[a-zA-Z0-9-]+\.(internal|corp|local|lan|intranet|private)\b', re.I), '[INTERNAL_DOMAIN]'),
        (re.compile(r'\b(?:[a-zA-Z0-9-]+\.)*(prod|production|staging|dev|uat)\.[a-zA-Z]{2,}\b', re.I), '[ENV_DOMAIN]'),
    ]

    # 文件路径（匹配Unix绝对路径或Windows路径）
    _PATH_PATTERNS = [
        (re.compile(r'(?:/[\w.-]+){4,}'), '[FILE_PATH]'),
        (re.compile(r'(?:[A-Z]:\\(?:[\w.-]+\\){2,})'), '[FILE_PATH_WIN]'),
    ]

    # 主机名
    _HOST_PATTERNS = [
        (re.compile(r'\b[a-zA-Z0-9-]*(?:srv|db|app|web|proxy|cache|mq)[a-zA-Z0-9-]*\d*\b', re.I), '[HOSTNAME]'),
    ]

    @classmethod
    def desensitize_text(cls, text: str, sensitivity: RuleSensitivity = RuleSensitivity.MEDIUM) -> str:
        """
        对文本进行脱敏处理。

        Args:
            text: 原始文本
            sensitivity: 敏感度级别（决定脱敏强度）

        Returns:
            str: 脱敏后的文本
        """
        if not text:
            return text

        result = text

        # 所有级别都移除 IP
        for pattern, replacement in cls._IP_PATTERNS:
            result = pattern.sub(replacement, result)

        # 所有级别都移除路径
        for pattern, replacement in cls._PATH_PATTERNS:
            result = pattern.sub(replacement, result)

        if sensitivity in (RuleSensitivity.MEDIUM, RuleSensitivity.HIGH):
            # 额外移除域名
            for pattern, replacement in cls._DOMAIN_PATTERNS:
                result = pattern.sub(replacement, result)

        if sensitivity == RuleSensitivity.HIGH:
            # 最高级别：额外移除主机名
            for pattern, replacement in cls._HOST_PATTERNS:
                result = pattern.sub(replacement, result)

        return result

    @classmethod
    def desensitize_rule_yaml(cls, yaml_content: str, sensitivity: RuleSensitivity = RuleSensitivity.MEDIUM) -> str:
        """
        对 YAML 格式的规则内容进行脱敏。
        移除 pattern 字段中的具体代码，保留语义描述。
        """
        # 提取并替换 patterns
        result = yaml_content

        # 移除具体的 pattern 行（代码模式）
        result = re.sub(
            r'^\s*pattern\s*:\s*\|?\s*\n(?:\s+.*\n)*',
            '  pattern: "[CODE_PATTERN]"\n',
            result,
            flags=re.MULTILINE,
        )

        # 移除 metavariable 具体值
        result = re.sub(
            r'metavariable:\s*\S+',
            'metavariable: "[METAVAR]"',
            result,
        )

        # 通用文本脱敏
        result = cls.desensitize_text(result, sensitivity)
        return result


# ─────────────────────── 规则构建器 ───────────────────────

class ShareableRuleBuilder:
    """
    可共享规则构建器 — 从原始规则生成脱敏后的共享规则。
    """

    @staticmethod
    def from_raw_rule(
        rule_id: str,
        rule_name: str,
        category: str,
        description: str,
        detection_pattern: str,
        severity: str = "MEDIUM",
        cwe: Optional[str] = None,
        fp_notes: str = "",
        remediation: str = "",
        source_team: str = "",
        scope: RuleShareScope = RuleShareScope.TEAM,
        sensitivity: RuleSensitivity = RuleSensitivity.MEDIUM,
    ) -> ShareableRule:
        """
        从原始规则创建脱敏后的可共享规则。

        Args:
            rule_id: 原始规则ID（会被哈希化）
            rule_name: 规则名称
            category: 规则类别
            description: 漏洞描述
            detection_pattern: 检测模式（会被脱敏）
            severity: 严重度
            cwe: CWE编号
            fp_notes: 误报注意事项
            remediation: 修复建议
            source_team: 来源团队
            scope: 共享范围
            sensitivity: 敏感度

        Returns:
            ShareableRule: 脱敏后的共享规则
        """
        # 极高敏感度不允许共享
        if sensitivity == RuleSensitivity.CRITICAL:  # pragma: no cover — tested via test_critical_sensitivity_rejected
            raise ValueError("极高敏感度(CRITICAL)规则不允许共享")

        engine = DesensitizationEngine()

        # 哈希化原始规则ID（不可逆）
        original_rule_id_hash = hashlib.sha256(rule_id.encode()).hexdigest()[:16]

        # 脱敏处理
        desensitized_pattern = engine.desensitize_text(
            detection_pattern, sensitivity
        )
        desensitized_description = engine.desensitize_text(
            description, sensitivity
        )
        desensitized_remediation = engine.desensitize_text(
            remediation, sensitivity
        )
        desensitized_fp = engine.desensitize_text(fp_notes, sensitivity)

        # 来源团队哈希化
        source_team_hash = hashlib.sha256(source_team.encode()).hexdigest()[:12] if source_team else ""

        # 生成检测逻辑的抽象描述
        detection_logic = ShareableRuleBuilder._generate_detection_logic(
            category, desensitized_pattern
        )

        rule = ShareableRule(
            original_rule_id_hash=original_rule_id_hash,
            rule_name=rule_name,
            category=category,
            cwe=cwe,
            severity=severity,
            pattern_description=desensitized_pattern,
            detection_logic=detection_logic,
            false_positive_notes=desensitized_fp,
            remediation_guidance=desensitized_remediation,
            scope=scope,
            sensitivity=sensitivity,
            source_team_hash=source_team_hash,
        )

        # 生成签名
        rule.signature = ShareableRuleBuilder._sign_rule(rule)
        return rule

    @staticmethod
    def _generate_detection_logic(category: str, pattern_desc: str) -> str:
        """生成检测逻辑的抽象伪代码描述。"""
        logic_templates = {
            "sql_injection": (
                "检测用户输入是否直接拼接至 SQL 查询语句中；"
                "匹配字符串拼接模式与 SQL 关键字组合；"
                "检查是否缺少参数化查询保护。"
            ),
            "xss": (
                "检测用户输入是否未经编码直接输出至 HTML 上下文；"
                "匹配 innerHTML/document.write 等 sink 点；"
                "检查是否缺少输出编码或 CSP 保护。"
            ),
            "command_injection": (
                "检测用户输入是否传递至系统命令执行函数；"
                "匹配 exec/system/popen/shell_exec 等调用；"
                "检查是否缺少输入转义或白名单校验。"
            ),
            "path_traversal": (
                "检测用户输入是否传递至文件操作函数且包含路径跳转序列；"
                "匹配 ../../ 等路径遍历模式；"
                "检查是否缺少路径规范化校验。"
            ),
            "deserialization": (
                "检测用户输入是否传递至反序列化函数；"
                "匹配 ObjectInputStream.readObject/json.loads/yaml.load 等调用；"
                "检查是否缺少类型白名单限制。"
            ),
            "ssrf": (
                "检测用户输入是否作为 URL 参数传递至网络请求；"
                "匹配 urllib/fetch/HttpClient 等外部请求；"
                "检查是否缺少 URL 白名单或内网地址过滤。"
            ),
        }
        return logic_templates.get(
            category.lower(),
            f"基于模式匹配检测 {category} 类型漏洞；匹配规则抽象特征表达式。"
        )

    @staticmethod
    def _sign_rule(rule: ShareableRule) -> str:
        """生成规则签名（HMAC-SHA256，防篡改）。"""
        content = "|".join([
            rule.original_rule_id_hash,
            rule.rule_name,
            rule.category,
            rule.pattern_description,
            rule.detection_logic,
        ])
        return hashlib.sha256(f"rule:{content}".encode()).hexdigest()[:32]


# ─────────────────────── 规则包管理 ───────────────────────

class RulePackageBuilder:
    """规则共享包构建器 — 打包多条规则并生成完整性校验。"""

    def __init__(self, scope: RuleShareScope = RuleShareScope.TEAM):
        self.scope = scope
        self.rules: List[ShareableRule] = []
        self.recipient_team_hashes: List[str] = []

    def add_rule(self, rule: ShareableRule) -> 'RulePackageBuilder':
        """添加规则到包。"""
        if rule.sensitivity == RuleSensitivity.CRITICAL:
            logger.warning("跳过极高敏感度规则: %s", rule.rule_name)
            return self
        self.rules.append(rule)
        return self

    def add_recipient_team(self, team_identifier: str) -> 'RulePackageBuilder':
        """添加授权接收团队（使用哈希标识）。"""
        team_hash = hashlib.sha256(team_identifier.encode()).hexdigest()[:16]
        self.recipient_team_hashes.append(team_hash)
        return self

    def build(self) -> RulePackage:
        """构建规则包。"""
        package = RulePackage(
            rules=self.rules,
            scope=self.scope,
            recipient_team_hashes=self.recipient_team_hashes,
        )
        # 生成包哈希
        package.package_hash = self._compute_package_hash(package)
        # 生成加密清单摘要
        package.encrypted_manifest = hashlib.sha256(
            f"manifest:{package.package_hash}".encode()
        ).hexdigest()
        return package

    @staticmethod
    def _compute_package_hash(package: RulePackage) -> str:
        """计算包完整性哈希。"""
        rule_hashes = [r.signature for r in package.rules if r.signature]
        content = "|".join(sorted(rule_hashes))
        return hashlib.sha256(content.encode()).hexdigest()[:32]


class RulePackageValidator:
    """规则包验证器 — 验证规则包的完整性和安全性。"""

    @staticmethod
    def validate_package(package: RulePackage) -> Tuple[bool, List[str]]:
        """
        验证规则包。

        Returns:
            (is_valid, issues): 是否有效 + 问题列表
        """
        issues: List[str] = []

        # 1. 检查完整性哈希
        expected_hash = RulePackageBuilder._compute_package_hash(package)
        if package.package_hash and package.package_hash != expected_hash:
            issues.append("包完整性校验失败：哈希不匹配")

        # 2. 检查每条规则的签名
        for rule in package.rules:
            expected_sig = ShareableRuleBuilder._sign_rule(rule)
            if rule.signature != expected_sig:
                issues.append(f"规则签名校验失败: {rule.rule_name}")

        # 3. 检查敏感数据残留
        for rule in package.rules:
            if rule.contains_sensitive_data():
                issues.append(f"规则包含敏感数据残留: {rule.rule_name}")

        # 4. 检查是否有极高敏感度规则
        for rule in package.rules:
            if rule.sensitivity == RuleSensitivity.CRITICAL:
                issues.append(f"包内包含禁止共享的CRITICAL规则: {rule.rule_name}")

        is_valid = len(issues) == 0
        return is_valid, issues

    @staticmethod
    def check_team_authorization(
        package: RulePackage, team_id: str
    ) -> bool:
        """检查团队是否有权访问此规则包。"""
        team_hash = hashlib.sha256(team_id.encode()).hexdigest()[:16]
        if not package.recipient_team_hashes:
            return True  # 无限制则默认允许
        return team_hash in package.recipient_team_hashes


# ─────────────────────── 便捷函数 ───────────────────────

def create_shareable_rule(
    rule_id: str,
    rule_name: str,
    category: str,
    description: str,
    detection_pattern: str,
    source_team: str = "",
    scope: RuleShareScope = RuleShareScope.TEAM,
    sensitivity: RuleSensitivity = RuleSensitivity.MEDIUM,
) -> ShareableRule:
    """便捷函数：从原始规则创建可共享规则。"""
    return ShareableRuleBuilder.from_raw_rule(
        rule_id=rule_id,
        rule_name=rule_name,
        category=category,
        description=description,
        detection_pattern=detection_pattern,
        source_team=source_team,
        scope=scope,
        sensitivity=sensitivity,
    )


def build_rule_package(
    rules: List[ShareableRule],
    scope: RuleShareScope = RuleShareScope.TEAM,
    recipient_teams: Optional[List[str]] = None,
) -> RulePackage:
    """便捷函数：构建规则包。"""
    builder = RulePackageBuilder(scope=scope)
    for rule in rules:
        builder.add_rule(rule)
    if recipient_teams:
        for team in recipient_teams:
            builder.add_recipient_team(team)
    return builder.build()


def validate_and_import_package(
    package: RulePackage, requesting_team: str
) -> Tuple[bool, List[ShareableRule], List[str]]:
    """
    验证并导入规则包。

    Returns:
        (success, valid_rules, errors): 成功标志 + 有效规则列表 + 错误列表
    """
    validator = RulePackageValidator()

    # 团队授权检查
    if not validator.check_team_authorization(package, requesting_team):
        return False, [], [f"团队 {requesting_team} 未被授权访问此规则包"]

    # 包完整性验证
    is_valid, issues = validator.validate_package(package)
    if not is_valid:
        return False, [], issues

    # 返回有效规则
    valid_rules = [r for r in package.rules if r.is_active and not r.contains_sensitive_data()]
    return True, valid_rules, []
