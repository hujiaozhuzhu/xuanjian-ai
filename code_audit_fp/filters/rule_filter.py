"""
L1: 规则过滤器

基于白名单/黑名单的快速过滤，支持：
- 规则ID过滤
- 文件路径模式匹配
- 代码模式匹配
- 严重程度过滤
"""

import re
from typing import List, Optional, Dict, Any
from .base import BaseFilter
from ..models import ScanResult, FilterResult, FilterReason


class RuleFilter(BaseFilter):
    """规则过滤器"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化规则过滤器
        
        Args:
            config: 配置字典，包含规则配置
        """
        super().__init__(config)
        self.filter_level = "L1"
        
        # 加载规则配置
        self.global_whitelist = self.config.get("global_whitelist", [])
        self.global_blacklist = self.config.get("global_blacklist", [])
        self.rule_whitelist = self.config.get("rule_whitelist", {})
        self.rule_blacklist = self.config.get("rule_blacklist", {})
        
        # 编译正则表达式
        self._compile_patterns()
    
    def _compile_patterns(self):
        """编译正则表达式模式"""
        self._compiled_patterns = {}
        
        # 编译文件路径模式
        for rule in self.global_whitelist + self.global_blacklist:
            if "file_pattern" in rule:
                pattern = rule["file_pattern"]
                # 将glob模式转换为正则表达式
                regex_pattern = pattern.replace(".", r"\.").replace("*", ".*").replace("?", ".")
                self._compiled_patterns[pattern] = re.compile(regex_pattern)
    
    async def filter(self, scan_result: ScanResult) -> FilterResult:
        """
        过滤单条扫描结果
        
        Args:
            scan_result: 扫描结果
            
        Returns:
            FilterResult: 过滤结果
        """
        if not self.enabled:
            return self._create_pass_through_result(scan_result)
        
        # 检查全局白名单
        whitelist_match = self._check_whitelist(scan_result)
        if whitelist_match:
            return self._create_false_positive_result(
                scan_result,
                whitelist_match,
                "L1"
            )
        
        # 检查全局黑名单（强制标记为真实问题）
        blacklist_match = self._check_blacklist(scan_result)
        if blacklist_match:
            return self._create_true_positive_result(
                scan_result,
                blacklist_match,
                "L1"
            )
        
        # 检查规则特定白名单
        rule_whitelist_match = self._check_rule_whitelist(scan_result)
        if rule_whitelist_match:
            return self._create_false_positive_result(
                scan_result,
                rule_whitelist_match,
                "L1"
            )
        
        # 检查规则特定黑名单
        rule_blacklist_match = self._check_rule_blacklist(scan_result)
        if rule_blacklist_match:
            return self._create_true_positive_result(
                scan_result,
                rule_blacklist_match,
                "L1"
            )
        
        # 没有匹配任何规则，传递到下一层
        return self._create_pass_through_result(scan_result)
    
    def _check_whitelist(self, scan_result: ScanResult) -> Optional[Dict[str, Any]]:
        """
        检查全局白名单
        
        Args:
            scan_result: 扫描结果
            
        Returns:
            Optional[Dict]: 匹配的规则，如果没有匹配返回None
        """
        for rule in self.global_whitelist:
            if self._match_rule(scan_result, rule):
                return rule
        return None
    
    def _check_blacklist(self, scan_result: ScanResult) -> Optional[Dict[str, Any]]:
        """
        检查全局黑名单
        
        Args:
            scan_result: 扫描结果
            
        Returns:
            Optional[Dict]: 匹配的规则，如果没有匹配返回None
        """
        for rule in self.global_blacklist:
            if self._match_rule(scan_result, rule):
                return rule
        return None
    
    def _check_rule_whitelist(self, scan_result: ScanResult) -> Optional[Dict[str, Any]]:
        """
        检查规则特定白名单
        
        Args:
            scan_result: 扫描结果
            
        Returns:
            Optional[Dict]: 匹配的规则，如果没有匹配返回None
        """
        rule_id = scan_result.rule_id
        if rule_id in self.rule_whitelist:
            for rule in self.rule_whitelist[rule_id]:
                if self._match_rule(scan_result, rule):
                    return rule
        return None
    
    def _check_rule_blacklist(self, scan_result: ScanResult) -> Optional[Dict[str, Any]]:
        """
        检查规则特定黑名单
        
        Args:
            scan_result: 扫描结果
            
        Returns:
            Optional[Dict]: 匹配的规则，如果没有匹配返回None
        """
        rule_id = scan_result.rule_id
        if rule_id in self.rule_blacklist:
            for rule in self.rule_blacklist[rule_id]:
                if self._match_rule(scan_result, rule):
                    return rule
        return None
    
    def _match_rule(self, scan_result: ScanResult, rule: Dict[str, Any]) -> bool:
        """
        检查扫描结果是否匹配规则
        
        Args:
            scan_result: 扫描结果
            rule: 规则配置
            
        Returns:
            bool: 是否匹配
        """
        # 检查规则ID
        if "rule_id" in rule and rule["rule_id"] != scan_result.rule_id:
            return False
        
        # 检查文件路径模式
        if "file_pattern" in rule:
            pattern = rule["file_pattern"]
            if pattern in self._compiled_patterns:
                if not self._compiled_patterns[pattern].match(scan_result.file):
                    return False
            else:
                # 简单的通配符匹配
                if not self._simple_glob_match(scan_result.file, pattern):
                    return False
        
        # 检查代码模式
        if "code_pattern" in rule:
            try:
                if not re.search(rule["code_pattern"], scan_result.code):
                    return False
            except re.error:
                # 正则表达式无效，跳过此条件
                pass
        
        # 检查严重程度
        if "severity" in rule:
            if isinstance(rule["severity"], list):
                if scan_result.severity.value not in rule["severity"]:
                    return False
            else:
                if scan_result.severity.value != rule["severity"]:
                    return False
        
        # 检查工具
        if "tool" in rule:
            if isinstance(rule["tool"], list):
                if scan_result.tool.value not in rule["tool"]:
                    return False
            else:
                if scan_result.tool.value != rule["tool"]:
                    return False
        
        # 所有条件都匹配
        return True
    
    def _simple_glob_match(self, text: str, pattern: str) -> bool:
        """
        简单的通配符匹配
        
        Args:
            text: 要匹配的文本
            pattern: 通配符模式
            
        Returns:
            bool: 是否匹配
        """
        # 将通配符模式转换为正则表达式
        regex_pattern = pattern.replace(".", r"\.").replace("*", ".*").replace("?", ".")
        regex_pattern = f"^{regex_pattern}$"
        
        try:
            return bool(re.match(regex_pattern, text))
        except re.error:
            return False
    
    def _create_false_positive_result(
        self,
        scan_result: ScanResult,
        rule: Dict[str, Any],
        filter_level: str
    ) -> FilterResult:
        """
        创建误报结果
        
        Args:
            scan_result: 扫描结果
            rule: 匹配的规则
            filter_level: 过滤层级
            
        Returns:
            FilterResult: 过滤结果
        """
        reason = rule.get("reason", "匹配白名单规则")
        confidence = rule.get("confidence", 0.9)
        
        return FilterResult(
            original=scan_result,
            is_false_positive=True,
            confidence=confidence,
            filter_reasons=[
                FilterReason(
                    filter_level=filter_level,
                    rule_name="whitelist_rule",
                    description=reason,
                    confidence=confidence
                )
            ],
            risk_score=self._calculate_risk_score(scan_result, True, confidence),
            recommendation=self._generate_recommendation(scan_result, True, confidence, 0)
        )
    
    def _create_true_positive_result(
        self,
        scan_result: ScanResult,
        rule: Dict[str, Any],
        filter_level: str
    ) -> FilterResult:
        """
        创建真实问题结果
        
        Args:
            scan_result: 扫描结果
            rule: 匹配的规则
            filter_level: 过滤层级
            
        Returns:
            FilterResult: 过滤结果
        """
        reason = rule.get("reason", "匹配黑名单规则")
        confidence = rule.get("confidence", 0.9)
        
        return FilterResult(
            original=scan_result,
            is_false_positive=False,
            confidence=confidence,
            filter_reasons=[
                FilterReason(
                    filter_level=filter_level,
                    rule_name="blacklist_rule",
                    description=reason,
                    confidence=confidence
                )
            ],
            risk_score=self._calculate_risk_score(scan_result, False, confidence),
            recommendation=self._generate_recommendation(scan_result, False, confidence, 0)
        )
    
    def _create_pass_through_result(self, scan_result: ScanResult) -> FilterResult:
        """
        创建传递结果（未匹配任何规则）
        
        Args:
            scan_result: 扫描结果
            
        Returns:
            FilterResult: 过滤结果
        """
        return FilterResult(
            original=scan_result,
            is_false_positive=False,
            confidence=0.5,
            filter_reasons=[],
            risk_score=self._calculate_risk_score(scan_result, False, 0.5),
            recommendation="未匹配任何规则，传递到下一层过滤器"
        )