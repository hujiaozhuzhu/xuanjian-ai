"""
L2: 上下文过滤器

基于代码上下文分析，识别：
- 死代码路径
- 安全守卫措施
- 输入验证逻辑
- 数据流分析
"""

import ast
import re
from typing import List, Optional, Dict, Any, Set
from pathlib import Path
from .base import BaseFilter
from ..models import ScanResult, FilterResult, FilterReason, ContextAnalysisResult


class ContextFilter(BaseFilter):
    """上下文过滤器"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化上下文过滤器
        
        Args:
            config: 配置字典
        """
        super().__init__(config)
        self.filter_level = "L2"
        
        # 安全守卫关键词
        self.security_guard_keywords = self.config.get(
            "security_guard_keywords",
            [
                "sanitize", "escape", "validate", "verify", "check",
                "clean", "purify", "encode", "decode", "hash",
                "encrypt", "decrypt", "sign", "verify", "authorize",
                "authenticate", "permission", "role", "access"
            ]
        )
        
        # 输入验证关键词
        self.input_validation_keywords = self.config.get(
            "input_validation_keywords",
            [
                "isinstance", "type", "len", "range", "min", "max",
                "assert", "raise", "ValueError", "TypeError", "invalid",
                "format", "strip", "lstrip", "rstrip", "replace"
            ]
        )
        
        # 死代码模式
        self.dead_code_patterns = self.config.get(
            "dead_code_patterns",
            [
                r"if\s+False\s*:",
                r"if\s+0\s*:",
                r"#.*TODO.*remove",
                r"#.*FIXME.*dead",
                r"pass\s*$",
                r"\.\.\.\s*$"
            ]
        )
        
        # 缓存文件内容
        self._file_cache: Dict[str, str] = {}
        self._ast_cache: Dict[str, ast.AST] = {}
    
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
        
        # 分析上下文
        context_analysis = await self._analyze_context(scan_result)
        
        # 根据上下文分析结果判断是否为误报
        is_false_positive, confidence, reasons = self._evaluate_context(
            scan_result, context_analysis
        )
        
        if is_false_positive:
            return FilterResult(
                original=scan_result,
                is_false_positive=True,
                confidence=confidence,
                filter_reasons=reasons,
                risk_score=self._calculate_risk_score(scan_result, True, confidence),
                recommendation=self._generate_recommendation(scan_result, True, confidence, 0),
                context_analysis=context_analysis.model_dump()
            )
        else:
            return FilterResult(
                original=scan_result,
                is_false_positive=False,
                confidence=confidence,
                filter_reasons=reasons,
                risk_score=self._calculate_risk_score(scan_result, False, confidence),
                recommendation=self._generate_recommendation(scan_result, False, confidence, 0),
                context_analysis=context_analysis.model_dump()
            )
    
    async def _analyze_context(self, scan_result: ScanResult) -> ContextAnalysisResult:
        """
        分析代码上下文
        
        Args:
            scan_result: 扫描结果
            
        Returns:
            ContextAnalysisResult: 上下文分析结果
        """
        file_path = scan_result.file
        line_number = scan_result.line
        
        # 读取文件内容
        file_content = await self._read_file(file_path)
        if file_content is None:
            return ContextAnalysisResult(
                file_path=file_path,
                line_number=line_number,
                context_features={"error": "无法读取文件"}
            )
        
        # 获取上下文行
        lines = file_content.split('\n')
        context_start = max(0, line_number - 11)  # 前10行
        context_end = min(len(lines), line_number + 10)  # 后10行
        context_lines = lines[context_start:context_end]
        
        # 分析上下文特征
        is_dead_code = self._detect_dead_code(file_content, line_number)
        has_security_guards = self._detect_security_guards(context_lines)
        has_input_validation = self._detect_input_validation(context_lines)
        data_flow_length = self._analyze_data_flow(file_content, line_number)
        complexity_score = self._calculate_complexity(file_content, line_number)
        
        return ContextAnalysisResult(
            file_path=file_path,
            line_number=line_number,
            is_dead_code=is_dead_code,
            has_security_guards=has_security_guards,
            has_input_validation=has_input_validation,
            data_flow_length=data_flow_length,
            complexity_score=complexity_score,
            context_features={
                "context_lines": context_lines,
                "guard_keywords_found": self._find_guard_keywords(context_lines),
                "validation_keywords_found": self._find_validation_keywords(context_lines)
            }
        )
    
    async def _read_file(self, file_path: str) -> Optional[str]:
        """
        读取文件内容
        
        Args:
            file_path: 文件路径
            
        Returns:
            Optional[str]: 文件内容，如果读取失败返回None
        """
        if file_path in self._file_cache:
            return self._file_cache[file_path]
        
        try:
            # 尝试读取文件
            path = Path(file_path)
            if path.exists():
                content = path.read_text(encoding='utf-8')
                self._file_cache[file_path] = content
                return content
        except Exception:
            pass
        
        return None
    
    def _detect_dead_code(self, file_content: str, line_number: int) -> bool:
        """
        检测死代码
        
        Args:
            file_content: 文件内容
            line_number: 行号
            
        Returns:
            bool: 是否为死代码
        """
        lines = file_content.split('\n')
        if line_number > len(lines):
            return False
        
        # 获取当前行和周围行
        start_line = max(0, line_number - 5)
        end_line = min(len(lines), line_number + 5)
        context = '\n'.join(lines[start_line:end_line])
        
        # 检查死代码模式
        for pattern in self.dead_code_patterns:
            if re.search(pattern, context, re.MULTILINE):
                return True
        
        # 检查是否在注释中
        current_line = lines[line_number - 1].strip()
        if current_line.startswith('#') or current_line.startswith('//'):
            return True
        
        # 检查是否在字符串中（简单检测）
        if current_line.count('"') % 2 != 0 or current_line.count("'") % 2 != 0:
            # 引号不匹配，可能在字符串中
            pass
        
        return False
    
    def _detect_security_guards(self, context_lines: List[str]) -> bool:
        """
        检测安全守卫
        
        Args:
            context_lines: 上下文行
            
        Returns:
            bool: 是否有安全守卫
        """
        context_text = '\n'.join(context_lines).lower()
        
        for keyword in self.security_guard_keywords:
            if keyword.lower() in context_text:
                return True
        
        return False
    
    def _detect_input_validation(self, context_lines: List[str]) -> bool:
        """
        检测输入验证
        
        Args:
            context_lines: 上下文行
            
        Returns:
            bool: 是否有输入验证
        """
        context_text = '\n'.join(context_lines).lower()
        
        for keyword in self.input_validation_keywords:
            if keyword.lower() in context_text:
                return True
        
        return False
    
    def _analyze_data_flow(self, file_content: str, line_number: int) -> int:
        """
        分析数据流
        
        Args:
            file_content: 文件内容
            line_number: 行号
            
        Returns:
            int: 数据流长度（简化实现）
        """
        # 简化实现：返回从函数开始到当前行的行数差
        lines = file_content.split('\n')
        if line_number > len(lines):
            return 0
        
        # 向上查找函数定义
        for i in range(line_number - 1, max(-1, line_number - 50), -1):
            line = lines[i].strip()
            if line.startswith('def ') or line.startswith('function ') or line.startswith('func '):
                return line_number - i - 1
        
        return line_number - 1
    
    def _calculate_complexity(self, file_content: str, line_number: int) -> float:
        """
        计算代码复杂度
        
        Args:
            file_content: 文件内容
            line_number: 行号
            
        Returns:
            float: 复杂度评分 0-10
        """
        lines = file_content.split('\n')
        if line_number > len(lines):
            return 5.0
        
        # 获取函数上下文
        start_line = max(0, line_number - 20)
        end_line = min(len(lines), line_number + 20)
        context = '\n'.join(lines[start_line:end_line])
        
        complexity = 0.0
        
        # 控制流语句增加复杂度
        control_keywords = ['if', 'else', 'elif', 'for', 'while', 'switch', 'case', 'try', 'except', 'catch']
        for keyword in control_keywords:
            complexity += context.count(keyword) * 0.5
        
        # 嵌套深度增加复杂度
        indent_levels = []
        for line in lines[start_line:end_line]:
            if line.strip():
                indent = len(line) - len(line.lstrip())
                indent_levels.append(indent)
        
        if indent_levels:
            max_indent = max(indent_levels)
            complexity += max_indent / 4  # 每4个空格增加1点复杂度
        
        # 限制在0-10范围内
        return min(10.0, max(0.0, complexity))
    
    def _find_guard_keywords(self, context_lines: List[str]) -> List[str]:
        """
        查找安全守卫关键词
        
        Args:
            context_lines: 上下文行
            
        Returns:
            List[str]: 找到的关键词列表
        """
        found_keywords = []
        context_text = '\n'.join(context_lines).lower()
        
        for keyword in self.security_guard_keywords:
            if keyword.lower() in context_text:
                found_keywords.append(keyword)
        
        return found_keywords
    
    def _find_validation_keywords(self, context_lines: List[str]) -> List[str]:
        """
        查找输入验证关键词
        
        Args:
            context_lines: 上下文行
            
        Returns:
            List[str]: 找到的关键词列表
        """
        found_keywords = []
        context_text = '\n'.join(context_lines).lower()
        
        for keyword in self.input_validation_keywords:
            if keyword.lower() in context_text:
                found_keywords.append(keyword)
        
        return found_keywords
    
    def _evaluate_context(
        self,
        scan_result: ScanResult,
        context_analysis: ContextAnalysisResult
    ) -> tuple:
        """
        评估上下文分析结果
        
        Args:
            scan_result: 扫描结果
            context_analysis: 上下文分析结果
            
        Returns:
            tuple: (is_false_positive, confidence, reasons)
        """
        reasons = []
        false_positive_score = 0.0
        
        # 死代码检测
        if context_analysis.is_dead_code:
            false_positive_score += 0.8
            reasons.append(FilterReason(
                filter_level=self.filter_level,
                rule_name="dead_code_detection",
                description="代码在死代码路径中，不可达",
                confidence=0.8
            ))
        
        # 安全守卫检测
        if context_analysis.has_security_guards:
            false_positive_score += 0.6
            guard_keywords = context_analysis.context_features.get("guard_keywords_found", [])
            reasons.append(FilterReason(
                filter_level=self.filter_level,
                rule_name="security_guard_detection",
                description=f"检测到安全守卫措施: {', '.join(guard_keywords)}",
                confidence=0.6
            ))
        
        # 输入验证检测
        if context_analysis.has_input_validation:
            false_positive_score += 0.4
            validation_keywords = context_analysis.context_features.get("validation_keywords_found", [])
            reasons.append(FilterReason(
                filter_level=self.filter_level,
                rule_name="input_validation_detection",
                description=f"检测到输入验证: {', '.join(validation_keywords)}",
                confidence=0.4
            ))
        
        # 数据流长度分析
        if context_analysis.data_flow_length > 10:
            false_positive_score += 0.2
            reasons.append(FilterReason(
                filter_level=self.filter_level,
                rule_name="data_flow_analysis",
                description=f"数据流长度较长({context_analysis.data_flow_length})，可能经过验证",
                confidence=0.2
            ))
        
        # 复杂度分析
        if context_analysis.complexity_score > 7.0:
            false_positive_score += 0.1
            reasons.append(FilterReason(
                filter_level=self.filter_level,
                rule_name="complexity_analysis",
                description=f"代码复杂度较高({context_analysis.complexity_score})，需要仔细分析",
                confidence=0.1
            ))
        
        # 判断是否为误报
        # 阈值可配置
        threshold = self.config.get("false_positive_threshold", 0.5)
        is_false_positive = false_positive_score >= threshold
        confidence = min(1.0, false_positive_score)
        
        return is_false_positive, confidence, reasons
    
    def _create_pass_through_result(self, scan_result: ScanResult) -> FilterResult:
        """
        创建传递结果
        
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
            recommendation="上下文分析未发现明显误报特征，传递到下一层过滤器"
        )