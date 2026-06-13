"""
过滤器基类

定义所有过滤器的通用接口和基础功能
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from ..models import ScanResult, FilterResult, FilterReason


class BaseFilter(ABC):
    """过滤器基类"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化过滤器
        
        Args:
            config: 配置字典
        """
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
    
    @abstractmethod
    async def filter(self, scan_result: ScanResult) -> FilterResult:
        """
        过滤单条扫描结果
        
        Args:
            scan_result: 扫描结果
            
        Returns:
            FilterResult: 过滤结果
        """
        pass
    
    async def filter_batch(self, scan_results: List[ScanResult]) -> List[FilterResult]:
        """
        批量过滤扫描结果
        
        Args:
            scan_results: 扫描结果列表
            
        Returns:
            List[FilterResult]: 过滤结果列表
        """
        results = []
        for scan_result in scan_results:
            try:
                result = await self.filter(scan_result)
                results.append(result)
            except Exception as e:
                # 如果过滤失败，保留原始结果
                result = FilterResult(
                    original=scan_result,
                    is_false_positive=False,
                    confidence=0.5,
                    filter_reasons=[
                        FilterReason(
                            filter_level="L1",  # 默认层级
                            rule_name="filter_error",
                            description=f"过滤器执行失败: {str(e)}",
                            confidence=0.0
                        )
                    ],
                    risk_score=5.0,
                    recommendation="过滤器执行失败，建议人工审核"
                )
                results.append(result)
        return results
    
    def _create_filter_reason(
        self,
        filter_level: str,
        rule_name: str,
        description: str,
        confidence: float
    ) -> FilterReason:
        """
        创建过滤原因
        
        Args:
            filter_level: 过滤层级
            rule_name: 规则名称
            description: 描述
            confidence: 置信度
            
        Returns:
            FilterReason: 过滤原因
        """
        return FilterReason(
            filter_level=filter_level,
            rule_name=rule_name,
            description=description,
            confidence=confidence
        )
    
    def _calculate_risk_score(
        self,
        scan_result: ScanResult,
        is_false_positive: bool,
        confidence: float
    ) -> float:
        """
        计算风险评分
        
        Args:
            scan_result: 扫描结果
            is_false_positive: 是否为误报
            confidence: 置信度
            
        Returns:
            float: 风险评分 0-10
        """
        # 基础风险分
        base_score = {
            "ERROR": 9.0,
            "WARNING": 6.0,
            "INFO": 3.0
        }.get(scan_result.severity.value, 5.0)
        
        # 如果是误报，降低风险分
        if is_false_positive:
            # 根据置信度调整，置信度越高，风险分越低
            return base_score * (1 - confidence * 0.8)
        else:
            # 真实问题，根据置信度调整
            return base_score * confidence
    
    def _generate_recommendation(
        self,
        scan_result: ScanResult,
        is_false_positive: bool,
        confidence: float,
        risk_score: float
    ) -> str:
        """
        生成处理建议
        
        Args:
            scan_result: 扫描结果
            is_false_positive: 是否为误报
            confidence: 置信度
            risk_score: 风险评分
            
        Returns:
            str: 处理建议
        """
        if is_false_positive:
            if confidence > 0.9:
                return "高置信度误报，建议忽略"
            elif confidence > 0.7:
                return "中等置信度误报，建议快速确认后忽略"
            else:
                return "低置信度误报，建议人工确认"
        
        # 真实问题的建议
        if risk_score >= 8.0:
            return "高风险漏洞，建议立即修复"
        elif risk_score >= 6.0:
            return "中风险漏洞，建议尽快修复"
        elif risk_score >= 4.0:
            return "低风险漏洞，建议计划修复"
        else:
            return "信息性问题，建议代码审查时关注"