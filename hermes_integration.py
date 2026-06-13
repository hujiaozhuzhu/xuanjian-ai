#!/usr/bin/env python3
"""
Hermes Agent集成示例

展示如何在Hermes Agent中使用代码审计误报过滤MCP技能
"""

import asyncio
import json
from typing import Dict, Any, List


class HermesCodeAuditIntegration:
    """Hermes Agent代码审计集成"""
    
    def __init__(self):
        """初始化集成"""
        self.mcp_server = None
        self.config = {
            "rule_filter": {
                "enabled": True,
                "global_whitelist": [
                    {
                        "file_pattern": "*/test/*",
                        "reason": "测试代码",
                        "confidence": 0.9
                    }
                ]
            },
            "context_filter": {
                "enabled": True,
                "false_positive_threshold": 0.5
            },
            "ml_filter": {
                "enabled": True,
                "confidence_threshold": 0.7
            }
        }
    
    async def initialize(self):
        """初始化MCP服务器"""
        from code_audit_fp import create_server
        
        self.mcp_server = create_server()
        print("代码审计误报过滤MCP服务器已初始化")
    
    async def scan_and_filter(
        self,
        target_path: str,
        scan_tools: List[str] = ["semgrep"],
        filter_level: str = "all"
    ) -> Dict[str, Any]:
        """
        扫描并过滤代码
        
        Args:
            target_path: 目标路径
            scan_tools: 扫描工具列表
            filter_level: 过滤层级
            
        Returns:
            Dict[str, Any]: 扫描和过滤结果
        """
        if not self.mcp_server:
            await self.initialize()
        
        # 模拟扫描结果（实际应用中会调用真实的扫描工具）
        scan_results = await self._simulate_scan(target_path, scan_tools)
        
        # 应用过滤
        filtered_results = []
        for result in scan_results:
            filter_result = await self.mcp_server._apply_filters(
                result, filter_level, 0.7
            )
            filtered_results.append(filter_result)
        
        # 计算统计信息
        statistics = self.mcp_server._calculate_statistics(filtered_results)
        
        return {
            "scan_results": scan_results,
            "filtered_results": filtered_results,
            "statistics": statistics,
            "summary": {
                "total_issues": statistics.total,
                "false_positives": statistics.false_positives,
                "true_positives": statistics.true_positives,
                "reduction_rate": statistics.reduction_rate
            }
        }
    
    async def _simulate_scan(
        self,
        target_path: str,
        scan_tools: List[str]
    ) -> List[Dict[str, Any]]:
        """
        模拟扫描（实际应用中会调用真实的扫描工具）
        
        Args:
            target_path: 目标路径
            scan_tools: 扫描工具列表
            
        Returns:
            List[Dict[str, Any]]: 模拟的扫描结果
        """
        # 模拟的扫描结果
        mock_results = [
            {
                "tool": "semgrep",
                "rule_id": "python.lang.security.injection.sql-injection",
                "file": f"{target_path}/app/database.py",
                "line": 42,
                "code": "cursor.execute(user_input)",
                "severity": "ERROR",
                "message": "SQL injection vulnerability"
            },
            {
                "tool": "semgrep",
                "rule_id": "python.lang.security.injection.sql-injection",
                "file": f"{target_path}/tests/test_database.py",
                "line": 15,
                "code": "cursor.execute(mock_input)",
                "severity": "ERROR",
                "message": "SQL injection vulnerability"
            },
            {
                "tool": "bandit",
                "rule_id": "B608",
                "file": f"{target_path}/app/query.py",
                "line": 25,
                "code": "query = f'SELECT * FROM users WHERE id = {user_id}'",
                "severity": "WARNING",
                "message": "Possible SQL injection vector"
            },
            {
                "tool": "semgrep",
                "rule_id": "python.lang.security.injection.command-injection",
                "file": f"{target_path}/app/utils.py",
                "line": 10,
                "code": "os.system(user_command)",
                "severity": "ERROR",
                "message": "Command injection vulnerability"
            }
        ]
        
        return mock_results
    
    async def analyze_specific_issue(
        self,
        file_path: str,
        line_number: int
    ) -> Dict[str, Any]:
        """
        分析特定问题
        
        Args:
            file_path: 文件路径
            line_number: 行号
            
        Returns:
            Dict[str, Any]: 分析结果
        """
        if not self.mcp_server:
            await self.initialize()
        
        # 创建模拟的扫描结果
        from code_audit_fp.models import ScanResult
        
        scan_result = ScanResult(
            tool="semgrep",
            rule_id="manual_analysis",
            file=file_path,
            line=line_number,
            code="",
            severity="WARNING",
            message="手动分析"
        )
        
        # 分析上下文
        context_result = await self.mcp_server.context_filter._analyze_context(scan_result)
        
        return {
            "file_path": file_path,
            "line_number": line_number,
            "context_analysis": context_result.model_dump(),
            "recommendations": self._generate_recommendations(context_result)
        }
    
    def _generate_recommendations(self, context_result) -> List[str]:
        """
        生成建议
        
        Args:
            context_result: 上下文分析结果
            
        Returns:
            List[str]: 建议列表
        """
        recommendations = []
        
        if context_result.is_dead_code:
            recommendations.append("代码在死代码路径中，可以安全忽略")
        
        if context_result.has_security_guards:
            recommendations.append("检测到安全守卫措施，可能已经防护")
        
        if context_result.has_input_validation:
            recommendations.append("检测到输入验证，可能已经防护")
        
        if context_result.complexity_score > 7.0:
            recommendations.append("代码复杂度较高，建议仔细审查")
        
        if not recommendations:
            recommendations.append("未发现明显误报特征，建议人工确认")
        
        return recommendations


async def main():
    """主函数"""
    print("Hermes Agent代码审计集成示例")
    print("=" * 50)
    
    # 创建集成实例
    integration = HermesCodeAuditIntegration()
    
    # 示例1：扫描并过滤
    print("\n1. 扫描并过滤代码:")
    result = await integration.scan_and_filter(
        target_path="/path/to/project",
        scan_tools=["semgrep", "bandit"],
        filter_level="all"
    )
    
    print(f"总问题数: {result['summary']['total_issues']}")
    print(f"误报数: {result['summary']['false_positives']}")
    print(f"真实问题数: {result['summary']['true_positives']}")
    print(f"误报减少率: {result['summary']['reduction_rate']}")
    
    # 示例2：分析特定问题
    print("\n2. 分析特定问题:")
    analysis = await integration.analyze_specific_issue(
        file_path="/path/to/project/app/database.py",
        line_number=42
    )
    
    print(f"文件: {analysis['file_path']}")
    print(f"行号: {analysis['line_number']}")
    print(f"是否死代码: {analysis['context_analysis']['is_dead_code']}")
    print(f"是否有安全守卫: {analysis['context_analysis']['has_security_guards']}")
    print(f"建议:")
    for rec in analysis['recommendations']:
        print(f"  - {rec}")
    
    print("\n" + "=" * 50)
    print("集成示例完成！")


if __name__ == "__main__":
    asyncio.run(main())