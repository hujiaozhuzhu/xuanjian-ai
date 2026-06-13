#!/usr/bin/env python3
"""
示例脚本：展示如何使用代码审计误报过滤MCP技能
"""

import asyncio
import json
from code_audit_fp import create_server


async def example_basic_usage():
    """基本使用示例"""
    print("=== 基本使用示例 ===")
    
    # 创建服务器实例
    server = create_server()
    
    # 模拟扫描结果
    scan_results = [
        {
            "tool": "semgrep",
            "rule_id": "python.lang.security.injection.sql-injection",
            "file": "app/database.py",
            "line": 42,
            "code": "cursor.execute(user_input)",
            "severity": "ERROR",
            "message": "SQL injection vulnerability"
        },
        {
            "tool": "semgrep",
            "rule_id": "python.lang.security.injection.sql-injection",
            "file": "tests/test_database.py",
            "line": 15,
            "code": "cursor.execute(mock_input)",
            "severity": "ERROR",
            "message": "SQL injection vulnerability"
        },
        {
            "tool": "bandit",
            "rule_id": "B608",
            "file": "app/query.py",
            "line": 25,
            "code": "query = f'SELECT * FROM users WHERE id = {user_id}'",
            "severity": "WARNING",
            "message": "Possible SQL injection vector through string-based query construction"
        }
    ]
    
    # 调用过滤工具
    # 注意：这里直接调用内部方法，实际使用应通过MCP客户端
    filtered_results = []
    for result in scan_results:
        from code_audit_fp.models import ScanResult
        scan_result = ScanResult(**result)
        filter_result = await server._apply_filters(scan_result, "all", 0.7)
        filtered_results.append(filter_result)
    
    # 输出结果
    for result in filtered_results:
        print(f"\n文件: {result.original.file}:{result.original.line}")
        print(f"规则: {result.original.rule_id}")
        print(f"是否误报: {result.is_false_positive}")
        print(f"置信度: {result.confidence:.2f}")
        print(f"风险评分: {result.risk_score:.2f}")
        print(f"建议: {result.recommendation}")
        
        if result.filter_reasons:
            print("过滤原因:")
            for reason in result.filter_reasons:
                print(f"  - [{reason.filter_level}] {reason.description}")


async def example_context_analysis():
    """上下文分析示例"""
    print("\n=== 上下文分析示例 ===")
    
    server = create_server()
    
    # 分析特定代码位置
    # 注意：这里需要实际文件存在
    try:
        context_result = await server.context_filter._analyze_context(
            ScanResult(
                tool="semgrep",
                rule_id="manual_analysis",
                file="code_audit_fp/server.py",  # 使用项目自身文件作为示例
                line=50,
                code="",
                severity="WARNING",
                message="手动分析"
            )
        )
        
        print(f"文件: {context_result.file_path}")
        print(f"行号: {context_result.line_number}")
        print(f"是否死代码: {context_result.is_dead_code}")
        print(f"是否有安全守卫: {context_result.has_security_guards}")
        print(f"是否有输入验证: {context_result.has_input_validation}")
        print(f"数据流长度: {context_result.data_flow_length}")
        print(f"复杂度评分: {context_result.complexity_score:.2f}")
        
    except Exception as e:
        print(f"上下文分析失败: {e}")


async def example_training_data():
    """训练数据示例"""
    print("\n=== 训练数据示例 ===")
    
    # 示例训练数据
    training_data = [
        {
            "features": {
                "rule_confidence": 0.9,
                "severity_score": 1.0,
                "code_complexity": 0.6,
                "data_flow_length": 5,
                "has_security_guards": 0.0,
                "has_input_validation": 0.0,
                "is_test_code": 0.0,
                "file_depth": 3,
                "line_count": 1
            },
            "is_false_positive": False
        },
        {
            "features": {
                "rule_confidence": 0.9,
                "severity_score": 1.0,
                "code_complexity": 0.3,
                "data_flow_length": 2,
                "has_security_guards": 1.0,
                "has_input_validation": 1.0,
                "is_test_code": 1.0,
                "file_depth": 4,
                "line_count": 1
            },
            "is_false_positive": True
        }
    ]
    
    print("训练数据示例:")
    for i, data in enumerate(training_data):
        print(f"  样本 {i+1}:")
        print(f"    特征: {data['features']}")
        print(f"    标签: {'误报' if data['is_false_positive'] else '真实问题'}")


async def main():
    """主函数"""
    print("代码审计误报过滤MCP技能示例")
    print("=" * 50)
    
    await example_basic_usage()
    await example_context_analysis()
    await example_training_data()
    
    print("\n" + "=" * 50)
    print("示例完成！")
    print("\n要运行MCP服务器，请执行:")
    print("  python main.py --transport stdio")
    print("或")
    print("  python main.py --transport sse --port 8000")


if __name__ == "__main__":
    asyncio.run(main())