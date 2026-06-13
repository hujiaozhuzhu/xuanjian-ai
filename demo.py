#!/usr/bin/env python3
"""
快速演示脚本

展示代码审计误报过滤MCP技能的核心功能
"""

import asyncio
import json


async def demo():
    """演示主函数"""
    print("🔍 代码审计误报过滤MCP技能演示")
    print("=" * 60)
    
    # 1. 导入模块
    print("\n1. 导入模块...")
    try:
        from code_audit_fp import create_server
        from code_audit_fp.models import ScanResult
        print("   ✅ 模块导入成功")
    except ImportError as e:
        print(f"   ❌ 模块导入失败: {e}")
        print("   请先安装依赖: pip install -r requirements.txt")
        return
    
    # 2. 创建服务器
    print("\n2. 创建服务器...")
    try:
        server = create_server()
        print("   ✅ 服务器创建成功")
    except Exception as e:
        print(f"   ❌ 服务器创建失败: {e}")
        return
    
    # 3. 准备测试数据
    print("\n3. 准备测试数据...")
    test_cases = [
        {
            "name": "真实SQL注入漏洞",
            "data": ScanResult(
                tool="semgrep",
                rule_id="python.lang.security.injection.sql-injection",
                file="app/database.py",
                line=42,
                code="cursor.execute(user_input)",
                severity="ERROR",
                message="SQL injection vulnerability"
            )
        },
        {
            "name": "测试代码中的模拟调用",
            "data": ScanResult(
                tool="semgrep",
                rule_id="python.lang.security.injection.sql-injection",
                file="tests/test_database.py",
                line=15,
                code="cursor.execute(mock_input)",
                severity="ERROR",
                message="SQL injection vulnerability"
            )
        },
        {
            "name": "有安全守卫的代码",
            "data": ScanResult(
                tool="semgrep",
                rule_id="python.lang.security.injection.sql-injection",
                file="app/secure_query.py",
                line=30,
                code="cursor.execute(sanitize_input(user_input))",
                severity="ERROR",
                message="SQL injection vulnerability"
            )
        },
        {
            "name": "可能的误报",
            "data": ScanResult(
                tool="bandit",
                rule_id="B608",
                file="app/report.py",
                line=45,
                "code": "query = f'SELECT * FROM users WHERE id = {user_id}'",
                severity="WARNING",
                message="Possible SQL injection vector"
            )
        }
    ]
    print(f"   ✅ 准备了 {len(test_cases)} 个测试用例")
    
    # 4. 运行过滤
    print("\n4. 运行三层过滤...")
    results = []
    for test_case in test_cases:
        print(f"\n   测试: {test_case['name']}")
        print(f"   文件: {test_case['data'].file}:{test_case['data'].line}")
        print(f"   代码: {test_case['data'].code[:50]}...")
        
        # 应用过滤
        result = await server._apply_filters(test_case['data'], "all", 0.7)
        results.append(result)
        
        # 显示结果
        status = "🚫 误报" if result.is_false_positive else "✅ 真实问题"
        print(f"   结果: {status}")
        print(f"   置信度: {result.confidence:.2%}")
        print(f"   风险评分: {result.risk_score:.1f}/10")
        print(f"   建议: {result.recommendation}")
        
        if result.filter_reasons:
            print("   过滤原因:")
            for reason in result.filter_reasons:
                print(f"     - [{reason.filter_level}] {reason.description}")
    
    # 5. 统计信息
    print("\n5. 统计信息:")
    statistics = server._calculate_statistics(results)
    print(f"   总问题数: {statistics.total}")
    print(f"   误报数: {statistics.false_positives}")
    print(f"   真实问题数: {statistics.true_positives}")
    print(f"   误报减少率: {statistics.reduction_rate}")
    
    # 6. 性能测试
    print("\n6. 性能测试...")
    import time
    
    # 批量处理测试
    batch_size = 100
    test_batch = [test_cases[0]['data']] * batch_size
    
    start_time = time.time()
    for result in test_batch:
        await server._apply_filters(result, "all", 0.7)
    end_time = time.time()
    
    total_time = end_time - start_time
    throughput = batch_size / total_time
    
    print(f"   批量处理 {batch_size} 条结果")
    print(f"   总时间: {total_time:.2f} 秒")
    print(f"   吞吐量: {throughput:.0f} 条/秒")
    
    # 7. 配置信息
    print("\n7. 当前配置:")
    print(f"   规则过滤: {'启用' if server.rule_filter.enabled else '禁用'}")
    print(f"   上下文过滤: {'启用' if server.context_filter.enabled else '禁用'}")
    print(f"   ML过滤: {'启用' if server.ml_filter.enabled else '禁用'}")
    
    if server.ml_filter.model:
        print(f"   ML模型: 已加载")
    elif server.ml_filter.onnx_session:
        print(f"   ONNX模型: 已加载")
    else:
        print(f"   ML模型: 未加载（使用启发式规则）")
    
    # 8. 使用建议
    print("\n8. 使用建议:")
    print("   • 对于测试代码，建议配置白名单规则")
    print("   • 对于有安全守卫的代码，上下文过滤器会自动识别")
    print("   • 建议训练自定义ML模型以提高准确性")
    print("   • 定期更新规则配置以适应新的代码模式")
    
    print("\n" + "=" * 60)
    print("演示完成！")
    print("\n下一步:")
    print("1. 查看 README.md 了解详细使用方法")
    print("2. 查看 USAGE_GUIDE.md 了解集成指南")
    print("3. 运行 python example.py 查看更多示例")
    print("4. 运行 python -m pytest test_example.py 运行测试")


if __name__ == "__main__":
    asyncio.run(demo())