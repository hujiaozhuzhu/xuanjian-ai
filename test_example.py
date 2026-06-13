#!/usr/bin/env python3
"""
测试代码审计误报过滤MCP技能
"""

import asyncio
import pytest
from code_audit_fp import create_server
from code_audit_fp.models import ScanResult, FilterResult


@pytest.fixture
def server():
    """创建服务器实例"""
    return create_server()


@pytest.fixture
def sample_scan_results():
    """示例扫描结果"""
    return [
        ScanResult(
            tool="semgrep",
            rule_id="python.lang.security.injection.sql-injection",
            file="app/database.py",
            line=42,
            code="cursor.execute(user_input)",
            severity="ERROR",
            message="SQL injection vulnerability"
        ),
        ScanResult(
            tool="semgrep",
            rule_id="python.lang.security.injection.sql-injection",
            file="tests/test_database.py",
            line=15,
            code="cursor.execute(mock_input)",
            severity="ERROR",
            message="SQL injection vulnerability"
        ),
        ScanResult(
            tool="bandit",
            rule_id="B608",
            file="app/query.py",
            line=25,
            code="query = f'SELECT * FROM users WHERE id = {user_id}'",
            severity="WARNING",
            message="Possible SQL injection vector"
        )
    ]


@pytest.mark.asyncio
async def test_rule_filter(server, sample_scan_results):
    """测试规则过滤器"""
    # 测试白名单规则
    test_result = sample_scan_results[1]  # 测试文件中的结果
    
    # 应用规则过滤
    filter_result = await server.rule_filter.filter(test_result)
    
    # 验证结果
    assert isinstance(filter_result, FilterResult)
    assert filter_result.original == test_result


@pytest.mark.asyncio
async def test_context_filter(server, sample_scan_results):
    """测试上下文过滤器"""
    # 测试上下文分析
    result = sample_scan_results[0]
    
    # 应用上下文过滤
    filter_result = await server.context_filter.filter(result)
    
    # 验证结果
    assert isinstance(filter_result, FilterResult)
    assert filter_result.original == result


@pytest.mark.asyncio
async def test_ml_filter(server, sample_scan_results):
    """测试ML过滤器"""
    # 测试ML过滤
    result = sample_scan_results[0]
    
    # 应用ML过滤
    filter_result = await server.ml_filter.filter(result)
    
    # 验证结果
    assert isinstance(filter_result, FilterResult)
    assert filter_result.original == result


@pytest.mark.asyncio
async def test_full_filter_pipeline(server, sample_scan_results):
    """测试完整过滤流水线"""
    # 测试完整过滤流程
    for result in sample_scan_results:
        filter_result = await server._apply_filters(result, "all", 0.7)
        
        # 验证结果
        assert isinstance(filter_result, FilterResult)
        assert filter_result.original == result
        assert isinstance(filter_result.is_false_positive, bool)
        assert 0 <= filter_result.confidence <= 1
        assert 0 <= filter_result.risk_score <= 10


@pytest.mark.asyncio
async def test_statistics_calculation(server, sample_scan_results):
    """测试统计信息计算"""
    # 应用过滤
    results = []
    for result in sample_scan_results:
        filter_result = await server._apply_filters(result, "all", 0.7)
        results.append(filter_result)
    
    # 计算统计信息
    statistics = server._calculate_statistics(results)
    
    # 验证统计信息
    assert statistics.total == len(sample_scan_results)
    assert statistics.false_positives + statistics.true_positives == statistics.total
    assert statistics.reduction_rate.endswith("%")


def test_model_loading():
    """测试模型加载"""
    # 测试默认配置下的模型加载
    server = create_server()
    
    # 验证过滤器初始化
    assert server.rule_filter is not None
    assert server.context_filter is not None
    assert server.ml_filter is not None


def test_config_loading():
    """测试配置加载"""
    # 测试默认配置
    server = create_server()
    
    # 验证配置
    assert "rule_filter" in server.config
    assert "context_filter" in server.config
    assert "ml_filter" in server.config


if __name__ == "__main__":
    # 运行测试
    pytest.main([__file__, "-v"])