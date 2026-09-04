"""
MCP 服务器测试
"""

import pytest
from fp_sentinel.mcp_server import MCPAuditServer, create_mcp_server


class TestMCPServer:
    """MCP服务器测试"""

    def test_create_server(self):
        """创建服务器"""
        server = create_mcp_server()
        assert server is not None
        assert isinstance(server, MCPAuditServer)

    def test_server_has_mcp(self):
        """服务器有MCP实例"""
        server = create_mcp_server()
        assert hasattr(server, 'mcp')
        assert server.mcp is not None

    def test_server_default_config(self):
        """默认配置"""
        server = create_mcp_server()
        assert server.config is not None
        assert "rule_filter" in server.config

    def test_server_with_custom_config(self):
        """自定义配置"""
        config = {
            "rule_filter": {"enabled": False},
            "context_filter": {"enabled": True},
        }
        server = create_mcp_server(config)
        assert server.config["rule_filter"]["enabled"] is False

    def test_server_has_filters(self):
        """服务器有过滤器"""
        server = create_mcp_server()
        assert server.rule_filter is not None
        assert server.context_filter is not None
        assert server.ml_filter is not None

    def test_server_has_scanner_manager(self):
        """服务器有扫描器管理器"""
        server = create_mcp_server()
        assert server.scanner_manager is not None

    def test_server_scans_storage(self):
        """扫描存储"""
        server = create_mcp_server()
        assert isinstance(server._scans, dict)
        assert isinstance(server._findings, dict)

    def test_calculate_statistics(self):
        """统计计算"""
        server = create_mcp_server()
        # 空结果统计
        stats = server._calculate_statistics([])
        assert stats.total == 0

    def test_default_config_values(self):
        """默认配置值"""
        config = MCPAuditServer._default_config()
        assert config["rule_filter"]["enabled"] is True
        assert config["context_filter"]["enabled"] is True
        assert config["context_filter"]["false_positive_threshold"] == 0.5
