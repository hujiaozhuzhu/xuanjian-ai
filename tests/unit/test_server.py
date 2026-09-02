"""
服务器模块测试
"""

import pytest
from fp_sentinel.server import FPServer


class TestFPServer:
    """FPServer 测试"""

    def test_import_server(self):
        """导入服务器"""
        assert FPServer is not None

    def test_create_server(self):
        """创建服务器"""
        server = FPServer()
        assert server is not None

    def test_server_has_scanner_manager(self):
        """服务器有扫描器管理器"""
        server = FPServer()
        assert hasattr(server, 'scanner_manager')

    def test_server_has_filters(self):
        """服务器有过滤器"""
        server = FPServer()
        assert hasattr(server, 'rule_filter')
        assert hasattr(server, 'context_filter')

    def test_server_has_scans_storage(self):
        """服务器有扫描存储"""
        server = FPServer()
        assert hasattr(server, '_scans')
        assert isinstance(server._scans, dict)

    def test_server_has_findings_storage(self):
        """服务器有发现存储"""
        server = FPServer()
        assert hasattr(server, '_findings')
        assert isinstance(server._findings, dict)

    def test_calculate_statistics_empty(self):
        """空统计"""
        server = FPServer()
        stats = server._calculate_statistics([])
        assert stats.total == 0
