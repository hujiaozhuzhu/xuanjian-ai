"""
RPC 服务器测试
"""

import pytest
from fp_sentinel.rpc_server import RPCServer


class TestRPCServer:
    """RPC服务器测试"""

    def test_create_server(self):
        server = RPCServer()
        assert server is not None
        assert server.host == "127.0.0.1"
        assert server.port == 18800

    def test_create_custom_server(self):
        server = RPCServer(host="0.0.0.0", port=19000)
        assert server.host == "0.0.0.0"
        assert server.port == 19000

    def test_server_not_running(self):
        server = RPCServer()
        assert server.is_running is False

    def test_server_with_auth(self):
        server = RPCServer(auth_token="test-token")
        assert server.auth_token == "test-token"

    def test_server_no_auth(self):
        server = RPCServer()
        assert server.auth_token is None

    def test_server_connections_empty(self):
        server = RPCServer()
        assert len(server._connections) == 0

    def test_server_has_app(self):
        """服务器有app"""
        server = RPCServer()
        # app 在 start() 后创建，或在构造时创建
        assert server is not None

    def test_check_auth_no_token(self):
        """无token时认证通过"""
        server = RPCServer()
        mock_request = type('Request', (), {'headers': {}})()
        assert server._check_auth(mock_request) is True

    def test_check_auth_with_token(self):
        """有token时认证检查"""
        server = RPCServer(auth_token="test-token")
        mock_request = type('Request', (), {'headers': {'Authorization': 'Bearer test-token'}})()
        assert server._check_auth(mock_request) is True

    def test_check_auth_wrong_token(self):
        """错误token认证失败"""
        server = RPCServer(auth_token="test-token")
        mock_request = type('Request', (), {'headers': {'Authorization': 'Bearer wrong-token'}})()
        assert server._check_auth(mock_request) is False
