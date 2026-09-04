"""
RPC 处理器测试
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from fp_sentinel.rpc_server import RPCServer


class TestRPCHandlers:
    """RPC处理器测试"""

    def test_create(self):
        server = RPCServer()
        assert server is not None

    def test_custom_config(self):
        server = RPCServer(host="0.0.0.0", port=19000, auth_token="test")
        assert server.host == "0.0.0.0"
        assert server.port == 19000
        assert server.auth_token == "test"

    def test_not_running(self):
        server = RPCServer()
        assert server.is_running is False

    def test_connections_empty(self):
        server = RPCServer()
        assert len(server._connections) == 0

    def test_check_auth_no_token(self):
        server = RPCServer()
        req = type('Req', (), {'headers': {}})()
        assert server._check_auth(req) is True

    def test_check_auth_valid(self):
        server = RPCServer(auth_token="abc123")
        req = type('Req', (), {'headers': {'Authorization': 'Bearer abc123'}})()
        assert server._check_auth(req) is True

    def test_check_auth_invalid(self):
        server = RPCServer(auth_token="abc123")
        req = type('Req', (), {'headers': {'Authorization': 'Bearer wrong'}})()
        assert server._check_auth(req) is False

    def test_check_auth_no_header(self):
        server = RPCServer(auth_token="abc123")
        req = type('Req', (), {'headers': {}})()
        assert server._check_auth(req) is False

    def test_set_engine(self):
        server = RPCServer()
        engine = MagicMock()
        server.set_engine(engine)
        assert server._engine == engine

    def test_handlers_empty(self):
        server = RPCServer()
        assert isinstance(server._message_handlers, dict)
