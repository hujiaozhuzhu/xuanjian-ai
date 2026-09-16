"""越权探测测试（全部 mock HTTP，不发送真实请求）。"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from fp_sentinel.web_api.endpoints_models import ApiEndpoint
from fp_sentinel.web_api.privilege_scan import (
    PrivilegeScanner,
    PrivilegeFinding,
)


def _mock_response(status: int, body: bytes) -> MagicMock:
    """构造单个 mock 响应。

    Args:
        status: HTTP 状态码。
        body: 响应体字节。

    Returns:
        MagicMock: 模拟的响应对象。
    """
    resp = MagicMock()
    resp.status_code = status
    resp.content = body
    resp.headers = {"Content-Type": "application/json"}
    return resp


def _build_client(status_a: int, body_a: bytes, status_b: int, body_b: bytes) -> MagicMock:
    """构造按顺序响应的 mock HTTP 客户端。

    Args:
        status_a: 账号 A 状态码。
        body_a: 账号 A 响应体。
        status_b: 账号 B 状态码。
        body_b: 账号 B 响应体。

    Returns:
        MagicMock: 配置好 side_effect 的 mock 客户端。
    """
    client = MagicMock()
    client.request.side_effect = [
        _mock_response(status_a, body_a),
        _mock_response(status_b, body_b),
    ]
    return client


class TestHorizontalPrivilege:
    """水平越权探测测试。"""

    def test_exposed_different_bodies(self, tmp_path: Path) -> None:
        """验证不同 body 且 200 标记为暴露。"""
        body_a = b'{"user": "alice", "email": "alice@example.com", "id": 1001, "role": "user"}'
        body_b = (
            b'{"user": "bob", "email": "bob@example.com", "id": 1002, '
            b'"role": "user", "permissions": ["read", "write", "admin"], '
            b'"address": "123 Main St, Springfield, IL 62701", '
            b'"phone": "555-1234"}'
        )
        client = _build_client(200, body_a, 200, body_b)
        scanner = PrivilegeScanner(
            base_url="https://example.com",
            test_cookies={"a": "sess_a", "b": "sess_b"},
            audit_log_path=tmp_path / ".audit.log",
            http_client=client,
        )
        endpoints = [ApiEndpoint(method="GET", url="https://example.com/api/users/me")]
        findings = scanner.test_horizontal(endpoints, "sess_a", "sess_b")
        assert len(findings) == 1
        assert findings[0].verdict == "exposed"
        assert findings[0].finding_type == "horizontal"
        assert findings[0].cwe_id == "CWE-639"

    def test_controlled_both_401(self, tmp_path: Path) -> None:
        """验证双 401 为受控。"""
        client = _build_client(401, b"a", 401, b"b")
        scanner = PrivilegeScanner(
            base_url="https://example.com",
            test_cookies={"a": "sess_a", "b": "sess_b"},
            audit_log_path=tmp_path / ".audit.log",
            http_client=client,
        )
        endpoints = [ApiEndpoint(method="GET", url="https://example.com/api/users/me")]
        findings = scanner.test_horizontal(endpoints, "sess_a", "sess_b")
        assert findings[0].verdict == "controlled"

    def test_same_body_controlled(self, tmp_path: Path) -> None:
        """验证相同 body 为受控。"""
        client = _build_client(200, b"same", 200, b"same")
        scanner = PrivilegeScanner(
            base_url="https://example.com",
            test_cookies={"a": "sess_a", "b": "sess_b"},
            audit_log_path=tmp_path / ".audit.log",
            http_client=client,
        )
        endpoints = [ApiEndpoint(method="GET", url="https://example.com/api/public")]
        findings = scanner.test_horizontal(endpoints, "sess_a", "sess_b")
        assert findings[0].verdict == "controlled"

    def test_audit_log_written(self, tmp_path: Path) -> None:
        """验证审计日志被写入。"""
        client = _build_client(200, b"aa", 200, b"bbbb")
        audit_path = tmp_path / ".audit.log"
        scanner = PrivilegeScanner(
            base_url="https://example.com",
            test_cookies={"a": "sess_a", "b": "sess_b"},
            audit_log_path=audit_path,
            http_client=client,
        )
        endpoints = [ApiEndpoint(method="GET", url="https://example.com/api/orders")]
        scanner.test_horizontal(endpoints, "sess_a", "sess_b")
        assert audit_path.exists()
        content = audit_path.read_text(encoding="utf-8")
        assert "web-api-priv" in content
        # 不泄露响应体全文
        assert "aa" not in content
        assert "bbbb" not in content


class TestVerticalPrivilege:
    """垂直越权探测测试。"""

    def test_exposed_low_gets_200(self, tmp_path: Path) -> None:
        """验证低权限 200 + 有数据为暴露。"""
        client = MagicMock()
        client.request.side_effect = [
            _mock_response(200, b'{"admin": true}'),  # admin
            _mock_response(200, b'{"data": "leaked"}'),  # low
        ]
        scanner = PrivilegeScanner(
            base_url="https://example.com",
            test_cookies={"a": "sess_a", "b": "sess_b"},
            admin_cookie="admin_sess",
            low_cookie="low_sess",
            audit_log_path=tmp_path / ".audit.log",
            http_client=client,
        )
        endpoints = [ApiEndpoint(method="GET", url="https://example.com/admin/config")]
        findings = scanner.test_vertical("admin_sess", "low_sess", endpoints)
        assert len(findings) == 1
        assert findings[0].verdict == "exposed"
        assert findings[0].cwe_id == "CWE-285"

    def test_controlled_low_gets_403(self, tmp_path: Path) -> None:
        """验证低权限 403 为受控。"""
        client = MagicMock()
        client.request.side_effect = [
            _mock_response(200, b"ok"),
            _mock_response(403, b"forbidden"),
        ]
        scanner = PrivilegeScanner(
            base_url="https://example.com",
            test_cookies={"a": "sess_a", "b": "sess_b"},
            admin_cookie="admin_sess",
            low_cookie="low_sess",
            audit_log_path=tmp_path / ".audit.log",
            http_client=client,
        )
        endpoints = [ApiEndpoint(method="GET", url="https://example.com/admin/delete")]
        findings = scanner.test_vertical("admin_sess", "low_sess", endpoints)
        assert findings[0].verdict == "controlled"


class TestNeverBruteforce:
    """爆破禁令测试。"""

    def test_bruteforce_disabled(self) -> None:
        """验证 NEVER_ATTEMPT_BRUTEFORCE 常量存在且为 True。"""
        assert PrivilegeScanner.NEVER_ATTEMPT_BRUTEFORCE is True

    def test_post_rejected(self, tmp_path: Path) -> None:
        """验证 POST 请求被拒绝。"""
        client = MagicMock()
        scanner = PrivilegeScanner(
            base_url="https://example.com",
            test_cookies={"a": "sess_a", "b": "sess_b"},
            audit_log_path=tmp_path / ".audit.log",
            http_client=client,
        )
        endpoints = [ApiEndpoint(method="POST", url="https://example.com/api/x")]
        with pytest.raises(ValueError, match="POST"):
            scanner.test_horizontal(endpoints, "sess_a", "sess_b")


class TestPrivilegeFindingModel:
    """PrivilegeFinding 数据模型测试。"""

    def test_to_finding_report_horizontal(self) -> None:
        """验证水平越权转换为 FindingReport。"""
        finding = PrivilegeFinding(
            method="GET",
            url="https://example.com/api/orders/1",
            finding_type="horizontal",
            verdict="exposed",
            status_a=200,
            status_b=200,
            cwe_id="CWE-639",
        )
        report = finding.to_finding_report()
        assert report.cwe_id == "CWE-639"
        assert report.category == "access-control"
        assert "水平越权" in report.title

    def test_to_finding_report_vertical(self) -> None:
        """验证垂直越权转换为 FindingReport。"""
        finding = PrivilegeFinding(
            method="GET",
            url="https://example.com/admin/users",
            finding_type="vertical",
            verdict="exposed",
            status_a=200,
            status_b=200,
            cwe_id="CWE-285",
        )
        report = finding.to_finding_report()
        assert report.cwe_id == "CWE-285"
        assert "垂直越权" in report.title
