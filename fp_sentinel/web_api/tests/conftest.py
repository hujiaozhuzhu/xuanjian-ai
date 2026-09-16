"""Web API 模块测试构造器与共享 Fixture。

提供手工构造的样本数据，避免依赖外部文件。
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# 构造回退存根（当正式模型不可用时使用）
# ---------------------------------------------------------------------------


def _build_fallback_models() -> types.ModuleType:
    """构造 FindingReport / Evidence 存根模块。

    Returns:
        types.ModuleType: 包含存根的虚拟模块。
    """
    from dataclasses import dataclass, field

    mod = types.ModuleType("fallback_models_stub")

    @dataclass
    class Evidence:
        """证据存根。"""

        id: str = ""
        location: str = ""
        content: str = ""
        description: str = ""
        source: str = "静态"

        def to_dict(self) -> Dict[str, Any]:
            """序列化为可 JSON 化的 dict。"""
            from dataclasses import asdict
            return asdict(self)

    @dataclass
    class FindingReport:
        """漏洞发现存根。"""

        id: str = ""
        title: str = ""
        severity: str = "MEDIUM"
        cwe_id: str = ""
        owasp_masvs: str = ""
        category: str = ""
        description: str = ""
        evidence: List[Evidence] = field(default_factory=list)
        remediation: str = ""
        references: List[str] = field(default_factory=list)
        tool_version: str = ""
        confidence: float = 0.5

        def to_dict(self) -> Dict[str, Any]:
            """序列化为可 JSON 化的 dict。"""
            from dataclasses import asdict
            return asdict(self)

    mod.Evidence = Evidence
    mod.FindingReport = FindingReport
    return mod


# 注入存根到 sys.modules
_fallback = _build_fallback_models()
sys.modules["fp_sentinel.mobile_reporting"] = types.ModuleType("fp_sentinel.mobile_reporting")
sys.modules["fp_sentinel.mobile_reporting.models"] = types.ModuleType(
    "fp_sentinel.mobile_reporting.models"
)
sys.modules["fp_sentinel.mobile_reporting.models.report_models"] = _fallback
sys.modules["fp_sentinel.mobile_reporting.formats"] = types.ModuleType(
    "fp_sentinel.mobile_reporting.formats"
)
sys.modules["fp_sentinel.mobile_reporting.formats.base_generator"] = types.ModuleType(
    "fp_sentinel.mobile_reporting.formats.base_generator"
)


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_har(tmp_path: Path) -> Path:
    """构造一个临时 HAR 样本文件。

    Args:
        tmp_path: pytest 临时目录。

    Returns:
        Path: HAR 文件路径。
    """
    har_data = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://example.com/api/login",
                    },
                    "response": {
                        "status": 200,
                        "content": {"mimeType": "application/json", "size": 1024},
                    },
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://example.com/api/users/profile",
                    },
                    "response": {
                        "status": 200,
                        "content": {"mimeType": "application/json", "size": 2048},
                    },
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://example.com/api/users/profile",
                    },
                    "response": {
                        "status": 200,
                        "content": {"mimeType": "application/json", "size": 2048},
                    },
                },
            ]
        }
    }
    har_path = tmp_path / "sample.har"
    har_path.write_text(json.dumps(har_data), encoding="utf-8")
    return har_path


@pytest.fixture
def sample_burp_xml(tmp_path: Path) -> Path:
    """构造 Burp XML 样本文件。

    Args:
        tmp_path: pytest 临时目录。

    Returns:
        Path: Burp XML 文件路径。
    """
    xml_content = """<?xml version="1.0"?>
<items>
  <item>
    <url>https://example.com/admin/users</url>
    <host>example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <status>200</status>
    <responselength>4096</responselength>
    <path>/admin/users</path>
  </item>
  <item>
    <url>https://example.com/api/payment</url>
    <host>example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>POST</method>
    <status>200</status>
    <responselength>512</responselength>
    <path>/api/payment</path>
  </item>
</items>
"""
    path = tmp_path / "sample_burp.xml"
    path.write_text(xml_content, encoding="utf-8")
    return path


@pytest.fixture
def sample_burp_json(tmp_path: Path) -> Path:
    """构造 Burp JSON 样本文件。

    Args:
        tmp_path: pytest 临时目录。

    Returns:
        Path: Burp JSON 文件路径。
    """
    data = [
        {
            "url": "https://example.com/api/config",
            "host": "example.com",
            "port": "443",
            "protocol": "https",
            "method": "PUT",
            "status": "200",
            "responselength": "1024",
            "path": "/api/config",
        }
    ]
    path = tmp_path / "sample_burp.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def sample_nuclei(tmp_path: Path) -> Path:
    """构造 Nuclei JSONL 样本文件。

    Args:
        tmp_path: pytest 临时目录。

    Returns:
        Path: Nuclei 文件路径。
    """
    lines = [
        json.dumps(
            {
                "template-id": "sql-injection-detect",
                "matched-at": "https://example.com/api/users?id=1",
                "type": "http",
                "severity": "high",
            }
        ),
        json.dumps(
            {
                "template-id": "xss-detect",
                "matched-at": "https://example.com/search?q=test",
                "type": "http",
                "severity": "medium",
            }
        ),
    ]
    path = tmp_path / "nuclei_results.json"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


@pytest.fixture
def sample_js_files(tmp_path: Path) -> List[Path]:
    """构造 JS 样本文件。

    Args:
        tmp_path: pytest 临时目录。

    Returns:
        List[Path]: JS 文件路径列表。
    """
    js_content_a = """
const apiBase = "https://example.com/api/v1";
axios.post("/api/login", data);
fetch("/api/users/profile");
const url = "/api/order/list";
axios.get("/api/order/123");
"""
    js_content_b = """
const baseURL = "https://cdn.example.com";
axios({
  url: "/api/upload",
  method: "POST",
});
fetch("/api/admin/config");
"""
    paths: List[Path] = []
    for idx, content in enumerate([js_content_a, js_content_b]):
        p = tmp_path / f"app_{idx}.js"
        p.write_text(content, encoding="utf-8")
        paths.append(p)
    return paths


@pytest.fixture
def mock_http_client() -> Any:
    """构造 mock HTTP 客户端。

    Returns:
        MagicMock: 含 ``request`` 方法的 mock 对象。
    """
    client = MagicMock()
    response_a = MagicMock()
    response_a.status_code = 200
    response_a.content = b'{"user": "alice", "email": "alice@example.com"}'
    response_a.headers = {"Content-Type": "application/json"}
    response_b = MagicMock()
    response_b.status_code = 200
    response_b.content = b'{"user": "bob", "email": "bob@example.com"}'
    response_b.headers = {"Content-Type": "application/json"}
    client.request.side_effect = [response_a, response_b]
    return client


@pytest.fixture
def mock_http_controlled() -> Any:
    """构造受控场景的 mock（双 401）。

    Returns:
        MagicMock: 模拟双 401 的 mock 对象。
    """
    client = MagicMock()

    def _response(method: str, url: str, **kwargs: Any) -> MagicMock:  # noqa: ARG001
        resp = MagicMock()
        resp.status_code = 401
        resp.content = b'{"error": "unauthorized"}'
        resp.headers = {}
        return resp

    client.request.side_effect = _response
    return client
