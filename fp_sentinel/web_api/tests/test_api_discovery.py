"""API 端点发现测试。

覆盖 HAR / Burp XML / Burp JSON / Nuclei / JS / Text 提取。
"""

from __future__ import annotations

import pytest

from fp_sentinel.web_api.api_discovery import ApiDiscovery


class TestHarDiscovery:
    """HAR 文件解析测试。"""

    def test_basic_extraction(self, sample_har: pytest.fixture) -> None:
        """验证 HAR 基本提取与去重。"""
        endpoints = ApiDiscovery.from_har(sample_har)
        # 三个条目，其中 /api/users/profile 重复 -> 2 个唯一
        assert len(endpoints) == 2
        paths = {ep.path for ep in endpoints}
        assert "/api/login" in paths
        assert "/api/users/profile" in paths

    def test_method_and_status(self, sample_har: pytest.fixture) -> None:
        """验证 method / status_code / content_type / response_size 正确提取。"""
        endpoints = ApiDiscovery.from_har(sample_har)
        login_ep = next(ep for ep in endpoints if ep.path == "/api/login")
        assert login_ep.method == "POST"
        assert login_ep.status_code == 200
        assert login_ep.content_type == "application/json"
        assert login_ep.response_size == 1024
        assert login_ep.source == "har"

    def test_missing_file_raises(self, tmp_path: pytest.fixture) -> None:
        """验证不存在文件抛 FileNotFoundError。"""
        with pytest.raises(FileNotFoundError):
            ApiDiscovery.from_har(tmp_path / "nonexistent.har")

    def test_malformed_json_raises(self, tmp_path: pytest.fixture) -> None:
        """验证非法 JSON 文件抛 JSONDecodeError。"""
        bad = tmp_path / "bad.har"
        bad.write_text("not a json file", encoding="utf-8")
        with pytest.raises(Exception):  # noqa: B017 - 任意异常
            ApiDiscovery.from_har(bad)


class TestBurpXml:
    """Burp XML 解析测试。"""

    def test_basic_extraction(self, sample_burp_xml: pytest.fixture) -> None:
        """验证基本 XML items 解析。"""
        endpoints = ApiDiscovery.from_burp(sample_burp_xml)
        assert len(endpoints) == 2
        paths = {ep.path for ep in endpoints}
        assert "/admin/users" in paths
        assert "/api/payment" in paths

    def test_fields_extracted(self, sample_burp_xml: pytest.fixture) -> None:
        """验证字段完整提取。"""
        endpoints = ApiDiscovery.from_burp(sample_burp_xml)
        admin = next(ep for ep in endpoints if ep.path == "/admin/users")
        assert admin.host == "example.com"
        assert admin.port == 443
        assert admin.protocol == "https"
        assert admin.method == "GET"
        assert admin.status_code == 200
        assert admin.response_size == 4096
        assert admin.source == "burp"


class TestBurpJson:
    """Burp JSON 解析测试。"""

    def test_basic_extraction(self, sample_burp_json: pytest.fixture) -> None:
        """验证 JSON 格式 items 解析。"""
        endpoints = ApiDiscovery.from_burp(sample_burp_json)
        assert len(endpoints) == 1
        ep = endpoints[0]
        assert ep.url == "https://example.com/api/config"
        assert ep.method == "PUT"
        assert ep.source == "burp"
