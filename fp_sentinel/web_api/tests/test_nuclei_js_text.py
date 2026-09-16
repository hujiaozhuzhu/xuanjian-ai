"""Nuclei / JS / Text 提取测试。"""

from __future__ import annotations

import pytest

from fp_sentinel.web_api.api_discovery import ApiDiscovery


class TestNucleiParsing:
    """Nuclei JSON 解析测试。"""

    def test_basic_extraction(self, sample_nuclei: pytest.fixture) -> None:
        """验证 Nuclei JSONL 基本解析。"""
        endpoints = ApiDiscovery.from_nuclei_json(sample_nuclei)
        assert len(endpoints) == 2

    def test_template_and_severity(self, sample_nuclei: pytest.fixture) -> None:
        """验证 template-id / severity_hint 正确传递。"""
        endpoints = ApiDiscovery.from_nuclei_json(sample_nuclei)
        sql_ep = next(
            ep for ep in endpoints if "users" in ep.url
        )
        assert sql_ep.matched_template == "sql-injection-detect"
        assert sql_ep.severity_hint == "high"
        assert sql_ep.source == "nuclei"
        assert sql_ep.content_type == "http"

    def test_missing_file_raises(self, tmp_path: pytest.fixture) -> None:
        """验证不存在文件抛异常。"""
        with pytest.raises(FileNotFoundError):
            ApiDiscovery.from_nuclei_json(tmp_path / "nope.json")


class TestJsExtraction:
    """JS 正则提取测试。"""

    def test_basic_extraction(self, sample_js_files: pytest.fixture) -> None:
        """验证从 JS 文件提取候选路径。"""
        endpoints = ApiDiscovery.from_js(sample_js_files)
        assert len(endpoints) > 0
        urls = {ep.url for ep in endpoints}
        # 至少应该提取出 login / profile / order 等
        assert any("login" in u for u in urls)

    def test_dedup_across_files(self, sample_js_files: pytest.fixture) -> None:
        """验证跨文件去重。"""
        endpoints = ApiDiscovery.from_js(sample_js_files)
        unique_urls = {ep.url for ep in endpoints}
        assert len(unique_urls) == len(endpoints)


class TestTextExtraction:
    """通用文本提取测试。"""

    def test_absolute_urls(self) -> None:
        """验证绝对 URL 提取。"""
        text = "访问 https://example.com/api/test 查看结果"
        endpoints = ApiDiscovery.from_text(text)
        assert len(endpoints) >= 1
        assert any("https://example.com/api/test" in ep.url for ep in endpoints)

    def test_relative_paths(self) -> None:
        """验证相对路径提取。"""
        text = "调用 /api/users/profile 接口"
        endpoints = ApiDiscovery.from_text(text)
        assert any("/api/users/profile" in ep.url for ep in endpoints)

    def test_empty_text(self) -> None:
        """验证空文本返回空列表。"""
        endpoints = ApiDiscovery.from_text("")
        assert endpoints == []
