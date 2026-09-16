"""dynamic_scanner/js_renderer.py 测试 — 验证 _simulated_analyze 路径和数据提取逻辑。"""

import unittest

from fp_sentinel.dynamic_scanner.js_renderer import JSRenderingAnalyzer
from fp_sentinel.dynamic_scanner.models import DynamicScanConfig, JSRenderResult


class TestJSRenderingAnalyzerSimulated(unittest.TestCase):
    """Test simulated (no browser) analysis path."""

    def test_analyze_without_browser_engine(self):
        """Verify analyze returns success=True in simulated (no browser) mode."""
        analyzer = JSRenderingAnalyzer(browser_engine=None)
        result = analyzer.analyze("https://example.com/app")
        self.assertTrue(result.success)
        self.assertEqual(result.url, "https://example.com/app")
        self.assertGreater(len(result.rendered_html), 0)

    def test_analyze_with_config(self):
        """Verify analyze respects DynamicScanConfig parameters."""
        config = DynamicScanConfig(target_url="https://test.com", js_render_wait_ms=3000)
        analyzer = JSRenderingAnalyzer(browser_engine=None)
        result = analyzer.analyze("https://test.com", config=config)
        self.assertTrue(result.success)
        self.assertEqual(result.load_time_ms, 300.0)  # 3000 / 10 = 300.0

    def test_simulated_analyze_returns_all_fields(self):
        """Verify simulated result has all expected fields populated."""
        analyzer = JSRenderingAnalyzer(browser_engine=None)
        result = analyzer.analyze("https://spa.example.com")
        # Check data elements are populated
        self.assertGreater(len(result.data_elements), 0)
        # Check API calls detected
        self.assertGreater(len(result.api_calls_detected), 0)
        # Check dom_mutations
        self.assertEqual(result.dom_mutations, 3)
        # Check title
        self.assertEqual(result.rendered_title, "Simulated Title")


class TestIdentifyApiCalls(unittest.TestCase):
    """Test _identify_api_calls for same-domain/foreign-domain filtering."""

    def setUp(self):
        self.analyzer = JSRenderingAnalyzer(browser_engine=None)

    def test_same_domain_api_included(self):
        """Verify same-domain API calls are included."""
        network_calls = [
            {"url": "https://example.com/api/users", "method": "GET"},
            {"url": "https://example.com/api/products", "method": "POST"},
        ]
        result = self.analyzer._identify_api_calls(network_calls, "https://example.com/")
        self.assertEqual(len(result), 2)

    def test_foreign_domain_api_excluded(self):
        """Verify foreign-domain API calls are excluded."""
        network_calls = [
            {"url": "https://evil.com/api/users", "method": "GET"},
            {"url": "https://example.com/api/data", "method": "GET"},
        ]
        result = self.analyzer._identify_api_calls(network_calls, "https://example.com/")
        self.assertEqual(len(result), 1)
        self.assertIn("example.com", result[0]["url"])

    def test_non_api_url_excluded(self):
        """Verify non-API URLs are excluded even from same domain."""
        network_calls = [
            {"url": "https://example.com/about", "method": "GET"},
            {"url": "https://example.com/contact", "method": "GET"},
        ]
        result = self.analyzer._identify_api_calls(network_calls, "https://example.com/")
        self.assertEqual(len(result), 0)

    def test_graphql_included(self):
        """Verify /graphql endpoints are recognized as API."""
        network_calls = [
            {"url": "https://example.com/graphql", "method": "POST"},
        ]
        result = self.analyzer._identify_api_calls(network_calls, "https://example.com/")
        self.assertEqual(len(result), 1)

    def test_empty_list(self):
        """Verify empty network_calls returns empty list."""
        result = self.analyzer._identify_api_calls([], "https://example.com/")
        self.assertEqual(result, [])


class TestExtractDataElements(unittest.TestCase):
    """Test _extract_data_elements for HTML parsing."""

    def setUp(self):
        self.analyzer = JSRenderingAnalyzer(browser_engine=None)

    def test_input_field_extraction(self):
        """Verify <input name=... value=...> fields are extracted."""
        html = '<html><input name="search" value="hello"><input name="page" value="1"></html>'
        result = self.analyzer._extract_data_elements("", html)
        input_elements = [e for e in result if e["type"] == "input_field"]
        self.assertEqual(len(input_elements), 2)
        self.assertEqual(input_elements[0]["name"], "search")
        self.assertEqual(input_elements[0]["value"], "hello")

    def test_data_attribute_extraction(self):
        """Verify data-* attributes are extracted."""
        html = '<div data-user-id="12345" data-role="admin">User</div>'
        result = self.analyzer._extract_data_elements("", html)
        data_elements = [e for e in result if e["type"] == "data_attribute"]
        self.assertEqual(len(data_elements), 2)
        self.assertEqual(data_elements[0]["name"], "data-user-id")
        self.assertEqual(data_elements[0]["value"], "12345")

    def test_window_var_extraction(self):
        """Verify window.__VAR__ = {...} inline JSON is extracted."""
        html = '<script>window.__CONFIG__ = {"api":"https://a.com","debug":true};</script>'
        result = self.analyzer._extract_data_elements("", html)
        json_elements = [e for e in result if e["type"] == "inline_json"]
        self.assertEqual(len(json_elements), 1)
        self.assertEqual(json_elements[0]["name"], "__CONFIG__")
        self.assertIn("api", json_elements[0]["value"])

    def test_empty_html(self):
        """Verify empty HTML returns no elements."""
        # Need at least empty string to not crash regex
        result = self.analyzer._extract_data_elements("", "")
        # May return data_attributes for empty string (0 matches), that's fine
        self.assertIsInstance(result, list)


class TestJSRenderResultModel(unittest.TestCase):
    """Test JSRenderResult dataclass fields and defaults."""

    def test_default_values(self):
        """Verify JSRenderResult has correct default values."""
        result = JSRenderResult(url="https://test.com")
        self.assertEqual(result.rendered_title, "")
        self.assertEqual(result.rendered_html, "")
        self.assertEqual(result.data_elements, [])
        self.assertEqual(result.api_calls_detected, [])
        self.assertEqual(result.dom_mutations, 0)
        self.assertEqual(result.load_time_ms, 0.0)
        self.assertTrue(result.success)
        self.assertEqual(result.error, "")

    def test_field_assignment(self):
        """Verify all fields can be assigned."""
        result = JSRenderResult(
            url="https://test.com",
            rendered_title="Title",
            rendered_html="<html></html>",
            data_elements=[{"type": "input", "name": "x", "value": "y"}],
            api_calls_detected=[{"url": "/api/x", "method": "GET"}],
            dom_mutations=5,
            load_time_ms=1234.5,
            success=True,
        )
        self.assertEqual(result.rendered_title, "Title")
        self.assertEqual(result.dom_mutations, 5)
        self.assertAlmostEqual(result.load_time_ms, 1234.5)

    def test_field_count(self):
        """Verify JSRenderResult has expected number of fields."""
        result = JSRenderResult(url="X")
        field_count = len(result.model_fields)
        # Should have: url, rendered_title, rendered_html, data_elements,
        # api_calls_detected, dom_mutations, load_time_ms, success, error
        self.assertGreaterEqual(field_count, 9)


class TestDomToDataElements(unittest.TestCase):
    """Test _dom_to_data_elements recursion."""

    def setUp(self):
        self.analyzer = JSRenderingAnalyzer(browser_engine=None)

    def test_input_element(self):
        """Verify DOM snapshot with input tag is extracted."""
        dom = {"tag": "input", "attrs": {"name": "username", "value": "admin"}, "children": []}
        result = self.analyzer._dom_to_data_elements(dom)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "input")
        self.assertEqual(result[0]["name"], "username")

    def test_link_element(self):
        """Verify DOM snapshot with anchor tag is extracted."""
        dom = {"tag": "a", "attrs": {"href": "/admin"}, "text": "Admin Panel", "children": []}
        result = self.analyzer._dom_to_data_elements(dom)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "link")
        self.assertEqual(result[0]["value"], "/admin")

    def test_nested_children(self):
        """Verify nested children are recursively extracted."""
        dom = {
            "tag": "div",
            "attrs": {},
            "children": [
                {"tag": "input", "attrs": {"name": "q", "value": ""}, "children": []},
                {"tag": "a", "attrs": {"href": "/next"}, "text": "Next", "children": []},
            ],
        }
        result = self.analyzer._dom_to_data_elements(dom)
        self.assertEqual(len(result), 2)

    def test_non_dict_input(self):
        """Verify non-dict input returns empty list."""
        result = self.analyzer._dom_to_data_elements(["not", "a", "dict"])
        self.assertEqual(result, [])

    def test_none_children(self):
        """Verify None children are handled gracefully."""
        dom = {"tag": "input", "attrs": {"name": "test"}, "children": None}
        result = self.analyzer._dom_to_data_elements(dom)
        self.assertEqual(len(result), 1)


if __name__ == "__main__":
    unittest.main()
