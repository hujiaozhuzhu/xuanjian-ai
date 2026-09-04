"""
Web 应用测试
"""

import pytest
from fp_sentinel.web.app import create_web_app


class TestWebApp:
    """Web应用测试"""

    def test_import_web_app(self):
        """导入Web应用"""
        assert create_web_app is not None

    def test_create_web_app(self):
        """创建Web应用"""
        # Mock server
        class MockServer:
            _scans = {}
            _findings = {}
            scanner_manager = None
            rule_filter = None
            context_filter = None
            ml_filter = None

            def _calculate_statistics(self, results):
                from fp_sentinel.models import FilterStatistics
                return FilterStatistics(
                    total=0, false_positives=0, likely_false_positives=0,
                    true_positives=0, needs_review=0, reduction_rate="0%",
                    processing_time_ms=0, filter_level_stats={},
                )

        app = create_web_app(MockServer())
        assert app is not None

    def test_web_app_routes(self):
        """Web应用路由"""
        class MockServer:
            _scans = {}
            _findings = {}
            scanner_manager = None
            rule_filter = None
            context_filter = None
            ml_filter = None

            def _calculate_statistics(self, results):
                from fp_sentinel.models import FilterStatistics
                return FilterStatistics(
                    total=0, false_positives=0, likely_false_positives=0,
                    true_positives=0, needs_review=0, reduction_rate="0%",
                    processing_time_ms=0, filter_level_stats={},
                )

        app = create_web_app(MockServer())
        # 检查路由存在
        routes = [route.path for route in app.routes]
        assert len(routes) > 0
