"""
玄鉴 v2.4.0 — 版本变化趋势图模块测试

测试覆盖率目标: >= 95%
测试子功能: 版本变化趋势图生成 (VersionTrendChart)

版本: 2.4.0
"""

import json
import os
import struct
import tempfile
import zlib
from pathlib import Path

import pytest

from fp_sentinel.visualization.version_trend import (
    VersionTrendChart,
    _hex_to_rgb_png,
    _draw_line_png,
    _draw_text_png,
    _save_png_png,
)
from fp_sentinel.visualization.models import (
    ChartTheme,
    OutputFormat,
    TrendInput,
    TrendMetric,
    TrendPoint,
    get_risk_color,
    get_theme_background,
    get_theme_text_color,
)


# ─────────────────────── Fixtures ───────────────────────

@pytest.fixture
def sample_trend_points():
    """生成标准趋势数据点"""
    return [
        TrendPoint(
            version="v1.0.0",
            scan_time="2024-01-01T00:00:00",
            total_count=50,
            by_severity={"CRITICAL": 3, "HIGH": 12, "MEDIUM": 20, "LOW": 15},
            fixed_count=0,
            new_count=50,
            remaining_count=50,
        ),
        TrendPoint(
            version="v1.1.0",
            scan_time="2024-02-01T00:00:00",
            total_count=35,
            by_severity={"CRITICAL": 2, "HIGH": 8, "MEDIUM": 15, "LOW": 10},
            fixed_count=18,
            new_count=3,
            remaining_count=32,
        ),
        TrendPoint(
            version="v1.2.0",
            scan_time="2024-03-01T00:00:00",
            total_count=20,
            by_severity={"CRITICAL": 1, "HIGH": 4, "MEDIUM": 10, "LOW": 5},
            fixed_count=30,
            new_count=2,
            remaining_count=18,
        ),
        TrendPoint(
            version="v1.3.0",
            scan_time="2024-04-01T00:00:00",
            total_count=15,
            by_severity={"CRITICAL": 0, "HIGH": 3, "MEDIUM": 8, "LOW": 4},
            fixed_count=38,
            new_count=1,
            remaining_count=14,
        ),
    ]


@pytest.fixture
def trend_input(sample_trend_points):
    """标准 TrendInput 实例"""
    return TrendInput(points=sample_trend_points, project_name="test-project")


@pytest.fixture
def empty_trend_input():
    """空 TrendInput 实例"""
    return TrendInput(points=[], project_name="empty-project")


@pytest.fixture
def temp_output_dir():
    """临时输出目录"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def default_chart():
    """默认 VersionTrendChart 实例"""
    return VersionTrendChart()


@pytest.fixture
def dark_chart():
    """深色主题图表"""
    return VersionTrendChart(theme=ChartTheme.DARK)


@pytest.fixture
def light_chart():
    """浅色主题图表"""
    return VersionTrendChart(theme=ChartTheme.LIGHT)


# ─────────────────────── TrendPoint 测试 ───────────────────────

class TestTrendPoint:
    """TrendPoint 数据模型测试"""

    def test_fix_rate_calculation(self):
        p = TrendPoint(
            version="v1", fixed_count=30, remaining_count=20, total_count=50
        )
        assert p.fix_rate == 60.0  # 30 / (30+20) * 100

    def test_fix_rate_zero_total(self):
        p = TrendPoint(version="v1", fixed_count=0, remaining_count=0)
        assert p.fix_rate == 0.0

    def test_fix_rate_all_fixed(self):
        p = TrendPoint(version="v1", fixed_count=50, remaining_count=0)
        assert p.fix_rate == 100.0

    def test_critical_high_count(self):
        p = TrendPoint(
            version="v1",
            by_severity={"CRITICAL": 3, "HIGH": 10, "MEDIUM": 5},
        )
        assert p.critical_high_count == 13

    def test_critical_high_count_missing_keys(self):
        p = TrendPoint(version="v1", by_severity={"MEDIUM": 5})
        assert p.critical_high_count == 0

    def test_critical_high_count_empty(self):
        p = TrendPoint(version="v1")
        assert p.critical_high_count == 0


# ─────────────────────── TrendInput 测试 ───────────────────────

class TestTrendInput:
    """TrendInput 数据模型测试"""

    def test_has_data_true(self, trend_input):
        assert trend_input.has_data is True

    def test_has_data_false(self, empty_trend_input):
        assert empty_trend_input.has_data is False

    def test_metric_series_total(self, trend_input):
        series = trend_input.get_metric_series(TrendMetric.TOTAL_COUNT)
        assert series == [50, 35, 20, 15]

    def test_metric_series_fix_rate(self, trend_input):
        series = trend_input.get_metric_series(TrendMetric.FIX_RATE)
        assert len(series) == 4

    def test_metric_series_severity_dist(self, trend_input):
        series = trend_input.get_metric_series(TrendMetric.SEVERITY_DISTRIBUTION)
        assert series == [15, 10, 5, 3]  # CRITICAL + HIGH

    def test_metric_series_new_vs_fixed(self, trend_input):
        series = trend_input.get_metric_series(TrendMetric.NEW_VS_FIXED)
        assert series == [50, 3, 2, 1]


# ─────────────────────── VersionTrendChart 初始化测试 ───────────────────────

class TestVersionTrendChartInit:
    """初始化测试"""

    def test_default_init(self):
        chart = VersionTrendChart()
        assert chart.theme == ChartTheme.DARK
        assert chart.show_fix_rate is True

    def test_custom_theme(self):
        chart = VersionTrendChart(theme=ChartTheme.LIGHT)
        assert chart.theme == ChartTheme.LIGHT

    def test_no_fix_rate(self):
        chart = VersionTrendChart(show_fix_rate=False)
        assert chart.show_fix_rate is False


# ─────────────────────── 趋势图生成测试 ───────────────────────

class TestTrendChartGeneration:
    """趋势图生成测试"""

    def test_generate_both_formats(self, dark_chart, trend_input, temp_output_dir):
        result = dark_chart.generate(
            trend_input, output_dir=temp_output_dir, output_format=OutputFormat.BOTH
        )
        assert result.output_path_html is not None
        assert result.output_path_png is not None
        assert os.path.exists(result.output_path_html)
        assert os.path.exists(result.output_path_png)

    def test_generate_html_only(self, dark_chart, trend_input, temp_output_dir):
        result = dark_chart.generate(
            trend_input, output_dir=temp_output_dir, output_format=OutputFormat.HTML
        )
        assert result.output_path_html is not None
        assert result.output_path_png is None

    def test_generate_png_only(self, dark_chart, trend_input, temp_output_dir):
        result = dark_chart.generate(
            trend_input, output_dir=temp_output_dir, output_format=OutputFormat.PNG
        )
        assert result.output_path_html is None
        assert result.output_path_png is not None

    def test_generate_creates_directory(self, dark_chart, trend_input, temp_output_dir):
        new_dir = os.path.join(temp_output_dir, "nested", "deep")
        result = dark_chart.generate(
            trend_input, output_dir=new_dir, output_format=OutputFormat.HTML
        )
        assert os.path.isdir(new_dir)

    def test_result_metadata(self, dark_chart, trend_input, temp_output_dir):
        result = dark_chart.generate(
            trend_input, output_dir=temp_output_dir, output_format=OutputFormat.HTML
        )
        assert result.total_versions == 4
        assert "generated_at" in result.metadata
        assert result.metadata["project_name"] == "test-project"

    def test_result_overall_change(self, dark_chart, trend_input, temp_output_dir):
        result = dark_chart.generate(
            trend_input, output_dir=temp_output_dir, output_format=OutputFormat.HTML
        )
        # v1.0=50, v4.0=15 => (15-50)/50 = -70%
        assert result.overall_change == -70.0


class TestTrendChartThemes:
    """不同主题测试"""

    def test_dark_theme_html(self, dark_chart, trend_input, temp_output_dir):
        result = dark_chart.generate(
            trend_input, output_dir=temp_output_dir, output_format=OutputFormat.HTML
        )
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            content = f.read()
        assert "#0d1117" in content or "#161b22" in content

    def test_light_theme_html(self, light_chart, trend_input, temp_output_dir):
        result = light_chart.generate(
            trend_input, output_dir=temp_output_dir, output_format=OutputFormat.HTML
        )
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            content = f.read()
        assert "#ffffff" in content

    def test_all_themes_png(self, trend_input, temp_output_dir):
        for theme in [ChartTheme.DARK, ChartTheme.LIGHT, ChartTheme.HIGH_CONTRAST]:
            chart = VersionTrendChart(theme=theme)
            result = chart.generate(
                trend_input, output_dir=temp_output_dir,
                output_format=OutputFormat.PNG,
                filename_prefix=f"trend_{theme.value}",
            )
            assert os.path.exists(result.output_path_png)


# ─────────────────────── HTML 内容测试 ───────────────────────

class TestTrendHtmlContent:
    """HTML 内容校验"""

    def test_has_canvas(self, dark_chart, trend_input, temp_output_dir):
        result = dark_chart.generate(
            trend_input, output_dir=temp_output_dir, output_format=OutputFormat.HTML
        )
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            content = f.read()
        assert "<canvas" in content

    def test_has_table(self, dark_chart, trend_input, temp_output_dir):
        result = dark_chart.generate(
            trend_input, output_dir=temp_output_dir, output_format=OutputFormat.HTML
        )
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            content = f.read()
        assert "<table>" in content

    def test_has_all_versions(self, dark_chart, trend_input, temp_output_dir):
        result = dark_chart.generate(
            trend_input, output_dir=temp_output_dir, output_format=OutputFormat.HTML
        )
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            content = f.read()
        assert "v1.0.0" in content
        assert "v1.3.0" in content

    def test_has_stat_cards(self, dark_chart, trend_input, temp_output_dir):
        result = dark_chart.generate(
            trend_input, output_dir=temp_output_dir, output_format=OutputFormat.HTML
        )
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            content = f.read()
        assert "stat-card" in content

    def test_has_inline_js(self, dark_chart, trend_input, temp_output_dir):
        result = dark_chart.generate(
            trend_input, output_dir=temp_output_dir, output_format=OutputFormat.HTML
        )
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            content = f.read()
        # 内联 JS 渲染折线图
        assert "getContext" in content
        assert "fillText" in content or "ctx.fill" in content

    def test_no_external_deps(self, dark_chart, trend_input, temp_output_dir):
        result = dark_chart.generate(
            trend_input, output_dir=temp_output_dir, output_format=OutputFormat.HTML
        )
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            content = f.read()
        assert "<script src=" not in content

    def test_fix_rate_in_table(self, dark_chart, trend_input, temp_output_dir):
        result = dark_chart.generate(
            trend_input, output_dir=temp_output_dir, output_format=OutputFormat.HTML
        )
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            content = f.read()
        assert "修复率" in content or "fix_rate" in content or "%" in content

    def test_version_count_display(self, dark_chart, trend_input, temp_output_dir):
        result = dark_chart.generate(
            trend_input, output_dir=temp_output_dir, output_format=OutputFormat.HTML
        )
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            content = f.read()
        assert "4" in content  # 4 versions


# ─────────────────────── PNG 编码测试 ───────────────────────

class TestTrendPngEncoding:
    """PNG 编码工具测试"""

    def test_hex_to_rgb_png(self):
        assert _hex_to_rgb_png("#ff0000") == [255, 0, 0]

    def test_hex_to_rgb_png_short(self):
        assert _hex_to_rgb_png("#fff") == [255, 255, 255]

    def test_draw_line_png_horizontal(self):
        width, height = 50, 50
        pixels = [0, 0, 0] * (width * height)
        _draw_line_png(pixels, width, 0, 25, 49, 25, [255, 255, 255])
        # 线上应有白色像素
        found = False
        for x in range(50):
            idx = (25 * width + x) * 3
            if pixels[idx] == 255 and pixels[idx + 1] == 255 and pixels[idx + 2] == 255:
                found = True
                break
        assert found

    def test_draw_line_png_vertical(self):
        width, height = 50, 50
        pixels = [0, 0, 0] * (width * height)
        _draw_line_png(pixels, width, 25, 0, 25, 49, [255, 0, 0])
        found = False
        for y in range(50):
            idx = (y * width + 25) * 3
            if pixels[idx] == 255 and pixels[idx + 1] == 0:
                found = True
                break
        assert found

    def test_draw_line_png_out_of_bounds(self):
        """越界绘制不崩溃"""
        width, height = 30, 30
        pixels = [0, 0, 0] * (width * height)
        _draw_line_png(pixels, width, -10, -10, 100, 100, [255, 0, 0])

    def test_draw_text_png_basic(self):
        """绘制文本不崩溃"""
        width, height = 100, 20
        pixels = [0, 0, 0] * (width * height)
        _draw_text_png(pixels, width, 5, 5, "AB12", [255, 255, 255])

    def test_save_png_png_creates_file(self, temp_output_dir):
        """PNG 文件生成"""
        width, height = 20, 20
        pixels = [100, 150, 200] * (width * height)
        path = os.path.join(temp_output_dir, "trend_test.png")
        _save_png_png(pixels, width, height, path)
        assert os.path.exists(path)
        assert os.path.getsize(path) > 0

    def test_save_png_png_valid_signature(self, temp_output_dir):
        """PNG 文件签名正确"""
        width, height = 10, 10
        pixels = [255, 255, 255] * (width * height)
        path = os.path.join(temp_output_dir, "sig_test.png")
        _save_png_png(pixels, width, height, path)

        with open(path, "rb") as f:
            sig = f.read(8)
        assert sig == b'\x89PNG\r\n\x1a\n'

    def test_save_png_png_dimensions(self, temp_output_dir):
        """PNG 尺寸正确"""
        width, height = 30, 25
        pixels = [0, 128, 255] * (width * height)
        path = os.path.join(temp_output_dir, "dim_test.png")
        _save_png_png(pixels, width, height, path)

        with open(path, "rb") as f:
            data = f.read()
        png_w = struct.unpack(">I", data[16:20])[0]
        png_h = struct.unpack(">I", data[20:24])[0]
        assert png_w == width
        assert png_h == height


# ─────────────────────── 边界情况测试 ───────────────────────

class TestTrendEdgeCases:
    """边界情况测试"""

    def test_empty_input(self, dark_chart, empty_trend_input, temp_output_dir):
        """空输入数据"""
        result = dark_chart.generate(
            empty_trend_input, output_dir=temp_output_dir, output_format=OutputFormat.BOTH
        )
        assert result.total_versions == 0
        assert os.path.exists(result.output_path_html)
        assert os.path.exists(result.output_path_png)

    def test_single_point(self, dark_chart, temp_output_dir):
        """单数据点"""
        inp = TrendInput(points=[
            TrendPoint(
                version="v1", total_count=10,
                by_severity={"HIGH": 5, "MEDIUM": 5},
                fixed_count=0, new_count=10,
            )
        ])
        result = dark_chart.generate(
            inp, output_dir=temp_output_dir, output_format=OutputFormat.BOTH
        )
        assert result.total_versions == 1
        assert result.overall_change == 0.0
        assert os.path.exists(result.output_path_png)

    def test_same_count_no_change(self, dark_chart, temp_output_dir):
        """数量不变时变化率为 0"""
        inp = TrendInput(points=[
            TrendPoint(version="v1", total_count=20),
            TrendPoint(version="v2", total_count=20),
        ])
        result = dark_chart.generate(
            inp, output_dir=temp_output_dir, output_format=OutputFormat.HTML
        )
        assert result.overall_change == 0.0

    def test_increasing_count(self, dark_chart, temp_output_dir):
        """漏洞增加"""
        inp = TrendInput(points=[
            TrendPoint(version="v1", total_count=10),
            TrendPoint(version="v2", total_count=30),
        ])
        result = dark_chart.generate(
            inp, output_dir=temp_output_dir, output_format=OutputFormat.HTML
        )
        assert result.overall_change == 200.0  # (30-10)/10*100

    def test_decreasing_count(self, dark_chart, temp_output_dir):
        """漏洞减少"""
        inp = TrendInput(points=[
            TrendPoint(version="v1", total_count=100),
            TrendPoint(version="v2", total_count=25),
        ])
        result = dark_chart.generate(
            inp, output_dir=temp_output_dir, output_format=OutputFormat.HTML
        )
        assert result.overall_change == -75.0  # (25-100)/100*100

    def test_zero_to_nonzero(self, dark_chart, temp_output_dir):
        """从零开始"""
        inp = TrendInput(points=[
            TrendPoint(version="v1", total_count=0),
            TrendPoint(version="v2", total_count=10),
        ])
        result = dark_chart.generate(
            inp, output_dir=temp_output_dir, output_format=OutputFormat.HTML
        )
        # 0->10, first=0, 应返回 0（避免除以零）
        assert result.overall_change == 0.0

    def test_many_versions(self, dark_chart, temp_output_dir):
        """大量版本"""
        points = [
            TrendPoint(
                version=f"v{i}.0", total_count=50 - i * 2,
                by_severity={"HIGH": max(0, 10 - i), "MEDIUM": max(0, 20 - i)},
            )
            for i in range(20)
        ]
        inp = TrendInput(points=points)
        result = dark_chart.generate(
            inp, output_dir=temp_output_dir, output_format=OutputFormat.BOTH
        )
        assert result.total_versions == 20
        assert os.path.exists(result.output_path_png)

    def test_long_version_string(self, dark_chart, temp_output_dir):
        """长版本名"""
        inp = TrendInput(points=[
            TrendPoint(version="release-2024-01-01-build-1000-alpha", total_count=10),
        ])
        result = dark_chart.generate(
            inp, output_dir=temp_output_dir, output_format=OutputFormat.BOTH
        )
        assert os.path.exists(result.output_path_png)


# ─────────────────────── 综合场景测试 ───────────────────────

class TestTrendIntegration:
    """集成场景测试"""

    def test_full_pipeline(self, temp_output_dir):
        """完整管道"""
        points = [
            TrendPoint(
                version="v1", total_count=100,
                by_severity={"CRITICAL": 5, "HIGH": 20, "MEDIUM": 50, "LOW": 25},
                fixed_count=0, new_count=100, remaining_count=100,
            ),
            TrendPoint(
                version="v2", total_count=60,
                by_severity={"CRITICAL": 2, "HIGH": 10, "MEDIUM": 30, "LOW": 18},
                fixed_count=45, new_count=5, remaining_count=55,
            ),
            TrendPoint(
                version="v3", total_count=30,
                by_severity={"CRITICAL": 1, "HIGH": 5, "MEDIUM": 15, "LOW": 9},
                fixed_count=72, new_count=2, remaining_count=28,
            ),
        ]
        inp = TrendInput(points=points, project_name="integration-test")
        chart = VersionTrendChart(theme=ChartTheme.DARK)
        result = chart.generate(
            inp, output_dir=temp_output_dir, output_format=OutputFormat.BOTH,
            filename_prefix="integration_trend",
        )

        assert result.total_versions == 3
        assert result.overall_change == -70.0
        assert "integration_trend" in result.output_path_html
        assert "integration_trend" in result.output_path_png

        # 验证 HTML 结构完整
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            html = f.read()
        assert "<!DOCTYPE html>" in html
        assert "</html>" in html
        assert "<table>" in html
        assert "<canvas" in html

    def test_repeated_generation(self, temp_output_dir, sample_trend_points):
        """重复生成不互相干扰"""
        inp = TrendInput(points=sample_trend_points)
        chart = VersionTrendChart()

        r1 = chart.generate(inp, output_dir=temp_output_dir, filename_prefix="r1")
        r2 = chart.generate(inp, output_dir=temp_output_dir, filename_prefix="r2")

        assert r1.total_versions == r2.total_versions
        assert r1.overall_change == r2.overall_change
        assert r1.output_path_html != r2.output_path_html

    def test_no_fix_rate_mode(self, temp_output_dir, sample_trend_points):
        """不显示修复率"""
        inp = TrendInput(points=sample_trend_points)
        chart = VersionTrendChart(show_fix_rate=False)
        result = chart.generate(
            inp, output_dir=temp_output_dir, output_format=OutputFormat.HTML
        )
        assert os.path.exists(result.output_path_html)

    def test_fix_rate_boundary_values(self, temp_output_dir):
        """修复率边界值"""
        points = [
            TrendPoint(version="v1", fixed_count=0, remaining_count=100),
            TrendPoint(version="v2", fixed_count=50, remaining_count=50),
            TrendPoint(version="v3", fixed_count=100, remaining_count=0),
        ]
        inp = TrendInput(points=points)
        chart = VersionTrendChart()
        result = chart.generate(
            inp, output_dir=temp_output_dir, output_format=OutputFormat.HTML
        )
        # 不应出现 NaN 或 None 修复率
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            content = f.read()
        assert "nan" not in content.lower()
        assert "NaN" not in content

    def test_all_severities_represented(self, temp_output_dir):
        """所有严重度级别都在表中展示"""
        points = [
            TrendPoint(
                version="v1", total_count=31,
                by_severity={"CRITICAL": 1, "HIGH": 5, "MEDIUM": 10, "LOW": 10, "INFO": 5},
            ),
        ]
        inp = TrendInput(points=points)
        chart = VersionTrendChart()
        result = chart.generate(
            inp, output_dir=temp_output_dir, output_format=OutputFormat.HTML
        )
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            content = f.read()
        assert "CRITICAL" in content
        assert "HIGH" in content
        assert "MEDIUM" in content
        assert "LOW" in content


# ─────────────────────── 自定义前缀测试 ───────────────────────

class TestTrendCustomPrefix:
    """自定义文件前缀测试"""

    def test_custom_prefix_both(self, dark_chart, trend_input, temp_output_dir):
        result = dark_chart.generate(
            trend_input, output_dir=temp_output_dir,
            output_format=OutputFormat.BOTH,
            filename_prefix="security_audit_2024q1",
        )
        assert "security_audit_2024q1" in result.output_path_html
        assert "security_audit_2024q1" in result.output_path_png


# ─────────────────────── PNG 输出尺寸测试 ───────────────────────

class TestTrendPngSize:
    """PNG 尺寸校验"""

    def test_png_file_reasonable_size(self, dark_chart, trend_input, temp_output_dir):
        """PNG 文件大小合理"""
        result = dark_chart.generate(
            trend_input, output_dir=temp_output_dir, output_format=OutputFormat.PNG
        )
        size = os.path.getsize(result.output_path_png)
        assert size > 500  # 至少有内容
        assert size < 5_000_000  # < 5MB

    def test_png_valid_ihdr(self, dark_chart, trend_input, temp_output_dir):
        """PNG IHDR 正确"""
        result = dark_chart.generate(
            trend_input, output_dir=temp_output_dir, output_format=OutputFormat.PNG
        )
        with open(result.output_path_png, "rb") as f:
            data = f.read()
        # IHDR: width 和 height
        width = struct.unpack(">I", data[16:20])[0]
        height = struct.unpack(">I", data[20:24])[0]
        assert width == 900
        assert height == 450

    def test_png_decompressable(self, dark_chart, trend_input, temp_output_dir):
        """PNG IDAT 可解压"""
        result = dark_chart.generate(
            trend_input, output_dir=temp_output_dir, output_format=OutputFormat.PNG
        )
        with open(result.output_path_png, "rb") as f:
            data = f.read()
        # 找到 IDAT
        offset = 8
        idat_data = b""
        while offset < len(data):
            chunk_len = struct.unpack(">I", data[offset:offset + 4])[0]
            chunk_type = data[offset + 4:offset + 8]
            chunk_data = data[offset + 8:offset + 8 + chunk_len]
            if chunk_type == b"IDAT":
                idat_data = chunk_data
                break
            offset += 12 + chunk_len
        assert idat_data != b""
        decompressed = zlib.decompress(idat_data)
        assert len(decompressed) > 0
