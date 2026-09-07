"""
玄鉴 v2.5.1 — 漏洞热力图模块测试

测试覆盖率目标: >= 95%
测试子功能: 漏洞热力图生成 (VulnerabilityHeatmap)

版本: 2.5.1
"""

import json
import os
import struct
import tempfile
import zlib
from pathlib import Path

import pytest

from fp_sentinel.visualization.heatmap import (
    VulnerabilityHeatmap,
    _hex_to_rgb,
    _draw_rect,
    _draw_line,
    _draw_text,
    _save_png,
)
from fp_sentinel.visualization.models import (
    ChartTheme,
    HeatmapInput,
    OutputFormat,
    SEVERITY_WEIGHT,
    VULN_TYPE_DISPLAY,
    get_risk_color,
    get_theme_background,
    get_theme_text_color,
)


# ─────────────────────── Fixtures ───────────────────────

@pytest.fixture
def sample_heatmap_data():
    """生成标准热力图输入数据"""
    return {
        ("auth", "SQL_INJECTION"): {"CRITICAL": 1, "HIGH": 2},
        ("auth", "XSS"): {"HIGH": 1, "MEDIUM": 3},
        ("api", "SQL_INJECTION"): {"HIGH": 4, "MEDIUM": 2, "LOW": 1},
        ("api", "SSRF"): {"CRITICAL": 2, "HIGH": 1},
        ("core", "PATH_TRAVERSAL"): {"MEDIUM": 2, "LOW": 1},
        ("core", "DESERIALIZATION"): {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1},
    }


@pytest.fixture
def heatmap_input(sample_heatmap_data):
    """标准 HeatmapInput 实例"""
    return HeatmapInput(
        data=sample_heatmap_data,
        project_name="test-project",
        scan_time="2024-01-15T10:30:00",
    )


@pytest.fixture
def empty_heatmap_input():
    """空 HeatmapInput 实例"""
    return HeatmapInput(data={}, project_name="empty-project")


@pytest.fixture
def temp_output_dir():
    """临时输出目录"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def default_generator():
    """默认 VulnerabilityHeatmap 实例"""
    return VulnerabilityHeatmap()


@pytest.fixture
def dark_generator():
    """深色主题生成器"""
    return VulnerabilityHeatmap(theme=ChartTheme.DARK)


@pytest.fixture
def light_generator():
    """浅色主题生成器"""
    return VulnerabilityHeatmap(theme=ChartTheme.LIGHT)


@pytest.fixture
def hc_generator():
    """高对比度主题生成器"""
    return VulnerabilityHeatmap(theme=ChartTheme.HIGH_CONTRAST)


# ─────────────────────── HeatmapInput 测试 ───────────────────────

class TestHeatmapInput:
    """HeatmapInput 数据模型测试"""

    def test_modules_property(self, heatmap_input):
        modules = heatmap_input.modules
        assert "api" in modules
        assert "auth" in modules
        assert "core" in modules
        assert len(modules) == 3

    def test_modules_property_correct(self, heatmap_input):
        modules = heatmap_input.modules
        assert set(modules) == {"api", "auth", "core"}

    def test_modules_sorted(self, heatmap_input):
        modules = heatmap_input.modules
        assert modules == sorted(modules)

    def test_vuln_types_property(self, heatmap_input):
        types = heatmap_input.vuln_types
        assert "SQL_INJECTION" in types
        assert "XSS" in types
        assert "SSRF" in types
        assert "PATH_TRAVERSAL" in types
        assert "DESERIALIZATION" in types

    def test_total_count(self, heatmap_input):
        total = heatmap_input.total_count()
        assert total == 26  # sum of all counts

    def test_get_value(self, heatmap_input):
        assert heatmap_input.get_value("auth", "XSS") == 4  # 1 HIGH + 3 MEDIUM
        assert heatmap_input.get_value("api", "SSRF") == 3   # 2 CRITICAL + 1 HIGH
        assert heatmap_input.get_value("nonexist", "XSS") == 0

    def test_get_severity_breakdown(self, heatmap_input):
        breakdown = heatmap_input.get_severity_breakdown("auth", "SQL_INJECTION")
        assert breakdown == {"CRITICAL": 1, "HIGH": 2}

    def test_get_severity_breakdown_missing(self, heatmap_input):
        breakdown = heatmap_input.get_severity_breakdown("nonexist", "XSS")
        assert breakdown == {}

    def test_max_value(self, heatmap_input):
        max_val = heatmap_input.max_value
        # api/SQL_INJECTION = 4+2+1 = 7, which is the max
        assert max_val == 7

    def test_empty_input(self, empty_heatmap_input):
        assert empty_heatmap_input.modules == []
        assert empty_heatmap_input.vuln_types == []
        assert empty_heatmap_input.total_count() == 0
        assert empty_heatmap_input.max_value == 0


# ─────────────────────── 颜色工具测试 ───────────────────────

class TestColorUtils:
    """颜色工具函数测试"""

    def test_hex_to_rgb_short(self):
        assert _hex_to_rgb("#fff") == [255, 255, 255]

    def test_hex_to_rgb_long(self):
        assert _hex_to_rgb("#ff0000") == [255, 0, 0]

    def test_hex_to_rgb_no_hash(self):
        assert _hex_to_rgb("00ff00") == [0, 255, 0]

    def test_get_risk_color_dark(self):
        c = get_risk_color(0, ChartTheme.DARK)
        assert c.startswith("#")
        assert len(c) == 7

    def test_get_risk_color_light(self):
        c = get_risk_color(5, ChartTheme.LIGHT)
        assert c.startswith("#")

    def test_get_risk_color_high_contrast(self):
        c = get_risk_color(10, ChartTheme.HIGH_CONTRAST)
        assert c == "#000000"

    def test_get_risk_color_extremes(self):
        c0 = get_risk_color(0)
        c10 = get_risk_color(10)
        assert c0 != c10

    def test_get_theme_background(self):
        assert get_theme_background(ChartTheme.DARK) == "#0d1117"
        assert get_theme_background(ChartTheme.LIGHT) == "#ffffff"
        assert get_theme_background(ChartTheme.HIGH_CONTRAST) == "#ffffff"

    def test_get_theme_text_color(self):
        assert get_theme_text_color(ChartTheme.DARK) == "#c9d1d9"
        assert get_theme_text_color(ChartTheme.LIGHT) == "#212529"


# ─────────────────────── 常量测试 ───────────────────────

class TestConstants:
    """常量定义测试"""

    def test_severity_weight_complete(self):
        assert "CRITICAL" in SEVERITY_WEIGHT
        assert "HIGH" in SEVERITY_WEIGHT
        assert "MEDIUM" in SEVERITY_WEIGHT
        assert "LOW" in SEVERITY_WEIGHT
        assert "INFO" in SEVERITY_WEIGHT

    def test_severity_weight_order(self):
        assert SEVERITY_WEIGHT["CRITICAL"] > SEVERITY_WEIGHT["HIGH"]
        assert SEVERITY_WEIGHT["HIGH"] > SEVERITY_WEIGHT["MEDIUM"]
        assert SEVERITY_WEIGHT["MEDIUM"] > SEVERITY_WEIGHT["LOW"]
        assert SEVERITY_WEIGHT["LOW"] > SEVERITY_WEIGHT["INFO"]

    def test_vuln_type_display_key_types(self):
        assert "SQL_INJECTION" in VULN_TYPE_DISPLAY
        assert "XSS" in VULN_TYPE_DISPLAY
        assert "COMMAND_INJECTION" in VULN_TYPE_DISPLAY


# ─────────────────────── PNG 编码工具测试 ───────────────────────

class TestPngEncoding:
    """PNG 编码工具函数测试"""

    def test_draw_rect(self):
        width, height = 100, 100
        pixels = [255, 255, 255] * (width * height)
        _draw_rect(pixels, width, 10, 10, 20, 20, [255, 0, 0])

        # 左上角点检查 (R 分量)
        idx = (10 * width + 10) * 3
        assert pixels[idx] == 255
        assert pixels[idx + 1] == 0
        assert pixels[idx + 2] == 0
        # 外部不变
        idx_out = (0 * width + 0) * 3
        assert pixels[idx_out] == 255
        assert pixels[idx_out + 1] == 255
        assert pixels[idx_out + 2] == 255

    def test_draw_line_horizontal(self):
        width, height = 100, 100
        pixels = [0, 0, 0] * (width * height)
        _draw_line(pixels, width, 0, 50, 99, 50, [255, 255, 255])
        # 线上至少有一个白像素
        found_white = False
        for x in range(100):
            idx = (50 * width + x) * 3
            if pixels[idx] == 255 and pixels[idx + 1] == 255 and pixels[idx + 2] == 255:
                found_white = True
                break
        assert found_white

    def test_draw_line_vertical(self):
        width, height = 100, 100
        pixels = [0, 0, 0] * (width * height)
        _draw_line(pixels, width, 50, 0, 50, 99, [255, 255, 255])
        found_white = False
        for y in range(100):
            idx = (y * width + 50) * 3
            if pixels[idx] == 255 and pixels[idx + 1] == 255 and pixels[idx + 2] == 255:
                found_white = True
                break
        assert found_white

    def test_draw_line_diagonal(self):
        width, height = 50, 50
        pixels = [0, 0, 0] * (width * height)
        _draw_line(pixels, width, 0, 0, 49, 49, [255, 0, 0])
        # 对角线上应有红色
        idx = (25 * width + 25) * 3
        assert pixels[idx] == 255
        assert pixels[idx + 1] == 0
        assert pixels[idx + 2] == 0

    def test_draw_line_out_of_bounds(self):
        """越界绘制不崩溃"""
        width, height = 50, 50
        pixels = [0, 0, 0] * (width * height)
        # 起点和终点都在界外，应不崩溃
        _draw_line(pixels, width, -10, -10, 100, 100, [255, 0, 0])

    def test_save_png_creates_file(self, temp_output_dir):
        """PNG 文件生成"""
        width, height = 10, 10
        pixels = [128, 64, 32] * (width * height)
        path = os.path.join(temp_output_dir, "test.png")
        _save_png(pixels, width, height, path)
        assert os.path.exists(path)
        assert os.path.getsize(path) > 0

    def test_save_png_valid_format(self, temp_output_dir):
        """PNG 文件格式校验"""
        width, height = 10, 10
        pixels = [255, 0, 0] * (width * height)
        path = os.path.join(temp_output_dir, "test.png")
        _save_png(pixels, width, height, path)

        with open(path, "rb") as f:
            data = f.read()

        # PNG 签名
        assert data[:8] == b'\x89PNG\r\n\x1a\n'

        # IHDR 块
        ihdr_len = struct.unpack(">I", data[8:12])[0]
        assert ihdr_len == 13  # IHDR 数据长度为 13
        assert data[12:16] == b"IHDR"

        # 宽高校验
        png_width = struct.unpack(">I", data[16:20])[0]
        png_height = struct.unpack(">I", data[20:24])[0]
        assert png_width == width
        assert png_height == height

    def test_save_png_roundtrip_data(self, temp_output_dir):
        """PNG 数据可正确解码"""
        width, height = 4, 4
        pixels = []
        for y in range(height):
            for x in range(width):
                pixels.extend([x * 60, y * 60, 128])

        path = os.path.join(temp_output_dir, "roundtrip.png")
        _save_png(pixels, width, height, path)

        with open(path, "rb") as f:
            data = f.read()

        # 定位 IDAT 块并解压缩
        offset = 8  # 跳过签名
        idat_data = b""
        while offset < len(data):
            chunk_len = struct.unpack(">I", data[offset:offset + 4])[0]
            chunk_type = data[offset + 4:offset + 8]
            chunk_data = data[offset + 8:offset + 8 + chunk_len]
            if chunk_type == b"IDAT":
                idat_data = chunk_data
                break
            offset += 12 + chunk_len

        decompressed = zlib.decompress(idat_data)
        # 扫描行 = height * (1 + width * 3)
        expected_len = height * (1 + width * 3)
        assert len(decompressed) == expected_len

    def test_save_png_single_color(self, temp_output_dir):
        """单色大图 PNG 生成"""
        width, height = 200, 200
        pixels = [100, 150, 200] * (width * height)
        path = os.path.join(temp_output_dir, "large.png")
        _save_png(pixels, width, height, path)
        assert os.path.exists(path)


# ─────────────────────── VulnerabilityHeatmap 核心测试 ───────────────────────

class TestVulnerabilityHeatmapInit:
    """初始化测试"""

    def test_default_init(self):
        gen = VulnerabilityHeatmap()
        assert gen.theme == ChartTheme.DARK
        assert gen.cell_size == 60

    def test_custom_init(self):
        gen = VulnerabilityHeatmap(theme=ChartTheme.LIGHT, cell_size=80)
        assert gen.theme == ChartTheme.LIGHT
        assert gen.cell_size == 80

    def test_high_contrast_init(self):
        gen = VulnerabilityHeatmap(theme=ChartTheme.HIGH_CONTRAST)
        assert gen.theme == ChartTheme.HIGH_CONTRAST


class TestHeatmapGeneration:
    """热力图生成测试"""

    def test_generate_both_formats(self, dark_generator, heatmap_input, temp_output_dir):
        """同时生成 HTML 和 PNG"""
        result = dark_generator.generate(
            heatmap_input, output_dir=temp_output_dir, output_format=OutputFormat.BOTH
        )
        assert result.output_path_html is not None
        assert result.output_path_png is not None
        assert os.path.exists(result.output_path_html)
        assert os.path.exists(result.output_path_png)

    def test_generate_html_only(self, dark_generator, heatmap_input, temp_output_dir):
        """仅生成 HTML"""
        result = dark_generator.generate(
            heatmap_input, output_dir=temp_output_dir, output_format=OutputFormat.HTML
        )
        assert result.output_path_html is not None
        assert result.output_path_png is None

    def test_generate_png_only(self, dark_generator, heatmap_input, temp_output_dir):
        """仅生成 PNG"""
        result = dark_generator.generate(
            heatmap_input, output_dir=temp_output_dir, output_format=OutputFormat.PNG
        )
        assert result.output_path_html is None
        assert result.output_path_png is not None

    def test_generate_creates_directory(self, dark_generator, heatmap_input, temp_output_dir):
        """自动创建输出目录"""
        new_dir = os.path.join(temp_output_dir, "nested", "deep", "dir")
        result = dark_generator.generate(
            heatmap_input, output_dir=new_dir, output_format=OutputFormat.HTML
        )
        assert os.path.isdir(new_dir)

    def test_result_cells_populated(self, dark_generator, heatmap_input, temp_output_dir):
        """结果中单元格数据正确"""
        result = dark_generator.generate(
            heatmap_input, output_dir=temp_output_dir,
            output_format=OutputFormat.HTML,
        )
        assert len(result.cells) > 0
        # 每个 cell 应该有 module, vuln_type, count
        for cell in result.cells:
            assert cell.module
            assert cell.vuln_type
            assert cell.count > 0
            assert cell.risk_score >= 0

    def test_result_total_findings(self, dark_generator, heatmap_input, temp_output_dir):
        """总漏洞数正确"""
        result = dark_generator.generate(
            heatmap_input, output_dir=temp_output_dir,
            output_format=OutputFormat.HTML,
        )
        assert result.total_findings == heatmap_input.total_count()

    def test_result_modules_and_types(self, dark_generator, heatmap_input, temp_output_dir):
        """模块和类型列表正确"""
        result = dark_generator.generate(
            heatmap_input, output_dir=temp_output_dir,
            output_format=OutputFormat.HTML,
        )
        assert set(result.modules) == set(heatmap_input.modules)
        assert set(result.vuln_types) == set(heatmap_input.vuln_types)


class TestHeatmapThemes:
    """不同主题生成测试"""

    def test_dark_theme_output(self, dark_generator, heatmap_input, temp_output_dir):
        result = dark_generator.generate(
            heatmap_input, output_dir=temp_output_dir,
            output_format=OutputFormat.HTML,
        )
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            content = f.read()
        assert "#0d1117" in content  # dark background

    def test_light_theme_output(self, light_generator, heatmap_input, temp_output_dir):
        result = light_generator.generate(
            heatmap_input, output_dir=temp_output_dir,
            output_format=OutputFormat.HTML,
        )
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            content = f.read()
        assert "#ffffff" in content  # light background

    def test_hc_theme_output(self, hc_generator, heatmap_input, temp_output_dir):
        result = hc_generator.generate(
            heatmap_input, output_dir=temp_output_dir,
            output_format=OutputFormat.HTML,
        )
        assert result.output_path_html is not None

    def test_all_themes_png(self, heatmap_input, temp_output_dir):
        """所有主题都能生成 PNG"""
        for theme in [ChartTheme.DARK, ChartTheme.LIGHT, ChartTheme.HIGH_CONTRAST]:
            gen = VulnerabilityHeatmap(theme=theme)
            result = gen.generate(
                heatmap_input, output_dir=temp_output_dir,
                output_format=OutputFormat.PNG,
                filename_prefix=f"test_{theme.value}",
            )
            assert os.path.exists(result.output_path_png)


class TestHeatmapEmptyData:
    """空数据场景测试"""

    def test_empty_data_html(self, dark_generator, empty_heatmap_input, temp_output_dir):
        result = dark_generator.generate(
            empty_heatmap_input, output_dir=temp_output_dir,
            output_format=OutputFormat.HTML,
        )
        assert result.total_findings == 0
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            content = f.read()
        assert "无漏洞数据" in content or "No data" in content or "无数据" in content

    def test_empty_data_png(self, dark_generator, empty_heatmap_input, temp_output_dir):
        result = dark_generator.generate(
            empty_heatmap_input, output_dir=temp_output_dir,
            output_format=OutputFormat.PNG,
        )
        assert os.path.exists(result.output_path_png)

    def test_empty_cells(self, dark_generator, empty_heatmap_input, temp_output_dir):
        result = dark_generator.generate(
            empty_heatmap_input, output_dir=temp_output_dir,
            output_format=OutputFormat.HTML,
        )
        assert result.cells == []


class TestHeatmapEdgeCases:
    """边界情况测试"""

    def test_single_cell(self, dark_generator, temp_output_dir):
        """单个单元格"""
        inp = HeatmapInput(
            data={("module1", "XSS"): {"HIGH": 5}},
            project_name="single",
        )
        result = dark_generator.generate(
            inp, output_dir=temp_output_dir, output_format=OutputFormat.BOTH,
        )
        assert result.total_findings == 5
        assert len(result.cells) == 1
        assert result.cells[0].count == 5

    def test_single_severity(self, dark_generator, temp_output_dir):
        """全部同一严重度"""
        inp = HeatmapInput(
            data={
                ("a", "XSS"): {"CRITICAL": 10},
                ("b", "XSS"): {"CRITICAL": 5},
            },
        )
        result = dark_generator.generate(
            inp, output_dir=temp_output_dir, output_format=OutputFormat.HTML,
        )
        assert result.total_findings == 15

    def test_large_count(self, dark_generator, temp_output_dir):
        """大数字"""
        inp = HeatmapInput(
            data={("big", "SQL_INJECTION"): {"HIGH": 999}},
        )
        result = dark_generator.generate(
            inp, output_dir=temp_output_dir, output_format=OutputFormat.BOTH,
        )
        assert result.total_findings == 999
        assert os.path.exists(result.output_path_png)

    def test_zero_count_entries_filtered(self, dark_generator, temp_output_dir):
        """零计数的条目被过滤"""
        inp = HeatmapInput(
            data={
                ("a", "XSS"): {"HIGH": 0, "CRITICAL": 0},
                ("b", "XSS"): {"HIGH": 5},
            },
        )
        result = dark_generator.generate(
            inp, output_dir=temp_output_dir, output_format=OutputFormat.HTML,
        )
        # 单元格 a/XSS 应被过滤（全零）
        cells_modules = [(c.module, c.vuln_type) for c in result.cells]
        assert ("a", "XSS") not in cells_modules
        assert ("b", "XSS") in cells_modules

    def test_many_modules(self, dark_generator, temp_output_dir):
        """大量模块"""
        data = {(f"module_{i}", "XSS"): {"HIGH": i + 1} for i in range(20)}
        inp = HeatmapInput(data=data)
        result = dark_generator.generate(
            inp, output_dir=temp_output_dir, output_format=OutputFormat.BOTH,
        )
        assert len(result.modules) == 20

    def test_special_chars_in_module_name(self, dark_generator, temp_output_dir):
        """模块名含特殊字符（HTML 转义）"""
        inp = HeatmapInput(
            data={("auth/api/v2", "XSS"): {"HIGH": 3}},
        )
        result = dark_generator.generate(
            inp, output_dir=temp_output_dir, output_format=OutputFormat.HTML,
        )
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            content = f.read()
        # module name should be present
        assert "auth/api/v2" in content or "auth&#x2F;api&#x2F;v2" in content


class TestHeatmapRiskScore:
    """风险评分计算测试"""

    def test_all_critical_max_score(self, dark_generator, temp_output_dir):
        """全 CRITICAL 时风险分最高"""
        inp = HeatmapInput(
            data={("a", "XSS"): {"CRITICAL": 10}},
        )
        result = dark_generator.generate(
            inp, output_dir=temp_output_dir, output_format=OutputFormat.HTML,
        )
        cell = result.cells[0]
        # CRITICAL weight = 1.0, so risk should be close to 10
        assert cell.risk_score >= 9.0

    def test_all_info_min_score(self, dark_generator, temp_output_dir):
        """全 INFO 时风险分最低"""
        inp = HeatmapInput(
            data={("a", "XSS"): {"INFO": 10}},
        )
        result = dark_generator.generate(
            inp, output_dir=temp_output_dir, output_format=OutputFormat.HTML,
        )
        cell = result.cells[0]
        # INFO weight = 0.1, so risk should be ~1
        assert cell.risk_score <= 2.0

    def test_mixed_severity_score(self, dark_generator, temp_output_dir):
        """混合严重度评分计算"""
        inp = HeatmapInput(
            data={("a", "XSS"): {"CRITICAL": 1, "LOW": 1}},
        )
        result = dark_generator.generate(
            inp, output_dir=temp_output_dir, output_format=OutputFormat.HTML,
        )
        cell = result.cells[0]
        # (1.0 * 1 + 0.3 * 1) / 2 * 10 = 6.5
        assert 5.0 <= cell.risk_score <= 7.5


class TestHeatmapHtmlContent:
    """HTML 内容校验"""

    def test_html_has_title(self, dark_generator, heatmap_input, temp_output_dir):
        result = dark_generator.generate(
            heatmap_input, output_dir=temp_output_dir,
            output_format=OutputFormat.HTML,
        )
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            content = f.read()
        assert "<title>" in content
        assert "test-project" in content

    def test_html_has_table(self, dark_generator, heatmap_input, temp_output_dir):
        result = dark_generator.generate(
            heatmap_input, output_dir=temp_output_dir,
            output_format=OutputFormat.HTML,
        )
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            content = f.read()
        assert "<table>" in content

    def test_html_has_stats_cards(self, dark_generator, heatmap_input, temp_output_dir):
        result = dark_generator.generate(
            heatmap_input, output_dir=temp_output_dir,
            output_format=OutputFormat.HTML,
        )
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            content = f.read()
        assert "stat-card" in content

    def test_html_no_external_deps(self, dark_generator, heatmap_input, temp_output_dir):
        """HTML 不包含外部依赖（CDN / script src）"""
        result = dark_generator.generate(
            heatmap_input, output_dir=temp_output_dir,
            output_format=OutputFormat.HTML,
        )
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            content = f.read()
        assert "<script src=" not in content
        assert "cdn." not in content.lower()


class TestHeatmapPngContent:
    """PNG 内容校验"""

    def test_png_has_content(self, dark_generator, heatmap_input, temp_output_dir):
        result = dark_generator.generate(
            heatmap_input, output_dir=temp_output_dir,
            output_format=OutputFormat.PNG,
        )
        assert os.path.getsize(result.output_path_png) > 100

    def test_png_dimensions_reasonable(self, dark_generator, heatmap_input, temp_output_dir):
        """PNG 尺寸合理"""
        result = dark_generator.generate(
            heatmap_input, output_dir=temp_output_dir,
            output_format=OutputFormat.PNG,
        )
        with open(result.output_path_png, "rb") as f:
            data = f.read()
        # 从 IHDR 读取宽高
        width = struct.unpack(">I", data[16:20])[0]
        height = struct.unpack(">I", data[20:24])[0]
        # 3 modules + 5 vuln_types => larger image
        assert width > 200
        assert height > 100


class TestHeatmapMetadata:
    """元数据测试"""

    def test_metadata_populated(self, dark_generator, heatmap_input, temp_output_dir):
        result = dark_generator.generate(
            heatmap_input, output_dir=temp_output_dir,
            output_format=OutputFormat.HTML,
        )
        assert result.metadata["project_name"] == "test-project"
        assert result.metadata["theme"] == "dark"
        assert "generated_at" in result.metadata


class TestHeatmapCustomPrefix:
    """自定义文件名前缀测试"""

    def test_custom_prefix(self, dark_generator, heatmap_input, temp_output_dir):
        result = dark_generator.generate(
            heatmap_input, output_dir=temp_output_dir,
            output_format=OutputFormat.BOTH,
            filename_prefix="my_custom_report",
        )
        assert "my_custom_report" in result.output_path_html
        assert "my_custom_report" in result.output_path_png


# ─────────────────────── 综合场景测试 ───────────────────────

class TestHeatmapIntegration:
    """集成场景测试"""

    def test_full_pipeline_both_formats(self, temp_output_dir, sample_heatmap_data):
        """完整管道：输入 -> 处理 -> 输出"""
        inp = HeatmapInput(
            data=sample_heatmap_data,
            project_name="integration-test",
            scan_time="2024-01-15T10:30:00",
        )
        gen = VulnerabilityHeatmap(theme=ChartTheme.DARK)
        result = gen.generate(
            inp, output_dir=temp_output_dir, output_format=OutputFormat.BOTH
        )

        assert result.total_findings == 26
        assert len(result.cells) > 0
        assert os.path.exists(result.output_path_html)
        assert os.path.exists(result.output_path_png)
        assert len(result.modules) == 3

        # 验证 HTML 有效性
        with open(result.output_path_html, "r", encoding="utf-8") as f:
            html_content = f.read()
        assert html_content.startswith("<!DOCTYPE html>")
        assert "</html>" in html_content

    def test_repeated_generation(self, temp_output_dir, sample_heatmap_data):
        """重复生成不互相干扰"""
        inp = HeatmapInput(data=sample_heatmap_data)
        gen = VulnerabilityHeatmap()

        result1 = gen.generate(inp, output_dir=temp_output_dir,
                                filename_prefix="run1")
        result2 = gen.generate(inp, output_dir=temp_output_dir,
                                filename_prefix="run2")

        assert result1.total_findings == result2.total_findings
        assert result1.output_path_html != result2.output_path_html

    def test_different_themes_same_data(self, temp_output_dir, sample_heatmap_data):
        """不同主题使用相同数据"""
        inp = HeatmapInput(data=sample_heatmap_data)
        results = []
        for theme in [ChartTheme.DARK, ChartTheme.LIGHT, ChartTheme.HIGH_CONTRAST]:
            gen = VulnerabilityHeatmap(theme=theme)
            result = gen.generate(inp, output_dir=temp_output_dir,
                                  filename_prefix=f"theme_{theme.value}",
                                  output_format=OutputFormat.HTML)
            results.append(result)

        # 所有结果应有相同数量的单元格
        cell_counts = [len(r.cells) for r in results]
        assert len(set(cell_counts)) == 1

        # 但颜色不同
        colors = [r.cells[0].color for r in results if r.cells]
        assert len(set(colors)) > 1
