# 玄鉴 v2.4.0 — 漏洞热力图生成 (Vulnerability Heatmap)

> 版本: v2.4.0 ｜ 生成日期: 2026-09-08 ｜ 模块归属: 知识图谱可视化

---

## 一、功能概述

漏洞热力图生成器按模块、漏洞类型、严重程度三维度生成项目风险热力图。
支持 HTML 交互式（Self-contained，纯内联 CSS+JS，零外部依赖）与 PNG 静态图
（zlib+struct 编码，纯标准库）两种输出格式。

---

## 二、子功能清单

| 编号 | 功能 | 实现文件 | 测试文件 |
|------|------|---------|---------|
| A1 | 数据模型定义 | `fp_sentinel/visualization/models.py` | `tests/unit/test_visualization_heatmap.py` |
| A2 | 热力图生成核心逻辑 | `fp_sentinel/visualization/heatmap.py` | `tests/unit/test_visualization_heatmap.py` |
| A3 | HTML 交互输出 | `fp_sentinel/visualization/heatmap.py._render_html()` | 同上 |
| A4 | PNG 静态图输出 | `fp_sentinel/visualization/heatmap.py._render_png()` | 同上 |

---

## 三、核心 API

### 3.1 HeatmapInput

```python
@dataclass
class heatmapInput:
    data: Dict[Tuple[str, str], Dict[str, int]]  # {(module, vuln_type): {severity: count}}
    project_name: str = ""
    scan_time: Optional[str] = None
```

### 3.2 VulnerabilityHeatmap

```python
class VulnerabilityHeatmap:
    def __init__(
        self,
        theme: ChartTheme = ChartTheme.DARK,
        cell_size: int = 60,
        font_size: int = 12,
    )

    def generate(
        self,
        inp: HeatmapInput,
        output_dir: str = "./reports",
        output_format: OutputFormat = OutputFormat.BOTH,
        filename_prefix: str = "vuln_heatmap",
    ) -> HeatmapResult
```

---

## 四、使用示例

```python
from fp_sentinel.visualization import VulnerabilityHeatmap, HeatmapInput, ChartTheme

data = {
    ("auth", "SQL_INJECTION"): {"CRITICAL": 1, "HIGH": 2},
    ("api", "XSS"): {"HIGH": 3, "MEDIUM": 2},
}
inp = HeatmapInput(data=data, project_name="my-app")
gen = VulnerabilityHeatmap(theme=ChartTheme.DARK)
result = gen.generate(inp, output_dir="./reports", output_format=OutputFormat.BOTH)
# result.output_path_html, result.output_path_png
```

---

## 五、测试结果

| 测试文件 | 用例数 | 全部通过 | 覆盖率 |
|---------|-------|---------|-------|
| `tests/unit/test_visualization_heatmap.py` | 68 | 68 | ~98% |

---

## 六、测试覆盖分类

| 分类 | 用例数 | 说明 |
|------|-------|------|
| 数据模型 | 9 | HeatmapInput 属性计算、空数据 |
| 颜色工具 | 9 | hex_to_rgb、get_risk_color、主题 |
| 常量定义 | 3 | SEVERITY_WEIGHT、VULN_TYPE_DISPLAY |
| PNG 编码 | 8 | draw_rect/line/text、save_png/roundtrip |
| 生成器初始化 | 3 | 默认/自定义/高对比度 |
| 生成管道 | 8 | HTML/PNG/BOTH 输出、目录创建、元数据 |
| 主题 | 4 | DARK/LIGHT/HIGH_CONTRAST |
| 空数据 | 3 | 空数据 HTML/PNG、空单元格 |
| 边界情况 | 9 | 单单元格、大数、零过滤、特殊字符 |
| 风险评分 | 3 | CRITICAL/INFO/混合 |
| HTML 内容 | 4 | 标题、表格、统计卡、零外部依赖 |
| PNG 内容 | 2 | 文件大小、尺寸合理性 |
| 综合场景 | 3 | 完整管道、重复生成、多主题 |

---

## 七、变更说明

### v2.4.0 新增

- **新增模块**: `fp_sentinel/visualization/` (models.py, heatmap.py, version_trend.py, \_\_init\_\_.py)
- **新增数据模型**: HeatmapInput, HeatmapCell, HeatmapResult, TrendPoint, TrendResult, TrendInput
- **新增图表类型**: VulnerabilityHeatmap, VersionTrendChart
- **输出格式**: HTML (自包含) + PNG (zlib+struct，零第三方依赖)
- **配色主题**: dark / light / high_contrast
- **风险评分**: 0-10 分，基于 SEVERITY_WEIGHT 加权平均

### 兼容影响

- 不影响任何现有模块
- `fp_sentinel/__init__.py` 未修改（仅 visualization/\_\_init\_\_.py 定义自身版本）
- 不引入新的 pip install 依赖

---

## 八、PNG 编码技术说明

PNG 使用 Python 标准库 `zlib` + `struct` 编码，不依赖 matplotlib/Pillow：
1. 将绘图输出到 RGB 扁平整数列表 `[R,G,B,R,G,B,...]`
2. 添加 filter byte 0（None）构建扫描行
3. zlib 压缩（level 9）
4. 构造 IHDR + IDAT + IEND 块
5. 写入文件

5x7 点阵字体覆盖 A-Z, 0-9 及常用符号。

---

## 九、安全合规

| 红线 | 状态 |
|------|------|
| S1 禁止外网请求 | 模块零网络调用 |
| S2 禁止修改用户代码 | 只读分析、生成报告文件 |
| S3 禁止删除文件 | 仅写入到新文件 |
| S7 输出路径白限 | 由调用方指定 output_dir |

---

## 十、文件结构

```
fp_sentinel/visualization/
├── __init__.py          # 模块入口、公共 API
├── models.py            # 数据模型、颜色映射、主题
├── heatmap.py           # 漏洞热力图生成器
└── version_trend.py     # 版本变化趋势图生成器

tests/unit/
├── test_visualization_heatmap.py    # 68 用例
└── test_visualization_version_trend.py  # 58 用例
```

---

*文档由 CatPaw Agent 根据 v2.4.0 Knowledge Graph Visualization Module 开发结果自动生成*
