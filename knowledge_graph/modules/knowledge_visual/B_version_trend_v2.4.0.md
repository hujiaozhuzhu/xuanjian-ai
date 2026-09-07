# 玄鉴 v2.5.1 — 版本变化趋势图 (Version Trend Chart)

> 版本: v2.5.1 ｜ 生成日期: 2026-09-08 ｜ 模块归属: 知识图谱可视化

---

## 一、功能概述

版本变化趋势图生成器展示不同版本间漏洞数量、严重程度、修复率的变化趋势。
支持 HTML 交互式（内联 Canvas 折线图，零外部 JS 依赖）与 PNG 静态图
（zlib+struct 编码，纯标准库）两种输出格式。

---

## 二、核心 API

### 2.1 TrendPoint

```python
@dataclass
class TrendPoint:
    version: str                                # 版本号
    scan_time: Optional[str] = None
    total_count: int = 0
    by_severity: Dict[str, int] = field(default_factory=dict)
    fixed_count: int = 0
    new_count: int = 0
    remaining_count: int = 0
```

### 2.2 VersionTrendChart

```python
class VersionTrendChart:
    def __init__(
        self,
        theme: ChartTheme = ChartTheme.DARK,
        show_fix_rate: bool = True,
    )

    def generate(
        self,
        inp: TrendInput,
        output_dir: str = "./reports",
        output_format: OutputFormat = OutputFormat.BOTH,
        filename_prefix: str = "version_trend",
    ) -> TrendResult
```

---

## 三、使用示例

```python
from fp_sentinel.visualization import VersionTrendChart, TrendInput, TrendPoint

points = [
    TrendPoint(version="v1.0", total_count=50,
               by_severity={"CRITICAL": 3, "HIGH": 12, "MEDIUM": 20},
               fixed_count=0, new_count=50),
    TrendPoint(version="v1.1", total_count=35,
               by_severity={"CRITICAL": 2, "HIGH": 8, "MEDIUM": 15},
               fixed_count=18, new_count=3),
]
inp = TrendInput(points=points, project_name="my-app")
chart = VersionTrendChart(theme=ChartTheme.DARK)
result = chart.generate(inp, output_dir="./reports", output_format=OutputFormat.BOTH)
# result.output_path_html, result.output_path_png
```

---

## 四、测试结果

| 测试文件 | 用例数 | 全部通过 | 覆盖率 |
|---------|-------|---------|-------|
| `tests/unit/test_visualization_version_trend.py` | 58 | 58 | ~97% |

---

## 五、测试覆盖分类

| 分类 | 用例数 | 说明 |
|------|-------|------|
| TrendPoint 模型 | 6 | fix_rate 计算、critical_high_count |
| TrendInput 模型 | 6 | has_data、指标序列提取 |
| 生成器初始化 | 3 | 默认/自定义主题/fix_rate 开关 |
| 趋势图生成 | 6 | BOTH/HTML/PNG、目录创建、元数据 |
| 主题 | 3 | DARK/LIGHT/HIGH_CONTRAST PNG |
| HTML 内容 | 8 | canvas/table/版本/统计卡/JS/零依赖/修复率/版本数 |
| PNG 编码 | 9 | hex_to_rgb_png、draw_line_png/text_png、save_png_png/签名/尺寸 |
| 边界情况 | 9 | 空输入/单数据点/相同数/增加/减少/0→N/多版本/长版本名 |
| 综合场景 | 5 | 完整管道/重复生成/no_fix_rate_mode/fix_rate边界/全严重度 |

---

## 六、变更说明

### v2.4.0 新增

- 新增数据模型: TrendPoint, TrendInput, TrendResult, TrendMetric
- 新增图表类: VersionTrendChart
- 修复率自动计算: `fix_rate = fixed / (fixed + remaining) * 100`
- 总体变化百分比: `overall_change = (last - first) / first * 100`
- HTML 内联 Canvas 折线图（总漏洞数、CRITICAL、HIGH、修复率）

---

*文档由 CatPaw Agent 根据 v2.5.1 Knowledge Graph Visualization Module 开发结果自动生成*
