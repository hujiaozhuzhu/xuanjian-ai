# 玄鉴 v2.4.0 — 知识图谱可视化模块总览 (Knowledge Graph Visualization)

> 版本: v2.4.0 ｜ 生成日期: 2026-09-08 ｜ 模块归属: 知识图谱可视化

---

## 一、模块概述

知识图谱可视化模块 (Knowledge Graph Visualization) 是玄鉴 v2.4.0 的核心子模块，
提供漏洞热力图与版本变化趋势图两种可视化输出，帮助安全团队直观理解项目风险分布
与演进态势。

### 版本演进

| 版本 | 状态 | 主要变更 |
|------|------|---------|
| v2.1.0 | 已发布 | 基础三层过滤、Java误报规则(65条) |
| v2.2.0 | 已发布 | 攻防增强、开发者画像 |
| v2.3.0 | 已发布 | 规则自动调优、自定义规则加载、Java规则库优化 |
| **v2.4.0** | **已完成** | **漏洞热力图、版本变化趋势图、零第三方绘图依赖** |

---

## 二、子功能清单

| 编号 | 子功能 | 状态 | 文档 |
|------|-------|------|------|
| A | 漏洞热力图 (Vulnerability Heatmap) | 定稿 | [A_heatmap_v2.4.0.md](A_heatmap_v2.4.0.md) |
| B | 版本变化趋势图 (Version Trend Chart) | 定稿 | [B_version_trend_v2.4.0.md](B_version_trend_v2.4.0.md) |

---

## 三、文件结构

```
fp_sentinel/visualization/
├── __init__.py          # 模块入口、公共 API
├── models.py            # 数据模型、颜色映射、主题、严重度权重
├── heatmap.py           # 漏洞热力图生成器 (HTML+PNG)
└── version_trend.py     # 版本变化趋势图生成器 (HTML+PNG)

tests/unit/
├── test_visualization_heatmap.py         # 68 用例
└── test_visualization_version_trend.py   # 58 用例

knowledge_graph/modules/knowledge_visual/
├── overview_v2.4.0.md                   # 本文件 - 模块总览
├── A_heatmap_v2.4.0.md                  # 热力图子功能文档
└── B_version_trend_v2.4.0.md            # 趋势图子功能文档
```

---

## 四、测试汇总

| 测试文件 | 用例数 | 通过 | 覆盖率目标 |
|---------|-------|------|-----------|
| test_visualization_heatmap.py | 68 | 68 | >= 95% |
| test_visualization_version_trend.py | 58 | 58 | >= 95% |
| **合计** | **126** | **126** | **~97%** |

---

## 五、架构设计

### 5.1 设计原则

1. **零第三方绘图依赖**: PNG 使用 Python 标准库 (zlib + struct) 编码
2. **自包含 HTML**: 无 CDN/JS 依赖，离线可查看
3. **三色主题**: dark (默认) / light / high_contrast
4. **向后兼容**: 新增文件，不修改现有模块代码
5. **只读操作**: 分析扫描结果，不修改用户代码

### 5.2 模块交互关系

```
visualization/
├── models.py           ←── 共享数据模型 ──→ heatmap.py + version_trend.py
├── heatmap.py          ←── 输出 HTML → reports/*.html
└── version_trend.py    ←── 输出 PNG  → reports/*.png
```

### 5.3 数据流向

```
Findings/ScanHistory
    ↓ (HeatmapInput / TrendInput)
VulnerabilityHeatmap / VersionTrendChart
    ↓
HTML (自包含) + PNG (zlib+struct)
    ↓
reports/*.html, reports/*.png
```

---

## 六、输出格式说明

### HTML 交互式

- 内联 CSS + JavaScript（Canvas）
- 响应式统计卡片
- 数据表格（模块/漏洞类型/计数/风险评分/严重度分布）
- 悬停 tooltip（热力图色块）
- Canvas 折线图（版本趋势图）

### PNG 静态图

- Pure Python PNG 编码（zlib 压缩 + struct 打包）
- 5x7 点阵字体
- Bresenham 直线算法
- 网格线 + 轴标签 + 图例

---

## 七、安全合规

| 红线 | 实现 |
|------|------|
| S1 禁止外网请求 | 模块零网络调用 |
| S2 禁止修改用户代码 | 只读分析，生成报告 |
| S3 禁止删除文件 | 仅写入新文件 |
| S7 输出路径由调用方指定 | 默认 ./reports/ |

---

## 八、回滚策略

若 v2.4.0 引入问题，执行以下命令回滚整个模块：
```
1. 删除 fp_sentinel/visualization/ 目录
2. 删除 tests/unit/test_visualization_*.py 文件
```

---

*文档由 CatPaw Agent 根据 v2.4.0 Knowledge Graph Visualization Module 开发结果自动生成*
