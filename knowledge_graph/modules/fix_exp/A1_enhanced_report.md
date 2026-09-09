# A1. 审计报告生成增强模块

## 模块路径
`fp_sentinel/reporting/enhanced_report.py`

## 功能概述

重构审计报告模板，增加架构图、攻击路径可视化、风险热力图，提升报告可读性。

在原有 10 章节固定报告基础上，新增 4 个增强章节，总计 14 章节。

## 新增章节

### 1. 系统架构图（风险标注）
- **文件**: `_render_ascii_arch()`
- **功能**: 从 findings 自动推断系统架构，输出 ASCII 分层图
- **节点入口**: entry/service/db/external 四层
- **风险标注**: `[!!!]` `[!!]` `[!]` `[.]` `[i]` 五级可视化
- **数据流**: 自动展示模块间调用关系

### 2. 攻击路径 SVG 可视化
- **文件**: `_render_attack_path_svg()`
- **功能**: 生成自包含 SVG 交互式图表
- **特性**:
  - 颜色编码：高概率红色 `#e94560`，中概率橙色 `#ffa657`，低概率蓝色 `#58a6ff`
  - 箭头连接：SVG marker 实现步骤间数据流
  - 零依赖：纯 Python 生成，无外部 JS 库

### 3. 风险热力图矩阵
- **文件**: `_build_inline_heatmap()`
- **功能**: 纵轴模块 × 横轴漏洞类型的 ASCII 风险矩阵
- **输出格式**: Markdown 表格，内嵌 `数量(风险评分)`
- **数据来源**: findings 按 module+vuln_type 聚合后的严重度加权

### 4. 整改进度时间线
- **文件**: `_render_fix_timeline_section()`
- **功能**: 按被攻破概率排序，展示整改进度条
- **阶段标识**: P0 `[!!!]` / P1 `[!!]` / P2 `[!]` / P3 `[.]`
- **进度条**: ASCII `[####----]` 形式展示风险百分比

### 5. 行业基准对比（增强章节）
- **文件**: `_render_industry_benchmark_comparison()`
- **功能**: 将 findings 汇总为企业指标，对比行业基准
- **对比维度**: vulnerability_density / repair_speed / compliance / coverage
- **输出**: Markdown 表格 + 关键发现列表

## 数据结构

```python
@dataclass
class ArchitectureNode:
    name: str
    node_type: str  # entry/service/db/external
    tech_stack: str = ""
    exposure: str = "internal"
    risk_level: str = "MEDIUM"
    connections: List[str] = field(default_factory=list)

@dataclass
class ArchitectureDiagram:
    nodes: List[ArchitectureNode]
    edges: List[Tuple[str, str, str]]  # (from, to, protocol)

@dataclass
class EnhancedReportConfig:
    include_arch_diagram: bool = True
    include_attack_svg: bool = True
    include_heatmap: bool = True
    include_risk_trend: bool = True
    include_industry_comparison: bool = True
    theme: str = "dark"
    output_format: str = "markdown"
```

## 公开 API

```python
def generate_enhanced_report(
    project: str,
    findings: List[Any],
    chain_report: AttackChainReport,
    verify_results: Optional[List[VerifyResult]] = None,
    exploit_results: Optional[List[ExploitabilityResult]] = None,
    poc_map: Optional[Dict[str, PocInstance]] = None,
    architecture: Optional[ArchitectureDiagram] = None,
    industry: str = "internet",
    config: Optional[EnhancedReportConfig] = None,
    generated_at: Optional[str] = None,
) -> str:

def write_enhanced_report(content: str, output_dir: str, filename: str) -> Path:

def generate_and_write_enhanced_report(...) -> Path:  # 一站式便捷函数
```

## 安全红线

- **S1**: 不生成任何面向外网的 PoC/EXP（仅 localhost）
- **S2**: 不修改用户源文件（仅输出建议）
- **S5**: 报告数据 30 天清理
- **S7**: 输出路径白名单校验（复用 attack_report 的 `resolve_output_path`）

## 依赖

- `fp_sentinel.reporting.attack_report` - 原 10 章节报告
- `fp_sentinel.visualization.heatmap` - 热力图基础组件
- `fp_sentinel.industry_benchmark` - 行业基准数据

## 测试覆盖

- 测试文件: `tests/exp_fix/test_enhanced_report.py`
- 测试数量: ~70
- 覆盖率: 96%
- 覆盖要点: 架构图渲染/SVG生成/热力图矩阵/时间线/行业对比/配置开关/写入安全
