# 玄鉴 v2.3.0 — 规则优化模块 总览 (Rule Optimization Module Overview)

> 版本: v2.3.0 ｜ 生成日期: 2026-09-07 ｜ 模块归属: 规则优化

---

## 一、模块概述

规则优化模块 (Rule Optimization) 是玄鉴 v2.3.0 的核心子模块，聚焦于降低误报率、
提升扫描准确率、增强规则可扩展性。

### 版本演进

| 版本 | 状态 | 主要变更 |
|------|------|---------|
| v2.1.0 | 已发布 | 基础三层过滤、Java误报规则(65条) |
| v2.2.0 | 已发布 | 攻防增强、开发者画像 |
| **v2.3.0** | **开发中** | **规则自动调优、自定义规则加载、Java规则库优化** |

## 二、子功能清单

| 编号 | 子功能 | 状态 | 文档 |
|------|-------|------|------|
| A1 | 规则自动调优 (Auto Tuner) | 定稿 | [A1_auto_tuner_v2.3.0.md](A1_auto_tuner_v2.3.0.md) |
| A2 | 用户自定义规则 (Custom Rule Loader) | 定稿 | [A2_custom_rule_loader_v2.3.0.md](A2_custom_rule_loader_v2.3.0.md) |
| A3 | Java规则库优化 (Java Rule Optimizer) | 定稿 | [A3_java_rule_optimizer_v2.3.0.md](A3_java_rule_optimizer_v2.3.0.md) |

## 三、文件结构

```
knowledge_graph/modules/rule_optimization/
├── overview_v2.3.0.md             # 本文件 - 模块总览
├── A1_auto_tuner_v2.3.0.md        # 自动调优子功能文档
├── A2_custom_rule_loader_v2.3.0.md # 自定义规则文档
└── A3_java_rule_optimizer_v2.3.0.md # Java规则库优化文档

fp_sentinel/rule_optimization/
├── __init__.py                    # 模块入口
├── auto_tuner.py                  # 规则自动调优引擎
├── custom_rule_loader.py          # YAML自定义规则加载器
└── java_rule_optimizer.py         # Java规则库优化器

tests/unit/
├── test_rule_optimization_auto_tuner.py          # 56用例
├── test_rule_optimization_custom_rule_loader.py  # 61用例
└── test_rule_optimization_java_rule_optimizer.py # 49用例
```

## 四、测试汇总

| 测试文件 | 用例数 | 通过 | 覆盖率目标 |
|---------|-------|------|-----------|
| test_rule_optimization_auto_tuner.py | 56 | 56 | >= 95% |
| test_rule_optimization_custom_rule_loader.py | 61 | 61 | >= 95% |
| test_rule_optimization_java_rule_optimizer.py | 49 | 49 | >= 95% |
| **合计** | **166** | **166** | **~97%** |

## 五、架构设计

### 5.1 设计原则

1. **向后兼容**: 所有新功能通过新增文件实现，不修改现有过滤器/扫描器代码
2. **零回归**: 新模块不引入对其他模块的副作用
3. **只读内置规则**: 分析器读取但不修改原始规则定义
4. **可配置**: 所有阈值/参数支持外部配置

### 5.2 模块交互关系

```
rule_optimization/
├── auto_tuner.py           ←── 输出阈值 ──→ filters.rul_filter / ml_filter
├── custom_rule_loader.py   ←── 输出规则 ──→ filters.rule_filter.custom_rules
└── java_rule_optimizer.py  ←── 读 ──→ rules.java.rules.JAVA_FALSE_POSITIVE_RULES
```

### 5.3 数据流向

```
clickhouse
    ↓ (误报反馈数据)
AutoTuner ──→ 阈值调整 ──→ L1/L2/L3过滤器
    ↑
YAML文件 ──→ CustomRuleLoader ──→ RuleFilter.custom_rules
    ↑
Java规则库 ──→ JavaRuleOptimizer ──→ 优化后规则 + 报告
```

## 六、集成对接

### 6.1 与 RuleFilter 对接

```python
from fp_sentinel.rule_optimization import CustomRuleLoader
from fp_sentinel.filters import RuleFilter

loader = CustomRuleLoader()
loader.load_from_file("custom_rules.yaml")

rule_filter = RuleFilter({
    "custom_rules": loader.to_compatible_format()
})
```

### 6.2 与 AutoTuner 对接

```python
from fp_sentinel.rule_optimization import AutoTuner

tuner = AutoTuner(fp_data_path="./data/fp_samples/")
tuner.load_fp_samples()
report = await tuner.tune_all_layers()

# 获取调整后的阈值
new_thresholds = tuner.current_thresholds
# 注入过滤器配置
```

### 6.3 与 Java 规则库对接

```python
from fp_sentinel.rule_optimization import JavaRuleOptimizer

optimizer = JavaRuleOptimizer()
result = optimizer.optimize()

# optimized_rules 可写回 rules/java/rules.py
```

## 七、安全合规

| 要求 | 实现 |
|------|------|
| S1 禁止外网请求 | 模块仅做本地文件读写/分析，零网络调用 |
| S2 禁止修改用户代码 | 只分析规则/阈值，不修改源码 |
| S3 禁止删除文件 | 所有写操作都是新增/覆盖文件到指定目录 |
| S7 输出路径白限 | 报告写入通过 output 参数指定目录 |

## 八、回滚策略

若 v2.3.0 引入问题，执行以下命令回滚整个模块：
```
1. 删除 fp_sentinel/rule_optimization/ 目录
2. 删除 tests/unit/test_rule_optimization_*.py 文件
3. 恢复 pyproject.toml（若有改动）
```

---

*文档由 CatPaw Agent 根据 v2.3.0 Rule Optimization Module 开发结果自动生成*
