# 玄鉴 v2.3.0 — Java 规则库优化器 (Java Rule Optimizer)

> 版本: v2.3.0 ｜ 子功能: A3-Java规则库优化 ｜ 归档日期: 2026-09-07

---

## 一、功能概述

Java 规则库优化器对内置 Java 误报规则执行深度优化：
1. **合并重复规则**: 基于正则模式相似度检测并合并重复规则
2. **修复已知漏洞**: 更新过时正则、补充遗漏的安全模式
3. **补充新规则**: 添加Spring Cloud/JPA安全查询等新场景规则
4. **提升准确率**: 修复无效confidence、检测过度泛化的正则

## 二、文件结构

```
fp_sentinel/rule_optimization/
├── java_rule_optimizer.py         # Java规则库优化器核心实现
└── ...

tests/unit/
├── test_rule_optimization_java_rule_optimizer.py  # 测试文件 (49用例)
```

## 三、核心设计

### 3.1 相似度算法

使用Jaccard相似度的变体来计算模式之间的相似度：

```
相似度 = len(交集) / len(并集)
```

- 模式按 `|` 分割为子模式
- 长度 >= 3 的子模式才参与计算
- 阈值默认 0.85，超过则触发合并

### 3.2 优化流水线

```
原始规则集
    ↓
[步骤1] 重复规则合并（按漏洞类别分组）
    ↓
[步骤2] 已知修复补丁应用（6个规则）
    ↓
[步骤3] 新规则补充（3条新增）
    ↓
[步骤4] 安全漏洞修复（confidence范围、正则合法性）
    ↓
优化后规则集 + 变更记录
```

### 3.3 已知修复补丁 (KNOWN_FIXES)

| 规则名 | 修复内容 |
|--------|---------|
| `java_sql_prepared_statement` | 补充Lambda写法 createPreparedStatement |
| `java_xss_json_response` | 补充@ResponseBody/MappingJackson，调高置信度到0.75 |
| `java_ssrf_whitelist` | 补充@AllowedDomains注解匹配 |
| `java_hardcoded_test` | 扩大测试文件匹配范围(fixture/benchmark) |
| `java_crypto_aes256` | 补充AES/ECB/NoPadding等变体 |
| `java_deser_trusted_source` | 补充CaffeineCache/EhcacheManager，调高置信度到0.75 |

### 3.4 新增规则 (NEW_RULES v2.3.0)

| 规则名 | 覆盖场景 | 置信度 |
|--------|---------|-------|
| `java_sql_spring_data_jpa_query` | Spring Data JPA @Query / JpaSpecificationExecutor | 0.85 |
| `java_ssrf_spring_web_client_filter` | Spring Cloud LoadBalancer / DiscoveryClient | 0.90 |
| `java_xss_react_vue_escape` | React/Vue前端模板标记在Java后端 | 0.60 |

## 四、API 说明

### JavaRuleOptimizer 类

| 方法 | 说明 |
|------|------|
| `optimize()` | 执行全部优化步骤 |
| `save_report(result)` | 保存优化报告 |
| `save_optimized_rules(result)` | 保存优化后的规则 |
| `analyze_rules()` | 分析当前规则库统计 |
| `compare_with_guard_patterns()` | 对比安全守卫覆盖度 |

### OptimizationResult 数据模型

| 字段 | 说明 |
|------|------|
| `before_count` | 优化前规则数 |
| `after_count` | 优化后规则数 |
| `duplicates_found` | 发现的重复数 |
| `duplicates_merged` | 合并的重复数 |
| `rules_updated` | 更新的规则数 |
| `rules_added` | 新增的规则数 |
| `conflicts_resolved` | 解决的冲突数 |
| `changes` | 变更记录列表 |
| `duplicate_groups` | 重复分组信息 |
| `optimized_rules` | 优化后的规则列表 |

## 五、内置规则库统计

优化前规则库共 **65条** Java 误报规则，分布如下：

| 漏洞类别 | 规则数 |
|---------|-------|
| SQL注入 | 15 |
| XSS | 10 |
| SSRF | 10 |
| 命令注入 | 8 |
| 路径穿越 | 7 |
| 反序列化 | 5 |
| 加密安全 | 5 |
| 硬编码凭证/常量 | 4 |
| 弱加密(TLS1.3) | 1 |

## 六、测试结果

```
============ 49 passed in 1.02s ============
```

| 测试类别 | 用例数 | 通过 |
|---------|-------|------|
| 常量定义 | 5 | 5 |
| 数据模型 | 4 | 4 |
| 初始化 | 4 | 4 |
| 重复检测 | 3 | 3 |
| 相似度计算 | 6 | 6 |
| 规则选择 | 2 | 2 |
| 已知修复 | 3 | 3 |
| 新规则 | 3 | 3 |
| 漏洞修复 | 3 | 3 |
| 完整流程 | 5 | 5 |
| 持久化 | 3 | 3 |
| 分析工具 | 4 | 4 |
| 内置规则验证 | 4 | 4 |

## 七、变更说明

| 变更项 | 类型 | 说明 |
|-------|------|------|
| `java_rule_optimizer.py` | 新增 | Java规则库优化器核心模块 |
| `test_rule_optimization_java_rule_optimizer.py` | 新增 | 测试文件(49用例) |

混合修改：
- `rule_optimization/__init__.py` 新增模块入口导入

无现有 `rules/java/rules.py` 等规则定义文件修改（只读分析）。

## 八、安全保障

1. **非破坏性**: 优化器不修改原始规则（深拷贝），输出为新列表
2. **可审计**: 每条变更都有完整记录（RuleChange）
3. **可回滚**: 保存优化前版本，随时恢复
4. **边界约束**: 相似度阈值可配置，默认0.85保守值
5. **置信度保护**: 自动修复异常confidence值到[0,1]范围
6. **正则安全**: 加载后验证全部模式正则合法性

## 九、使用示例

```python
from fp_sentinel.rule_optimization import JavaRuleOptimizer

optimizer = JavaRuleOptimizer()
result = optimizer.optimize()

# 查看优化报告
print(result.summary())

# 保存报告到 ./reports/optimization/
optimizer.save_report(result)

# 保存优化后规则
optimizer.save_optimized_rules(result)

# 查看分类统计
stats = optimizer.analyze_rules()

# 查看覆盖度分析
coverage = optimizer.compare_with_guard_patterns()
```
