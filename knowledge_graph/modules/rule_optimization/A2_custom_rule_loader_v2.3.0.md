# 玄鉴 v2.3.0 — 用户自定义规则加载器 (Custom Rule Loader)

> 版本: v2.3.0 ｜ 子功能: A2-自定义规则加载器 ｜ 归档日期: 2026-09-07

---

## 一、功能概述

用户自定义规则加载器支持通过 YAML 文件导入自定义扫描规则，自动兼容现有扫描器逻辑（RuleFilter）。
支持文件加载、目录批量加载、字符串加载三种方式，提供完整的格式验证、去重、冲突检测能力。

## 二、文件结构

```
fp_sentinel/rule_optimization/
├── custom_rule_loader.py          # 自定义规则加载器核心实现
└── ...

tests/unit/
├── test_rule_optimization_custom_rule_loader.py  # 测试文件 (61用例)
```

## 三、核心设计

### 3.1 支持的 YAML 格式

#### 格式一（标准格式）
```yaml
version: "1.0"
rules:
  - name: custom_sql_safe_wrapper
    rule_id_pattern: 'sql.injection|sql-injection'
    code_pattern: 'SafeQuery\.execute|SqlBuilder\.build'
    reason: 使用项目自定义的安全查询封装
    confidence: 0.85
```

#### 格式二（兼容现有 xuanjian.yaml）
```yaml
custom_rules:
  - name: my_auth_check
    rule_id: 'exact.rule.id'
    file_pattern: '.*/internal/api/.*'
    reason: 内部API
    confidence: 0.7
```

#### 格式三（列表格式）
```yaml
- name: list_rule_1
  code_pattern: 'safe\.method'
  reason: 安全方法
  confidence: 0.9
```

### 3.2 规则字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | str | 是 | 规则名称，唯一标识 |
| `rule_id` | str | 否 | 精确匹配规则ID |
| `rule_id_pattern` | str | 否 | 正则匹配规则ID |
| `file_pattern` | str | 否 | 正则匹配文件路径 |
| `code_pattern` | str | 否 | 正则匹配代码片段 |
| `severity` | str | 否 | 匹配严重程度 |
| `tool` | str | 否 | 匹配扫描工具 |
| `language` | str | 否 | 匹配编程语言 |
| `reason` | str | 否 | 误报原因说明 |
| `confidence` | float | 否 | 置信度 0-1，默认0.8 |
| `enabled` | bool | 否 | 是否启用，默认true |
| `description` | str | 否 | 规则描述 |
| `references` | list | 否 | 参考资料链接 |
| `tags` | list | 否 | 标签分类 |

### 3.3 数据流

```
YAML 文件 → yaml.safe_load → 格式验证 → 规则解析 → 正则编译 → 去重 → CustomRule 列表
                            ↓
                    版本兼容性检查
                    字段类型验证
                    正则合法性检查
```

## 四、API 说明

### CustomRuleLoader 类

| 方法 | 说明 |
|------|------|
| `load_from_file(path)` | 从单个YAML文件加载 |
| `load_from_directory(path)` | 从目录批量加载 |
| `load_from_string(yaml_str)` | 从YAML字符串加载 |
| `to_compatible_format()` | 转为 RuleFilter 兼容格式 |
| `to_full_format()` | 导出完整格式 |
| `get_filter_config_section()` | 生成配置片段 |
| `get_merge_suggestions(existing)` | 合并冲突分析 |
| `get_rules()` | 获取全部规则 |
| `get_enabled_rules()` | 获取已启用规则 |
| `get_rule_by_name(name)` | 按名称查找 |
| `get_rules_by_tag(tag)` | 按标签查找 |
| `get_rules_by_language(lang)` | 按语言查找 |
| `clear()` | 清除已加载规则 |

### CustomRule 数据模型

- 自动编译正则表达式
- 自动完成 `to_dict()` 转换（兼容 RuleFilter 格式）
- 支持完整格式导出 `to_full_dict()`

## 五、兼容现有扫描器

加载完成后的规则可直接赋值给 `RuleFilter.custom_rules`：

```python
from fp_sentinel.rule_optimization import CustomRuleLoader

loader = CustomRuleLoader()
result = loader.load_from_file("custom_rules.yaml")
compatible_rules = loader.to_compatible_format()

# 直接注入 RuleFilter
rule_filter.custom_rules.extend(compatible_rules)

# 或写入 xuanjian.yaml
config_section = loader.get_filter_config_section()
```

## 六、测试结果

```
============ 61 passed in 1.13s ============
```

| 测试类别 | 用例数 | 通过 |
|---------|-------|------|
| 常量定义 | 6 | 6 |
| CustomRule模型 | 10 | 10 |
| 初始化 | 3 | 3 |
| 文件加载 | 7 | 7 |
| 目录加载 | 3 | 3 |
| 字符串加载 | 4 | 4 |
| 规则解析 | 7 | 7 |
| 格式转换 | 4 | 4 |
| 规则查询 | 7 | 7 |
| 合并建议 | 6 | 6 |
| 边界情况 | 4 | 4 |

## 七、变更说明

| 变更项 | 类型 | 说明 |
|-------|------|------|
| `custom_rule_loader.py` | 新增 | 自定义规则加载器核心模块 |
| `test_rule_optimization_custom_rule_loader.py` | 新增 | 测试文件(61用例) |

无现有代码修改，完全向后兼容。

## 八、安全保障

1. **格式验证**: YAML schema 版本检查、字段类型验证
2. **正则安全**: 编译前验证正则合法性，编译失败优雅降级
3. **去重机制**: 按名称去重，重复规则自动跳过
4. **置信度约束**: 加载时 clamp 到 [0, 1] 范围
5. **数量限制**: 单文件最多500条（可配置），防止内存溢出
6. **安全字段白名单**: severity/tool/language 仅接受合法值
