# A2 — 跨团队规则共享 (Cross-Team Rule Sharing)

> 子功能编号：A2 | 模块路径：`fp_sentinel/privacy/rule_sharing.py`
> 状态：已完成 | 安全红线：S9/S8

## 功能目标

支持安全共享自定义扫描规则，规则经过脱敏处理，不包含任何企业敏感信息。

## 核心组件

### DesensitizationEngine
脱敏引擎 — 多层清洗策略：
- **IP 脱敏**：内网 A/B/C 类地址 → `[INTERNAL_IP_*]`
- **域名脱敏**：`*.internal/corp/local` → `[INTERNAL_DOMAIN]`
- **路径脱敏**：文件路径 → `[FILE_PATH]`
- **主机名脱敏**：srv/db/app/web 等前缀 → `[HOSTNAME]`
- 四级敏感度（LOW/MEDIUM/HIGH）控制脱敏强度

### ShareableRuleBuilder
可共享规则构建器：
- 原始规则 ID → SHA-256 哈希（不可逆）
- 自动检测逻辑生成（按漏洞类别映射伪代码模板）
- HMAC-SHA256 签名（防篡改）

### RulePackageBuilder + RulePackageValidator
规则包管理：
- 打包多条规则 + 授权团队列表
- 包完整性哈希校验
- CRITICAL 敏感度规则自动排除

## 脱敏决策树

```
规则敏感度分类
├── LOW       → 仅 IP + 路径脱敏
├── MEDIUM    → IP + 路径 + 域名脱敏 (默认)
├── HIGH      → IP + 路径 + 域名 + 主机名脱敏
└── CRITICAL  → ❌ 禁止共享（raise ValueError）
```

## 数据流

```
原始规则 (含敏感信息)
    → ShareableRuleBuilder.from_raw_rule()
    → 敏感数据检测 + 脱敏清洗
    → SHA-256 哈希化 ID + 团队标识
    → 签名生成
    → 封装为 ShareableRule
    → RulePackageBuilder 打包
    → 验证 → 加密传输 → 导入
```

## 安全约束

- `contains_sensitive_data()` 自动检测残留明文
- 团队标识 + 规则ID 一律使用 SHA-256 哈希（不可逆）
- 规则包签名防止传输中篡改
- `validate_and_import_package()` 三重校验：授权 + 完整性 + 脱敏

## 测试覆盖

- `TestDesensitizationEngine`：6 用例（IP/路径/YAML/空值/级别）
- `TestShareableRuleBuilder`：3 用例（创建/CRITICAL拒绝/哈希化）
- `TestRulePackageBuilder`：4 用例（空包/规则/CRITICAL排除/接收方）
- `TestRulePackageValidator`：4 用例（有效包/敏感数据/授权/无限制）
