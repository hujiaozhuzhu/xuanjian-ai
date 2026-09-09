# A3 — 隐私保护验证 (Privacy Protection Validation)

> 子功能编号：A3 | 模块路径：`fp_sentinel/privacy/privacy_validator.py`
> 状态：已完成 | 安全红线：S8/S9

## 功能目标

内置数据防泄露校验，所有对外传输的数据都经过同态加密。
提供隐私合规报告，符合数据安全法、等保2.0、PIPL、ISO 27001 要求。

## 核心组件

### PlaintextDetector
明文检测器 — 静态扫描数据中的敏感内容：
- 代码特征检测（def/class/function/import/eval 等）
- 敏感数据模式检测（password=/token=/secret= 等）
- 内网 IP 地址检测
- `check_data_safety()` 统一入口

### PrivacyComplianceChecker
合规检查器 — 对标四大标准：

| 标准 | 检查项 |
|------|--------|
| 数据安全法 | 分类分级、加密传输、出境评估、去标识化 |
| 等保2.0 | 身份鉴别、安全审计、完整性、保密性、入侵防范 |
| PIPL | 最小必要、知情权 |
| ISO 27001 | 密码控制、通信安全、合规性 |

- `check_gradient_compliance()` — 梯度加密验证
- `check_rule_compliance()` — 规则脱敏验证
- `check_finding_compliance()` — 结果脱敏验证
- `check_epsilon_budget()` — DP 预算超限检测

### DataTransferAuditor
传输审计器 — 自动审计每次数据交换：
- `audit_gradient_transfer()` — 梯度传输审计
- `audit_rule_transfer()` — 规则传输审计
- `audit_result_transfer()` — 结果传输审计
- `get_audit_summary()` — 批量合规率统计

## 风险等级判定

```
critical_failed > 0  → CRITICAL
high_failed > 1       → HIGH
high_failed > 0       → MEDIUM
otherwise             → LOW
```

## 数据流

```
数据准备
    → PlaintextDetector.detect_plaintext_code()
    → PlaintextDetector.detect_sensitive_data()
    → DataTransferAuditor.audit_XXX_transfer()
    → PrivacyComplianceChecker.run_full_compliance_check()
    → 生成 PrivacyComplianceReport
    → 写入 SQLite (compliance_report_records)
```

## 报告结构

```python
PrivacyComplianceReport:
  overall_passed: bool
  standards_checked: [ComplianceStandard]  # 已对标的标准
  checks: [PrivacyCheckItem]                # 每项检查结果
  passed_count / failed_count: int          # 统计
  risk_level: str                           # low/medium/high/critical
  summary: str                              # 自然语言摘要
  report_hash: str                          # 完整性校验
```

## 安全约束

- 每次传输前强制 `is_safe_for_transmission()` 校验
- 明文检测覆盖代码片段、内网 IP、密钥模式
- DP 累计隐私损失自动跟踪（基本组合定理 + 高级组合定理）
- 不可通过的结果阻断传输并写入审计日志

## 测试覆盖

- `TestPlaintextDetector`：5 用例（代码/敏感/IP/安全）
- `TestPrivacyComplianceChecker`：8 用例（全标准/梯度/规则/结果/预算）
- `TestDataTransferAuditor`：4 用例（梯度合规/不合规/规则/摘要）
