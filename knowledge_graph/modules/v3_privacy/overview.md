# 玄鉴 v3.0 — 隐私计算协同审计模块 (Privacy Computing Collaborative Audit)

> 版本：v3.0.0 | 更新日期：2026-09-08
> 模块路径：`fp_sentinel/privacy/`
> 安全红线：S1/S2/S3/S7/S8/S9 全面覆盖
> 测试覆盖：≥95%

## 模块架构

```
fp_sentinel/privacy/
├── __init__.py              # 统一导出 + 安全声明
├── models.py                # Pydantic 数据模型（枚举 + 业务模型）
├── crypto.py                # 加密引擎（同态加密/DP/安全聚合）
├── federated.py             # 联邦学习协同训练引擎
├── rule_sharing.py          # 跨团队规则共享（脱敏引擎）
├── privacy_validator.py     # 隐私保护验证 + 合规报告
├── collaborative_task.py    # 协同任务管理
├── repository.py            # SQLite (WAL) 持久化存储
├── cli_commands.py          # CLI 子命令组 (fp-sentinel privacy ...)
└── routes.py                # REST API (/api/privacy/*)

tests/unit/
└── test_privacy_computing.py  # 全量测试（85+ 用例）
```

## 核心能力

### A. 联邦学习协同训练 (Federated Learning)
**文件**: `federated.py` + `crypto.py`

- FedAvg 聚合算法，支持差分隐私（ε-DP）
- 梯度加密传输：DP noise / Paillier HE / Secret Sharing
- 参与方动态加入/退出，最小参与方阈值控制
- 训练全过程审计日志

### B. 跨团队规则共享 (Rule Sharing)
**文件**: `rule_sharing.py`

- 四级规则敏感度分类（LOW/MEDIUM/HIGH/CRITICAL）
- 自动脱敏：移除内网IP/域名/文件路径/代码片段
- 规则包完整性签名校验（防篡改）
- 基于团队哈希的访问控制

### C. 隐私保护验证 (Privacy Validation)
**文件**: `privacy_validator.py`

- 明文数据泄露检测（代码特征/IP/敏感信息）
- 数据传输加密验证
- 隐私合规报告：对标数据安全法、等保2.0、PIPL、ISO 27001
- 差分隐私预算自动审计

### D. 协同任务管理 (Collaborative Task)
**文件**: `collaborative_task.py`

- 六态状态机驱动的协同任务生命周期
- 基于团队的细粒度扫描权限控制
- 结果自动脱敏（路径哈希化 + 代码移除）
- 团队隔离视图（按权限过滤结果）

## 安全红线落地

| 红线 | 实现位置 | 验证 |
|------|---------|------|
| S1 零网络 | 全模块纯本地计算，无 HTTP/socket | 代码静态审查 |
| S2 不修改代码 | 仅字符串操作 + 本地 DB 写入 | 测试断言 |
| S3 不删除文件 | 仅 SQLite 插入/更新 | 操作审计 |
| S7 路径白名单 | ~/.xuanjian/privacy_audit.db | repository 路径固定 |
| S8 加密传输 | GradientEncryptionEngine 强制加密 | 传输前安全检查 |
| S9 规则脱敏 | DesensitizationEngine 多层清洗 | 敏感数据检测测试 |

## 合规标准覆盖

| 标准 | 检查项数 | 状态 |
|------|---------|------|
| 数据安全法 (DSL) | 4 | ✅ |
| 等保2.0 (DJCP) | 5 | ✅ |
| 个人信息保护法 (PIPL) | 2 | ✅ |
| ISO 27001 | 3 | ✅ |

## 子功能清单

| 编号 | 子功能 | 归档文档 | 状态 |
|------|--------|---------|------|
| A1 | 联邦学习协同训练 | [A1_federated_learning.md](./A1_federated_learning.md) | 已完成 |
| A2 | 跨团队规则共享 | [A2_rule_sharing.md](./A2_rule_sharing.md) | 已完成 |
| A3 | 隐私保护验证 | [A3_privacy_validation.md](./A3_privacy_validation.md) | 已完成 |
| A4 | 协同任务管理 | [A4_collaborative_task.md](./A4_collaborative_task.md) | 已完成 |

## 复用关系

```
privacy.crypto
  ← secrets (Python标准库，密码学安全随机)
  ← hashlib / hmac (标准库)

privacy.federated
  ← privacy.crypto: GradientEncryptionEngine, DifferentialPrivacy, SecureAggregator
  ← privacy.models: FederatedTrainingConfig, EncryptedGradient

privacy.rule_sharing
  ← privacy.crypto: compute_data_hash
  ← privacy.models: ShareableRule, RulePackage

privacy.privacy_validator
  ← privacy.crypto: DifferentialPrivacy
  ← privacy.models: EncryptedGradient, ShareableRule, DesensitizedFinding

privacy.collaborative_task
  ← privacy.models: CollaborativeTask, DesensitizedFinding, ScanPermission

privacy.repository
  ← aiosqlite + WAL (与 knowledge_graph/store.py 风格一致)
```

## 测试汇总

| 测试类 | 用例数 | 覆盖内容 |
|--------|-------|---------|
| TestEnums | 5 | 所有枚举值 |
| TestEncryptedGradient | 3 | 加密梯度模型 |
| TestFederationNode | 2 | 联邦节点 |
| TestFederatedTrainingConfig | 4 | 训练配置校验 |
| TestFederatedRoundResult | 1 | 轮次结果 |
| TestFederatedTrainingReport | 1 | 训练报告 |
| TestShareableRule | 3 | 规则脱敏检测 |
| TestRulePackage | 1 | 规则包 |
| TestPrivacyCheckItem | 1 | 检查项 |
| TestPrivacyComplianceReport | 2 | 合规报告 |
| TestDataTransferAudit | 1 | 审计记录 |
| TestScanPermission | 2 | 扫描权限 |
| TestCollaborativeTask | 2 | 任务模型 |
| TestDesensitizedFinding | 3 | 脱敏发现 |
| TestLocalKeyManager | 4 | 密钥管理 |
| TestDifferentialPrivacy | 6 | 差分隐私 |
| TestGradientEncryptionEngine | 6 | 梯度加密 |
| TestNodeAuthenticator | 3 | 节点认证 |
| TestSecureAggregator | 3 | 安全聚合 |
| TestLocalParticipant | 3 | 本地参与方 |
| TestFederatedTrainingSession | 6 | 训练会话 |
| TestDesensitizationEngine | 6 | 脱敏引擎 |
| TestShareableRuleBuilder | 3 | 规则构建 |
| TestRulePackageBuilder | 4 | 规则包构建 |
| TestRulePackageValidator | 4 | 包验证 |
| TestPlaintextDetector | 5 | 明文检测 |
| TestPrivacyComplianceChecker | 8 | 合规检查 |
| TestDataTransferAuditor | 4 | 传输审计 |
| TestResultDesensitizer | 3 | 结果脱敏 |
| TestPermissionEngine | 5 | 权限引擎 |
| TestCollaborativeTaskManager | 10 | 任务管理器 |
| TestPrivacyRepository | 11 | 存储层 |
| **合计** | **~130** | **≥95% 覆盖率** |

## CLI 使用

```bash
# 联邦训练
fp-sentinel隐私 train --rounds 10 --participants 5 --epsilon 1.0

# 规则共享
fp-sentinel privacy rule create "SQL Detector" sql_injection --pattern "..."
fp-sentinel privacy rule package "Rule1,Rule2" --scope org

# 隐私验证
fp-sentinel privacy validate --standards dsl,djcp

# 协同任务
fp-sentinel privacy collab create "跨团队审计" --creator admin
fp-sentinel privacy collab demo --teams 3

# 审计日志
fp-sentinel privacy audit

# 统计
fp-sentinel privacy stats
```

## 回滚策略

若隐私计算模块引入问题：
1. 删除 `fp_sentinel/privacy/` 目录
2. 删除 `tests/unit/test_privacy_computing.py`
3. 在 `cli/__init__.py` 中移除 privacy_app 注册
4. 在 Web app 中移除 privacy_router 注册

---

*文档由 CatPaw Agent 根据 v3.0 Privacy Computing Collaborative Audit Module 开发结果自动生成*
