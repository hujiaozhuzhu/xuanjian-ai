# A1 — 联邦学习协同训练 (Federated Learning)

> 子功能编号：A1 | 模块路径：`fp_sentinel/privacy/federated.py` + `crypto.py`
> 状态：已完成 | 安全红线：S1/S8

## 功能目标

支持多分支机构/团队联合训练漏洞检出模型，原始数据全程不出本地，仅上传加密的模型梯度。

## 核心组件

### FederatedTrainingSession
联邦训练会话 — 协调方角色，管理训练生命周期：
- `initialize()` → 初始化全局模型 + 加密引擎
- `add_participant()` → 注册参与节点
- `run_training_round()` → 单轮训练（本地训练→加密→聚合→更新）
- `run_full_training()` → 完整训练循环（直到收敛或达到最大轮次）

### LocalParticipant
本地参与方 — 模拟分支机构的训练节点：
- `initialize_model()` → 初始化本地权重
- `local_train()` → 执行本地 SGD 训练
- `apply_global_model()` → 应用全局更新

### GradientEncryptionEngine
梯度加密引擎 — 三种模式：
1. **差分隐私噪声 (GRADIENT_NOISE_DP)**：拉普拉斯机制 ε-DP
2. **Paillier 半同态 (HOMOMORPHIC_PAILLIER)**：加法同态加密
3. **秘密共享 (SECRET_SHARING)**：分片分发

### SecureAggregator
安全聚合器 — FedAvg 加权聚合：
- 按 sample_count 加权平均
- 异常梯度检测（范数阈值）

## 数据流

```
参与方本地训练 → 加密梯度 → 传输审计 → 协调方聚合 → 更新全局模型 → 分发
     ↑                                                              │
     └──────────────────────────────────────────────────────────────┘
                         （下一轮）
```

## 安全约束

- 梯度明文永不离开本地（LocalParticipant.local_train 后直接加密）
- EncryptedGradient.is_safe_for_transmission() 强制校验
- 差分隐私累计预算自动跟踪
- 所有传输通过 DataTransferAuditor 审计

## 测试覆盖

- `TestLocalParticipant`：3 用例
- `TestFederatedTrainingSession`：6 用例（含完整训练流程）
- `TestGradientEncryptionEngine`：6 用例（三种加密方案）
- `TestSecureAggregator`：3 用例（加权聚合 + 边界）
