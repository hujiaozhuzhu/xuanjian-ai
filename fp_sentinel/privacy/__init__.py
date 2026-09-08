"""
玄鉴 v3.0 — 隐私计算协同审计模块 (Privacy Computing Collaborative Audit)

提供四项核心能力：
(a) 联邦学习协同训练：支持多分支机构/团队联合训练漏洞检出模型，
    原始数据全程不出本地，仅上传加密的模型梯度
(b) 跨团队规则共享：支持安全共享自定义扫描规则，规则经过脱敏处理，
    不包含任何企业敏感信息
(c) 隐私保护验证：内置数据防泄露校验，所有对外传输的数据都经过同态加密，
    提供隐私合规报告，符合数据安全法、等保2.0要求
(d) 协同任务管理：支持创建跨团队协同审计任务，分配不同范围的扫描权限，
    结果汇总时自动脱敏

安全红线：
- S1: 零网络请求 — 所有计算本地完成，仅传输加密后的模型梯度
- S2: 不修改被扫描源代码
- S3: 不删除任何文件
- S7: 所有持久化数据存储于 ~/.xuanjian/ 白名单目录
- S8: 模型参数传输前必须经过同态加密/梯度混淆
- S9: 规则共享前必须脱敏 — 清除所有企业敏感信息
"""

from .models import (
    CollaborativeTaskStatus,
    ComplianceStandard,
    EncryptionScheme,
    FederationRole,
    RuleSensitivity,
    RuleShareScope,
    TaskVisibility,
    TrainingStatus,
    EncryptedGradient,
    FederationNode,
    FederatedRoundResult,
    FederatedTrainingConfig,
    FederatedTrainingReport,
    RulePackage,
    ShareableRule,
    DataTransferAudit,
    PrivacyCheckItem,
    PrivacyComplianceReport,
    CollaborativeTask,
    DesensitizedFinding,
    ScanPermission,
)
from .crypto import (
    DifferentialPrivacy,
    GradientEncryptionEngine,
    LocalKeyManager,
    NodeAuthenticator,
    SecureAggregator,
    compute_data_hash,
)
from .federated import (
    FederatedTrainingSession,
    LocalParticipant,
    create_training_session,
)
from .rule_sharing import (
    DesensitizationEngine,
    RulePackageBuilder,
    RulePackageValidator,
    ShareableRuleBuilder,
    build_rule_package,
    create_shareable_rule,
    validate_and_import_package,
)
from .privacy_validator import (
    DataTransferAuditor,
    PlaintextDetector,
    PrivacyComplianceChecker,
    generate_compliance_report,
    validate_gradient_safe,
    validate_rule_safe,
)
from .collaborative_task import (
    CollaborativeTaskManager,
    PermissionEngine,
    ResultDesensitizer,
    create_collaborative_task,
)
from .repository import PrivacyRepository, default_privacy_db_path, open_privacy_repo

__all__ = [
    "__version__",
    "CollaborativeTaskStatus",
    "ComplianceStandard",
    "EncryptionScheme",
    "FederationRole",
    "RuleSensitivity",
    "RuleShareScope",
    "TaskVisibility",
    "TrainingStatus",
    "EncryptedGradient",
    "FederationNode",
    "FederatedRoundResult",
    "FederatedTrainingConfig",
    "FederatedTrainingReport",
    "RulePackage",
    "ShareableRule",
    "DataTransferAudit",
    "PrivacyCheckItem",
    "PrivacyComplianceReport",
    "CollaborativeTask",
    "DesensitizedFinding",
    "ScanPermission",
    "DifferentialPrivacy",
    "GradientEncryptionEngine",
    "LocalKeyManager",
    "NodeAuthenticator",
    "SecureAggregator",
    "compute_data_hash",
    "FederatedTrainingSession",
    "LocalParticipant",
    "create_training_session",
    "DesensitizationEngine",
    "RulePackageBuilder",
    "RulePackageValidator",
    "ShareableRuleBuilder",
    "build_rule_package",
    "create_shareable_rule",
    "validate_and_import_package",
    "DataTransferAuditor",
    "PlaintextDetector",
    "PrivacyComplianceChecker",
    "generate_compliance_report",
    "validate_gradient_safe",
    "validate_rule_safe",
    "CollaborativeTaskManager",
    "PermissionEngine",
    "ResultDesensitizer",
    "create_collaborative_task",
    "PrivacyRepository",
    "default_privacy_db_path",
    "open_privacy_repo",
]

__version__ = "3.0.0-privacy"
