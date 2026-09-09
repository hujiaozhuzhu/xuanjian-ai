"""
玄鉴 v3.0 — 隐私计算协同审计模块 (Privacy Computing Collaborative Audit)

数据模型定义：联邦学习协同训练、跨团队规则共享、隐私保护验证、协同任务管理
所有数据全程本地化处理，禁止任何明文数据传输与跨网络传输原始代码/漏洞数据。

安全红线：
- S1: 零网络请求 — 所有计算本地完成，仅传输加密后的模型梯度
- S2: 不修改被扫描源代码
- S3: 不删除任何文件
- S7: 所有持久化数据存储于 ~/.xuanjian/ 白名单目录
- S8: 模型参数传输前必须经过同态加密/梯度混淆
- S9: 规则共享前必须脱敏 — 清除所有企业敏感信息（内部IP、域名、代码片段、路径）
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


# ─────────────────────────── 枚举 ───────────────────────────

class FederationRole(str, Enum):
    """联邦学习参与方角色"""
    COORDINATOR = "coordinator"
    PARTICIPANT = "participant"
    AUDITOR = "auditor"


class TrainingStatus(str, Enum):
    """训练任务状态"""
    INITIALIZING = "initializing"
    WAITING = "waiting"
    TRAINING = "training"
    AGGREGATING = "aggregating"
    VALIDATING = "validating"
    COMPLETED = "completed"
    FAILED = "failed"


class EncryptionScheme(str, Enum):
    """加密方案"""
    HOMOMORPHIC_PAILLIER = "he_paillier"
    GRADIENT_NOISE_DP = "dp_noise"
    SECRET_SHARING = "secret_sharing"


class RuleShareScope(str, Enum):
    """规则共享范围"""
    TEAM = "team"
    DEPARTMENT = "dept"
    ORGANIZATION = "org"
    PUBLIC = "public"


class RuleSensitivity(str, Enum):
    """规则敏感度分类"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TaskVisibility(str, Enum):
    """协同任务可见范围"""
    OWNER_ONLY = "owner_only"
    TEAM = "team_team"
    DEPARTMENT = "dept_dept"
    ORGANIZATION = "org_org"


class ComplianceStandard(str, Enum):
    """合规标准"""
    DATA_SECURITY_LAW = "data_security_law"
    DJCP_2_0 = "djcp_2_0"
    PIPL = "pipl"
    ISO_27001 = "iso_27001"


# ─────────────────────── 联邦学习模型 ───────────────────────

def _gen_id() -> str:
    return str(uuid.uuid4())


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class FederationNode(BaseModel):
    """联邦学习参与节点"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=_gen_id, description="节点唯一ID")
    name: str = Field(..., description="节点名称（分支机构/团队标识）")
    role: FederationRole = Field(default=FederationRole.PARTICIPANT)
    public_key: str = Field("", description="节点公钥（用于梯度加密验证）")
    data_size: int = Field(0, ge=0, description="本地数据量（不暴露原始数据）")
    gradient_hash: str = Field("", description="最新梯度哈希（用于完整性校验）")
    joined_at: str = Field(default_factory=_now_iso, description="加入时间 ISO8601")
    last_heartbeat: str = Field(default_factory=_now_iso, description="最后心跳")
    is_active: bool = Field(default=True, description="是否活跃")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EncryptedGradient(BaseModel):
    """加密梯度包 — 唯一允许对外传输的数据形式"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=_gen_id)
    node_id: str = Field(..., description="来源节点ID")
    round_number: int = Field(..., ge=0, description="训练轮次")
    encrypted_params: str = Field(..., description="加密后的模型参数密文")
    encryption_scheme: EncryptionScheme = Field(default=EncryptionScheme.GRADIENT_NOISE_DP)
    param_hash: str = Field("", description="参数明文哈希（聚合端验证用）")
    gradient_norm: float = Field(0.0, ge=0.0, description="梯度范数（用于异常检测）")
    sample_count: int = Field(0, ge=0, description="本次训练样本数")
    created_at: str = Field(default_factory=_now_iso)

    def is_safe_for_transmission(self) -> bool:
        """传输安全检查：必须包含加密参数且无明文数据泄露"""
        return bool(self.encrypted_params) and len(self.encrypted_params) > 0


class FederatedTrainingConfig(BaseModel):
    """联邦训练配置"""
    model_config = ConfigDict(extra="forbid")
    task_id: str = Field(default_factory=_gen_id)
    model_architecture: str = Field("vulnerability_detector_v3", description="模型架构标识")
    max_rounds: int = Field(10, ge=1, le=1000, description="最大训练轮次")
    min_participants: int = Field(2, ge=2, le=100, description="最小参与方数")
    target_accuracy: float = Field(0.85, ge=0.0, le=1.0, description="目标准确率")
    learning_rate: float = Field(0.01, gt=0.0, le=1.0)
    batch_size: int = Field(32, ge=1)
    encryption_scheme: EncryptionScheme = Field(default=EncryptionScheme.GRADIENT_NOISE_DP)
    dp_epsilon: float = Field(1.0, ge=0.0, le=10.0, description="差分隐私预算")
    aggregation_method: str = Field("fedavg")
    local_epochs: int = Field(5, ge=1, le=100)
    created_at: str = Field(default_factory=_now_iso)


class FederatedRoundResult(BaseModel):
    """单轮训练结果"""
    model_config = ConfigDict(extra="ignore")
    round_number: int = Field(..., ge=0)
    participating_nodes: List[str] = Field(default_factory=list)
    global_loss: float = Field(0.0, ge=0.0)
    global_accuracy: float = Field(0.0, ge=0.0, le=1.0)
    privacy_loss_spent: float = Field(0.0, ge=0.0, description="累计隐私损失")
    aggregation_time_ms: float = Field(0.0, ge=0.0)
    created_at: str = Field(default_factory=_now_iso)


class FederatedTrainingReport(BaseModel):
    """联邦训练最终报告"""
    model_config = ConfigDict(extra="ignore")
    task_id: str = Field(...)
    model_architecture: str = Field(...)
    total_rounds: int = Field(0, ge=0)
    final_accuracy: float = Field(0.0, ge=0.0, le=1.0)
    final_loss: float = Field(0.0, ge=0.0)
    total_privacy_loss: float = Field(0.0, ge=0.0)
    participant_count: int = Field(0, ge=0)
    round_results: List[FederatedRoundResult] = Field(default_factory=list)
    model_hash: str = Field("", description="最终模型哈希")
    compliance_passed: bool = Field(default=True)
    completed_at: str = Field(default_factory=_now_iso)


# ─────────────────────── 规则共享模型 ───────────────────────

class ShareableRule(BaseModel):
    """可共享规则（已脱敏）"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=_gen_id)
    original_rule_id_hash: str = Field("", description="原始规则ID哈希（不可逆）")
    rule_name: str = Field(..., description="规则名称")
    category: str = Field(..., description="规则类别")
    cwe: Optional[str] = Field(None, description="关联CWE")
    severity: str = Field("MEDIUM", description="严重度")
    pattern_description: str = Field(..., description="模式描述（脱敏后，无具体代码）")
    detection_logic: str = Field(..., description="检测逻辑（伪代码/抽象描述）")
    false_positive_notes: str = Field("", description="误报注意事项")
    remediation_guidance: str = Field("", description="修复建议")
    scope: RuleShareScope = Field(default=RuleShareScope.TEAM)
    sensitivity: RuleSensitivity = Field(default=RuleSensitivity.MEDIUM)
    source_team_hash: str = Field("", description="来源团队标识（脱敏hash）")
    signature: str = Field("", description="规则签名（防篡改）")
    shared_at: str = Field(default_factory=_now_iso)
    is_active: bool = Field(default=True)

    def contains_sensitive_data(self) -> bool:
        """检查是否包含敏感数据残留"""
        sensitive_patterns = [
            "192.168.", "10.0.", "172.16.", "172.17.", "172.18.",
            "172.19.", "172.20.", "172.31.", "internal.", "corp.",
            "prod-", "production", "password=", "secret=", "api_key=",
        ]
        text = f"{self.rule_name} {self.pattern_description} {self.detection_logic}".lower()
        return any(p in text for p in sensitive_patterns)


class RulePackage(BaseModel):
    """规则共享包"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=_gen_id)
    rules: List[ShareableRule] = Field(default_factory=list)
    scope: RuleShareScope = Field(default=RuleShareScope.TEAM)
    encrypted_manifest: str = Field("", description="加密清单（防篡改）")
    package_hash: str = Field("", description="包完整性哈希")
    created_at: str = Field(default_factory=_now_iso)
    expires_at: Optional[str] = Field(None)
    recipient_team_hashes: List[str] = Field(default_factory=list)


# ─────────────────────── 隐私验证模型 ───────────────────────

class PrivacyCheckItem(BaseModel):
    """单项隐私检查"""
    model_config = ConfigDict(extra="ignore")
    check_id: str = Field(..., description="检查项ID")
    check_name: str = Field(..., description="检查项名称")
    standard: ComplianceStandard = Field(...)
    passed: bool = Field(...)
    severity: str = Field("HIGH")
    details: str = Field("")
    remediation: str = Field("")
    evidence_hash: str = Field("")


class PrivacyComplianceReport(BaseModel):
    """隐私合规报告"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=_gen_id)
    generated_at: str = Field(default_factory=_now_iso)
    overall_passed: bool = Field(default=False)
    standards_checked: List[ComplianceStandard] = Field(default_factory=list)
    checks: List[PrivacyCheckItem] = Field(default_factory=list)
    passed_count: int = Field(0, ge=0)
    failed_count: int = Field(0, ge=0)
    risk_level: str = Field("low")
    summary: str = Field("")
    report_hash: str = Field("")


class DataTransferAudit(BaseModel):
    """数据传输审计记录"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=_gen_id)
    transfer_type: str = Field(...)
    source_node: str = Field(...)
    destination_node: str = Field(...)
    encryption_verified: bool = Field(default=False)
    plaintext_detected: bool = Field(default=False)
    data_size_bytes: int = Field(0, ge=0)
    transfer_timestamp: str = Field(default_factory=_now_iso)
    compliance_passed: bool = Field(default=True)


# ─────────────────────── 协同任务模型 ───────────────────────

class CollaborativeTaskStatus(str, Enum):
    """协同任务状态"""
    DRAFT = "draft"
    PENDING_ASSIGNMENT = "pending"
    SCANNING = "scanning"
    AGGREGATING = "aggregating"
    REVIEWING = "reviewing"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class ScanPermission(BaseModel):
    """扫描权限范围"""
    model_config = ConfigDict(extra="forbid")
    team_id: str = Field(...)
    team_name: str = Field("")
    allowed_paths: List[str] = Field(default_factory=list)
    excluded_paths: List[str] = Field(default_factory=list)
    max_severity_access: str = Field("CRITICAL")
    can_view_code: bool = Field(default=False)
    can_view_full_path: bool = Field(default=True)
    can_export: bool = Field(default=True)


class CollaborativeTask(BaseModel):
    """跨团队协同审计任务"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=_gen_id)
    title: str = Field(...)
    description: str = Field("")
    status: CollaborativeTaskStatus = Field(default=CollaborativeTaskStatus.DRAFT)
    creator: str = Field("")
    visibility: TaskVisibility = Field(default=TaskVisibility.TEAM)
    permissions: List[ScanPermission] = Field(default_factory=list)
    target_repositories: List[str] = Field(default_factory=list)
    total_findings_count: int = Field(0, ge=0)
    aggregated_result_hash: str = Field("")
    scan_started_at: Optional[str] = Field(None)
    scan_completed_at: Optional[str] = Field(None)
    created_at: str = Field(default_factory=_now_iso)
    updated_at: str = Field(default_factory=_now_iso)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DesensitizedFinding(BaseModel):
    """脱敏后的安全发现"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=_gen_id)
    task_id: str = Field(...)
    rule_id: str = Field(...)
    severity: str = Field(...)
    category: Optional[str] = Field(None)
    language: Optional[str] = Field(None)
    cwe: Optional[str] = Field(None)
    file_path_hash: str = Field("")
    line_range: str = Field("")
    description: str = Field(...)
    fix_suggestion: str = Field("")
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    source_team_hash: str = Field("")
    created_at: str = Field(default_factory=_now_iso)

    def contains_plaintext_code(self) -> bool:
        """检查是否包含明文代码残留"""
        combined = f"{self.description} {self.fix_suggestion}".lower()
        # 严格代码语法模式，避免匹配技术术语（如 PreparedStatement、execute 等合法词汇）
        code_indicators = [
            "def ", "class ", "function ", "import ", "<?php", "<?=",
            "select * from ", "exec(", "eval(", "os.system(",
        ]
        return any(ind in combined for ind in code_indicators)
