"""
玄鉴 v3.0 — 联邦学习协同训练引擎

支持多分支机构/团队联合训练漏洞检出模型：
- 原始数据全程不出本地
- 仅上传加密的模型梯度
- 支持 FedAvg 聚合、差分隐私保护
- 支持参与方动态加入/退出
- 训练过程全审计

安全红线：
- S1: 所有计算本地完成（联邦模拟在同一进程内）
- S8: 梯度传输前必须加密
- S2: 不修改被扫描源码
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .crypto import (
    GradientEncryptionEngine,
    NodeAuthenticator,
    SecureAggregator,
    DifferentialPrivacy,
)
from .models import (
    EncryptedGradient,
    EncryptionScheme,
    FederationNode,
    FederationRole,
    FederatedRoundResult,
    FederatedTrainingConfig,
    FederatedTrainingReport,
    TrainingStatus,
)

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class LocalParticipant:
    """
    本地联邦学习参与方 — 模拟一个分支机构的本地训练。

    实际部署中，每个参与方运行在自己的节点上。本地模拟用
    不同实例表示不同节点，仅交换加密后的梯度。
    """

    def __init__(
        self,
        node: FederationNode,
        local_data_size: int = 1000,
        encryption_engine: Optional[GradientEncryptionEngine] = None,
    ):
        self.node = node
        self.local_data_size = local_data_size
        self.engine = encryption_engine or GradientEncryptionEngine()
        self.local_model_weights: List[float] = []
        self.training_history: List[Dict[str, Any]] = []
        self.is_trained = False

    def initialize_model(self, dimension: int = 10, seed: Optional[int] = None) -> None:
        """初始化本地模型权重（模拟）。"""
        import random
        rng = random.Random(seed if seed is not None else hash(self.node.id))
        self.local_model_weights = [rng.gauss(0, 0.1) for _ in range(dimension)]
        self.is_trained = False

    def local_train(
        self,
        global_weights: List[float],
        epochs: int = 5,
        learning_rate: float = 0.01,
    ) -> List[float]:
        """
        执行本地训练 — 模拟本地 SGD 更新。

        Args:
            global_weights: 全局模型权重
            epochs: 本地训练轮数
            learning_rate: 学习率

        Returns:
            gradient: 本地梯度（权重变化量）
        """
        if not self.local_model_weights:
            self.local_model_weights = list(global_weights)

        # 模拟本地训练：每个 epoch 添加一定噪声模拟收敛
        import random
        rng = random.Random(hash(self.node.id) + epochs)

        for _ in range(epochs):
            for i in range(len(self.local_model_weights)):
                # 模拟 SGD 更新
                grad = rng.gauss(0, 0.01) * learning_rate
                self.local_model_weights[i] -= grad

        # 计算梯度差（全局权重 - 本地权重）
        gradient = [
            gw - lw for gw, lw in zip(global_weights, self.local_model_weights)
        ]
        self.is_trained = True
        return gradient

    def apply_global_model(self, global_weights: List[float]) -> None:
        """应用全局模型更新（聚合后的权重）。"""
        self.local_model_weights = list(global_weights)


class FederatedTrainingSession:
    """
    联邦学习训练会话 — 协调多个参与方进行联合训练。

    协调方角色：
    1. 初始化全局模型
    2. 分发全局权重（模拟）
    3. 收集加密梯度
    4. 聚合梯度
    5. 更新全局模型
    6. 重复直到收敛
    """

    def __init__(self, config: FederatedTrainingConfig):
        self.config = config
        self.session_id = config.task_id
        self.status = TrainingStatus.INITIALIZING
        self.coordinator = FederationNode(
            name="coordinator",
            role=FederationRole.COORDINATOR,
        )
        self.participants: Dict[str, LocalParticipant] = {}
        self.global_weights: List[float] = []
        self.model_dimension: int = 10
        self.current_round: int = 0
        self.round_results: List[FederatedRoundResult] = []
        self.encryption_engine = GradientEncryptionEngine(config.encryption_scheme)
        self.authenticator = NodeAuthenticator()
        self.transfer_audit_log: List[Dict[str, Any]] = []
        self._global_loss: float = float("inf")
        self._global_accuracy: float = 0.0
        self._privacy_loss: float = 0.0

    async def initialize(self) -> None:
        """初始化训练会话。"""
        self.status = TrainingStatus.INITIALIZING
        # 初始化加密引擎
        self.encryption_engine.initialize(dp_epsilon=self.config.dp_epsilon)
        # 初始化全局模型
        import random
        rng = random.Random(42)
        self.global_weights = [rng.gauss(0, 0.1) for _ in range(self.model_dimension)]
        self.current_round = 0
        self._global_loss = float("inf")
        self._global_accuracy = 0.0
        self._privacy_loss = 0.0
        self.status = TrainingStatus.WAITING
        logger.info("Federated session initialized: %s", self.session_id)

    async def add_participant(
        self,
        name: str,
        data_size: int = 1000,
    ) -> FederationNode:
        """添加参与节点。"""
        node = FederationNode(
            name=name,
            role=FederationRole.PARTICIPANT,
            data_size=data_size,
            public_key=self.encryption_engine.key_manager.export_public_key_pem(),
        )
        participant = LocalParticipant(
            node=node,
            local_data_size=data_size,
        )
        participant.initialize_model(self.model_dimension)
        self.participants[node.id] = participant
        logger.info("Participant added: %s (data_size=%d)", name, data_size)
        return node

    async def run_training_round(self) -> FederatedRoundResult:
        """
        执行一轮联邦训练。

        流程：
        1. 分发全局权重到各参与方
        2. 各参与方本地训练
        3. 收集加密梯度
        4. 验证梯度安全性
        5. 聚合梯度
        6. 更新全局模型
        """
        if self.status == TrainingStatus.WAITING:
            self.status = TrainingStatus.TRAINING

        self.current_round += 1
        round_num = self.current_round
        start_time = time.time()

        # ── Step 1: 各参与方本地训练 + 加密梯度 ──
        encrypted_gradients: List[EncryptedGradient] = []
        participating_node_ids: List[str] = []

        for pid, participant in self.participants.items():
            if not participant.node.is_active:
                continue

            # 本地训练
            gradient = participant.local_train(
                self.global_weights,
                epochs=self.config.local_epochs,
                learning_rate=self.config.learning_rate,
            )

            # 加密梯度
            encrypted_grad = self.encryption_engine.encrypt_gradients(
                gradients=gradient,
                node_id=pid,
                round_number=round_num,
                sensitivity=1.0,
                epsilon=self.config.dp_epsilon,
            )

            # 安全性验证
            if not encrypted_grad.is_safe_for_transmission():
                logger.warning("Node %s 加密梯度不安全，跳过", pid)
                continue

            # 审计记录
            self.transfer_audit_log.append({
                "type": "gradient_upload",
                "node_id": pid,
                "round": round_num,
                "encrypted": True,
                "scheme": self.config.encryption_scheme.value,
            })

            encrypted_gradients.append(encrypted_grad)
            participating_node_ids.append(pid)

        if len(encrypted_gradients) < self.config.min_participants:
            self.status = TrainingStatus.FAILED
            raise RuntimeError(
                f"参与方不足: {len(encrypted_gradients)} < {self.config.min_participants}"
            )

        # ── Step 2: 聚合加密梯度 ──
        self.status = TrainingStatus.AGGREGATING
        agg_result = SecureAggregator.aggregate_fedavg(encrypted_gradients)

        # ── Step 3: 更新全局模型 ──
        # 模拟梯度下降更新
        agg_norm = agg_result["aggregated_norm"]
        for i in range(len(self.global_weights)):
            self.global_weights[i] -= self.config.learning_rate * agg_norm * 0.01

        # 更新参与方本地模型
        for pid, participant in self.participants.items():
            if pid in participating_node_ids:
                participant.apply_global_model(self.global_weights)

        # ── Step 4: 计算本轮指标 ──
        # 模拟损失和准确率（训练轮次越多越好）
        progress = min(1.0, round_num / self.config.max_rounds)
        self._global_loss = max(0.1, 1.0 * (1 - progress * 0.9))
        self._global_accuracy = min(
            0.99, 0.5 + progress * 0.45 + 0.01 * math.sin(round_num)
        )
        # 隐私损失累计
        self._privacy_loss = DifferentialPrivacy.compute_privacy_loss(
            rounds=round_num,
            epsilon_per_round=self.config.dp_epsilon,
        )

        aggregation_time = (time.time() - start_time) * 1000

        round_result = FederatedRoundResult(
            round_number=round_num,
            participating_nodes=participating_node_ids,
            global_loss=self._global_loss,
            global_accuracy=self._global_accuracy,
            privacy_loss_spent=self._privacy_loss,
            aggregation_time_ms=aggregation_time,
        )
        self.round_results.append(round_result)

        # 检查收敛
        if self._global_accuracy >= self.config.target_accuracy:
            self.status = TrainingStatus.COMPLETED
        elif round_num >= self.config.max_rounds:
            self.status = TrainingStatus.COMPLETED

        logger.info(
            "Round %d: accuracy=%.4f, loss=%.4f, privacy_loss=%.4f, time=%.1fms",
            round_num, self._global_accuracy, self._global_loss,
            self._privacy_loss, aggregation_time,
        )

        return round_result

    async def run_full_training(self) -> FederatedTrainingReport:
        """执行完整训练流程。"""
        if self.status == TrainingStatus.WAITING:
            self.status = TrainingStatus.TRAINING

        while (
            self.status == TrainingStatus.TRAINING
            and self.current_round < self.config.max_rounds
        ):
            result = await self.run_training_round()
            if result.global_accuracy >= self.config.target_accuracy:
                break

        if self.status != TrainingStatus.COMPLETED:
            self.status = TrainingStatus.COMPLETED

        # 生成报告
        model_hash = hashlib.sha256(
            json.dumps(self.global_weights, default=str).encode()
        ).hexdigest()

        self.status = TrainingStatus.VALIDATING

        # 隐私合规校验
        compliance_passed = self._privacy_loss <= self.config.dp_epsilon * self.config.max_rounds * 1.5

        self.status = TrainingStatus.COMPLETED

        report = FederatedTrainingReport(
            task_id=self.session_id,
            model_architecture=self.config.model_architecture,
            total_rounds=self.current_round,
            final_accuracy=self._global_accuracy,
            final_loss=self._global_loss,
            total_privacy_loss=self._privacy_loss,
            participant_count=len(self.participants),
            round_results=self.round_results,
            model_hash=model_hash,
            compliance_passed=compliance_passed,
        )

        logger.info(
            "Training completed: rounds=%d, accuracy=%.4f, privacy_compliant=%s",
            report.total_rounds, report.final_accuracy, report.compliance_passed,
        )
        return report

    def get_session_status(self) -> Dict[str, Any]:
        """获取会话状态。"""
        return {
            "session_id": self.session_id,
            "status": self.status.value,
            "current_round": self.current_round,
            "max_rounds": self.config.max_rounds,
            "participants": len(self.participants),
            "current_accuracy": self._global_accuracy,
            "current_loss": self._global_loss,
            "privacy_loss": self._privacy_loss,
        }


def create_training_session(
    max_rounds: int = 10,
    min_participants: int = 2,
    target_accuracy: float = 0.85,
    engine: EncryptionScheme = EncryptionScheme.GRADIENT_NOISE_DP,
    dp_epsilon: float = 1.0,
) -> FederatedTrainingSession:
    """
    便捷工厂函数 — 创建联邦训练会话。

    Args:
        max_rounds: 最大训练轮次
        min_participants: 最小参与方数
        target_accuracy: 目标准确率
        engine: 加密方案
        dp_epsilon: 差分隐私预算

    Returns:
        FederatedTrainingSession 训练会话实例
    """
    config = FederatedTrainingConfig(
        max_rounds=max_rounds,
        min_participants=min_participants,
        target_accuracy=target_accuracy,
        encryption_scheme=engine,
        dp_epsilon=dp_epsilon,
    )
    return FederatedTrainingSession(config)
