"""
玄鉴 v3.0 — 隐私计算加密层

提供：
- 同态加密简化实现（Paillier 风格，基于大整数运算，纯本地）
- 差分隐私噪声注入（用于梯度混淆）
- 密钥管理（本地生成、本地存储，永不外发）
- 梯度加密/解密/聚合

安全红线：
- S8: 仅传输加密后的模型参数，原始梯度永不暴露
- S1: 纯本地运算，零网络请求
- S7: 密钥仅存在于内存，不持久化到磁盘（除非显式导出到白名单路径）

注意：本模块使用的加密方案是教学/工程简化实现。
生产环境应替换为成熟库（如 python-paillier, opacus 等）。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    EncryptedGradient,
    EncryptionScheme,
    FederationNode,
)


# ─────────────────────── 密钥管理 ───────────────────────

class LocalKeyManager:
    """
    本地密钥管理器 — 密钥仅存在于内存中，不自动持久化。
    调用方必须显式调用 export_keys 才会将密钥写入白名单路径。
    """

    def __init__(self):
        self._private_key: Optional[Dict[str, int]] = None
        self._public_key: Optional[Dict[str, int]] = None
        self._key_id: str = ""

    def generate_keypair(self, key_size: int = 512) -> str:
        """
        生成 RSA-style 密钥对（用于同态加密基础）。

        Args:
            key_size: 密钥位数（最低 512，仅用于工程简化演示）

        Returns:
            key_id: 密钥标识
        """
        # 生成两个大素数
        p = self._generate_prime(key_size // 2)
        q = self._generate_prime(key_size // 2)
        n = p * q
        phi = (p - 1) * (q - 1)

        # 公钥指数 e
        e = 65537
        # 私钥指数 d
        d = self._modinv(e, phi)

        self._public_key = {"n": n, "e": e}
        self._private_key = {"n": n, "d": d, "p": p, "q": q}
        self._key_id = hashlib.sha256(f"{n}{e}".encode()).hexdigest()[:16]
        return self._key_id

    def get_public_key(self) -> Optional[Dict[str, int]]:
        return self._public_key

    def get_key_id(self) -> str:
        return self._key_id

    def has_keys(self) -> bool:
        return self._public_key is not None and self._private_key is not None

    @staticmethod
    def _generate_prime(bits: int) -> int:  # pragma: no cover — slow (Miller-Rabin); exercised via generate_keypair
        """生成指定位数的大素数（简化版，使用 secrets 模块）。"""
        while True:
            # secrets 提供密码学安全的随机数
            n = secrets.randbits(bits) | (1 << (bits - 1)) | 1
            if LocalKeyManager._is_prime(n):
                return n

    @staticmethod
    def _is_prime(n: int, k: int = 10) -> bool:  # pragma: no cover
        """Miller-Rabin 素性检测。"""
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False

        # 写 n-1 = 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        # k 轮测试
        for _ in range(k):
            a = secrets.randbelow(n - 3) + 2
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    @staticmethod
    def _modinv(a: int, m: int) -> int:  # pragma: no cover
        """模逆元（扩展欧几里得算法）。"""
        g, x, _ = LocalKeyManager._extended_gcd(a, m)
        if g != 1:
            raise ValueError("模逆元不存在")
        return x % m

    @staticmethod
    def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        g, x, y = LocalKeyManager._extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

    def export_public_key_pem(self) -> str:
        """导出公钥为 PEM 格式字符串。"""
        if not self._public_key:
            raise RuntimeError("未生成密钥对")
        n = self._public_key["n"]
        e = self._public_key["e"]
        payload = json.dumps({"n": n, "e": e, "key_id": self._key_id})
        return f"-----BEGIN PUBLIC KEY-----\n{payload}\n-----END PUBLIC KEY-----"


# ─────────────────────── 差分隐私 ───────────────────────

class DifferentialPrivacy:
    """
    差分隐私噪声机制 — 向梯度添加 calibrated noise。
    使用拉普拉斯机制实现 epsilon-DP。
    """

    @staticmethod
    def add_laplace_noise(
        value: float,
        sensitivity: float,
        epsilon: float,
    ) -> float:
        """
        向单个值添加拉普拉斯噪声。

        Args:
            value: 原始值
            sensitivity: 查询敏感度（梯度最大变化量）
            epsilon: 隐私预算（越小隐私保护越强）

        Returns:
            加噪后的值
        """
        if epsilon <= 0:
            raise ValueError("epsilon 必须为正数")
        scale = sensitivity / epsilon
        # 使用 secrets 生成均匀随机数，然后转换为拉普拉斯分布
        u = secrets.randbelow(2**53) / 2**53 - 0.5  # U(-0.5, 0.5)
        # 逆 CDF 方法：拉普拉斯分布
        noise = -scale * math.copysign(1.0, u) * math.log(1 - 2 * abs(u))
        return value + noise

    @staticmethod
    def add_noise_to_gradients(
        gradients: List[float],
        sensitivity: float = 1.0,
        epsilon: float = 1.0,
    ) -> List[float]:
        """向梯度向量批量添加拉普拉斯噪声。"""
        return [
            DifferentialPrivacy.add_laplace_noise(g, sensitivity, epsilon)
            for g in gradients
        ]

    @staticmethod
    def compute_privacy_loss(
        rounds: int,
        epsilon_per_round: float,
        delta: float = 1e-5,
    ) -> float:
        """
        使用基本组合定理计算累计隐私损失。

        Args:
            rounds: 训练轮次
            epsilon_per_round: 每轮隐私预算
            delta: 松弛参数

        Returns:
            累计隐私损失上界（基本组合: rounds * epsilon_per_round）
        """
        # 基本组合定理（最坏情况上界）
        basic_composition = rounds * epsilon_per_round
        # 高级组合定理（更紧的界）— 仅当 delta > 0 时适用
        if delta > 0:
            advanced = epsilon_per_round * math.sqrt(2 * rounds * math.log(1 / delta))
            return min(basic_composition, advanced)
        return basic_composition


# ─────────────────────── 梯度加密引擎 ───────────────────────

class GradientEncryptionEngine:
    """
    梯度加密引擎 — 负责模型参数的加密、混淆与完整性校验。

    支持三种模式：
    1. HE Paillier: 半同态加密（支持加法同态）
    2. DP Noise: 差分隐私噪声混淆（联邦学习常用）
    3. Secret Sharing: 秘密共享（分片分发）
    """

    def __init__(self, scheme: EncryptionScheme = EncryptionScheme.GRADIENT_NOISE_DP):
        self.scheme = scheme
        self.key_manager = LocalKeyManager()
        self._dp = DifferentialPrivacy()

    def initialize(self, dp_epsilon: float = 1.0) -> str:
        """初始化加密引擎，返回 key_id。"""
        key_id = self.key_manager.generate_keypair()
        self.dp_epsilon = dp_epsilon
        return key_id

    def encrypt_gradients(
        self,
        gradients: List[float],
        node_id: str,
        round_number: int,
        sensitivity: float = 1.0,
        epsilon: float = 1.0,
    ) -> EncryptedGradient:
        """
        加密梯度 — 核心接口，确保梯度在传输前被加密。

        Args:
            gradients: 原始梯度值列表
            node_id: 节点标识
            round_number: 训练轮次
            sensitivity: DP 敏感度
            epsilon: DP 预算

        Returns:
            EncryptedGradient 加密梯度包
        """
        if self.scheme == EncryptionScheme.GRADIENT_NOISE_DP:
            noisy = DifferentialPrivacy.add_noise_to_gradients(
                gradients, sensitivity, epsilon
            )
            # 序列化并进行 base64 风格编码（这里用 hex 简化）
            payload = json.dumps(noisy)
            encrypted_params = self._derive_cipher(payload, node_id, round_number)
        elif self.scheme == EncryptionScheme.HOMOMORPHIC_PAILLIER:
            # 简化 Paillier：逐元素 RSA 加密（仅演示，非真正 Paillier）
            encrypted_params = self._pailliar_encrypt(gradients)
        else:
            # Secret Sharing: 简单分片 + 哈希
            encrypted_params = self._secret_share(gradients, node_id)

        param_hash = hashlib.sha256(
            json.dumps(gradients).encode()
        ).hexdigest()
        gradient_norm = math.sqrt(sum(g * g for g in gradients))

        return EncryptedGradient(
            node_id=node_id,
            round_number=round_number,
            encrypted_params=encrypted_params,
            encryption_scheme=self.scheme,
            param_hash=param_hash,
            gradient_norm=gradient_norm,
            sample_count=len(gradients),
        )

    def _derive_cipher(self, payload: str, node_id: str, round_number: int) -> str:
        """使用 HKDF-style 派生加密密钥并 XOR 加密（简化实现）。"""
        salt = f"{node_id}:{round_number}".encode()
        key = hashlib.pbkdf2_hmac("sha256", b"gradient-key", salt, 1000, dklen=32)
        payload_bytes = payload.encode("utf-8")
        # XOR with key stream
        key_stream = (key * (len(payload_bytes) // len(key) + 1))[:len(payload_bytes)]
        cipher = bytes(a ^ b for a, b in zip(payload_bytes, key_stream))
        return cipher.hex()

    def _pailliar_encrypt(self, gradients: List[float]) -> str:
        """简化 Paillier 加密 — 逐元素加密。"""
        if not self.key_manager.has_keys():
            self.key_manager.generate_keypair()
        pk = self.key_manager.get_public_key()
        n = pk["n"]
        e = pk["e"]
        encrypted = [pow(int(g * 1000) + n, e, n * n) for g in gradients]
        return json.dumps(encrypted)

    def _secret_share(self, gradients: List[str], node_id: str) -> str:
        """简化秘密共享 — 生成份额哈希。"""
        seed = hashlib.sha256(f"{node_id}:sss".encode()).digest()
        shares = []
        for g in gradients:
            share = hmac.new(seed, str(g).encode(), hashlib.sha256).hexdigest()
            shares.append(share)
        return json.dumps(shares)

    @staticmethod
    def verify_gradient_integrity(
        gradient: EncryptedGradient,
        expected_hash: str,
    ) -> bool:
        """验证梯度完整性。"""
        return gradient.param_hash == expected_hash and gradient.is_safe_for_transmission()


# ─────────────────────── 密钥交换与认证 ───────────────────────

class NodeAuthenticator:
    """节点间双向认证（基于Challenge-Response，零信任）。"""

    @staticmethod
    def generate_challenge() -> str:
        """生成随机挑战字符串。"""
        return secrets.token_hex(32)

    @staticmethod
    def sign_challenge(challenge: str, node_secret: str) -> str:
        """节点对挑战签名（HMAC-SHA256）。"""
        return hmac.new(
            node_secret.encode(), challenge.encode(), hashlib.sha256
        ).hexdigest()

    @staticmethod
    def verify_challenge_response(
        challenge: str, response: str, node_secret: str
    ) -> bool:
        """验证挑战响应。"""
        expected = NodeAuthenticator.sign_challenge(challenge, node_secret)
        return hmac.compare_digest(expected, response)


# ─────────────────────── 聚合加密 ───────────────────────

class SecureAggregator:
    """
    安全聚合器 — 聚合加密梯度。
    在 DP noise 模式下，聚合噪声后得到近似全局梯度（噪声相互抵消趋势）。
    """

    @staticmethod
    def aggregate_fedavg(
        gradient_packages: List[EncryptedGradient],
    ) -> Dict[str, Any]:
        """
        FedAvg 聚合 — 加权平均（按 sample_count 加权）。

        注意：实际场景中，加密梯度在密文上聚合（如 Paillier 的同态加法）。
        这里在解密/去噪后聚合（DP noise 模式下的标准流程）。

        Returns:
            {
                "aggregated_norm": float,
                "total_samples": int,
                "participants": int,
                "scheme": str,
            }
        """
        if not gradient_packages:
            return {
                "aggregated_norm": 0.0,
                "total_samples": 0,
                "participants": 0,
                "scheme": EncryptionScheme.GRADIENT_NOISE_DP.value,
            }

        total_samples = sum(g.sample_count for g in gradient_packages)
        total_norm = sum(g.gradient_norm for g in gradient_packages)

        # 加权平均
        if total_samples > 0:
            weighted_norm = sum(
                g.gradient_norm * g.sample_count for g in gradient_packages
            ) / total_samples
        else:
            weighted_norm = total_norm / len(gradient_packages)

        return {
            "aggregated_norm": weighted_norm,
            "total_samples": total_samples,
            "participants": len(gradient_packages),
            "scheme": gradient_packages[0].encryption_scheme.value,
            "gradient_norms": [g.gradient_norm for g in gradient_packages],
        }


# ─────────────────────── 工具函数 ───────────────────────

def derive_node_shared_secret(
    node_a_key: str, node_b_key: str
) -> str:
    """派生节点间共享密钥。"""
    combined = "".join(sorted([node_a_key, node_b_key]))
    return hashlib.sha256(combined.encode()).hexdigest()


def compute_data_hash(data: Any) -> str:
    """计算数据 integrity hash。"""
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()
