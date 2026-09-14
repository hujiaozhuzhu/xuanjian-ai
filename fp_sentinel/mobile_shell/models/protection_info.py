"""
加固信息数据模型 —— ProtectionInfo

对齐《v4.0.0-mobile-reverse-engineering-plan.md》2.1.4 CLI 设计：
    fp-sentinel mobile shell detect ./app.apk
    # Output: {protection: "360加固", version: "v4.2", confidence: 0.95}
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

#: 支持识别的加固类型常量（含"无壳"）
PROTECTION_NONE = "无壳"
PROTECTION_360 = "360加固"
PROTECTION_TENCENT = "腾讯乐固"
PROTECTION_BANGCLE = "梆梆加固"
PROTECTION_IJIAMI = "爱加密"
PROTECTION_NAGA = "娜迦加固"
PROTECTION_BAIDU = "百度加固"
PROTECTION_ALI = "阿里聚安全"
PROTECTION_UNKNOWN = "unknown"

KNOWN_PROTECTIONS: List[str] = [
    PROTECTION_360,
    PROTECTION_TENCENT,
    PROTECTION_BANGCLE,
    PROTECTION_IJIAMI,
    PROTECTION_NAGA,
    PROTECTION_BAIDU,
    PROTECTION_ALI,
]


@dataclass
class ProtectionInfo:
    """加固类型识别结果。

    Attributes:
        protection:      加固类型名称（KNOWN_PROTECTIONS 之一 / 无壳 / unknown）
        confidence:      置信度 0-1
        version:         可选加固 SDK 版本（特征串中解析）
        packer_class:    可选加固入口 Application 类名
        native_libs:     命中的加固 so 文件列表
        signature_files: 命中的特征文件列表（如 ijiami.dat）
        signatures:      命中的特征字符串列表
        is_packed:       是否为加固包（无壳为 False）
        details:         额外元数据（入口类、dex 数量等）
    """

    protection: str = PROTECTION_UNKNOWN
    confidence: float = 0.0
    version: Optional[str] = None
    packer_class: Optional[str] = None
    native_libs: List[str] = field(default_factory=list)
    signature_files: List[str] = field(default_factory=list)
    signatures: List[str] = field(default_factory=list)
    is_packed: bool = False
    details: Dict[str, object] = field(default_factory=dict)

    def merge_hit(
        self,
        file_hits: List[str],
        string_hits: List[str],
        lib_hits: List[str],
        packer_class: Optional[str],
    ) -> None:
        """合并一次命中扫描的产物。"""
        self.signature_files.extend(file_hits)
        self.signatures.extend(string_hits)
        self.native_libs.extend(lib_hits)
        if packer_class and not self.packer_class:
            self.packer_class = packer_class

    @property
    def hit_count(self) -> int:
        """总命中特征数（文件 + 字符串 + so + 入口类）。"""
        return (
            len(self.signature_files)
            + len(self.signatures)
            + len(self.native_libs)
            + (1 if self.packer_class else 0)
        )

    def summary(self) -> str:
        """单行摘要（CLI 输出用）。"""
        return (
            f"protection={self.protection} confidence={self.confidence:.2f} "
            f"packed={self.is_packed}"
        )
