# -*- coding: utf-8 -*-
"""HookPoint —— Hook 点位数据模型。

一个 HookPoint 描述"应该在哪里下 Hook"这一最小可执行单元：
类名 / 方法名 / 参数签名 / 匹配到的技法 / 置信度，以及支撑置信度的
评分明细（包名相关、方法特征、调用链、字符串特征、历史经验）。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class HookPoint:
    """单条 Hook 点位。"""

    # ── 核心定位四要素 ──
    class_name: str                      # 完整类名，如 com.android.insecurebankv2.CryptoClass
    method_name: str                     # 方法名，如 encrypt
    param_signature: str                 # 参数签名，如 (Ljava/lang/String;)Ljava/lang/String;
    technique: str                       # 匹配到的技法名，如 keyword / base64
    confidence: float                    # 置信度 0.0 ~ 1.0（由关键性评分引擎计算）

    # ── 上下文信息（用于回溯与展示） ──
    score_breakdown: Dict[str, float] = field(default_factory=dict)
    call_chain: List[str] = field(default_factory=list)   # 入口 -> 目标 的调用链（类#方法）
    reason: str = ""                     # 命中理由（人读）
    strings_matched: List[str] = field(default_factory=list)
    entry_reachable: bool = False        # 是否可从入口组件（Activity/Receiver/Service）到达
    source: str = "static"               # static / dynamic / mock
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """序列化为 dict（可直接 json.dumps）。"""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """序列化为 JSON 字符串。"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HookPoint":
        """从 dict 反序列化。未知字段收进 metadata，保证向前兼容。"""
        known = {
            "class_name", "method_name", "param_signature", "technique",
            "confidence", "score_breakdown", "call_chain", "reason",
            "strings_matched", "entry_reachable", "source", "metadata",
        }
        extra = {k: v for k, v in (data or {}).items() if k not in known}
        data = {k: v for k, v in (data or {}).items() if k in known}
        if extra:
            meta = data.setdefault("metadata", {})
            meta.update(extra)
        return cls(**data)

    @property
    def qualified_method(self) -> str:
        """`类名#方法名` 形式的唯一标识。"""
        return f"{self.class_name}#{self.method_name}"

    def short_signature(self) -> str:
        """人类可读的参数签名，如 encrypt(java.lang.String) : java.lang.String。"""
        return self.param_signature or "()"

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return (
            f"HookPoint({self.qualified_method!r}, sig={self.param_signature!r}, "
            f"technique={self.technique!r}, confidence={self.confidence:.2f})"
        )
