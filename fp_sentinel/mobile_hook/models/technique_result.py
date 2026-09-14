# -*- coding: utf-8 -*-
"""TechniqueResult —— 单个技法的一次执行结果。"""

from __future__ import annotations

import time
import traceback
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from .hook_point import HookPoint


@dataclass
class TechniqueResult:
    """技法执行结果：技法名、是否成功、产出的 HookPoint 列表、耗时与元信息。"""

    technique: str                                   # 技法名（如 base64）
    success: bool = False                            # 是否成功执行（不代表有无命中）
    hook_points: List[HookPoint] = field(default_factory=list)
    error: Optional[str] = None                      # 失败时的错误摘要
    duration_ms: float = 0.0                         # 执行耗时
    degraded: bool = False                           # 是否发生了降级（如 frida 不可用回退静态分析）
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def ok(
        cls,
        technique: str,
        hook_points: List[HookPoint],
        duration_ms: float = 0.0,
        degraded: bool = False,
        **meta: Any,
    ) -> "TechniqueResult":
        """构造成功结果。"""
        return cls(
            technique=technique,
            success=True,
            hook_points=hook_points,
            duration_ms=duration_ms,
            degraded=degraded,
            metadata=meta,
        )

    @classmethod
    def fail(
        cls,
        technique: str,
        error: Optional[str] = None,
        exc: Optional[BaseException] = None,
        **meta: Any,
    ) -> "TechniqueResult":
        """构造失败结果。传入 exc 时自动截取 traceback 末段，便于排障。"""
        if exc is not None and not error:
            tb = traceback.format_exception_only(type(exc), exc)
            error = "".join(tb).strip()
        return cls(technique=technique, success=False, error=error, metadata=meta)

    @property
    def count(self) -> int:
        """命中 HookPoint 数量。"""
        return len(self.hook_points)

    def ranked(self, top_n: Optional[int] = None) -> List[HookPoint]:
        """按置信度降序返回命中点位。"""
        pts = sorted(self.hook_points, key=lambda p: p.confidence, reverse=True)
        return pts[:top_n] if top_n else pts

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

    def start_timer(self) -> None:
        """记录起始时间（配合 stop_timer 统计 duration_ms）。"""
        self._t0 = time.perf_counter()  # type: ignore[attr-defined]

    def stop_timer(self) -> None:
        """结束计时并写入 duration_ms。未 start 过则忽略。"""
        t0 = getattr(self, "_t0", None)
        if t0 is not None:
            self.duration_ms = (time.perf_counter() - t0) * 1000.0
            del self._t0  # type: ignore[attr-defined]
