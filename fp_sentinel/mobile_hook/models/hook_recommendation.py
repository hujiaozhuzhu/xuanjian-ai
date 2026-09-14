# -*- coding: utf-8 -*-
"""HookRecommendation —— Hook 点位推荐引擎的最终输出。

一次 recommend() 产生一个 HookRecommendation：
目标 APK、分析目标（goal）、排序后的 HookPoint 列表、各技法命中统计。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from .hook_point import HookPoint
from .technique_result import TechniqueResult

__version__ = "4.0.0"


@dataclass
class HookRecommendation:
    """推荐结果集合。"""

    apk_path: str                                    # 目标 APK 路径
    goal: str = "generic"                            # 分析目标（encrypt-trace 等）
    hook_points: List[HookPoint] = field(default_factory=list)  # 已按置信度降序
    technique_results: List[TechniqueResult] = field(default_factory=list)
    package_name: str = ""                           # 目标包名
    degraded: bool = False                           # 是否发生降级（frida 不可用等）
    engine_version: str = __version__
    timestamp: float = field(default_factory=time.time)

    @property
    def top(self) -> Optional[HookPoint]:
        """置信度最高的点位；无结果时为 None。"""
        return self.hook_points[0] if self.hook_points else None

    def rank(self, top_n: Optional[int] = None) -> List[HookPoint]:
        """返回前 N 个点位（默认全部，列表本身已排序）。"""
        return self.hook_points[:top_n] if top_n else list(self.hook_points)

    def technique_stats(self) -> Dict[str, int]:
        """统计各技法命中数量，如 {'base64': 3, 'keyword': 5}。"""
        stats: Dict[str, int] = {}
        for hp in self.hook_points:
            stats[hp.technique] = stats.get(hp.technique, 0) + 1
        return stats

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def format_table(self, top_n: Optional[int] = None) -> str:
        """渲染为人类可读的对齐表格（纯文本，不依赖 rich，便于 CLI 与日志复用）。

        列：Rank / Class / Method / Score / Technique
        """
        rows = self.rank(top_n)
        headers = ("Rank", "Class", "Method", "Score", "Technique")
        width = (6, 46, 28, 8, 12)
        lines = ["  ".join(h.ljust(w) for h, w in zip(headers, width)).rstrip()]
        lines.append("  ".join("-" * w for w in width))
        for i, hp in enumerate(rows, 1):
            cells = (
                str(i),
                hp.class_name[: width[1]],
                hp.method_name[: width[2]],
                f"{hp.confidence:.2f}",
                hp.technique[: width[4]],
            )
            lines.append("  ".join(c.ljust(w) for c, w in zip(cells, width)).rstrip())
        return "\n".join(lines)
