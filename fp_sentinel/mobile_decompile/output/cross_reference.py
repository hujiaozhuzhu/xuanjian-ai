"""交叉引用（XRef）分析。

基于调用图建立 符号 -> 引用者/被引用者 的双向索引，
为关键字搜索的 CALL/XREF 匹配与 Hook 点位推荐（能力③）提供底座。
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple


class CrossReferenceAnalyzer:
    """交叉引用索引。

    引用模型：``references[a] = [b, ...]`` 表示 a 引用了 b。
    语义由调用方决定（如 a 的方法体调用了 b）。
    """

    def __init__(self, call_graph: Optional[Dict[str, List[str]]] = None) -> None:
        self._references: Dict[str, List[str]] = {}
        self._referenced_by: Dict[str, List[str]] = {}
        if call_graph:
            for caller, callees in call_graph.items():
                for callee in callees:
                    self.add_reference(caller, callee)

    def add_reference(self, source: str, target: str) -> None:
        if source == target:
            return
        targets = self._references.setdefault(source, [])
        if target not in targets:
            targets.append(target)
        sources = self._referenced_by.setdefault(target, [])
        if source not in sources:
            sources.append(source)

    def get_references(self, symbol: str) -> List[str]:
        """symbol 引用了谁。"""
        return list(self._references.get(symbol, []))

    def get_referenced_by(self, symbol: str) -> List[str]:
        """谁引用了 symbol。"""
        return list(self._referenced_by.get(symbol, []))

    def xrefs_of(self, symbol: str) -> Tuple[List[str], List[str]]:
        """返回 (referenced_by, references) 双向结果。"""
        return self.get_referenced_by(symbol), self.get_references(symbol)

    def symbols(self) -> List[str]:
        """全部出现过的符号（引用方与被引用方）。"""
        seen = set(self._references)
        seen.update(self._referenced_by)
        return sorted(seen)

    def most_referenced(self, top_n: int = 10) -> List[Tuple[str, int]]:
        """被引用次数最多的符号（调用链热度的直接来源）。"""
        ranked = sorted(
            self._referenced_by.items(), key=lambda kv: len(kv[1]), reverse=True
        )
        return [(sym, len(refs)) for sym, refs in ranked[:top_n]]

    def to_dict(self) -> Dict[str, List[str]]:
        return {k: list(v) for k, v in self._references.items()}

    def __len__(self) -> int:
        return len(self._references)
