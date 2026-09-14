# -*- coding: utf-8 -*-
"""CallChainAnalyzer —— 调用链分析器。

基于 ApkContext 中的方法级调用关系（invokes），构建"调用者 -> 被调者"
有向图，支持：
- 指定目标点位的反向调用链回溯（谁调用到了这里），深度默认 12（≥10）；
- 入口组件（Activity/Service/Receiver/Provider）可达性判定；
- 最短路径提取（BFS），用于输出人类可读的 调用链 列表。
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .apk_context import ApkContext, MethodInfo

logger = logging.getLogger(__name__)

DEFAULT_MAX_DEPTH = 12  # 规划要求深度 >= 10


@dataclass
class CallChain:
    """一条从入口（或自由起点）到目标的调用链。"""

    target: Tuple[str, str]                          # 目标 (类, 方法)
    nodes: List[str] = field(default_factory=list)   # 顺序节点 "类#方法"（含起点与目标）
    entry_point: Optional[str] = None                # 起点是否为入口组件
    depth: int = 0                                   # 链条长度（边数）

    @property
    def reachable_from_entry(self) -> bool:
        return self.entry_point is not None

    def as_list(self) -> List[str]:
        return list(self.nodes)


class CallChainAnalyzer:
    """类间/方法间调用关系分析。"""

    def __init__(self, context: ApkContext, max_depth: int = DEFAULT_MAX_DEPTH):
        if max_depth < 1:
            raise ValueError("max_depth 必须 >= 1")
        self.context = context
        self.max_depth = max_depth
        self._caller_index: Optional[Dict[Tuple[str, str], Set[Tuple[str, str]]]] = None
        self._callee_index: Optional[Dict[Tuple[str, str], Set[Tuple[str, str]]]] = None

    # ────────────────────────── 索引构建 ──────────────────────────

    def _build_index(self) -> Tuple[Dict, Dict]:
        """构建 caller/callee 索引（惰性，一次构建复用）。"""
        if self._caller_index is not None and self._callee_index is not None:
            return self._caller_index, self._callee_index
        callers: Dict[Tuple[str, str], Set[Tuple[str, str]]] = {}
        callees: Dict[Tuple[str, str], Set[Tuple[str, str]]] = {}
        app_classes = self.context.app_classes()
        for cls in app_classes.values():
            for m in cls.methods:
                src = (m.class_name, m.name)
                for (c, n) in m.invokes:
                    dst = (c, n)
                    callers.setdefault(dst, set()).add(src)
                    callees.setdefault(src, set()).add(dst)
        self._caller_index = callers
        self._callee_index = callees
        return callers, callees

    def invalidate(self) -> None:
        """上下文数据变化后调用，强制重建索引。"""
        self._caller_index = None
        self._callee_index = None

    # ────────────────────────── 基本查询 ──────────────────────────

    def callers_of(self, class_name: str, method_name: str, depth: int = 1) -> List[Tuple[str, str]]:
        """返回 N 层内的直接/间接调用者（BFS，去重）。"""
        callers, _ = self._build_index()
        target = (class_name, method_name)
        seen: Set[Tuple[str, str]] = {target}
        frontier = {target}
        result: List[Tuple[str, str]] = []
        for _ in range(max(1, depth)):
            nxt: Set[Tuple[str, str]] = set()
            for node in frontier:
                for caller in callers.get(node, ()):
                    if caller not in seen:
                        seen.add(caller)
                        nxt.add(caller)
                        result.append(caller)
            frontier = nxt
            if not frontier:
                break
        return result

    def callees_of(self, class_name: str, method_name: str, depth: int = 1) -> List[Tuple[str, str]]:
        """返回 N 层内的直接/间接被调用者。"""
        _, callees = self._build_index()
        target = (class_name, method_name)
        seen: Set[Tuple[str, str]] = {target}
        frontier = {target}
        result: List[Tuple[str, str]] = []
        for _ in range(max(1, depth)):
            nxt: Set[Tuple[str, str]] = set()
            for node in frontier:
                for callee in callees.get(node, ()):
                    if callee not in seen:
                        seen.add(callee)
                        nxt.add(callee)
                        result.append(callee)
            frontier = nxt
            if not frontier:
                break
        return result

    # ────────────────────────── 反向回溯 ──────────────────────────

    def trace_back(
        self,
        class_name: str,
        method_name: str,
        max_depth: Optional[int] = None,
    ) -> List[CallChain]:
        """从目标方法反向回溯到入口组件（或深度上限），返回最短链列表。

        采用 BFS：先到入口的路径即为最短路径；未触达入口则返回到达
        深度上限的链（起点为最远调用者）。
        """
        depth_limit = max_depth or self.max_depth
        callers, _ = self._build_index()
        target = (class_name, method_name)

        entries = set(self.context.entry_point_list)
        # BFS：节点携带 (node, path)
        queue: deque = deque([(target, [target])])
        visited: Dict[Tuple[str, str], int] = {target: 0}
        chains: List[CallChain] = []
        found_entry = False

        while queue:
            node, path = queue.popleft()
            cur_depth = len(path) - 1
            node_class = node[0]
            # 先判入口（深度限制不能阻断最短入口链的终点判定）
            if node_class in entries and node != target:
                found_entry = True
                chains.append(self._make_chain(target, path, entry=node_class))
                continue  # 继续找其它入口的更短链
            if cur_depth >= depth_limit:
                continue
            for caller in callers.get(node, ()):
                if caller in visited and visited[caller] <= cur_depth + 1:
                    continue
                if caller in path:  # 防环
                    continue
                visited[caller] = cur_depth + 1
                queue.append((caller, [caller] + path))

        # 兜底：没有任何入口可达时，取最深的一条链
        if not chains and not found_entry:
            deepest = self._deepest_caller(target, depth_limit)
            if deepest:
                chains.append(self._make_chain(target, [deepest, target], entry=None))
        return chains

    def _deepest_caller(self, target: Tuple[str, str], depth_limit: int) -> Optional[Tuple[str, str]]:
        callers, _ = self._build_index()
        node = target
        seen: Set[Tuple[str, str]] = {target}
        for _ in range(depth_limit):
            nxt = callers.get(node, ())
            pick = None
            for cand in sorted(nxt):
                if cand not in seen:
                    pick = cand
                    break
            if pick is None:
                break
            seen.add(pick)
            node = pick
        return None if node == target else node

    def _make_chain(self, target: Tuple[str, str], path: List[Tuple[str, str]], entry: Optional[str]) -> CallChain:
        nodes = [f"{c}#{m}" for (c, m) in path]
        return CallChain(
            target=target,
            nodes=nodes,
            entry_point=entry,
            depth=len(nodes) - 1,
        )

    # ────────────────────────── 可达性 ──────────────────────────

    def entry_reachable(self, class_name: str, method_name: str, max_depth: Optional[int] = None) -> bool:
        """目标方法是否可从入口组件到达（BFS 反向，深度受 max_depth 限制）。"""
        chains = self.trace_back(class_name, method_name, max_depth=max_depth)
        return any(c.reachable_from_entry for c in chains)

    # ────────────────────────── 评分辅助 ──────────────────────────

    def chain_score(self, class_name: str, method_name: str) -> Tuple[float, List[str], bool]:
        """调用链维度评分（0.0 ~ 1.0），并返回代表链与可达性。

        规则：
        - 从入口可达: 基础 0.7，链越短越接近 UI 交互 1.0（按深度线性衰减）；
        - 不可达入口但有调用者: 0.4；
        - 完全孤立: 0.1。
        """
        chains = self.trace_back(class_name, method_name)
        reachable = any(c.reachable_from_entry for c in chains)
        if reachable:
            best = min((c.depth for c in chains if c.reachable_from_entry), default=0)
            score = max(0.7, 1.0 - 0.03 * best)
            chain_nodes = min(
                (c.nodes for c in chains if c.reachable_from_entry),
                key=len,
                default=[],
            )
            return score, chain_nodes, True
        if chains:
            return 0.4, (chains[0].nodes if chains[0].nodes else []), False
        # 无任何调用关系时，检查是否自身就是入口
        if f"{class_name}" in set(self.context.entry_point_list):
            return 0.7, [f"{class_name}#{method_name}"], True
        return 0.1, [], False
