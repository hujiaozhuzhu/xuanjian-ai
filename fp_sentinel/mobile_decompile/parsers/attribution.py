"""字符串/调用 归因索引（玄鉴 v4.0 Round 3 —— NEW-02 证据归因）。

对 APK 内全部 DEX 做一次指令级遍历（androguard EncodedMethod.get_code()），
建立三类索引，把"命中的字符串/API 名"映射回 ``类#方法``：

1. ``string_index``  : const-string 指令 —— 字符串常量 → 使用它的 (class, method) 列表;
2. ``called_index``  : invoke 指令 —— 被调 API 全名 ``pkg.Cls.method`` → 调用方 (class, method);
3. ``called_name_index``: 被调 API 裸方法名 → 调用方 (class, method)（供裸方法名证据定位）。

安全约束：只读解析，不修改任何原始文件；进程内缓存（同一 APK 只建一次）。

性能（NEW-02 验收）：InsecureBankv2 全量索引构建 ≈ 3~5s（远低于 30s 预算），
单次 locate 为 O(1) 字典查询（<<1ms）。
"""

from __future__ import annotations

import os
import re
import time
import zipfile
from typing import Dict, List, Optional, Tuple

__all__ = ["AttributionIndex", "get_attribution_index", "normalize_class_name"]

_DEX_NAME_RE = re.compile(r"^classes\d*\.dex$")
_METHOD_REF_RE = re.compile(r"^L([^;]+);->([^(]+)\(")

# 指令遍历护栏：超大 APK 的方法数/时间预算（超出即停止，索引部分可用）
_MAX_METHODS = 200_000
_TIME_BUDGET_SEC = 25.0


def normalize_class_name(name: str) -> str:
    """把 DEX 内部类名 ``Lcom/pkg/Cls$Inner;`` 归一为 ``com.pkg.Cls$Inner``。"""
    if not name:
        return ""
    n = name.strip()
    while n.startswith("["):
        n = n[1:]
    if n.startswith("L") and n.endswith(";"):
        n = n[1:-1]
    return n.replace("/", ".")


def _java_method_fqn(cls_internal: str, method_name: str) -> str:
    return f"{normalize_class_name(cls_internal)}.{method_name}"


class AttributionIndex:
    """string / invoke → (class, method) 归因索引。"""

    def __init__(self) -> None:
        # 值统一为 java 形态类名（点分）+ 方法名
        self.string_index: Dict[str, List[Tuple[str, str]]] = {}
        self.called_index: Dict[str, List[Tuple[str, str]]] = {}
        self.called_name_index: Dict[str, List[Tuple[str, str]]] = {}
        self.method_count = 0
        self.instruction_count = 0
        self.truncated = False
        self.build_sec = 0.0

    # ------------------------------------------------------------------ build
    @classmethod
    def from_apk(cls, apk_path: str) -> "AttributionIndex":
        """从 APK / 独立 DEX 构建归因索引；androguard 不可用时返回空索引。"""
        idx = cls()
        try:
            idx.build(apk_path)
        except ImportError:
            raise
        except Exception:  # 坏 APK / 解析失败 → 空索引（调用方降级为 unattributed）
            idx.string_index = {}
            idx.called_index = {}
            idx.called_name_index = {}
        return idx

    def build(self, apk_path: str) -> None:
        from .dex_parser import _require_androguard  # 延迟导入, 保持无依赖时可降级

        _require_androguard()
        from androguard.core.dex import DEX  # type: ignore

        started = time.perf_counter()
        dex_blobs: List[bytes] = []
        if zipfile.is_zipfile(apk_path):
            with zipfile.ZipFile(apk_path) as zf:
                names = sorted(
                    n for n in zf.namelist()
                    if _DEX_NAME_RE.match(os.path.basename(n))
                )
                for n in names:
                    dex_blobs.append(zf.read(n))
        elif str(apk_path).lower().endswith(".dex"):
            with open(apk_path, "rb") as fh:
                dex_blobs.append(fh.read())
        else:
            raise ValueError(f"不支持的归因目标: {apk_path}")

        for blob in dex_blobs:
            dex = DEX(blob)
            for cls_item in dex.get_classes():
                for method in cls_item.get_methods():
                    self._walk_method(method)
                    if self.method_count >= _MAX_METHODS or \
                            time.perf_counter() - started > _TIME_BUDGET_SEC:
                        self.truncated = True
                        self.build_sec = time.perf_counter() - started
                        return
        self.build_sec = time.perf_counter() - started

    def _walk_method(self, method: any) -> None:
        try:
            code = method.get_code()
        except Exception:
            code = None
        if code is None:
            return
        cls_name = normalize_class_name(method.get_class_name() or "")
        meth_name = method.get_name() or ""
        if not cls_name or not meth_name:
            return
        self.method_count += 1
        try:
            instructions = code.get_bc().get_instructions()
        except Exception:
            return
        for ins in instructions:
            try:
                self.instruction_count += 1
                op = ins.get_name() or ""
                if op.startswith("const-string"):
                    s = ins.get_string()
                    if s:
                        self.string_index.setdefault(s, []).append((cls_name, meth_name))
                elif op.startswith("invoke"):
                    for operand in ins.get_operands():
                        if not isinstance(operand, tuple) or len(operand) < 3:
                            continue
                        ref = operand[2]
                        if not isinstance(ref, str):
                            continue
                        m = _METHOD_REF_RE.match(ref)
                        if not m:
                            continue
                        caller = (cls_name, meth_name)
                        callee_cls = normalize_class_name(m.group(1))
                        callee_name = m.group(2)
                        fqn = f"{callee_cls}.{callee_name}"
                        self.called_index.setdefault(fqn, []).append(caller)
                        self.called_name_index.setdefault(callee_name, []).append(caller)
                        break
            except Exception:  # 单条指令解析失败不阻断整体
                continue

    # ----------------------------------------------------------------- query
    @staticmethod
    def _prefer(entries: List[Tuple[str, str]], package_name: str = "",
                limit: int = 5) -> List[Tuple[str, str]]:
        """业务包条目优先，去重截断。"""
        seen: set = set()
        biz: List[Tuple[str, str]] = []
        lib: List[Tuple[str, str]] = []
        for cls, meth in entries:
            key = (cls, meth)
            if key in seen:
                continue
            seen.add(key)
            if package_name and cls.startswith(package_name):
                biz.append(key)
            else:
                lib.append(key)
        out = biz + lib
        return out[:limit]

    def locations(
        self, value: str, package_name: str = "", limit: int = 5
    ) -> List[Tuple[str, str]]:
        """返回 value 的全部候选归因 (class, method)，业务包优先。"""
        if not value:
            return []
        v = value.strip()
        # 1) 精确字符串常量
        if v in self.string_index:
            return self._prefer(self.string_index[v], package_name, limit)
        # 2) class#method / pkg.Class.method 形态
        if "#" in v:
            cls, _, meth = v.partition("#")
            return [(cls, meth)]
        if v.count(".") >= 2 and not v.endswith("."):
            head, _, tail = v.rpartition(".")
            # 3) 被调 API 全名 → 调用方
            if v in self.called_index:
                return self._prefer(self.called_index[v], package_name, limit)
            # 4) 类名.方法名 —— 类是应用内声明则直接归因
            if head in self.called_index or tail in self.called_name_index:
                entries = self.called_name_index.get(tail) or self.called_index.get(head) or []
                filtered = [
                    (c, m) for (c, m) in entries
                    if m == tail or c == head
                ]
                if filtered:
                    return self._prefer(filtered, package_name, limit)
        # 5) 裸方法名（调用面归因）
        if re.fullmatch(r"[a-zA-Z_$][a-zA-Z0-9_$]*", v) and v in self.called_name_index:
            return self._prefer(self.called_name_index[v], package_name, limit)
        return []

    def locate(
        self, value: str, package_name: str = ""
    ) -> Optional[Tuple[str, str]]:
        """单值归因：返回最优先 (class, method)，失败返回 None。"""
        locs = self.locations(value, package_name, limit=1)
        return locs[0] if locs else None

    def locate_kv(
        self, evidence: str, package_name: str = ""
    ) -> Optional[Tuple[str, str]]:
        """key=value 形态证据的归因：优先整串，其次对值片段逐 token 定位。"""
        direct = self.locate(evidence, package_name)
        if direct:
            return direct
        # Round 3: 泛化 token（框架通用词）不参与回退定位 —— 避免把
        # "android.permission.X" 这类证据错误归因到无关的框架方法上。
        generic = {
            "android", "androidx", "support", "permission", "manifest",
            "package", "com", "java", "javax", "kotlin", "org", "http",
            "https", "content", "provider", "activity", "service",
            "receiver", "string", "strings", "string_pool", "exported",
        }
        for token in re.split(r"[^A-Za-z0-9_$]+", evidence):
            if len(token) >= 6 and token.lower() not in generic:
                hit = self.locate(token, package_name)
                if hit:
                    return hit
        return None


# ---------------------------------------------------------------- 进程内缓存
_CACHE: Dict[str, AttributionIndex] = {}
_CACHE_MAX = 8


def get_attribution_index(apk_path: str) -> AttributionIndex:
    """进程级缓存入口：同一 APK 只构建一次索引。"""
    key = os.path.abspath(apk_path)
    idx = _CACHE.get(key)
    if idx is None:
        idx = AttributionIndex.from_apk(apk_path)
        if len(_CACHE) >= _CACHE_MAX:
            _CACHE.pop(next(iter(_CACHE)))
        _CACHE[key] = idx
    return idx
