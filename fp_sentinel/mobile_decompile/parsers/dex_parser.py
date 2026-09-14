"""DEX 文件解析器（基于 androguard，纯 Python）。

玄鉴 v4.0 能力② 反编译引擎的解析底座：
- 从 APK（zip 容器）或独立 .dex 文件加载 Dalvik 字节码；
- 提供类/方法/字段/字符串表的结构化视图；
- 惰性构建交叉引用（xref）与调用图 —— 只有真正需要时才付出
  create_xref 的开销（大 APK 上可达数十秒）。

安全约束：只读解析，不修改任何原始文件；DEX 字节在内存中处理。
"""

from __future__ import annotations

import os
import re
import zipfile
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

from ..models.class_info import (
    ClassHierarchy,
    ClassInfo,
    FieldInfo,
    MethodInfo,
)
from ..models.decompile_result import CallGraph

try:  # androguard 为 P0 依赖；缺失时给出可操作的提示而非裸 traceback
    from androguard.core.analysis.analysis import Analysis  # type: ignore
    from androguard.core.dex import DEX  # type: ignore

    HAS_ANDROGUARD = True
except Exception:  # pragma: no cover - 仅在未安装 androguard 的环境触发
    Analysis = None  # type: ignore[assignment]
    DEX = None  # type: ignore[assignment]
    HAS_ANDROGUARD = False

_DEX_NAME_RE = re.compile(r"^classes\d*\.dex$")

_IMPORT_HINT = (
    "androguard 未安装。请执行: pip install androguard "
    "(玄鉴 v4.0 反编译引擎的 P0 依赖)"
)


def _require_androguard() -> None:
    if not HAS_ANDROGUARD:
        raise ImportError(_IMPORT_HINT)


def make_method_signature(class_name: str, method_name: str, descriptor: str) -> str:
    """拼装完整方法签名 ``Lcls;->name(desc)ret``。

    对 androguard 不同版本的 descriptor 语义（proto-only 或全签名）做防御性兼容。
    """
    desc = descriptor or ""
    if "->" in desc:
        return desc
    return f"{class_name or ''}->{method_name or ''}{desc}"


class DexParser:
    """DEX/APK 解析器。

    用法::

        parser = DexParser("app.apk")           # 仅解析（快）
        parser.ensure_xref()                    # 需要交叉引用时再构建（慢）
        classes = parser.classes()
        strings = parser.strings()
    """

    def __init__(self, target_path: str, load: bool = True) -> None:
        self.target_path = str(target_path)
        self._dexes: List[Any] = []
        self._analysis: Optional[Any] = None
        self._xref_ready = False
        self._strings_cache: Optional[List[str]] = None
        if load:
            self.load()

    # ------------------------------------------------------------------ load

    def load(self) -> None:
        """加载目标文件中的全部 DEX（APK 容器或独立 .dex）。"""
        _require_androguard()
        if not os.path.exists(self.target_path):
            raise FileNotFoundError(f"目标文件不存在: {self.target_path}")

        dex_blobs: List[Tuple[str, bytes]]
        if zipfile.is_zipfile(self.target_path):
            with zipfile.ZipFile(self.target_path) as zf:
                names = sorted(
                    n for n in zf.namelist() if _DEX_NAME_RE.match(os.path.basename(n))
                )
                if not names:
                    raise ValueError(f"APK 中未找到 classes*.dex: {self.target_path}")
                dex_blobs = [(n, zf.read(n)) for n in names]
        elif self.target_path.lower().endswith(".dex"):
            with open(self.target_path, "rb") as fh:
                dex_blobs = [(os.path.basename(self.target_path), fh.read())]
        else:
            raise ValueError(
                f"不支持的文件类型: {self.target_path} (仅支持 APK/DEX)"
            )

        self._analysis = Analysis()
        for name, blob in dex_blobs:
            dex = DEX(blob)
            self._analysis.add(dex)
            self._dexes.append(dex)

    # ------------------------------------------------------------ properties

    @property
    def dex_count(self) -> int:
        return len(self._dexes)

    @property
    def class_count(self) -> int:
        if self._analysis is not None:
            return sum(1 for ca in self._analysis.get_classes() if not ca.is_external())
        return sum(len(list(d.get_classes())) for d in self._dexes)

    @property
    def method_count(self) -> int:
        return sum(len(list(d.get_methods())) for d in self._dexes)

    def ensure_xref(self) -> Any:
        """惰性构建方法交叉引用（首次调用耗时较长，之后复用）。"""
        if self._analysis is None:
            self.load()
        assert self._analysis is not None
        if not self._xref_ready:
            self._analysis.create_xref()
            self._xref_ready = True
        return self._analysis

    # --------------------------------------------------------------- strings

    def strings(self) -> List[str]:
        """去重后的字符串常量表（保持首次出现顺序）。"""
        if self._strings_cache is not None:
            return self._strings_cache
        seen: set = set()
        out: List[str] = []
        for dex in self._dexes:
            for s in dex.get_strings():
                if s not in seen:
                    seen.add(s)
                    out.append(s)
        self._strings_cache = out
        return out

    def method_refs(self, limit: int = 200000) -> List[Tuple[str, str]]:
        """全部方法引用（含外部 API），返回 (java类名, 方法名) 列表。

        DEX 方法引用只在代码 invoke 时生成，因此该列表近似"调用面"。
        供 insight 等下游引擎做 API 级证据匹配（RD-005）。
        """
        out: List[Tuple[str, str]] = []
        for dex in self._dexes:
            try:
                items = list(dex.get_methods())
            except Exception:  # pragma: no cover - 个别坏 dex
                continue
            for item in items:
                try:
                    cls = item.get_class_name() or ""
                    name = item.get_name() or ""
                except Exception:  # pragma: no cover
                    continue
                if cls.startswith("L") and cls.endswith(";"):
                    cls = cls[1:-1].replace("/", ".")
                if cls and name:
                    out.append((cls, name))
                    if len(out) >= limit:
                        return out
        return out

    def search_strings(
        self, pattern: str, regex: bool = False, limit: int = 100
    ) -> List[str]:
        """在字符串常量表中搜索。"""
        results: List[str] = []
        if regex:
            compiled = re.compile(pattern)
            for s in self.strings():
                if compiled.search(s):
                    results.append(s)
                    if len(results) >= limit:
                        break
        else:
            kw = pattern.lower()
            for s in self.strings():
                if kw in s.lower():
                    results.append(s)
                    if len(results) >= limit:
                        break
        return results

    # --------------------------------------------------------------- classes

    def classes(self, app_package: Optional[str] = None) -> List[ClassInfo]:
        """全部应用内类（排除外部引用类）。无需 xref，解析完即可调用。"""
        if self._analysis is None:
            self.load()
        assert self._analysis is not None
        out: List[ClassInfo] = []
        for ca in self._analysis.get_classes():
            if ca.is_external():
                continue
            out.append(self._class_info_from_analysis(ca, app_package))
        return out

    def get_class(self, class_name: str) -> Optional[ClassInfo]:
        """按类名查询（支持 ``Lcom/pkg/Cls;`` 与 ``com.pkg.Cls`` 两种形式）。"""
        internal = class_name if class_name.startswith("L") else _java_to_internal(class_name)
        if self._analysis is None:
            self.load()
        assert self._analysis is not None
        ca = self._analysis.get_class_analysis(internal)
        if ca is None or ca.is_external():
            return None
        return self._class_info_from_analysis(ca)

    def _class_info_from_analysis(
        self, ca: Any, app_package: Optional[str] = None
    ) -> ClassInfo:
        vm = ca.get_vm_class()
        methods: List[MethodInfo] = []
        for ma in ca.get_methods():
            em = ma.get_method()
            if em is None:
                continue
            methods.append(
                MethodInfo(
                    name=em.get_name() or "",
                    descriptor=em.get_descriptor() or "",
                    access_flags=str(em.get_access_flags_string() or ""),
                    class_name=ca.name,
                )
            )
        fields: List[FieldInfo] = []
        if vm is not None:
            for f in vm.get_fields():
                fields.append(
                    FieldInfo(
                        name=f.get_name() or "",
                        type_desc=f.get_descriptor() or "",
                        access_flags=str(f.get_access_flags_string() or ""),
                    )
                )
        interfaces = list(vm.get_interfaces()) if vm is not None else []
        info = ClassInfo(
            name=ca.name,
            super_name=ca.extends or "",
            interfaces=interfaces,
            methods=methods,
            fields=fields,
        )
        return info

    # ------------------------------------------------------------- hierarchy

    def class_hierarchy(self) -> ClassHierarchy:
        """构建继承树。"""
        hierarchy = ClassHierarchy()
        for info in self.classes():
            parent = info.super_name or None
            hierarchy.add_class(info.name, parent)
        return hierarchy

    # ------------------------------------------------------------ call graph

    def call_graph(self) -> CallGraph:
        """构建方法级调用图（需要 xref）。"""
        graph = CallGraph()
        self.ensure_xref()
        assert self._analysis is not None
        for ma in self._analysis.get_methods():
            if ma.is_external():
                continue
            em = ma.get_method()
            if em is None:
                continue
            caller_sig = make_method_signature(
                em.get_class_name() or "", em.get_name() or "", em.get_descriptor() or ""
            )
            for _, callee_ma, _off in ma.get_xref_to():
                callee_em = callee_ma.get_method()
                if callee_em is None:
                    continue
                callee_sig = make_method_signature(
                    callee_em.get_class_name() or "",
                    callee_em.get_name() or "",
                    callee_em.get_descriptor() or "",
                )
                graph.add_edge(caller_sig, callee_sig)
        return graph

    # ------------------------------------------------------------- xref API

    def method_xrefs(self, method_signature: str) -> Tuple[List[str], List[str]]:
        """返回 (callers, callees)。method_signature 形如 ``Lcls;->name(desc)ret``。"""
        self.ensure_xref()
        assert self._analysis is not None
        ma = self._find_method_analysis(method_signature)
        if ma is None:
            return [], []
        callers = [
            sig
            for sig in (self._xref_entry_signature(e) for e in ma.get_xref_from())
            if sig
        ]
        callees = [
            sig
            for sig in (self._xref_entry_signature(e) for e in ma.get_xref_to())
            if sig
        ]
        return _dedupe(callers), _dedupe(callees)

    def find_methods(self, keyword: str, limit: int = 50) -> List[Tuple[str, int]]:
        """按关键字匹配方法签名，返回 (signature, 调用者数量)。需要 xref。"""
        self.ensure_xref()
        kw = keyword.lower()
        out: List[Tuple[str, int]] = []
        assert self._analysis is not None
        for ma in self._analysis.get_methods():
            if ma.is_external():
                continue
            em = ma.get_method()
            if em is None:
                continue
            cls = (em.get_class_name() or "").lower()
            name = (em.get_name() or "").lower()
            if kw in cls or kw in name:
                caller_count = sum(1 for _ in ma.get_xref_from())
                out.append(
                    (
                        make_method_signature(
                            em.get_class_name() or "",
                            em.get_name() or "",
                            em.get_descriptor() or "",
                        ),
                        caller_count,
                    )
                )
                if len(out) >= limit:
                    break
        return out

    def _find_method_analysis(self, method_signature: str) -> Optional[Any]:
        assert self._analysis is not None
        try:
            class_part, rest = method_signature.split("->", 1)
        except ValueError:
            return None
        name_part = rest.split("(", 1)[0]
        ca = self._analysis.get_class_analysis(class_part)
        if ca is None:
            return None
        for ma in ca.get_methods():
            em = ma.get_method()
            if em is not None and em.get_name() == name_part:
                sig = make_method_signature(
                    em.get_class_name() or "", em.get_name() or "", em.get_descriptor() or ""
                )
                if sig == method_signature:
                    return ma
        # 兜底：签名形式差异时按名字匹配第一个同名方法
        for ma in ca.get_methods():
            em = ma.get_method()
            if em is not None and em.get_name() == name_part:
                return ma
        return None

    @staticmethod
    def _xref_entry_signature(entry: Any) -> Optional[str]:
        """把 xref 条目（ClassAnalysis, MethodAnalysis[, offset] 元组）归一为签名。"""
        meth_analysis = None
        if isinstance(entry, tuple):
            for part in entry:
                if hasattr(part, "get_method"):
                    meth_analysis = part
                    break
        elif hasattr(entry, "get_method"):
            meth_analysis = entry
        if meth_analysis is None:
            return None
        em = meth_analysis.get_method()
        if em is None:
            return None
        return make_method_signature(
            em.get_class_name() or "", em.get_name() or "", em.get_descriptor() or ""
        )


def _java_to_internal(java_name: str) -> str:
    return "L" + java_name.replace(".", "/") + ";"


def _dedupe(items: List[str]) -> List[str]:
    seen: set = set()
    out: List[str] = []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


@lru_cache(maxsize=4)
def get_dex_parser(target_path: str) -> DexParser:
    """进程级缓存：同一 APK 只解析一次（CLI 多个子命令间复用）。"""
    return DexParser(target_path)
