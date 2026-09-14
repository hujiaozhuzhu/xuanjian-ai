# -*- coding: utf-8 -*-
"""ApkContext —— 静态分析上下文（androguard 封装）。

所有技法与核心引擎都不直接触碰 androguard API，而是通过 ApkContext
访问 APK 的静态信息：包名、入口组件、类 -> 方法 -> 字符串常量 / 调用目标。

- ``ApkContext.from_apk(path)``：真实 APK（androguard 分析，进程内缓存）。
- ``ApkContext.from_dict(data)`` / ``StaticApkContext``：纯数据上下文，
  供单元测试与降级路径使用（不依赖 androguard）。

androguard 缺失时 ``from_apk`` 抛出 :class:`AndroguardUnavailableError`，
上层捕获后可降级为纯字典/原始字符串扫描。
"""

from __future__ import annotations

import logging
import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# dex 常量池字符串上限（防御性截断，超大 APK 防止内存膨胀）
MAX_STRING_LEN = 4096


class AndroguardUnavailableError(ImportError):
    """androguard 未安装，无法做深度静态分析。"""


@dataclass
class MethodInfo:
    """方法级静态信息。"""

    class_name: str                                  # 完整类名
    name: str                                        # 方法名
    descriptor: str = ""                             # 参数签名，如 (Ljava/lang/String;)V
    strings: List[str] = field(default_factory=list) # 方法体内引用的字符串常量
    invokes: List[Tuple[str, str]] = field(default_factory=list)  # 调用目标 (类名, 方法名)

    @property
    def qualified(self) -> str:
        return f"{self.class_name}#{self.name}"


@dataclass
class ClassInfo:
    """类级静态信息。"""

    name: str
    methods: List[MethodInfo] = field(default_factory=list)
    superclass: str = ""
    interfaces: List[str] = field(default_factory=list)

    def method(self, name: str) -> Optional[MethodInfo]:
        for m in self.methods:
            if m.name == name:
                return m
        return None


class ApkContext:
    """APK 静态分析上下文基类。

    子类只需实现 ``_load()`` 填充 package_name / entry_points / classes。
    """

    def __init__(self) -> None:
        self.apk_path: str = ""
        self.package_name: str = ""
        self.entry_points: List[str] = set()  # type: ignore[assignment]
        self.classes: Dict[str, ClassInfo] = {}
        self._loaded = False

    # ────────────────────────── 工厂 ──────────────────────────

    @classmethod
    def from_apk(cls, apk_path: str, force_reload: bool = False) -> "ApkContext":
        """用 androguard 分析真实 APK（带进程内缓存）。"""
        return _AndroguardContext(apk_path, force_reload=force_reload)

    @classmethod
    def from_dict(cls, data: Dict) -> "StaticApkContext":
        """从纯 dict 构造（测试 / 外部反编译管线注入）。"""
        return StaticApkContext(data)

    # ────────────────────────── 加载 ──────────────────────────

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self._load()
            self._loaded = True

    def ensure_loaded(self) -> None:
        """公开版懒加载入口（推荐引擎在取包名前调用）。"""
        self._ensure_loaded()

    def _load(self) -> None:  # pragma: no cover - 子类实现
        raise NotImplementedError

    # ────────────────────────── 查询接口 ──────────────────────────

    @property
    def entry_point_list(self) -> List[str]:
        """入口组件（Activity/Service/Receiver/Provider）类名列表。"""
        self._ensure_loaded()
        return sorted(self.entry_points)

    def get_class(self, class_name: str) -> Optional[ClassInfo]:
        self._ensure_loaded()
        return self.classes.get(class_name)

    def all_class_names(self) -> List[str]:
        self._ensure_loaded()
        return sorted(self.classes.keys())

    def app_classes(self, package: Optional[str] = None) -> Dict[str, ClassInfo]:
        """属于目标包（或以 package 为前缀）的类。"""
        self._ensure_loaded()
        prefix = package or self.package_name
        if not prefix:
            return dict(self.classes)
        return {n: c for n, c in self.classes.items() if n.startswith(prefix)}

    def find_methods(self, pattern: str, regex: bool = False) -> List[MethodInfo]:
        """按名称模式查找方法（限应用自有类）。"""
        self._ensure_loaded()
        out: List[MethodInfo] = []
        compiled = re.compile(pattern) if regex else None
        for cls in self.app_classes().values():
            for m in cls.methods:
                if compiled is not None:
                    if compiled.search(m.name):
                        out.append(m)
                elif pattern.lower() in m.name.lower():
                    out.append(m)
        return out

    def methods_with_string(self, keyword: str, case_sensitive: bool = False) -> List[MethodInfo]:
        """方法体内引用了包含 keyword 的字符串常量的方法。"""
        self._ensure_loaded()
        out: List[MethodInfo] = []
        needle = keyword if case_sensitive else keyword.lower()
        for cls in self.app_classes().values():
            for m in cls.methods:
                for s in m.strings:
                    hay = s if case_sensitive else s.lower()
                    if needle in hay:
                        out.append(m)
                        break
        return out

    def methods_calling(self, target_class: str, target_method: str) -> List[MethodInfo]:
        """调用了 target_class.target_method 的应用方法（直接调用方，一层）。"""
        self._ensure_loaded()
        out: List[MethodInfo] = []
        for cls in self.app_classes().values():
            for m in cls.methods:
                for (c, n) in m.invokes:
                    if c == target_class and n == target_method:
                        out.append(m)
                        break
        return out

    def summary(self) -> Dict:
        """上下文摘要（日志 / CLI 展示用）。"""
        self._ensure_loaded()
        return {
            "apk_path": self.apk_path,
            "package_name": self.package_name,
            "classes": len(self.classes),
            "entry_points": len(self.entry_points),
            "methods": sum(len(c.methods) for c in self.classes.values()),
        }


class StaticApkContext(ApkContext):
    """纯数据上下文：不依赖 androguard，可直接由 dict 构造。

    dict 结构::

        {
          "package_name": "com.example.app",
          "apk_path": "...",
          "entry_points": ["com.example.app.MainActivity"],
          "classes": [
             {"name": "com.example.app.Crypto",
              "superclass": "java.lang.Object",
              "methods": [
                 {"name": "encrypt",
                  "descriptor": "(Ljava/lang/String;)Ljava/lang/String;",
                  "strings": ["AES/CBC/PKCS5Padding"],
                  "invokes": [["javax.crypto.Cipher", "doFinal"]]},
              ]},
          ]
        }
    """

    def __init__(self, data: Optional[Dict] = None) -> None:
        super().__init__()
        self._data: Dict = data or {}

    def _load(self) -> None:
        self.apk_path = self._data.get("apk_path", "")
        self.package_name = self._data.get("package_name", "")
        self.entry_points = set(self._data.get("entry_points", []))
        for cls_data in self._data.get("classes", []):
            name = cls_data.get("name", "")
            info = ClassInfo(
                name=name,
                superclass=cls_data.get("superclass", ""),
                interfaces=list(cls_data.get("interfaces", [])),
            )
            for m_data in cls_data.get("methods", []):
                info.methods.append(
                    MethodInfo(
                        class_name=name,
                        name=m_data.get("name", ""),
                        descriptor=m_data.get("descriptor", ""),
                        strings=list(m_data.get("strings", [])),
                        invokes=[tuple(i) for i in m_data.get("invokes", [])],
                    )
                )
            self.classes[name] = info


class _AndroguardContext(ApkContext):
    """androguard 驱动的真实上下文。"""

    _CACHE: Dict[str, "ApkContext"] = {}
    _CACHE_LOCK = threading.Lock()

    def __init__(self, apk_path: str, force_reload: bool = False) -> None:
        super().__init__()
        self.apk_path = str(Path(apk_path).resolve())
        key = f"{self.apk_path}:{os.path.getmtime(self.apk_path)}"
        with _AndroguardContext._CACHE_LOCK:
            cached = _AndroguardContext._CACHE.get(key)
        if cached is not None and not force_reload:
            # 复用缓存实例的数据
            self.package_name = cached.package_name
            self.entry_points = cached.entry_points
            self.classes = cached.classes
            self._loaded = True
            return
        self._load()
        self._loaded = True
        with _AndroguardContext._CACHE_LOCK:
            _AndroguardContext._CACHE[key] = self

    # ── androguard 兼容导入（4.x 为 androguard.core.dex，旧版为 dvm） ──
    @staticmethod
    def _import_androguard():
        try:
            from androguard.misc import AnalyzeAPK  # noqa: F401
            import androguard.core.dex as dex_mod  # noqa: F401

            return AnalyzeAPK, dex_mod
        except ImportError:
            try:  # 旧版本回退
                from androguard.misc import AnalyzeAPK  # noqa: F401
                import androguard.core.bytecodes.dvm as dex_mod  # noqa: F401

                return AnalyzeAPK, dex_mod
            except ImportError as exc:
                raise AndroguardUnavailableError(
                    "androguard 未安装，无法进行 APK 深度静态分析。"
                    "请执行: pip install androguard"
                ) from exc

    def _load(self) -> None:
        AnalyzeAPK, _dex_mod = self._import_androguard()
        logger.info("androguard 正在分析: %s", self.apk_path)
        a, d_list, dx = AnalyzeAPK(self.apk_path)

        self.package_name = a.get_package() or ""
        entries: set = set()
        for attr in (
            "get_activities",
            "get_services",
            "get_receivers",
            "get_providers",
        ):
            try:
                entries.update(a.__getattribute__(attr)())
            except Exception:  # pragma: no cover - 个别 APK 缺组件清单
                continue
        self.entry_points = entries

        for d in d_list:
            for cls in d.get_classes():
                name = cls.get_name()
                class_name = name[1:-1].replace("/", ".") if (
                    isinstance(name, str) and name.startswith("L") and name.endswith(";")
                ) else str(name)
                info = ClassInfo(
                    name=class_name,
                    superclass=self._clean_type(getattr(cls, "sName", "")),
                )
                for m in cls.get_methods():
                    mi = MethodInfo(
                        class_name=class_name,
                        name=m.get_name() or "",
                        descriptor=m.get_descriptor() or "",
                    )
                    try:
                        for insn in m.get_instructions():
                            self._collect_insn(insn, mi)
                    except Exception:  # pragma: no cover - 个别坏方法体
                        logger.debug("指令遍历失败: %s", mi.qualified, exc_info=True)
                    # 调用目标：优先用 dx 交叉引用（跨 dex / external 均可解析）
                    for target in self._xref_targets(dx, m):
                        mi.invokes.append(target)
                    info.methods.append(mi)
                self.classes[class_name] = info

        logger.info(
            "androguard 分析完成: package=%s classes=%d",
            self.package_name,
            len(self.classes),
        )

    @staticmethod
    def _clean_type(name: str) -> str:
        if isinstance(name, str) and name.startswith("L") and name.endswith(";"):
            return name[1:-1].replace("/", ".")
        return name or ""

    def _collect_insn(self, insn, mi: MethodInfo) -> None:
        """从指令中收集字符串常量（const-string / const-string/jumbo）。"""
        op = getattr(insn, "get_op_value", lambda: None)()
        if op in (0x1A, 0x1B):
            try:
                s = insn.get_string()
                if isinstance(s, str) and len(s) <= MAX_STRING_LEN:
                    mi.strings.append(s)
            except Exception:  # pragma: no cover
                pass

    @staticmethod
    def _xref_targets(dx, encoded_method):
        """用 dx 交叉引用解析方法调用目标，返回 [(类名, 方法名), ...]。

        androguard 4.x: MethodAnalysis.get_xref_to() 产出
        (ClassAnalysis, MethodAnalysis, offset)；旧版本接口差异时静默降级为空。
        """
        targets: List[Tuple[str, str]] = []
        if dx is None:
            return targets
        try:
            ma = dx.get_method(encoded_method) if hasattr(dx, "get_method") else None
            if ma is None or not hasattr(ma, "get_xref_to"):
                return targets
            for item in ma.get_xref_to():
                callee = item[1] if isinstance(item, tuple) else item
                name = getattr(callee, "name", None) or callee.get_name()
                cls_name = _AndroguardContext._clean_type(callee.get_class_name())
                if cls_name and name:
                    targets.append((cls_name, name))
        except Exception:  # pragma: no cover - 接口版本差异
            logger.debug("xref 解析失败: %s", encoded_method, exc_info=True)
        return targets
