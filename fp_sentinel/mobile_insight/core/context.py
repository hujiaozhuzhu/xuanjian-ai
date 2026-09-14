"""分析上下文 —— 规则引擎的统一信号输入。

信号来源(填充方式):
1. 反编译结果(能力②): add_classes / add_methods / add_strings;
2. Manifest 解析: set_manifest_flags / add_exported_components / add_permissions;
3. APK 深度抽取(默认): from_apk —— 复用能力②的 DexParser/ManifestParser，
   取真实字符串池/类名/方法引用与 Manifest 精确导出组件;
4. 轻量 APK 抽取(androguard 不可用时的降级): 解压 classes*.dex 做二进制
   字符串粗提取。

Round 2 修复（RD-003 误报治理）:
- 框架类白名单: ``android.*`` / ``java.*`` / ``javax.*`` / ``androidx.*`` /
  ``com.google.*`` / ``org.apache.*`` 等框架/第三方库类名不作为业务信号，
  ``has_signal`` / ``find_evidence`` 对 classes 池自动过滤;
- XML/资源标记过滤: ``http://schemas.android.com``、``xmlns:``、``@+id/``
  等资源文件标记不参与规则匹配（消除 "XML 命名空间被判 HTTP 明文接口"
  类误报）;
- 证据排序: find_evidence 业务包证据优先于框架/库证据;
- 结构化导出组件: exported_by_kind 来自 Manifest 精确解析（二次确认）。

Round 3 修复（NEW-02/03/06 证据归因）:
- 类名归一化: DEX 内部形态 ``Lcom/pkg/Cls;`` 统一转为点分 java 形态，
  消除 "Landroid/support/... 被误判业务类 → CP-004 库类 HIGH 误报";
- 归因索引: from_apk 深度路径构建 string/invoke → ``类#方法`` 归因索引
  （进程内缓存），``locate_evidence`` 为规则命中回填代码级归因;
- 库/业务分层: ``classify_class`` 输出 business/library/framework/obfuscated;
- ``find_evidence_fragments``: 返回正则命中的字符串片段而非整段原文
  （NEW-08: AA-003 证据不再是原始正则文本）。
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Literal, Optional, Tuple

from fp_sentinel.mobile_decompile.parsers.attribution import (
    AttributionIndex,
    get_attribution_index,
    normalize_class_name,
)

__all__ = [
    "AnalysisContext",
    "is_framework_class",
    "is_resource_marker",
    "normalize_class_name",
    "classify_class",
]

# dex 内 ASCII 可见字符串(≥4 长度); 二进制粗提取足够覆盖规则关键词
_ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
# AXML 字符串池 UTF-16LE 片段提取(粗解析, 只做信号归集)
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){3,}")

# ---------------------------------------------------------------------------
# 框架/库类白名单（RD-003）: 这些前缀的类名不作为业务信号，避免
# "android.view.ActionProvider 被判 Content Provider 导出" 类误报。
# 注: 应用自身包（package_name 前缀）永远视为业务类 —— 例如
# com.android.insecurebankv2.* 以 "com.android." 开头但属于业务包。
# ---------------------------------------------------------------------------
FRAMEWORK_PREFIXES: tuple = (
    "android.",          # 含 android.support / android.view / android.os …
    "androidx.",
    "java.",
    "javax.",
    "kotlin.",
    "kotlinx.",
    "dalvik.",
    "com.google.",       # com.google.android.gms / com.google.protobuf …
    "org.apache.",
    "org.json.",
    "org.w3c.",
    "org.xmlpull.",
    "junit.",
    "com.facebook.",
    "com.squareup.",      # okhttp2/retrofit1/picasso 旧命名空间
    "com.fasterxml.",
    "io.reactivex.",
    # ------------------------------------------------------------------
    # v4.0 C1（终验报告 §3.3/§6.2）: 三方库前缀白名单补齐 —— 这些库内部
    # 代码不是应用自身漏洞面, classify_class 归入 library,
    # 归因落点据此降级（见 engine._to_insight）。
    # ------------------------------------------------------------------
    "okhttp3.",           # OkHttp3 终验 NW-004/NW-005 误报根除
    "okio.",              # OkHttp 底层 IO
    "retrofit2.",
    "gson.",              # 阴影/重定位后的 gson 命名空间
    "com.google.gson.",
    "org.jetbrains.",
    "com.bumptech.",      # Glide
    "org.chromium.",
    "com.tencent.bugly.", # 仅 Bugly; com.tencent.* 其余可能是业务包
    "com.umeng.",
    "rx.",                # RxJava 1
)

# XML/资源文件标记（RD-003）: 不参与网络/加密类规则匹配
_RESOURCE_MARKER_RE = re.compile(
    r"^\*?https?://(?:schemas\.\w+\.com|(?:www\.)?w3\.org)"   # AXML 命名空间
    r"|^(?:xmlns|tools):"                                      # XML 命名空间声明
    r"|^@[+\?]"                                                # @+id/ @style/ 资源引用
    r"|^@android:",
    re.IGNORECASE,
)


def is_framework_class(name: str, package_name: str = "") -> bool:
    """判断类名是否属于框架/第三方库（应用自身包前缀的类永远返回 False）。"""
    if not name:
        return False
    name = normalize_class_name(name)
    if package_name and name.startswith(package_name):
        return False
    return any(name.startswith(prefix) for prefix in FRAMEWORK_PREFIXES)


# ---------------------------------------------------------------------------
# NEW-06: 库/业务分层。classify_class 把类名归入四类:
#   business   —— 应用自身包（package_name 前缀）内的类;
#   framework  —— Android/JVM 框架命名空间;
#   library    —— 已知第三方库命名空间;
#   obfuscated —— Kotlin/R8 混淆形态（单字母类名/单字母包段）。
# ---------------------------------------------------------------------------
_FRAMEWORK_ONLY_PREFIXES: tuple = (
    "android.",
    "androidx.",   # v4.0 C1: 与 android.support.* 同级 —— androidx 垫片内部
                    # 实现不构成应用自身漏洞面（终验报告 R3.1b 覆盖缺口）
    "java.",
    "javax.",
    "kotlin.",
    "kotlinx.",
    "dalvik.",
)
_LIBRARY_PREFIXES: tuple = FRAMEWORK_PREFIXES


def classify_class(name: str, package_name: str = "") -> Literal[
    "business", "library", "framework", "obfuscated"
]:
    """类名来源分类（NEW-06）。未知形态默认视为业务类。"""
    n = normalize_class_name(name or "")
    if not n:
        return "business"
    if package_name and n.startswith(package_name):
        # 业务包内也可能是混淆类: 包名前缀匹配但类名/子包为单字母
        rest = n[len(package_name):].lstrip(".")
        segments = rest.split(".")
        if rest and all(len(s) <= 1 for s in segments):
            return "obfuscated"
        return "business"
    if n.startswith(_FRAMEWORK_ONLY_PREFIXES):
        return "framework"
    if n.startswith(_LIBRARY_PREFIXES):
        return "library"
    # 混淆形态: 单字母包段(如 a.b.c) 或单字母类名
    segments = n.split(".")
    if len(segments) >= 2 and all(len(s) <= 1 for s in segments[:-1]):
        return "obfuscated"
    if len(segments[-1]) <= 1 and len(segments) >= 2:
        return "obfuscated"
    return "business"


def is_resource_marker(text: str) -> bool:
    """判断字符串是否为 XML/资源文件标记（不作为业务证据）。"""
    return bool(_RESOURCE_MARKER_RE.search(text.strip()))


@dataclass
class AnalysisContext:
    """规则匹配上下文。"""

    package_name: str = ""
    platform: str = "android"
    strings: set = field(default_factory=set)
    classes: set = field(default_factory=set)
    methods: set = field(default_factory=set)
    permissions: set = field(default_factory=set)
    manifest_flags: Dict[str, Any] = field(default_factory=dict)
    exported_components: List[str] = field(default_factory=list)
    # RD-003: 来自 Manifest 精确解析的导出组件（kind -> [类名]），
    # 作为组件导出类规则的唯一事实源；轻量模式为空。
    exported_by_kind: Dict[str, List[str]] = field(default_factory=dict)
    # NEW-02: 代码归因索引（APK 深度模式构建; None = 未构建/不可归因）
    attribution_index: Optional[AttributionIndex] = None
    attribution_available: bool = False

    # ---- 填充接口 ----
    def add_strings(self, values: Iterable[str]) -> "AnalysisContext":
        self.strings.update(v for v in values if v)
        return self

    def add_classes(self, values: Iterable[str]) -> "AnalysisContext":
        self.classes.update(v for v in values if v)
        return self

    def add_methods(self, values: Iterable[str]) -> "AnalysisContext":
        self.methods.update(v for v in values if v)
        return self

    def add_permissions(self, values: Iterable[str]) -> "AnalysisContext":
        self.permissions.update(v for v in values if v)
        return self

    def add_exported_components(self, values: Iterable[str]) -> "AnalysisContext":
        self.exported_components.extend(v for v in values if v)
        return self

    def add_exported_component(self, kind: str, class_name: str) -> "AnalysisContext":
        """登记单个导出组件（结构化，RD-003 二次确认事实源）。"""
        if not kind or not class_name:
            return self
        self.exported_by_kind.setdefault(kind, [])
        if class_name not in self.exported_by_kind[kind]:
            self.exported_by_kind[kind].append(class_name)
        marker = f"{class_name} (exported=true)"
        if marker not in self.exported_components:
            self.exported_components.append(marker)
        return self

    def set_manifest_flags(self, flags: Dict[str, Any]) -> "AnalysisContext":
        self.manifest_flags.update(flags)
        return self

    # ------------------------------------------------- 白名单过滤（RD-003）
    def is_business_class(self, name: str) -> bool:
        """非框架/库类（应用自身包优先判定）。"""
        return not is_framework_class(name, self.package_name)

    def _pool_items(self, pool: set) -> Iterable[str]:
        """classes 池迭代时过滤框架类; strings 池过滤 XML/资源标记。"""
        for item in pool:
            if pool is self.classes and not self.is_business_class(item):
                continue
            if pool is self.strings and is_resource_marker(item):
                continue
            yield item

    # ------------------------------------------------- 代码归因（NEW-02）
    def build_attribution(self, apk_path: str) -> bool:
        """为上下文构建代码归因索引（进程内缓存，同一 APK 只建一次）。"""
        try:
            self.attribution_index = get_attribution_index(apk_path)
            self.attribution_available = self.attribution_index.method_count > 0
        except Exception:
            self.attribution_index = None
            self.attribution_available = False
        return self.attribution_available

    def locate_evidence(
        self, evidence: str
    ) -> Optional[Tuple[str, str]]:
        """把一条证据字符串归因为 (class, method); 失败返回 None。

        归因不可用（索引未构建/为空）时返回 None 但不视为"已尝试归因"，
        调用方应据 ``attribution_available`` 区分降级路径。
        """
        if not self.attribution_available or self.attribution_index is None:
            return None
        text = str(evidence).strip()
        # NEW-01: 去掉凭证分级前缀（"[LEVEL3] xxx" → "xxx"），保证整串优先归因
        text = re.sub(r"^\[LEVEL[0-9]\]\s*", "", text)
        # 去掉结构化后缀（如 " (exported=true)"）
        text = re.sub(r"\s*\([^)]*\)\s*$", "", text).strip()
        if not text:
            return None
        hit = self.attribution_index.locate_kv(text, self.package_name)
        if hit is None:
            return None
        cls, meth = hit
        if cls.startswith("L") and cls.endswith(";"):
            cls = normalize_class_name(cls)
        return cls, meth

    # --------------------------------------------------------- 信号查询
    def has_signal(self, pattern: str) -> bool:
        """regex 是否命中任一信号池(字符串/类/方法/权限/导出组件/manifest)。

        classes 池仅业务类参与; strings 池排除 XML/资源标记（RD-003）。
        """
        rx = re.compile(pattern, re.IGNORECASE)
        pools = (self.strings, self.classes, self.methods, self.permissions)
        for pool in pools:
            for item in self._pool_items(pool):
                if rx.search(item):
                    return True
        for comp in self.exported_components:
            if rx.search(comp):
                return True
        for key, value in self.manifest_flags.items():
            if rx.search(str(key)) or rx.search(str(value)):
                return True
        return False

    def find_evidence(self, pattern: str, limit: int = 5) -> List[str]:
        """返回命中样例(证据), 供提示展示。

        证据统一 trim; 业务包证据排前，框架/库证据排后（RD-003）。
        """
        rx = re.compile(pattern, re.IGNORECASE)
        evidence: List[tuple] = []
        pools = (self.classes, self.methods, self.strings, self.permissions)
        for pool in pools:
            for item in self._pool_items(pool):
                if rx.search(item):
                    business = (
                        pool is not self.classes or self.is_business_class(item)
                    )
                    evidence.append((0 if business else 1, item.strip()))
        # R3.1 确定性: 必须按 (优先级, 文本) 全序排序 —— 仅按优先级排序时
        # 同层内顺序跟随 set 迭代序（PYTHONHASHSEED），导致 evidence[0]
        # 以及其后的归因结果在多次运行间漂移。
        evidence.sort()
        return [text for _, text in evidence[:limit]]

    def find_evidence_fragments(
        self, pattern: str, limit: int = 5, width: int = 80
    ) -> List[str]:
        """返回正则在字符串池中命中的"片段"（NEW-08）。

        与 find_evidence 的差异: 证据是命中的具体子串（截断至 width），
        而非包含该子串的整段原文 —— 避免"数百字符的正则源码"作为证据。
        """
        rx = re.compile(pattern, re.IGNORECASE)
        out: List[str] = []
        seen: set = set()
        for item in self._pool_items(self.strings):
            m = rx.search(item)
            if not m:
                continue
            frag = m.group(0).strip()
            if not frag or frag in seen:
                continue
            seen.add(frag)
            out.append(frag[:width])
        # R3.1 确定性: 字符串池为 set，迭代序随 PYTHONHASHSEED 漂移;
        # 全量收集后排序再截断，保证片段顺序可复现。
        out.sort()
        return out[:limit]

    # ------------------------------------------------- 轻量 APK 信号抽取
    @classmethod
    def from_apk(cls, apk_path: str, max_strings: int = 60000) -> "AnalysisContext":
        """从 APK 抽取信号。

        默认走深度路径（复用能力②的 DexParser/ManifestParser: 真实字符串池、
        类名、方法引用与 Manifest 精确导出组件）; androguard 不可用或解析
        失败时降级为二进制粗提取（零依赖）。
        """
        ctx = cls()
        try:
            return cls._from_apk_deep(ctx, apk_path, max_strings)
        except Exception:
            # 深度路径不可用（androguard 缺失 / 损坏 APK 之外的临时错误）时降级
            return cls._from_apk_light(ctx, apk_path, max_strings)

    # -- 深度路径: 复用 mobile_decompile 的解析底座 --
    @staticmethod
    def _from_apk_deep(ctx: "AnalysisContext", apk_path: str, max_strings: int) -> "AnalysisContext":
        import os

        from fp_sentinel.mobile_decompile.parsers.dex_parser import DexParser
        from fp_sentinel.mobile_decompile.parsers.manifest_parser import ManifestParser

        ctx.package_name = ""
        try:
            info = ManifestParser(apk_path).parse()
            ctx.package_name = info.package_name or os.path.splitext(
                os.path.basename(apk_path))[0]
            ctx.add_permissions(info.permissions)
            kinds = {"activity": "has_activity", "service": "has_service",
                     "receiver": "has_receiver", "provider": "has_provider"}
            for comp in info.components:
                flag = kinds.get(comp.type)
                if flag:
                    ctx.manifest_flags[flag] = True
                if comp.exported and flag:
                    kind = comp.type
                    ctx.add_exported_component(kind, comp.name)
            # NEW-05: application 节点属性透出（debuggable/allowBackup/网络安全配置）
            ctx.manifest_flags["debuggable"] = bool(info.debuggable)
            if info.allow_backup is not None:
                ctx.manifest_flags["allow_backup"] = bool(info.allow_backup)
            if info.network_security_config:
                ctx.manifest_flags["network_security_config"] = \
                    info.network_security_config
        except Exception:
            ctx.package_name = os.path.splitext(os.path.basename(apk_path))[0]

        parser = DexParser(apk_path)
        if not ctx.package_name:
            ctx.package_name = os.path.splitext(os.path.basename(apk_path))[0]

        # 真实字符串池（去重、清洗）
        strings = [s.strip() for s in parser.strings() if s and s.strip()]
        ctx.add_strings(strings[:max_strings])

        # 应用内类（排除外部引用类; NEW-03: 归一为点分 java 形态，
        # 使 Landroid/support/... 等内部形态正确落入框架白名单）
        ctx.add_classes(
            normalize_class_name(c.name) for c in parser.classes()
        )

        # 方法引用（含外部 API 调用面）: 裸方法名 + `pkg.Class.method` 全名
        for cls_name, meth_name in parser.method_refs():
            ctx.methods.add(meth_name)
            ctx.methods.add(f"{normalize_class_name(cls_name)}.{meth_name}")

        # NEW-02: 代码归因索引（进程内缓存; 失败时保持不可归因降级路径）
        ctx.build_attribution(apk_path)
        return ctx

    # -- 降级路径: 二进制粗提取（原实现保留） --
    @staticmethod
    def _from_apk_light(ctx: "AnalysisContext", apk_path: str, max_strings: int) -> "AnalysisContext":
        import os

        ctx.package_name = os.path.splitext(os.path.basename(apk_path))[0]

        dex_strings: List[str] = []
        manifest_strings: List[str] = []
        with zipfile.ZipFile(apk_path) as zf:
            for name in zf.namelist():
                if name.startswith("classes") and name.endswith(".dex"):
                    data = zf.read(name)
                    dex_strings.extend(
                        m.group(0).decode("ascii", errors="ignore")
                        for m in _ASCII_RE.finditer(data)
                    )
                elif name == "AndroidManifest.xml":
                    data = zf.read(name)
                    manifest_strings.extend(
                        m.group(0).decode("utf-16-le", errors="ignore")
                        for m in _UTF16_RE.finditer(data)
                    )
                if len(dex_strings) > max_strings * 2:
                    break

        # 类名/方法名识别(从 dex 字符串中筛 Lxxx/yyy;zzz 形态)
        for s in dex_strings:
            if s.startswith("L") and ";" in s and "/" in s:
                cls_name = s[1:].split(";", 1)[0].replace("/", ".")
                if _looks_like_class(cls_name):
                    ctx.classes.add(cls_name)
            elif _looks_like_method(s):
                ctx.methods.add(s)

        ctx.strings.update(dex_strings[:max_strings])
        ctx.strings.update(manifest_strings)

        # manifest 信号
        joined = "\n".join(manifest_strings)
        for perm in _PERM_RE.findall(joined):
            ctx.permissions.add(perm.strip())
        for comp_kind in ("activity", "service", "receiver", "provider"):
            if comp_kind in joined.lower():
                ctx.manifest_flags[f"has_{comp_kind}"] = True
        return ctx


_PERM_RE = re.compile(r"android\.permission\.[A-Z_]+")
_CLASS_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-zA-Z0-9_$]+)+$")
_METHOD_RE = re.compile(r"^[a-zA-Z_$][a-zA-Z0-9_$]{2,60}$")


def _looks_like_class(name: str) -> bool:
    return bool(_CLASS_NAME_RE.match(name))


def _looks_like_method(name: str) -> bool:
    if not _METHOD_RE.match(name):
        return False
    # 过滤明显非方法名的字符串(大写常量/URL 片段)
    if name.isupper() or name.startswith("http"):
        return False
    return True
