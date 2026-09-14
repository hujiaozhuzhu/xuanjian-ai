"""Android Java 层反编译引擎（jadx 优先，androguard 兜底）。

策略：
1. 若系统安装了 jadx，调用其命令行产出高质量 Java 源码；
2. jadx 不可用或执行失败时，优雅降级到 androguard 纯 Python 解析，
   产出结构化代码大纲（outline：类头/字段/方法签名/访问标志），
   并支持字符串表/调用/交叉引用等全部搜索能力。

安全约束（红线 M3）：全程只读，不修改原始 APK；jadx 输出只写入
DecompileConfig.output_dir 指定的独立目录。
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple

from ..models.class_info import ClassHierarchy, ClassInfo
from ..models.decompile_result import (
    CallGraph,
    DecompileConfig,
    DecompileResult,
    ManifestInfo,
    SourceFile,
    StringEntry,
)
from ..models.search_result import (
    MatchType,
    SearchOptions,
    SearchResult,
    compute_critical_score,
)
from ..parsers.dex_parser import DexParser, get_dex_parser
from ..parsers.manifest_parser import ManifestParser
from .base import PLATFORM_ANDROID, Decompiler


def render_class_outline(info: ClassInfo) -> str:
    """把 ClassInfo 渲染为结构化代码大纲（androguard 兑底产物）。"""
    lines = [
        "// 玄鉴 v4.0 androguard 反编译大纲 (outline)",
        f"// 原始类名: {info.name}",
        f"package {info.package};",
        "",
    ]
    header = f"class {info.java_name.rsplit('.', 1)[-1]}"
    if info.super_name:
        header += f" extends {info.super_name.lstrip('L').rstrip(';').replace('/', '.')}"
    if info.interfaces:
        itfs = ", ".join(
            i.lstrip("L").rstrip(";").replace("/", ".") for i in info.interfaces
        )
        header += f" implements {itfs}"
    lines.append(header + " {")
    for f in info.fields:
        flags = f"{f.access_flags} " if f.access_flags else ""
        lines.append(f"    {flags}{f.type_desc} {f.name};")
    if info.fields and info.methods:
        lines.append("")
    for m in info.methods:
        flags = f"{m.access_flags} " if m.access_flags else ""
        lines.append(f"    {flags}{m.name}{m.descriptor};  // {m.full_signature}")
    lines.append("}")
    return "\n".join(lines) + "\n"


def split_signature(signature: str) -> Tuple[str, str, str]:
    """把 ``Lcom/pkg/Cls;->name(desc)ret`` 拆为 (class, method, descriptor)。"""
    if "->" not in signature:
        return "", signature, ""
    class_part, rest = signature.split("->", 1)
    method = rest.split("(", 1)[0]
    desc_idx = rest.find("(")
    descriptor = rest[desc_idx:] if desc_idx >= 0 else ""
    return class_part, method, descriptor


def _display_class(internal_name: str) -> str:
    """``Lcom/pkg/Cls;`` -> ``com.pkg.Cls``（非内部形式原样返回）。"""
    if internal_name.startswith("L") and internal_name.endswith(";"):
        return internal_name[1:-1].replace("/", ".")
    return internal_name


class AndroidJavaDecompiler(Decompiler):
    """Android Java/Smali 层反编译器。"""

    name = "android-java"
    platform = PLATFORM_ANDROID

    def __init__(
        self,
        target_path: Optional[str] = None,
        dex_parser: Optional[DexParser] = None,
        config: Optional[DecompileConfig] = None,
    ) -> None:
        self.target_path = target_path
        self.config = config or DecompileConfig()
        self._parser: Optional[DexParser] = dex_parser
        self._source_files: Dict[str, SourceFile] = {}  # relative_path -> SourceFile
        self._manifest_info: Optional[ManifestInfo] = None

    # ------------------------------------------------------------- jadx 工具

    # 常见安装路径（RD-006: 自动查找 jadx）
    _JADX_COMMON_PATHS = (
        r"C:\jadx\bin\jadx.bat",
        r"C:\jadx\bin\jadx.gradle.bat",
        r"C:\Program Files\jadx\bin\jadx.bat",
        r"C:\Program Files (x86)\jadx\bin\jadx.bat",
        "/usr/local/bin/jadx",
        "/usr/bin/jadx",
        "/opt/jadx/bin/jadx",
        "/snap/bin/jadx",
    )

    @classmethod
    def find_jadx(cls) -> Optional[str]:
        """探测 jadx 可执行文件；不可用返回 None（触发优雅降级）。

        RD-006: 除 PATH 外，还扫描常见安装路径（Windows/Linux/macOS）。
        """
        for exe in ("jadx", "jadx.bat", "jadx.exe", "jadx.cmd"):
            path = shutil.which(exe)
            if path:
                return path
        home = os.path.expanduser("~")
        extra = (
            os.path.join(home, "jadx", "bin", "jadx"),
            os.path.join(home, "jadx", "bin", "jadx.bat"),
            os.path.join(home, "opt", "jadx", "bin", "jadx"),
        ) + cls._JADX_COMMON_PATHS
        for path in extra:
            if os.path.isfile(path):
                return path
        return None

    @staticmethod
    def try_install_jadx() -> Optional[str]:  # pragma: no cover - 依赖外部包管理器
        """尽力自动安装 jadx（RD-006, best-effort, 失败静默返回 None）。"""
        import platform as _platform

        system = _platform.system()
        candidates = {
            "Windows": (
                ["scoop", "install", "jadx"],
                ["choco", "install", "jadx", "-y"],
                ["winget", "install", "--id", "skylot.jadx", "--accept-source-agreements",
                 "--accept-package-agreements", "--silent"],
            ),
            "Darwin": (["brew", "install", "jadx"],),
            "Linux": (
                ["sudo", "-n", "apt-get", "install", "-y", "jadx"],
                ["snap", "install", "jadx"],
            ),
        }.get(system, ())
        for cmd in candidates:
            try:
                subprocess.run(
                    cmd, capture_output=True, text=True, timeout=600, check=False)
            except (subprocess.TimeoutExpired, OSError):
                continue
            found = AndroidJavaDecompiler.find_jadx()
            if found:
                return found
        return None

    @staticmethod
    def supports(target_path: str) -> bool:
        """支持 APK（zip 容器）与独立 DEX 文件。"""
        if not os.path.exists(target_path):
            return False
        lower = target_path.lower()
        if lower.endswith((".apk", ".dex", ".zip")):
            return True
        try:
            import zipfile

            return zipfile.is_zipfile(target_path)
        except OSError:
            return False

    def _get_parser(self, target: Optional[str] = None) -> DexParser:
        if self._parser is None:
            self._parser = get_dex_parser(target or self.target_path or "")
        return self._parser

    @property
    def parser(self) -> DexParser:
        return self._get_parser()

    # ------------------------------------------------------------ 反编译主流程

    async def decompile(
        self, target: str, config: Optional[DecompileConfig] = None
    ) -> DecompileResult:
        cfg = config or self.config
        self.config = cfg
        self.target_path = str(target)
        self._used_jadx = False
        result = self.new_result(target)
        t0 = self.now()

        if not os.path.exists(self.target_path):
            result.add_error(f"目标文件不存在: {self.target_path}")
            result.duration_sec = self.now() - t0
            return result
        if not self.supports(self.target_path):
            result.add_error(f"不支持的输入格式: {self.target_path}")
            result.duration_sec = self.now() - t0
            return result

        engine = cfg.engine
        jadx_attempted = engine in ("auto", "jadx")
        decompiled = False
        jadx_path = self.find_jadx() if jadx_attempted else None
        if jadx_attempted and jadx_path is None:
            # RD-006: 未找到 jadx 时先尝试常见路径自动安装（best-effort）
            jadx_path = await asyncio.to_thread(self.try_install_jadx)
            if jadx_path is None:
                result.add_warning("jadx 未安装且自动安装未成功，将使用 androguard 降级解析")
        if jadx_attempted and jadx_path is not None:
            decompiled = await asyncio.to_thread(
                self._decompile_with_jadx, cfg, result
            )
            if not decompiled:
                result.add_warning("jadx 执行失败，降级到 androguard 解析")
        elif engine == "jadx" and jadx_path is None:
            result.add_warning("jadx 不可用，降级到 androguard 解析")

        if not decompiled:
            try:
                await asyncio.to_thread(self._decompile_with_androguard, cfg, result)
                decompiled = True
                if jadx_attempted:
                    result.add_warning(
                        "jadx 未安装，当前为方法签名大纲（outline），不可用于代码审计；"
                        "仅供结构/字符串/交叉引用分析"
                    )
            except Exception as exc:  # androguard 解析失败
                result.add_error(f"androguard 解析失败: {exc}")

        if cfg.include_manifest:
            self._try_parse_manifest(result)

        result.success = decompiled and len(result.source_files) > 0
        result.class_count = self.parser.class_count
        result.method_count = self.parser.method_count
        result.engine_used = "jadx" if self._used_jadx else "androguard"
        result.quality_score = self._quality_score(cfg)
        result.duration_sec = self.now() - t0
        if cfg.include_strings:
            result.string_table = self.string_table(cfg.max_strings)
        return result

    def _decompile_with_jadx(self, cfg: DecompileConfig, result: DecompileResult) -> bool:
        """调用 jadx 命令行；成功时填充 result.source_files。"""
        jadx = self.find_jadx()
        assert jadx is not None
        out_dir = cfg.output_dir or os.path.join(
            os.path.dirname(self.target_path or ".") or ".", "_jadx_out"
        )
        os.makedirs(out_dir, exist_ok=True)
        try:
            proc = subprocess.run(
                [jadx, "-d", out_dir, self.target_path or ""],
                capture_output=True,
                text=True,
                timeout=cfg.timeout_sec,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            result.add_warning(f"jadx 调用异常: {exc}")
            return False
        if proc.returncode != 0:
            result.add_warning(
                f"jadx 返回码 {proc.returncode}: {(proc.stderr or proc.stdout)[:200]}"
            )
            return False
        count = self._load_source_dir(out_dir, result, language="java", cfg=cfg)
        self._used_jadx = True
        if count == 0:
            result.add_warning("jadx 执行成功但未产出源码文件")
            self._used_jadx = False
            return False
        return True

    def _decompile_with_androguard(self, cfg: DecompileConfig, result: DecompileResult) -> None:
        """androguard 兜底：为每个应用内类生成结构化代码大纲。"""
        parser = self._get_parser(self.target_path)
        out_dir = cfg.output_dir
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        count = 0
        for info in parser.classes():
            if count >= cfg.max_source_files:
                result.add_warning(f"源码文件数超过上限 {cfg.max_source_files}，已截断")
                break
            rel = f"outline/{info.name.lstrip('L').rstrip(';')}.java"
            content = render_class_outline(info)
            result.source_files.append(
                SourceFile(
                    path=os.path.join(out_dir, rel) if out_dir else rel,
                    relative_path=rel,
                    content=content,
                    language="outline",
                )
            )
            if out_dir:
                self._write_file(os.path.join(out_dir, rel), content)
            count += 1
        self._source_files = {sf.relative_path: sf for sf in result.source_files}

    @staticmethod
    def _write_file(path: str, content: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)

    def _load_source_dir(
        self, out_dir: str, result: DecompileResult, language: str, cfg: DecompileConfig
    ) -> int:
        """从 jadx 输出目录收集源码文件。"""
        count = 0
        for root, _dirs, files in os.walk(out_dir):
            for fname in sorted(files):
                if not fname.endswith((".java", ".smali")):
                    continue
                full = os.path.join(root, fname)
                rel = os.path.relpath(full, out_dir).replace("\\", "/")
                try:
                    with open(full, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except OSError as exc:
                    result.add_warning(f"读取源码失败 {rel}: {exc}")
                    continue
                result.source_files.append(
                    SourceFile(
                        path=full,
                        relative_path=rel,
                        content=content,
                        language=language if fname.endswith(".java") else "smali",
                    )
                )
                self._source_files[rel] = result.source_files[-1]
                count += 1
                if count >= cfg.max_source_files:
                    result.add_warning(f"源码文件数超过上限 {cfg.max_source_files}，已截断")
                    break
            if count >= cfg.max_source_files:
                break
        return count

    def _try_parse_manifest(self, result: DecompileResult) -> None:
        try:
            self._manifest_info = ManifestParser(self.target_path or "").parse()
            result.manifest_info = self._manifest_info
        except (ImportError, FileNotFoundError, ValueError) as exc:
            result.add_warning(f"Manifest 解析跳过: {exc}")

    def _quality_score(self, cfg: DecompileConfig) -> float:
        if not self._source_files:
            return 0.0
        if self._used_jadx:
            return 0.9
        return 0.3  # RD-006: androguard 大纲仅为方法签名，明确标注低质量

    # ------------------------------------------------------------- 查询能力

    def string_table(self, limit: int = 20000) -> List[StringEntry]:
        return [
            StringEntry(value=s, source_file=self.target_path)
            for s in self.parser.strings()[:limit]
        ]

    def get_manifest(self) -> Optional[ManifestInfo]:
        if self._manifest_info is None:
            self._try_parse_manifest(DecompileResult(success=False))
        return self._manifest_info

    def source_texts(self) -> Dict[str, str]:
        """相对路径 -> 源码文本（未反编译时为空）。"""
        return {rel: sf.content for rel, sf in self._source_files.items()}

    # ------------------------------------------------- search_keyword 实现

    def search_keyword(
        self,
        keyword: str,
        match_types: Optional[List[MatchType]] = None,
        scope: Optional[str] = None,
        limit: int = 200,
        case_sensitive: bool = False,
    ) -> List[SearchResult]:
        """关键字搜索：TEXT（源码文本）/ STRING（常量）/ CALL（调用）/ XREF（交叉引用）。"""
        options = self.options(match_types, scope, limit)
        options.case_sensitive = case_sensitive
        results: List[SearchResult] = []
        if options.allows(MatchType.TEXT):
            results.extend(self._search_text(keyword, options))
        if options.allows(MatchType.STRING):
            results.extend(self._search_strings(keyword, options))
        if options.allows(MatchType.CALL):
            results.extend(self._search_call_or_xref(keyword, options, MatchType.CALL))
        if options.allows(MatchType.XREF):
            results.extend(self._search_call_or_xref(keyword, options, MatchType.XREF))
        return results[: options.limit]

    def _search_text(self, keyword: str, options: SearchOptions) -> List[SearchResult]:
        """在已加载的源码文本中逐行匹配。"""
        out: List[SearchResult] = []
        kw = keyword if options.case_sensitive else keyword.lower()
        for rel, sf in self._source_files.items():
            lines = sf.content.splitlines()
            for idx, line in enumerate(lines):
                hay = line if options.case_sensitive else line.lower()
                if kw not in hay:
                    continue
                cls, meth = self._class_method_from_path(rel)
                snippet = line.strip()
                out.append(
                    SearchResult(
                        keyword=keyword,
                        file_path=sf.path,
                        class_name=cls,
                        method_name=meth,
                        line_number=idx + 1,
                        code_snippet=snippet,
                        context_before="\n".join(
                            lines[max(0, idx - options.context_lines): idx]
                        ),
                        context_after="\n".join(
                            lines[idx + 1: idx + 1 + options.context_lines]
                        ),
                        match_type=MatchType.TEXT,
                        relevance_score=self._text_relevance(kw, hay),
                        critical_score=compute_critical_score(
                            keyword, cls, meth, snippet
                        ),
                    )
                )
                if len(out) >= options.limit:
                    return out
        return out

    @staticmethod
    def _text_relevance(kw: str, line_lower: str) -> float:
        if kw in line_lower.replace(" ", ""):
            return 0.8
        return 0.5

    @staticmethod
    def _class_method_from_path(rel_path: str) -> Tuple[str, str]:
        base = rel_path.rsplit("/", 1)[-1]
        cls = base.rsplit(".", 1)[0]
        return cls, ""

    def _search_strings(self, keyword: str, options: SearchOptions) -> List[SearchResult]:
        """字符串常量表匹配。"""
        out: List[SearchResult] = []
        for value in self.parser.search_strings(
            keyword, regex=False, limit=options.limit
        ):
            if not options.in_scope(value):
                continue
            out.append(
                SearchResult(
                    keyword=keyword,
                    file_path=self.target_path or "",
                    class_name="",
                    method_name="",
                    code_snippet=value,
                    match_type=MatchType.STRING,
                    relevance_score=0.6 if value.strip() == keyword else 0.4,
                    critical_score=compute_critical_score(keyword, "", "", value),
                )
            )
            if len(out) >= options.limit:
                break
        return out

    def _search_call_or_xref(
        self, keyword: str, options: SearchOptions, match_type: MatchType
    ) -> List[SearchResult]:
        """CALL：谁调用了匹配的方法；XREF：匹配类/方法的引用者列表。"""
        out: List[SearchResult] = []
        parser = self.parser
        for sig, caller_count in parser.find_methods(keyword, limit=options.limit):
            cls, meth, _desc = split_signature(sig)
            if not options.in_scope(cls):
                continue
            callers, callees = parser.method_xrefs(sig)
            references = callers if match_type == MatchType.CALL else callers + callees
            for ref in references:
                ref_cls, ref_meth, _ = split_signature(ref)
                if not options.in_scope(ref_cls):
                    continue
                ref_cls = _display_class(ref_cls)
                out.append(
                    SearchResult(
                        keyword=keyword,
                        file_path=self.target_path or "",
                        class_name=ref_cls,
                        method_name=ref_meth,
                        code_snippet=(
                            f"{ref}  -->  {sig}"
                            if match_type == MatchType.CALL
                            else f"{sig}  <=>  {ref}"
                        ),
                        match_type=match_type,
                        relevance_score=0.7 if match_type == MatchType.CALL else 0.6,
                        critical_score=compute_critical_score(
                            keyword, ref_cls, ref_meth, sig, caller_count
                        ),
                    )
                )
                if len(out) >= options.limit:
                    return out
        return out

    # ------------------------------------------------------------- 结构能力

    def get_class_hierarchy(self) -> ClassHierarchy:
        return self.parser.class_hierarchy()

    def get_class_info(self, class_name: str) -> Optional[ClassInfo]:
        return self.parser.get_class(class_name)

    def get_call_graph(self) -> CallGraph:
        return self.parser.call_graph()
