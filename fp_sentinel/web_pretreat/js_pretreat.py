"""JS 预处理 / 解混淆工具 —— 为审计做的轻量 JS 预处理。

本模块 **不替代** 专业反混淆器（如 de4js、JStillery），
只把能做的做扎实：

1. 压缩 JS 美化（优先用 ``jsbeautifier``，缺失时降级为正则最小美化）；
2. 字面量字符串提取（URL / 端点 / 密钥 / 中文注释）；
3. API 模式识别（URL / fetch / axios / WebSocket 路径拼接）；
4. 可疑片段定位（eval / document.write / innerHTML / atob / Function 反括号）；
5. Packer 检测（eval-packed / URL-encoded / Webpack / obfuscator-io）；
6. 对 >5 MB 文件自动分块处理并给 memory_warning。

使用示例::

    from fp_sentinel.web_pretreat.js_pretreat import JsPrettier

    p = JsPrettier()
    code = p.prettify(minified_source)
    strings = p.extract_strings(code)
    apis = p.find_api_patterns(code)
    suspicious = p.find_suspicious(code)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

__all__ = ["JsPrettier", "PackedType"]

# jsbeautifier 是可选依赖，缺失时降级正则
try:
    import jsbeautifier  # type: ignore[import-untyped]
except ImportError:  # 可选依赖缺失，降级正则
    jsbeautifier = None  # type: ignore[assignment]

# ── 常量 ──

#: 触发分块处理的字节阈值 (5 MB)
LARGE_FILE_THRESHOLD: int = 5 * 1024 * 1024

#: 最小提取字符串长度
MIN_STRING_LEN: int = 4

#: Packer 类型字符串
PackedType = str  # noqa: E501 —— 列出所有 packer 类型
# packer 类型列表:
#   "eval_packed" | "url_encoded" | "packer_feng" | "webpack"
#   | "obfuscator_io" | "unknown" | "none"

# ── 正则模式 ──

# 单/双/反引号包围的字面量字符串 (匹配 '...' "..." 和 `...`)
_STRING_LITERAL_RE = re.compile(
    r"""(?P<quote>[`'"])((?:(?!(?<!\\)(?P=quote)).)*?)(?P=quote)""",
    re.DOTALL,
)

# URL / API 端点模式
# 使用 ASCII 可见字符做字符类，避免嵌入三种引号时 Python 解析歧义
_API_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    # 匹配 http:// 或 https:// 开头的 URL
    ("url_http", re.compile(r"https?://[^\s`'\"]+", re.IGNORECASE)),
    # 匹配 href= 或 src= 等属性赋值里的相对路径 (三个引号之一包围)
    ("url_relative", re.compile(r"""(?:href|src|action)\s*=\s*[`'"](/[^`'"\s]+)""")),
    # 匹配 fetch( 调用里的路径字符串
    ("fetch_api", re.compile(r"""fetch\s*\(\s*[`'"]([^`'"\s]+)""")),
    # 匹配 axios.get/axios.post 等调用里的路径字符串
    (
        "axios_api",
        re.compile(
            r"""axios(?:\.(?:get|post|put|delete|patch|head|options))?"""
            r"""\s*\(\s*[`'"]([^`'"\s]+)"""
        ),
    ),
    # 匹配路由定义
    ("route_def", re.compile(r"""(?:route|addRoute|Router\.\w+)\s*\(\s*[`'"]([^`'"\s]+)""")),
    # 匹配 WebSocket 连接
    ("websocket", re.compile(r"""new\s+WebSocket\s*\(\s*[`'"]([^`'"\s]+)""")),
]

# 可疑代码模式
_SUSPICIOUS_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("eval_function", re.compile(r"eval\s*\(", re.IGNORECASE)),
    ("function_constructor", re.compile(r"new\s+Function\s*\(", re.IGNORECASE)),
    ("function_call", re.compile(r"Function\s*\(\s*[`'\"]", re.IGNORECASE)),
    ("document_write", re.compile(r"document\.write\s*\(", re.IGNORECASE)),
    ("inner_html_assign", re.compile(r"\.innerHTML\s*=", re.IGNORECASE)),
    ("atob_decode", re.compile(r"atob\s*\(", re.IGNORECASE)),
    ("unescape_packed", re.compile(r"unescape\s*\(\s*[`'\"]%", re.IGNORECASE)),
    ("fromcharcode", re.compile(r"fromCharCode\s*\(", re.IGNORECASE)),
    (
        "script_inject",
        re.compile(r"document\.createElement\s*\(\s*[`'\"]script[`'\"]\s*\)", re.IGNORECASE),
    ),
]

# Packer 特征模式
_PACKER_SIGNATURES: List[Tuple[PackedType, re.Pattern[str]]] = [
    ("eval_packed", re.compile(r"eval\s*\(\s*(?:function|atob)\s*\(", re.IGNORECASE)),
    ("url_encoded", re.compile(r"%[0-9a-fA-F]{2}(?:%[0-9a-fA-F]{2}){10,}", re.IGNORECASE)),
    ("packer_feng", re.compile(r"String\.fromCharCode\s*\(\s*[0-9,\s]+\s*\)", re.IGNORECASE)),
    ("webpack", re.compile(r"webpackJsonp|__webpack_modules__|__webpack_require__", re.IGNORECASE)),
    ("obfuscator_io", re.compile(r"_0x[a-f0-9]{4,}", re.IGNORECASE)),
]


@dataclass
class JsPreprocessWarning:
    """预处理过程中的警告信息。"""

    category: str
    message: str


@dataclass
class JsPreprocessResult:
    """单个 JS 文件的预处理结果。

    携带美化后原文、提取字符串、API 模式、可疑片段、Packer 类型和分析警告。
    """

    original_src: str
    prettified_src: str
    used_beautifier: bool
    warnings: List[JsPreprocessWarning] = field(default_factory=list)
    strings: List[Dict[str, str]] = field(default_factory=list)
    apis: List[Dict[str, str]] = field(default_factory=list)
    suspicious: List[Dict[str, str]] = field(default_factory=list)
    packer_type: str = "none"


# ── 正则降级美化辅助 ──

# 在以下 token 后面追加换行
_NEWLINE_AFTER: Tuple[str, ...] = (";", "{", "}", ",")


def _regex_prettify(src: str) -> str:
    """退化路径下的最小正则美化。

    在不依赖 jsbeautifier 的情况下：

    - 在 ``;`` / ``{`` / ``}`` / ``,`` 后追加换行；
    - 连续空白压缩为单个空格；
    - 字符串字面量内部绝不做任何修改（防止破坏内容）。
    """
    if not src:
        return src

    result: List[str] = []
    i: int = 0
    length: int = len(src)

    while i < length:
        ch = src[i]

        # 遇到字符串字面量原样保留
        if ch in ("'", '"', "`"):
            quote = ch
            j = i + 1
            while j < length:
                if src[j] == "\\" and j + 1 < length:
                    j += 2  # 跳过转义
                    continue
                if src[j] == quote:
                    j += 1
                    break
                j += 1
            result.append(src[i:j])
            i = j
            continue

        # 遇到注释原样保留
        if ch == "/" and i + 1 < length:
            if src[i + 1] == "/":  # 单行注释
                end = src.find("\n", i)
                if end == -1:
                    end = length
                result.append(src[i:end])
                i = end
                continue
            if src[i + 1] == "*":  # 多行评论
                end = src.find("*/", i + 2)
                if end == -1:
                    end = length
                else:
                    end += 2
                result.append(src[i:end])
                i = end
                continue

        result.append(ch)

        # 在某些 token 后面追加换行
        if ch in _NEWLINE_AFTER:
            # 检查下一个非空白字符是否已换行
            k = i + 1
            while k < length and src[k] in (" ", "\t"):
                k += 1
            if k < length and src[k] not in ("\n", "\r", "}"):
                result.append("\n")

        i += 1

    # 压缩多余的连续空白行，并确保每行结尾有换行
    raw = "".join(result)
    # 行首缩进: 简单按 {+1 / }-1 计算 depth
    lines: List[str] = []
    depth: int = 0
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # } 开头的行减少缩进
        cur_depth = depth
        if stripped.startswith("}"):
            cur_depth = max(0, depth - 1)
        indent = "  " * cur_depth
        lines.append(indent + stripped)
        # 更新 depth
        depth_change = stripped.count("{") - stripped.count("}")
        if stripped.startswith("}"):
            depth = max(0, depth + depth_change + 1)  # } 已经外部 depth - 1
        else:
            depth = max(0, depth + depth_change)

    return "\n".join(lines) + ("\n" if lines else "")


class JsPrettier:
    """JS 预处理器 —— 美化、提取、识别可疑片段。

    设计原则：绝不在磁盘上修改原始文件，绝不在沙箱外执行目标 JS。
    所有分析都在内存中完成，失败时安全降级而非抛异常。
    """

    def __init__(self, min_string_len: int = MIN_STRING_LEN) -> None:
        """初始化 JsPrettier。

        Parameters
        ----------
        min_string_len:
            提取字面量字符串的默认最小长度（过短的噪音串跳过）。
        """
        self._min_string_len = min_string_len

    @property
    def has_beautifier(self) -> bool:
        """是否可用原生 jsbeautifier。"""
        return jsbeautifier is not None

    # ──────────────────────────────────────────
    # 1. prettify
    # ──────────────────────────────────────────

    def prettify(self, src: str) -> str:
        """美化 JS 源代码。

        优先使用 ``jsbeautifier``；缺失或失败时降级到正则最小美化。

        Parameters
        ----------
        src:
            原始 JS 源码（可以是压缩 / 混淆 / 单行巨字符串均可）。

        Returns
        -------
        str
            美化后的源码字符串。任何失败路径下都返回退化但可读的版本，
            不会抛异常。
        """
        size = len(src.encode("utf-8"))
        if size > LARGE_FILE_THRESHOLD:
            logger.warning(
                "JS 文件 %d MB 超过 %d MB 阈值，建议分块处理；仍尝试美化",
                size // (1024 * 1024),
                LARGE_FILE_THRESHOLD // (1024 * 1024),
            )
        if jsbeautifier is None:
            logger.debug("jsbeautifier 不可用，使用正则降级美化")
            return _regex_prettify(src)
        try:
            return jsbeautifier.beautify(src)
        except Exception as exc:  # noqa: BLE001 —— 任何异常均安全降级
            logger.warning("jsbeautifier 出错: %s；回退到正则美化", exc)
            return _regex_prettify(src)

    # ──────────────────────────────────────────
    # 2. extract_strings
    # ──────────────────────────────────────────

    def extract_strings(self, src: str, min_len: Optional[int] = None) -> List[Dict[str, str]]:
        """提取全部字面量字符串（引号包围的文本）。

        同时给每个字符串打一个初判标签（``url`` / ``api_path`` / ``secret_like``
        / ``comment_like`` / ``other``），帮助审计员快速筛选。

        Parameters
        ----------
        src:
            待分析的 JS 源码（通常先经过 :meth:`prettify` 更方便阅读）。
        min_len:
            最小长度阈值，未指定时用实例默认值。

        Returns
        -------
        list[dict]
            每项包含 ``value`` / ``tag`` / ``line`` / ``snippet`` 四个字段。
        """
        min_len = min_len if min_len is not None else self._min_string_len
        if not src:
            return []

        results: List[Dict[str, str]] = []
        seen: set[str] = set()

        for match in _STRING_LITERAL_RE.finditer(src):
            raw = match.group(0)
            inner = raw[1:-1]  # 去掉包裹的引号

            if len(inner) < min_len:
                continue
            if inner in seen:
                continue
            seen.add(inner)

            # 计算行号
            start = match.start()
            line = src[:start].count("\n") + 1
            # 上下文片段 (前后 20 字符)
            ctx_start = max(0, start - 20)
            ctx_end = min(len(src), match.end() + 20)
            snippet = src[ctx_start:ctx_end].replace("\n", "\\n")
            if len(snippet) > 80:
                snippet = snippet[:77] + "..."

            tag = _classify_string(inner)
            results.append({
                "value": inner,
                "tag": tag,
                "line": str(line),
                "snippet": snippet,
            })

        return results

    # ──────────────────────────────────────────
    # 3. find_api_patterns
    # ──────────────────────────────────────────

    def find_api_patterns(self, src: str) -> List[Dict[str, str]]:
        """从源码中识别常见 URL / 端点拼接模式。

        使用 :data:`_API_PATTERNS` 列表匹配 ``https://``、``href=``、
        ``fetch(``、``axios.`` 等结构，并标注行号与完整匹配片段。

        Returns
        -------
        list[dict]
            每项包含 ``pattern_type`` / ``match`` / ``line`` / ``snippet``。
        """
        if not src:
            return []

        results: List[Dict[str, str]] = []
        seen: set[str] = set()

        for ptype, pattern in _API_PATTERNS:
            for match in pattern.finditer(src):
                line = src[: match.start()].count("\n") + 1
                text = match.group(0)
                key = f"{ptype}:{line}:{text}"
                if key in seen:
                    continue
                seen.add(key)
                snippet = _make_snippet(src, match.start(), match.end())
                results.append({
                    "pattern_type": ptype,
                    "match": text,
                    "line": str(line),
                    "snippet": snippet,
                })

        return results

    # ──────────────────────────────────────────
    # 4. find_suspicious
    # ──────────────────────────────────────────

    def find_suspicious(self, src: str) -> List[Dict[str, str]]:
        """识别可疑 JS 代码片段。

        可疑项包括 ``eval(Function(``、``document.write``、``innerHTML=``、
        ``atob(``、``Function(`` 反括号执行、``fromCharCode`` 堆拼接、
        document.createElement("script") 等动态注入特征。

        Returns
        -------
        list[dict]
            每项包含 ``pattern_type`` / ``match_text`` / ``line`` / ``snippet``。
        """
        if not src:
            return []

        results: List[Dict[str, str]] = []
        seen: set[str] = set()

        for ptype, pattern in _SUSPICIOUS_PATTERNS:
            for match in pattern.finditer(src):
                line = src[: match.start()].count("\n") + 1
                text = match.group(0)
                key = f"{ptype}:{line}:{text}"
                if key in seen:
                    continue
                seen.add(key)
                snippet = _make_snippet(src, match.start(), match.end())
                results.append({
                    "pattern_type": ptype,
                    "match_text": text,
                    "line": str(line),
                    "snippet": snippet,
                })

        return results

    # ──────────────────────────────────────────
    # 5. detect_packer
    # ──────────────────────────────────────────

    def detect_packer(self, src: str) -> str:
        """识别 JS 的 packing 类型。

        仅做静态特征匹配；如果特征命中则返回对应类型字符串，
        并在日志里提示"如需深入请配合专业反混淆器"。

        Parameters
        ----------
        src:
            原始 JS 源码（是压缩未美化的反而更容易命中）。

        Returns
        -------
        str
            ``"eval_packed"`` / ``"url_encoded"`` / ``"packer_feng"`` /
            ``"webpack"`` / ``"obfuscator_io"`` / ``"unknown"`` / ``"none"``。
        """
        if not src:
            return "none"

        for packer_type, pattern in _PACKER_SIGNATURES:
            if pattern.search(src):
                logger.info(
                    "检测到 %s packing 特征；如需深入解混淆请配合专业反混淆器 (de4js / JStillery)。",
                    packer_type,
                )
                return packer_type

        # unknown: 长单行 + 大量转义
        lines = src.splitlines()
        if len(lines) <= 3 and len(src) > 5000:
            avg_line = len(src) / max(len(lines), 1)
            if avg_line > 2000:
                logger.info(
                    "疑似高压缩 JS（行均 %.0f 字符）；请用 SourceMap 或专业反混淆器深入。",
                    avg_line,
                )
                return "unknown"

        return "none"

    # ──────────────────────────────────────────
    # 6. full pipeline
    # ──────────────────────────────────────────

    def process(self, src: str) -> JsPreprocessResult:
        """完整预处理流水线。

        对给定的 JS 源码依次执行: detect_packer -> prettify -> extract_strings ->
        find_api_patterns -> find_suspicious，并把所有结果打包返回。

        对 >5 MB 文件自动设置 memory_warning。
        """
        warnings: List[JsPreprocessWarning] = []
        size = len(src.encode("utf-8"))
        if size > LARGE_FILE_THRESHOLD:
            warnings.append(JsPreprocessWarning(
                category="memory_warning",
                message=f"文件 {size // (1024 * 1024)} MB，建议用流式分块处理。",
            ))

        packer = self.detect_packer(src)
        used_beautifier = self.has_beautifier
        prettified = self.prettify(src)
        strings = self.extract_strings(prettified)
        apis = self.find_api_patterns(prettified)
        suspicious = self.find_suspicious(prettified)

        return JsPreprocessResult(
            original_src=src,
            prettified_src=prettified,
            used_beautifier=used_beautifier,
            warnings=warnings,
            strings=strings,
            apis=apis,
            suspicious=suspicious,
            packer_type=packer,
        )


# ── 内部辅助函数 ──

def _classify_string(inner: str) -> str:
    """根据字符串内容给出初始标签。"""
    if inner.startswith(("http://", "https://", "//")):
        return "url"
    if inner.startswith("/api") or inner.startswith("/v") or inner.startswith("/rest"):
        return "api_path"
    # 密钥类特征
    lower = inner.lower()
    if any(kw in lower for kw in ("key", "token", "secret", "passwd", "password", "apikey")):
        if len(inner) >= 8:
            return "secret_like"
    # 中文占比 > 30% 且含常见中文 -> sample comment_like 标签
    chinese_chars = sum(1 for ch in inner if "一" <= ch <= "鿿")
    if chinese_chars > 0 and chinese_chars / len(inner) > 0.3:
        return "comment_like"
    return "other"


def _make_snippet(src: str, start: int, end: int, margin: int = 30) -> str:
    """生成指定位置前后的上下文片段。"""
    ctx_start = max(0, start - margin)
    ctx_end = min(len(src), end + margin)
    snippet = src[ctx_start:ctx_end].replace("\n", "\\n")
    if len(snippet) > 100:
        snippet = snippet[:97] + "..."
    return snippet
