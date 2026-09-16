"""基础 JS 解混淆工具 —— 为审计做的轻量本地化解还原。

不替代专业反混淆器; 在内存中做安全、可失败降级的基础还原：

1. ``_0x[a-f0-9]{4,}`` hex string array lookup 还原
2. ``String.fromCharCode(104,116,...)`` 求值还原
3. ``%68%74%74%70`` URL-encoded 字符串解码
4. 通用数字-字符替换 (``String.fromCharCode`` 单参数)

所有函数在异常时均返回原文 + ``success=False`` 标记, 绝不抛异常。
"""

from __future__ import annotations

import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class DeobfuscateResult:
    """解混淆结果."""
    source: str
    result: str
    success: bool = True
    technique_applied: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


# ─────────────────────── 检测函数 ───────────────────────


def _detect_packer_deep(src: str) -> dict:
    """更深入的混淆类型检测.

    返回 ``{"type": str, "confidence": float, "keys": list}``.
    """
    result: dict = {"type": "none", "confidence": 0.0, "keys": []}

    if not src:
        return result

    # JSFuck 检测: ][ ... [ ... constructor 模式, 以及过度使用 [][][] 嵌套
    jsfuck_constructor = re.search(r"\]\[.*\[.*constructor", src[:5000])
    jsfuck_nested_brackets = re.search(r"(\[[\]\s]*\]){5,}", src[:5000])
    jsfuck_long_fromcharcode = re.search(
        r"String\.fromCharCode\([\d,\s]{20,}\)", src[:5000]
    )

    if jsfuck_constructor or jsfuck_nested_brackets or jsfuck_long_fromcharcode:
        result["type"] = "jsfuck"
        indicators = []
        if jsfuck_constructor:
            indicators.append("constructor_pattern")
        if jsfuck_nested_brackets:
            indicators.append("nested_brackets")
        if jsfuck_long_fromcharcode:
            indicators.append("long_fromcharcode")
        result["keys"] = indicators
        # confidence based on evidence strength
        result["confidence"] = min(0.4 + 0.2 * len(indicators), 0.95)
        return result

    # obfuscatorIO 变量重命名检测: _0xabcd_0xefgh 序列 (连续多个 _0x 变量)
    obfuscator_pairs = re.findall(
        r"_0x[a-f0-9]{4,}\s*=\s*_0x[a-f0-9]{4,}", src[:10000]
    )
    obfuscator_var_sequence = re.findall(
        r"(?:var|let|const)\s+_0x[a-f0-9]{4,}\s*,\s*_0x[a-f0-9]{4,}", src[:10000]
    )
    obfuscator_hex_array = re.findall(
        r"_0x[a-f0-9]{4,}\s*\[\s*_0x[a-f0-9]{4,}\s*\]", src[:10000]
    )

    if obfuscator_pairs or obfuscator_var_sequence or obfuscator_hex_array:
        result["type"] = "obfuscator_io"
        indicators = []
        if obfuscator_pairs:
            indicators.append(f"assignment_pairs({len(obfuscator_pairs)})")
        if obfuscator_var_sequence:
            indicators.append(f"var_sequence({len(obfuscator_var_sequence)})")
        if obfuscator_hex_array:
            indicators.append(f"hex_array_access({len(obfuscator_hex_array)})")
        result["keys"] = indicators
        result["confidence"] = min(0.5 + 0.15 * len(indicators), 0.95)
        return result

    # eval-packed (通用)
    if re.search(r"eval\s*\(\s*(?:function|atob)\s*\(", src[:2000]):
        result["type"] = "eval_packed"
        result["confidence"] = 0.7
        result["keys"] = ["eval_function_pattern"]
        return result

    # URL-encoded (大量 %XX)
    url_encoded_count = len(re.findall(r"%[0-9a-fA-F]{2}", src[:5000]))
    if url_encoded_count > 20:
        result["type"] = "url_encoded"
        result["confidence"] = min(0.3 + url_encoded_count / 200.0, 0.8)
        result["keys"] = [f"url_encoded_segments({url_encoded_count})"]
        return result

    return result


def detect_jsfuck(src: str) -> bool:
    """检测是否为 JSFuck 混淆."""
    if not src:
        return False
    sample = src[:10000]
    # JSFuck signature: excessive bracket nesting + constructor access
    if re.search(r"\]\[.*\[.*constructor", sample):
        return True
    if re.search(r"(\[[\]\s]*\]){5,}", sample):
        return True
    return False


def detect_obfuscator_io(src: str) -> Tuple[bool, List[str]]:
    """检测是否为 obfuscatorIO 混淆.

    Returns:
        (detected, variable_names)
    """
    if not src:
        return False, []
    sample = src[:10000]
    var_pattern = re.compile(r"\b(_0x[a-f0-9]{4,})\b")
    variables = var_pattern.findall(sample)
    unique_vars = list(set(variables))
    is_obfuscated = len(unique_vars) >= 3
    return is_obfuscated, unique_vars


# ─────────────────────── 解混淆函数 ───────────────────────


def deobfuscate_inline(src: str) -> str:
    """基础本地化还原入口.

    依次尝试:
    1. hex string array lookup 还原 (_0x[hex] 索引)
    2. String.fromCharCode 求值
    3. URL decode
    4. 通用数字-字符替换

    任意步骤失败则跳过, 不抛异常.

    Returns:
        还原后的源码 (失败时返回原文).
    """
    try:
        return _deobfuscate_inline_impl(src).result
    except Exception as exc:
        logger.warning("deobfuscate_inline failed, returning original: %s", exc)
        return src


def _deobfuscate_inline_impl(src: str) -> DeobfuscateResult:
    """deobfuscate_inline 的内部实现."""
    result = DeobfuscateResult(source=src, result=src)

    if not src:
        result.warnings.append("Empty source")
        return result

    packer = _detect_packer_deep(src)
    result.technique_applied.append(f"detected_{packer['type']}")

    working = src

    # 1. Hex string array lookup 还原
    try:
        working = _resolve_hex_string_arrays(working)
        result.technique_applied.append("hex_array_lookup")
    except Exception as exc:
        logger.debug("hex_array_lookup skipped: %s", exc)
        result.warnings.append(f"hex_array_lookup: {exc}")

    # 2. String.fromCharCode 求值
    try:
        working = _resolve_fromcharcode_calls(working)
        result.technique_applied.append("fromcharcode_eval")
    except Exception as exc:
        logger.debug("fromcharcode_eval skipped: %s", exc)
        result.warnings.append(f"fromcharcode_eval: {exc}")

    # 3. URL decode
    try:
        working = _resolve_url_encoding(working)
        result.technique_applied.append("url_decode")
    except Exception as exc:
        logger.debug("url_decode skipped: %s", exc)
        result.warnings.append(f"url_decode: {exc}")

    # 4. 通用数字-字符替换 (Decimal representation)
    try:
        working = _resolve_decimal_char_refs(working)
        result.technique_applied.append("decimal_char_ref")
    except Exception as exc:
        logger.debug("decimal_char_ref skipped: %s", exc)
        result.warnings.append(f"decimal_char_ref: {exc}")

    result.result = working
    if working != src:
        result.success = True
    else:
        result.success = packer["type"] != "none"

    return result


def _resolve_hex_string_arrays(src: str) -> str:
    """还原 obfuscatorIO 的 _0x[hex] string array lookup.

    模式: var _0x1234 = ["str1", "str2", ...]; ... _0x1234[0] ...
    或: _0x1234[0x0] -> "str1"
    """
    if not src:
        return src

    # 查找 string array 定义: var/let/const _0xHEX = [...]
    array_pattern = re.compile(
        r"(var|let|const)\s+(_0x[a-f0-9]{4,})\s*=\s*\[([^}\]]*)\]",
        re.IGNORECASE,
    )

    # 元素提取: 匹配单引号/双引号/反引号包围的字符串
    _elem_re = re.compile(r"""['"`]([^'"`]*?)['"`]""")

    lookup_table: Dict[str, str] = {}
    for match in array_pattern.finditer(src):
        array_var = match.group(2)
        array_content = match.group(3)
        # 解析数组元素
        elements = _elem_re.findall(array_content)
        for idx, val in enumerate(elements):
            try:
                lookup_table[f"{array_var}[{idx}]"] = val
                # 也支持十六进制索引
                lookup_table[f"{array_var}[0x{idx:x}]"] = val
                lookup_table[f"{array_var}[0x{idx:02x}]"] = val
            except Exception:
                pass

    if not lookup_table:
        return src

    # 替换 _0xHEX[idx] -> 'value'
    working = src
    longest_first = sorted(lookup_table.keys(), key=len, reverse=True)
    for key in longest_first:
        val = lookup_table[key]
        if val and not val.isspace():
            working = working.replace(key, repr(val))

    return working


def _resolve_fromcharcode_calls(src: str) -> str:
    """求值 String.fromCharCode(104,116,116,112,...) -> 'http'."""
    if not src:
        return src

    pattern = re.compile(r"String\.fromCharCode\s*\(([^\)]*)\)", re.IGNORECASE)
    working = src

    for match in pattern.finditer(src):
        args_str = match.group(1).strip()
        if not args_str:
            continue
        try:
            # 解析数字参数
            nums = [
                int(x.strip(), 0)  # 0 base allows 0x prefix
                for x in args_str.split(",")
                if x.strip()
            ]
            if 3 <= len(nums) <= 1000:  # 合理范围
                decoded = "".join(
                    chr(n & 0xFFFF) for n in nums if 0 <= n <= 0x10FFFF
                )
                if decoded:
                    start, end = match.span()
                    working = working[:start] + repr(decoded) + working[end:]
        except (ValueError, OverflowError, TypeError):
            continue

    return working


def _resolve_url_encoding(src: str) -> str:
    """解码 URL-encoded 字符串: %68%74%74%70 -> 'http'."""
    if not src:
        return src

    # 匹配连续的 %XX 序列 (>= 3 个)
    pattern = re.compile(r"((?:%[0-9a-fA-F]{2}){3,})")
    working = src

    for match in pattern.finditer(src):
        encoded = match.group(1)
        try:
            decoded = urllib.parse.unquote(encoded)
            if decoded and decoded != encoded and not decoded.isspace():
                start, end = match.span()
                working = working[:start] + repr(decoded) + working[end:]
        except Exception:
            continue

    return working


def _resolve_decimal_char_refs(src: str) -> str:
    """将纯数字代表的字符引用 (如从CharCode的结果) 还原."""
    if not src:
        return src

    # 查找一连串的数字加法形成字符串: '' + 104 + 116 + 116 + 112
    pattern = re.compile(r"""''((?:\s*\+\s*\d{2,3})+)""")
    working = src

    for match in pattern.finditer(src):
        try:
            numbers_str = match.group(1)
            nums = re.findall(r"\d+", numbers_str)
            if 3 <= len(nums) <= 100:
                chars = "".join(chr(int(n) & 0xFFFF) for n in nums)
                if chars and not chars.isspace():
                    start, end = match.span()
                    working = working[:start] + repr(chars) + working[end:]
        except (ValueError, OverflowError):
            continue

    return working


__all__ = [
    "deobfuscate_inline",
    "detect_jsfuck",
    "detect_obfuscator_io",
    "_detect_packer_deep",
    "DeobfuscateResult",
]
