# -*- coding: utf-8 -*-
"""dex 方法描述符解析工具。

把 JNI 风格方法描述符解析为 Frida ``overload(...)`` 所需的参数类型列表::

    "(Ljava/lang/String;[B)V" -> ["java.lang.String", "byte[]"]
    "()V"                     -> []
    "[[I"                     -> ["int[][]"]
"""

from __future__ import annotations

from typing import List, Tuple

_PRIMITIVES = {
    "V": "void",
    "Z": "boolean",
    "B": "byte",
    "S": "short",
    "C": "char",
    "I": "int",
    "J": "long",
    "F": "float",
    "D": "double",
}


def _parse_type(sig: str, pos: int) -> Tuple[str, int]:
    """从 sig[pos:] 解析一个类型，返回 (类型名, 下一个位置)。"""
    dims = 0
    while pos < len(sig) and sig[pos] == "[":
        dims += 1
        pos += 1
    if pos >= len(sig):
        raise ValueError(f"描述符提前结束: {sig!r}")
    ch = sig[pos]
    if ch == "L":
        end = sig.index(";", pos)
        base = sig[pos + 1:end].replace("/", ".")
        pos = end + 1
    elif ch in _PRIMITIVES:
        base = _PRIMITIVES[ch]
        pos += 1
    else:
        raise ValueError(f"非法类型字符 {ch!r} in {sig!r}")
    return base + "[]" * dims, pos


def parse_descriptor(descriptor: str) -> List[str]:
    """解析完整方法描述符，返回参数类型列表。空/非法输入返回 []。"""
    if not descriptor or not descriptor.startswith("("):
        return []
    # 兼容 androguard 输出中参数间可能存在的空格
    descriptor = descriptor.replace(" ", "")
    try:
        end = descriptor.index(")")
    except ValueError:
        return []
    params: List[str] = []
    pos = 1
    body = descriptor[:end + 1]
    while pos < end:
        t, pos = _parse_type(body, pos)
        params.append(t)
    return params


def return_type(descriptor: str) -> str:
    """解析方法描述符的返回类型。"""
    if not descriptor or ")" not in descriptor:
        return ""
    ret = descriptor.replace(" ", "").split(")", 1)[1]
    try:
        t, _ = _parse_type(ret, 0)
        return t
    except (ValueError, IndexError):
        return ret
