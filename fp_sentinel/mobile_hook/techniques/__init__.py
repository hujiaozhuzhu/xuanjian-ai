# -*- coding: utf-8 -*-
"""玄鉴 v4.0 mobile_hook 定位技法包。"""

from .base import (
    Technique,
    build_technique,
    get_technique_registry,
    register_technique,
)

__all__ = [
    "Technique",
    "build_technique",
    "get_technique_registry",
    "register_technique",
    "TECHNIQUE_NAMES",
]

# 七种内置技法名（固定顺序，与规划文档 2.3.1 对应）
TECHNIQUE_NAMES = [
    "keyword",
    "collection",
    "toast",
    "log",
    "json",
    "string",
    "base64",
]
