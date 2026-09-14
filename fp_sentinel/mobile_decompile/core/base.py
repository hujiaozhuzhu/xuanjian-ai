"""Decompiler 抽象基类。

玄鉴 v4.0 能力② 反编译引擎 —— 核心接口定义（对应规划文档 2.2.3 节）。
"""

from __future__ import annotations

import os
import time
from abc import ABC, abstractmethod
from typing import List, Optional

from ..models.class_info import ClassHierarchy
from ..models.decompile_result import DecompileConfig, DecompileResult
from ..models.search_result import MatchType, SearchOptions, SearchResult

# 平台标识
PLATFORM_ANDROID = "android"
PLATFORM_IOS = "ios"


class Decompiler(ABC):
    """反编译引擎抽象基类。

    子类需实现三个核心能力：
    - ``decompile``: 执行反编译（异步）
    - ``search_keyword``: 关键字搜索（逆向核心）
    - ``get_class_hierarchy``: 获取类层次结构
    """

    name: str = "base"
    platform: str = ""

    # --------------------------------------------------------- abstract API

    @abstractmethod
    async def decompile(
        self, target: str, config: Optional[DecompileConfig] = None
    ) -> DecompileResult:
        """执行反编译，返回 DecompileResult。"""

    @abstractmethod
    def search_keyword(
        self,
        keyword: str,
        match_types: Optional[List[MatchType]] = None,
        scope: Optional[str] = None,
        limit: int = 200,
    ) -> List[SearchResult]:
        """关键字搜索（逆向核心），支持 TEXT/STRING/CALL/XREF 四种匹配。"""

    @abstractmethod
    def get_class_hierarchy(self) -> ClassHierarchy:
        """获取类层次结构（继承树）。"""

    # ----------------------------------------------------------- shared API

    @staticmethod
    def supports(target_path: str) -> bool:
        """判断是否支持该目标文件（按扩展名/魔数）。"""
        return os.path.exists(target_path)

    @staticmethod
    def new_result(target: str) -> DecompileResult:
        """创建带时间起点的空结果（duration 由调用方回填）。"""
        return DecompileResult(success=False, target_path=str(target))

    @staticmethod
    def now() -> float:
        return time.time()

    @staticmethod
    def options(
        match_types: Optional[List[MatchType]] = None,
        scope: Optional[str] = None,
        limit: int = 200,
    ) -> SearchOptions:
        """构造搜索选项（默认全部 MatchType）。"""
        return SearchOptions(
            match_types=match_types or list(MatchType),
            scope=scope,
            limit=limit,
        )
