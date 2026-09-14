"""报告生成器基类。

所有报告格式生成器（Excel / CSV / PDF ...）继承 :class:`BaseReportGenerator`，
并共享统一的输出路径安全策略（S7 红线）：

1. 输出路径必须落在白名单根目录之内（解析真实路径，防符号链接与 ``..`` 穿越）；
2. 输出文件后缀必须在允许集合内；
3. 违规一律抛出 :class:`PathNotAllowedError`，绝不静默降级为其他路径；
4. 创建父目录后、写入文件前，对父目录重新解析真实路径并再次校验
   白名单（写前二次校验，收窄 TOCTOU 竞争窗口）。残余风险：校验与
   写入之间仍存在无法完全消除的竞争窗口，需配合受控运行环境使用。
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable, Optional, Set, Union

try:  # 正式模型由 models 子包提供；未就绪时使用存根
    from ..models.report_models import MobileSecurityReport
except ImportError:  # pragma: no cover - 依赖并行开发的模型包
    from ._models_stub import MobileSecurityReport

__all__ = ["BaseReportGenerator", "PathNotAllowedError"]

logger = logging.getLogger(__name__)


class PathNotAllowedError(PermissionError):
    """S7 红线违规：输出路径不在白名单内或后缀不被允许。"""


class BaseReportGenerator(ABC):
    """报告生成器基类。

    Args:
        allowed_roots: 输出路径白名单根目录集合。为空时默认仅允许
            当前工作目录（``Path.cwd()``）。
        allowed_suffixes: 允许的输出文件后缀集合（小写，含点号）。
            为空时使用生成器自身默认值。
    """

    #: 基类默认允许的输出后缀
    DEFAULT_ALLOWED_SUFFIXES = frozenset({".xlsx", ".csv"})

    def __init__(
        self,
        allowed_roots: Optional[Iterable[Union[str, Path]]] = None,
        allowed_suffixes: Optional[Iterable[str]] = None,
    ) -> None:
        roots = [Path(r) for r in (allowed_roots or [Path.cwd()])]
        if not roots:
            roots = [Path.cwd()]
        self._allowed_roots: Set[Path] = {
            r.expanduser().resolve(strict=False) for r in roots
        }
        suffixes = allowed_suffixes or self.DEFAULT_ALLOWED_SUFFIXES
        self._allowed_suffixes: Set[str] = {s.lower() for s in suffixes}

    # ─────────────────────────── 抽象接口 ───────────────────────────

    @abstractmethod
    def generate(self, report: MobileSecurityReport, output_path: Path) -> Path:
        """生成报告。

        Args:
            report: 移动安全评估报告数据。
            output_path: 输出路径（必须通过白名单校验）。

        Returns:
            实际生成的产物路径（Excel 为文件；CSV 降级为产物目录）。
        """
        ...

    @abstractmethod
    def get_format_name(self) -> str:
        """返回格式名称，例如 ``"Excel (.xlsx)"``。"""
        ...

    # ────────────────────────── 白名单管理 ──────────────────────────

    def add_allowed_root(self, root: Union[str, Path]) -> None:
        """向白名单追加一个允许的输出根目录。

        Args:
            root: 根目录路径（绝对或相对，均解析为真实路径）。
        """
        resolved = Path(root).expanduser().resolve(strict=False)
        self._allowed_roots.add(resolved)
        logger.debug("已追加输出白名单根目录: %s", resolved)

    @property
    def allowed_roots(self) -> Set[Path]:
        """当前白名单根目录集合（只读视图）。"""
        return set(self._allowed_roots)

    # ────────────────────────── S7 红线校验 ─────────────────────────

    def validate_output_path(
        self,
        path: Union[str, Path],
        allowed_suffixes: Optional[Iterable[str]] = None,
    ) -> Path:
        """路径白名单校验（S7 红线）。

        校验规则：
        - 相对路径先按当前工作目录解析，再取真实路径（穿透符号链接）；
        - 真实路径必须位于某个白名单根目录之下（``..`` 穿越失效）；
        - 文件后缀必须在允许集合内；
        - 通过后自动创建父目录；
        - 创建父目录后、写入前，重新解析父目录真实路径并二次校验
          白名单（防 TOCTOU：初次校验后父目录可能被符号链接等重定向。
          残余风险：二次校验与实际写入之间仍存在竞争窗口，无法完全
          消除，需配合受控运行环境使用）。

        Args:
            path: 待校验的输出路径。
            allowed_suffixes: 本次调用临时覆盖的后缀白名单。

        Returns:
            校验通过并解析后的绝对路径。

        Raises:
            PathNotAllowedError: 路径逃逸出白名单、后缀不被允许或路径无效。
        """
        if isinstance(path, str):
            path = Path(path)
        raw = Path(path)
        if not str(raw).strip():
            raise PathNotAllowedError("输出路径为空，拒绝生成。")

        if not raw.is_absolute():
            raw = Path.cwd() / raw

        try:
            resolved = raw.expanduser().resolve(strict=False)
        except OSError as exc:  # 平台相关的非法路径
            raise PathNotAllowedError(f"输出路径无法解析: {raw} ({exc})") from exc

        suffixes = (
            {s.lower() for s in allowed_suffixes}
            if allowed_suffixes is not None
            else self._allowed_suffixes
        )

        inside = any(
            self._is_relative_to(resolved, root) for root in self._allowed_roots
        )
        if not inside:
            raise PathNotAllowedError(
                f"S7 红线: 输出路径 {resolved} 不在白名单根目录 "
                f"{sorted(str(r) for r in self._allowed_roots)} 之内。"
            )
        if resolved.suffix.lower() not in suffixes:
            raise PathNotAllowedError(
                f"S7 红线: 输出后缀 {resolved.suffix!r} 不在允许集合 "
                f"{sorted(suffixes)} 内。路径: {resolved}"
            )

        resolved.parent.mkdir(parents=True, exist_ok=True)

        # 写前二次校验（防 TOCTOU）：父目录可能在首次校验后被符号链接
        # 等手段重定向到白名单之外，写入前重新解析并再次校验。
        try:
            parent_real = resolved.parent.resolve(strict=False)
        except OSError as exc:
            raise PathNotAllowedError(
                f"S7 红线: 输出路径父目录无法解析: {resolved.parent} ({exc})"
            ) from exc
        parent_inside = any(
            self._is_relative_to(parent_real, root)
            for root in self._allowed_roots
        )
        if not parent_inside:
            raise PathNotAllowedError(
                f"S7 红线（写前二次校验）: 输出路径父目录 {parent_real} "
                f"不在白名单根目录 "
                f"{sorted(str(r) for r in self._allowed_roots)} 之内。"
            )
        return resolved

    @staticmethod
    def _is_relative_to(child: Path, parent: Path) -> bool:
        """判断 ``child`` 是否位于 ``parent`` 之下（含相等）。"""
        try:
            child.relative_to(parent)
            return True
        except ValueError:
            return False
