"""BaseReportGenerator S7 白名单写前二次校验（防 TOCTOU）回归测试。

覆盖：首次校验通过后、写入前父目录被重定向到白名单之外时，
二次校验必须拦截并抛出 :class:`PathNotAllowedError`。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fp_sentinel.mobile_reporting.formats.base_generator import (
    BaseReportGenerator,
    PathNotAllowedError,
)


class _StubGenerator(BaseReportGenerator):
    """仅用于校验路径白名单的最小存根生成器。"""

    def get_format_name(self) -> str:
        """返回格式名称。"""
        return "stub"

    def generate(self, report: object, output_path: Path) -> Path:
        """生成报告（存根：仅做路径校验）。"""
        return self.validate_output_path(output_path)


def test_write_before_second_check_blocks_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """模拟 TOCTOU：写入前父目录被重定向到白名单外时二次校验拦截。"""
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    outside.mkdir()
    target = root / "out" / "report.xlsx"

    real_resolve = Path.resolve
    state = {"calls": 0}

    def fake_resolve(self: Path, strict: bool = False) -> Path:
        """首次解析返回白名单内路径，二次（写前）解析返回逃逸路径。"""
        state["calls"] += 1
        if state["calls"] == 1:
            return target
        return outside / "report.xlsx"

    # 先构造生成器（解析白名单根目录），再打补丁，避免 __init__ 的
    # resolve 调用干扰计数
    gen = _StubGenerator(allowed_roots=[root])
    monkeypatch.setattr(Path, "resolve", fake_resolve)
    with pytest.raises(PathNotAllowedError) as exc_info:
        gen.validate_output_path(target)
    assert state["calls"] >= 2
    assert "写前二次校验" in str(exc_info.value)
    # 确保还原真实 resolve，避免影响其他用例
    assert real_resolve is not None


def test_normal_path_still_passes(tmp_path: Path) -> None:
    """常规白名单内路径在加入写前二次校验后仍正常通过。"""
    gen = _StubGenerator(allowed_roots=[tmp_path])
    resolved = gen.validate_output_path(tmp_path / "sub" / "ok.xlsx")
    assert resolved == (tmp_path / "sub" / "ok.xlsx").resolve()
    assert resolved.exists() or resolved.parent.exists()
