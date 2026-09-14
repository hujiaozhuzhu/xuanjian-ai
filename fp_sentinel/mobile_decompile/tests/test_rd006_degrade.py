"""RD-006 回归测试 —— 反编译降级路径质量标注与 jadx 自动查找。

- find_jadx 扫描常见安装路径（不只 PATH）;
- 大纲降级质量分 0.3 + 显式降级警告;
- summary 的 quality_label / degrade_warning 字段;
- text 输出出现 "完成（大纲模式）" 与 "outline-only (jadx unavailable)";
- try_install_jadx 失败静默（best-effort 语义）。
"""

from __future__ import annotations

import json

import pytest

from fp_sentinel.mobile_decompile.core.android_java import AndroidJavaDecompiler
from fp_sentinel.mobile_decompile.models.decompile_result import (
    DecompileResult,
    SourceFile,
)
from fp_sentinel.mobile_decompile.output.formatter import format_result

from . import requires_insecure_bank  # noqa: F401  (靶场存在性保证导入有效)


class TestFindJadx:
    def test_common_path_discovered(self, tmp_path, monkeypatch):
        fake = tmp_path / "bin" / "jadx.bat"
        fake.parent.mkdir(parents=True)
        fake.write_text("@echo off\n", encoding="utf-8")
        monkeypatch.setattr(
            AndroidJavaDecompiler, "_JADX_COMMON_PATHS", (str(fake),))
        # shutil.which 不受影响（PATH 中无 jadx 时走常见路径分支）
        result = AndroidJavaDecompiler.find_jadx()
        assert result == str(fake)

    def test_returns_none_when_nowhere(self, monkeypatch):
        monkeypatch.setattr(
            AndroidJavaDecompiler, "_JADX_COMMON_PATHS", ())
        monkeypatch.setattr(
            "os.path.expanduser", lambda p: str(__import__("pathlib").Path("/nonexistent-home")))
        # PATH 中无 jadx 的沙箱环境下应返回 None（若环境恰好有 jadx 则跳过）
        import shutil

        if any(shutil.which(e) for e in ("jadx", "jadx.bat", "jadx.exe", "jadx.cmd")):
            pytest.skip("环境中已安装 jadx, 无法测试 None 分支")
        assert AndroidJavaDecompiler.find_jadx() is None

    def test_try_install_jadx_never_raises(self, monkeypatch):
        """auto-install best-effort: 所有包管理器失败时静默返回 None。"""

        def boom(cmd, **kwargs):
            raise OSError("no package manager")

        monkeypatch.setattr(
            "fp_sentinel.mobile_decompile.core.android_java.subprocess.run", boom)
        # find_jadx 返回 None → 安装尝试也不会误报成功
        monkeypatch.setattr(
            AndroidJavaDecompiler, "find_jadx", staticmethod(lambda: None))
        assert AndroidJavaDecompiler.try_install_jadx() is None


def _outline_result() -> DecompileResult:
    result = DecompileResult(success=True, engine_used="androguard")
    result.source_files.append(SourceFile(
        path="outline/com/a/B.java",
        relative_path="outline/com/a/B.java",
        content="// outline\n",
        language="outline",
    ))
    result.quality_score = 0.3
    result.add_warning(
        "jadx 未安装，当前为方法签名大纲（outline），不可用于代码审计；"
        "仅供结构/字符串/交叉引用分析")
    return result


class TestQualityLabel:
    def test_outline_result_summary(self):
        s = _outline_result().summary()
        assert s["quality_label"] == "outline-only (jadx unavailable)"
        assert s["degrade_warning"] is True
        assert s["quality_score"] == 0.3

    def test_jadx_result_summary(self):
        result = DecompileResult(success=True, engine_used="jadx", quality_score=0.9)
        result.source_files.append(SourceFile(
            path="a.java", relative_path="a.java", content="class A {}"))
        s = result.summary()
        assert s["quality_label"] == "full-source"
        assert s["degrade_warning"] is False

    def test_empty_result_unknown_label(self):
        s = DecompileResult(success=False).summary()
        assert s["quality_label"] == "unknown"
        assert s["degrade_warning"] is False


class TestFormatterDegrade:
    def test_text_outline_mode(self):
        text = format_result(_outline_result(), "text")
        assert "完成（大纲模式）" in text
        assert "outline-only (jadx unavailable)" in text
        assert "不可用于代码审计" in text

    def test_text_full_source_keeps_success(self):
        result = DecompileResult(success=True, engine_used="jadx", quality_score=0.9)
        result.source_files.append(SourceFile(
            path="a.java", relative_path="a.java", content="class A {}"))
        text = format_result(result, "text")
        assert "反编译结果: 成功" in text
        assert "大纲" not in text

    def test_json_contains_quality_label(self):
        payload = json.loads(format_result(_outline_result(), "json"))
        assert payload["quality_label"] == "outline-only (jadx unavailable)"


class TestCliDegradeMarking:
    @requires_insecure_bank
    def test_real_apk_json_marks_outline(self, monkeypatch, insecure_bank_parser):
        from typer.testing import CliRunner

        from fp_sentinel.mobile_decompile.cli import decompile_app
        from fp_sentinel.mobile_decompile.core.android_java import (
            AndroidJavaDecompiler as _AJD,
        )
        from . import INSECURE_BANK_APK

        monkeypatch.setattr(_AJD, "find_jadx", staticmethod(lambda: None))
        monkeypatch.setattr(_AJD, "try_install_jadx", staticmethod(lambda: None))
        result = CliRunner().invoke(
            decompile_app, ["run", str(INSECURE_BANK_APK), "--format", "json"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["success"]
        assert payload["quality_label"] == "outline-only (jadx unavailable)"
        assert payload["degrade_warning"] is True
        assert payload["quality_score"] == 0.3
