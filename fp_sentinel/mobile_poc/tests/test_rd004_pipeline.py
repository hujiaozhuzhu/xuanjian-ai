"""RD-004 回归测试 —— hook recommend → poc generate 流水线 schema 统一。

覆盖:
- HookRecommendation 完整输出（{"hook_points": [...]} 包装）可直接喂给
  POCGenerator/generate CLI;
- 字段别名归一化（fqcn/method/signature 等）;
- 部分点位（只有 class_name 或 method_name）触发明确 schema 报错;
- --rank 选择第 N 个点位; --output 文件路径形态;
- mock E2E: recommend 输出 JSON → generate 成功渲染出可校验脚本。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fp_sentinel.mobile_hook.models.hook_point import HookPoint
from fp_sentinel.mobile_hook.models.hook_recommendation import HookRecommendation
from fp_sentinel.mobile_poc.cli import main as poc_main
from fp_sentinel.mobile_poc.core.generator import (
    POCGenerator,
    HookPointSchemaError,
)


def _make_recommendation() -> HookRecommendation:
    """构造一条与 hook recommend CLI 输出同构的推荐结果。"""
    hp1 = HookPoint(
        class_name="com.android.insecurebankv2.CryptoClass",
        method_name="encrypt",
        param_signature="(Ljava/lang/String;)Ljava/lang/String;",
        technique="keyword",
        confidence=0.91,
        reason="AES 常量命中",
    )
    hp2 = HookPoint(
        class_name="com.android.insecurebankv2.DoLogin",
        method_name="doLogin",
        param_signature="(Ljava/lang/String;Ljava/lang/String;)V",
        technique="base64",
        confidence=0.72,
    )
    return HookRecommendation(
        apk_path="InsecureBankv2.apk",
        goal="generic",
        hook_points=[hp1, hp2],
        package_name="com.android.insecurebankv2",
    )


class TestSchemaUnify:
    def test_recommendation_wrapper_unwrapped(self):
        gen = POCGenerator()
        rec = _make_recommendation()
        result = gen.generate_for_goal("basic-hook", hook_point=rec.to_dict())
        assert result.success
        assert "CryptoClass" in result.script and "encrypt" in result.script

    def test_recommendation_json_file(self, tmp_path):
        rec_file = tmp_path / "recommend.json"
        rec_file.write_text(
            json.dumps(_make_recommendation().to_dict(), ensure_ascii=False),
            encoding="utf-8")
        gen = POCGenerator()
        result = gen.generate_for_goal("basic-hook", hook_point=str(rec_file))
        assert result.success

    def test_rank_selects_nth_point(self):
        gen = POCGenerator()
        result = gen.generate_for_goal(
            "basic-hook", hook_point=_make_recommendation().to_dict(), rank=1)
        assert result.success
        assert "DoLogin" in result.script and "doLogin" in result.script

    def test_rank_out_of_range_errors(self):
        """NEW-09: --rank 越界必须显式报错，而不是静默回退首个点位。"""
        gen = POCGenerator()
        with pytest.raises(HookPointSchemaError, match="超出范围"):
            gen.generate_for_goal(
                "basic-hook", hook_point=_make_recommendation().to_dict(), rank=99)

    def test_list_hook_points(self):
        gen = POCGenerator()
        points = [{"class_name": "a.B", "method_name": "c"},
                  {"class_name": "a.D", "method_name": "e"}]
        result = gen.generate_for_goal("basic-hook", hook_point=list(points), rank=1)
        assert result.success and "a.D" in result.script

    def test_empty_wrapper_raises(self):
        gen = POCGenerator()
        with pytest.raises(HookPointSchemaError):
            gen.generate_for_goal("basic-hook", hook_point={"hook_points": []})

    def test_partial_point_raises_clear_error(self):
        gen = POCGenerator()
        with pytest.raises(HookPointSchemaError) as exc:
            gen.generate_for_goal(
                "basic-hook", hook_point={"class_name": "a.B"})
        assert "method_name" in str(exc.value)

    def test_alias_signature_normalized(self):
        ctx = POCGenerator._build_context(
            {"fqcn": "a.B", "method": "c", "signature": "(I)V"})
        assert ctx["class_name"] == "a.B"
        assert ctx["method_name"] == "c"
        assert ctx["param_signature"] == "(I)V"

    def test_wrapper_package_inherited(self):
        ctx = POCGenerator._build_context(
            {"hook_points": [{"class_name": "a.B", "method_name": "c"}],
             "package_name": "com.t.app"})
        assert ctx["package_name"] == "com.t.app"

    def test_invalid_json_file_raises(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        with pytest.raises(HookPointSchemaError):
            POCGenerator._build_context(str(bad))


class TestGenerateCLI:
    def test_generate_from_recommendation_file(self, tmp_path, capsys):
        rec_file = tmp_path / "rec.json"
        rec_file.write_text(
            json.dumps(_make_recommendation().to_dict(), ensure_ascii=False),
            encoding="utf-8")
        code = poc_main([
            "generate", "--goal", "basic-hook", "--hook-point", str(rec_file),
            "--no-save"])
        assert code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["success"]
        # RD-004: payload 始终包含 script
        assert "CryptoClass" in payload["script"]

    def test_output_file_path_form(self, tmp_path, capsys):
        out_file = tmp_path / "scripts" / "hook.js"
        rec_file = tmp_path / "rec.json"
        rec_file.write_text(
            json.dumps(_make_recommendation().to_dict(), ensure_ascii=False),
            encoding="utf-8")
        code = poc_main([
            "generate", "--goal", "basic-hook", "--hook-point", str(rec_file),
            "--output", str(out_file)])
        assert code == 0
        assert out_file.exists()
        content = out_file.read_text(encoding="utf-8")
        assert "CryptoClass" in content
        payload = json.loads(capsys.readouterr().out)
        assert payload["script_path"] == str(out_file.resolve())

    def test_partial_point_clear_cli_error(self, capsys, tmp_path):
        hp = tmp_path / "hp.json"
        hp.write_text(json.dumps({"class_name": "a.B"}), encoding="utf-8")
        code = poc_main([
            "generate", "--goal", "basic-hook", "--hook-point", str(hp),
            "--no-save"])
        assert code == 2
        out = capsys.readouterr().out
        assert "missing required field" in out
        # 错误信息是纯 JSON, 不含渲染堆栈
        payload = json.loads(out)
        assert payload["success"] is False


class TestRecommendToPocE2E:
    """E2E: recommend (mock) 输出 → POC 生成 → 校验通过。"""

    def test_full_pipeline(self, tmp_path, capsys):
        # 1) 生成与 hook recommend CLI 同构的 JSON（真实 CLI 在有靶场 APK 时
        #    输出同构结构, 这里用模型直构造以保证测试确定性）
        rec_file = tmp_path / "recommend_out.json"
        rec_file.write_text(
            json.dumps(_make_recommendation().to_dict(), ensure_ascii=False),
            encoding="utf-8")
        # 2) 直接喂给 poc generate（修复前: undefined variable 'method_name'）
        out_dir = tmp_path / "poc_out"
        code = poc_main([
            "generate", "--goal", "basic-hook", "--hook-point", str(rec_file),
            "--output", str(out_dir)])
        assert code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["success"]
        # 3) 落盘脚本存在且含定位信息
        assert Path(payload["script_path"]).exists()
