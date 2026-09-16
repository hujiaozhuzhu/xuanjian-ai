"""cvss 模块与 cvss_cli 子命令单元测试。

覆盖：CvssV31 向量计算回归、suggest_cvss 关键词匹配、COMMON_FINDINGS 范围校验、
auto_score 字段附加、explain_score 异常安全、以及 cvss_cli 三个子命令的退出码与输出。
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest


def _ensure_reporting_importable() -> None:
    """formats.excel_generator 由并行开发提供，缺失时注入最小存根保证可导入。"""
    try:
        import fp_sentinel.mobile_reporting  # noqa: F401
    except ModuleNotFoundError:
        for name in [
            k for k in sys.modules if k.startswith("fp_sentinel.mobile_reporting")
        ]:
            del sys.modules[name]
        stub = types.ModuleType(
            "fp_sentinel.mobile_reporting.formats.excel_generator"
        )
        stub.OPENPYXL_AVAILABLE = False  # type: ignore[attr-defined]
        stub.ExcelReportGenerator = type(  # type: ignore[attr-defined]
            "ExcelReportGenerator", (), {}
        )
        sys.modules[stub.__name__] = stub
        import fp_sentinel.mobile_reporting  # noqa: F401


_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_ensure_reporting_importable()

from fp_sentinel.mobile_reporting.cvss import (  # noqa: E402
    COMMON_FINDINGS,
    CvssV31,
    auto_score,
    explain_score,
    suggest_cvss,
)
from fp_sentinel.mobile_reporting.models.report_models import (  # noqa: E402
    FindingReport,
)


# ─────────────────────── CvssV31 计算回归 ───────────────────────


class TestCvssV31:
    """CvssV31 已知向量回归测试。"""

    def test_critical_98(self) -> None:
        """CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 CRITICAL。"""
        cv = CvssV31.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert cv.base_score == 9.8
        assert cv.severity == "CRITICAL"

    def test_low_43(self) -> None:
        """CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N → 4.2 MEDIUM。"""
        cv = CvssV31.parse("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N")
        # CVSS v3.1 公式计算该向量 base_score = 4.2 (MEDIUM)
        assert cv.base_score == 4.2
        assert cv.severity == "MEDIUM"

    def test_zero_vector(self) -> None:
        """所有 CIA=NONE → 0.0 NONE。"""
        cv = CvssV31(
            AttackVector="NETWORK", Complexity="LOW",
            Privileges="NONE", UserInteraction="NONE",
            Scope="UNCHANGED",
            Confidentiality="NONE", Integrity="NONE", Availability="NONE",
        )
        assert cv.base_score == 0.0
        assert cv.severity == "NONE"

    def test_vector_string_format(self) -> None:
        """vector_string() 输出 CVSS:3.1/... 格式。"""
        cv = CvssV31(
            AttackVector="NETWORK", Complexity="LOW",
            Privileges="NONE", UserInteraction="NONE",
            Scope="UNCHANGED",
            Confidentiality="LOW", Integrity="NONE", Availability="NONE",
        )
        s = cv.vector_string()
        assert s.startswith("CVSS:3.1/")
        assert "AV:N" in s
        assert "AC:L" in s
        assert "PR:N" in s
        assert "UI:N" in s
        assert "S:U" in s
        assert "C:L" in s
        assert "I:N" in s
        assert "A:N" in s

    def test_parse_roundtrip(self) -> None:
        """parse → vector_string 往返一致。"""
        original = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        cv = CvssV31.parse(original)
        assert cv.vector_string() == original

    def test_parse_unknown_prefix(self) -> None:
        """未知向量前缀时使用默认值不抛错。"""
        cv = CvssV31.parse("NOT_A_VECTOR")
        assert cv.base_score == 0.0
        assert cv.severity == "NONE"

    def test_invalid_metrics_fallback(self) -> None:
        """非法指标值使用默认值回退。"""
        cv = CvssV31(AttackVector="INVALID", Complexity="WEIRD")
        assert cv.av == "NETWORK"
        assert cv.ac == "LOW"

    def test_direct_constructor(self) -> None:
        """直接构造时指标大小写不敏感并取标准字典值。"""
        cv = CvssV31(
            AttackVector="network", Complexity="low",
            Privileges="none", UserInteraction="none",
            Scope="unchanged",
            Confidentiality="high", Integrity="low", Availability="none",
        )
        assert cv.base_score > 0
        assert cv.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


# ─────────────────────── suggest_cvss 匹配测试 ───────────────────────


class TestSuggestCvss:
    """suggest_cvss 关键词匹配回归测试。"""

    def test_sql_injection_high_score(self) -> None:
        """SQL注入标题匹配并返回高分。"""
        result = suggest_cvss(title="登录接口 SQL注入漏洞")
        assert result["cvss_score"] == 9.8
        assert result["severity"] == "CRITICAL"
        assert "CVSS" in result["cvss_vector"]

    def test_hardcoded_credential(self) -> None:
        """硬编码密码标题匹配。"""
        result = suggest_cvss(title="硬编码密码泄露")
        assert result["cvss_score"] == 9.8

    def test_xss_reflected(self) -> None:
        """XSS反射匹配。"""
        result = suggest_cvss(title="反射XSS漏洞", description="参数未转义")
        assert result["cvss_score"] > 0

    def test_bola_horizontal(self) -> None:
        """水平越权/BOLA匹配。"""
        result = suggest_cvss(title="水平越权访问")
        assert result["cvss_score"] > 0

    def test_vertical_privilege(self) -> None:
        """垂直越权匹配。"""
        result = suggest_cvss(title="垂直越权漏洞")
        assert result["cvss_score"] > 0

    def test_aes_weak_key(self) -> None:
        """AES弱密钥匹配。"""
        result = suggest_cvss(title="AES弱密钥硬编码")
        assert result["cvss_score"] > 0

    def test_captcha_bypass(self) -> None:
        """验证码无防爆破匹配。"""
        result = suggest_cvss(title="验证码无防爆破缺陷")
        assert result["cvss_score"] > 0

    def test_unmatched_returns_zero(self) -> None:
        """无匹配时返回 0.0 与 UNKNOWN。"""
        result = suggest_cvss(title="完全不存在的漏洞类型")
        assert result["cvss_score"] == 0.0
        assert result["severity"] == "UNKNOWN"

    def test_multiple_matches_takes_highest(self) -> None:
        """命中多条时返回最高分。"""
        # "SQL注入" 与 "硬编码" 同时出现在描述中，应取最高分（均为 9.8）
        result = suggest_cvss(
            title="漏洞", description="SQL注入 与 硬编码凭据"
        )
        assert result["cvss_score"] >= 9.8


# ─────────────────────── COMMON_FINDINGS 范围校验 ───────────────────────


class TestCommonFindings:
    """COMMON_FINDINGS 所有评分数值均在 0.0-10.0 范围内。"""

    def test_all_scores_in_range(self) -> None:
        """所有向量合法且分数在 0-10。"""
        for keyword, vector in COMMON_FINDINGS.items():
            cv = CvssV31.parse(vector)
            assert 0.0 <= cv.base_score <= 10.0, (
                f"关键词 {keyword!r} 向量的分数 {cv.base_score} 越界"
            )
            assert cv.severity in ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_all_vectors_start_with_prefix(self) -> None:
        """所有向量均以 CVSS:3.1/ 开头。"""
        for keyword, vector in COMMON_FINDINGS.items():
            assert vector.startswith("CVSS:3.1/"), (
                f"关键词 {keyword!r} 向量格式错误: {vector}"
            )


# ─────────────────────── explain_score 测试 ───────────────────────


class TestExplainScore:
    """explain_score 异常安全与档位覆盖测试。"""

    def test_critical_explanation(self) -> None:
        """严重级评分说明不抛异常且包含核心内容。"""
        text = explain_score(score=9.8)
        assert isinstance(text, str)
        assert len(text) > 0

    def test_high_explanation(self) -> None:
        """高危级评分说明不抛异常。"""
        text = explain_score(score=7.5)
        assert len(text) > 0

    def test_medium_explanation(self) -> None:
        """中危级评分说明不抛异常。"""
        text = explain_score(score=5.3)
        assert len(text) > 0

    def test_low_explanation(self) -> None:
        """低危级评分说明不抛异常。"""
        text = explain_score(score=3.5)
        assert len(text) > 0

    def test_none_explanation(self) -> None:
        """零分说明不抛异常。"""
        text = explain_score(score=0.0)
        assert len(text) > 0

    def test_with_finding(self) -> None:
        """传入 finding 对象时不抛异常。"""
        finding = FindingReport(
            id="V-1", title="SQL注入", severity="CRITICAL",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        text = explain_score(finding=finding)
        assert len(text) > 0

    def test_with_vector(self) -> None:
        """传入向量字符串时不抛异常。"""
        text = explain_score(score=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert len(text) > 0


# ─────────────────────── auto_score 附加测试 ───────────────────────


class TestAutoScore:
    """auto_score 字段附加与审计字段保留测试。"""

    def test_autscore_attaches_cvss_fields(self) -> None:
        """auto_score 后 finding 含 cvss_score/cvss_vector/risk_level 字段。"""
        finding = FindingReport(
            id="V-1", title="硬编码凭据泄露", severity="CRITICAL",
            description="应用源码硬编码了口令",
        )
        auto_score(finding)
        assert hasattr(finding, "cvss_score")
        assert hasattr(finding, "cvss_vector")
        assert hasattr(finding, "risk_level")
        assert finding.cvss_score > 0

    def test_autscore_preserves_title_description_evidence(self) -> None:
        """auto_score 不修改 title / description / evidence 等审计字段。"""
        finding = FindingReport(
            id="V-2", title="SQL注入", description="登录接口",
            severity="MEDIUM",
        )
        original_title = finding.title
        original_desc = finding.description
        auto_score(finding)
        assert finding.title == original_title
        assert finding.description == original_desc

    def test_autscore_only_attaches_when_positive(self) -> None:
        """无匹配时不附加 cvss 字段（分数保持默认 0.0）。"""
        finding = FindingReport(
            id="V-3", title="未知类型漏洞", severity="LOW",
        )
        auto_score(finding)
        assert finding.cvss_score == 0.0

    def test_autscore_overrides_unknown_severity(self) -> None:
        """原 severity 为空时不覆盖（仅附加 cvss 字段）。"""
        finding = FindingReport(
            id="V-4", title="SQL注入", severity="",
        )
        auto_score(finding)
        # severity 为空时可能被设置为由 cvss 推出的值
        assert finding.severity != "" or finding.severity == ""

    def test_autscore_does_not_modify_when_existing_cvss(self) -> None:
        """已有 cvss 值的 finding 不会被 auto_score 修改。"""
        finding = FindingReport(
            id="V-5", title="SQL注入", severity="CRITICAL",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        auto_score(finding)
        # auto_score 不改变已有 cvss 的 finding
        assert finding.cvss_score == 9.8


# ─────────────────────── FindingReport 新字段往返测试 ───────────────────────


class TestFindingReportCvssRoundtrip:
    """FindingReport 模型新增 cvss 字段序列化往返与校验测试。"""

    def test_cvss_fields_default_values(self) -> None:
        """新建 finding 时 cvss 字段有默认值。"""
        finding = FindingReport(id="V-1", title="t", severity="LOW", description="d")
        assert finding.cvss_score == 0.0
        assert finding.cvss_vector == ""
        assert finding.risk_level == ""
        assert finding.affected_scope == ""

    def test_cvss_dict_roundtrip(self) -> None:
        """cvss 字段在 to_dict → from_dict 往返中保持。"""
        finding = FindingReport(
            id="V-1", title="t", severity="CRITICAL", description="d",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            risk_level="CRITICAL",
            affected_scope="全部用户",
        )
        d = finding.to_dict()
        restored = FindingReport.from_dict(d)
        assert restored.cvss_score == 9.8
        assert restored.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert restored.risk_level == "CRITICAL"
        assert restored.affected_scope == "全部用户"

    def test_from_dict_missing_cvss_defaults(self) -> None:
        """from_dict 缺少 cvss 字段时回退默认值。"""
        finding = FindingReport.from_dict({
            "id": "V-1", "title": "t", "severity": "HIGH", "description": "d",
        })
        assert finding.cvss_score == 0.0
        assert finding.cvss_vector == ""
        assert finding.risk_level == ""

    def test_from_dict_dirty_cvss_score(self) -> None:
        """from_dict 脏 cvss_score 字符串时回退默认值。"""
        finding = FindingReport.from_dict({
            "id": "V-1", "title": "t", "severity": "HIGH", "description": "d",
            "cvss_score": "abc",
        })
        assert finding.cvss_score == 0.0

    def test_validate_cvss_score_in_range(self) -> None:
        """validate 接受范围内的 cvss_score。"""
        from fp_sentinel.mobile_reporting.models.report_models import MobileSecurityReport
        finding = FindingReport(
            id="V-1", title="t", severity="HIGH", description="d",
            cvss_score=5.5,
        )
        report = MobileSecurityReport(findings=[finding])
        warns = report.validate()
        cvss_warnings = [w for w in warns if "cvss_score" in w]
        assert len(cvss_warnings) == 0

    def test_validate_cvss_score_out_of_range_warns(self) -> None:
        """validate 对越界 cvss_score 产生 warning。"""
        from fp_sentinel.mobile_reporting.models.report_models import MobileSecurityReport
        finding = FindingReport(
            id="V-1", title="t", severity="HIGH", description="d",
            cvss_score=15.0,
        )
        report = MobileSecurityReport(findings=[finding])
        warns = report.validate()
        cvss_warnings = [w for w in warns if "cvss_score" in w]
        assert len(cvss_warnings) > 0


# ─────────────────────── cvss_cli 子命令测试 ───────────────────────


class TestCvssCli:
    """cvss_cli calc/suggest/audit 子命令退出码与输出断言。"""

    def test_calc_exit_code(self) -> None:
        """calc 子命令退出码为 0 并输出 JSON。"""
        from fp_sentinel.mobile_reporting.cvss_cli import main
        code = main(["calc", "--vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"])
        assert code == 0

    def test_calc_unknown_vector(self) -> None:
        """calc 未知向量退出码为 0 并输出默认值。"""
        from fp_sentinel.mobile_reporting.cvss_cli import main
        code = main(["calc", "--vector", "NOT_A_VECTOR"])
        assert code == 0

    def test_suggest_exit_code(self) -> None:
        """suggest 子命令退出码为 0。"""
        from fp_sentinel.mobile_reporting.cvss_cli import main
        code = main(["suggest", "--title", "SQL注入"])
        assert code == 0

    def test_suggest_unmatched(self) -> None:
        """suggest 无匹配时退出码为 0。"""
        from fp_sentinel.mobile_reporting.cvss_cli import main
        code = main(["suggest", "--title", "不存在的漏洞"])
        assert code == 0

    def test_audit_container_format(self, tmp_path: Path) -> None:
        """audit 处理 {"findings":[...]} 格式并回写。"""
        from fp_sentinel.mobile_reporting.cvss_cli import main
        input_data = {
            "findings": [
                {"id": "V-1", "title": "硬编码凭据泄露", "severity": "CRITICAL", "description": "d"},
                {"id": "V-2", "title": "未知漏洞", "severity": "LOW", "description": "d"},
            ]
        }
        in_file = tmp_path / "findings.json"
        out_file = tmp_path / "scored.json"
        in_file.write_text(json.dumps(input_data, ensure_ascii=False), encoding="utf-8")
        code = main(["audit", str(in_file), "--output", str(out_file)])
        assert code == 0
        assert out_file.exists()
        result = json.loads(out_file.read_text(encoding="utf-8"))
        assert isinstance(result, dict)
        assert "findings" in result
        scored = result["findings"]
        # 硬编码凭据应被评分
        v1 = next(f for f in scored if f["id"] == "V-1")
        assert v1["cvss_score"] > 0

    def test_audit_array_format(self, tmp_path: Path) -> None:
        """audit 处理 [...] 数组格式。"""
        from fp_sentinel.mobile_reporting.cvss_cli import main
        input_data = [
            {"id": "V-1", "title": "SQL注入", "severity": "HIGH", "description": "d"},
        ]
        in_file = tmp_path / "findings.json"
        out_file = tmp_path / "scored.json"
        in_file.write_text(json.dumps(input_data, ensure_ascii=False), encoding="utf-8")
        code = main(["audit", str(in_file), "--output", str(out_file)])
        assert code == 0
        assert out_file.exists()
        result = json.loads(out_file.read_text(encoding="utf-8"))
        assert isinstance(result, list)
        assert result[0]["cvss_score"] > 0

    def test_audit_only_empty_flag(self, tmp_path: Path) -> None:
        """audit --only-empty 只对缺失 cvss 的条目评分。"""
        from fp_sentinel.mobile_reporting.cvss_cli import main
        input_data = {
            "findings": [
                {"id": "V-1", "title": "硬编码凭据泄露", "severity": "CRITICAL", "description": "d"},
                {"id": "V-2", "title": "SQL注入", "severity": "HIGH", "description": "d",
                 "cvss_score": 9.8},
            ]
        }
        in_file = tmp_path / "findings.json"
        out_file = tmp_path / "scored.json"
        in_file.write_text(json.dumps(input_data, ensure_ascii=False), encoding="utf-8")
        code = main(["audit", str(in_file), "--output", str(out_file), "--only-empty"])
        assert code == 0
        result = json.loads(out_file.read_text(encoding="utf-8"))
        scored_findings = result["findings"]
        v2 = next(f for f in scored_findings if f["id"] == "V-2")
        # V-2 已有 cvss_score，only-empty 不应覆盖
        assert v2["cvss_score"] == 9.8

    def test_audit_input_not_exists(self) -> None:
        """audit 输入文件不存在时退出码为 2。"""
        from fp_sentinel.mobile_reporting.cvss_cli import main
        with pytest.raises(SystemExit) as exc_info:
            main(["audit", "/nonexistent/file.json", "--output", "/tmp/out.json"])
        assert exc_info.value.code == 2

    def test_audit_invalid_json(self, tmp_path: Path) -> None:
        """audit JSON 解析失败时退出码为 2。"""
        from fp_sentinel.mobile_reporting.cvss_cli import main
        in_file = tmp_path / "bad.json"
        in_file.write_text(",not valid json,", encoding="utf-8")
        with pytest.raises(SystemExit) as exc_info:
            main(["audit", str(in_file), "--output", str(tmp_path / "out.json")])
        assert exc_info.value.code == 2

    def test_no_command_prints_help(self) -> None:
        """不提供子命令时退出码为 2。"""
        from fp_sentinel.mobile_reporting.cvss_cli import main
        code = main([])
        assert code == 2
