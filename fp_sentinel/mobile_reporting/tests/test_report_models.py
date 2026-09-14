"""models.report_models 单元测试：模型创建 / 序列化往返 / validate 规则。"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


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


_ensure_reporting_importable()

from fp_sentinel.mobile_reporting.models import (  # noqa: E402
    Appendix,
    EnvironmentInfo,
    Evidence,
    ExpInfo,
    FindingReport,
    MobileSecurityReport,
    PocInfo,
    ReportMetadata,
    ReportStatistics,
    ReproStep,
    ScreenshotRef,
    TargetAppInfo,
)


def _build_full_report(tmp_path: Path) -> MobileSecurityReport:
    """构造一份全字段完整的报告。"""
    shot_file = tmp_path / "shot.png"
    shot_file.write_bytes(b"\x89PNG\r\n\x1a\nfake")
    finding = FindingReport(
        id="VUL-001",
        title="硬编码凭据泄露",
        severity="CRITICAL",
        cwe_id="CWE-798",
        owasp_masvs="MASVS-STORAGE-1",
        category="数据存储",
        description="应用存在硬编码凭据",
        evidence=[
            Evidence(
                id="EV-VUL-001-01",
                location="com/a/B.java:42",
                content='PASS = "superSecret"',
                description="反编译可见明文口令",
                source="静态",
            )
        ],
        screenshots=[
            ScreenshotRef(
                id="SHOT-001",
                path=str(shot_file),
                caption="jadx 视图",
                sha256="a" * 64,
                width=100,
                height=80,
                format="png",
            )
        ],
        repro_steps=[
            ReproStep(
                step_no=1,
                action="反编译 APK",
                expected_result="生成 smali 目录",
                actual_result="反编译成功",
                command="apktool d demo.apk -o out",
            )
        ],
        poc=PocInfo(
            id="POC-VUL-001",
            name="明文捕获",
            type="frida",
            script_path="poc/hook.js",
            script_content="Java.perform(function() {});",
            safety_level="SAFE",
            description="基础 Hook",
        ),
        exp=ExpInfo(
            id="EXP-VUL-001",
            name="受控利用",
            preconditions=["已获取 APK"],
            steps=["提取凭据", "登录验证"],
            impact="接管账户",
            mitigation="移除硬编码凭据",
        ),
        remediation="使用 Keystore 管理凭据",
        references=["https://cwe.mitre.org/data/definitions/798.html"],
        tool_version="4.0.0",
        confidence=0.9,
    )
    return MobileSecurityReport(
        metadata=ReportMetadata(title="演示报告", version="V2.0", date="2025-01-01"),
        environment=EnvironmentInfo(
            os="Windows 11",
            python_version="3.12.1",
            tool_versions={"frida": "16.5.6"},
            target_app=TargetAppInfo(
                name="demo",
                package="com.demo",
                version="1.0",
                sha256="b" * 64,
                file_size=1024,
            ),
            scan_time="2025-01-01T10:00:00",
            scan_command="fp_sentinel insight scan demo.apk",
        ),
        statistics=ReportStatistics(
            total_count=1,
            by_severity={"CRITICAL": 1},
            by_category={"数据存储": 1},
            scan_duration_seconds=1.5,
        ),
        findings=[finding],
        appendix=Appendix(
            glossary={"MASVS": "移动应用安全验证标准"},
            toolchain_info={"jadx": "1.4.7"},
            raw_logs_ref="logs/scan.log",
        ),
        report_format="json",
        generated_at="2025-01-01T12:00:00",
    )


class TestSerializationRoundtrip:
    """序列化往返测试。"""

    def test_dict_roundtrip(self, tmp_path: Path) -> None:
        """to_dict -> from_dict 后字段完全一致。"""
        report = _build_full_report(tmp_path)
        restored = MobileSecurityReport.from_dict(report.to_dict())
        assert restored.to_dict() == report.to_dict()

    def test_json_roundtrip(self, tmp_path: Path) -> None:
        """JSON 字符串往返无损（中文与嵌套对象完整保留）。"""
        report = _build_full_report(tmp_path)
        text = report.to_json()
        restored = MobileSecurityReport.from_dict(json.loads(text))
        assert restored.to_dict() == report.to_dict()
        assert restored.findings[0].evidence[0].location == "com/a/B.java:42"
        assert restored.environment.target_app.package == "com.demo"
        assert restored.metadata.title == "演示报告"

    def test_from_dict_tolerates_empty(self) -> None:
        """空输入 / 字段缺失时宽容反序列化。"""
        report = MobileSecurityReport.from_dict(None)
        assert report.findings == []
        assert report.metadata.title
        bare = MobileSecurityReport.from_dict({"findings": [{"id": "VUL-001"}]})
        assert bare.findings[0].severity == "MEDIUM"
        assert bare.findings[0].poc is None
        assert bare.findings[0].exp is None

    def test_nested_model_from_dict(self) -> None:
        """子模型独立反序列化，字段缺失取默认值。"""
        poc = PocInfo.from_dict({"id": "POC-1"})
        assert poc.safety_level == "SAFE" and poc.type == "frida"
        exp = ExpInfo.from_dict({"steps": ["a", 1]})
        assert exp.steps == ["a", "1"]
        env = EnvironmentInfo.from_dict({"tool_versions": {"frida": 16}})
        assert env.tool_versions == {"frida": "16"}


class TestValidate:
    """validate 校验规则测试。"""

    def test_clean_report_passes(self, tmp_path: Path) -> None:
        """完整合法报告无 warning。"""
        assert _build_full_report(tmp_path).validate() == []

    def test_empty_report_passes(self) -> None:
        """空报告合法。"""
        assert MobileSecurityReport().validate() == []

    def test_invalid_severity(self) -> None:
        """非法 severity 产生 warning。"""
        report = MobileSecurityReport(
            findings=[FindingReport(id="VUL-001", title="t", severity="SUPER")]
        )
        assert any("非法 severity" in w for w in report.validate())

    def test_duplicate_finding_ids(self) -> None:
        """重复 id 产生 warning。"""
        dup = FindingReport(id="VUL-001", title="t", severity="LOW")
        report = MobileSecurityReport(findings=[dup, dup])
        assert any("id 重复" in w for w in report.validate())

    def test_missing_required_fields(self) -> None:
        """必填字段为空产生 warning。"""
        report = MobileSecurityReport(
            findings=[FindingReport(id="", title="", severity="HIGH")]
        )
        warnings = report.validate()
        assert any("必填字段为空: id" in w for w in warnings)
        assert any("必填字段为空: title" in w for w in warnings)
        assert any("必填字段为空: description" in w for w in warnings)

    def test_confidence_out_of_range(self) -> None:
        """confidence 越界产生 warning。"""
        report = MobileSecurityReport(
            findings=[
                FindingReport(
                    id="VUL-001", title="t", severity="LOW", confidence=1.5
                )
            ]
        )
        assert any("confidence" in w for w in report.validate())

    def test_missing_screenshot_file(self) -> None:
        """截图文件不存在产生 warning。"""
        report = MobileSecurityReport(
            findings=[
                FindingReport(
                    id="VUL-001",
                    title="t",
                    severity="LOW",
                    screenshots=[
                        ScreenshotRef(id="SHOT-001", path="no/such/file.png")
                    ],
                )
            ]
        )
        assert any("截图文件不存在" in w for w in report.validate())

    def test_screenshot_without_path(self) -> None:
        """截图缺少 path 产生 warning。"""
        report = MobileSecurityReport(
            findings=[
                FindingReport(
                    id="VUL-001",
                    title="t",
                    severity="LOW",
                    screenshots=[ScreenshotRef(id="SHOT-001")],
                )
            ]
        )
        assert any("缺少 path" in w for w in report.validate())


# ---------------------------------------------------------------------------
# from_dict 脏数据健壮性与 validate 大小写一致性回归
# ---------------------------------------------------------------------------


class TestFromDictDirtyData:
    """脏 JSON 反序列化不崩溃回归。"""

    def test_tool_versions_list_becomes_empty(self) -> None:
        """tool_versions 为列表时转空 dict 而非崩溃。"""
        env = EnvironmentInfo.from_dict({"tool_versions": ["frida", "1.0"]})
        assert env.tool_versions == {}

    def test_file_size_dirty_string_falls_back(self) -> None:
        """file_size / width / height / step_no 为脏字符串时回退默认值。"""
        assert TargetAppInfo.from_dict({"file_size": "abc"}).file_size == 0
        ref = ScreenshotRef.from_dict({"width": "abc", "height": "xyz"})
        assert ref.width == 0 and ref.height == 0
        step = ReproStep.from_dict({"step_no": "abc"})
        assert step.step_no == 1

    def test_nested_non_dict_elements_skipped(self) -> None:
        """evidence / screenshots / repro_steps 中非对象元素跳过不崩溃。"""
        finding = FindingReport.from_dict({
            "id": "X1",
            "title": "t",
            "severity": "HIGH",
            "description": "d",
            "evidence": ["junk", {"content": "real"}],
            "screenshots": ["junk", {"path": "a.png"}],
            "repro_steps": [1, {"action": "a"}],
        })
        assert [e.content for e in finding.evidence] == ["real"]
        assert [s.path for s in finding.screenshots] == ["a.png"]
        assert [r.action for r in finding.repro_steps] == ["a"]

    def test_nested_non_list_ignored(self) -> None:
        """嵌套字段为非列表时整体忽略不崩溃。"""
        finding = FindingReport.from_dict({
            "id": "X1",
            "title": "t",
            "severity": "HIGH",
            "description": "d",
            "evidence": "not-a-list",
        })
        assert finding.evidence == []

    def test_findings_non_dict_element_skipped(self) -> None:
        """报告级 findings 列表中的非对象元素跳过不崩溃。"""
        report = MobileSecurityReport.from_dict({
            "findings": ["junk", {"id": "X1", "title": "t",
                                  "severity": "HIGH", "description": "d"}],
        })
        assert [f.id for f in report.findings] == ["X1"]

    def test_statistics_non_dict_counts(self) -> None:
        """statistics 的 by_severity/by_category 非对象时转空 dict。"""
        stats = ReportStatistics.from_dict({
            "by_severity": ["HIGH"],
            "by_category": "junk",
            "total_count": "abc",
        })
        assert stats.by_severity == {}
        assert stats.by_category == {}
        assert stats.total_count == 0

    def test_confidence_clamped_to_bounds(self) -> None:
        """confidence 越界截断到 [0, 1]，非法值回退默认。"""
        assert FindingReport.from_dict({"confidence": 5}).confidence == 1.0
        assert FindingReport.from_dict({"confidence": -0.2}).confidence == 0.0
        assert FindingReport.from_dict({"confidence": "abc"}).confidence == 0.5
        assert FindingReport.from_dict({"confidence": 0.7}).confidence == 0.7


class TestValidateSeverityCaseInsensitive:
    """validate 与 from_dict 大小写行为一致性回归。"""

    def test_lowercase_severity_not_warned(self) -> None:
        """severity 为小写 "high" 时 validate 不告警。"""
        report = MobileSecurityReport(
            findings=[
                FindingReport(
                    id="VUL-001", title="t", severity="high", description="d"
                )
            ]
        )
        warnings = report.validate()
        assert not any("severity" in w for w in warnings)

    def test_invalid_severity_still_warned(self) -> None:
        """真正非法的 severity 仍然告警。"""
        report = MobileSecurityReport(
            findings=[
                FindingReport(
                    id="VUL-001", title="t", severity="SUPER", description="d"
                )
            ]
        )
        assert any("非法 severity" in w for w in report.validate())

    def test_confidence_out_of_range_warned(self) -> None:
        """直接构造的越界 confidence 仍被 validate 告警。"""
        report = MobileSecurityReport(
            findings=[
                FindingReport(
                    id="VUL-001", title="t", severity="HIGH", description="d",
                    confidence=1.5,
                )
            ]
        )
        assert any("confidence 超出" in w for w in report.validate())
