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
