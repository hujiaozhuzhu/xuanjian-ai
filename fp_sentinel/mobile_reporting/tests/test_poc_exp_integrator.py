"""core.poc_exp_integrator 单元测试：POC/EXP 集成与安全红线。"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

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

from fp_sentinel.mobile_reporting.core.poc_exp_integrator import (  # noqa: E402
    PocExpIntegrator,
)
from fp_sentinel.mobile_reporting.models import (  # noqa: E402
    FindingReport,
    MobileSecurityReport,
    ReportStatistics,
)

SAFE_SCRIPT = (
    "Java.perform(function() {\n"
    "  var cls = Java.use('com.a.Crypto');\n"
    "  console.log(cls.encrypt('input'));\n"
    "});\n"
)
DANGEROUS_SCRIPT = (
    "var exec = require('child_process');\n"
    "os.system('rm -rf /tmp/payload');\n"
    "send('done');\n"
)


def _finding(fid: str = "VUL-001") -> FindingReport:
    """构造测试 finding。"""
    return FindingReport(
        id=fid, title="测试漏洞", severity="HIGH", description="d"
    )


class TestSafetyCheck:
    """安全红线检查测试。"""

    @pytest.mark.parametrize(
        "snippet,expected",
        [
            ("os.system('ls')", "DANGER"),
            ("subprocess.call(cmd)", "DANGER"),
            ("run('rm -rf /tmp/x')", "DANGER"),
            ("del /q C:\\logs", "DANGER"),
            ("rd /s C:\\dir", "DANGER"),
            ("Remove-Item C:\\x", "DANGER"),
            ("mkfs.ext4 /dev/sda", "DANGER"),
            ("shutdown -h now", "DANGER"),
            ("dd if=/dev/zero of=/dev/sdb", "DANGER"),
            ("format c: /q", "DANGER"),
            ("Java.perform(function(){})", "WARNING"),
            ("Interceptor.attach(addr, cb)", "WARNING"),
            ("console.log('hello')", "SAFE"),
        ],
    )
    def test_levels(self, snippet: str, expected: str) -> None:
        """危险/警示/安全特征正确分级。"""
        level, reasons = PocExpIntegrator.safety_check(snippet)
        assert level == expected
        if expected == "SAFE":
            assert reasons == []
        else:
            assert reasons

    def test_danger_wins_over_warning(self) -> None:
        """同时命中危险与警示特征时取 DANGER。"""
        level, _ = PocExpIntegrator.safety_check(
            "Java.perform(function(){ os.system('id'); });"
        )
        assert level == "DANGER"


class TestAttachPoc:
    """attach_poc 集成测试。"""

    def test_attach_safe_poc(self, tmp_path: Path) -> None:
        """安全 POC 完整集成（内容 + 元数据）。"""
        poc_dir = tmp_path / "poc"
        poc_dir.mkdir()
        script = poc_dir / "vul-001_hook.js"
        script.write_text(SAFE_SCRIPT, encoding="utf-8")
        (poc_dir / "vul-001_hook.json").write_text(
            '{"name": "明文捕获", "type": "frida", "description": "Hook encrypt"}',
            encoding="utf-8",
        )
        finding = _finding()
        integrator = PocExpIntegrator()
        poc = integrator.attach_poc(finding, str(poc_dir))
        assert poc is not None
        assert finding.poc is poc
        assert poc.id == "POC-VUL-001"
        assert poc.name == "明文捕获"
        assert poc.type == "frida"
        assert poc.safety_level in ("SAFE", "WARNING")
        assert poc.script_content == SAFE_SCRIPT
        assert poc.script_path == str(script)

    def test_danger_poc_marked_and_truncated(self, tmp_path: Path) -> None:
        """危险 POC 标记 DANGER 并截断展示（安全红线）。"""
        poc_dir = tmp_path / "poc"
        poc_dir.mkdir()
        script = poc_dir / "vul-002_danger.js"
        payload = "os.system('rm -rf /tmp/payload');\n" * 200
        script.write_text(payload + DANGEROUS_SCRIPT, encoding="utf-8")
        finding = _finding("VUL-002")
        poc = PocExpIntegrator().attach_poc(finding, str(poc_dir))
        assert poc is not None
        assert poc.safety_level == "DANGER"
        assert len(poc.script_content) < len(payload)
        assert "截断" in poc.script_content
        assert "rm -rf" in poc.description

    def test_invalid_poc_dir(self, tmp_path: Path) -> None:
        """目录不存在时返回 None 而不抛异常。"""
        finding = _finding()
        assert PocExpIntegrator().attach_poc(finding, str(tmp_path / "nope")) is None
        assert finding.poc is None

    def test_poc_dir_without_scripts(self, tmp_path: Path) -> None:
        """目录内无脚本时返回 None。"""
        poc_dir = tmp_path / "poc"
        poc_dir.mkdir()
        (poc_dir / "readme.txt").write_text("no scripts", encoding="utf-8")
        finding = _finding()
        assert PocExpIntegrator().attach_poc(finding, str(poc_dir)) is None

    def test_script_not_reused_across_findings(self, tmp_path: Path) -> None:
        """同一脚本不会被重复挂接到多个 finding。"""
        poc_dir = tmp_path / "poc"
        poc_dir.mkdir()
        (poc_dir / "generic_hook.js").write_text(SAFE_SCRIPT, encoding="utf-8")
        integrator = PocExpIntegrator()
        report = MobileSecurityReport(
            findings=[_finding("VUL-001"), _finding("VUL-002")]
        )
        attached = integrator.attach_poc_to_findings(report, str(poc_dir))
        assert list(attached) == ["VUL-001"]
        assert report.findings[1].poc is None


class TestAttachExpAndCoverage:
    """attach_exp 与覆盖统计测试。"""

    def test_attach_exp(self) -> None:
        """EXP 字段完整填入。"""
        finding = _finding()
        integrator = PocExpIntegrator()
        exp = integrator.attach_exp(
            finding,
            {
                "id": "EXP-9",
                "name": "凭据提取利用",
                "preconditions": ["已反编译 APK", "可访问登录页"],
                "steps": ["提取硬编码凭据", "使用凭据登录"],
                "impact": "接管任意账户",
                "mitigation": "移除硬编码凭据",
            },
        )
        assert finding.exp is exp
        assert exp.id == "EXP-9"
        assert exp.preconditions == ["已反编译 APK", "可访问登录页"]
        assert exp.steps == ["提取硬编码凭据", "使用凭据登录"]
        assert exp.impact == "接管任意账户"
        assert exp.mitigation == "移除硬编码凭据"

    def test_attach_exp_defaults(self) -> None:
        """空 EXP 数据时使用默认 id 与名称。"""
        finding = _finding("VUL-007")
        exp = PocExpIntegrator().attach_exp(finding, {})
        assert exp.id == "EXP-VUL-007"
        assert exp.name == "VUL-007 受控利用"

    def test_update_coverage(self, tmp_path: Path) -> None:
        """coverage_metrics 正确写入 statistics。"""
        poc_dir = tmp_path / "poc"
        poc_dir.mkdir()
        (poc_dir / "vul-001.js").write_text(DANGEROUS_SCRIPT, encoding="utf-8")
        (poc_dir / "vul-002.js").write_text(SAFE_SCRIPT, encoding="utf-8")
        findings = [_finding("VUL-001"), _finding("VUL-002"), _finding("VUL-003")]
        report = MobileSecurityReport(
            findings=findings, statistics=ReportStatistics()
        )
        integrator = PocExpIntegrator()
        integrator.attach_poc(findings[0], str(poc_dir))
        integrator.attach_poc(findings[1], str(poc_dir))
        integrator.attach_exp(findings[1], {"steps": ["s1"]})
        metrics = integrator.update_coverage(report)
        assert metrics["poc_findings"] == 2
        assert metrics["exp_findings"] == 1
        assert abs(metrics["poc_coverage"] - 2 / 3) < 1e-4
        assert abs(metrics["exp_coverage"] - 1 / 3) < 1e-4
        assert metrics["danger_poc_count"] == 1
        assert report.statistics.coverage_metrics["poc_findings"] == 2

    def test_update_coverage_creates_statistics(self) -> None:
        """statistics 缺失时自动创建。"""
        report = MobileSecurityReport(findings=[_finding()])
        metrics = PocExpIntegrator().update_coverage(report)
        assert report.statistics is not None
        assert metrics["poc_coverage"] == 0.0

    def test_update_coverage_empty_report(self) -> None:
        """空报告覆盖率为 0。"""
        report = MobileSecurityReport()
        metrics = PocExpIntegrator().update_coverage(report)
        assert metrics["poc_coverage"] == 0.0
        assert metrics["exp_coverage"] == 0.0
