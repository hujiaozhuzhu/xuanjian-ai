"""core.data_collector 单元测试：扫描产物 JSON -> MobileSecurityReport。"""

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

from fp_sentinel.mobile_reporting.core.data_collector import (  # noqa: E402
    DataCollector,
)


def _insight_dict() -> dict:
    """构造 mobile_insight 风格的产物 dict。"""
    return {
        "target": "demo.apk",
        "duration_sec": 2.5,
        "insights": [
            {
                "id": "INS-1",
                "title": "AES/ECB 弱加密",
                "category": "CRYPTO",
                "severity": "HIGH",
                "confidence": 0.8,
                "description": "使用 ECB 模式加密敏感数据",
                "code_reference": {"file": "com/a/Crypto.java", "line": 18},
                "cwe_ids": ["CWE-327"],
                "masvs_refs": ["MASVS-CRYPTO-1"],
                "evidence": ['Cipher.getInstance("AES/ECB/PKCS5Padding")'],
                "references": ["https://cwe.mitre.org/data/definitions/327.html"],
                "fix_hint": "改用 AES/GCM",
            },
            {
                "id": "INS-2",
                "title": "日志泄露用户名",
                "category": "STORAGE",
                "confidence": 0.6,
                "description": "Log.d 输出用户名",
                "code_reference": {"file": "com/a/Login.java", "line": 57},
            },
        ],
    }


def _hook_dict() -> dict:
    """构造 mobile_hook 风格的产物 dict。"""
    return {
        "package_name": "com.demo",
        "techniques": [
            {
                "technique": "base64",
                "success": True,
                "duration_ms": 1200.0,
                "hook_points": [
                    {
                        "class_name": "com.a.Crypto",
                        "method_name": "encrypt",
                        "param_signature": "(Ljava/lang/String;)",
                        "technique": "base64",
                        "confidence": 0.9,
                        "reason": "命中 Base64 编码调用",
                        "strings_matched": ["secret"],
                    }
                ],
            }
        ],
    }


TARGET_INFO = {
    "name": "demo",
    "package": "com.demo",
    "version": "1.0",
    "sha256": "c" * 64,
    "scan_command": "fp_sentinel insight scan demo.apk --sensitive",
}


class TestCollect:
    """主流程收集测试。"""

    def test_full_collection(self) -> None:
        """insight + hook 产物正确聚合为报告。"""
        collector = DataCollector(tool_version="4.0.0")
        report = collector.from_scan_outputs(
            insight_json=_insight_dict(),
            hook_json=_hook_dict(),
            target_info=TARGET_INFO,
        )
        assert len(report.findings) == 3
        ids = [f.id for f in report.findings]
        assert ids == ["INS-1", "INS-2", "HOOK-0101"]
        first = report.findings[0]
        assert first.severity == "HIGH"
        assert first.category == "密码学"
        assert first.cwe_id == "CWE-327"
        assert first.owasp_masvs == "MASVS-CRYPTO-1"
        assert first.evidence[0].location == "com/a/Crypto.java:18"
        assert first.evidence[0].source == "静态"
        assert first.tool_version == "4.0.0"
        assert abs(first.confidence - 0.8) < 1e-9

    def test_statistics_auto_computed(self) -> None:
        """by_severity / by_category / 总耗时自动统计。"""
        report = DataCollector().from_scan_outputs(
            insight_json=_insight_dict(),
            hook_json=_hook_dict(),
            target_info=TARGET_INFO,
        )
        stats = report.statistics
        assert stats is not None
        assert stats.total_count == 3
        assert stats.by_severity == {"HIGH": 1, "MEDIUM": 2}
        assert stats.by_category == {"密码学": 1, "数据存储": 1, "动态行为": 1}
        # 2.5s (insight) + 1.2s (hook technique)
        assert abs(stats.scan_duration_seconds - 3.7) < 0.01

    def test_repro_steps_generated(self) -> None:
        """每个 finding 自动生成扫描命令回放复现步骤。"""
        report = DataCollector().from_scan_outputs(
            insight_json=_insight_dict(), target_info=TARGET_INFO
        )
        for finding in report.findings:
            assert finding.repro_steps, finding.id
            step = finding.repro_steps[0]
            assert "fp_sentinel" in step.command
            assert step.expected_result

    def test_environment_and_metadata(self) -> None:
        """环境信息与元信息来自 target_info。"""
        report = DataCollector().from_scan_outputs(
            insight_json=_insight_dict(), target_info=TARGET_INFO
        )
        env = report.environment
        assert env is not None
        assert env.target_app is not None
        assert env.target_app.name == "demo"
        assert env.target_app.package == "com.demo"
        assert env.target_app.sha256 == "c" * 64
        assert env.python_version
        assert env.scan_command == TARGET_INFO["scan_command"]
        assert report.metadata.title == "demo 移动安全评估报告"

    def test_poc_attached_by_vuln_id(self) -> None:
        """poc_json 按 metadata.vuln_id 挂接到对应 finding。"""
        poc_dict = {
            "results": [
                {
                    "success": True,
                    "template": "java/basic_hook.js.tmpl",
                    "goal": "plaintext-capture",
                    "language": "js",
                    "script": "Java.perform(function() { console.log('x'); });",
                    "script_path": "out/poc/basic_hook.js",
                    "metadata": {"vuln_id": "INS-1"},
                }
            ]
        }
        report = DataCollector().from_scan_outputs(
            insight_json=_insight_dict(), poc_json=poc_dict
        )
        poc = report.findings[0].poc
        assert poc is not None
        assert poc.id == "POC-INS-1"
        assert poc.type == "frida"
        assert poc.safety_level in ("SAFE", "WARNING")


class TestTolerance:
    """字段缺失宽容处理测试。"""

    def test_missing_fields_warn_not_crash(self) -> None:
        """severity 缺失/非法时降级为 MEDIUM 并记录 warning。"""
        collector = DataCollector()
        report = collector.from_scan_outputs(
            insight_json=_insight_dict(), target_info=TARGET_INFO
        )
        assert report.findings[1].severity == "MEDIUM"
        assert any("INS-2" in w for w in collector.warnings)

    def test_none_inputs(self) -> None:
        """全空输入产出空报告且不抛异常。"""
        collector = DataCollector()
        report = collector.from_scan_outputs(target_info=None)
        assert report.findings == []
        assert report.statistics.total_count == 0

    def test_invalid_json_string(self) -> None:
        """非法 JSON 字符串降级为空 dict 并记录 warning。"""
        collector = DataCollector()
        report = collector.from_scan_outputs(
            insight_json="{not-json", target_info=TARGET_INFO
        )
        assert report.findings == []
        assert collector.warnings

    def test_hook_without_techniques(self) -> None:
        """hook 产物缺 techniques 时记录 warning。"""
        collector = DataCollector()
        collector.from_scan_outputs(hook_json={"package_name": "com.demo"})
        assert any("techniques" in w for w in collector.warnings)

    def test_non_dict_items_skipped(self) -> None:
        """产物中的非对象元素被跳过并记录 warning。"""
        collector = DataCollector()
        report = collector.from_scan_outputs(
            insight_json={"insights": ["oops", 42]}, target_info=TARGET_INFO
        )
        assert report.findings == []
        assert len(collector.warnings) >= 2

    def test_load_from_json_file(self, tmp_path: Path) -> None:
        """支持直接传 JSON 文件路径。"""
        path = tmp_path / "insight.json"
        path.write_text(
            json.dumps(_insight_dict(), ensure_ascii=False), encoding="utf-8"
        )
        collector = DataCollector()
        report = collector.from_scan_outputs(
            insight_json=str(path), target_info=TARGET_INFO
        )
        assert len(report.findings) == 2
        # 文件路径加载本身不应引入额外 warning（INS-2 的容错告警除外）
        assert all("文件" not in w for w in collector.warnings)


# ---------------------------------------------------------------------------
# 脏数据健壮性回归（metadata / evidence / script_content）
# ---------------------------------------------------------------------------


class TestDirtyDataRobustness:
    """脏 JSON 输入不崩溃回归。"""

    def test_poc_metadata_non_dict_no_crash(self) -> None:
        """poc results 的 metadata 为字符串时不崩溃并记录 warning。"""
        collector = DataCollector()
        report = collector.from_scan_outputs(
            insight_json={"insights": [
                {"id": "INS-1", "title": "t", "severity": "HIGH",
                 "description": "d"}
            ]},
            poc_json={"results": [
                {"goal": "演示", "script": "console.log(1)",
                 "metadata": "not-a-dict", "vuln_id": None},
            ]},
            target_info=TARGET_INFO,
        )
        assert report.findings
        assert any("metadata 不是对象" in w for w in collector.warnings)

    def test_poc_metadata_dict_still_attaches(self) -> None:
        """metadata 为合法 dict 时正常挂接（不回归）。"""
        collector = DataCollector()
        report = collector.from_scan_outputs(
            insight_json={"insights": [
                {"id": "INS-1", "title": "t", "severity": "HIGH",
                 "description": "d"}
            ]},
            poc_json={"results": [
                {"goal": "演示", "script": "console.log(1)",
                 "metadata": {"vuln_id": "INS-1"}},
            ]},
            target_info=TARGET_INFO,
        )
        assert report.findings[0].poc is not None
        assert report.findings[0].poc.id == "POC-INS-1"

    def test_evidence_string_wrapped_as_single_evidence(self) -> None:
        """evidence 为字符串时包装为单条证据。"""
        collector = DataCollector()
        report = collector.from_scan_outputs(
            insight_json={"insights": [
                {"id": "INS-1", "title": "t", "severity": "HIGH",
                 "description": "d", "evidence": "Cipher.getInstance(...)"},
            ]},
            target_info=TARGET_INFO,
        )
        evidence = report.findings[0].evidence
        assert len(evidence) == 1
        assert evidence[0].content == "Cipher.getInstance(...)"

    def test_evidence_list_non_scalar_filtered(self) -> None:
        """evidence 列表中标量正常转 str，不因脏元素崩溃。"""
        collector = DataCollector()
        report = collector.from_scan_outputs(
            insight_json={"insights": [
                {"id": "INS-1", "title": "t", "severity": "HIGH",
                 "description": "d", "evidence": [123, "plain"]},
            ]},
            target_info=TARGET_INFO,
        )
        evidence = report.findings[0].evidence
        assert evidence[0].content == "123"
        assert evidence[0].description == "d"

    def test_poc_script_content_truncated_for_display(self) -> None:
        """超长 POC 脚本全文按安全级别截断放入 PocInfo。"""
        long_script = "console.log('safe line');\n" * 400  # > 5000 字符
        collector = DataCollector()
        report = collector.from_scan_outputs(
            insight_json={"insights": [
                {"id": "INS-1", "title": "t", "severity": "HIGH",
                 "description": "d"}
            ]},
            poc_json={"results": [
                {"goal": "长脚本", "script": long_script,
                 "metadata": {"vuln_id": "INS-1"}},
            ]},
            target_info=TARGET_INFO,
        )
        poc = report.findings[0].poc
        assert poc is not None
        assert len(poc.script_content) < len(long_script)
        assert "已截断" in poc.script_content
