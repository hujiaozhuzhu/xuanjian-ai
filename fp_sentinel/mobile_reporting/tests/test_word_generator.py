"""WordGenerator（Word 安全审计报告生成器）单元测试。

覆盖：生成成功、章节完整性、截图正常嵌入、截图缺失占位、CRITICAL 级 POC
截断警示、S7 路径白名单（目录越界 / 后缀不允许）以及生成后自检。

说明：``formats`` 包的 ``__init__.py`` 会导入并行开发中的
``excel_generator``；该模块未就绪时会阻断整个包的导入。本测试在导入前
注入一个最小占位模块（仅在真实模块确实不可导入时生效），不改动任何
``__init__.py`` 与其他 Agent 的文件。
"""

from __future__ import annotations

import importlib
import struct
import sys
import types
import zlib
from pathlib import Path

import pytest
from docx import Document


def _bootstrap_parallel_modules() -> None:
    """为并行开发中尚不存在的 excel_generator 注入最小占位模块。"""
    module_name = "fp_sentinel.mobile_reporting.formats.excel_generator"
    try:
        importlib.import_module(module_name)
        return
    except ModuleNotFoundError:
        pass
    if module_name not in sys.modules:
        stub = types.ModuleType(module_name)
        stub.OPENPYXL_AVAILABLE = False  # type: ignore[attr-defined]
        stub.ExcelReportGenerator = type(  # type: ignore[attr-defined]
            "ExcelReportGenerator", (), {"__doc__": "并行开发期间的导入占位"}
        )
        sys.modules[module_name] = stub


_bootstrap_parallel_modules()

from fp_sentinel.mobile_reporting.formats import (  # noqa: E402
    _fallback_models,
    base_generator,
    word_generator,
)

Evidence = _fallback_models.Evidence
MobileSecurityReport = _fallback_models.MobileSecurityReport
ReproStep = _fallback_models.ReproStep
Screenshot = _fallback_models.Screenshot
TargetAppInfo = _fallback_models.TargetAppInfo
Vulnerability = _fallback_models.Vulnerability
PathNotAllowedError = base_generator.PathNotAllowedError
ReportGenerationError = word_generator.ReportGenerationError
WordGenerator = word_generator.WordGenerator

_WNS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"

EXPECTED_H1 = [
    "1. 概述与声明",
    "2. 执行摘要",
    "3. 详细漏洞分析",
    "4. 附录A 测试环境",
    "5. 附录B 术语表",
    "6. 文档信息",
]


def _make_min_png(path: Path, width: int = 120, height: int = 80) -> Path:
    """用 struct 手工构造最小合法 PNG（签名 + IHDR + IEND），不依赖 PIL。"""

    def chunk(chunk_type: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(
            ">I", crc
        )

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    payload = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IEND", b"")
    path.write_bytes(payload)
    return path


def _build_report(png_path: Path, missing_png: Path) -> MobileSecurityReport:
    """构造含 3 个 finding（CRITICAL/HIGH/LOW）的示例报告。"""
    critical_poc = "\n".join(
        f"print('POC_LINE_{i:02d}')" for i in range(1, 16)
    )
    findings = [
        Vulnerability(
            vuln_id="VULN-001",
            title="硬编码凭据泄露",
            severity="CRITICAL",
            category="数据存储",
            cwe="CWE-798",
            masvs="MASVS-STORAGE-1",
            description="应用源码中存在硬编码超级用户口令，可被离线提取。",
            impact="攻击者可完全接管任意账户，造成资金损失与数据泄露。",
            components=["com.example.ChangePassword"],
            evidence=[
                Evidence(
                    location="com/example/ChangePassword.java:42",
                    content='private static final String PWD = "superSecret";',
                    description="硬编码口令常量定义。",
                ),
            ],
            reproduction_steps=[
                ReproStep(
                    action="使用 apktool 反编译目标 APK",
                    command="apktool d app.apk -o out",
                    expected="生成 smali 与资源文件",
                    actual="反编译成功",
                ),
            ],
            screenshots=[
                Screenshot(
                    path=str(png_path),
                    description="反编译视图中的硬编码口令",
                ),
            ],
            poc=critical_poc,
            exp="",
            fix_suggestions=["移除硬编码凭据，改用服务端认证"],
            references=["https://cwe.mitre.org/data/definitions/798.html"],
        ),
        Vulnerability(
            vuln_id="VULN-002",
            title="Content Provider 未授权访问",
            severity="HIGH",
            category="平台交互",
            cwe="CWE-926",
            masvs="MASVS-PLATFORM-1",
            description="provider 声明为 exported 且无权限保护。",
            impact="恶意应用可静默读取用户数据。",
            evidence=[
                Evidence(
                    location="AndroidManifest.xml:31",
                    content='<provider android:exported="true" />',
                ),
            ],
            reproduction_steps=[
                ReproStep(
                    action="查询 provider 数据",
                    command="adb shell content query --uri content://x/y",
                    expected="拒绝访问",
                    actual="返回全部记录",
                ),
            ],
            screenshots=[
                Screenshot(
                    path=str(missing_png),
                    description="provider 导出配置截图",
                ),
            ],
            poc="adb shell content query --uri content://x/y",
            fix_suggestions=["显式关闭 exported 或配置签名级权限"],
        ),
        Vulnerability(
            vuln_id="VULN-003",
            title="应用可调试",
            severity="LOW",
            category="应用配置",
            cwe="CWE-489",
            masvs="MASVS-RESILIENCE-2",
            description="发布版 debuggable 属性为 true。",
            impact="降低逆向与运行时篡改成本。",
            evidence=[
                Evidence(
                    location="AndroidManifest.xml:7",
                    content='debuggable="true"',
                )
            ],
            reproduction_steps=[
                ReproStep(
                    action="检查 debuggable 属性",
                    command="aapt dump badging app.apk | grep debuggable",
                    expected="无标记",
                    actual="命中 debuggable",
                ),
            ],
            poc="adb shell run-as com.example ls databases/",
            fix_suggestions=["发布构建移除 debuggable"],
        ),
    ]
    target = TargetAppInfo(
        app_name="DemoApp",
        package_name="com.example.demo",
        version_name="1.2.3",
        version_code="123",
        min_sdk="21",
        target_sdk="33",
        file_size="2.3 MB",
        sha256="ab" * 32,
    )
    return MobileSecurityReport(
        title="DemoApp 移动应用渗透测试报告",
        subtitle="基于静态分析与动态调试的综合性安全评估",
        company="玄鉴信息安全技术有限公司",
        classification="内部资料",
        report_version="V1.0",
        scan_date="2025-06-01",
        test_start_time="2025-06-01 09:00",
        test_end_time="2025-06-02 18:00",
        project_background="针对 DemoApp 的授权渗透测试。",
        test_scope=["com.example.demo 静态与动态分析"],
        test_methods=["静态分析", "动态调试", "人工验证"],
        target=target,
        environment={"操作系统": "Windows 10", "Python": "3.12"},
        vulnerabilities=findings,
        overall_assessment="存在严重级别漏洞，总体风险为高风险。",
    )


@pytest.fixture()
def sample_report(tmp_path: Path) -> MobileSecurityReport:
    """示例报告：含真实 PNG 截图与一个路径不存在的截图引用。"""
    png_path = _make_min_png(tmp_path / "evidence_vuln001.png")
    missing_png = tmp_path / "not_exist.png"
    return _build_report(png_path, missing_png)


@pytest.fixture()
def generator(tmp_path: Path) -> WordGenerator:
    """白名单限定为 tmp_path 的 WordGenerator。"""
    return WordGenerator(allowed_roots=[tmp_path])


def _generate(
    generator: WordGenerator,
    sample_report: MobileSecurityReport,
    tmp_path: Path
) -> Path:
    return generator.generate(sample_report, tmp_path / "audit_report.docx")


def _doc_text(doc: Document) -> str:
    """汇总段落与表格文本，便于全文断言。"""
    parts = [p.text for p in doc.paragraphs]
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                parts.append(cell.text)
    return "\n".join(parts)


# ───────────────────────────── 用例 ─────────────────────────────


def test_generate_success(
    generator: WordGenerator,
    sample_report: MobileSecurityReport,
    tmp_path: Path
) -> None:
    """生成成功：返回绝对路径、文件存在且非空。"""
    out = _generate(generator, sample_report, tmp_path)
    assert out.is_absolute()
    assert out.exists()
    assert out.suffix == ".docx"
    assert out.stat().st_size > 0


def test_chapter_structure(
    generator: WordGenerator,
    sample_report: MobileSecurityReport,
    tmp_path: Path
) -> None:
    """章节完整性：6 个 Heading1、段落数 > 50、关键内容齐全。"""
    out = _generate(generator, sample_report, tmp_path)
    doc = Document(str(out))
    h1_texts = [p.text for p in doc.paragraphs if p.style.name == "Heading 1"]
    assert h1_texts == EXPECTED_H1
    assert len(doc.paragraphs) > 50

    text = _doc_text(doc)
    for keyword in (
        "密级：内部资料",
        "测试范围",
        "测试方法",
        "免责声明",
        "总体风险评级",
        "严重度分布统计",
        "关键发现",
        "3.1 VULN-001",
        "3.2 VULN-002",
        "3.3 VULN-003",
        "复现步骤",
        "修复建议",
        "参考链接",
        "术语表",
        "版本记录",
        "CRITICAL",
    ):
        assert keyword in text, f"缺少关键内容: {keyword}"
    assert "VULN-999" not in text


def test_screenshot_embedded(
    generator: WordGenerator,
    sample_report: MobileSecurityReport,
    tmp_path: Path
) -> None:
    """真实截图应被 add_picture 嵌入并带规范图注。"""
    out = _generate(generator, sample_report, tmp_path)
    doc = Document(str(out))
    assert len(doc.inline_shapes) >= 1
    text = _doc_text(doc)
    assert "图 1-1" in text
    assert "反编译视图中的硬编码口令" in text


def test_screenshot_missing_placeholder(
    generator: WordGenerator,
    sample_report: MobileSecurityReport,
    tmp_path: Path
) -> None:
    """截图文件不存在时插入占位段落，且不产生空白或错误图片。"""
    out = _generate(generator, sample_report, tmp_path)
    doc = Document(str(out))
    text = _doc_text(doc)
    assert "截图缺失" in text
    assert "not_exist.png" in text
    # 缺失截图不应生成图注
    assert "图 2-1" not in text
    # 全文仅 1 张嵌入图片（VULN-001 的真实截图）
    assert len(doc.inline_shapes) == 1


def test_critical_poc_truncated(
    generator: WordGenerator,
    sample_report: MobileSecurityReport,
    tmp_path: Path
) -> None:
    """CRITICAL 级 POC 只展示前 10 行并附警示语与截断说明。"""
    out = _generate(generator, sample_report, tmp_path)
    doc = Document(str(out))
    text = _doc_text(doc)
    assert "警示" in text
    assert "前 10 行" in text
    assert "POC_LINE_10" in text
    assert "POC_LINE_11" not in text
    assert "共 15 行" in text


def test_low_severity_poc_full(
    generator: WordGenerator,
    sample_report: MobileSecurityReport,
    tmp_path: Path
) -> None:
    """非 CRITICAL 级 POC 完整展示。"""
    out = _generate(generator, sample_report, tmp_path)
    doc = Document(str(out))
    text = _doc_text(doc)
    assert "adb shell run-as com.example ls databases/" in text


def test_s7_whitelist_rejects_outside_root(
    sample_report: MobileSecurityReport, tmp_path: Path
) -> None:
    """S7 红线：输出路径逃逸出白名单根目录时抛 PathNotAllowedError。"""
    restricted_root = tmp_path / "reports"
    generator = WordGenerator(allowed_roots=[restricted_root])
    outside = tmp_path / "outside.docx"
    with pytest.raises(PathNotAllowedError):
        generator.generate(sample_report, outside)
    assert not outside.exists()


def test_s7_whitelist_rejects_bad_suffix(
    generator: WordGenerator,
    sample_report: MobileSecurityReport,
    tmp_path: Path
) -> None:
    """S7 红线：输出后缀不在允许集合内时抛 PathNotAllowedError。"""
    with pytest.raises(PathNotAllowedError):
        generator.generate(sample_report, tmp_path / "report.exe")


def test_self_check_raises_on_incomplete_doc(
    generator: WordGenerator,
    sample_report: MobileSecurityReport,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """生成后自检：文档构成不达标（段落数<=50）时抛 ReportGenerationError。"""
    monkeypatch.setattr(
        WordGenerator, "_build_findings", lambda self, report: None
    )
    monkeypatch.setattr(
        WordGenerator, "_build_summary", lambda self, report: None
    )
    monkeypatch.setattr(
        WordGenerator, "_build_overview", lambda self, report: None
    )
    with pytest.raises(ReportGenerationError):
        _generate(generator, sample_report, tmp_path)


def test_severity_distribution_colored(
    generator: WordGenerator,
    sample_report: MobileSecurityReport,
    tmp_path: Path
) -> None:
    """严重度分布统计表应存在且单元格带底色（w:shd fill）。"""
    out = _generate(generator, sample_report, tmp_path)
    doc = Document(str(out))
    target_table = None
    for table in doc.tables:
        headers = [cell.text for cell in table.rows[0].cells]
        if headers == ["严重程度", "数量"]:
            target_table = table
            break
    assert target_table is not None, "未找到严重度分布统计表"
    fills: list = []
    for row in target_table.rows[1:6]:
        tc_pr = row.cells[0]._tc.tcPr
        assert tc_pr is not None, "严重度单元格缺少底纹"
        shd = tc_pr.findall(_WNS + "shd")
        assert shd, "严重度单元格缺少 w:shd 元素"
        fills.append(shd[0].get(_WNS + "fill"))
    assert fills[0] == "8B1A1A"  # CRITICAL 深红
    assert fills[1] == "C00000"  # HIGH 红
    assert fills[2] == "E36C0A"  # MEDIUM 橙
    assert fills[4] == "2E74B5"  # INFO 蓝


# ─────────────────────── 健壮性回归测试 ───────────────────────


def test_empty_findings_report_generates(
    generator: WordGenerator, tmp_path: Path
) -> None:
    """空 findings 的合法报告能成功生成且自检通过。"""
    report = MobileSecurityReport(
        title="空报告自检",
        vulnerabilities=[],
    )
    out = generator.generate(report, tmp_path / "empty.docx")
    assert out.exists()
    doc = Document(str(out))
    h1_texts = [p.text for p in doc.paragraphs if p.style.name == "Heading 1"]
    assert len(h1_texts) == 6
    assert len(doc.tables) >= 1
    assert len(doc.paragraphs) >= 10
    text = _doc_text(doc)
    assert "本次测试未发现" in text


def test_string_evidence_rendered(
    generator: WordGenerator, tmp_path: Path
) -> None:
    """evidence 为字符串列表时应作为代码内容正确展示。"""
    vuln = Vulnerability(
        vuln_id="VULN-STR",
        title="字符串证据展示",
        severity="MEDIUM",
        evidence=["adb shell dumpsys package com.example", "const X = 1;"],
    )
    report = MobileSecurityReport(
        title="字符串证据", vulnerabilities=[vuln]
    )
    out = generator.generate(report, tmp_path / "str_evidence.docx")
    text = _doc_text(Document(str(out)))
    assert "证据 1 位置：未知位置" in text
    assert "adb shell dumpsys package com.example" in text
    assert "const X = 1;" in text


def test_unknown_severity_counted_as_unknown(
    generator: WordGenerator, tmp_path: Path
) -> None:
    """脏 severity（含首尾空格的合法值 / 未知值）统计不崩溃且未知值入"未知"列。"""
    vulns = [
        Vulnerability(
            vuln_id="VULN-U1",
            title="带空格的高危",
            severity="  HIGH  ",
        ),
        Vulnerability(
            vuln_id="VULN-U2",
            title="未知等级",
            severity="WEIRD",
        ),
    ]
    report = MobileSecurityReport(
        title="未知severity", vulnerabilities=vulns
    )
    out = generator.generate(report, tmp_path / "unknown_sev.docx")
    doc = Document(str(out))
    text = _doc_text(doc)
    # "  HIGH  " 被 strip/upper 后计入 HIGH，而非产生未知行之外的脏键
    assert "[HIGH]" in text
    # 未知值计入"未知"列
    assert "未知" in text
    table = next(
        t for t in doc.tables
        if [c.text for c in t.rows[0].cells] == ["严重程度", "数量"]
    )
    rows = {r.cells[0].text: r.cells[1].text for r in table.rows[1:]}
    assert rows["HIGH"] == "1"
    assert rows["未知"] == "1"
    assert rows["合计"] == "2"
