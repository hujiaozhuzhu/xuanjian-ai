"""HtmlGenerator 单元测试。

覆盖：生成成功、单文件自包含（无外部 CSS/JS 外链）、XSS 转义、
截图缺失占位、超大图片标注、S7 输出路径白名单、生成后自检失败，
以及回退模型 / 共享模型两种数据来源的兼容性。
截图使用 struct 手工构造的最小合法 PNG（不依赖 PIL）。

说明：``formats`` 包的 ``__init__.py`` 会导入并行开发中的
``excel_generator``；该模块未就绪时会阻断整个包的导入。本测试在导入前
注入一个最小占位模块（仅在真实模块确实不可导入时生效），不改动任何
``__init__.py`` 与其他 Agent 的文件。
"""

from __future__ import annotations

import importlib
import os
import re
import struct
import sys
import types
import zlib
from pathlib import Path
from typing import Tuple

import pytest


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
    html_generator,
)

Evidence = _fallback_models.Evidence
MobileSecurityReport = _fallback_models.MobileSecurityReport
ReproStep = _fallback_models.ReproStep
Screenshot = _fallback_models.Screenshot
TargetAppInfo = _fallback_models.TargetAppInfo
Vulnerability = _fallback_models.Vulnerability
PathNotAllowedError = base_generator.PathNotAllowedError
HtmlGenerator = html_generator.HtmlGenerator
ReportGenerationError = html_generator.ReportGenerationError


def _png_chunk(ctype: bytes, data: bytes) -> bytes:
    """构造带长度与 CRC 的 PNG chunk。"""
    return (
        struct.pack(">I", len(data))
        + ctype
        + data
        + struct.pack(">I", zlib.crc32(ctype + data) & 0xFFFFFFFF)
    )


def _make_png(width: int = 6, height: int = 6, fill: bytes = b"\x4a\x7a\xb3"
              ) -> bytes:
    """手工构造最小合法 PNG（RGB 纯色，8 位色深，不依赖 PIL）。"""
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    row = b"\x00" + fill * width  # 每行前置 filter 字节 0（None）
    raw = row * height
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(raw))
        + _png_chunk(b"IEND", b"")
    )


def _make_big_png(path: Path, min_bytes: int) -> None:
    """构造文件体积超过 min_bytes 的合法 PNG（随机像素不可压缩）。"""
    pixels = min_bytes * 2  # RGB 3 字节/像素，冗余一倍确保超限
    width = 1024
    height = (pixels + width * 3 - 1) // (width * 3)
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw = b"".join(
        b"\x00" + os.urandom(width * 3) for _ in range(height)
    )
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(raw, level=1))
        + _png_chunk(b"IEND", b"")
    )


@pytest.fixture()
def sample_report(tmp_path: Path) -> MobileSecurityReport:
    """构造含 3 个 finding 的示例报告（含 XSS 注入标题与坏截图路径）。"""
    png_path = tmp_path / "shot_ok.png"
    png_path.write_bytes(_make_png())
    target = TargetAppInfo(
        app_name="DemoApp",
        package_name="com.example.demo",
        version_name="1.2.3",
        version_code="123",
        min_sdk="24",
        target_sdk="34",
        file_size="2.4 MB",
        sha256="a" * 64,
    )
    vulns = [
        Vulnerability(
            vuln_id="VULN-001",
            title="<script>alert(1)</script> 硬编码凭据泄露",
            severity="CRITICAL",
            category="数据存储",
            cwe="CWE-798",
            masvs="MASVS-STORAGE-1",
            description=(
                "APK 内存在硬编码口令 <b>superUserPass</b>，"
                "攻击者可离线提取并登录任意账户。"
            ),
            impact="账户完全接管，造成资金与数据损失。",
            components=["com.example.demo.ChangePassword"],
            evidence=[
                Evidence(
                    location="com/example/ChangePassword.java:42",
                    content='String P = "superUserPass";',
                    description="硬编码凭据字段",
                ),
            ],
            reproduction_steps=[
                ReproStep(
                    action="反编译 APK 并搜索关键字",
                    command="apktool d demo.apk -o out"
                    " && grep -rn superUserPass out/",
                    expected="无命中",
                    actual="命中硬编码字符串",
                ),
            ],
            screenshots=[
                Screenshot(
                    path=str(png_path),
                    description="jadx 中的硬编码口令",
                ),
            ],
            poc="adb shell am start -n com.example.demo/.LoginActivity",
            exp="使用提取凭据调用登录接口完成账户接管。",
            fix_suggestions=["移除硬编码凭据", "引入 Keystore 安全存储"],
            references=["https://cwe.mitre.org/data/definitions/798.html"],
        ),
        Vulnerability(
            vuln_id="VULN-002",
            title="Content Provider 未授权访问",
            severity="HIGH",
            category="平台交互",
            cwe="CWE-926",
            masvs="MASVS-PLATFORM-1",
            description="Provider 导出且无权限保护，第三方应用可读取。",
            impact="用户隐私数据批量泄露。",
            components=["com.example.demo.TrackProvider"],
            evidence=[
                Evidence(
                    location="AndroidManifest.xml:31",
                    content='<provider android:exported="true" />',
                ),
            ],
            reproduction_steps=[
                ReproStep(action="查询 provider 数据",
                          command="adb shell content query --uri content://x"),
            ],
            screenshots=[
                Screenshot(path="screenshots/ghost.png",
                           description="provider 配置截图"),
            ],
            poc="adb shell content query --uri content://com.example/x",
            exp="",
            fix_suggestions=["android:exported 置为 false"],
            references=["https://mas.owasp.org/MASVS/"],
        ),
        Vulnerability(
            vuln_id="VULN-003",
            title="弱加密算法（AES/ECB 模式）",
            severity="MEDIUM",
            category="密码学",
            cwe="CWE-327",
            masvs="MASVS-CRYPTO-1",
            description="使用 AES/ECB 模式加密敏感数据。",
            impact="已知明文条件下可推断其余密文字段。",
            components=["com.example.demo.CryptoClass"],
            evidence=[
                Evidence(
                    location="com/example/CryptoClass.java:18",
                    content='Cipher.getInstance("AES/ECB/PKCS5Padding");',
                ),
            ],
            reproduction_steps=[],
            screenshots=[],
            poc="frida -U -f com.example.demo -l hook.js",
            exp="",
            fix_suggestions=["改用 AES/GCM 并随机 IV"],
            references=["https://cwe.mitre.org/data/definitions/327.html"],
        ),
    ]
    return MobileSecurityReport(
        title="DemoApp 渗透测试报告",
        subtitle="自动化扫描 + 人工验证",
        company="玄鉴AI",
        classification="内部资料",
        report_version="V1.0",
        scan_date="2025-06-01",
        target=target,
        environment={"操作系统": "Windows 10", "Python": "3.12"},
        overall_assessment="整体风险为高危，建议立即修复。",
        project_background="内部靶场应用安全评估。",
        test_scope=["com.example.demo"],
        test_methods=["静态分析", "动态调试"],
        cli_commands=["fp_sentinel insight scan demo.apk"],
        vulnerabilities=vulns,
    )


def _render(
    tmp_path: Path,
    report: object,
    evidence_roots: list[Path] | None = None,
) -> Tuple[HtmlGenerator, Path, str]:
    """在白名单目录内生成报告并返回 (generator, 路径, HTML 内容)。

    默认将 tmp_path 设为截图证据白名单根目录（与测试截图位置一致）。
    """
    out_dir = tmp_path / "out"
    gen = HtmlGenerator(
        allowed_roots=[out_dir],
        screenshot_base_dir=tmp_path,
        evidence_roots=evidence_roots if evidence_roots is not None
        else [tmp_path],
    )
    path = gen.generate(report, out_dir / "report.html")
    return gen, path, path.read_text(encoding="utf-8")


class TestGenerateSuccess:
    """生成成功与结构完整性。"""

    def test_generate_success(self, tmp_path, sample_report) -> None:
        gen, path, html = _render(tmp_path, sample_report)
        assert path.is_file()
        assert html.lstrip().startswith("<!DOCTYPE html>")
        assert gen.get_format_name() == "HTML (.html)"
        for vuln_id in ("VULN-001", "VULN-002", "VULN-003"):
            assert f'id="finding-{vuln_id}"' in html
            assert f'href="#finding-{vuln_id}"' in html
        # 唯一一张可用截图：缩略图 src + 灯箱 data-full 各一次
        assert html.count("data:image/png;base64,") == 2

    def test_nav_badges_and_sections(
        self, tmp_path, sample_report
    ) -> None:
        _, _, html = _render(tmp_path, sample_report)
        assert 'data-sev="CRITICAL"' in html
        assert 'data-sev="HIGH"' in html
        assert 'id="search-input"' in html
        assert 'id="theme-toggle"' in html
        assert "目标应用信息" in html
        assert "严重度分布" in html
        assert "附录" in html


class TestSelfContained:
    """单文件自包含：不允许任何外部 CSS/JS 外链。"""

    def test_no_external_resources(self, tmp_path, sample_report) -> None:
        _, path, html = _render(tmp_path, sample_report)
        assert '<script src=' not in html
        assert re.search(r"<link[^>]+href=", html) is None
        assert "@import" not in html
        # 剔除参考链接文本后，不得残留任何 http(s) 外链
        stripped = re.sub(
            r'<ul class="ref-list">.*?</ul>', "", html, flags=re.S
        )
        assert "http://" not in stripped
        assert "https://" not in stripped


class TestXssEscaping:
    """所有动态文本必须经 html.escape 转义。"""

    def test_script_injection_escaped(
        self, tmp_path, sample_report
    ) -> None:
        _, _, html = _render(tmp_path, sample_report)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
        # 描述中的注入标签同样被转义
        assert "<b>superUserPass</b>" not in html
        assert "&lt;b&gt;superUserPass&lt;/b&gt;" in html

    def test_manifest_snippet_escaped(
        self, tmp_path, sample_report
    ) -> None:
        _, _, html = _render(tmp_path, sample_report)
        # 证据代码块中的 XML 片段不得以原始形态出现
        assert '<provider android:exported="true" />' not in html
        assert "&lt;provider" in html


class TestScreenshots:
    """截图嵌入 / 缺失占位 / 超大标注。"""

    def test_missing_screenshot_placeholder(
        self, tmp_path, sample_report
    ) -> None:
        _, _, html = _render(tmp_path, sample_report)
        assert "截图缺失" in html
        assert "文件不存在: screenshots/ghost.png" in html

    def test_embedded_screenshot_attrs(
        self, tmp_path, sample_report
    ) -> None:
        _, _, html = _render(tmp_path, sample_report)
        assert 'class="shot-thumb"' in html
        assert "data-caption=" in html
        # 缺少模型侧 sha256 时应自动计算（16 位十六进制前缀）
        assert re.search(r'data-sha="[0-9a-f]{16}"', html)

    def test_oversize_annotation(self, tmp_path, sample_report) -> None:
        big_path = tmp_path / "shot_big.png"
        _make_big_png(big_path, 5 * 1024 * 1024)
        sample_report.vulnerabilities[2].screenshots.append(
            Screenshot(path=str(big_path), description="超大截图")
        )
        _, _, html = _render(tmp_path, sample_report)
        assert "超大图片" in html

    def test_unsupported_format_placeholder(self, tmp_path) -> None:
        bogus = tmp_path / "fake.png"
        bogus.write_bytes(b"GIF89a-not-a-png")
        report = _minimal_report_with_shot(str(bogus))
        _, _, html = _render(tmp_path, report)
        assert "截图缺失" in html
        assert "不支持的图片格式" in html

    def test_verification_failed_placeholder(self, tmp_path) -> None:
        png = tmp_path / "bad.png"
        png.write_bytes(_make_png())
        shot = Screenshot(path=str(png), description="校验失败截图")
        shot.verification_status = "problem"
        report = _minimal_report_with_shot(str(png), shots=[shot])
        _, _, html = _render(tmp_path, report)
        assert "截图校验未通过" in html

    def test_screenshot_outside_evidence_whitelist(
        self, tmp_path
    ) -> None:
        """截图真实路径不在证据白名单内时，渲染占位框且不嵌入 base64。"""
        png = tmp_path / "outside_whitelist.png"
        png.write_bytes(_make_png())
        report = _minimal_report_with_shot(str(png))
        allowed_root = tmp_path / "evidence"
        allowed_root.mkdir()
        gen, _, html = _render(
            tmp_path, report, evidence_roots=[allowed_root]
        )
        assert "截图缺失" in html
        assert "路径不在证据白名单" in html
        assert "data:image/" not in html
        assert gen._embedded_count == 0
        assert gen._blocked_count == 1


def _minimal_report_with_shot(
    path_str: str, shots: list[Screenshot] | None = None
) -> MobileSecurityReport:
    """构造仅含单 finding 单截图的最小报告。"""
    return MobileSecurityReport(
        title="最小报告",
        vulnerabilities=[
            Vulnerability(
                vuln_id="VULN-100",
                title="截图占位验证",
                severity="LOW",
                screenshots=shots
                if shots is not None
                else [Screenshot(path=path_str, description="占位")],
            ),
        ],
    )


class TestS7Whitelist:
    """输出路径白名单（S7 红线）。"""

    def test_outside_allowed_root_rejected(
        self, tmp_path, sample_report
    ) -> None:
        gen = HtmlGenerator(allowed_roots=[tmp_path / "out"])
        with pytest.raises(PathNotAllowedError):
            gen.generate(sample_report, tmp_path / "escape.html")

    def test_bad_suffix_rejected(self, tmp_path, sample_report) -> None:
        gen = HtmlGenerator(allowed_roots=[tmp_path / "out"])
        with pytest.raises(PathNotAllowedError):
            gen.generate(sample_report, tmp_path / "out" / "report.txt")

    def test_relative_traversal_rejected(
        self, tmp_path, sample_report
    ) -> None:
        gen = HtmlGenerator(allowed_roots=[tmp_path / "out"])
        with pytest.raises(PathNotAllowedError):
            gen.generate(sample_report, tmp_path / "out" / ".." / "up.html")


class TestSharedModelCompatibility:
    """共享模型（models.report_models）来源的兼容性冒烟。"""

    def test_shared_model_findings(self, tmp_path) -> None:
        from fp_sentinel.mobile_reporting.models.report_models import (  # noqa: E501
            EnvironmentInfo,
            Evidence as SharedEvidence,
            FindingReport,
            MobileSecurityReport as SharedReport,
            PocInfo,
            ReportMetadata,
            ReproStep as SharedReproStep,
            ScreenshotRef,
        )

        png_path = tmp_path / "shared_shot.png"
        png_path.write_bytes(_make_png())
        finding = FindingReport(
            id="VULN-201",
            title="<script>alert(1)</script> 共享模型注入",
            severity="HIGH",
            cwe_id="CWE-79",
            owasp_masvs="MASVS-PLATFORM-1",
            description="共享模型字段别名兼容冒烟测试。",
            evidence=[
                SharedEvidence(
                    location="a.java:1", content="<img src=x>"
                ),
            ],
            repro_steps=[
                SharedReproStep(
                    action="步骤一",
                    command="adb shell cmd",
                    expected_result="ok",
                    actual_result="bad",
                ),
            ],
            screenshots=[
                ScreenshotRef(
                    path=str(png_path),
                    caption="共享模型截图",
                    verified=True,
                ),
            ],
            poc=PocInfo(script_content="poc-code-here"),
            remediation="请立即修复。",
            references=["https://example.com/ref"],
        )
        report = SharedReport(
            metadata=ReportMetadata(
                title="共享模型报告", date="2025-07-01"
            ),
            findings=[finding],
            environment=EnvironmentInfo(
                os="Windows", python_version="3.12"
            ),
        )
        _, _, html = _render(tmp_path, report)
        assert 'id="finding-VULN-201"' in html
        assert "<script>alert(1)</script>" not in html
        assert "共享模型报告" in html
        assert "poc-code-here" in html
        assert "请立即修复。" in html
        assert "CWE-79" in html
        assert "data:image/png;base64," in html


class TestSelfCheck:
    """生成后自检失败必须抛 ReportGenerationError。"""

    def test_missing_doctype_raises(self, tmp_path) -> None:
        gen = HtmlGenerator(allowed_roots=[tmp_path])
        fake = [{"anchor": "finding-VULN-001", "screenshots": []}]
        with pytest.raises(ReportGenerationError):
            gen._self_check("<html><body>x</body></html>", fake)

    def test_missing_anchor_raises(self, tmp_path) -> None:
        gen = HtmlGenerator(allowed_roots=[tmp_path])
        fake = [{"anchor": "finding-VULN-001", "screenshots": []}]
        doc = "<!DOCTYPE html><html><body></body></html>"
        with pytest.raises(ReportGenerationError):
            gen._self_check(doc, fake)

    def test_wrong_base64_count_raises(self, tmp_path) -> None:
        gen = HtmlGenerator(allowed_roots=[tmp_path])
        gen._embedded_count = 1  # 模拟已成功嵌入 1 张截图
        fake = [{
            "anchor": "finding-VULN-001",
            "screenshots": [{"state": "ok"}],
        }]
        doc = '<!DOCTYPE html><html><body id="finding-VULN-001">' \
              "</body></html>"
        with pytest.raises(ReportGenerationError):
            gen._self_check(doc, fake)

    def test_evidence_text_with_data_uri_not_misjudged(
        self, tmp_path
    ) -> None:
        """证据文本恰含 "data:image/" 字样时自检不误判、生成不失败。"""
        report = MobileSecurityReport(
            title="data URI 证据文本报告",
            vulnerabilities=[
                Vulnerability(
                    vuln_id="VULN-300",
                    title="证据含 data:image/ 字样",
                    severity="LOW",
                    evidence=[
                        Evidence(
                            location="a.java:1",
                            content=(
                                'log.d("payload", "data:image/png;base64,'
                                'iVBORw0KGgo=");'
                            ),
                        ),
                    ],
                ),
            ],
        )
        # 无截图嵌入（expected=0），文本额外出现 data:image/ 不应报错
        _, _, html = _render(tmp_path, report)
        assert "data:image/png;base64," in html
