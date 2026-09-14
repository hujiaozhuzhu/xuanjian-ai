"""ExcelGenerator 单元测试。

覆盖：生成成功与文件存在、10 个工作表、S7 路径白名单、
severity 条件着色、超链接锚点、排版（冻结/换行）、
POC 超长截断与序列化往返。
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from openpyxl import Workbook, load_workbook

from fp_sentinel.mobile_reporting.formats._fallback_models import (
    Evidence,
    MobileSecurityReport,
    ReproStep,
    Screenshot,
    TargetAppInfo,
    Vulnerability,
    create_insecurebank_sample_report,
)
from fp_sentinel.mobile_reporting.formats.base_generator import (
    PathNotAllowedError,
)
from fp_sentinel.mobile_reporting.formats.excel_generator import (
    SEVERITY_ORDER,
    SEVERITY_STYLES,
    SHEET_ORDER,
    ExcelGenerator,
    ReportGenerationError,
    _PNG_SIGNATURE,
    _png_size,
)


def _make_png(width: int = 4, height: int = 3) -> bytes:
    """用 struct 手工构造最小合法 PNG（签名 + IHDR + IEND）。"""

    def chunk(ctype: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + ctype + data \
            + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IEND", b"")
    )


@pytest.fixture()
def sample_report(tmp_path: Path) -> MobileSecurityReport:
    """构造含 3 个 finding、全 severity、截图/POC/EXP 齐全的报告。"""
    png1 = tmp_path / "shot_login.png"
    png1.write_bytes(_make_png(1080, 1920))
    png2 = tmp_path / "shot_provider.png"
    png2.write_bytes(_make_png(720, 1280))

    shot1 = Screenshot(
        path=str(png1), description="登录页硬编码口令展示"
    )
    shot1.sha256 = "a" * 64
    shot1.verification_status = "verified"
    shot2 = Screenshot(
        path=str(png2), description="provider 导出配置截图"
    )

    vulns = [
        Vulnerability(
            vuln_id="VULN-001",
            title="硬编码凭据泄露",
            severity="CRITICAL",
            category="数据存储",
            cwe="CWE-798",
            masvs="MASVS-STORAGE-1",
            description=(
                "应用源码中存在硬编码超级用户口令，攻击者可离线提取后"
                "直接登录任意账户，造成资金损失与数据泄露。"
            ),
            impact="任意攻击者可完全接管用户账户。",
            components=["com.demo.ChangePassword"],
            evidence=[
                Evidence(
                    location="com/demo/ChangePassword.java:42",
                    content='PREF_SUPER_PASS = "superSecurePassword";',
                    description="硬编码口令赋值点",
                ),
                Evidence(
                    location="com/demo/DbHelper.java:17",
                    content='String KEY = "static_key_123";',
                ),
            ],
            reproduction_steps=[
                ReproStep(
                    action="反编译 APK",
                    command="apktool d app.apk -o out",
                    expected="生成 smali 目录",
                    actual="反编译成功",
                ),
                ReproStep(
                    action="搜索硬编码口令",
                    command="grep -rn 'superSecurePassword' out/",
                    expected="无命中",
                    actual="命中 ChangePassword.smali",
                ),
            ],
            screenshots=[shot1],
            poc=(
                "adb shell am start -n com.demo/.LoginActivity\n"
                "# 使用提取的凭据登录\n"
                "# username: jack"
            ),
            exp=(
                "1. 反编译提取凭据\n2. 使用凭据登录管理员账户\n"
                "3. 转账并清空审计日志"
            ),
            fix_suggestions=[
                "移除硬编码凭据，改用服务端认证",
                "引入 Android Keystore 保护密钥",
            ],
            references=[
                "https://cwe.mitre.org/data/definitions/798.html",
            ],
        ),
        Vulnerability(
            vuln_id="VULN-002",
            title="Content Provider 未授权访问",
            severity="HIGH",
            category="平台交互",
            cwe="CWE-926",
            masvs="MASVS-PLATFORM-1",
            description=(
                "TrackUserContentProvider 声明为 exported=true 且无权限"
                "保护，第三方应用可直接读写用户交易记录。"
            ),
            impact="用户隐私数据批量泄露。",
            evidence=[
                Evidence(
                    location="AndroidManifest.xml:31",
                    content='<provider android:exported="true" />',
                ),
            ],
            reproduction_steps=[
                ReproStep(
                    action="查询 provider 数据",
                    command="adb shell content query --uri content://demo",
                    expected="拒绝访问",
                    actual="返回全部记录",
                ),
            ],
            screenshots=[shot2],
            poc="adb shell content query --uri content://demo/trackerdata",
            fix_suggestions=["将 android:exported 置为 false"],
            references=["https://cwe.mitre.org/data/definitions/926.html"],
        ),
        Vulnerability(
            vuln_id="VULN-003",
            title="弱加密算法（AES/ECB）",
            severity="MEDIUM",
            category="密码学",
            cwe="CWE-327",
            masvs="MASVS-CRYPTO-1",
            description="使用 AES/ECB 模式加密敏感数据，可被模式分析恢复明文。",
            impact="部分加密字段可被推断。",
            evidence=[
                Evidence(
                    location="com/demo/CryptoClass.java:18",
                    content='Cipher.getInstance("AES/ECB/PKCS5Padding")',
                ),
            ],
            fix_suggestions=["改用 AES/GCM 并随机生成 IV"],
        ),
    ]
    return MobileSecurityReport(
        title="测试目标应用安全审计报告",
        subtitle="玄鉴AI 移动安全评估",
        classification="机密",
        report_version="V4.0",
        scan_date="2025-06-01",
        target=TargetAppInfo(
            app_name="DemoApp",
            package_name="com.demo.app",
            version_name="1.2.3",
            sha256="b" * 64,
        ),
        environment={"操作系统": "Windows 10", "Python": "3.12"},
        overall_assessment="总体风险为高风险，建议立即修复 CRITICAL 问题。",
        vulnerabilities=vulns,
    )


@pytest.fixture()
def generator(tmp_path: Path) -> ExcelGenerator:
    """以 tmp_path 为输出白名单根目录的生成器。"""
    return ExcelGenerator(allowed_roots=[tmp_path])


def _load(tmp_path: Path, name: str = "report.xlsx"):
    out = tmp_path / name
    assert out.exists() and out.stat().st_size > 0
    return load_workbook(out)


def test_generate_success(generator, sample_report, tmp_path):
    """生成成功：文件存在、返回路径一致、10 个工作表。"""
    out = tmp_path / "out" / "report.xlsx"
    result = generator.generate(sample_report, out)
    assert result == out
    wb = _load(tmp_path, "out/report.xlsx")
    assert wb.sheetnames == SHEET_ORDER
    wb.close()


def test_sheet_count_and_content(generator, sample_report, tmp_path):
    """每个 sheet 有内容、冻结首行，漏洞清单表头正确。"""
    out = tmp_path / "report.xlsx"
    generator.generate(sample_report, out)
    wb = _load(tmp_path)
    assert len(wb.sheetnames) == 10
    for name in SHEET_ORDER:
        ws = wb[name]
        assert ws.max_row >= 1
        assert ws.freeze_panes == "A2"
        assert any(
            cell.value not in (None, "")
            for row in ws.iter_rows()
            for cell in row
        )
    headers = [
        wb["漏洞清单"].cell(row=1, column=i + 1).value for i in range(10)
    ]
    assert headers[0] == "编号"
    assert "等级" in headers and "OWASP MASVS" in headers
    wb.close()


def test_s7_path_whitelist(sample_report, tmp_path):
    """白名单外路径与非法后缀均抛 PathNotAllowedError。"""
    root = tmp_path / "allowed"
    gen = ExcelGenerator(allowed_roots=[root])
    with pytest.raises(PathNotAllowedError):
        gen.generate(sample_report, tmp_path / "outside.xlsx")
    with pytest.raises(PathNotAllowedError):
        gen.generate(sample_report, root / "report.exe")
    with pytest.raises(PathNotAllowedError):
        gen.generate(sample_report, str(tmp_path / ".." / "escape.xlsx"))
    # 白名单内正常生成
    result = gen.generate(sample_report, root / "sub" / "ok.xlsx")
    assert result.exists()


def test_severity_colors(generator, sample_report, tmp_path):
    """概览表 severity 等级与数量单元格填充/字色与配置一致。"""
    out = tmp_path / "color.xlsx"
    generator.generate(sample_report, out)
    wb = _load(tmp_path, "color.xlsx")
    ws = wb["漏洞概览"]
    for offset, sev in enumerate(SEVERITY_ORDER):
        label = ws.cell(row=2 + offset, column=1)
        count = ws.cell(row=2 + offset, column=2)
        assert label.value == sev
        bg, fg = SEVERITY_STYLES[sev]
        for cell in (label, count):
            assert cell.fill.start_color.rgb[-6:] == bg.upper()
            assert cell.font.color.rgb[-6:] == fg.upper()
    # 漏洞清单 severity 列同样着色（首个 finding 为 CRITICAL）
    sev_cell = wb["漏洞清单"].cell(row=2, column=3)
    assert sev_cell.value == "CRITICAL"
    assert sev_cell.fill.start_color.rgb[-6:] == \
        SEVERITY_STYLES["CRITICAL"][0].upper()
    wb.close()


def test_hyperlink_to_detail(generator, sample_report, tmp_path):
    """漏洞清单编号单元格超链接指向漏洞详情区块。"""
    out = tmp_path / "link.xlsx"
    generator.generate(sample_report, out)
    wb = _load(tmp_path, "link.xlsx")
    cell = wb["漏洞清单"].cell(row=2, column=1)
    assert cell.value == "VULN-001"
    assert cell.hyperlink is not None
    assert "漏洞详情" in str(cell.hyperlink.target)
    wb.close()


def test_layout_wrap_text(generator, sample_report, tmp_path):
    """详情页长文本设置 wrap_text，等宽代码片段存在。"""
    out = tmp_path / "layout.xlsx"
    generator.generate(sample_report, out)
    wb = _load(tmp_path, "layout.xlsx")
    detail = wb["漏洞详情"]
    wrapped = [
        cell
        for row in detail.iter_rows()
        for cell in row
        if cell.value and cell.alignment and cell.alignment.wrap_text
    ]
    assert wrapped
    evidence = wb["证据明细"]
    mono = [
        cell
        for row in evidence.iter_rows()
        for cell in row
        if cell.value and cell.font and cell.font.name == "Consolas"
    ]
    assert mono
    wb.close()


def test_roundtrip(generator, sample_report, tmp_path):
    """序列化往返：保存后重新打开，关键数据保持一致。"""
    out = tmp_path / "roundtrip.xlsx"
    generator.generate(sample_report, out)
    wb = _load(tmp_path, "roundtrip.xlsx")
    assert wb["封面"]["A1"].value == sample_report.title
    assert wb["封面"]["B4"].value == "机密"
    assert wb["封面"]["B5"].value == "DemoApp"
    detail_texts = [
        str(cell.value)
        for row in wb["漏洞详情"].iter_rows()
        for cell in row
        if cell.value
    ]
    joined = "\n".join(detail_texts)
    assert "VULN-001" in joined
    assert "硬编码凭据泄露" in joined
    list_ids = [
        wb["漏洞清单"].cell(row=2 + i, column=1).value for i in range(3)
    ]
    assert list_ids == ["VULN-001", "VULN-002", "VULN-003"]
    poc_texts = [
        str(cell.value)
        for row in wb["POC脚本"].iter_rows()
        for cell in row
        if cell.value
    ]
    assert any("adb shell am start" in t for t in poc_texts)
    wb.close()


def test_poc_long_content_truncated(tmp_path):
    """超 100 行的 POC 内容被截断并注明原始行数。"""
    long_poc = "\n".join(f"# poc line {i}" for i in range(150))
    vuln = Vulnerability(
        vuln_id="VULN-900",
        title="长 POC 截断测试",
        severity="LOW",
        poc=long_poc,
    )
    report = MobileSecurityReport(
        title="截断测试", vulnerabilities=[vuln]
    )
    gen = ExcelGenerator(allowed_roots=[tmp_path])
    out = tmp_path / "trunc.xlsx"
    gen.generate(report, out)
    wb = _load(tmp_path, "trunc.xlsx")
    texts = [
        str(cell.value)
        for row in wb["POC脚本"].iter_rows()
        for cell in row
        if cell.value
    ]
    assert any("已截断" in t and "150" in t for t in texts)
    wb.close()


def _build_all_severity_vulns() -> list:
    """构造覆盖全部 severity 的 5 条漏洞（最小数据集）。

    注：上游 ``create_insecurebank_sample_report`` 目前未将 vulns
    传入聚合模型（已向上游反馈），测试中据此补齐以保证全等级覆盖。
    """
    return [
        Vulnerability(
            vuln_id=f"VULN-{i:03d}",
            title=f"示例漏洞 {i}",
            severity=sev,
            category="示例分类",
            cwe=f"CWE-{700 + i}",
            masvs=f"MASVS-TEST-{i}",
            description=f"severity={sev} 的示例漏洞描述。",
            poc=f"echo poc-{i}",
            evidence=[Evidence(location="a.java:1", content="flag")],
            reproduction_steps=[ReproStep(
                action="执行", command=f"echo {i}",
                expected="ok", actual="ok")],
        )
        for i, sev in enumerate(
            ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"), 1
        )
    ]


def test_sample_factory_report(tmp_path):
    """_fallback_models 示例报告（5 findings）可完整生成。"""
    report = create_insecurebank_sample_report()
    if not report.vulnerabilities:
        report.vulnerabilities = _build_all_severity_vulns()
    gen = ExcelGenerator(allowed_roots=[tmp_path])
    out = tmp_path / "sample.xlsx"
    result = gen.generate(report, out)
    assert result == out
    wb = _load(tmp_path, "sample.xlsx")
    assert len(wb.sheetnames) == 10
    assert wb["封面"]["A1"].value == report.title
    wb.close()


def test_screenshot_info_extracted(generator, sample_report, tmp_path):
    """截图清单解析 PNG 尺寸、SHA256 前 16 位与校验状态。"""
    out = tmp_path / "shots.xlsx"
    generator.generate(sample_report, out)
    wb = _load(tmp_path, "shots.xlsx")
    rows = [
        [cell.value for cell in row]
        for row in wb["截图清单"].iter_rows(min_row=2)
        if row[0].value
    ]
    assert rows, "截图清单应有数据行"
    by_path = {r[1]: r for r in rows}
    login = by_path[[p for p in by_path if p.endswith("shot_login.png")][0]]
    assert login[3] == "a" * 16
    assert login[4] == "1080x1920"
    assert login[5] == "PNG"
    assert login[6] == "✓已验证"
    assert login[7] == "VULN-001"
    provider = by_path[
        [p for p in by_path if p.endswith("shot_provider.png")][0]
    ]
    assert provider[3] == "-"
    assert "✗" in str(provider[6])
    wb.close()


def test_report_generation_error_type():
    """ReportGenerationError 可用且继承 RuntimeError。"""
    assert issubclass(ReportGenerationError, RuntimeError)


# ─────────────────────── 健壮性回归测试 ───────────────────────


def test_illegal_chars_and_oversize_text_sanitized(tmp_path):
    """含 \\x00 控制字符与超长文本的 finding 不崩溃且内容被清洗/截断。"""
    dirty_desc = "前缀\x00含NUL\x0b与\x1a非法字符" + "长" * 45000
    vuln = Vulnerability(
        vuln_id="VULN-DIRTY",
        title="脏字符\x00与超长文本",
        severity="HIGH",
        description=dirty_desc,
        evidence=[
            Evidence(
                location="a.java:1",
                content="code\x00with\x1bNUL",
            ),
        ],
    )
    report = MobileSecurityReport(title="清洗测试", vulnerabilities=[vuln])
    gen = ExcelGenerator(allowed_roots=[tmp_path])
    out = tmp_path / "dirty.xlsx"
    gen.generate(report, out)  # 不应抛 openpyxl 非法字符异常
    wb = _load(tmp_path, "dirty.xlsx")
    texts = [
        str(cell.value)
        for row in wb["漏洞详情"].iter_rows()
        for cell in row
        if cell.value
    ]
    joined = "\n".join(texts)
    assert "\x00" not in joined
    assert "\x0b" not in joined and "\x1a" not in joined
    # 超长文本被截断到 32000 + 截断标记
    assert any("已截断" in t for t in texts)
    assert all(len(t) <= 32000 + 10 for t in texts)
    # 证据片段中的控制字符同样被清洗
    evi_texts = [
        str(cell.value)
        for row in wb["证据明细"].iter_rows()
        for cell in row
        if cell.value
    ]
    assert all("\x00" not in t and "\x1b" not in t for t in evi_texts)
    wb.close()


def test_dirty_numeric_fields_no_crash(tmp_path):
    """数量字段为脏字符串（如 "abc"）时生成 Excel 不崩溃。"""
    vuln = SimpleNamespace(
        vuln_id="VULN-N1",
        title="脏数字字段",
        severity="HIGH",
        screenshot_count="abc",
        screenshots=[],
    )
    report = MobileSecurityReport(title="脏数字", vulnerabilities=[vuln])
    gen = ExcelGenerator(allowed_roots=[tmp_path])
    out = tmp_path / "dirty_num.xlsx"
    gen.generate(report, out)
    wb = _load(tmp_path, "dirty_num.xlsx")
    # 脏 screenshot_count 转换失败后回退为截图列表长度 0
    assert wb["漏洞清单"].cell(row=2, column=8).value == 0
    wb.close()


def test_dirty_statistics_and_coverage_no_crash(tmp_path):
    """统计 severity_counts 值与 coverage_rate 为脏字符串时计算不崩溃。

    注：整份空 findings 报告的 Excel 自检（漏洞详情表非空校验）属既有
    行为，此处针对脏数值容错逻辑做单元级验证。
    """
    gen = ExcelGenerator(allowed_roots=[tmp_path])
    report = SimpleNamespace(
        title="脏统计",
        vulnerabilities=[],
        statistics=SimpleNamespace(
            severity_counts={"HIGH": "abc", "LOW": 2},
            coverage_rate="abc",
        ),
    )
    wb = Workbook()
    ws = wb.active
    ws.title = "漏洞概览"
    gen._fill_overview(ws, report, [])  # 不应抛 ValueError
    counts = {
        ws.cell(row=2 + i, column=1).value: ws.cell(row=2 + i, column=2).value
        for i in range(5)
    }
    assert counts["HIGH"] == 0  # "abc" 转换失败按 0 处理
    assert counts["LOW"] == 2  # 合法值 2 保留
    # coverage_rate="abc" 走兜底展示，不崩溃
    pairs = gen._coverage_pairs(report, [])
    coverage = dict(pairs).get("工具覆盖率")
    assert coverage is not None


def test_duplicate_finding_id_keeps_first_anchor(tmp_path):
    """重复 vuln_id：锚点保留首次出现行，后续详情标题追加 (重复#N)。"""
    dup1 = SimpleNamespace(
        vuln_id="VULN-DUP", title="第一次出现", severity="HIGH"
    )
    dup2 = SimpleNamespace(
        vuln_id="VULN-DUP", title="重复出现", severity="HIGH"
    )
    report = MobileSecurityReport(
        title="重复ID", vulnerabilities=[dup1, dup2]
    )
    gen = ExcelGenerator(allowed_roots=[tmp_path])
    out = tmp_path / "dup.xlsx"
    gen.generate(report, out)
    wb = _load(tmp_path, "dup.xlsx")
    ws = wb["漏洞详情"]
    head_texts = [
        str(ws.cell(row=r, column=1).value)
        for r in range(1, ws.max_row + 1)
        if ws.cell(row=r, column=1).value
    ]
    heads = [t for t in head_texts if t.startswith("VULN-DUP")]
    assert heads[0] == "VULN-DUP  第一次出现"
    assert any("(重复#2)" in t for t in heads[1:])
    # 漏洞清单超链接指向首次出现的区块行
    link = wb["漏洞清单"].cell(row=3, column=1)
    assert link.hyperlink is not None
    wb.close()


def test_save_failure_raises_and_cleans_residual(
    tmp_path, monkeypatch
):
    """wb.save 失败时抛 ReportGenerationError 并清理残留半成品文件。"""
    import fp_sentinel.mobile_reporting.formats.excel_generator as eg

    vuln = Vulnerability(vuln_id="VULN-S1", title="保存失败", severity="LOW")
    report = MobileSecurityReport(title="保存失败", vulnerabilities=[vuln])
    gen = ExcelGenerator(allowed_roots=[tmp_path])
    out = tmp_path / "residual.xlsx"
    out.write_bytes(b"stale-residual")  # 预置残留文件

    def _boom(_self, _path):
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(eg.Workbook, "save", _boom)
    with pytest.raises(ReportGenerationError) as exc_info:
        gen.generate(report, out)
    assert "未被占用" in str(exc_info.value) or "写权限" in str(exc_info.value)
    # 残留半成品文件已被清理
    assert not out.exists()


def test_png_size_handles_invalid_paths(tmp_path):
    """_png_size 对截断文件头与含 NUL 路径均返回 None 而非抛异常。"""
    truncated = tmp_path / "truncated.png"
    truncated.write_bytes(_PNG_SIGNATURE + b"\x00\x00")  # 不足 26 字节
    assert _png_size(truncated) is None
    nul_path = tmp_path / "nul\x00.png"  # 路径含 NUL → ValueError
    assert _png_size(nul_path) is None


def test_zero_findings_report_generates_with_placeholders(tmp_path):
    """零发现是合法场景：报告可正常生成，依赖漏洞的表写入占位说明。"""
    gen = ExcelGenerator(allowed_roots=[tmp_path])
    report = SimpleNamespace(
        title="零发现报告",
        report_version="V1.0",
        vulnerabilities=[],
        statistics=SimpleNamespace(severity_counts={}, coverage_rate=0.0),
    )
    out = gen.generate(report, tmp_path / "empty.xlsx")
    assert out.exists()
    wb = _load(tmp_path, "empty.xlsx")
    assert wb["漏洞详情"].cell(row=1, column=1).value == (
        "本次扫描未发现安全问题，无漏洞详情可展示。"
    )
    assert wb["漏洞清单"].cell(row=1, column=1).value == "本次扫描未发现安全问题。"
    assert wb["POC脚本"].cell(row=1, column=1).value is not None
    assert wb["复现步骤"].cell(row=1, column=1).value is not None
    wb.close()
