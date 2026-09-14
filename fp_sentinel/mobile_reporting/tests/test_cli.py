"""cli 单元测试：非 sample 模式与参数健壮性回归。"""

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

from fp_sentinel.mobile_reporting.cli import main  # noqa: E402


def _write_insight(tmp_path: Path) -> Path:
    """构造最小可用的 mobile_insight 产物 JSON。"""
    insight = {
        "target": "demo.apk",
        "duration_sec": 1.5,
        "insights": [
            {
                "id": "INS-1",
                "title": "弱加密",
                "category": "CRYPTO",
                "severity": "HIGH",
                "description": "使用 ECB 模式",
                "evidence": ["AES/ECB"],
            }
        ],
    }
    path = tmp_path / "insight.json"
    path.write_text(json.dumps(insight, ensure_ascii=False), encoding="utf-8")
    return path


class TestCliMain:
    """CLI 主流程回归。"""

    def test_non_sample_mode_exit_zero(self, tmp_path: Path) -> None:
        """非 --sample 模式从最小 insight JSON 成功生成报告，退出码 0。"""
        insight = _write_insight(tmp_path)
        out_dir = tmp_path / "out"
        rc = main(
            [
                "--format",
                "html",
                "--output",
                str(out_dir),
                "--insight",
                str(insight),
            ]
        )
        assert rc == 0
        assert (out_dir / "mobile_security_report.html").is_file()

    def test_empty_format_exit_one(self, tmp_path: Path) -> None:
        """--format 解析为空列表时报错并返回退出码 1。"""
        out_dir = tmp_path / "out"
        rc = main(["--format", "", "--output", str(out_dir), "--sample"])
        assert rc == 1
        assert not out_dir.exists()

    def test_comma_only_format_exit_one(self, tmp_path: Path) -> None:
        """--format 仅含逗号分隔符时同样报错退出码 1。"""
        rc = main(
            ["--format", " , , ", "--output", str(tmp_path / "out"), "--sample"]
        )
        assert rc == 1

    def test_non_sample_mode_with_apk_env(self, tmp_path: Path) -> None:
        """非 --sample 模式携带 --apk 时环境采集同样走实例方法成功。"""
        insight = _write_insight(tmp_path)
        apk = tmp_path / "demo.apk"
        apk.write_bytes(b"PK\x03\x04fake")
        out_dir = tmp_path / "out"
        rc = main(
            [
                "--format",
                "html",
                "--output",
                str(out_dir),
                "--insight",
                str(insight),
                "--apk",
                str(apk),
            ]
        )
        assert rc == 0
