"""CLI 退出码与参数解析测试。"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from fp_sentinel.web_api.cli import main, _parse_cookies


class TestParseCookies:
    """Cookie 解析测试。"""

    def test_valid_cookies(self) -> None:
        """验证合法 cookie 解析。"""
        cookies = _parse_cookies(["sessionid=abc123", "token=xyz"])
        assert cookies == {"sessionid": "abc123", "token": "xyz"}

    def test_invalid_format(self) -> None:
        """验证格式错误的 cookie 被忽略。"""
        cookies = _parse_cookies(["broken", "ok=1"])
        assert cookies == {"ok": "1"}

    def test_empty_input(self) -> None:
        """验证空列表返回空字典。"""
        assert _parse_cookies([]) == {}


class TestCliMain:
    """CLI 入口测试。"""

    def test_discover_help(self) -> None:
        """验证 discover 子命令无必填参数不会崩溃（help 模式）。"""
        with pytest.raises(SystemExit):
            main(["discover", "--help"])

    def test_scan_privilege_no_auth_rejected(self, tmp_path: Path) -> None:
        """验证未加 --i-have-authorization 时退出码为 2。"""
        result = main(
            [
                "scan-privilege",
                "--base-url",
                "https://example.com",
                "--cookie-a",
                "sess=a",
                "--cookie-b",
                "sess=b",
                "--paths",
                "/admin/users",
                "--output-dir",
                str(tmp_path / "out"),
            ]
        )
        assert result == 2

    def test_discover_minimal(self, tmp_path: Path, sample_har: Path) -> None:
        """验证 discover 命令成功运行。"""
        result = main(
            [
                "discover",
                "--har",
                str(sample_har),
                "--output-dir",
                str(tmp_path / "out"),
            ]
        )
        assert result == 0
        # 验证输出文件存在
        out_dir = tmp_path / "out"
        assert (out_dir / "endpoints.json").exists()
        assert (out_dir / "classifications.json").exists()
        assert (out_dir / "endpoints_access_list.csv").exists()

    def test_discover_missing_file(self, tmp_path: Path) -> None:
        """验证 HAR 不存在时优雅退出。"""
        with pytest.raises(FileNotFoundError):
            main(
                [
                    "discover",
                    "--har",
                    str(tmp_path / "nope.har"),
                    "--output-dir",
                    str(tmp_path / "out"),
                ]
            )

    def test_scan_privilege_with_auth(self, tmp_path: Path) -> None:
        """验证越权探测 --i-have-authorization 下成功退出。"""
        with patch("fp_sentinel.web_api.cli.PrivilegeScanner") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.test_horizontal.return_value = []
            mock_instance.test_vertical.return_value = []
            mock_cls.return_value = mock_instance
            result = main(
                [
                    "scan-privilege",
                    "--base-url",
                    "https://example.com",
                    "--cookie-a",
                    "sess_a=aaa",
                    "--cookie-b",
                    "sess_b=bbb",
                    "--paths",
                    "/admin/users",
                    "--rate-limit",
                    "10",
                    "--i-have-authorization",
                    "--output-dir",
                    str(tmp_path / "out"),
                ]
            )
            assert result == 0
            mock_cls.assert_called_once()

    def test_unknown_subcommand_help(self, capsys: pytest.CaptureFixture) -> None:
        """验证未知子命令打印帮助。"""
        result = main([])
        assert result == 0
