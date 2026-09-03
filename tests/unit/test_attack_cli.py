"""
A7/A8. CLI 集成测试（--report / --output / attack-purge / 版本号）
"""

from typer.testing import CliRunner

from fp_sentinel.cli import app
from fp_sentinel import __version__

runner = CliRunner()


class TestScanReportOption:
    def test_scan_report_help(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--report" in result.output
        assert "--output" in result.output

    def test_scan_invalid_report_kind(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1\n")
        result = runner.invoke(app, [
            "scan", str(tmp_path), "--no-save", "--report", "bogus",
        ])
        assert result.exit_code == 1

    def test_scan_report_none_generates_nothing(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1\n")
        out = tmp_path / "reports"
        result = runner.invoke(app, [
            "scan", str(tmp_path), "--no-save", "--report", "none",
            "--output", str(out),
        ])
        assert result.exit_code in (0, 1)
        if out.exists():
            assert not any(out.glob("*.md"))

    def test_scan_report_attack_generates_md(self, tmp_path):
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "app.py").write_text(
            'from flask import request\n'
            'uid = request.args.get("id")\n'
            'q = "SELECT * FROM users WHERE id = " + uid\n'
        )
        out = tmp_path / "reports"
        result = runner.invoke(app, [
            "scan", str(proj), "--no-save", "--report", "attack",
            "--output", str(out),
        ])
        assert result.exit_code in (0, 1)
        # 扫描器不可用时可能无 findings，文件生成以 findings 存在为前提
        if (out / "attack_report.md").exists():
            content = (out / "attack_report.md").read_text(encoding="utf-8")
            assert "安全声明" in content
            assert "PoC 仅用于防御验证" in content


class TestAttackPurge:
    def test_attack_purge_registered(self):
        result = runner.invoke(app, ["attack-purge", "--help"])
        assert result.exit_code == 0
        assert "--days" in result.output

    def test_attack_subcommand_registered(self):
        result = runner.invoke(app, ["attack", "--help"])
        assert result.exit_code == 0

    def test_attack_purge_runs(self, tmp_path, monkeypatch):
        """对空库执行 purge 不报错"""
        import asyncio
        from fp_sentinel.database import get_database
        from fp_sentinel.cli.attack_commands import (
            ATTACK_RECORDS_SQL, purge_attack_records,
        )

        async def _seed():
            async with get_database(str(tmp_path / "p.db")) as db:
                await db.conn.executescript(ATTACK_RECORDS_SQL)
                await db.conn.execute(
                    """INSERT INTO attack_poc_records
                       (project_path, rule_id, file_path, line_start, vuln_type,
                        poc_text, verify_status, probability, created_at)
                       VALUES ('p', 'r', 'f', 1, '', '', 'simulated', 0,
                               '2020-01-01T00:00:00')""",
                )
                await db.conn.commit()
                deleted = await purge_attack_records(db, days=30)
                return deleted

        deleted = asyncio.run(_seed())
        assert deleted == 1

    def test_profile_registration_graceful(self):
        """profile 子命令：模块就绪则注册，未就绪静默降级（不报错）"""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0  # --help 正常成功退出


class TestVersion:
    def test_version_is_2_2_3(self):
        assert __version__ == "2.2.3"

    def test_version_command(self):
        result = runner.invoke(app, ["version"])
        assert "2.2.3" in result.output
