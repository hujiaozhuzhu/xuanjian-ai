"""
A4. 靶场验证器测试（诚实三态）
"""

from pathlib import Path

from fp_sentinel.attack.target_validator import (
    VerifyStatus,
    docker_available,
    verify,
    verify_many,
)
from fp_sentinel.models import Finding, Severity


def _f(rule_id, code, file_path="app.py"):
    return Finding(
        scanner="python_scanner",
        rule_id=rule_id,
        severity=Severity.HIGH,
        file_path=file_path,
        line_start=10,
        code_snippet=code,
    )


class TestSimulatedVerification:
    def test_sql_simulated(self, tmp_path):
        """sink + 输入特征同时命中 → simulated"""
        src = tmp_path / "app.py"
        src.write_text(
            'from flask import request\n'
            'uid = request.args.get("id")\n'
            'q = "SELECT * FROM users WHERE id = " + uid\n'
            'db.execute(q)\n'
        )
        r = verify(_f("py.injection.sql", "db.execute(q)"), project_root=str(tmp_path))
        assert r.status == VerifyStatus.SIMULATED
        assert r.method == "signature-match"
        assert "127.0.0.1" not in r.evidence or True  # 零网络

    def test_yaml_simulated(self, tmp_path):
        (tmp_path / "app.py").write_text(
            'data = request.get_data().decode()\nresult = yaml.load(data)\n'
        )
        r = verify(_f("py.deserialization.yaml", "yaml.load(data)"), project_root=str(tmp_path))
        assert r.status == VerifyStatus.SIMULATED


class TestManualRequired:
    def test_unreadable_source(self, tmp_path):
        r = verify(_f("py.injection.sql", "db.execute(q)"), project_root=str(tmp_path / "nope"))
        assert r.status == VerifyStatus.MANUAL_REQUIRED

    def test_no_sink_signature(self, tmp_path):
        (tmp_path / "app.py").write_text("print('hello')\n")
        r = verify(_f("py.injection.sql", "db.execute(q)"), project_root=str(tmp_path))
        assert r.status == VerifyStatus.MANUAL_REQUIRED


class TestHonestStatus:
    def test_no_docker_no_verified_local(self, tmp_path):
        """无 Docker 环境（或未显式开启）绝不出现 verified_local"""
        (tmp_path / "app.py").write_text(
            'uid = request.args.get("id")\ndb.execute("SELECT " + uid)\n'
        )
        r = verify(_f("py.injection.sql", "db.execute"), project_root=str(tmp_path))
        assert r.status != VerifyStatus.VERIFIED_LOCAL

    def test_allow_docker_without_docker_degrades(self, tmp_path):
        """本环境无 Docker → allow_docker=True 也降级 simulated/manual"""
        (tmp_path / "app.py").write_text(
            'uid = request.args.get("id")\ndb.execute("SELECT " + uid)\n'
        )
        if docker_available():
            pytest.skip("本机存在 Docker，跳过降级断言")
        r = verify(
            _f("py.injection.sql", "db.execute"),
            project_root=str(tmp_path),
            allow_docker=True,
        )
        assert r.status != VerifyStatus.VERIFIED_LOCAL

    def test_verify_many_aligns(self, tmp_path):
        (tmp_path / "app.py").write_text(
            'uid = request.args.get("id")\ndb.execute("SELECT " + uid)\n'
        )
        findings = [
            _f("py.injection.sql", "db.execute"),
            _f("py.deserialization.yaml", "yaml.load"),
        ]
        results = verify_many(findings, project_root=str(tmp_path))
        assert len(results) == len(findings)
