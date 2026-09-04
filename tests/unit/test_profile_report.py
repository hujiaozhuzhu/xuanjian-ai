"""
P4 报告生成测试：隐私声明、匿名化、S7 输出白名单、个人报告
"""

import pytest

from fp_sentinel.models import Finding, Severity
from fp_sentinel.profile.analyzer import build_team_profile
from fp_sentinel.profile.models import AttributionRecord, alias_hash
from fp_sentinel.reporting.profile_report import (
    PRIVACY_BANNER,
    REPORT_FOOTER,
    check_reveal_allowed,
    generate_personal_report,
    generate_team_report,
    save_report,
    validate_output_path,
)


def _findings():
    return [
        Finding(
            scanner="s", rule_id="r1", severity=Severity.HIGH,
            file_path="a.py", line_start=1, message="m",
            fingerprint=f"fp{i}", cwe="CWE-89",
            created_at=f"2026-08-0{i + 1}T10:00:00+00:00",
        )
        for i in range(3)
    ]


def _team():
    findings = _findings()
    attrs = [
        AttributionRecord(
            finding_fingerprint=f"fp{i}", alias_hash=alias_hash("alice@example.com")
        )
        for i in range(3)
    ]
    return build_team_profile(
        findings=findings, attributions=attrs, period="2026-08", kloc=3.0,
        display_names={alias_hash("alice@example.com"): "alice"},
    )


def test_team_report_contains_privacy_banner_and_footer():
    md = generate_team_report(_team())
    assert PRIVACY_BANNER in md
    assert REPORT_FOOTER in md
    assert "不用于绩效考核" in md
    assert "本地保护非强加密" in md
    assert "团队健康度" in md
    assert "四指标" in md
    assert "下月目标" in md


def test_team_report_default_anonymous():
    """未 reveal 时报告只显示别名，不显示姓名/email"""
    md = generate_team_report(_team())
    assert "alice@example.com" not in md
    assert "alice" not in md.replace("alias", "")  # 显示名"alice"不出现
    assert alias_hash("alice@example.com") in md


def test_team_report_reveal_shows_display_name():
    md = generate_team_report(_team(), reveal=True)
    assert "alice" in md  # 解密姓名出现（调用方须先过 check_reveal_allowed）


def test_reveal_gate_requires_env_and_flag():
    """--reveal 需 FP_SENTINEL_REVEAL=1 + 双条件，缺一不可"""
    assert check_reveal_allowed(False, "1") is False
    assert check_reveal_allowed(True, "0") is False
    assert check_reveal_allowed(True, None) is False
    assert check_reveal_allowed(True, "1") is True


def test_personal_report_includes_team_average():
    team = _team()
    profile = team.members[0]
    md = generate_personal_report(profile, team_metrics=team.metrics)
    assert PRIVACY_BANNER in md
    assert "与团队匿名平均对比" in md
    assert profile.alias in md
    assert "alice@example.com" not in md


def test_validate_output_path_rejects_traversal(tmp_path):
    """S7 白名单：越出输出目录的路径被拒绝"""
    base = tmp_path / "reports"
    base.mkdir()
    with pytest.raises(ValueError):
        validate_output_path(str(tmp_path / "evil.md"), base_dir=str(base))
    ok = validate_output_path(str(base / "sub" / "report.md"), base_dir=str(base))
    assert ok.name == "report.md"


def test_save_report_writes_into_whitelist_dir(tmp_path):
    base = tmp_path / "reports"
    path = save_report("# t\n", "team.md", base_dir=str(base))
    assert path.exists()
    assert path.read_text(encoding="utf-8").startswith("# t")
