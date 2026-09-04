"""
P3 画像算法金标准测试（合成数据集：3 虚拟作者跨 2 个月）

数据集设计（手工推算的期望值，验证六维度与团队健康度）：
- alice：6 条（CWE-89×4、CWE-79×2），1 条 fingerprint 重复（复犯），1 条修复 +24h，
  修复后 30 天内同文件同 CWE 复发 1 次
- bob：2 条（CWE-79、CWE-798 各 1），均 +24h 修复，无复发
- carol：3 条（CWE-89×2、CWE-22×1），1 条 +240h 修复
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import pytest

from fp_sentinel.models import Finding, Severity
from fp_sentinel.profile.analyzer import (
    build_team_profile,
    compute_team_health,
    filter_by_period,
    analyze_developer,
)
from fp_sentinel.profile.models import (
    AttributionRecord,
    UNKNOWN_ALIAS,
    alias_hash,
)

T0 = datetime(2026, 7, 2, 10, 0, tzinfo=timezone.utc)


def _dt(days: int) -> datetime:
    return T0 + timedelta(days=days)


def _f(fp: str, cwe: str, file: str, at: datetime, severity: str = "HIGH") -> Finding:
    return Finding(
        scanner="semgrep",
        rule_id="r." + cwe,
        severity=Severity(severity),
        file_path=file,
        line_start=1,
        message="m",
        fingerprint=fp,
        cwe=cwe,
        created_at=at,
    )


def _make_findings() -> List[Finding]:
    return [
        # alice —— 7 月 5 条 + 8 月 1 条
        _f("a1", "CWE-89", "db.py", _dt(0), "CRITICAL"),       # 07-02
        _f("a4", "CWE-79", "view.py", _dt(3), "HIGH"),          # 07-05 修复+24h
        _f("a2", "CWE-89", "db.py", _dt(8), "HIGH"),            # 07-10
        _f("a3", "CWE-89", "api.py", _dt(18), "HIGH"),          # 07-20
        _f("a5", "CWE-79", "view.py", _dt(23), "MEDIUM"),       # 07-25（a4 修复后复发）
        _f("a1", "CWE-89", "db.py", _dt(44), "LOW"),            # 08-15（fingerprint 复犯）
        # bob —— 7 月 2 条
        _f("b1", "CWE-79", "x.js", _dt(6), "HIGH"),             # 07-08 修复+24h
        _f("b2", "CWE-798", "key.js", _dt(13), "HIGH"),         # 07-15 修复+24h
        # carol —— 8 月 3 条
        _f("c1", "CWE-89", "api2.py", _dt(30), "HIGH"),         # 08-01 修复+240h
        _f("c2", "CWE-89", "api2.py", _dt(32), "CRITICAL"),     # 08-03
        _f("c3", "CWE-22", "files.py", _dt(39), "CRITICAL"),    # 08-10
    ]


def _fix_events(findings: List[Finding]) -> Dict[str, datetime]:
    offsets = {"a4": 1, "b1": 1, "b2": 1, "c1": 10}  # 天
    return {
        f.fingerprint: f.created_at + timedelta(days=offsets[f.fingerprint])
        for f in findings if f.fingerprint in offsets
    }


def _attributions(findings: List[Finding]) -> List[AttributionRecord]:
    owner = {}
    for f in findings:
        if f.fingerprint.startswith("a"):
            owner[f.fingerprint] = alias_hash("alice@example.com")
        elif f.fingerprint.startswith("b"):
            owner[f.fingerprint] = alias_hash("bob@example.com")
        else:
            owner[f.fingerprint] = alias_hash("carol@example.com")
    return [
        AttributionRecord(finding_fingerprint=f.fingerprint, alias_hash=owner[f.fingerprint])
        for f in findings
    ]


# ─────────────────────── 成员六维度 ───────────────────────

def test_alice_cwe_preference_and_gaps():
    findings = _make_findings()
    alice = [f for f in findings if f.fingerprint.startswith("a")]
    p = analyze_developer(alias_hash("alice@example.com"), alice, period="2026-07")
    assert p.total_findings == 6
    assert p.vuln_counts_by_cwe == {"CWE-89": 4, "CWE-79": 2}
    assert p.cwe_top3[0] == "CWE-89"
    # 知识盲区：占比 >30% → CWE-89（4/6≈66.7%）
    assert p.knowledge_gaps == ["CWE-89"]


def test_alice_repeat_rate():
    alice = [f for f in _make_findings() if f.fingerprint.startswith("a")]
    p = analyze_developer("alias-a", alice)
    # a1 重复出现 1 次 / 共 6 条
    assert abs(p.repeat_rate - 1 / 6) < 1e-6


def test_alice_fix_speed():
    alice = [f for f in _make_findings() if f.fingerprint.startswith("a")]
    p = analyze_developer("alias-a", alice, fix_events=_fix_events(_make_findings()))
    # 仅 a4 有修复事件，+24h
    assert p.avg_fix_hours == 24.0


def test_alice_fix_quality_recurrence_detected():
    alice = [f for f in _make_findings() if f.fingerprint.startswith("a")]
    p = analyze_developer("alias-a", alice, fix_events=_fix_events(_make_findings()))
    # a4 修复后 20 天同文件(view.py)同 CWE-79 复发（a5）→ 修复质量 0
    assert p.fix_pass_rate == 0.0


def test_bob_clean_fix_quality():
    findings = _make_findings()
    bob = [f for f in findings if f.fingerprint.startswith("b")]
    p = analyze_developer("alias-b", bob, fix_events=_fix_events(findings))
    assert p.avg_fix_hours == 24.0
    assert p.fix_pass_rate == 1.0  # 无复发
    assert p.repeat_rate == 0.0
    assert p.knowledge_gaps == []  # 各 50%，无 >30% 盲区
    assert sorted(p.cwe_top3) == ["CWE-79", "CWE-798"]


def test_carol_trend_single_month_and_fix_speed():
    carol = [f for f in _make_findings() if f.fingerprint.startswith("c")]
    p = analyze_developer("alias-c", carol, fix_events=_fix_events(_make_findings()))
    assert p.avg_fix_hours == 240.0
    # 单月数据不外推，斜率 0
    assert p.trend == 0.0
    assert p.knowledge_gaps == ["CWE-89"]  # 2/3 ≈ 66.7%


def test_alice_trend_negative_is_improving():
    alice = [f for f in _make_findings() if f.fingerprint.startswith("a")]
    p = analyze_developer("alias-a", alice)
    # 7 月 5 条 → 8 月 1 条：斜率 -4
    assert p.trend == -4.0


def test_no_fix_data_leaves_empty_not_guessed():
    """无修复数据 → 置空 None，不猜"""
    p = analyze_developer("alias-x", _make_findings()[:2], fix_events=None)
    assert p.avg_fix_hours is None
    assert p.fix_pass_rate is None


def test_period_filter():
    findings = _make_findings()
    july = filter_by_period(findings, "2026-07")
    august = filter_by_period(findings, "2026-08")
    assert len(july) == 7
    assert len(august) == 4


# ─────────────────────── 团队健康度 ───────────────────────

def test_team_health_gold_standard():
    """健康度金标准：kloc=5，全部修复事件已知
    密度 = 11/5 = 2.2/千行 → 30×1.2/2.2 = 16.36
    平均修复 = (24×3+240)/4 = 78h → 30×72/78 = 27.69
    复犯率 = 1/11 ≈ 9.09% ≤ 20% → 25（封顶）
    高危占比 = 9/11 ≈ 81.8%（CRITICAL+HIGH，按实现定义）
        总分按实现计算，验证各分项与范围
    """
    findings = _make_findings()
    score, m = compute_team_health(findings, kloc=5.0, fix_events=_fix_events(findings))
    assert m["vuln_density"] == 2.2
    assert abs(m["avg_fix_hours"] - 78.0) < 1e-6
    assert abs(m["repeat_rate"] - 1 / 11) < 1e-6
    assert abs(m["high_risk_ratio"] - 9 / 11) < 1e-6
    assert abs(m["density_score"] - 30 * 1.2 / 2.2) < 0.01
    assert abs(m["fix_speed_score"] - 30 * 72 / 78) < 0.01
    assert m["repeat_score"] == 25.0
    assert abs(m["high_risk_score"] - 15 * (1 - 9 / 11) / 0.9) < 0.01
    assert score == pytest.approx(
        m["density_score"] + m["fix_speed_score"] + m["repeat_score"] + m["high_risk_score"],
        abs=0.1,
    )
    assert 0 <= score <= 100


def test_team_health_neutral_when_no_fix_data():
    """无修复事件 → 修复速度按中性 15 分计（不猜）"""
    findings = _make_findings()
    score, m = compute_team_health(findings, kloc=5.0, fix_events=None)
    assert m["avg_fix_hours"] is None
    assert m["fix_speed_score"] == 15.0


def test_team_health_neutral_density_without_kloc():
    """未提供 kloc → 密度按中性 15 分计"""
    _, m = compute_team_health(_make_findings(), kloc=None)
    assert m["vuln_density"] is None
    assert m["density_score"] == 15.0


def test_team_health_perfect_inputs():
    """0 发现 + 无修复数据场景不崩溃，得分在范围内"""
    score, m = compute_team_health([], kloc=1.0)
    assert 0 <= score <= 100
    assert m["total_findings"] == 0


# ─────────────────────── 团队画像组装 ───────────────────────

def test_build_team_profile_members_and_coverage():
    findings = _make_findings()
    team = build_team_profile(
        findings=findings,
        attributions=_attributions(findings),
        period=None,
        fix_events=_fix_events(findings),
        kloc=5.0,
    )
    assert team.findings == 11
    assert team.coverage == 1.0
    assert team.health_score == pytest.approx(72.1, abs=0.1)
    # 3 个成员，按发现数降序：alice(6) > carol(3) > bob(2)
    aliases = [m.alias for m in team.members]
    assert len(aliases) == 3
    assert team.members[0].total_findings == 6
    assert team.members[0].cwe_top3[0] == "CWE-89"
    assert UNKNOWN_ALIAS not in aliases


def test_build_team_profile_unattributed_goes_unknown():
    findings = _make_findings()[:2]
    team = build_team_profile(findings=findings, attributions=[], period=None)
    assert team.coverage == 0.0
    assert team.members[0].alias == UNKNOWN_ALIAS
