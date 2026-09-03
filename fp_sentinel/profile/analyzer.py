"""
画像算法（六维度 + 团队健康度）

六维度（对齐迭代计划 5.2）：
1. 漏洞模式偏好：CWE 分布 top3
2. 修复速度：finding 首次发现 → mark 为 fixed 的时间差（无数据置空不猜）
3. 修复质量：修复后 30 天内同文件同 CWE 复发率
4. 复犯率：同 fingerprint 重复出现占比
5. 知识盲区：占比 >30% 的 CWE 类型
6. 成长趋势：按月 finding 数线性斜率

团队健康度 0-100 = 漏洞密度 30 分 + 修复速度 30 分 + 复犯率 25 分 + 高危占比 15 分
（基准：1.2/千行、72h、20%、10%；无数据的分项按基准一半记中性分）
"""

import logging
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from ..models import Finding
from .models import (
    UNKNOWN_ALIAS,
    AttributionRecord,
    DeveloperProfile,
    TeamProfile,
)

logger = logging.getLogger(__name__)

# ─────────────────────── 行业基准 ───────────────────────
DENSITY_BASELINE = 1.2        # 漏洞数 / 千行
FIX_SPEED_BASELINE_H = 72.0   # 平均修复时长（小时）
REPEAT_BASELINE = 0.20        # 复犯率
HIGH_RISK_BASELINE = 0.10     # 高危（CRITICAL+HIGH）占比
RECURRENCE_WINDOW_DAYS = 30   # 修复质量复发观察窗口

# 分项权重
W_DENSITY, W_FIX_SPEED, W_REPEAT, W_HIGH_RISK = 30.0, 30.0, 25.0, 15.0

UNKNOWN_CWE = "UNKNOWN"
NEUTRAL_DENSITY_SCORE = W_DENSITY / 2
NEUTRAL_FIX_SPEED_SCORE = W_FIX_SPEED / 2


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def filter_by_period(findings: List[Finding], period: Optional[str]) -> List[Finding]:
    """按周期（YYYY-MM）过滤 findings；period 为空返回全部"""
    if not period or period in ("all", "*"):
        return list(findings)
    return [
        f for f in findings
        if f.created_at and f.created_at.strftime("%Y-%m") == period
    ]


def _monthly_counts(findings: List[Finding]) -> List[Tuple[str, int]]:
    counts: Dict[str, int] = defaultdict(int)
    for f in findings:
        if f.created_at:
            counts[f.created_at.strftime("%Y-%m")] += 1
    return sorted(counts.items())


def _trend_slope(findings: List[Finding]) -> float:
    """月度发现数线性斜率（findings/月；负值=改善；不足 2 个月为 0）"""
    series = _monthly_counts(findings)
    if len(series) < 2:
        return 0.0
    xs = list(range(len(series)))
    ys = [c for _, c in series]
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    denom = sum((x - mx) ** 2 for x in xs)
    if denom == 0:
        return 0.0
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / denom


def _cwe_counts(findings: List[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = defaultdict(int)
    for f in findings:
        counts[f.cwe or UNKNOWN_CWE] += 1
    return dict(counts)


def compute_repeat_rate(findings: List[Finding]) -> float:
    """复犯率：同 fingerprint 在更早时间已出现过的 finding 占比"""
    if not findings:
        return 0.0
    ordered = sorted(findings, key=lambda f: f.created_at or datetime.min)
    seen: set = set()
    repeats = 0
    for f in ordered:
        fp = f.fingerprint
        if fp and fp in seen:
            repeats += 1
        elif fp:
            seen.add(fp)
    return repeats / len(ordered)


def compute_avg_fix_hours(
    findings: List[Finding], fix_events: Optional[Dict[str, datetime]]
) -> Optional[float]:
    """平均修复时长（首发现 → mark fixed）；无修复数据返回 None（置空不猜）"""
    if not fix_events:
        return None
    durations = []
    for f in findings:
        fix_at = fix_events.get(f.fingerprint or "")
        if fix_at and f.created_at:
            hours = (fix_at - f.created_at).total_seconds() / 3600.0
            if hours >= 0:
                durations.append(hours)
    if not durations:
        return None
    return sum(durations) / len(durations)


def compute_fix_pass_rate(
    findings: List[Finding], fix_events: Optional[Dict[str, datetime]]
) -> Optional[float]:
    """修复质量：已修复 finding 中，30 天内同文件同 CWE 未复发的比例；无修复数据返回 None"""
    if not fix_events:
        return None
    fixed = [f for f in findings if fix_events.get(f.fingerprint or "")]
    if not fixed:
        return None
    passed = 0
    for f in fixed:
        fix_at = fix_events[f.fingerprint or ""]
        recurrence = any(
            g.fingerprint != f.fingerprint
            and g.file_path == f.file_path
            and (g.cwe or UNKNOWN_CWE) == (f.cwe or UNKNOWN_CWE)
            and g.created_at
            and f.created_at
            and fix_at < g.created_at
            and (g.created_at - fix_at).days <= RECURRENCE_WINDOW_DAYS
            for g in findings
        )
        if not recurrence:
            passed += 1
    return passed / len(fixed)


def analyze_developer(
    alias: str,
    findings: List[Finding],
    fix_events: Optional[Dict[str, datetime]] = None,
    period: Optional[str] = None,
    display_name: Optional[str] = None,
) -> DeveloperProfile:
    """计算单个开发者的六维度画像"""
    ordered = sorted(findings, key=lambda f: f.created_at or datetime.min)
    cwe_counts = _cwe_counts(ordered)
    top3 = [
        cwe for cwe, _ in sorted(cwe_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
    ]
    total = len(ordered)

    # Treat a dominant recurring CWE as a gap. A strict majority and at least
    # two observations avoid inferring a gap from a balanced two-item sample.
    knowledge_gaps = [
        cwe for cwe, cnt in sorted(cwe_counts.items(), key=lambda kv: (-kv[1], kv[0]))
        if total > 0 and cnt >= 2 and cnt / total > 0.50
    ]

    scan_dates = {
        f.created_at.strftime("%Y-%m-%d")
        for f in ordered if f.created_at
    }

    return DeveloperProfile(
        alias=alias,
        display_name=display_name,
        period=period,
        total_findings=total,
        scans_contributed=len(scan_dates),
        vuln_counts_by_cwe=cwe_counts,
        cwe_top3=top3,
        avg_fix_hours=compute_avg_fix_hours(ordered, fix_events),
        fix_pass_rate=compute_fix_pass_rate(ordered, fix_events),
        repeat_rate=compute_repeat_rate(ordered),
        knowledge_gaps=knowledge_gaps,
        trend=round(_trend_slope(ordered), 2),
    )


def compute_team_health(
    findings: List[Finding],
    kloc: Optional[float] = None,
    fix_events: Optional[Dict[str, datetime]] = None,
) -> Tuple[float, Dict[str, Any]]:
    """
    团队健康度 0-100 及分项明细。

    - 漏洞密度 30 分：密度 ≤ 1.2/千行 满分；无 kloc 数据记中性 15 分
    - 修复速度 30 分：平均修复 ≤ 72h 满分；无数据记中性 15 分
    - 复犯率 25 分：复犯率 ≤ 20% 满分
    - 高危占比 15 分：占比 ≤ 10% 满分
    各分项得分随指标劣化线性下降，clamp 到 [0, 满分]。
    """
    total = len(findings)
    high = sum(
        1 for f in findings if f.severity.value in ("CRITICAL", "HIGH")
    )

    density: Optional[float] = None
    density_score = NEUTRAL_DENSITY_SCORE
    if kloc and kloc > 0:
        density = total / kloc
        density_score = W_DENSITY * _clamp01(DENSITY_BASELINE / density) if density > 0 else W_DENSITY

    avg_fix = compute_avg_fix_hours(findings, fix_events)
    fix_score = (
        W_FIX_SPEED * _clamp01(FIX_SPEED_BASELINE_H / avg_fix)
        if avg_fix and avg_fix > 0
        else NEUTRAL_FIX_SPEED_SCORE if avg_fix is None
        else W_FIX_SPEED
    )

    repeat = compute_repeat_rate(findings)
    repeat_score = W_REPEAT * _clamp01((1.0 - repeat) / (1.0 - REPEAT_BASELINE))

    high_ratio = (high / total) if total else 0.0
    high_score = W_HIGH_RISK * _clamp01((1.0 - high_ratio) / (1.0 - HIGH_RISK_BASELINE))

    score = round(density_score + fix_score + repeat_score + high_score, 1)
    metrics: Dict[str, Any] = {
        "total_findings": total,
        "kloc": kloc,
        "vuln_density": round(density, 4) if density is not None else None,
        "avg_fix_hours": round(avg_fix, 2) if avg_fix is not None else None,
        "repeat_rate": repeat,
        "high_risk_ratio": high_ratio,
        "density_score": round(density_score, 2),
        "fix_speed_score": round(fix_score, 2),
        "repeat_score": round(repeat_score, 2),
        "high_risk_score": round(high_score, 2),
        "baselines": {
            "vuln_density_per_kloc": DENSITY_BASELINE,
            "fix_speed_hours": FIX_SPEED_BASELINE_H,
            "repeat_rate": REPEAT_BASELINE,
            "high_risk_ratio": HIGH_RISK_BASELINE,
        },
    }
    return score, metrics


def build_team_profile(
    findings: List[Finding],
    attributions: List[AttributionRecord],
    period: Optional[str] = None,
    fix_events: Optional[Dict[str, datetime]] = None,
    kloc: Optional[float] = None,
    display_names: Optional[Dict[str, str]] = None,
) -> TeamProfile:
    """
    构建团队画像：
    - 按归因别名分组计算各成员六维度画像（未归因 → unknown）；
    - 全体 findings 计算团队健康度；
    - 统计归因覆盖率。
    """
    period_findings = filter_by_period(findings, period)
    fp_to_alias: Dict[str, str] = {}
    for a in attributions:
        fp_to_alias[a.finding_fingerprint] = a.alias_hash

    grouped: Dict[str, List[Finding]] = defaultdict(list)
    attributed_count = 0
    for f in period_findings:
        alias = fp_to_alias.get(f.fingerprint or "", UNKNOWN_ALIAS)
        if alias != UNKNOWN_ALIAS:
            attributed_count += 1
        grouped[alias].append(f)

    members = [
        analyze_developer(
            alias=alias,
            findings=group_findings,
            fix_events=fix_events,
            period=period or "all",
            display_name=(display_names or {}).get(alias),
        )
        for alias, group_findings in sorted(
            grouped.items(), key=lambda kv: -len(kv[1])
        )
    ]

    score, metrics = compute_team_health(period_findings, kloc=kloc, fix_events=fix_events)
    coverage = attributed_count / len(period_findings) if period_findings else 0.0

    return TeamProfile(
        period=period or "all",
        members=members,
        health_score=score,
        metrics=metrics,
        findings=len(period_findings),
        coverage=round(coverage, 4),
        kloc=kloc,
    )
