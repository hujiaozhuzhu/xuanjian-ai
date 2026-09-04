"""
开发者画像报告生成（Markdown）

安全红线（S6/S7）：
- 报告头部固定隐私声明：画像仅用于培训与能力提升，不用于绩效考核；
- 团队报告个人表默认匿名别名；--reveal 需 FP_SENTINEL_REVEAL=1 环境变量
  + --i-am-security-officer 双条件（见 check_reveal_allowed）方可显示解密姓名；
- 本模块不实现任何"画像评分导出为绩效格式"的接口；
- 报告文件只写入 --output 指定目录（默认 ./reports/），拒绝路径穿越（S7 白名单）；
- 报告脚注声明：本地保护非强加密，数据仅存本地 SQLite。
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..profile.analyzer import (
    DENSITY_BASELINE,
    FIX_SPEED_BASELINE_H,
    HIGH_RISK_BASELINE,
    REPEAT_BASELINE,
)
from ..profile.models import DeveloperProfile, TeamProfile

logger = logging.getLogger(__name__)

PRIVACY_BANNER = (
    "> **隐私声明**：本报告中的开发者均以匿名别名（SHA256 摘要）呈现。"
    "画像数据仅用于培训与能力提升，**不用于绩效考核、评级或任何人事决策**。"
    "数据仅存储于本地 SQLite，不上传网络。"
)

REPORT_FOOTER = (
    "> ---\n"
    "> *注：画像的别名化与本地加密仅为本地保护措施，**本地保护非强加密**；"
    "如需移除个人数据，请使用 `profile forget <alias>`。*"
)

DEFAULT_OUTPUT_DIR = "reports"


def check_reveal_allowed(reveal_flag: bool, env_value: Optional[str] = None) -> bool:
    """
    reveal 双条件校验（实际调用方还需 --i-am-security-officer 旗标）：

    reveal_flag=True 且环境变量 FP_SENTINEL_REVEAL=1 同时满足才允许。
    """
    import os

    env = env_value if env_value is not None else os.environ.get("FP_SENTINEL_REVEAL")
    return bool(reveal_flag) and env == "1"


def validate_output_path(path: str, base_dir: Optional[str] = None) -> Path:
    """
    S7 报告输出白名单：resolve 后必须位于 base_dir（默认 ./reports/）内，
    否则视为路径穿越并拒绝。
    """
    base = Path(base_dir or DEFAULT_OUTPUT_DIR).resolve()
    target = Path(path).resolve()
    if base != target and base not in target.parents:
        raise ValueError(
            f"路径穿越被拒绝（S7 白名单）：{path} 不在输出目录 {base} 内"
        )
    return target


def save_report(markdown: str, filename: str, base_dir: Optional[str] = None) -> Path:
    """将报告写入白名单输出目录"""
    target = validate_output_path(Path(base_dir or DEFAULT_OUTPUT_DIR) / filename, base_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(markdown, encoding="utf-8")
    return target


def _fmt_hours(v: Optional[float]) -> str:
    if v is None:
        return "无数据"
    if v < 1:
        return f"{v * 60:.0f} 分钟"
    if v < 48:
        return f"{v:.1f} 小时"
    return f"{v / 24:.1f} 天"


def _fmt_ratio(v: Optional[float]) -> str:
    return "无数据" if v is None else f"{v * 100:.1f}%"


def _cwe_str(profile: DeveloperProfile) -> str:
    if not profile.cwe_top3:
        return "-"
    counts = profile.vuln_counts_by_cwe
    return ", ".join(f"{cwe}({counts.get(cwe, 0)})" for cwe in profile.cwe_top3)


def generate_team_report(
    team: TeamProfile,
    reveal: bool = False,
    top_n: int = 5,
) -> str:
    """
    生成团队画像报告（Markdown）。

    reveal=True 时才在个人表中显示解密姓名（调用方须先通过 check_reveal_allowed 校验）。
    """
    m = team.metrics
    member_rows: List[Dict[str, Any]] = []
    for p in team.members[:top_n]:
        name = p.display_name if (reveal and p.display_name) else p.alias
        member_rows.append(
            {
                "成员": name,
                "发现数": p.total_findings,
                "Top CWE": _cwe_str(p),
                "平均修复时长": _fmt_hours(p.avg_fix_hours),
                "复犯率": _fmt_ratio(p.repeat_rate),
                "趋势": f"{p.trend:+.1f}/月",
            }
        )

    lines: List[str] = []
    lines.append(f"# 玄鉴 开发者画像 · 团队报告（{team.period}）")
    lines.append("")
    lines.append(PRIVACY_BANNER)
    lines.append("")
    lines.append("## 1. 团队健康度")
    lines.append("")
    lines.append(f"**{team.health_score:.1f} / 100**（发现 {team.findings} 条，归因覆盖率 {_fmt_ratio(team.coverage)}）")
    lines.append("")

    lines.append("## 2. 四指标 vs 行业基准")
    lines.append("")
    lines.append("| 指标 | 实际值 | 基准 | 分项得分/满分 | 评价 |")
    lines.append("|------|--------|------|--------------|------|")

    density = m.get("vuln_density")
    kloc_note = "" if m.get("kloc") else "（未提供代码行数，按中性计）"
    lines.append(
        f"| 漏洞密度 | {density if density is not None else '无数据'}/千行{kloc_note} "
        f"| {DENSITY_BASELINE}/千行 | {m.get('density_score', 0):.1f}/30 "
        f"| {'达标' if m.get('density_score', 0) >= 15 else '待改进'} |"
    )
    avg_fix = m.get("avg_fix_hours")
    lines.append(
        f"| 平均修复时长 | {_fmt_hours(avg_fix)} | {FIX_SPEED_BASELINE_H:.0f}h "
        f"| {m.get('fix_speed_score', 0):.1f}/30 | {'达标' if m.get('fix_speed_score', 0) >= 15 else '待改进'} |"
    )
    lines.append(
        f"| 复犯率 | {_fmt_ratio(m.get('repeat_rate', 0.0))} | {REPEAT_BASELINE * 100:.0f}% "
        f"| {m.get('repeat_score', 0):.1f}/25 | {'达标' if m.get('repeat_score', 0) >= 12.5 else '待改进'} |"
    )
    lines.append(
        f"| 高危占比 | {_fmt_ratio(m.get('high_risk_ratio', 0.0))} | {HIGH_RISK_BASELINE * 100:.0f}% "
        f"| {m.get('high_risk_score', 0):.1f}/15 | {'达标' if m.get('high_risk_score', 0) >= 7.5 else '待改进'} |"
    )
    lines.append("")

    lines.append("## 3. 关键发现")
    lines.append("")
    key_points: List[str] = []
    if m.get("repeat_rate", 0) > REPEAT_BASELINE:
        key_points.append(
            f"- 复犯率 {_fmt_ratio(m['repeat_rate'])} 高于基准 {REPEAT_BASELINE * 100:.0f}%："
            "存在同位置问题反复出现，建议引入根因复盘。"
        )
    if m.get("high_risk_ratio", 0) > HIGH_RISK_BASELINE:
        key_points.append(
            f"- 高危占比 {_fmt_ratio(m['high_risk_ratio'])} 高于基准 {HIGH_RISK_BASELINE * 100:.0f}%："
            "CRITICAL/HIGH 问题占比偏高，建议优先排期修复。"
        )
    if avg_fix is not None and avg_fix > FIX_SPEED_BASELINE_H:
        key_points.append(
            f"- 平均修复时长 {_fmt_hours(avg_fix)} 超过基准 {FIX_SPEED_BASELINE_H:.0f}h：建议缩短修复 SLA。"
        )
    if team.coverage < 0.5:
        key_points.append(
            f"- 归因覆盖率仅 {_fmt_ratio(team.coverage)}：多数发现未能定位到作者"
            "（非 git 目录或 blame 缺失），画像参考价值有限。"
        )
    if not key_points:
        key_points.append("- 各项指标均在基准之内，保持当前工程实践。")
    lines.extend(key_points)
    lines.append("")

    lines.append(f"## 4. Top {top_n} 个人画像（匿名别名）")
    lines.append("")
    if member_rows:
        header = "| " + " | ".join(member_rows[0].keys()) + " |"
        sep = "|" + "|".join(["------"] * len(member_rows[0])) + "|"
        lines.append(header)
        lines.append(sep)
        for row in member_rows:
            lines.append("| " + " | ".join(str(v) for v in row.values()) + " |")
    else:
        lines.append("（周期内无归因数据）")
    lines.append("")

    lines.append("## 5. 下月目标（算法建议）")
    lines.append("")
    targets: List[str] = []
    if density is not None and density > DENSITY_BASELINE:
        targets.append(f"- 漏洞密度从 {density:.2f}/千行 降至 ≤ {DENSITY_BASELINE}/千行。")
    if avg_fix is not None and avg_fix > FIX_SPEED_BASELINE_H:
        targets.append(f"- 平均修复时长从 {_fmt_hours(avg_fix)} 缩短至 ≤ {FIX_SPEED_BASELINE_H:.0f}h。")
    if m.get("repeat_rate", 0) > REPEAT_BASELINE:
        targets.append(f"- 复犯率从 {_fmt_ratio(m['repeat_rate'])} 降至 ≤ {REPEAT_BASELINE * 100:.0f}%。")
    if m.get("high_risk_ratio", 0) > HIGH_RISK_BASELINE:
        targets.append(f"- 高危占比从 {_fmt_ratio(m['high_risk_ratio'])} 降至 ≤ {HIGH_RISK_BASELINE * 100:.0f}%。")
    if not targets:
        targets.append("- 维持当前各项指标在基准之内，重点巩固团队安全知识共享。")
    lines.extend(targets)
    lines.append("")
    lines.append(REPORT_FOOTER)
    lines.append("")
    return "\n".join(lines)


def generate_personal_report(
    profile: DeveloperProfile,
    team_metrics: Optional[Dict[str, Any]] = None,
    reveal: bool = False,
) -> str:
    """生成个人画像报告（本人视角，含团队匿名平均对比）"""
    m = team_metrics or {}
    name = profile.display_name if (reveal and profile.display_name) else profile.alias

    lines: List[str] = []
    lines.append(f"# 玄鉴 开发者画像 · 个人报告（{profile.period or 'all'}）")
    lines.append("")
    lines.append(PRIVACY_BANNER)
    lines.append("")
    lines.append(f"**开发者**：{name}")
    lines.append("")

    lines.append("## 六维度画像")
    lines.append("")
    lines.append("| 维度 | 数值 | 说明 |")
    lines.append("|------|------|------|")
    lines.append(
        f"| 漏洞模式偏好 | {_cwe_str(profile)} | 发现数 Top3 的 CWE 类型 |"
    )
    lines.append(
        f"| 修复速度 | {_fmt_hours(profile.avg_fix_hours)} | 首次发现到 mark fixed 的时间差（无数据置空） |"
    )
    lines.append(
        f"| 修复质量 | {_fmt_ratio(profile.fix_pass_rate)} | 修复后 30 天内同文件同 CWE 未复发比例 |"
    )
    lines.append(
        f"| 复犯率 | {_fmt_ratio(profile.repeat_rate)} | 同一问题（fingerprint）重复出现占比 |"
    )
    lines.append(
        f"| 知识盲区 | {', '.join(profile.knowledge_gaps) if profile.knowledge_gaps else '无'} | 占比 >30% 的 CWE 类型 |"
    )
    trend_desc = "改善中" if profile.trend < 0 else ("上升中" if profile.trend > 0 else "持平")
    lines.append(
        f"| 成长趋势 | {profile.trend:+.1f}/月（{trend_desc}） | 月度发现数线性斜率，负值代表改善 |"
    )
    lines.append("")

    lines.append("## 与团队匿名平均对比")
    lines.append("")
    team_avg_fix = m.get("avg_fix_hours")
    lines.append("| 指标 | 本人 | 团队 |")
    lines.append("|------|------|------|")
    lines.append(
        f"| 平均修复时长 | {_fmt_hours(profile.avg_fix_hours)} | {_fmt_hours(team_avg_fix)} |"
    )
    lines.append(
        f"| 复犯率 | {_fmt_ratio(profile.repeat_rate)} | {_fmt_ratio(m.get('repeat_rate'))} |"
    )
    lines.append(
        f"| 高危占比 | 见团队报告 | {_fmt_ratio(m.get('high_risk_ratio'))} |"
    )
    lines.append("")

    lines.append("## 建议")
    lines.append("")
    tips: List[str] = []
    if profile.knowledge_gaps:
        tips.append(
            f"- 针对高频 CWE（{', '.join(profile.knowledge_gaps)}）进行专项学习与代码自查清单建设。"
        )
    if profile.avg_fix_hours is not None and profile.avg_fix_hours > FIX_SPEED_BASELINE_H:
        tips.append(f"- 将平均修复时长压缩到 {FIX_SPEED_BASELINE_H:.0f}h 以内。")
    if profile.repeat_rate > REPEAT_BASELINE:
        tips.append("- 关注同位置复发问题，修复时补充回归测试。")
    if not tips:
        tips.append("- 各维度表现良好，继续保持安全编码习惯。")
    lines.extend(tips)
    lines.append("")
    lines.append(REPORT_FOOTER)
    lines.append("")
    return "\n".join(lines)
