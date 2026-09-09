"""
玄鉴 v3.0 — 误报优化 CLI 命令模块

提供 fp-optimize 子命令组，覆盖：
  - submit-feedback 提交用户反馈
  - list           查询反馈/统计
  - stats          查看统计和趋势
  - optimize       触发自动优化
  - profile        管理代码风格画像
"""

import asyncio
import sys
from pathlib import Path

import click


# ═════════════════════ 异步辅助 ═════════════════════

def coro(func):
    """将 async click 回调同步化"""
    import functools
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return asyncio.run(func(*args, **kwargs))
    return wrapper


def get_store(db_path=None):
    """构建并初始化 FeedbackStore"""
    from ..fp_optimize.feedback_store import FeedbackStore

    if db_path is None:
        db_path = str(Path.home() / ".xuanjian" / "fp_optimize.db")
    return FeedbackStore(db_path=db_path)


async def _ensure_store(store):
    await store.initialize()
    return store


# ═════════════════════ 命令组 ═════════════════════

@click.group("fp-optimize")
@click.option("--db", "db_path", default=None, help="FeedbackStore 数据库路径")
@click.pass_context
def fp_optimize(ctx, db_path):
    """自适应误报引擎 (v3.0): 反馈收集、自动优化、统计仪表板"""
    ctx.ensure_object(dict)
    ctx.obj["db_path"] = db_path


# ═════════════════════ feedback 子组（显式 --help） ═════════════════════

@fp_optimize.group("feedback")
def feedback():
    """用户反馈管理"""
    pass


@feedback.command("submit")
@click.option("--finding-id", required=True, help="关联发现ID")
@click.option("--type", "ftype", required=True,
              type=click.Choice(["false_positive", "true_positive", "unsure"]),
              help="反馈类型")
@click.option("--project-id", default=None, help="项目ID")
@click.option("--confidence", default=1.0, type=float, help="置信度 0-1")
@click.option("--reason", default=None, help="反馈原因")
@click.option("--marker", default=None, help="标记人")
@click.option("--rule-id", default=None, help="规则ID")
@click.option("--scanner", default=None, help="扫描器名称")
@coro
async def submit_feedback(finding_id, ftype, project_id, confidence, reason, marker, rule_id, scanner, **kwargs):
    """提交单条误报/真报反馈"""
    from ..fp_optimize.models import FeedbackType, FeedbackSource

    store = get_store(kwargs.get("db_path"))
    await _ensure_store(store)
    fb = await store.add_feedback(
        finding_id=finding_id,
        feedback_type=FeedbackType(ftype),
        project_id=project_id,
        source=FeedbackSource.MANUAL,
        confidence=confidence,
        reason=reason,
        marker=marker,
        rule_id=rule_id,
        scanner=scanner,
    )
    click.echo(f"[OK] 反馈已记录 | id={fb.id} | type={ftype} | finding={finding_id}")


@feedback.command("list")
@click.option("--project-id", default=None, help="按项目筛选")
@click.option("--ftype", "feedback_type", default=None, help="按反馈类型筛选")
@click.option("--rule-id", default=None, help="按规则筛选")
@click.option("--limit", default=50, type=int, help="最大返回数")
@coro
async def list_feedbacks(project_id, feedback_type, rule_id, limit, **kwargs):
    """列出反馈记录"""
    store = get_store(kwargs.get("db_path"))
    await _ensure_store(store)
    items = await store.list_feedbacks(
        project_id=project_id,
        feedback_type=feedback_type,
        rule_id=rule_id,
        limit=limit,
    )
    if not items:
        click.echo("(无反馈记录)")
        return
    click.echo(f"{'ID':<40} {'TYPE':<15} {'PROJECT':<12} {'FINDING':<16} {'TIME'}")
    click.echo("-" * 110)
    for f in items:
        click.echo(f"{f.id:<40} {f.feedback_type.value:<15} {str(f.project_id or '-'):<12} "
                   f"{str(f.finding_id)[:14]:<16} {f.created_at.strftime('%Y-%m-%d %H:%M') if f.created_at else '-'}")


# ═════════════════════ stats ═════════════════════

@fp_optimize.command("stats")
@click.option("--project-id", default=None, help="项目ID")
@click.option("--json-output", "as_json", is_flag=True, default=False, help="JSON 输出")
@coro
async def show_stats(project_id, as_json, **kwargs):
    """查看统计汇总"""
    from ..fp_optimize.feedback_engine import FeedbackLearningEngine

    store = get_store(kwargs.get("db_path"))
    await _ensure_store(store)
    engine = FeedbackLearningEngine(store)
    stats = await engine.get_feedback_statistics(project_id)

    if as_json:
        click.echo(stats.model_dump_json(indent=2))
    else:
        click.echo("[[ 误报优化统计 ]]")
        click.echo(f"  总反馈: {stats.total_feedbacks}")
        click.echo(f"  误报数: {stats.fp_feedbacks}")
        click.echo(f"  真报数: {stats.tp_feedbacks}")
        click.echo(f"  待定数: {stats.unsure_feedbacks}")
        click.echo(f"  当前误报率: {stats.fp_rate:.2%}")
        click.echo(f"  目标误报率: {stats.target_fp_rate:.0%}")
        click.echo(f"  趋势: {stats.fp_rate_trend}")
        click.echo(f"  优化次数: {stats.optimization_count}")
        if stats.top_fp_rules:
            click.echo("\n  [[ 高频误报规则 TOP5 ]]")
            for r in stats.top_fp_rules[:5]:
                click.echo(f"    {r['rule_id']}: {r['fp_count']}/{r['total']} ({r['fp_pct']}%)")


@fp_optimize.command("trend")
@click.option("--project-id", default=None, help="项目ID")
@click.option("--days", default=30, type=int, help="天数")
@coro
async def show_trend(project_id, days, **kwargs):
    """查看误报率趋势"""
    from ..fp_optimize.stats_engine import StatsEngine
    from ..fp_optimize.feedback_engine import FeedbackLearningEngine

    store = get_store(kwargs.get("db_path"))
    await _ensure_store(store)
    fe = FeedbackLearningEngine(store)
    se = StatsEngine(store)
    # 复用 engine 内部引用
    se._feedback_engine = fe

    report = await se.get_trend_report(project_id, days)

    click.echo(f"[[ {days}天 误报率趋势报告 ]]")
    if report.get("trends"):
        for t in report["trends"]:
            rate_str = f"{t['fp_rate_pct']}%" if t.get("fp_rate_pct") is not None else "N/A"
            arrow = "↑" if t["fp_rate_pct"] and t["fp_rate_pct"] > 1 else "↓"
            click.echo(f"  {t['date']}  samples={t['samples']:>3}  fp={t['fp_count']:>3}  "
                       f"rate={rate_str:>6}  {arrow}")
    else:
        click.echo("  (暂无数据)")

    if report.get("prediction"):
        p = report["prediction"]
        click.echo(f"\n  预测(7天): {p.get('predicted_fp_rate_7d', 'N/A')}%")
        click.echo(f"  预测趋势: {p.get('trend', 'N/A')}")


@fp_optimize.command("recommendations")
@click.option("--project-id", default=None, help="项目ID")
@coro
async def show_recommendations(project_id, **kwargs):
    """查看优化建议"""
    from ..fp_optimize.stats_engine import StatsEngine
    from ..fp_optimize.feedback_engine import FeedbackLearningEngine

    store = get_store(kwargs.get("db_path"))
    await _ensure_store(store)
    fe = FeedbackLearningEngine(store)
    se = StatsEngine(store)
    se._feedback_engine = fe

    recs = await se.get_recommendations(project_id)
    if not recs:
        click.echo("(当前无需优化)")
        return
    for r in recs:
        prio = r["priority"]
        icon = {"high": "!", "medium": "~", "info": "·", "success": "✓"}.get(prio, " ")
        click.echo(f"  [{icon}] ({r['priority']}) {r['message']}")
        if r.get("action"):
            click.echo(f"      → {r['action']}")


# ═════════════════════ optimize ═════════════════════

@fp_optimize.command("run")
@click.option("--project-id", default=None, help="项目ID")
@click.option("--dry-run", is_flag=True, default=False, help="仅分析不应用")
@coro
async def run_optimize(project_id, dry_run, **kwargs):
    """执行自动优化：识别FP模式，调整规则权重和特异性"""
    from ..fp_optimize.feedback_engine import FeedbackLearningEngine
    from ..fp_optimize.models import OptimizationStatus

    store = get_store(kwargs.get("db_path"))
    await _ensure_store(store)
    engine = FeedbackLearningEngine(store)

    click.echo(f"开始自动优化 (dry_run={dry_run}) ...")
    result = await engine.analyze_and_optimize(project_id=project_id, dry_run=dry_run)

    click.echo(f"\n状态: {result.get('status')}")
    if "feedback_stats" in result:
        s = result["feedback_stats"]
        click.echo(f"  反馈总数: {s.get('total_feedbacks')}")
        click.echo(f"  误报率: {s.get('fp_rate', 0):.2%}")

    if "optimization_id" in result:
        click.echo(f"  优化记录ID: {result['optimization_id']}")

    if "weight_adjustments" in result:
        wa = result["weight_adjustments"]
        if wa:
            click.echo("\n  [[ 权重调整 ]]")
            for adj in wa:
                arrow = "↑" if adj.direction == "increase" else "↓"
                click.echo(f"    {adj.rule_id}  weight {adj.current_weight} → {adj.recommended_weight} {arrow}")

    if "specificity_adjustments" in result:
        sa = result["specificity_adjustments"]
        if sa:
            click.echo("\n  [[ 特异性调整 ]]")
            for adj in sa:
                click.echo(f"    {adj.rule_id}  pattern_count {adj.current_patterns} → {adj.recommended_patterns}")

    if dry_run:
        click.echo("\n(dry_run 模式，未实际应用任何更改)")


@fp_optimize.command("patterns")
@click.option("--project-id", default=None, help="项目ID")
@click.option("--min-confidence", default=0.6, type=float, help="最低置信度")
@coro
async def show_patterns(project_id, min_confidence, **kwargs):
    """识别系统性误报模式"""
    from ..fp_optimize.feedback_engine import FeedbackLearningEngine

    store = get_store(kwargs.get("db_path"))
    await _ensure_store(store)
    engine = FeedbackLearningEngine(store)
    patterns = await engine.identify_fp_patterns(project_id, min_confidence)

    if not patterns:
        click.echo("(未识别到显著误报模式)")
        return

    click.echo("[[ 系统性误报模式 ]]")
    for p in patterns:
        click.echo(f"\n  规则: {p['rule_id']}")
        click.echo(f"  误报概率: {p['fp_probability']:.1%}")
        if p.get("affected_findings"):
            click.echo(f"  影响发现: {len(p['affected_findings'])} 个")
        if p.get("suggestions"):
            for s in p["suggestions"]:
                click.echo(f"    建议: {s}")


# ═════════════════════ profile ═════════════════════

@fp_optimize.group("profile")
def profile():
    """代码风格画像管理"""
    pass


@profile.command("show")
@click.option("--project-id", required=True, help="项目ID")
@click.option("--json-output", "as_json", is_flag=True, default=False, help="JSON 输出")
@coro
async def show_profile(project_id, as_json, **kwargs):
    """查看代码风格画像"""
    from ..fp_optimize.personalization import PersonalizationEngine

    store = get_store(kwargs.get("db_path"))
    await _ensure_store(store)
    engine = PersonalizationEngine(store)
    profile = await engine.get_profile(project_id)
    if profile is None:
        click.echo(f"(项目 '{project_id}' 尚无风格画像，请运行 'fp optimize profile build' 构建)")
        return

    if as_json:
        click.echo(profile.model_dump_json(indent=2))
    else:
        click.echo(f"[[ 项目 '{project_id}' 代码风格画像 ]]")
        click.echo(f"  语言: {profile.languages}")
        click.echo(f"  风格标签: {profile.style_tags}")
        click.echo(f"  框架线索: {profile.framework_hints}")
        click.echo(f"  低置信包管理器: {profile.low_confidence_packages}")
        click.echo(f"  第三方模块: {profile.thirdparty_modules[:10]}...")
        click.echo(f"  可信函数: {profile.trusted_functions[:10]}...")
        click.echo(f"  样本指纹: {profile.sample_fingerprints} 个")
        click.echo(f"  错误模式: {profile.error_patterns}")
        click.echo(f"  构建版本: {profile.build_version}")
        click.echo(f"  更新时间: {profile.updated_at}")


@profile.command("build")
@click.option("--project-id", required=True, help="项目ID")
@click.argument("source_path", required=False, default=".")
@coro
async def build_profile(project_id, source_path, **kwargs):
    """构建代码风格画像（扫描项目目录）"""
    from ..fp_optimize.personalization import PersonalizationEngine

    store = get_store(kwargs.get("db_path"))
    await _ensure_store(store)
    engine = PersonalizationEngine(store)

    src = Path(source_path)
    if not src.exists():
        click.echo(f"(路径 {source_path} 不存在，使用空数据构建基础画像)")

    profile = await engine.build_profile(project_id)
    click.echo(f"[OK] 项目 '{project_id}' 代码风格画像已构建")
    click.echo(f"  语言: {profile.languages}")
    click.echo(f"  风格标签: {profile.style_tags}")
    click.echo(f"  样本指纹: {len(profile.sample_fingerprints)} 个")


@fp_optimize.command("export")
@click.option("--project-id", default=None, help="项目ID")
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "csv"]), help="导出格式")
@click.option("--output", "-o", default=None, help="输出路径（默认stdout）")
@coro
async def export_data(project_id, fmt, output, **kwargs):
    """导出反馈数据"""
    import csv
    import io
    import json as _json

    store = get_store(kwargs.get("db_path"))
    await _ensure_store(store)
    items = await store.list_feedbacks(project_id=project_id, limit=10000)

    if fmt == "json":
        data = _json.dumps([f.model_dump() for f in items], default=str, ensure_ascii=False, indent=2)
    else:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "finding_id", "feedback_type", "project_id", "confidence",
                     "reason", "marker", "rule_id", "scanner", "created_at"])
        for f in items:
            w.writerow([f.id, f.finding_id, f.feedback_type.value, f.project_id,
                        f.confidence, f.reason, f.marker, f.rule_id, f.scanner,
                        f.created_at.isoformat() if f.created_at else ""])
        data = buf.getvalue()

    if output:
        Path(output).write_text(data, encoding="utf-8")
        click.echo(f"[OK] 已导出 {len(items)} 条到 {output}")
    else:
        click.echo(data)


if __name__ == "__main__":
    fp_optimize()
