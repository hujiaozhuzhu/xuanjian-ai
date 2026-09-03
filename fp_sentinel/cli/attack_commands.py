"""
A7. 攻防 CLI 命令与报告流水线（Agent-Attack 领地）

- fp-sentinel attack purge / fp-sentinel attack-purge：清理 >30 天 PoC/攻防数据（S5）
- 报告流水线：scan 命令内部复用（合规/攻防 Markdown 生成）

安全红线：
- S1: PoC 生成经 _assert_local 守卫，目标默认 127.0.0.1
- S2: 只生成报告与 diff 字符串，绝不修改用户源文件
- S5: 攻防数据落库记录 created_at，attack-purge 清理过期数据
- S7: 报告文件仅写入 --output 白名单目录
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import typer
from rich.console import Console

from ..attack import (
    PocInstance,
    generate_poc,
    verify,
    assess,
    orchestrate,
    ExploitabilityResult,
    VerifyResult,
)
from ..attack.poc_templates import DEFAULT_PARAM, DEFAULT_TARGET
from ..attack.chain_orchestrator import AttackChainReport
from ..database import get_database, FindingRepo, ScanHistoryRepo
from ..reporting.attack_report import generate_attack_report, write_report
from ..reporting.compliance_report import compute_trend, generate_compliance_report

logger = logging.getLogger(__name__)
console = Console()

ATTACK_RECORDS_SQL = """
CREATE TABLE IF NOT EXISTS attack_poc_records (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project_path    TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    line_start      INTEGER DEFAULT 0,
    vuln_type       TEXT DEFAULT '',
    poc_text        TEXT DEFAULT '',
    verify_status   TEXT DEFAULT 'manual_required',
    probability     REAL DEFAULT 0.0,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_attack_records_created ON attack_poc_records(created_at);
"""


# ─────────────────────── 规则 → PoC 漏洞类型映射 ───────────────────────

_RULE_TO_VULN = [
    (("sql",), "sqli-union"),
    (("format",), "sql-format-string"),
    (("xss", "innerhtml"), "xss-dom"),
    (("command", "cmd", "os.system"), "cmd-injection"),
    (("eval", "function-constructor"), "cmd-injection"),
    (("ssrf",), "ssrf"),
    (("path", "traversal"), "path-traversal"),
    (("jwt",), "jwt-weak"),
    (("pickle",), "deser-pickle"),
    (("yaml",), "deser-yaml"),
    (("xxe",), "xxe"),
    (("proto",), "prototype-pollution"),
    (("redirect",), "open-redirect"),
    (("nosql",), "nosql-injection"),
    (("ssti", "template"), "ssti"),
    (("hash", "md5", "sha1"), "weak-hash"),
    (("secret", "hardcoded", "api-key", "password"), "hardcoded-secret"),
    (("debug",), "debug-mode"),
    (("csrf",), "csrf-missing"),
    (("prompt-injection", "aigc"), "llm-prompt-injection"),
]


def vuln_type_for_rule(rule_id: str) -> Optional[str]:
    """把扫描规则 ID 映射为 PoC 模板漏洞类型"""
    rid = (rule_id or "").lower()
    for patterns, vt in _RULE_TO_VULN:
        if any(p in rid for p in patterns):
            if vt in POC_VULN_TYPES:
                return vt
    return None


# 延迟导入避免循环
from ..attack.poc_templates import POC_TEMPLATES  # noqa: E402
POC_VULN_TYPES = set(POC_TEMPLATES.keys())


# ─────────────────────── 攻防流水线（scan 内部复用） ───────────────────────

def _read_file_context(project_path: str, file_path: str) -> Optional[str]:
    """只读源文件作为可达性上下文（不修改，S2）"""
    candidates = [Path(file_path), Path(project_path) / file_path.lstrip("/\\")]
    for p in candidates:
        try:
            if p.is_file():
                return p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return None


def build_attack_data(
    project_path: str,
    findings: List[Any],
) -> Tuple[AttackChainReport, List[ExploitabilityResult], List[VerifyResult], Dict[str, PocInstance]]:
    """攻防分析流水线：初筛 → 编排 → PoC → 验证（默认 simulated，零网络）"""
    # 1. 可利用性初筛（源码作为可达性上下文）
    exploit_results = []
    for f in findings:
        ctx = _read_file_context(project_path, getattr(f, "file_path", ""))
        exploit_results.append(assess(f, context_lines=ctx, network_exposure="public"))

    # 2. 攻击链编排
    from ..attack.chain_orchestrator import node_id
    chain_report = orchestrate(
        findings, project=Path(project_path).name,
        exploit_results={node_id(f): er for f, er in zip(findings, exploit_results)},
    )

    # 3. PoC 生成（目标固定为本地回环 —— S1；无法映射类型的规则不生成）
    poc_map: Dict[str, PocInstance] = {}
    for f in findings:
        vt = vuln_type_for_rule(getattr(f, "rule_id", ""))
        if vt and vt not in poc_map:
            try:
                poc_map[vt] = generate_poc(vt, target=DEFAULT_TARGET, param=DEFAULT_PARAM)
            except Exception as e:  # noqa: BLE001
                logger.warning("PoC 生成失败 %s: %s", vt, e)

    # 4. 验证（无 Docker 环境一律 simulated/manual_required，诚实标注）
    verify_results = [
        verify(f, project_root=project_path, allow_docker=False)
        for f in findings
    ]
    return chain_report, exploit_results, verify_results, poc_map


async def save_attack_records(
    db,
    project_path: str,
    findings: List[Any],
    exploit_results: List[ExploitabilityResult],
    verify_results: List[VerifyResult],
    poc_map: Dict[str, PocInstance],
) -> int:
    """攻防数据落库（S5：记录 created_at 供 30 天清理）"""
    await db.conn.executescript(ATTACK_RECORDS_SQL)
    rows = []
    for f, er, vr in zip(findings, exploit_results, verify_results):
        vt = vuln_type_for_rule(getattr(f, "rule_id", "")) or ""
        poc = poc_map.get(vt)
        rows.append((
            project_path,
            getattr(f, "rule_id", ""),
            getattr(f, "file_path", ""),
            getattr(f, "line_start", 0) or 0,
            vt,
            (poc.rendered if poc else "")[:2000],
            vr.status.value,
            er.probability,
            datetime.now(timezone.utc).isoformat(),
        ))
    if rows:
        await db.conn.executemany(
            """INSERT INTO attack_poc_records
               (project_path, rule_id, file_path, line_start, vuln_type,
                poc_text, verify_status, probability, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        await db.conn.commit()
    return len(rows)


async def purge_attack_records(db, days: int = 30) -> int:
    """清理超过 N 天的攻防 PoC 数据（S5）"""
    await db.conn.executescript(ATTACK_RECORDS_SQL)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    cursor = await db.conn.execute(
        "DELETE FROM attack_poc_records WHERE created_at < ?", (cutoff,)
    )
    await db.conn.commit()
    return cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0


# ─────────────────────── 命令定义 ───────────────────────

attack_app = typer.Typer(help="攻防数据管理（PoC 30 天清理等）", add_completion=False)


@attack_app.command("purge")
def purge_cmd(
    days: int = typer.Option(30, "--days", "-d", help="保留天数（默认 30 天）"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="配置文件"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """清理超过保留期的 PoC/攻防数据（S5 红线）"""
    _run_purge(days=days, config_file=config_file, verbose=verbose)


def attack_purge_entry(
    days: int = typer.Option(30, "--days", "-d", help="保留天数（默认 30 天）"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="配置文件"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """顶层别名命令：fp-sentinel attack-purge（同 attack purge）"""
    _run_purge(days=days, config_file=config_file, verbose=verbose)


def _run_purge(days: int, config_file: Optional[str], verbose: bool) -> None:
    from ..config import load_config, expand_db_path

    async def _run():
        if verbose:
            logging.basicConfig(level=logging.DEBUG)
        config = load_config(config_file)
        db_path = expand_db_path(config.database.path)
        async with get_database(db_path, config.database.wal_mode) as db:
            deleted = await purge_attack_records(db, days=days)
        console.print(f"[green]✓ 已清理 {deleted} 条超过 {days} 天的攻防 PoC 数据[/green]")

    asyncio.run(_run())
