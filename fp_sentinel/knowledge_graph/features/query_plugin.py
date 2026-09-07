"""
知识图谱查询插件 —— 扫描时按规则 CWE/分类自动匹配历史同类漏洞/修复/CVE

匹配逻辑：
1) 读取归档库（kg_fix_records），按「分类 / cwe / rule_id 前缀 / 语言 / 严重度」加权召回；
2) 若归档为空（首次部署），回退到内置的_CATEGORY_KNOWLEDGE 静态知识（CVE + fix_title + diff），
   保证零网络前提下也能给报告补充案例参考；
3) 对每条 finding 选出 top-K 最相似记录，并注入其「修复建议」（来自 fix_advisor 同步表）。

评分规则（score_match）：
    + 分类一致 ........ 0.50
    + CWE 一致 ........ 0.30    (两者任一为 None 不加分)
    + 严重度一致 ...... 0.10
    + 语言一致 ........ 0.05
    + 同 rule_id ...... 0.05
    + 时间衰减 ........ exp(-age_days/365) * 0.10
    上限 1.0；下限 0.05。
"""

from __future__ import annotations

import logging
import math
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..models import KnowledgeMatch

logger = logging.getLogger(__name__)


# ─────────────────────── 内置静态知识库（无归档时的兜底 CVE + 修复方案） ───────────────────────

class _Knowledge(Tuple):
    """placeholder, never used directly"""


# 分类 → 内置参考 (CVE, 修复标题, diff, incident_note, fix_effort_minutes, 标题对应的 fix_diff 关键字)
_CATEGORY_KNOWLEDGE: List[Dict[str, Any]] = [
    dict(
        category="sqli", cwe="CWE-89",
        fix_title="SQL 注入（字符串拼接）",
        reference_cve="CVE-2012-2122",
        incident_note="拼接 SQL 曾导致大规模拖库（如 Heartland 2008，1.3 亿条记录泄露）。",
        fix_diff=(
            "--- a/file.sql\n+++ b/suggested-fix\n@@ SQL 注入 @@\n"
            '-query = "SELECT * FROM users WHERE id = " + user_id\n'
            '+query = "SELECT * FROM users WHERE id = %s"\n'
            "+cursor.execute(query, (user_id,))"
        ),
        effort_minutes=45,
    ),
    dict(
        category="xss", cwe="CWE-79",
        fix_title="XSS（未转义输出）",
        reference_cve="CVE-2014-9031",
        incident_note="TweetDeck 2014 XSS 蠕虫令 3.8 万用户转发恶意推文。",
        fix_diff=(
            "--- a/file.html\n+++ b/suggested-fix\n@@ XSS @@\n"
            "-el.innerHTML = userInput\n"
            "+el.textContent = userInput  # 或 DOMPurify.sanitize(html)"
        ),
        effort_minutes=30,
    ),
    dict(
        category="cmd", cwe="CWE-78",
        fix_title="命令注入",
        reference_cve="CVE-2014-6271",
        incident_note="Shellshock（CVE-2014-6271）通过环境变量注入命令，波及数十万台服务器。",
        fix_diff=(
            "--- a/file.py\n+++ b/suggestedfix\n@@ 命令注入 @@\n"
            "-os.system('ping ' + host)\n"
            "+subprocess.run(['ping', host], shell=False)  # 参数数组 + 白名单"
        ),
        effort_minutes=60,
    ),
    dict(
        category="path", cwe="CWE-22",
        fix_title="路径遍历",
        reference_cve="CVE-2020-17519",
        incident_note="Apache Flink CVE-2020-17519 通过 ../ 读取任意文件。",
        fix_diff=(
            "--- a/file.py\n+++ b/suggestedfix\n@@ 路径遍历 @@\n"
            "-path = os.path.join(base, filename)\n"
            "+real = os.path.realpath(os.path.join(base, filename))\n"
            "+if not real.startswith(os.path.realpath(base)):\n"
            "+    abort(403)"
        ),
        effort_minutes=45,
    ),
    dict(
        category="secret", cwe="CWE-798",
        fix_title="硬编码密钥",
        reference_cve="CVE-2018-0114",
        incident_note="Uber 2016 年因硬编码 AWS 凭证泄露 5700 万用户数据。",
        fix_diff=(
            "--- a/file.py\n+++ b/suggestedfix\n@@ 硬编码密钥 @@\n"
            '-SECRET_KEY = "abc123"\n'
            '+SECRET_KEY = os.environ["SECRET_KEY"]  # 并轮换已泄露密钥'
        ),
        effort_minutes=30,
    ),
    dict(
        category="jwt", cwe="CWE-347",
        fix_title="JWT 弱密钥/弱算法",
        reference_cve="CVE-2015-9235",
        incident_note="CVE-2015-9235：algorithm 混淆允许 none/RS256↔HS256 伪造 token。",
        fix_diff=(
            "--- a/file.js\n+++ b/suggestedfix\n@@ JWT @@\n"
            "-const token = jwt.sign(payload, JWT_SECRET);\n"
            "+const token = jwt.sign(payload, process.env.JWT_SECRET, { algorithm: 'HS256' });"
        ),
        effort_minutes=30,
    ),
    dict(
        category="yaml", cwe="CWE-502",
        fix_title="YAML 不安全加载",
        reference_cve="CVE-2017-18342",
        incident_note="yaml.load 反序列化 RCE 是 Python 应用最常见 RCE 入口之一。",
        fix_diff=(
            "--- a/file.py\n+++ b/suggestedfix\n@@ YAML @@\n"
            "-result = yaml.load(data)\n"
            "+result = yaml.safe_load(data)"
        ),
        effort_minutes=15,
    ),
    dict(
        category="pickle", cwe="CWE-502",
        fix_title="Pickle 反序列化",
        reference_cve="CVE-2016-5636",
        incident_note="pickle.loads 等价于任意代码执行，历史上多次导致供应链 RCE。",
        fix_diff=(
            "--- a/file.py\n+++ b/suggestedfix\n@@ Pickle @@\n"
            "-obj = pickle.loads(data)\n"
            "+obj = json.loads(data)  # 禁止对不可信数据使用 pickle"
        ),
        effort_minutes=60,
    ),
    dict(
        category="eval", cwe="CWE-95",
        fix_title="eval 代码注入",
        reference_cve="CVE-2016-5636",
        incident_note="eval(用户输入) 直接等价于 RCE。",
        fix_diff=(
            "--- a/file.py\n+++ b/suggestedfix\n@@ eval @@\n"
            "-result = eval(expr)\n"
            "+result = ast.literal_eval(expr)  # 或 JSON.parse"
        ),
        effort_minutes=45,
    ),
    dict(
        category="ssrf", cwe="CWE-918",
        fix_title="SSRF",
        reference_cve="CVE-2021-21975",
        incident_note="vRealize SSRF（CVE-2021-21975）被用于窃取凭证后内网横向。",
        fix_diff=(
            "--- a/file.js\n+++ b/suggestedfix\n@@ SSRF @@\n"
            "-const resp = await axios.get(url);\n"
            "+if (!ALLOWED_HOSTS.some(h => url.startsWith(h))) return res.status(403).end();\n"
            "+const resp = await axios.get(url);"
        ),
        effort_minutes=60,
    ),
]

# 分类键 → 内置知识索引
_CATEGORY_INDEX: Dict[str, Dict[str, Any]] = {k["category"]: k for k in _CATEGORY_KNOWLEDGE}


# ────────────────────→ 分类推理：从 rule_id 推出分类键 ──────────────────────

_CATEGORY_RULE_PREFIX: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r"sql[._ -]?injection|injection[._ -]?sql|sqli|format.?string", re.I), "sqli"),
    (re.compile(r"xss|innerhtml|cross.?site", re.I), "xss"),
    (re.compile(r"command|cmd|injection[._ -]?command|os[._ -]?system", re.I), "cmd"),
    (re.compile(r"path|traversal|file[._ -]?read|access", re.I), "path"),
    (re.compile(r"secret|hardcoded|api[._ -]?key|password|hardcoded[._ -]?secret", re.I), "secret"),
    (re.compile(r"jwt|webtoken", re.I), "jwt"),
    (re.compile(r"yaml", re.I), "yaml"),
    (re.compile(r"pickle|marshal", re.I), "pickle"),
    (re.compile(r"eval|function[._ -]?constructor", re.I), "eval"),
    (re.compile(r"ssrf|url[._ -]?fetch|http[._ -]?request", re.I), "ssrf"),
]


def _infer_category(rule_id: str, explicit: Optional[str] = None) -> str:
    """从 rule_id + 显式 category 推导归一化分类键"""
    if explicit:
        return explicit.lower()
    rid = (rule_id or "").lower().replace("-", ".").replace("_", ".")
    for pattern, cat in _CATEGORY_RULE_PREFIX:
        if pattern.search(rid):
            return cat
    # fallback：按 '.' 首段
    return (rule_id or "unknown").split(".")[0].lower()


# ─────────────────────── 评分 ───────────────────────

def _age_days(archived_at: str) -> float:
    if not archived_at:
        return 3650.0
    try:
        dt = datetime.fromisoformat(archived_at.replace("Z", "+00:00"))
    except ValueError:
        return 3650.0
    delta = datetime.now(timezone.utc) - dt
    return max(0.0, delta.total_seconds() / 86400.0)


def score_match(
    *,
    finding_category: Optional[str],
    finding_cwe: Optional[str],
    finding_severity: Optional[str],
    finding_language: Optional[str],
    finding_rule_id: Optional[str],
    record: Dict[str, Any],
) -> float:
    """为一条归档记录 / 内置知识计算 0-1 相似度分数"""
    score = 0.0
    rec_cat = (record.get("category") or "").lower()
    find_cat = (finding_category or "").lower()
    if find_cat and rec_cat and find_cat == rec_cat:
        score += 0.50
    rec_cwe = record.get("cwe") or ""
    if finding_cwe and rec_cwe and finding_cwe.upper() == rec_cwe.upper():
        score += 0.30
    rec_sev = (record.get("severity") or "").upper()
    if finding_severity and finding_severity.upper() == rec_sev:
        score += 0.10
    rec_lang = (record.get("language") or "").lower()
    if finding_language and rec_lang and finding_language.lower() == rec_lang:
        score += 0.05
    rec_rule = (record.get("rule_id") or "").lower()
    if finding_rule_id and rec_rule and (
        rec_rule == finding_rule_id.lower()
        or rec_rule.startswith(finding_rule_id.lower())
        or finding_rule_id.lower().startswith(rec_rule)
    ):
        score += 0.05
    # 时间衰减：一年内给 0.10
    age = _age_days(record.get("archived_at") or "")
    score += math.exp(-age / 365.0) * 0.10
    return min(1.0, max(0.05, score))


# ─────────────────────── 查询插件 ───────────────────────

class KnowledgeQueryPlugin:
    """
    扫描期知识查询插件。

    - 通过 archive_fn 回调异步拉取候选记录（归档数据源）；
    - 通过 fallback 注入内置静态知识，做到「首次扫描也能补参考」；
    - match() 对单条 finding 召回 top-K 结果；
    - batch_match() 批量处理并对每条 finding 注入 metadata 与统计。

    archive_fn 原型: async (category, cwe, language, limit) -> List[dict]
    其中 dict 至少含 rule_id/severity/file_path/line_start/reference_cve/
                     fix_title/fix_diff/incident_note/archived_at
    """

    def __init__(
        self,
        archive_fn=None,
        *,
        top_k: int = 5,
        fallback: bool = True,
        min_score: float = 0.05,
    ):
        self.archive_fn = archive_fn
        self.top_k = int(top_k)
        self.fallback = fallback
        self.min_score = float(min_score)

    # ---------- 单条 / 批量 ----------
    async def match(
        self,
        *,
        rule_id: Optional[str] = None,
        category: Optional[str] = None,
        cwe: Optional[str] = None,
        severity: Optional[str] = None,
        language: Optional[str] = None,
    ) -> List[KnowledgeMatch]:
        cat = _infer_category(rule_id or "", category)
        candidates: List[Dict[str, Any]] = []

        # 1) 归档候选
        if self.archive_fn is not None:
            try:
                records = await self.archive_fn(
                    category=cat, cwe=cwe, language=language, limit=self.top_k * 10 or 50
                )
                for r in records:
                    candidates.append({
                        "rule_id": r.get("rule_id", ""),
                        "category": r.get("category") or cat,
                        "cwe": r.get("cwe"),
                        "language": r.get("language"),
                        "severity": r.get("severity"),
                        "file_path": r.get("file_path"),
                        "line_start": r.get("line_start"),
                        "fix_title": r.get("fix_title", ""),
                        "fix_diff": r.get("fix_diff", ""),
                        "reference_cve": r.get("reference_cve", ""),
                        "incident_note": r.get("incident_note", ""),
                        "archived_at": r.get("archived_at", ""),
                        "_id": r.get("id", ""),
                        "_origin": "archive",
                    })
            except Exception as e:  # noqa: BLE001 —— 归档读取失败不影响扫描
                logger.warning("knowledge archive_fn failed: %s", e)

        # 2) 内置 fallback
        if self.fallback and cat in _CATEGORY_INDEX:
            built = _CATEGORY_INDEX[cat]
            candidates.append({
                "rule_id": rule_id or "",
                "category": cat,
                "cwe": built["cwe"],
                "language": language,
                "severity": severity,
                "file_path": None,
                "line_start": None,
                "fix_title": built["fix_title"],
                "fix_diff": built["fix_diff"],
                "reference_cve": built["reference_cve"],
                "incident_note": built["incident_note"],
                "archived_at": "",
                "_id": f"fallback-{cat}",
                "_origin": "fallback",
            })

        # 评分 + 排序
        scored: List[KnowledgeMatch] = []
        for c in candidates:
            s = score_match(
                finding_category=cat,
                finding_cwe=cwe,
                finding_severity=severity,
                finding_language=language,
                finding_rule_id=rule_id,
                record=c,
            )
            if s < self.min_score:
                continue
            scored.append(
                KnowledgeMatch(
                    match_id=c["_id"] or f"kg-{cat}",
                    rule_id=c.get("rule_id") or rule_id or "",
                    category=c.get("category") or cat,
                    cwe=c.get("cwe"),
                    language=c.get("language"),
                    severity=c.get("severity"),
                    file_path=c.get("file_path"),
                    line_start=c.get("line_start"),
                    fix_title=c.get("fix_title", ""),
                    fix_diff=c.get("fix_diff", ""),
                    reference_cve=c.get("reference_cve", ""),
                    incident_note=c.get("incident_note", ""),
                    archived_at=c.get("archived_at", ""),
                    similarity=s,
                )
            )
        scored.sort(key=lambda m: m.similarity, reverse=True)
        # 去重：同 cve+rule_id 保留相似度最高
        seen: Dict[str, KnowledgeMatch] = {}
        for m in scored:
            key = f"{m.reference_cve}|{m.rule_id}"
            cur = seen.get(key)
            if cur is None or m.similarity > cur.similarity:
                seen[key] = m
        return list(seen.values())[: self.top_k]

    async def batch_match(
        self,
        findings: List[Any],
        *,
        meta_key: str = "knowledge_graph",
    ) -> Dict[str, List[KnowledgeMatch]]:
        """批量匹配；按 finding.id/fingerprint 返回命中字典。"""
        out: Dict[str, List[KnowledgeMatch]] = {}
        for f in findings:
            fid = _finding_key(f)
            if fid is None:
                continue
            cat = _finding_category(f)
            cwe = _finding_cwe(f)
            sev = _finding_severity(f)
            lang = _finding_language(f)
            rule = _finding_rule_id(f)
            matches = await self.match(
                rule_id=rule,
                category=cat,
                cwe=cwe,
                severity=sev,
                language=lang,
            )
            if matches:
                out[fid] = matches
        return out


# ─────────────────────── finding 字段提取（兼容 dict / Pydantic / dataclass） ───────────────────────

def _safe(obj: Any, key: str, *, alias: Optional[List[str]] = None) -> Any:
    keys = [key] + (alias or [])
    for k in keys:
        if isinstance(obj, dict):
            if k in obj:
                return obj[k]
        else:
            v = getattr(obj, k, None)
            if v is not None:
                return v
    return None


def _finding_key(finding: Any) -> Optional[str]:
    for k in ("id", "fingerprint", "finding_id"):
        v = _safe(finding, k)
        if v:
            return str(v)
    # 组合一个伪键
    rule = _finding_rule_id(finding) or ""
    fp = _safe(finding, "file_path", alias=["file"]) or ""
    line = _safe(finding, "line_start", alias=["line"]) or 0
    return f"{rule}:{fp}:{line}"


def _finding_rule_id(finding: Any) -> Optional[str]:
    return _safe(finding, "rule_id")


def _finding_category(finding: Any) -> Optional[str]:
    return _safe(finding, "category")


def _finding_cwe(finding: Any) -> Optional[str]:
    return _safe(finding, "cwe")


def _finding_severity(finding: Any) -> Optional[str]:
    v = _safe(finding, "severity")
    if v is None:
        return None
    return getattr(v, "value", str(v))


def _finding_language(finding: Any) -> Optional[str]:
    return _safe(finding, "language")


def all_fallback_categories() -> List[str]:
    """返回内置支持的所有分类键 —— 供测试与 CLI 展示"""
    return sorted(_CATEGORY_INDEX.keys())


def fallback(category: str) -> Optional[Dict[str, Any]]:
    """按分类取内置知识（只读）"""
    return _CATEGORY_INDEX.get(category.lower())
