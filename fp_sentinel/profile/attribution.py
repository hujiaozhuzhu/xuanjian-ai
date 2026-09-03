"""
作者归因采集（只读 git blame）

安全红线（S2/S6）：
- 仅执行只读 git 命令（blame/log/show），命令白名单硬校验，
  禁止任何 git 写操作（commit/push/tag/config 等一律拒绝）；
- 不修改、不删除用户代码，只读分析；
- 作者 email 不落盘：仅以 SHA256 别名摘要存储；
- 非 git 目录 / 行号无法归因 → 降级为 alias_hash="unknown"，并输出归因覆盖率；
- 每个项目最多缓存 max_records 条归因记录（默认 5000，可配置），避免大仓库性能问题。
"""

import logging
import os
import re
import subprocess
from bisect import bisect_left
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models import Finding
from .models import (
    UNKNOWN_ALIAS,
    AttributionRecord,
    encrypt_name,
    get_profile_key,
)

logger = logging.getLogger(__name__)

# 只读 git 子命令白名单（S2/S6 红线硬校验）
GIT_READONLY_SUBCOMMANDS = {"log", "blame", "show"}
GIT_TIMEOUT_SECONDS = 60
_SHA_RE = re.compile(r"^[0-9a-f]{40}")


class GitCommandViolation(RuntimeError):
    """尝试执行白名单之外的 git 命令（红线拦截）"""


def _run_git(args: List[str], cwd: str) -> subprocess.CompletedProcess:
    """执行只读 git 命令（白名单硬校验 + --no-pager + 超时）"""
    operands = [a for a in args if a != "--no-pager"]
    if not operands or operands[0] not in GIT_READONLY_SUBCOMMANDS:
        raise GitCommandViolation(f"非只读 git 命令被拒绝: {args[:2]}")
    cmd = ["git", "--no-pager"] + list(args)
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        timeout=GIT_TIMEOUT_SECONDS,
        check=False,
    )


def is_git_repo(path: str) -> bool:
    """判断目录是否位于 git 仓库内（git log 只读探测）"""
    try:
        proc = _run_git(["log", "-1", "--format=%H"], cwd=str(path))
        return proc.returncode == 0
    except (GitCommandViolation, subprocess.TimeoutExpired, OSError):
        return False


class LineBlame:
    """单行 blame 结果（内存态，email 不落盘）"""

    __slots__ = ("line", "email", "name", "commit_time")

    def __init__(self, line: int, email: str, name: str, commit_time: Optional[datetime]):
        self.line = line
        self.email = email
        self.name = name
        self.commit_time = commit_time


def blame_file(repo_path: str, rel_file: str) -> Dict[int, LineBlame]:
    """
    对仓库内单个文件执行 `git blame --porcelain`，返回 {行号: 归因}。

    只读操作；文件不存在或不在 git 追踪中时返回空 dict。
    """
    repo_path = str(repo_path)
    try:
        proc = _run_git(["blame", "--porcelain", "--", rel_file], cwd=repo_path)
    except (GitCommandViolation, subprocess.TimeoutExpired, OSError) as e:
        logger.debug("git blame 失败 %s: %s", rel_file, e)
        return {}
    if proc.returncode != 0:
        logger.debug("git blame 非零退出 %s: %s", rel_file, proc.stderr[:200])
        return {}

    blame: Dict[int, LineBlame] = {}
    lines = proc.stdout.decode("utf-8", errors="replace").splitlines()
    i = 0
    meta_by_sha: Dict[str, Dict[str, Any]] = {}
    while i < len(lines):
        line = lines[i]
        if _SHA_RE.match(line):
            # 新条目头：<sha> <orig-line> <final-line> [<num-lines>]
            # 注意：同一 commit 再次出现时 porcelain 只输出该头，不含 author 元数据
            parts = line.split()
            cur_sha = parts[0]
            cur_final_line = int(parts[2])
            cur_num = int(parts[3]) if len(parts) > 3 else 1
            cur_meta: Dict[str, Any] = {}
            i += 1
            # 读取元数据头直到内容行
            while i < len(lines) and not lines[i].startswith("\t"):
                header = lines[i]
                if header.startswith("author-mail "):
                    m = re.search(r"<([^>]+)>", header)
                    cur_meta["email"] = m.group(1) if m else ""
                elif header.startswith("author-time "):
                    try:
                        cur_meta["time"] = datetime.fromtimestamp(
                            int(header.split()[1]), tz=timezone.utc
                        )
                    except (ValueError, OSError):
                        cur_meta["time"] = None
                elif header.startswith("author "):
                    cur_meta["name"] = header[len("author "):]
                # The filename header is still part of the porcelain metadata;
                # continue to the tab-prefixed content line before parsing it.
                i += 1
            if cur_sha in meta_by_sha:
                merged = dict(meta_by_sha[cur_sha])
                merged.update(cur_meta)
                cur_meta = merged
            if cur_meta.get("email"):
                meta_by_sha[cur_sha] = cur_meta
            # 内容行（\t 前缀），逐行推进 final_line
            count = 0
            while i < len(lines) and lines[i].startswith("\t") and count < cur_num:
                blame[cur_final_line] = LineBlame(
                    line=cur_final_line,
                    email=cur_meta.get("email", ""),
                    name=cur_meta.get("name", ""),
                    commit_time=cur_meta.get("time"),
                )
                cur_final_line += 1
                count += 1
                i += 1
        else:
            i += 1
    return blame


def _nearest_blame_line(sorted_lines: List[int], target: int) -> Optional[int]:
    """在 blame 行号中寻找距离 target 最近的行（含 target 本身）"""
    if not sorted_lines:
        return None
    idx = bisect_left(sorted_lines, target)
    candidates = []
    if idx < len(sorted_lines):
        candidates.append(sorted_lines[idx])
    if idx > 0:
        candidates.append(sorted_lines[idx - 1])
    return min(candidates, key=lambda ln: abs(ln - target))


class AttributionResult:
    """归因结果汇总（内存态；持久化只含别名摘要）"""

    def __init__(self) -> None:
        self.records: List[AttributionRecord] = []
        # alias_hash -> 显示名（内存态；落盘时加密）
        self.display_names: Dict[str, str] = {}
        self.total = 0
        self.attributed = 0  # 成功归因到真实作者的条数
        self.truncated = False
        self.is_git = False

    @property
    def coverage(self) -> float:
        return (self.attributed / self.total) if self.total else 0.0

    def summary(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "attributed": self.attributed,
            "unknown": self.total - self.attributed,
            "coverage": round(self.coverage, 4),
            "truncated": self.truncated,
            "is_git_repo": self.is_git,
        }


def attribute_findings(
    project_path: str,
    findings: List[Finding],
    max_records: int = 5000,
) -> AttributionResult:
    """
    对一批 findings 执行只读 git 归因。

    - finding 行号 → blame 结果最近行 → 作者 email → SHA256 别名化；
    - 非 git 目录 / 无法归因 → alias_hash="unknown"；
    - 归因记录上限 max_records（避免大仓库性能问题）。
    """
    result = AttributionResult()
    result.total = len(findings)
    result.is_git = is_git_repo(project_path)
    repo = Path(project_path).resolve()

    blame_cache: Dict[str, Dict[int, LineBlame]] = {}
    blame_lines_cache: Dict[str, List[int]] = {}
    alias_of_email: Dict[str, str] = {}
    produced = 0

    for f in findings:
        if produced >= max_records:
            result.truncated = True
            # 超出上限的 findings 不再归因，也不写入记录
            continue
        alias = UNKNOWN_ALIAS
        hit_line = None
        committed_at = None
        rel_file: Optional[str] = None

        if result.is_git and f.file_path:
            rel_file = f.file_path.replace("\\", "/").lstrip("./")
            if rel_file not in blame_cache:
                blame_cache[rel_file] = blame_file(str(repo), rel_file)
                blame_lines_cache[rel_file] = sorted(blame_cache[rel_file].keys())
            blame = blame_cache[rel_file]
            if blame:
                nearest = _nearest_blame_line(blame_lines_cache[rel_file], f.line_start)
                if nearest is not None:
                    lb = blame[nearest]
                    if lb.email:
                        alias = alias_of_email.get(lb.email)
                        if alias is None:
                            alias = alias_of_email[lb.email] = _hash_email(lb.email)
                            result.display_names[alias] = lb.name or ""
                        hit_line = nearest
                        committed_at = (
                            lb.commit_time.isoformat() if lb.commit_time else None
                        )
        if alias != UNKNOWN_ALIAS:
            result.attributed += 1
        produced += 1
        result.records.append(
            AttributionRecord(
                finding_fingerprint=f.fingerprint or f"{f.rule_id}:{f.file_path}:{f.line_start}",
                alias_hash=alias,
                file=rel_file or f.file_path,
                line=hit_line,
                committed_at=committed_at,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
        )
    return result


def _hash_email(email: str) -> str:
    """SHA256 别名化（S6：email 明文不落盘）"""
    from .models import alias_hash

    return alias_hash(email)


async def attribute_and_store(
    db,
    project_path: str,
    findings: List[Finding],
    max_records: int = 5000,
) -> AttributionResult:
    """归因并入库（developer_alias + scan_attribution），返回结果汇总"""
    from .models import ProfileRepo

    result = attribute_findings(project_path, findings, max_records=max_records)
    repo = ProfileRepo(db)
    if result.is_git and os.path.isdir(str(project_path)):
        key = get_profile_key(db.db_path)
        for alias, name in result.display_names.items():
            await repo.upsert_alias(
                alias, display_name_encrypted=encrypt_name(name, key) if name else None
            )
    # 去重：同一 fingerprint 只保留最新一条归因
    await repo.save_attributions(result.records)
    return result
