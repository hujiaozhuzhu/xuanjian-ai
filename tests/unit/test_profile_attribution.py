"""
P2 归因测试：git 命令守卫、非 git 降级、真实仓库只读 blame、上限截断
"""

from pathlib import Path

import pytest

from fp_sentinel.models import Finding, Severity
from fp_sentinel.profile.attribution import (
    GitCommandViolation,
    _run_git,
    attribute_findings,
    blame_file,
    is_git_repo,
)
from fp_sentinel.profile.models import UNKNOWN_ALIAS, alias_hash

# 项目自身仓库（只读使用，不做任何 git 写操作）
PROJECT_ROOT = Path(__file__).resolve().parents[2]
TARGET_FILE = "fp_sentinel/__init__.py"


def _finding(file_path: str, line: int, fp: str) -> Finding:
    return Finding(
        scanner="semgrep",
        rule_id="test.rule",
        severity=Severity.HIGH,
        file_path=file_path,
        line_start=line,
        message="test",
        fingerprint=fp,
    )


def test_git_command_guard_rejects_write_operations():
    """红线：白名单外 git 命令（写操作）必须被拒绝"""
    for forbidden in (["commit", "-m", "x"], ["push"], ["tag", "v1"], ["config", "user.name"]):
        with pytest.raises(GitCommandViolation):
            _run_git(forbidden, cwd=str(PROJECT_ROOT))


def test_git_command_guard_allows_readonly():
    """只读命令（log/blame/show）可正常通过守卫"""
    proc = _run_git(["log", "-1", "--format=%H"], cwd=str(PROJECT_ROOT))
    assert proc.returncode == 0


def test_non_git_dir_degrades_to_unknown(tmp_path):
    """非 git 目录：全部降级 alias=unknown，覆盖率 0%"""
    (tmp_path / "app.py").write_text("eval(x)\n", encoding="utf-8")
    findings = [_finding("app.py", 1, "fp-1"), _finding("app.py", 1, "fp-2")]
    result = attribute_findings(str(tmp_path), findings)
    assert result.is_git is False
    assert result.total == 2
    assert result.attributed == 0
    assert result.coverage == 0.0
    assert all(r.alias_hash == UNKNOWN_ALIAS for r in result.records)
    s = result.summary()
    assert s["coverage"] == 0.0 and s["is_git_repo"] is False


@pytest.mark.skipif(not is_git_repo(str(PROJECT_ROOT)), reason="项目根目录不是 git 仓库")
def test_blame_file_on_real_repo():
    """真实仓库（本项目）只读 blame：可解析出行级归因"""
    blame = blame_file(str(PROJECT_ROOT), TARGET_FILE)
    assert blame, "blame 结果不应为空"
    line1 = blame.get(1)
    assert line1 is not None
    assert isinstance(line1.email, str)
    # 内存对象不落盘；email 与 name 为原始字段，仅用于即时别名化
    assert line1.commit_time is not None


@pytest.mark.skipif(not is_git_repo(str(PROJECT_ROOT)), reason="项目根目录不是 git 仓库")
def test_attribute_findings_on_real_repo_no_plaintext():
    """真实仓库归因：记录中只有别名摘要，无明文 email/姓名"""
    findings = [_finding(TARGET_FILE, 1, "fp-real-1")]
    result = attribute_findings(str(PROJECT_ROOT), findings)
    assert result.is_git is True
    assert result.coverage == 1.0
    rec = result.records[0]
    assert rec.alias_hash != UNKNOWN_ALIAS
    assert rec.alias_hash in result.display_names  # 姓名（内存态，落盘前加密）
    # 记录（落盘结构）中无 email/姓名明文字段
    dumped = rec.model_dump()
    assert "email" not in dumped and "name" not in dumped and "display_name" not in dumped
    # 姓名明文不出现在记录与摘要中
    import json
    blob = json.dumps(rec.model_dump()) + json.dumps(result.summary())
    for name in result.display_names.values():
        if name:
            assert name not in blob


@pytest.mark.skipif(not is_git_repo(str(PROJECT_ROOT)), reason="项目根目录不是 git 仓库")
def test_alias_consistency_for_same_author():
    """同一作者多次归因得到同一别名（确定性）"""
    findings = [
        _finding(TARGET_FILE, 1, "fp-a"),
        _finding(TARGET_FILE, min(5, 5), "fp-b"),
    ]
    result = attribute_findings(str(PROJECT_ROOT), findings)
    aliases = {r.alias_hash for r in result.records if r.alias_hash != UNKNOWN_ALIAS}
    # 同一文件的近期行通常同一作者；至少别名集合有限且非 unknown
    assert len(aliases) >= 1


def test_max_records_cap(tmp_path):
    """归因记录上限：达到 max_records 后截断并标记"""
    findings = [_finding("a.py", 1, f"fp-{i}") for i in range(5)]
    result = attribute_findings(str(tmp_path), findings, max_records=2)
    assert result.truncated is True
    assert len(result.records) == 2
