"""
验证 RuleRegistry 闸门校验函数的行为。
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fp_sentinel.rules.rule_registry import RuleRegistry, get_registry


@pytest.fixture(autouse=True)
def _reset_singleton():
    """每个测试前重置 get_registry 单例。"""
    import fp_sentinel.rules.rule_registry as _mod

    _mod._instance = None
    yield
    _mod._instance = None


def test_check_scope_ok():
    """白名单命中目标 IP 时返回 True。"""
    reg = RuleRegistry()
    assert reg.check_scope("10.0.0.1", ["10.0.0.1", "192.168.1.1"]) is True


def test_check_scope_fail():
    """目标 IP 不在白名单内返回 False。"""
    reg = RuleRegistry()
    assert reg.check_scope("10.0.0.5", ["10.0.0.1", "192.168.1.1"]) is False


def test_require_write_pass():
    """未请求写操作时直接放行。"""
    reg = RuleRegistry()
    assert reg.require_write_opt_in(False, False, False) is True


def test_require_write_pass_with_opt_in():
    """已请求写且双标志齐全时放行。"""
    reg = RuleRegistry()
    assert reg.require_write_opt_in(True, True, True) is True


def test_require_write_fail():
    """已请求写但缺少任一标志时返回 False。"""
    reg = RuleRegistry()
    assert reg.require_write_opt_in(True, True, False) is False
    assert reg.require_write_opt_in(True, False, True) is False
    assert reg.require_write_opt_in(True, False, False) is False


def test_fail_closed_exits(tmp_path):
    """fail_closed 触发 sys.exit(1) 并写入 audit 日志文件。"""
    reg = RuleRegistry()
    fake_audit = tmp_path / "audit_failure.log"
    with patch(
        "fp_sentinel.rules.rule_registry._AUDIT_LOG", fake_audit
    ), pytest.raises(SystemExit) as exc_info:
        reg.fail_closed(RuntimeError("boom"))
    assert exc_info.value.code == 1
    assert fake_audit.exists()
    assert "boom" in fake_audit.read_text(encoding="utf-8")


def test_registry_singleton():
    """get_registry 始终返回同一实例。"""
    a = get_registry()
    b = get_registry()
    assert a is b
