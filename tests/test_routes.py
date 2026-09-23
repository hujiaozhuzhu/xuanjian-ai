"""
tests/test_routes.py — load_routes 行为单测。

覆盖：
  1. 成功加载并解析
  2. 缺省路径不存在返回 {}
  3. 解析命中匹配规则
  4. defaultHint 字段存在性断言
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from fp_sentinel.rules.rule_registry import (
    load_routes,
    _DEFAULT_ROUTES_YAML,
)


# ────────────────────────── 测试 1：成功加载 ──────────────────────────
def test_load_routes_success(tmp_path: Path) -> None:
    yaml_text = textwrap.dedent(
        """\
        routes:
          - match: "target == 'web' && has_js_sources"
            pipeline: [js_pretreat, js_scanner, report]
            gate: rules/web-audit-gate.yaml
        defaultHint: "未匹配的 target 须人工确认"
        """
    )
    f = tmp_path / "routing-table.yaml"
    f.write_text(yaml_text, encoding="utf-8")

    data = load_routes(f)

    assert "routes" in data
    assert len(data["routes"]) == 1
    assert data["routes"][0]["pipeline"] == ["js_pretreat", "js_scanner", "report"]
    assert data["defaultHint"] == "未匹配的 target 须人工确认"


# ────────────────────────── 测试 2：缺省路径不存在返回 {} ──────────────
def test_load_routes_default_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = tmp_path / "nope" / "01-routing-table.yaml"
    monkeypatch.setattr(
        "fp_sentinel.rules.rule_registry._DEFAULT_ROUTES_YAML",
        fake,
    )

    assert load_routes() == {}


# ────────────────────────── 测试 3：解析命中（匹配规则） ───────────────
def test_load_routes_parse_and_hit(tmp_path: Path) -> None:
    yaml_text = textwrap.dedent(
        """\
        routes:
          - match: "target == 'mobile' && has_apk"
            pipeline: [shell_dumper, decompile]
            gate: rules/mobile-audit-gate.yaml
        """
    )
    f = tmp_path / "rt.yaml"
    f.write_text(yaml_text, encoding="utf-8")

    data = load_routes(f)

    hit = next(
        (r for r in data["routes"] if "mobile" in r["match"]),
        None,
    )
    assert hit is not None
    assert "shell_dumper" in hit["pipeline"]


# ────────────────────────── 测试 4：defaultHint 存在性断言 ─────────────
def test_load_routes_default_hint_absent_is_none(tmp_path: Path) -> None:
    yaml_text = textwrap.dedent(
        """\
        routes:
          - match: "target == 'web'"
            pipeline: [report]
        """
    )
    f = tmp_path / "rt.yaml"
    f.write_text(yaml_text, encoding="utf-8")

    data = load_routes(f)

    assert "defaultHint" not in data
    assert data.get("defaultHint") is None
