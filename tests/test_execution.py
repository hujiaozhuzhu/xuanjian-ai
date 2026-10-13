"""Execution gate tests.

These tests keep the gate deterministic by disabling optional module-contract
imports; the fixture focuses on local rules/routing and manifest integrity.
"""

from __future__ import annotations

import json

import pytest

from fp_sentinel.execution import (
    STATUS_FAIL_CLOSED,
    STATUS_PASSED,
    PreflightError,
    generate_manifest,
    preflight,
    require_preflight,
    verify_manifest,
)


ROUTING_TEXT = """routing:
  - name: local
    pipeline: scan
"""


def _skill_root(tmp_path, routing_text: str = ROUTING_TEXT):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "01-routing-table.yaml").write_text(routing_text, encoding="utf-8")
    (rules / "02-scope-boundary.md").write_text("scope: local\n", encoding="utf-8")
    return tmp_path


def test_preflight_passes_with_local_rules_and_routing(tmp_path):
    manifest = preflight(_skill_root(tmp_path), modules=(), route="scan")

    assert manifest["status"] == STATUS_PASSED
    assert manifest["route"] == "scan"
    assert manifest["limitations"] == []
    assert manifest["run_id"]
    assert manifest["rules_hash"]
    assert manifest["timestamps"]["started_at"]
    assert manifest["timestamps"]["finished_at"]
    assert verify_manifest(manifest)


def test_preflight_fails_closed_when_rules_are_missing(tmp_path):
    manifest = preflight(tmp_path, modules=())

    assert manifest["status"] == STATUS_FAIL_CLOSED
    assert any("rules directory missing" in item for item in manifest["limitations"])
    assert verify_manifest(manifest)


def test_preflight_fails_closed_when_routing_is_malformed(tmp_path):
    root = _skill_root(tmp_path, routing_text="routing: [unclosed\n")

    manifest = preflight(root, modules=())

    assert manifest["status"] == STATUS_FAIL_CLOSED
    assert any("routing table parse failed" in item for item in manifest["limitations"])


def test_manifest_hash_detects_tampering():
    manifest = generate_manifest(
        run_id="run-test",
        route={"target": "local"},
        rules_hash="rules-test",
        module_versions={"scanner": "1.0.0"},
        status=STATUS_PASSED,
        limitations=["offline"],
    )

    assert verify_manifest(manifest)
    manifest["status"] = STATUS_FAIL_CLOSED
    assert not verify_manifest(manifest)


def test_require_preflight_returns_pass_and_raises_on_failure(tmp_path):
    root = _skill_root(tmp_path)
    manifest = require_preflight(root, modules=())
    assert manifest["status"] == STATUS_PASSED

    with pytest.raises(PreflightError) as exc_info:
        require_preflight(tmp_path / "missing", modules=())
    assert exc_info.value.manifest["status"] == STATUS_FAIL_CLOSED
    assert verify_manifest(exc_info.value.manifest)


def test_preflight_fails_closed_when_self_check_returns_false(monkeypatch, tmp_path):
    import importlib
    import types
    preflight_module = importlib.import_module("fp_sentinel.execution.preflight")

    fake = types.SimpleNamespace(
        available=lambda: True,
        self_check=lambda: (False, "self-check sentinel"),
        module_version=lambda: "test-1.0",
    )
    monkeypatch.setattr(preflight_module.importlib, "import_module", lambda name: fake)

    manifest = preflight(_skill_root(tmp_path), modules=("fake.module",))

    assert manifest["status"] == STATUS_FAIL_CLOSED
    assert any("self_check() returned" in item for item in manifest["limitations"])
    assert any("self-check sentinel" in item for item in manifest["limitations"])


def test_cli_scan_stops_before_scanner_manager_on_gate_failure(monkeypatch, tmp_path):
    """The CLI must not construct ScannerManager after a failed preflight."""
    from typer.testing import CliRunner
    from fp_sentinel.cli import app

    failed_manifest = generate_manifest(
        route="scan",
        status=STATUS_FAIL_CLOSED,
        limitations=["test gate failure"],
    )
    manager_started = False

    def fake_preflight(*args, **kwargs):
        return failed_manifest

    def forbidden_manager(*args, **kwargs):
        nonlocal manager_started
        manager_started = True
        raise AssertionError("ScannerManager must not start after preflight failure")

    monkeypatch.setattr("fp_sentinel.cli.preflight", fake_preflight)
    monkeypatch.setattr("fp_sentinel.cli.ScannerManager", forbidden_manager)

    result = CliRunner().invoke(app, ["scan", str(tmp_path), "--no-save"])

    assert result.exit_code == 1
    assert "fail_closed" in result.output
    assert "test gate failure" in result.output
    assert manager_started is False


def test_cli_scan_writes_failed_manifest_sidecar(monkeypatch, tmp_path):
    from typer.testing import CliRunner
    from fp_sentinel.cli import app

    failed_manifest = generate_manifest(
        route="scan",
        status=STATUS_FAIL_CLOSED,
        limitations=["test gate failure"],
    )
    manager_started = False

    monkeypatch.setattr("fp_sentinel.cli.preflight", lambda *a, **k: failed_manifest)
    monkeypatch.setattr(
        "fp_sentinel.cli.ScannerManager",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("manager started")),
    )
    manifest_path = tmp_path / "failed-manifest.json"
    result = CliRunner().invoke(
        app,
        ["scan", str(tmp_path), "--no-save", "--manifest-file", str(manifest_path)],
    )

    assert result.exit_code == 1
    assert manifest_path.exists()
    written = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert written["status"] == STATUS_FAIL_CLOSED
    assert written["limitations"] == ["test gate failure"]
    assert verify_manifest(written)


def test_cli_scan_can_write_manifest_sidecar(monkeypatch, tmp_path):
    """A successful gate exposes the manifest through the explicit sidecar."""
    from typer.testing import CliRunner
    from fp_sentinel.cli import app

    # Avoid a real scan: after proving the gate, stop at manager construction.
    passing_manifest = generate_manifest(route="scan", status=STATUS_PASSED)
    monkeypatch.setattr("fp_sentinel.cli.preflight", lambda *a, **k: passing_manifest)

    class StopAfterInit:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("stop after gate")

    monkeypatch.setattr("fp_sentinel.cli.ScannerManager", StopAfterInit)
    manifest_path = tmp_path / "manifest.json"

    result = CliRunner().invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--no-save",
            "--manifest-file",
            str(manifest_path),
        ],
    )

    assert result.exit_code != 0
    assert manifest_path.exists()
    assert json.loads(manifest_path.read_text(encoding="utf-8"))["manifest_sha256"]
