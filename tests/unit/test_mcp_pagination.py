"""Independent MCP pagination, integrity, and execution-state tests."""

import asyncio
import json
from typing import Any, Dict

import pytest

from fp_sentinel.mcp_server import (
    MCPAuditServer,
    _content_sha256,
    _text_sha256,
    create_mcp_server,
)
from fp_sentinel.models import FilterResult, ScanResult, ScanTool, Severity, Verdict


def _finding(server: MCPAuditServer, finding_id: str, line: int) -> None:
    scan = ScanResult(
        id=finding_id,
        tool=ScanTool.JS_SCANNER,
        rule_id=f"rule.{line}",
        file="app.js",
        line=line,
        code="eval(input)",
        severity=Severity.HIGH,
        message="Code injection",
    )
    server._findings[finding_id] = FilterResult(
        id=finding_id,
        original=scan,
        verdict=Verdict.TRUE_POSITIVE,
        confidence=0.9,
        filter_reasons=[],
        risk_score=8.0,
        recommendation="Replace eval with a safe parser",
    )


def _scan(server: MCPAuditServer, status: str = "completed") -> Dict[str, Any]:
    return {
        "id": "scan-1",
        "project_path": "/tmp/project",
        "language": "javascript",
        "status": status,
        "error_code": None if status == "completed" else "SCANNER_FAILED",
        "findings": ["f-1", "f-2"],
        "completed_at": "2026-10-13T00:00:00+00:00" if status == "completed" else None,
    }


async def _tool_result_async(
    server: MCPAuditServer, name: str, args: Dict[str, Any]
) -> Dict[str, Any]:
    """Invoke the registered FastMCP function without depending on transport."""
    tool = server.mcp._tool_manager.get_tool(name)
    result = await tool.run(args)
    return json.loads(result)


def _tool_result(server: MCPAuditServer, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Synchronous adapter for tests that are not already async."""
    return asyncio.run(_tool_result_async(server, name, args))


def _seed_server(status: str = "completed") -> MCPAuditServer:
    server = create_mcp_server()
    _finding(server, "f-1", 10)
    _finding(server, "f-2", 20)
    server._scans["scan-1"] = _scan(server, status)
    return server


class TestMCPPagination:
    def test_list_findings_two_pages_limit_one_and_stable_hash(self):
        server = _seed_server()

        first = _tool_result(server, "list_findings", {"scan_id": "scan-1", "limit": 1})
        assert first["status"] == "completed"
        assert first["total"] == 2
        assert first["part_index"] == 1
        assert first["part_total"] == 2
        assert first["next_cursor"] == "1"
        assert [item["id"] for item in first["findings"]] == ["f-1"]
        assert len(first["content_sha256"]) == 64

        second = _tool_result(
            server,
            "list_findings",
            {"scan_id": "scan-1", "limit": 1, "cursor": first["next_cursor"]},
        )
        assert second["status"] == "completed"
        assert second["total"] == 2
        assert second["part_index"] == 2
        assert second["part_total"] == 2
        assert second["next_cursor"] is None
        assert [item["id"] for item in second["findings"]] == ["f-2"]

        repeated = _tool_result(server, "list_findings", {"scan_id": "scan-1", "limit": 1})
        assert repeated["content_sha256"] == first["content_sha256"]

    @pytest.mark.parametrize(
        ("args", "error_code"),
        [
            ({"scan_id": "scan-1", "limit": 0}, "INVALID_LIMIT"),
            ({"scan_id": "scan-1", "limit": 1001}, "INVALID_LIMIT"),
            ({"scan_id": "scan-1", "cursor": "not-a-cursor"}, "INVALID_CURSOR"),
            ({"scan_id": "scan-1", "cursor": "999"}, "INVALID_CURSOR"),
        ],
    )
    def test_invalid_pagination_returns_stable_error_envelope(
        self, args: Dict[str, Any], error_code: str
    ):
        result = _tool_result(_seed_server(), "list_findings", args)
        assert result["status"] == "failed"
        assert result["error_code"] == error_code
        assert result["total"] == 0
        assert result["next_cursor"] is None
        assert result["part_index"] == 1
        assert result["part_total"] == 1
        assert len(result["content_sha256"]) == 64

    @pytest.mark.parametrize("report_format", ["json", "markdown"])
    def test_export_report_content_hash_matches_format(self, report_format: str):
        server = _seed_server()
        result = _tool_result(
            server,
            "export_report",
            {"scan_id": "scan-1", "format": report_format, "limit": 1},
        )
        assert result["status"] == "completed"
        assert result["total"] == 2
        assert result["part_index"] == 1
        assert result["part_total"] == 2
        assert result["next_cursor"] == "1"
        assert len(result["content_sha256"]) == 64
        if report_format == "json":
            expected = _content_sha256(result["content"])
        else:
            expected = _text_sha256(result["content"])
        assert result["content_sha256"] == expected

    @pytest.mark.parametrize("status", ["failed", "incomplete", "partial"])
    def test_failed_or_incomplete_scan_is_not_reported_completed(self, status: str):
        server = _seed_server(status)
        result = _tool_result(server, "list_findings", {"scan_id": "scan-1", "limit": 1})
        assert result["status"] == status
        assert result["status"] != "completed"
        assert result["error_code"] == "SCANNER_FAILED"

    def test_missing_scan_has_error_code(self):
        result = _tool_result(
            create_mcp_server(), "list_findings", {"scan_id": "does-not-exist"}
        )
        assert result["status"] == "failed"
        assert result["error_code"] == "SCAN_NOT_FOUND"
