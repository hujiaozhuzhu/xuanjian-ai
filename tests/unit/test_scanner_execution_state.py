"""Scanner execution state regression tests."""

import asyncio
from typing import List, Optional

import pytest

from fp_sentinel.models import ScanResult, ScanTool, Severity
from fp_sentinel.scanners.base import BaseScanner
from fp_sentinel.scanners.manager import ScannerManager


class StubScanner(BaseScanner):
    """Expose deterministic scanner outcomes for manager state tests."""

    def __init__(
        self,
        mode: str = "empty",
        results: Optional[List[ScanResult]] = None,
    ) -> None:
        super().__init__()
        self.mode = mode
        self.results = results or []

    def get_tool_type(self) -> ScanTool:
        """Return a stable test scanner type."""
        return ScanTool.MANUAL

    async def scan(self, target_path: str, **kwargs) -> List[ScanResult]:
        """Return or raise the configured deterministic outcome."""
        self._execution_started()
        if self.mode == "exception":
            raise RuntimeError("stub scanner failed")
        if self.mode == "timeout":
            raise asyncio.TimeoutError()
        if self.mode == "non_zero":
            self._execution_failed("NON_ZERO_EXIT", "stub exited with code 2")
            return []
        if self.mode == "parse":
            self._execution_failed("PARSE_ERROR", "stub output is invalid")
            return []
        self._execution_completed(len(self.results))
        return self.results


def make_finding(rule_id: str = "stub.rule") -> ScanResult:
    """Build one valid result for aggregation tests."""
    return ScanResult(
        tool=ScanTool.MANUAL,
        rule_id=rule_id,
        file="stub.py",
        line=1,
        severity=Severity.MEDIUM,
        message="stub finding",
    )


def manager_with(*scanners: StubScanner) -> ScannerManager:
    """Build a manager with only deterministic test scanners."""
    manager = ScannerManager({"scanners": {}})
    keys = [ScanTool.MANUAL, ScanTool.BANDIT]
    manager.scanners = dict(zip(keys, scanners))
    return manager


@pytest.mark.asyncio
async def test_zero_findings_is_completed() -> None:
    """A successful empty result is not reported as a failure."""
    manager = manager_with(StubScanner("empty"))

    result = await manager.scan(".", language="python", scanners=[ScanTool.MANUAL])

    assert result == []
    assert manager.last_execution["status"] == "completed"
    assert manager.last_execution["error_code"] is None
    assert manager.last_execution["result_count"] == 0
    assert manager.last_execution["scanner_states"]["manual"]["status"] == "completed"


@pytest.mark.asyncio
async def test_no_available_scanner_is_explicit() -> None:
    """An empty scanner selection returns the no-scanners state."""
    manager = manager_with()

    result = await manager.scan(".", language="python", scanners=[])

    assert result == []
    assert manager.last_execution["status"] == "no_scanners"
    assert manager.last_execution["error_code"] == "NO_SCANNER_AVAILABLE"
    assert manager.last_execution["canonical_error_code"] == "NO_AVAILABLE_SCANNERS"
    assert manager.last_execution["failures"][0]["error_code"] == "NO_SCANNER_AVAILABLE"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "error_code", "canonical"),
    [
        ("exception", "SCANNER_EXCEPTION", "SCANNER_EXECUTION_FAILED"),
        ("timeout", "TIMEOUT", "SCANNER_TIMEOUT"),
        ("non_zero", "NON_ZERO_EXIT", "SCANNER_NON_ZERO_EXIT"),
        ("parse", "PARSE_ERROR", "SCANNER_PARSE_FAILED"),
    ],
)
async def test_failure_modes_are_explicit(
    mode: str, error_code: str, canonical: str
) -> None:
    """Exceptions, timeout, process, and parser failures never look completed."""
    manager = manager_with(StubScanner(mode))

    result = await manager.scan(".", language="python", scanners=[ScanTool.MANUAL])

    assert result == []
    assert manager.last_execution["status"] == "failed"
    assert manager.last_execution["error_code"] == error_code
    assert manager.last_execution["canonical_error_code"] == canonical
    assert manager.last_execution["failures"][0]["error_code"] == error_code
    assert manager.last_execution["scanner_states"]["manual"]["status"] == "failed"


@pytest.mark.asyncio
async def test_partial_results_keep_legacy_status() -> None:
    """Successful results plus a failed scanner produce partial with legacy alias."""
    manager = manager_with(
        StubScanner("results", [make_finding()]), StubScanner("parse")
    )

    result = await manager.scan(
        ".", language="python", scanners=[ScanTool.MANUAL, ScanTool.BANDIT]
    )

    assert len(result) == 1
    assert manager.last_execution["status"] == "partial"
    assert manager.last_execution["legacy_status"] == "incomplete"
    assert manager.last_execution["result_count"] == 1
    assert manager.last_execution["error_code"] == "PARSE_ERROR"
    assert manager.last_execution["executed_scanners"] == ["manual", "bandit"]


def test_scanner_state_records_result_count_and_timestamps() -> None:
    """Base scanner state contains completion metadata for zero and nonzero results."""
    scanner = StubScanner("results", [make_finding()])

    import asyncio as _asyncio

    assert _asyncio.run(scanner.scan("."))
    assert scanner.last_execution["status"] == "completed"
    assert scanner.last_execution["result_count"] == 1
    assert scanner.last_execution["started_at"]
    assert scanner.last_execution["completed_at"]
    assert scanner.last_execution["duration_ms"] is not None
