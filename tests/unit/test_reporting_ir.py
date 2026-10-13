"""Tests for the stable reporting intermediate representation."""

from dataclasses import dataclass
import hashlib
import json

import pytest

from fp_sentinel.models import Finding, Severity
from fp_sentinel.reporting.ir import (
    ReportIR,
    canonical_json,
    calculate_content_sha256,
    content_sha256,
    from_dict,
    from_findings,
    to_dict,
    to_json,
)


@dataclass
class DataclassFinding:
    rule_id: str
    severity: str
    file_path: str
    line_start: int


def _finding_dict(rule_id: str = "rule.sql") -> dict:
    return {
        "rule_id": rule_id,
        "severity": "HIGH",
        "file_path": "src/app.py",
        "line_start": 12,
        "message": "Unsafe query construction",
        "metadata": {"source": "unit", "tags": ["sql"]},
    }


def test_from_findings_accepts_mapping_and_finding_model() -> None:
    model = Finding(
        scanner="unit",
        rule_id="rule.xss",
        severity=Severity.MEDIUM,
        file_path="src/page.py",
        line_start=7,
        message="Unsafe output",
    )
    report = from_findings([_finding_dict(), model], limitations=["offline tools"])

    assert report.schema_version == "1.0"
    assert report.status == "completed"
    assert report.finding_count == 2
    assert report.findings[1]["severity"] == "MEDIUM"
    assert report.limitations == ["offline tools"]
    assert len(report.content_sha256) == 64


def test_from_findings_accepts_single_mapping_and_dataclass() -> None:
    report = ReportIR.from_findings(
        _finding_dict(),
        status="incomplete",
        limitations="scanner timeout",
    )
    dataclass_report = ReportIR.from_findings(
        [DataclassFinding("rule.path", "LOW", "src/a.py", 4)]
    )

    assert report.finding_count == 1
    assert report.limitations == ["scanner timeout"]
    assert dataclass_report.findings[0]["rule_id"] == "rule.path"


def test_to_dict_and_from_dict_round_trip() -> None:
    original = from_findings(
        [_finding_dict(), _finding_dict("rule.path")],
        status="failed",
        limitations=["tool unavailable", "partial scan"],
    )

    restored = from_dict(to_dict(original))

    assert restored.to_dict() == original.to_dict()
    assert restored.content_sha256 == original.content_sha256
    assert to_dict(original) is not original.to_dict()


def test_deterministic_json_is_independent_of_mapping_key_order() -> None:
    first = from_findings([{"b": 2, "a": 1}], limitations=["x"])
    second = from_findings([{"a": 1, "b": 2}], limitations=["x"])

    assert first.to_json() == second.to_json()
    assert to_json(first) == to_json(second)
    assert canonical_json({"z": 1, "a": 2}) == '{"a":2,"z":1}'
    assert json.loads(first.to_json())["finding_count"] == 1


def test_hash_is_stable_and_changes_with_report_content() -> None:
    report = from_findings([_finding_dict()])
    expected_payload = {
        "schema_version": report.schema_version,
        "status": report.status,
        "findings": report.findings,
        "limitations": report.limitations,
        "finding_count": report.finding_count,
    }
    expected = hashlib.sha256(
        json.dumps(
            expected_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()

    assert report.content_sha256 == expected
    assert calculate_content_sha256(
        report.schema_version, report.status, report.findings, report.limitations
    ) == report.content_sha256
    assert content_sha256(report) == report.content_sha256
    assert from_findings([_finding_dict("rule.other")]).content_sha256 != report.content_sha256


def test_integrity_metadata_rejects_tampering() -> None:
    report = from_findings([_finding_dict()])
    payload = report.to_dict()
    payload["findings"][0]["rule_id"] = "rule.changed"

    with pytest.raises(ValueError, match="content_sha256"):
        ReportIR.from_dict(payload)


def test_empty_report_has_complete_metadata() -> None:
    report = from_findings([])

    assert report.findings == []
    assert report.limitations == []
    assert report.finding_count == 0
    assert report.status == "completed"
    assert len(report.to_json()) > 0


def test_invalid_inputs_are_rejected() -> None:
    with pytest.raises(TypeError):
        from_findings("not a finding list")
    with pytest.raises(ValueError, match="finding_count"):
        ReportIR.from_dict(
            {
                "schema_version": "1.0",
                "status": "completed",
                "findings": [],
                "limitations": [],
                "finding_count": 1,
            }
        )
