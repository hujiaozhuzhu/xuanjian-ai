"""Stable intermediate representation for scan reports.

Accepts Finding models or mappings and emits deterministic JSON-compatible data
for report renderers without depending on CLI, MCP, or persistence layers.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import date, datetime, time
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Union

SCHEMA_VERSION = "1.0"
REPORT_IR_SCHEMA_VERSION = SCHEMA_VERSION
FindingInput = Union[Mapping[str, Any], Any]
_JSON_KWARGS = {"ensure_ascii": False, "sort_keys": True, "separators": (",", ":"), "allow_nan": False}


def _model_mapping(value: Any) -> Optional[Mapping[str, Any]]:
    """Extract a mapping from Pydantic or dataclass model values."""
    for name in ("model_dump", "dict"):
        method = getattr(value, name, None)
        if not callable(method):
            continue
        try:
            result = method(mode="json") if name == "model_dump" else method()
        except TypeError:
            result = method()
        if isinstance(result, Mapping):
            return result
    if is_dataclass(value) and not isinstance(value, type):
        result = asdict(value)
        if isinstance(result, Mapping):
            return result
    return None


def _json_value(value: Any) -> Any:
    """Normalize nested values into deterministic JSON-compatible values."""
    if isinstance(value, Enum):
        return _json_value(value.value)
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    model = _model_mapping(value)
    if model is not None:
        return _json_value(model)
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        items = [_json_value(item) for item in value]
        return sorted(items, key=_canonical_json)
    raise TypeError(f"Unsupported report value: {type(value).__name__}")


def _canonical_json(value: Any) -> str:
    """Serialize a value with stable keys, separators, and Unicode handling."""
    return json.dumps(_json_value(value), **_JSON_KWARGS)


def canonical_json(value: Any) -> str:
    """Return deterministic JSON for a report or JSON-compatible value."""
    return _canonical_json(value.to_dict() if isinstance(value, ReportIR) else value)


def _normalize_finding(finding: FindingInput) -> dict[str, Any]:
    """Copy one Finding model or mapping into a JSON-compatible dictionary."""
    source = finding if isinstance(finding, Mapping) else _model_mapping(finding)
    if source is None:
        raise TypeError("finding must be a Finding model, dataclass, or mapping")
    result = _json_value(source)
    if not isinstance(result, dict):
        raise TypeError("finding must normalize to an object")
    return result


def _normalize_findings(findings: Any) -> list[dict[str, Any]]:
    """Normalize Finding input without mutating caller-owned values."""
    if findings is None:
        return []
    if isinstance(findings, Mapping) or _model_mapping(findings) is not None:
        return [_normalize_finding(findings)]
    if isinstance(findings, (str, bytes)):
        raise TypeError("findings must be an iterable of Finding models or mappings")
    try:
        return [_normalize_finding(item) for item in findings]
    except TypeError as exc:
        raise TypeError("findings must be an iterable of Finding models or mappings") from exc


def _normalize_limitations(limitations: Any) -> list[str]:
    """Normalize report limitations into copied strings."""
    if limitations is None:
        return []
    if isinstance(limitations, str):
        return [limitations]
    if isinstance(limitations, bytes):
        return [limitations.decode("utf-8")]
    try:
        return [str(item) for item in limitations]
    except TypeError as exc:
        raise TypeError("limitations must be an iterable of strings") from exc


def _payload(schema: str, status: str, findings: list[dict[str, Any]], limits: list[str]) -> dict[str, Any]:
    """Build content payload without the self-referential digest."""
    return {"schema_version": schema, "status": status, "findings": findings, "limitations": limits, "finding_count": len(findings)}


def _digest(schema: str, status: str, findings: list[dict[str, Any]], limits: list[str]) -> str:
    """Hash a content payload using canonical UTF-8 JSON."""
    content = _canonical_json(_payload(schema, status, findings, limits))
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def calculate_content_sha256(schema_version: str = SCHEMA_VERSION, status: str = "completed", findings: Iterable[FindingInput] = (), limitations: Iterable[str] = ()) -> str:
    """Calculate a deterministic SHA-256 digest for report content."""
    normalized = _normalize_findings(findings)
    limits = _normalize_limitations(limitations)
    return _digest(str(schema_version), str(getattr(status, "value", status)), normalized, limits)


def content_sha256(value: Any = None, *, status: str = "completed", schema_version: str = SCHEMA_VERSION, limitations: Any = None) -> str:
    """Hash a ReportIR, serialized report dictionary, or Finding iterable."""
    if isinstance(value, ReportIR):
        return value.content_sha256 or ""
    if isinstance(value, Mapping) and {"findings", "limitations"}.issubset(value):
        schema_version = value.get("schema_version", schema_version)
        status = value.get("status", status)
        limitations = value.get("limitations", limitations)
        value = value.get("findings", [])
    return calculate_content_sha256(schema_version, status, value or (), limitations or ())


@dataclass(frozen=True)
class ReportIR(Mapping[str, Any]):
    """Stable report metadata and normalized findings."""
    schema_version: str = SCHEMA_VERSION
    status: str = "completed"
    findings: Any = field(default_factory=list)
    limitations: Any = field(default_factory=list)
    finding_count: Optional[int] = None
    content_sha256: Optional[str] = None

    def __post_init__(self) -> None:
        """Normalize fields and verify supplied count and digest."""
        normalized = _normalize_findings(self.findings)
        limits = _normalize_limitations(self.limitations)
        schema, status = str(self.schema_version), str(getattr(self.status, "value", self.status))
        count = len(normalized)
        if self.finding_count is not None and int(self.finding_count) != count:
            raise ValueError("finding_count must equal len(findings)")
        digest = _digest(schema, status, normalized, limits)
        if self.content_sha256 is not None and self.content_sha256 != digest:
            raise ValueError("content_sha256 does not match report content")
        for name, value in (("schema_version", schema), ("status", status), ("findings", normalized), ("limitations", limits), ("finding_count", count), ("content_sha256", digest)):
            object.__setattr__(self, name, value)

    @classmethod
    def from_findings(cls, findings: Any = None, *, status: str = "completed", limitations: Any = None, schema_version: str = SCHEMA_VERSION) -> "ReportIR":
        """Build a ReportIR from Finding models or dictionaries."""
        return cls(schema_version, status, findings, limitations)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ReportIR":
        """Rehydrate a report dictionary and verify its integrity metadata."""
        if not isinstance(value, Mapping):
            raise TypeError("report must be a mapping")
        required = ("schema_version", "status", "findings", "limitations")
        missing = [key for key in required if key not in value]
        if missing:
            raise ValueError(f"report is missing required fields: {', '.join(missing)}")
        return cls(value["schema_version"], value["status"], value["findings"], value["limitations"], value.get("finding_count"), value.get("content_sha256"))

    def to_dict(self) -> dict[str, Any]:
        """Return an independent JSON-compatible report dictionary."""
        return {"schema_version": self.schema_version, "status": self.status, "findings": _json_value(self.findings), "limitations": list(self.limitations), "finding_count": self.finding_count, "content_sha256": self.content_sha256}

    def to_json(self) -> str:
        """Return deterministic JSON for this report."""
        return _canonical_json(self.to_dict())

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __iter__(self):
        return iter(self.to_dict())

    def __len__(self) -> int:
        return 6


def from_findings(findings: Any = None, *, status: str = "completed", limitations: Any = None, schema_version: str = SCHEMA_VERSION) -> ReportIR:
    """Build a stable ReportIR from Finding models or dictionaries."""
    return ReportIR.from_findings(findings, status=status, limitations=limitations, schema_version=schema_version)


def from_dict(value: Mapping[str, Any]) -> ReportIR:
    """Build a stable ReportIR from a serialized dictionary."""
    return ReportIR.from_dict(value)


def to_dict(value: ReportIR) -> dict[str, Any]:
    """Convert a ReportIR into an independent dictionary."""
    if not isinstance(value, ReportIR):
        raise TypeError("value must be a ReportIR")
    return value.to_dict()


def to_json(value: ReportIR) -> str:
    """Convert a ReportIR into deterministic JSON."""
    if not isinstance(value, ReportIR):
        raise TypeError("value must be a ReportIR")
    return value.to_json()


__all__ = ["SCHEMA_VERSION", "REPORT_IR_SCHEMA_VERSION", "ReportIR", "canonical_json", "calculate_content_sha256", "content_sha256", "from_dict", "from_findings", "to_dict", "to_json"]
