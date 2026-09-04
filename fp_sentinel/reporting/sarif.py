"""
SARIF 2.1.0 输出器

将 fp_sentinel 扫描结果（Finding / ScanResult）转换为 SARIF 2.1.0 结构。

规范: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "fp-sentinel"

# Severity -> SARIF level
SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

# Severity -> 名义 CVSS 评分（用于 properties.cvss）
SEVERITY_TO_CVSS = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 3.0,
    "INFO": 0.0,
}


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """兼容 Finding(pydantic) 与 ScanResult 的字段读取"""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _severity_str(severity: Any) -> str:
    if severity is None:
        return "MEDIUM"
    return getattr(severity, "value", None) or str(severity)


def _rule_index_map(results: List[Any]) -> Dict[str, int]:
    """构建 ruleId -> ruleIndex 映射（按首次出现顺序）"""
    ordered: List[str] = []
    for r in results:
        rid = _get(r, "rule_id", "")
        if rid and rid not in ordered:
            ordered.append(rid)
    return {rid: idx for idx, rid in enumerate(ordered)}


def _build_rules(rule_index: Dict[str, int], results: List[Any]) -> List[Dict[str, Any]]:
    """构建 tool.driver.rules 数组（含 cwe 元信息）"""
    cwe_map: Dict[str, Optional[str]] = {}
    for r in results:
        rid = _get(r, "rule_id", "")
        if rid and rid not in cwe_map:
            cwe_map[rid] = _get(r, "cwe", None)

    rules = []
    for rid, idx in rule_index.items():
        rule: Dict[str, Any] = {
            "id": rid,
            "name": rid,
            "shortDescription": {"text": rid},
        }
        cwe = cwe_map.get(rid)
        if cwe:
            rule["properties"] = {"cwe": cwe}
        rules.append(rule)
    return rules


def _build_result(r: Any, rule_index: Dict[str, int]) -> Dict[str, Any]:
    """构建单条 SARIF result"""
    rid = _get(r, "rule_id", "unknown")
    severity = _severity_str(_get(r, "severity", "MEDIUM"))
    file_path = _get(r, "file_path", None) or _get(r, "file", "") or ""
    line = _get(r, "line_start", None)
    if not line:
        line = _get(r, "line", 1) or 1
    message = _get(r, "message", "") or rid
    code = _get(r, "code_snippet", None) or _get(r, "code", "") or ""

    metadata = _get(r, "metadata", {}) or {}
    result: Dict[str, Any] = {
        "ruleId": rid,
        "ruleIndex": rule_index.get(rid, 0),
        "level": SEVERITY_TO_LEVEL.get(severity, "warning"),
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path.replace("\\", "/")},
                    "region": {"startLine": int(line)},
                }
            }
        ],
        "properties": {
            "cvss": SEVERITY_TO_CVSS.get(severity, 5.0),
            "confidence": float(_get(r, "confidence", 0.0) or 0.0),
            "cwe": _get(r, "cwe", None),
        },
    }
    if metadata.get("beautified_line"):
        result["properties"]["preprocessing"] = {
            "kind": metadata.get("preprocessor"),
            "beautifiedLine": metadata["beautified_line"],
            "originalLineRange": metadata.get("original_line_range"),
            "originalOffsetHint": metadata.get("original_offset_hint", {}),
        }
    if code:
        result["properties"]["codeSnippet"] = code[:200]

    fingerprint = _get(r, "fingerprint", None)
    if fingerprint:
        result["partialFingerprints"] = {"fpSentinelFingerprint/v1": fingerprint}

    return result


def to_sarif(results: List[Any]) -> Dict[str, Any]:
    """
    将扫描结果转换为 SARIF 2.1.0 结构。

    Args:
        results: Finding 列表（兼容 ScanResult / dict）

    Returns:
        dict: SARIF 2.1.0 报告结构
    """
    results = results or []
    rule_index = _rule_index_map(results)

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": "https://github.com/xuanjian-ai/fp-sentinel",
                        "rules": _build_rules(rule_index, results),
                    }
                },
                "results": [_build_result(r, rule_index) for r in results],
            }
        ],
    }
