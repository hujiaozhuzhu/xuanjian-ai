"""
Reproducible Step Generator

Generates complete, human-readable verification steps from
HarmlessVerifyResult data.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .verifier import HarmlessVerifyResult, VerifyConfidence


def generate_reproducible_steps(result: HarmlessVerifyResult) -> List[str]:
    """Generate formatted reproducible steps from a verification result."""
    steps = _build_steps_from_result(result)
    return [_format_step(i + 1, s) for i, s in enumerate(steps)]


def build_verification_report(
    results: List[HarmlessVerifyResult],
    project_name: str = "",
) -> Dict[str, Any]:
    """Build a comprehensive verification report."""
    high_c = [r for r in results if r.confidence == VerifyConfidence.HIGH]
    med_c = [r for r in results if r.confidence == VerifyConfidence.MEDIUM]
    low_c = [r for r in results if r.confidence == VerifyConfidence.LOW]
    unc_c = [r for r in results if r.confidence == VerifyConfidence.UNCERTAIN]
    return {
        "project": project_name,
        "total_findings": len(results),
        "verified": {
            "high_confidence": len(high_c),
            "medium_confidence": len(med_c),
        },
        "needs_review": {
            "low_confidence": len(low_c),
            "uncertain": len(unc_c),
        },
        "coverage_pct": round(
            (len(high_c) + len(med_c)) / max(len(results), 1) * 100, 1
        ),
        "findings": [r.to_dict() for r in results],
        "is_harmless": True,
    }


def _build_steps_from_result(result: HarmlessVerifyResult) -> List[str]:
    """Build step descriptions from verification result."""
    steps = []
    steps.append(
        "Locate vulnerable code | File: " + str(result.file_path)
        + " | Line: " + str(result.line)
        + " | Sink: " + ("Yes" if result.sink_identified else "No")
    )
    if result.input_traced:
        steps.append(
            "Trace input to sink | User input reaches the dangerous function"
        )
    else:
        steps.append(
            "Identify input source | Find user-controllable input flowing to sink"
        )
    vtype = result.vuln_category or result.rule_id or "unknown"
    steps.append(
        "Craft harmless marker input | Type: " + str(vtype)
        + " | Marker: fp_sentinel_verify (safe, only proves reachability)"
    )
    steps.append(
        "Validate fix | After applying the fix, re-run the harmless marker"
    )
    if result.remediation_hint:
        steps.append("Recommended fix | " + str(result.remediation_hint))
    return steps


def _format_step(step_num: int, step_text: str) -> str:
    return "[Step " + str(step_num) + "] " + step_text


def get_remediation_for_rule(rule_id: str) -> str:
    """Get remediation guidance for a rule ID."""
    rid = (rule_id or "").lower()
    if "sql" in rid:
        return "Use parameterized queries (PreparedStatement, parameterized queries)"
    if "cmd" in rid or "command" in rid:
        return "Avoid shell execution; use subprocess with shell=False"
    if "xss" in rid:
        return "Use safe DOM APIs (textContent), implement CSP headers"
    if "path" in rid:
        return "Validate file paths against allowed directories using realpath"
    if "ssrf" in rid:
        return "Validate and whitelist URLs; block private IP ranges"
    if "deser" in rid or "serial" in rid:
        return "Use JSON instead of binary deserialization; ObjectInputFilter"
    if "ssti" in rid or "template" in rid:
        return "Use Jinja2 sandboxed environment; never render user templates"
    if "xxe" in rid or "xml" in rid:
        return "Disable external entity processing in XML parsers"
    if "crypto" in rid or "md5" in rid or "sha1" in rid:
        return "Replace MD5/SHA1 with SHA-256+; use AES-GCM"
    if "secret" in rid or "password" in rid or "hardcod" in rid:
        return "Use environment variables or secret managers"
    return "Review security best practices for this vulnerability type"
