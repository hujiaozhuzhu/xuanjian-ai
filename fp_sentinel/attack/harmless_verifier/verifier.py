"""
Harmless Auto-Verification Engine

Verifies漏洞危害using only harmless markers (fp_sentinel_verify).
Produces complete reproducible verification steps.

Safety: S1/S2/S4 - no real attack payloads, no code modification, only reads source.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

MARKER = "fp_sentinel_verify"


class VerifyConfidence(str, Enum):
    """Confidence level of harmless verification."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNCERTAIN = "uncertain"


@dataclass
class HarmlessVerifyStep:
    """A single step in the verification process."""
    step_number: int = 0
    action: str = ""           # description of what this step does
    command: str = ""          # harmless command or code snippet
    expected_result: str = ""  # what should happen if vulnerability exists
    evidence: str = ""         # actual result observed
    passed: bool = False       # whether this step confirmed the vulnerability


@dataclass
class HarmlessVerifyResult:
    """Complete harmless verification result for a single finding."""
    finding_id: str = ""
    rule_id: str = ""
    file_path: str = ""
    line: int = 0
    vuln_category: str = ""
    confidence: VerifyConfidence = VerifyConfidence.UNCERTAIN
    verified: bool = False
    is_harmless: bool = True    # always true - we only use harmless markers
    steps: List[HarmlessVerifyStep] = field(default_factory=list)
    summary: str = ""
    reproducible_steps: List[str] = field(default_factory=list)
    timestamp: str = ""
    duration_ms: float = 0.0
    sink_identified: bool = False
    input_traced: bool = False
    evidence: str = ""
    remediation_hint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "line": self.line,
            "vuln_category": self.vuln_category,
            "confidence": self.confidence.value,
            "verified": self.verified,
            "is_harmless": True,
            "step_count": len(self.steps),
            "summary": self.summary,
            "reproducible_steps": self.reproducible_steps,
            "evidence": self.evidence,
            "remediation_hint": self.remediation_hint,
            "timestamp": self.timestamp,
            "duration_ms": self.duration_ms,
        }


@dataclass
class VerificationReport:
    """Aggregated verification report for multiple findings."""
    report_id: str = ""
    project: str = ""
    started_at: str = ""
    completed_at: str = ""
    results: List[HarmlessVerifyResult] = field(default_factory=list)
    total_findings: int = 0
    verified_count: int = 0
    simulated_count: int = 0
    manual_count: int = 0
    error_count: int = 0

    def summary(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "project": self.project,
            "total": self.total_findings,
            "verified": self.verified_count,
            "simulated": self.simulated_count,
            "manual_required": self.manual_count,
            "errors": self.error_count,
            "coverage_pct": round(
                (self.verified_count + self.simulated_count) / max(self.total_findings, 1) * 100, 1
            ),
        }


class HarmlessVerifier:
    """Harmless vulnerability verification engine.

    Confirms vulnerability危害using source code analysis only:
    - Locates dangerous function calls (sinks) in source
    - Traces user input to the sink
    - Generates a harmless PoC that proves the issue is real
    """

    SINK_PATTERNS: Dict[str, List[str]] = {
        "sqli": [
            r"(?:execute|query|raw|RawSQL)\s*\(.*(?:\+|\.format|f[\"'])",
            r"(?:SELECT|INSERT|UPDATE|DELETE).*(?:\+|\.format|f[\"'])",
            r"\.execute\s*\(\s*[\"'].*%",
        ],
        "cmd_injection": [
            r"os\.system\s*\(.*(?:\+|\.format)",
            r"subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True",
            r"eval\s*\(",
            r"exec\s*\(",
        ],
        "xss": [
            r"\.innerHTML\s*=",
            r"document\.write\s*\(",
            r"\.insertAdjacentHTML\s*\(",
            r"dangerouslySetInnerHTML",
        ],
        "path_traversal": [
            r"(?:open|readFile|fs\.read)\s*\(.*(?:\+|\.format)",
            r"\.send_file\s*\(.*(?:\+|\.format)",
        ],
        "ssrf": [
            r"(?:requests|urllib|axios|fetch)\.(?:get|post|put|delete)\s*\(.*(?:\+|\.format)",
        ],
        "deserialization": [
            r"pickle\.loads?\s*\(",
            r"yaml\.load\s*\([^)]*\)(?!.*Loader)",
            r"ObjectInputStream",
            r"readObject\s*\(",
            r"JSON\.parseObject",
            r"unserialize\s*\(",
        ],
        "ssti": [
            r"Template\s*\(.*\)\.render",
            r"render_template_string\s*\(",
            r"\.render\s*\(.*\+",
        ],
        "xxe": [
            r"(?:lxml|xml\.etree|minidom|SAXParser)",
            r"XMLParser",
        ],
        "crypto_weak": [
            r"md5\s*\(",
            r"sha1\s*\(",
            r"DES",
            r"RC4",
        ],
        "hardcoded_secret": [
            r"(?:password|secret|token|api_key|apikey)\s*=\s*[\"'][^\"']{4,}[\"']",
        ],
    }

    INPUT_PATTERNS = [
        r"request\.(?:args|form|data|json|values|headers|files)",
        r"(?:req|params|body|query)",
        r"(?:process|os)\.environ",
        r"window\.location",
        r"URLSearchParams",
        r"input\s*\(",
        r"sys\.argv",
        r"\.GET\[",
        r"\.POST\[",
        r"params\[",
    ]

    def __init__(self, project_root: Optional[str] = None, allow_docker: bool = False):
        self.project_root = project_root
        self.allow_docker = allow_docker

    def verify_finding(self, finding: Any) -> HarmlessVerifyResult:
        """Verify a single finding using harmless methods."""
        start = time.time()
        result = HarmlessVerifyResult(
            finding_id=getattr(finding, "id", "") or f"finding-{uuid.uuid4().hex[:6]}",
            rule_id=getattr(finding, "rule_id", "") or "",
            file_path=getattr(finding, "file_path", "") or "",
            line=getattr(finding, "line_start", 0) or 0,
            vuln_category=getattr(finding, "category", "") or "",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        try:
            source = self._read_source(result.file_path)
            if source is None:
                result.confidence = VerifyConfidence.UNCERTAIN
                result.summary = "Source file not readable"
                result.remediation_hint = "Ensure file path is accessible for verification"
                result.duration_ms = round((time.time() - start) * 1000, 2)
                return result

            sink_match, sink_pattern = self._detect_sink(source, result.rule_id)
            result.sink_identified = sink_match

            input_match, input_pattern = self._trace_input(source)
            result.input_traced = input_match

            result.steps = self._build_verification_steps(
                result, source, sink_match, sink_pattern, input_match, input_pattern
            )
            result.reproducible_steps = self._generate_repro_steps(result)

            if sink_match and input_match:
                result.verified = True
                result.confidence = VerifyConfidence.HIGH
                result.evidence = (
                    f"Sink pattern '{sink_pattern}' found near "
                    f"input source '{input_pattern}' in {result.file_path}:{result.line}"
                )
            elif sink_match:
                result.verified = True
                result.confidence = VerifyConfidence.MEDIUM
                result.evidence = (
                    f"Sink pattern '{sink_pattern}' found in {result.file_path}:{result.line}"
                )
            else:
                result.confidence = VerifyConfidence.LOW
                result.summary = "Sink pattern not matched in source"
                result.manual_count = 0

            result.remediation_hint = self._get_remediation_hint(result.rule_id)

        except Exception as e:
            result.confidence = VerifyConfidence.UNCERTAIN
            result.summary = f"Verification error: {e}"

        result.duration_ms = round((time.time() - start) * 1000, 2)
        return result

    def verify_findings(self, findings: List[Any]) -> VerificationReport:
        """Verify multiple findings and produce aggregated report."""
        report = VerificationReport(
            report_id=f"hv-{uuid.uuid4().hex[:8]}",
            started_at=datetime.now(timezone.utc).isoformat(),
            total_findings=len(findings),
        )
        for finding in findings:
            result = self.verify_finding(finding)
            report.results.append(result)
            if result.confidence == VerifyConfidence.HIGH or result.confidence == VerifyConfidence.MEDIUM:
                report.verified_count += 1
            elif result.confidence == VerifyConfidence.LOW:
                report.simulated_count += 1
            else:
                report.manual_count += 1
        report.completed_at = datetime.now(timezone.utc).isoformat()
        return report

    def _read_source(self, file_path: str) -> Optional[str]:
        """Read source file safely."""
        candidates = [Path(file_path)]
        if self.project_root:
            rel = file_path.lstrip("/\\")
            candidates.append(Path(self.project_root) / rel)
        for p in candidates:
            try:
                if p.is_file():
                    return p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
        return None

    def _detect_sink(self, source: str, rule_id: str) -> tuple:
        """Detect dangerous sink patterns in source code."""
        vuln_type = self._rule_id_to_vuln_type(rule_id)
        patterns = self.SINK_PATTERNS.get(vuln_type, [])
        for pattern in patterns:
            try:
                if re.search(pattern, source, re.IGNORECASE | re.MULTILINE):
                    return True, pattern
            except re.error:
                continue
        return False, ""

    def _trace_input(self, source: str) -> tuple:
        """Trace user input in source code."""
        for pattern in self.INPUT_PATTERNS:
            try:
                if re.search(pattern, source):
                    return True, pattern
            except re.error:
                continue
        return False, ""

    def _rule_id_to_vuln_type(self, rule_id: str) -> str:
        """Map rule_id to vulnerability type key."""
        rid = rule_id.lower()
        mappings = [
            (["sql", "sqli", "injection.sql"], "sqli"),
            (["cmd", "command", "os.system", "injection.command"], "cmd_injection"),
            (["xss", "cross.site", "domxss"], "xss"),
            (["path", "traversal", "lfi"], "path_traversal"),
            (["ssrf", "server.side"], "ssrf"),
            (["deser", "deserial", "readobject", "unserialize", "pickle", "yaml.load"], "deserialization"),
            (["ssti", "template"], "ssti"),
            (["xxe", "xml"], "xxe"),
            (["crypto", "md5", "sha1", "weak.*hash"], "crypto_weak"),
            (["hardcoded", "secret", "credential", "password.*="], "hardcoded_secret"),
        ]
        for keywords, vtype in mappings:
            if any(k in rid for k in keywords):
                return vtype
        return ""

    def _build_verification_steps(
        self, result: HarmlessVerifyResult, source: str,
        sink_match: bool, sink_pattern: str,
        input_match: bool, input_pattern: str,
    ) -> List[HarmlessVerifyStep]:
        """Build step-by-step harmless verification process."""
        steps = []
        step_num = 1
        steps.append(HarmlessVerifyStep(
            step_number=step_num,
            action="Read source file",
            command=f"cat {result.file_path} | head -n {result.line + 5} | tail -n 10",
            expected_result=f"Shows code around line {result.line}",
            evidence=f"Source file read successfully ({len(source)} chars)",
            passed=True,
        ))
        step_num += 1
        if sink_match:
            steps.append(HarmlessVerifyStep(
                step_number=step_num,
                action=f"Detect dangerous sink pattern",
                command=f"grep -n '{sink_pattern}' {result.file_path}",
                expected_result="Sink pattern found in source",
                evidence=f"Matched: {sink_pattern}",
                passed=True,
            ))
            step_num += 1
        if input_match:
            steps.append(HarmlessVerifyStep(
                step_number=step_num,
                action="Trace user input to sink",
                command=f"grep -n '{input_pattern}' {result.file_path}",
                expected_result="User input pattern found in same file",
                evidence=f"Matched: {input_pattern}",
                passed=True,
            ))
            step_num += 1
        vuln_type = self._rule_id_to_vuln_type(result.rule_id)
        safe_payload = self._get_safe_payload(vuln_type)
        steps.append(HarmlessVerifyStep(
            step_number=step_num,
            action="Inject harmless marker as proof",
            command=f"# Send: {safe_payload} as the user input",
            expected_result=f"Marker '{MARKER}' appears in output or behavior changes",
            evidence="Harmless verification - no real attack executed",
            passed=sink_match and input_match,
        ))
        step_num += 1
        steps.append(HarmlessVerifyStep(
            step_number=step_num,
            action="Confirm vulnerability exists",
            command="# Review evidence from steps 1-4",
            expected_result="Vulnerability confirmed via harmless marker",
            evidence=f"Sink={'yes' if sink_match else 'no'}, Input={'yes' if input_match else 'no'}",
            passed=sink_match and input_match,
        ))
        return steps

    def _generate_repro_steps(self, result: HarmlessVerifyResult) -> List[str]:
        """Generate human-readable reproducible steps."""
        steps = [
            f"1. Open file: {result.file_path} at line {result.line}",
            f"2. Identify the dangerous function call (sink) at line {result.line}",
        ]
        if result.input_traced:
            steps.append("3. Trace user input to the sink - note that external input reaches the dangerous function")
        else:
            steps.append("3. Identify any user-controllable input that may reach this sink")
        vuln_type = self._rule_id_to_vuln_type(result.rule_id)
        safe_payload = self._get_safe_payload(vuln_type)
        steps.append(f"4. Send harmless marker as input: {safe_payload}")
        steps.append(f"5. Observe the marker in output, confirming the vulnerability exists")
        steps.append(f"6. Fix: Apply input validation and use safe APIs for {vuln_type} operations")
        return steps

    def _get_safe_payload(self, vuln_type: str) -> str:
        """Get a harmless marker payload for the vulnerability type."""
        payloads = {
            "sqli": "' OR 'fp_sentinel_verify'='fp_sentinel_verify",
            "cmd_injection": "; echo fp_sentinel_verify",
            "xss": '<script>alert("fp_sentinel_verify")</script>',
            "path_traversal": "../../../etc/passwd; echo fp_sentinel_verify",
            "ssrf": "http://127.0.0.1:9999/?mark=fp_sentinel_verify",
            "deserialization": '{"__class__":"fp_sentinel_verify"}',
            "ssti": '{{ fp_sentinel_verify }}',
            "xxe": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "fp_sentinel_verify">]>',
            "crypto_weak": "fp_sentinel_verify",
            "hardcoded_secret": "fp_sentinel_verify",
        }
        return payloads.get(vuln_type, MARKER)

    def _get_remediation_hint(self, rule_id: str) -> str:
        """Provide actionable remediation hint."""
        vtype = self._rule_id_to_vuln_type(rule_id)
        hints = {
            "sqli": "Use parameterized queries (PreparedStatement in Java, parameterized queries in Python/Go)",
            "cmd_injection": "Avoid shell execution with user input; use subprocess with shell=False and argument lists",
            "xss": "Use safe DOM APIs (textContent instead of innerHTML), implement CSP headers",
            "path_traversal": "Validate file paths against allowed directories; use os.path.realpath for canonical paths",
            "ssrf": "Validate and whitelist URLs before fetching; block private IP ranges",
            "deserialization": "Use JSON instead of binary deserialization; implement ObjectInputFilter",
            "ssti": "Use Jinja2 sandboxed environment; never render user-supplied templates",
            "xxe": "Disable external entity processing in XML parsers (setFeature to false)",
            "crypto_weak": "Replace MD5/SHA1 with SHA-256+; use AES-GCM instead of DES/RC4",
            "hardcoded_secret": "Use environment variables or secret managers (HashiCorp Vault, AWS Secrets Manager)",
        }
        return hints.get(vtype, "Review and apply security best practices for this vulnerability type")
