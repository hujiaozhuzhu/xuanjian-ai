"""
Dynamic Scanner Data Models

Defines all structures for WAF bypass testing, logic vulnerability
detection, and JS rendering analysis.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class BypassTechnique(str, Enum):
    URL_ENCODE = "url_encode"
    DOUBLE_ENCODE = "double_encode"
    BASE64 = "base64"
    HEX_ENCODE = "hex_encode"
    UNICODE_ESCAPE = "unicode_escape"
    CASE_VARIATION = "case_variation"
    WHITESPACE_INJECT = "whitespace_inject"
    COMMENT_INJECT = "comment_inject"
    PARAM_POLLUTION = "param_pollution"
    HEADER_INJECT = "header_inject"
    METHOD_OVERRIDE = "method_override"
    CONTENT_TYPE_SWITCH = "content_type_switch"
    CHUNKED_TRANSFER = "chunked_transfer"
    NULL_BYTE = "null_byte"
    MULTIPART_BYPASS = "multipart_bypass"


class LogicVulnType(str, Enum):
    PRICE_TAMPERING = "price_tampering"
    QUANTITY_TAMPERING = "quantity_tampering"
    COUPON_REUSE = "coupon_reuse"
    RACE_CONDITION = "race_condition"
    FLOW_SKIP = "flow_skip"
    NEGATIVE_VALUE = "negative_value"
    ORDERSPLIT = "order_split"
    IDOR = "idor"
    SESSION_FIXATION = "session_fixation"
    PASSWORD_RESET = "password_reset"


class BypassResult(BaseModel):
    model_config = {"extra": "forbid"}

    technique: BypassTechnique = Field(..., description="Technique used")
    payload: str = Field(..., description="Payload sent (harmless marker)")
    target_url: str = Field(..., description="Target URL")
    status_code: int = Field(0, description="HTTP response status")
    response_size: int = Field(0, description="Response body size")
    blocked: bool = Field(True, description="Whether WAF blocked the request")
    duration_ms: float = Field(0.0)
    evidence: str = Field("", description="Evidence of bypass (e.g., marker visible)")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class LogicVulnFinding(BaseModel):
    model_config = {"extra": "forbid"}

    vuln_type: LogicVulnType = Field(..., description="Type of logic vulnerability")
    endpoint: str = Field(..., description="Affected endpoint")
    description: str = Field(..., description="Finding description")
    severity: str = Field("HIGH", description="Severity level")
    proof: str = Field("", description="Proof/evidence of the finding")
    reproducible_steps: List[str] = Field(default_factory=list,
                                         description="Reproduction steps")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class JSRenderResult(BaseModel):
    model_config = {"extra": "forbid"}

    url: str = Field(..., description="Page URL")
    rendered_title: str = Field("", description="Title after JS rendering")
    rendered_html: str = Field("", description="Rendered HTML snippet")
    data_elements: List[Dict[str, str]] = Field(default_factory=list,
                                                description="Extracted data elements")
    api_calls_detected: List[Dict[str, str]] = Field(default_factory=list,
                                                     description="API calls detected during render")
    dom_mutations: int = Field(0, description="Number of DOM mutations observed")
    load_time_ms: float = Field(0.0, description="Total page load time")
    success: bool = Field(True)
    error: str = Field("")


class DynamicScanConfig(BaseModel):
    model_config = {"extra": "forbid"}

    target_url: str = Field(..., description="Base target URL")
    max_waf_techniques: int = Field(10, ge=1, le=15,
                                    description="Max WAF bypass techniques to try")
    logic_test_depth: int = Field(3, ge=1, le=5,
                                  description="Logic test recursion depth")
    js_render_wait_ms: int = Field(5000, ge=1000, le=30000,
                                   description="Max wait for JS rendering")
    enabled_techniques: List[BypassTechnique] = Field(
        default_factory=lambda: list(BypassTechnique),
        description="Techniques to enable (default all)",
    )
    test_payload: str = Field("fp_sentinel_verify",
                              description="Harmless marker payload")
    additional_headers: Dict[str, str] = Field(default_factory=dict)


class DynamicScanResult(BaseModel):
    model_config = {"extra": "forbid"}

    scan_id: str = Field(..., description="Unique scan ID")
    target_url: str = Field(..., description="Target URL")
    config: DynamicScanConfig = Field(...)
    bypass_results: List[BypassResult] = Field(default_factory=list)
    logic_findings: List[LogicVulnFinding] = Field(default_factory=list)
    js_render_results: List[JSRenderResult] = Field(default_factory=list)
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = Field(None)
    summary: Dict[str, Any] = Field(default_factory=dict)
