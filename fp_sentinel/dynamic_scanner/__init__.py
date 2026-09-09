"""
玄鉴 v3.1 - Enhanced Dynamic Scanner Module

Strengthens dynamic scanning with:
1. WAF Bypass Testing - multiple encoding/format techniques to test WAF rules
2. Logic Vulnerability Detection - automated business logic flaw testing
3. JS Dynamic Rendering Page Parse - extract data from SPAs and JS-heavy pages

Safety: S1/S2/S4 - all tests use harmless markers only.
"""

from .waf_bypass import WAFBypassTester, BypassTechnique
from .logic_detector import LogicVulnDetector, LogicVulnType
from .js_renderer import JSRenderingAnalyzer
from .models import (
    BypassResult,
    LogicVulnFinding,
    JSRenderResult,
    DynamicScanConfig,
    DynamicScanResult,
)

__all__ = [
    "WAFBypassTester",
    "BypassTechnique",
    "LogicVulnDetector",
    "LogicVulnType",
    "JSRenderingAnalyzer",
    "BypassResult",
    "LogicVulnFinding",
    "JSRenderResult",
    "DynamicScanConfig",
    "DynamicScanResult",
]
