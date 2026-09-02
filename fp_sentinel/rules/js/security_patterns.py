"""
JavaScript 安全模式定义

定义 JS 特有的安全检测模式，用于上下文分析和误报过滤
"""

from typing import Dict, List, Any


# ─────────────────────── 数据源 (Sources) ───────────────────────
# 用户可控的数据输入点

JS_SOURCES: Dict[str, List[str]] = {
    "user_input": [
        r"document\.getElementById\s*\([^)]+\)\.value",
        r"\.value\s*$",
        r"FormData",
        r"new\s+FormData",
    ],
    "url": [
        r"window\.location\.(href|search|hash|pathname)",
        r"document\.URL",
        r"document\.documentURI",
        r"location\.(href|search|hash)",
        r"URLSearchParams",
        r"\.search\b",
        r"\.hash\b",
    ],
    "dom": [
        r"document\.(getElementById|querySelector|getElementsBy)",
        r"\.innerHTML",
        r"\.outerHTML",
        r"\.textContent",
        r"\.innerText",
        r"\.getAttribute\s*\(",
        r"\.dataset\.",
        r"document\.cookie",
    ],
    "api_response": [
        r"(fetch|axios|XMLHttpRequest|\.ajax)\s*\(",
        r"\.json\s*\(\)",
        r"\.text\s*\(\)",
        r"response\.",
        r"res\.body",
        r"req\.(body|query|params|headers)",
    ],
    "storage": [
        r"localStorage\.(getItem|key)",
        r"sessionStorage\.(getItem|key)",
        r"document\.cookie",
        r"indexedDB",
    ],
    "message": [
        r"window\.addEventListener\s*\(\s*['\"]message['\"]",
        r"onmessage\s*=",
        r"postMessage",
        r"BroadcastChannel",
    ],
}


# ─────────────────────── 数据汇聚点 (Sinks) ───────────────────────
# 危险的操作点

JS_SINKS: Dict[str, List[str]] = {
    "xss": [
        r"\.innerHTML\s*=",
        r"\.outerHTML\s*=",
        r"document\.write(ln)?\s*\(",
        r"\.insertAdjacentHTML\s*\(",
        r"dangerouslySetInnerHTML",
        r"v-html",
        r"\$\(.*\)\.html\s*\(",
    ],
    "eval": [
        r"\beval\s*\(",
        r"new\s+Function\s*\(",
        r"setTimeout\s*\(\s*['\"]",
        r"setInterval\s*\(\s*['\"]",
    ],
    "url": [
        r"window\.(open|location)\s*=",
        r"location\.(href|replace|assign)\s*=",
        r"window\.open\s*\(",
        r"\.href\s*=",
    ],
    "request": [
        r"(fetch|axios|XMLHttpRequest|\.ajax)\s*\(",
        r"\.open\s*\(\s*['\"](?:GET|POST|PUT|DELETE)",
        r"\.send\s*\(",
    ],
    "storage": [
        r"localStorage\.setItem",
        r"sessionStorage\.setItem",
        r"document\.cookie\s*=",
    ],
    "dom_manipulation": [
        r"document\.createElement",
        r"\.appendChild\s*\(",
        r"\.insertBefore\s*\(",
        r"\.replaceChild\s*\(",
        r"\.append\s*\(",
        r"\.prepend\s*\(",
    ],
    "command": [
        r"(exec|execSync|spawn|spawnSync)\s*\(",
        r"child_process",
    ],
    "file": [
        r"(readFile|readFileSync|writeFile|writeFileSync)\s*\(",
        r"fs\.",
        r"createReadStream",
        r"createWriteStream",
    ],
}


# ─────────────────────── 危险函数组合 ───────────────────────
# Source -> Sink 的高危组合

DANGEROUS_COMBINATIONS = [
    {
        "name": "DOM XSS via innerHTML",
        "source": ["url", "dom", "user_input"],
        "sink": "xss",
        "severity": "HIGH",
        "cwe": "CWE-79",
    },
    {
        "name": "Code Injection via eval",
        "source": ["user_input", "url", "api_response"],
        "sink": "eval",
        "severity": "CRITICAL",
        "cwe": "CWE-95",
    },
    {
        "name": "Open Redirect",
        "source": ["url", "user_input", "api_response"],
        "sink": "url",
        "severity": "MEDIUM",
        "cwe": "CWE-601",
    },
    {
        "name": "SSRF",
        "source": ["user_input", "url"],
        "sink": "request",
        "severity": "HIGH",
        "cwe": "CWE-918",
    },
    {
        "name": "Client-side Storage of Sensitive Data",
        "source": ["api_response", "user_input"],
        "sink": "storage",
        "severity": "MEDIUM",
        "cwe": "CWE-922",
    },
    {
        "name": "Command Injection",
        "source": ["user_input", "url", "api_response"],
        "sink": "command",
        "severity": "CRITICAL",
        "cwe": "CWE-78",
    },
    {
        "name": "Path Traversal",
        "source": ["user_input", "url"],
        "sink": "file",
        "severity": "HIGH",
        "cwe": "CWE-22",
    },
]


# ─────────────────────── 代码复杂度指标 ───────────────────────

COMPLEXITY_INDICATORS = {
    "high_nesting": [  # 高嵌套深度
        r"if\s*\([^)]*\)\s*\{[^}]*if\s*\([^)]*\)\s*\{[^}]*if\s*\(",
    ],
    "callback_hell": [  # 回调地狱
        r"\}\)\s*\)\s*\)\s*\)",
        r"\.then\s*\([^)]*\)\s*\.then\s*\([^)]*\)\s*\.then\s*\(",
    ],
    "complex_condition": [  # 复杂条件
        r"if\s*\([^)]{100,}\)",
    ],
}
