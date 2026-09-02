"""
共享测试 Fixtures

提供漏洞代码片段、安全代码片段、绕过变体等测试数据
"""

import pytest
from pathlib import Path


# ─────────────────────── JS 漏洞代码片段 ───────────────────────

JS_VULN_SAMPLES = [
    {
        "id": "js-vuln-001",
        "rule_id": "js.xss.innerhtml",
        "code": 'element.innerHTML = userInput;',
        "file": "app.js",
        "line": 10,
        "severity": "HIGH",
        "should_detect": True,
    },
    {
        "id": "js-vuln-002",
        "rule_id": "js.injection.eval",
        "code": 'eval(userInput);',
        "file": "app.js",
        "line": 15,
        "severity": "CRITICAL",
        "should_detect": True,
    },
    {
        "id": "js-vuln-003",
        "rule_id": "js.injection.function-constructor",
        "code": 'new Function("return " + userInput)();',
        "file": "app.js",
        "line": 20,
        "severity": "CRITICAL",
        "should_detect": True,
    },
    {
        "id": "js-vuln-004",
        "rule_id": "js.xss.document-write",
        "code": 'document.write("<script>" + userInput + "</script>");',
        "file": "app.js",
        "line": 25,
        "severity": "HIGH",
        "should_detect": True,
    },
    {
        "id": "js-vuln-005",
        "rule_id": "js.injection.settimeout-string",
        "code": 'setTimeout("alert(" + userInput + ")", 0);',
        "file": "app.js",
        "line": 30,
        "severity": "HIGH",
        "should_detect": True,
    },
    {
        "id": "js-vuln-006",
        "rule_id": "js.secrets.hardcoded-password",
        "code": 'const password = "SuperSecret123!";',
        "file": "config.js",
        "line": 5,
        "severity": "HIGH",
        "should_detect": True,
    },
    {
        "id": "js-vuln-007",
        "rule_id": "js.secrets.hardcoded-private-key",
        "code": 'const key = "-----BEGIN PRIVATE KEY-----\nMIIEvg...";',
        "file": "crypto.js",
        "line": 8,
        "severity": "CRITICAL",
        "should_detect": True,
    },
    {
        "id": "js-vuln-008",
        "rule_id": "js.crypto.math-random",
        "code": 'const token = Math.random().toString(36);',
        "file": "auth.js",
        "line": 12,
        "severity": "LOW",
        "should_detect": True,
    },
    {
        "id": "js-vuln-009",
        "rule_id": "js.unsafe-postmessage-wildcard",
        "code": "window.parent.postMessage(data, '*');",
        "file": "messenger.js",
        "line": 45,
        "severity": "MEDIUM",
        "should_detect": True,
    },
    {
        "id": "js-vuln-010",
        "rule_id": "js.node.command-injection",
        "code": 'exec("ls " + userInput);',
        "file": "server.js",
        "line": 50,
        "severity": "CRITICAL",
        "should_detect": True,
    },
    {
        "id": "js-vuln-011",
        "rule_id": "js.node.sql-injection",
        "code": 'db.query("SELECT * FROM users WHERE id=" + userId);',
        "file": "db.js",
        "line": 20,
        "severity": "CRITICAL",
        "should_detect": True,
    },
    {
        "id": "js-vuln-012",
        "rule_id": "js.node.ssrf",
        "code": 'fetch(req.query.url);',
        "file": "proxy.js",
        "line": 15,
        "severity": "HIGH",
        "should_detect": True,
    },
    {
        "id": "js-vuln-013",
        "rule_id": "js.xss.dangerously-set",
        "code": '<div dangerouslySetInnerHTML={{__html: userInput}} />',
        "file": "Component.jsx",
        "line": 30,
        "severity": "HIGH",
        "should_detect": True,
    },
    {
        "id": "js-vuln-014",
        "rule_id": "js.xss.v-html",
        "code": '<div v-html="userInput"></div>',
        "file": "template.vue",
        "line": 10,
        "severity": "HIGH",
        "should_detect": True,
    },
    {
        "id": "js-vuln-015",
        "rule_id": "js.aigc.llm-output-eval",
        "code": 'eval(llmResponse);',
        "file": "ai.js",
        "line": 25,
        "severity": "CRITICAL",
        "should_detect": True,
    },
]


# ─────────────────────── JS 安全代码片段（误报测试） ───────────────────────

JS_SAFE_SAMPLES = [
    {
        "id": "js-safe-001",
        "rule_id": "js.xss.innerhtml",
        "code": 'element.textContent = userInput;',
        "file": "safe.js",
        "line": 10,
        "should_detect": False,
        "reason": "textContent 是安全赋值",
    },
    {
        "id": "js-safe-002",
        "rule_id": "js.injection.eval",
        "code": 'const data = JSON.parse(userInput);',
        "file": "safe.js",
        "line": 15,
        "should_detect": False,
        "reason": "JSON.parse 不是 eval",
    },
    {
        "id": "js-safe-003",
        "rule_id": "js.xss.innerhtml",
        "code": 'element.innerText = userInput;',
        "file": "safe.js",
        "line": 20,
        "should_detect": False,
        "reason": "innerText 自动转义",
    },
    {
        "id": "js-safe-004",
        "rule_id": "js.injection.eval",
        "code": 'const num = parseInt(userInput);',
        "file": "safe.js",
        "line": 25,
        "should_detect": False,
        "reason": "parseInt 不是 eval",
    },
    {
        "id": "js-safe-005",
        "rule_id": "js.xss.innerhtml",
        "code": 'const el = document.createElement("div");',
        "file": "safe.js",
        "line": 30,
        "should_detect": False,
        "reason": "createElement 是安全的",
    },
    {
        "id": "js-safe-006",
        "rule_id": "js.injection.eval",
        "code": 'console.log("debug: " + userInput);',
        "file": "safe.js",
        "line": 35,
        "should_detect": False,
        "reason": "console.log 不执行代码",
    },
    {
        "id": "js-safe-007",
        "rule_id": "js.xss.innerhtml",
        "code": 'element.innerHTML = DOMPurify.sanitize(userInput);',
        "file": "safe.js",
        "line": 40,
        "should_detect": False,
        "reason": "DOMPurify 消毒",
    },
    {
        "id": "js-safe-008",
        "rule_id": "js.secrets.hardcoded-password",
        "code": 'const password = process.env.PASSWORD;',
        "file": "safe.js",
        "line": 45,
        "should_detect": False,
        "reason": "从环境变量读取",
    },
    {
        "id": "js-safe-009",
        "rule_id": "js.injection.eval",
        "code": 'eval("1 + 1");',
        "file": "safe.js",
        "line": 50,
        "should_detect": False,
        "reason": "常量表达式",
    },
    {
        "id": "js-safe-010",
        "rule_id": "js.xss.innerhtml",
        "code": '// nosec: innerHTML is safe here\nelement.innerHTML = trustedHTML;',
        "file": "safe.js",
        "line": 55,
        "should_detect": False,
        "reason": "白名单注释",
    },
]


# ─────────────────────── Python 漏洞代码片段 ───────────────────────

PYTHON_VULN_SAMPLES = [
    {
        "id": "py-vuln-001",
        "rule_id": "py.injection.sql",
        "code": 'cursor.execute("SELECT * FROM users WHERE id=" + user_id)',
        "file": "db.py",
        "line": 10,
        "severity": "CRITICAL",
        "should_detect": True,
    },
    {
        "id": "py-vuln-002",
        "rule_id": "py.injection.command",
        "code": 'os.system("ls " + user_input)',
        "file": "cmd.py",
        "line": 15,
        "severity": "CRITICAL",
        "should_detect": True,
    },
    {
        "id": "py-vuln-003",
        "rule_id": "py.injection.eval",
        "code": 'eval(user_input)',
        "file": "eval.py",
        "line": 20,
        "severity": "CRITICAL",
        "should_detect": True,
    },
    {
        "id": "py-vuln-004",
        "rule_id": "py.deserialization.pickle",
        "code": 'pickle.loads(user_data)',
        "file": "deserialize.py",
        "line": 25,
        "severity": "CRITICAL",
        "should_detect": True,
    },
    {
        "id": "py-vuln-005",
        "rule_id": "py.deserialization.yaml",
        "code": 'yaml.load(user_input)',
        "file": "config.py",
        "line": 30,
        "severity": "CRITICAL",
        "should_detect": True,
    },
    {
        "id": "py-vuln-006",
        "rule_id": "py.crypto.weak_hash",
        "code": 'hashlib.md5(password.encode()).hexdigest()',
        "file": "auth.py",
        "line": 35,
        "severity": "HIGH",
        "should_detect": True,
    },
    {
        "id": "py-vuln-007",
        "rule_id": "py.crypto.hardcoded_key",
        "code": 'SECRET_KEY = "akjhdkjahsdkjhasdkjh1234"',
        "file": "settings.py",
        "line": 5,
        "severity": "CRITICAL",
        "should_detect": True,
    },
    {
        "id": "py-vuln-008",
        "rule_id": "py.ssrf.requests",
        "code": 'requests.get(req.args["url"])',
        "file": "proxy.py",
        "line": 40,
        "severity": "MEDIUM",
        "should_detect": True,
    },
    {
        "id": "py-vuln-009",
        "rule_id": "py.path.traversal",
        "code": 'open(os.path.join(base_dir, user_input))',
        "file": "files.py",
        "line": 45,
        "severity": "HIGH",
        "should_detect": True,
    },
    {
        "id": "py-vuln-010",
        "rule_id": "py.xxe.lxml",
        "code": 'etree.parse(user_xml)',
        "file": "xml_parser.py",
        "line": 50,
        "severity": "HIGH",
        "should_detect": True,
    },
]


# ─────────────────────── 红队绕过变体 ───────────────────────

BYPASS_VARIANTS = [
    {
        "strategy": "api_substitution",
        "difficulty": "L1",
        "original": 'eval(userInput)',
        "bypass": 'new Function("return " + userInput)()',
        "expected_detected": True,
    },
    {
        "strategy": "encoding_bypass",
        "difficulty": "L2",
        "original": 'eval(userInput)',
        "bypass": 'eval(atob("ZXZhbA=="))',
        "expected_detected": False,
    },
    {
        "strategy": "control_flow",
        "difficulty": "L3",
        "original": 'eval(userInput)',
        "bypass": 'if (true) { eval(userInput); }',
        "expected_detected": True,
    },
    {
        "strategy": "string_splitting",
        "difficulty": "L2",
        "original": 'eval(userInput)',
        "bypass": 'window["e" + "val"](userInput)',
        "expected_detected": False,
    },
    {
        "strategy": "async_wrapping",
        "difficulty": "L2",
        "original": 'eval(userInput)',
        "bypass": 'setTimeout(() => { eval(userInput); }, 0)',
        "expected_detected": True,
    },
]


# ─────────────────────── Fixtures ───────────────────────

@pytest.fixture
def js_vuln_samples():
    return JS_VULN_SAMPLES


@pytest.fixture
def js_safe_samples():
    return JS_SAFE_SAMPLES


@pytest.fixture
def python_vuln_samples():
    return PYTHON_VULN_SAMPLES


@pytest.fixture
def bypass_variants():
    return BYPASS_VARIANTS


@pytest.fixture
def tmp_code_dir(tmp_path):
    """创建临时代码目录"""
    code_dir = tmp_path / "project"
    code_dir.mkdir()
    return code_dir


@pytest.fixture
def js_vuln_file(tmp_code_dir):
    """创建包含漏洞的JS文件"""
    content = """
const userInput = req.query.input;

// XSS via innerHTML
element.innerHTML = userInput;

// Code injection via eval
eval(userInput);

// Command injection
exec("ls " + userInput);

// Hardcoded secret
const API_KEY = "sk-1234567890abcdef";

// Safe code (should not be flagged)
element.textContent = userInput;
const data = JSON.parse(userInput);
"""
    file_path = code_dir / "vulnerable.js"
    file_path.write_text(content)
    return file_path


@pytest.fixture
def js_safe_file(tmp_code_dir):
    """创建安全的JS文件"""
    content = """
const DOMPurify = require('dompurify');

// Safe: textContent
element.textContent = userInput;

// Safe: JSON.parse
const data = JSON.parse(userInput);

// Safe: DOMPurify
element.innerHTML = DOMPurify.sanitize(userInput);

// Safe: createElement
const el = document.createElement("div");

// Safe: parseInt
const num = parseInt(userInput);
"""
    file_path = code_dir / "safe.js"
    file_path.write_text(content)
    return file_path
