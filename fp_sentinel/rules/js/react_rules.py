"""
React / Angular 框架专属漏洞规则库 v1.0.0

覆盖 React 和 Angular 生态中常见的安全风险场景：
- React: dangerouslySetInnerHTML XSS、href 注入、useEffect 动态加载、eval/Function 执行、
  React Router 路径遍历、console 泄露、Socket.io 直接渲染等 (25 条)
- Angular: [innerHTML] 绑定、bypassSecurityTrust* 绕过、模板注入 ngTemplateOutlet、
  ElementRef DOM 操作、@ViewChild 直接访问、Zone.js monkey-patch、路由通配符绕过等 (8 条)

所有规则导出为 RULES: list[CustomRule]，与已有的 JS_SECURITY_RULES / VUE_SECURITY_RULES
并列使用，由 js_scanner 在扫描 .jsx/.tsx/.js/.ts 文件时加载。
"""

from typing import List

from .rules import CustomRule


# ─────────────────────── React XSS 规则 (8 条) ───────────────────────

REACT_XSS_RULES = [
    CustomRule(
        rule_id="react.xss.dangerously-set-innerhtml",
        description="React dangerouslySetInnerHTML 直接渲染未净化 HTML 导致 XSS",
        severity="HIGH",
        confidence=0.85,
        code_pattern=r"dangerouslySetInnerHTML\s*=\s*\{\s*__html\s*:",
        category="REACT_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
        false_positive_indicators=["DOMPurify", "sanitize", "escapeHtml", "purify"],
    ),
    CustomRule(
        rule_id="react.xss.dangerously-set-user-input",
        description="dangerouslySetInnerHTML 使用用户输入拼接的 __html 值导致 XSS",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"dangerouslySetInnerHTML\s*=\s*\{\s*__html\s*:\s*(?:[^}]*(?:\+|\$\{))(?:[^}]*(?:props|state|params|query|req\.|user|input))",
        category="REACT_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    CustomRule(
        rule_id="react.xss.innerhtml-assign",
        description="React 组件中通过 ref 直接操作 .innerHTML 赋值导致 DOM XSS",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"\.innerHTML\s*=",
        category="REACT_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
        false_positive_indicators=["textContent", "innerText", "DOMPurify", "sanitize"],
    ),
    CustomRule(
        rule_id="react.xss.insert-adjacent-html",
        description="insertAdjacentHTML 可能导致 DOM XSS (React ref 场景)",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"\.insertAdjacentHTML\s*\(",
        category="REACT_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    CustomRule(
        rule_id="react.xss.setstate-xss",
        description="setState 中直接设置含用户输入的 HTML 状态导致 XSS",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"setState\s*\([^)]*(?:html|content|body|dangerouslySetInnerHTML|__html)\s*:",
        category="REACT_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
        false_positive_indicators=["DOMPurify", "sanitize"],
    ),
    CustomRule(
        rule_id="react.xss.json-parse-render",
        description="JSON.parse 后未校验直接渲染到 JSX 中可能导致 XSS",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"JSON\.parse\s*\([^)]*(?:body|input|req\.|params|data)[^)]*\)\s*\)[\s\S]{0,50}(?:return|<)",
        category="REACT_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
        file_pattern="*.{jsx,tsx}",
    ),
    CustomRule(
        rule_id="react.xss.href-injection",
        description="href 直接使用用户输入拼接导致 open redirect 或 javascript: XSS",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"(?:href|to)\s*=\s*[`'\"]\s*\$\{[^}]*(?:props|location|params|query|req\.|user)",
        category="REACT_XSS",
        cwe="CWE-601",
        owasp="A01:2021 - Broken Access Control",
        false_positive_indicators=["encodeURI", "URL.canParse", "validate"],
    ),
    CustomRule(
        rule_id="react.xss.window-location-props",
        description="window.location 使用 props 赋值导致 open redirect (CWE-601)",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"(?:window\.location|location\.href)\s*=\s*(?:props\.|this\.props\.|params\.|query\.)(?:redirect|url|target|goto|returnUrl|return_to)",
        category="REACT_XSS",
        cwe="CWE-601",
        owasp="A01:2021 - Broken Access Control",
    ),
]


# ─────────────────────── React 安全风险规则 (10 条) ───────────────────────

REACT_SECURITY_RULES = [
    CustomRule(
        rule_id="react.sec.target-blank-no-rel",
        description="target=_blank 未搭配 rel=noopener/noreferrer 可能遭受 tabnabbing 攻击 (CWE-1022)",
        severity="MEDIUM",
        confidence=0.7,
        code_pattern=r"""target\s*=\s*["']_blank["'](?!.*rel\s*=)""",
        category="REACT_UNSAFE",
        cwe="CWE-1022",
        owasp="A05:2021 - Security Misconfiguration",
        false_positive_indicators=["noopener", "noreferrer"],
    ),
    CustomRule(
        rule_id="react.sec.useeffect-external-script",
        description="useEffect 中动态加载第三方外部脚本存在供应链攻击风险 (CWE-829)",
        severity="HIGH",
        confidence=0.65,
        code_pattern=r"useEffect\s*\([^)]*[\s\S]*?(?:createElement\s*\(\s*['\"]script|script\.src\s*=|import\s*\([^)]*(?:http|//))",
        category="REACT_INJECTION",
        cwe="CWE-829",
        owasp="A08:2021 - Software and Data Integrity Failures",
        false_positive_indicators=["integrity", "nonce", "strict-dynamic"],
    ),
    CustomRule(
        rule_id="react.sec.eval-dynamic-exec",
        description="React 组件中使用 eval() 或 new Function() 动态执行代码",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"\b(?:eval|Function)\s*\(",
        category="REACT_INJECTION",
        cwe="CWE-95",
        owasp="A03:2021 - Injection",
        false_positive_indicators=["JSON.parse", "parseInt", "parseFloat"],
    ),
    CustomRule(
        rule_id="react.sec.ssrf-fetch-url-props",
        description="fetch/axios 使用 props 拼接 URL 导致 SSRF",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"(?:fetch|axios(?:\.\w+)?)\s*\(\s*(?:[^,)]*(?:\$\{[^}]*(?:props|location|params|query|req\.|user|input)))",
        category="REACT_SSRF",
        cwe="CWE-918",
        owasp="A10:2021 - Server-Side Request Fraud",
        file_pattern="*.{jsx,tsx,js,ts}",
        false_positive_indicators=["URL.canParse", "allowed", "whitelist", "allowlist"],
    ),
    CustomRule(
        rule_id="react.sec.react-router-traversal",
        description="React Router v6 useRoutes / 动态导入中存在路径遍历风险",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"(?:useRoutes|createBrowserRouter)\s*\([^)]*(?:\*|:\w+\*|path\s*:\s*['\"]\*)",
        category="REACT_ROUTING",
        cwe="CWE-22",
        owasp="A01:2021 - Broken Access Control",
    ),
    CustomRule(
        rule_id="react.sec.console-sensitive",
        description="console.log/warn/error 输出敏感信息 (token/password/secret 等)",
        severity="LOW",
        confidence=0.45,
        code_pattern=r"""console\.(?:log|debug|info|warn|error)\s*\([^)]*(?:password|token|secret|key|auth|ssn|credential|credit)""",
        category="REACT_SECRETS",
        cwe="CWE-532",
        owasp="A09:2021 - Security Logging and Monitoring Failures",
        false_positive_indicators=["redact", "mask", "obfuscate", "***"],
    ),
    CustomRule(
        rule_id="react.sec.socket-io-onmessage-render",
        description="Socket.io onMessage 数据直接渲染 JSX 或设置 innerHTML 导致 XSS",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"(?:socket|io)\.(?:on|addEventListener)\s*\(\s*['\"](?:message|data)['\"][\s\S]{0,100}(?:setState|innerHTML|dangerouslySetInnerHTML|__html)",
        category="REACT_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
        file_pattern="*.{jsx,tsx,js,ts}",
    ),
    CustomRule(
        rule_id="react.sec.webgl-canvas-fingerprint-bypass",
        description="WebGL/Canvas 代码尝试绕过 fingerprint detection 或进行逆向检测",
        severity="LOW",
        confidence=0.4,
        code_pattern=r"(?:getParameter|getExtension|toDataURL|getImageData)\s*\([\s\S]{0,50}(?:webgl|canvas|renderer|vendor)",
        category="REACT_UNSAFE",
        cwe="CWE-200",
        owasp="A01:2021 - Broken Access Control",
        file_pattern="*.{jsx,tsx,js,ts}",
    ),
    CustomRule(
        rule_id="react.sec.localstorage-sensitive",
        description="React 组件将敏感信息 (token/password) 存到 localStorage 中易被 XSS 窃取",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"localStorage\.(?:setItem|getItem)\s*\(\s*['\"](?:token|jwt|access_token|password|secret|apiKey)['\"]",
        category="REACT_SECRETS",
        cwe="CWE-312",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    CustomRule(
        rule_id="react.sec.stale-closure-user-input",
        description="React useEffect/useCallback 闭包中引用过期用户输入状态导致安全策略绕过",
        severity="MEDIUM",
        confidence=0.45,
        code_pattern=r"use(?:Effect|Callback|Memo)\s*\(\s*[\(\)]\s*=>\s*\{[^}]*(?:setState|setValue)\s*\([^)]*(?:props\.|state\.)(?:user|input|data)",
        category="REACT_LOGIC",
        cwe="CWE-20",
        owasp="A04:2021 - Insecure Design",
        file_pattern="*.{jsx,tsx}",
    ),
]


# ─────────────────────── React 模板注入与渲染规则 (7 条) ───────────────────────

REACT_TEMPLATE_RULES = [
    CustomRule(
        rule_id="react.tmpl.hydration-mismatch-exploit",
        description="React hydration 过程中利用 mismatch 注入恶意 DOM",
        severity="MEDIUM",
        confidence=0.45,
        code_pattern=r"hydrateRoot|hydrate\s*\(",
        category="REACT_RENDER",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
        false_positive_indicators=["createRoot", "StrictMode"],
    ),
    CustomRule(
        rule_id="react.tmpl.static-props-xss",
        description="React 组件接收 props 后直接用于危险属性 (style/script) 导致 XSS",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"(?:style|on\w+)\s*=\s*\{\s*(?:props|this\.props)\.[\w.]+\s*\}",
        category="REACT_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
        false_positive_indicators=["sanitize", "isSafeUrl", "validator"],
    ),
    CustomRule(
        rule_id="react.tmpl.client-side-storage-leak",
        description="React 组件将敏感凭据存储在 sessionStorage 中面临 XSS 窃取风险",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"sessionStorage\.(?:setItem|getItem)\s*\(\s*['\"](?:token|jwt|secret|apiKey|password)['\"]",
        category="REACT_SECRETS",
        cwe="CWE-312",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    CustomRule(
        rule_id="react.tmpl.dangerously-trusted-types",
        description="React 中绕过 Trusted Types 策略动态创建 script/iframe",
        severity="HIGH",
        confidence=0.6,
        code_pattern=r"trustedTypes\s*\.\s*(?:createPolicy|emptyPolicy|defaultPolicy)",
        category="REACT_INJECTION",
        cwe="CWE-95",
        owasp="A03:2021 - Injection",
        false_positive_indicators=["require-trusted-types-for"],
    ),
    CustomRule(
        rule_id="react.tmpl.third-party-embed-unsafe",
        description="React 组件中嵌入第三方 iframe/widget 未设置 sandbox 属性",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"<iframe[^>]*(?!.*sandbox)",
        category="REACT_UNSAFE",
        cwe="CWE-1021",
        owasp="A05:2021 - Security MisConfiguration",
        file_pattern="*.{jsx,tsx}",
        false_positive_indicators=["sandbox="],
    ),
    CustomRule(
        rule_id="react.tmpl.generator-yield-exec",
        description="React 组件使用 Generator/async generator 动态注入并执行用户代码",
        severity="HIGH",
        confidence=0.65,
        code_pattern=r"function\s*\*\s*\w*[\s\S]*?(?:eval|Function|dangerouslySetInnerHTML|innerHTML)",
        category="REACT_INJECTION",
        cwe="CWE-95",
        owasp="A03:2021 - Injection",
        file_pattern="*.{jsx,tsx}",
    ),
    CustomRule(
        rule_id="react.tmpl.suspicious-useeffect-fetch",
        description="useEffect 中使用 fetch 外部 URL 且 URL 参数来自 props (open redirect/SSRF)",
        severity="HIGH",
        confidence=0.65,
        code_pattern=r"useEffect\s*\([\s\S]*fetch\s*\(\s*(?:[^)]*(?:\$|`|concat)[^)]*(?:props|location|params|query|req\.|user|input))",
        category="REACT_SSRF",
        cwe="CWE-918",
        owasp="A10:2021 - Server-Side Request Forgery",
        file_pattern="*.{jsx,tsx}",
    ),
]


# ─────────────────────── Angular 专属规则 (8 条) ───────────────────────

ANGULAR_RULES = [
    CustomRule(
        rule_id="ng.xss.innerhtml-binding",
        description="Angular [innerHTML] 属性绑定未净化可能导致 XSS (CWE-79)",
        severity="HIGH",
        confidence=0.85,
        code_pattern=r"\[innerHTML\]\s*=\s*['\"]",
        category="ANGULAR_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
        file_pattern="*.{ts,html}",
        false_positive_indicators=["sanitizer", "bypassSecurityTrustHtml", "sanitize"],
    ),
    CustomRule(
        rule_id="ng.xss.bypass-security-trust",
        description="Angular bypassSecurityTrustHtml/ResourceUrl/Script/Url/Style 绕过安全策略 (CWE-79)",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"bypassSecurityTrust(?:Html|ResourceUrl|Script|Url|Style)\s*\(",
        category="ANGULAR_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
        file_pattern="*.ts",
    ),
    CustomRule(
        rule_id="ng.inject.ng-template-outlet",
        description="Angular ngOutletContext/ngTemplateOutlet 使用用户可控输入可能导致模板注入",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"(?:ngTemplateOutlet|ngOutletContext)\s*:\s*(?:user|input|data|body|query|params)",
        category="ANGULAR_TEMPLATE_INJECTION",
        cwe="CWE-1336",
        owasp="A03:2021 - Injection",
        file_pattern="*.{ts,html}",
    ),
    CustomRule(
        rule_id="ng.dom.element-ref-native",
        description="Angular ElementRef.nativeElement 直接操作 DOM 绕过框架安全机制 (CWE-79)",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"(?:ElementRef|nativeElement)\s*\.?\s*(?:nativeElement)?\s*(?:\.|\?\.)\s*(?:innerHTML|outerHTML|insertAdjacentHTML|write|href|src)",
        category="ANGULAR_DOM",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
        file_pattern="*.ts",
        false_positive_indicators=["textContent", "setAttribute", "classList"],
    ),
    CustomRule(
        rule_id="ng.http.params-concat",
        description="Angular HttpClient HttpParams 使用字符串拼接用户输入可能导致注入",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"new\s+HttpParams\(\s*\)\s*(?:\.append|\.set)\s*\([^)]*(?:\+|\$\{)(?:[^)]*(?:params|query|input|req\.|user))",
        category="ANGULAR_INJECTION",
        cwe="CWE-20",
        owasp="A03:2021 - Injection",
        file_pattern="*.ts",
    ),
    CustomRule(
        rule_id="ng.dom.viewchild-dom-access",
        description="Angular @ViewChild / @ViewChildren 直接访问 nativeElement 进行 DOM 操作",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"@ViewChild\s*\([^)]*\)\s*\w+\s*:\s*[\s\S]*?\.nativeElement\.",
        category="ANGULAR_DOM",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
        file_pattern="*.ts",
        false_positive_indicators=["textContent", "classList", "setAttribute"],
    ),
    CustomRule(
        rule_id="ng.zone.monkey-patch",
        description="Zone.js monkey-patch 可能用于绕过 Angular 变更检测安全机制",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"(?:Zone|ngZone)\s*\.\s*(?:current|run|onError)\s*=|__Zone_disable",
        category="ANGULAR_ZONE",
        cwe="CWE-1021",
        owasp="A05:2021 - Security Misconfiguration",
        file_pattern="*.{ts,js}",
    ),
    CustomRule(
        rule_id="ng.route.wildcard-auth-bypass",
        description="Angular 路由通配符 (**) 未配置 auth guard 导致未授权访问 (CWE-284)",
        severity="HIGH",
        confidence=0.65,
        code_pattern=r"path\s*:\s*['\"]\*\*['\"](?!.*canActivate|canLoad|canActivateChild|canDeactivate)",
        category="ANGULAR_ROUTING",
        cwe="CWE-284",
        owasp="A01:2021 - Broken Access Control",
        file_pattern="*.ts",
        false_positive_indicators=["canActivate", "canLoad", "canActivateChild"],
    ),
]


# ─────────────────────── 汇总 ───────────────────────

RULES: List[CustomRule] = (
    REACT_XSS_RULES
    + REACT_SECURITY_RULES
    + REACT_TEMPLATE_RULES
    + ANGULAR_RULES
)
