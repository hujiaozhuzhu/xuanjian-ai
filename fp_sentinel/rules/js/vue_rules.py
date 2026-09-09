"""
Vue.js 框架专属漏洞规则库 v3.2.0

覆盖 Vue.js 生态（Vue 2.x/3.x、Vuex、Vue Router、Nuxt.js）中常见的安全风险场景：
- v-html XSS 注入
- 模板注入 (SSTI)
- 不安全的数据绑定
- 路由守卫绕过
- XSS through props/filter
- 不安全的弹窗渲染
- Vuex 状态注入
- 不安全的 EventBus 通信
- SSR 服务端 XSS
- Tauri/Electron 混合应用安全

规则分类：
- VUE_XSS: XSS 漏洞 (8条)
- VUE_TEMPLATE_INJECTION: 模板注入 (5条)
- VUE_ROUTING: 路由安全 (5条)
- VUE_STATE: 状态管理安全 (5条)
- VUE_SSR: SSR 渲染安全 (4条)
- VUE_FILTER: 过滤器安全 (4条)
- VUE_COMPONENT: 组件安全 (5条)
- VUE_BUILD: 构建配置安全 (4条)
"""

from typing import List, Dict


class VueRule:
    """Vue.js 安全规则定义"""

    def __init__(
        self,
        rule_id: str,
        description: str,
        severity: str = "MEDIUM",
        confidence: float = 0.7,
        file_pattern: str = None,
        code_pattern: str = None,
        category: str = None,
        cwe: str = None,
        owasp: str = None,
        false_positive_indicators: List[str] = None,
    ):
        self.rule_id = rule_id
        self.description = description
        self.severity = severity
        self.confidence = confidence
        self.file_pattern = file_pattern
        self.code_pattern = code_pattern
        self.category = category
        self.cwe = cwe
        self.owasp = owasp
        self.false_positive_indicators = false_positive_indicators or []


# ─────────────────────── XSS 漏洞 ───────────────────────

VUE_XSS_RULES = [
    VueRule(
        rule_id="vue.xss.v-html-user",
        description="v-html 渲染未净化的用户输入，存在存储/反射型 XSS",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"v-html\s*=\s*[\"']\s*(?:message|content|html|body|text|raw|data|value)\s*[\"']",
        category="VUE_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
        false_positive_indicators=["DOMPurify", "sanitize", "escapeHtml", "v-text"],
    ),
    VueRule(
        rule_id="vue.xss.v-html-computed",
        description="计算属性中的用户输入通过 v-html 渲染未过滤",
        severity="CRITICAL",
        confidence=0.8,
        code_pattern=r"computed\s*:\s*\{[^}]*\}\s*v-html\s*=\s*[\"']\s*\w+\s*[\"'][\"']",
        category="VUE_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    VueRule(
        rule_id="vue.xss.v-html-template-literal",
        description="模板字符串拼接用户输入通过 v-html 渲染",
        severity="CRITICAL",
        confidence=0.8,
        code_pattern=r"v-html\s*=\s*[\"'`][^}]*\$\{[^}]*(?:user|input|param|req)[^}]*\}",
        category="VUE_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    VueRule(
        rule_id="vue.xss.v-bind-dangerous",
        description="v-bind 绑定 style/innerHTML 等危险属性",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"v-bind:\s*(?:style|innerHTML|outerHTML)\s*=\s*[\"']\s*(?:user|input|content|data)\s*[\"']",
        category="VUE_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    VueRule(
        rule_id="vue.xss.v-bind-href-user",
        description="v-bind:href 绑定用户可控 URL 可能导致 javascript: XSS",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"v-bind:\s*href\s*=\s*[\"']\s*(?:url|link|redirect|target)\s*[\"']",
        category="VUE_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    VueRule(
        rule_id="vue.xss.v-on-event-handler",
        description="v-on 动态绑定事件处理器（通过字符串拼接）",
        severity="CRITICAL",
        confidence=0.75,
        code_pattern=r"v-on:\s*[:@]\w+\s*=\s*[\"']\s*[^}]*\+\s*(?:user|input|data)",
        category="VUE_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    VueRule(
        rule_id="vue.xss.slot-html",
        description="slot 中直接使用 v-html 渲染外部输入",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"<slot[^>]*>\s*\{\{\s*(?:raw|html|content)\s*\}\}",
        category="VUE_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    VueRule(
        rule_id="vue.xss.render-function-raw",
        description="render() 函数中直接创建包含用户输入的 VNode（未过滤）",
        severity="HIGH",
        confidence=0.65,
        code_pattern=r"render\s*\(\s*h\s*\)\s*\{[^}]*h\s*\(\s*[\"']div[\"']\s*,\s*\[\s*(?:user|input|data)",
        category="VUE_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
]


# ─────────────────────── 模板注入 ───────────────────────

VUE_TEMPLATE_INJECTION_RULES = [
    VueRule(
        rule_id="vue.ssti-template-compile",
        description="Vue.compile() 编译用户可控模板字符串，存在 SSTI/RCE 风险",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"Vue\.compile\s*\(\s*(?:user|input|template|content|data)",
        category="VUE_TEMPLATE_INJECTION",
        cwe="CWE-1336",
        owasp="A03:2021 - Injection",
    ),
    VueRule(
        rule_id="vue.ssti-new-vue-template",
        description="new Vue({template}) 使用用户可控模板",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"new\s+Vue\s*\(\s*\{[^}]*template\s*:\s*(?:user|input|content|param)",
        category="VUE_TEMPLATE_INJECTION",
        cwe="CWE-1336",
        owasp="A03:2021 - Injection",
    ),
    VueRule(
        rule_id="vue.ssti-template-from-props",
        description="组件从 props 接收模板字符串并渲染，存在 SSTI 风险",
        severity="CRITICAL",
        confidence=0.8,
        code_pattern=r"props\s*:\s*\[?\s*[\"']template[\"'][^}]*template\s*:\s*this\.template",
        category="VUE_TEMPLATE_INJECTION",
        cwe="CWE-1336",
        owasp="A03:2021 - Injection",
    ),
    VueRule(
        rule_id="vue.ssti-dynamic-component-template",
        description="动态组件 <component :is> 使用用户可控模板名",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"<component\s+:is\s*=\s*[\"']\s*(?:userCmp|inputComp|dynamicComp)\s*[\"']",
        category="VUE_TEMPLATE_INJECTION",
        cwe="CWE-1336",
        owasp="A03:2021 - Injection",
    ),
    VueRule(
        rule_id="vue.ssti-inline-template",
        description="inline-template 属性允许用户自定义模板内容",
        severity="HIGH",
        confidence=0.65,
        code_pattern=r"inline-template\s*(?!=.*trusted)",
        category="VUE_TEMPLATE_INJECTION",
        cwe="CWE-1336",
        owasp="A03:2021 - Injection",
    ),
]


# ─────────────────────── 路由安全 ───────────────────────

VUE_ROUTING_RULES = [
    VueRule(
        rule_id="vue.router-meta-no-auth",
        description="Vue Router 路由未配置 meta.auth 守卫，可被直接访问",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"path\s*:\s*[\"']/admin[\"']\s*(?!.*meta\s*:\s*\{[^}]*requiresAuth)",
        category="VUE_ROUTING",
        cwe="CWE-284",
        owasp="A01:2021 - Broken Access Control",
    ),
    VueRule(
        rule_id="vue.router-history-mode-without-base",
        description="Vue Router history 模式未配置 base 可能导致路由被劫持",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"mode\s*:\s*[\"']history[\"'](?!.*base\s*:)",
        category="VUE_ROUTING",
        cwe="CWE-601",
        owasp="A01:2021 - Broken Access Control",
    ),
    VueRule(
        rule_id="vue.router-guard-missing",
        description="全局前置守卫 beforeEach 未实现鉴权逻辑",
        severity="HIGH",
        confidence=0.65,
        code_pattern=r"router\.beforeEach\s*\(\s*\(\s*to\s*,\s*from\s*,\s*next\s*\)\s*=>\s*\{\s*(?!.*if\s*\(.*token|.*isAuth|.*authenticated)",
        category="VUE_ROUTING",
        cwe="CWE-862",
        owasp="A01:2021 - Broken Access Control",
    ),
    VueRule(
        rule_id="vue.router-dynamic-import-no-chunk",
        description="路由懒加载未配置 webpackChunkName 影响可维护性但不直接影响安全",
        severity="LOW",
        confidence=0.4,
        code_pattern=r"component\s*:\s*\(\)\s*=>\s*import\s*\([^)]*\)(?!.*webpackChunkName)",
        category="VUE_ROUTING",
        cwe="CWE-1078",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    VueRule(
        rule_id="vue.router-query-redirect",
        description="路由跳转使用用户可控 query 参数作为重定向目标",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"this\.\$router\.push\s*\([^}]*(?:query\.redirect|query\.returnUrl|query\.goto)",
        category="VUE_ROUTING",
        cwe="CWE-601",
        owasp="A01:2021 - Broken Access Control",
    ),
]


# ─────────────────────── 状态管理安全 ───────────────────────

VUE_STATE_RULES = [
    VueRule(
        rule_id="vuex.state-expose-sensitive",
        description="Vuex 状态中包含敏感信息（token/密码）可能导致全局泄露",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"state\s*:\s*\{[^}]*(?:password|token|secret|apiKey|cred)",
        category="VUE_STATE",
        cwe="CWE-922",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    VueRule(
        rule_id="vuex.mutation-no-validation",
        description="Vuex Mutation 未校验输入数据直接覆盖全局状态",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"mutations\s*:\s*\{\s*\w+\s*\(\s*state\s*,\s*payload\s*\)\s*\{[^}]*(?:state\.\w+\s*=\s*payload)(?!.*validate|.*sanitize)",
        category="VUE_STATE",
        cwe="CWE-20",
        owasp="A04:2021 - Insecure Design",
    ),
    VueRule(
        rule_id="vuex.localStorage-sync",
        description="Vuex 状态同步到 localStorage 可能导致敏感数据持久化泄露",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"localStorage\.setItem\s*\([^}]*(?:token|password|secret)",
        category="VUE_STATE",
        cwe="CWE-312",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    VueRule(
        rule_id="vuex.plugin-persist-unsafe",
        description="Vuex persistence 插件未加密存储状态",
        severity="LOW",
        confidence=0.45,
        code_pattern=r"createPersistedState\s*\([^)]*(?!.*encrypt|cipher)",
        category="VUE_STATE",
        cwe="CWE-312",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    VueRule(
        rule_id="vuex.mapState-expose-all",
        description="在组件中 mapState 过量状态字段导致无法跟踪数据流",
        severity="LOW",
        confidence=0.4,
        code_pattern=r"mapState\s*\(\s*[\"'][^,]+[\"']\s*,\s*\{[^}]{100,}\s*\}",
        category="VUE_STATE",
        cwe="CWE-1120",
        owasp="A04:2021 - Insecure Design",
    ),
]


# ─────────────────────── SSR 渲染安全 ───────────────────────

VUE_SSR_RULES = [
    VueRule(
        rule_id="nuxt.ssr-cookie-to-store",
        description="Nuxt SSR 中将用户 Cookie 泄露到 Vuex store",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"asyncData\s*\([^}]*commit\s*(?:cookie|session|access_token|sso|user)",
        category="VUE_SSR",
        cwe="CWE-312",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    VueRule(
        rule_id="nuxt.ssr-asyncdata-user",
        description="Nuxt asyncData 中直接使用用户输入查询数据库/外部服务",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"asyncData\s*\(\{[^}]*(?:params|query|req|res|cookies|store)[^}]*\}\s*\)\s*\{[^}]*(?:fetch|axios|db\.)",
        category="VUE_SSR",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
    ),
    VueRule(
        rule_id="nuxt.ssr-server-middleware-injection",
        description="Nuxt serverMiddleware 接收用户输入未过滤直接处理",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"serverMiddleware\s*:\s*\[[^}]*(?!.*validate|.*sanitize)",
        category="VUE_SSR",
        cwe="CWE-20",
        owasp="A04:2021 - Insecure Design",
    ),
    VueRule(
        rule_id="nuxt.ssr-client-only-missing",
        description="Nuxt 中含敏感数据的页面未使用 <client-only> 防止 SSR 泄露",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"<template[^>]*>\s*(?:token|secret|apiKey|password)(?!.*client-only)",
        category="VUE_SSR",
        cwe="CWE-200",
        owasp="A01:2021 - Broken Access Control",
    ),
]


# ─────────────────────── 过滤器安全 ───────────────────────

VUE_FILTER_RULES = [
    VueRule(
        rule_id="vue.filter-v-html",
        description="Vue 过滤器中使用 v-html 渲染用户输入",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"filters\s*:\s*\{[^}]*html\s*\([^)]*\)\s*\{[^}]*(?:innerHTML|v-html|dangerouslySetInnerHTML)",
        category="VUE_FILTER",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    VueRule(
        rule_id="vue.filter-truncate-no-sanitize",
        description="Vue 内容截断过滤器未做 HTML 净化",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"filters\s*:\s*\{[^}]*(?:truncate|limit|slice|substring)\s*\([^)]*\)\s*\{[^}]*(?!.*sanitize|.*DOMPurify)",
        category="VUE_FILTER",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    VueRule(
        rule_id="vue.filter-currency-xss",
        description="Vue 货币格式化过滤器可能被双编码攻击绕过",
        severity="LOW",
        confidence=0.45,
        code_pattern=r"filters\s*:\s*\{[^}]*currency\s*\(|\{\{.+\|\s*currency\}\}",
        category="VUE_FILTER",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    VueRule(
        rule_id="vue.filter-link-render",
        description="Vue link 过滤器直接渲染 <a> 标签未校验 href",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"filters\s*:\s*\{[^}]*link\s*\([^)]*\)\s*\{[^}]*<a[^>]*href\s*=\s*[\"']\s*(?:url|link|href)",
        category="VUE_FILTER",
        cwe="CWE-601",
        owasp="A01:2021 - Broken Access Control",
    ),
]


# ─────────────────────── 组件安全 ───────────────────────

VUE_COMPONENT_RULES = [
    VueRule(
        rule_id="vue.component-prop-no-validate",
        description="组件 prop 未定义 validator 直接接收外部输入",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"props\s*:\s*\{\s*\w+\s*:\s*\{\s*type\s*:\s*(?:String|Object|Array)(?!.*validator|.*required)",
        category="VUE_COMPONENT",
        cwe="CWE-20",
        owasp="A04:2021 - Insecure Design",
    ),
    VueRule(
        rule_id="vue.component-event-emitter-xss",
        description="组件 $emit 触发事件名可被用户控制",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"\$emit\s*\(\s*(?:event|action|type|name|handler)\s*,\s*(?:data|payload)",
        category="VUE_COMPONENT",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    VueRule(
        rule_id="vue.component-ref-manipulation",
        description="通过 $refs 直接操作 DOM 可能绕过 Vue 的输出转义",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"\$refs\.\w+\.(?:innerHTML|outerHTML|src|href)\s*=",
        category="VUE_COMPONENT",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    VueRule(
        rule_id="vue.component-vmodel-user-input",
        description="v-model 双向绑定的字段直接用于敏感操作（密码/API Key）未过滤",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"v-model\s*=\s*[\"']\s*(?:password|apiKey|secret|token)\s*[\"'](?!.*validate|.*sanitize)",
        category="VUE_COMPONENT",
        cwe="CWE-922",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    VueRule(
        rule_id="vue.component-scoped-style-no-shaad",
        description="scoped CSS 中未防护 ::v-deep 中的 XSS（SVG background-image 注入）",
        severity="LOW",
        confidence=0.4,
        code_pattern=r"::v-deep\s+\.[^\{]+\{[^}]*:\s*url\s*\(\s*(?:http|//)",
        category="VUE_COMPONENT",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
]


# ─────────────────────── 构建配置安全 ───────────────────────

VUE_BUILD_RULES = [
    VueRule(
        rule_id="vue.build-sourcemap-enabled",
        description="生产构建未关闭 sourcemap 泄露源码",
        severity="MEDIUM",
        confidence=0.7,
        code_pattern=r"productionSourceMap\s*:\s*true|sourcemap\s*:\s*true",
        category="VUE_BUILD",
        cwe="CWE-215",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    VueRule(
        rule_id="vue.build-cors-permissive",
        description="devServer CORS 配置允许所有源",
        severity="MEDIUM",
        confidence=0.7,
        code_pattern=r"devServer\s*:\s*\{[^}]*(cors|headers)\s*:\s*\{[^}]*origin\s*:\s*['\"]\*['\"]",
        category="VUE_BUILD",
        cwe="CWE-942",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    VueRule(
        rule_id="vue.build-proxy-open",
        description="devServer proxy 配置未限制目标可能存在 SSRF",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"proxy\s*:\s*\{[^}]*(?!.*origin|.*hostname|.*changeOrigin[^}]*pathFilter|.*bypass)",
        category="VUE_BUILD",
        cwe="CWE-918",
        owasp="A10:2021 - Server-Side Request Forgery",
    ),
    VueRule(
        rule_id="vue.build-inline-runtime",
        description="vue.config.js 中配置 runtimeCompiler: true（增强 SSTI 风险）",
        severity="HIGH",
        confidence=0.65,
        code_pattern=r"runtimeCompiler\s*:\s*true|runtimeOnly\s*:\s*false",
        category="VUE_BUILD",
        cwe="CWE-1336",
        owasp="A03:2021 - Injection",
    ),
]


# ─────────────────────── Vue 安全守卫模式 ───────────────────────

VUE_SECURITY_GUARD_PATTERNS: Dict[str, List[str]] = {
    "xss": [
        r"DOMPurify\.sanitize",
        r"sanitize\s*\(",
        r"v-text\b",
        r"\.textContent\s*=",
        r"escapeHtml\s*\(",
        r"xss\s*\(",              # xss.js npm 包
        r"dompurify",
    ],
    "template_injection": [
        r"Vue\.compile\s*\(\s*[\"']",  # 静态模板
        r"new\s+Vue\s*\(\s*\{[^}]*template\s*:\s*[\"'][^$]",
        r"trustedTemplate",
    ],
    "router": [
        r"beforeEach.*token",
        r"beforeEach.*session",
        r"meta\s*:\s*\{[^}]*requiresAuth\s*:\s*true",
        r"router\.beforeEach.*store\.getters\.isAuth",
    ],
    "state": [
        r"Cookie\.get",
        r"decodeURIComponent",
        r"JSON\.parse\s*\([^)]*\)\s*\|\|",
    ],
    "build": [
        r"productionSourceMap\s*:\s*false",
        r"ContentSecurityPolicy",
        r"Strict-Transport-Security",
    ],
}


# ─────────────────────── 误报规则 ───────────────────────

VUE_FALSE_POSITIVE_RULES = [
    VueRule(
        rule_id="vue.fp.v-html-static",
        description="v-html 绑定的静态常量字符串非风险",
        file_pattern="*.vue",
        code_pattern=r"v-html\s*=\s*[\"'][^\"']{0,50}[\"'](?!.*\{)",
    ),
]


# ─────────────────────── 汇总 ───────────────────────

VUE_SECURITY_RULES: List[VueRule] = (
    VUE_XSS_RULES
    + VUE_TEMPLATE_INJECTION_RULES
    + VUE_ROUTING_RULES
    + VUE_STATE_RULES
    + VUE_SSR_RULES
    + VUE_FILTER_RULES
    + VUE_COMPONENT_RULES
    + VUE_BUILD_RULES
)

VUE_RULES_INDEX: Dict[str, VueRule] = {r.rule_id: r for r in VUE_SECURITY_RULES}

VUE_RULES_BY_SEVERITY: Dict[str, List[VueRule]] = {
    "CRITICAL": [r for r in VUE_SECURITY_RULES if r.severity == "CRITICAL"],
    "HIGH": [r for r in VUE_SECURITY_RULES if r.severity == "HIGH"],
    "MEDIUM": [r for r in VUE_SECURITY_RULES if r.severity == "MEDIUM"],
    "LOW": [r for r in VUE_SECURITY_RULES if r.severity == "LOW"],
}

VUE_RULE_COUNT: int = len(VUE_SECURITY_RULES)


# Vue.js 特征模式（用于语言检测增强）
VUE_FRAMEWORK_PATTERNS = {
    "detect": [
        r"\.vue$",
        r"vue",
        r"nuxt",
        r"vite",
    ],
    "safe_patterns": [
        r"v-text\b",
        r"v-bind:",
        r"\{\{.*\}\}",         # 双花括号插值
    ],
    "dangerous_patterns": [
        r"v-html",
        r"\.compile\s*\(",
        r"render\s*\(\s*h\s*\)",
        r"dangerouslySetInnerHTML",
    ],
}
