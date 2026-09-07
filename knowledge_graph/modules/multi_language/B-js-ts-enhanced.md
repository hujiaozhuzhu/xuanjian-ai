# Sub-feature B: JS/TS Rule Enhancement v2.3.0

> Version: v2.3.0 | Added Rules: 27 | Total: 51 -> 78 | File: `fp_sentinel/rules/js/`

## 1. New Rule Categories (v2.3.0)

### 1.1 XSS Enhanced (5 rules)

| Rule ID | Severity | Confidence | Match Scenario |
|---------|----------|------------|----------------|
| `js.xss.svg-onload` | HIGH | 0.80 | `<svg onload=...>`, `<svg onerror=...>` |
| `js.xss.template-literal-xss` | HIGH | 0.75 | `el.innerHTML = \`${location.hash}\`` |
| `js.xss.document-domain` | MEDIUM | 0.60 | `document.domain = ...` |
| `js.xss.iframe-sandbox-escape` | MEDIUM | 0.45 | iframe with dangerous allow-* attrs |
| `js.xss.anchor-target-rel` | MEDIUM | 0.65 | `target="_blank"` without `rel=noopener` |

### 1.2 Prototype Pollution Enhanced (4 rules)

| Rule ID | Severity | Confidence | Match Scenario |
|---------|----------|------------|----------------|
| `js.proto.proto-access` | HIGH | 0.70 | `"__proto__"` string literal usage |
| `js.proto.constructor-prototype` | MEDIUM | 0.60 | `constructor...prototype` property chain |
| `js.proto.json-parse-unsafe` | HIGH | 0.65 | `JSON.parse(input)[prop]` with user input |
| `js.proto.array-prototype-pollution` | MEDIUM | 0.55 | `Array.prototype.method = ...` override |

### 1.3 Injection Enhanced (4 rules)

| Rule ID | Severity | Confidence | Match Scenario |
|---------|----------|------------|----------------|
| `js.injection.indirect-eval` | CRITICAL | 0.85 | `globalThis.eval` / `window.eval` / `self.eval` |
| `js.injection.Reflect-apply` | HIGH | 0.70 | `Reflect.apply(input, ...)` |
| `js.injection.createElement-script` | HIGH | 0.75 | `document.createElement("script")` |
| `js.injection.win-location-js` | HIGH | 0.80 | `location = "javascript:..."` |

### 1.4 Secrets Enhanced (5 rules)

| Rule ID | Severity | Confidence | Match Scenario |
|---------|----------|------------|----------------|
| `js.secrets.console-sensitive` | LOW | 0.40 | `console.log("token...")` / password leak |
| `js.secrets.error-stack-leak` | MEDIUM | 0.50 | `res.send(err.stack)` exposed to client |
| `js.secrets.url-credential-leak` | HIGH | 0.70 | `https://user:pass@host` patterns |
| `js.secrets.google-api-key` | HIGH | 0.70 | `AIza...` (35-char Google API key) |
| `js.secrets.jwt-in-localstorage` | MEDIUM | 0.60 | `localStorage.setItem("token", ...)` |

### 1.5 Unsafe DOM Enhanced (5 rules)

| Rule ID | Severity | Confidence | Match Scenario |
|---------|----------|------------|----------------|
| `js.unsafe.document-referrer-leak` | LOW | 0.40 | `document.referrer` exposure |
| `js.unsafe.name-window-leak` | MEDIUM | 0.50 | `window.name = ...` |
| `js.unsafe.worker-user-input` | HIGH | 0.70 | `new Worker(userURL)` |
| `js.unsafe.document-write-external` | CRITICAL | 0.80 | `document.write("<script...")` |
| `js.unsafe.override-promise` | MEDIUM | 0.45 | Native Promise/Array method override |

### 1.6 TypeScript Specific (4 rules)

| Rule ID | Severity | Confidence | Match Scenario |
|---------|----------|------------|----------------|
| `ts.any-typed-user-input` | LOW | 0.40 | `body: any` / `params: any` typed user input |
| `ts.enum-type-juggling` | LOW | 0.30 | `req.body["key"] as Type` |
| `ts.suppress-implicit-any` | LOW | 0.35 | `// @ts-ignore` / `@ts-nocheck` |
| `ts.non-null-assertion-on-input` | MEDIUM | 0.50 | `req.body!` / `params!` non-null assertion |

## 2. New Guard Groups (JS_SECURITY_GUARD_PATTERNS)

```python
# v2.3.0 new guard groups:
"xss_enhanced":       [r"DOMPurify\.sanitize", r"sanitize\s*\(", r"textContent\s*=", ...],
"prototype_pollution_enhanced": [r"Object\.freeze\s*\(", r"Object\.seal\s*\(", r"Map\s*\(", ...],
"template_injection":  [r"\.escape\s*\(", r"Handlebars\.escapeExpression", ...],
"worker_ssrf":        [r"importScripts\s*\(", r"module\s*:\s*\{", ...],
"ts_typing":          [r"z\.string\(\)", r"class-validator", r"joi\.", r"yup\.", ...],
```

## 3. Architecture Specifications

- **Rule class**: Reuses existing `CustomRule` (isomorphic)
- **Modular organization**: New rules append as separate lists before aggregation
- **Guard group mapping**: `CATEGORY_GUARD_GROUPS` extended for new categories
- **False positive strategy**: Layered (false_positive_indicators inline + window guard + deterministic bypass)

## 4. Test Coverage

File: `tests/unit/test_js_enhanced_v230.py` (23 tests)

Coverage classes:
- `TestEnhancedJSRulesCompile` (4 tests): All v2.3.0 regex compile guard
- `TestEnhancedRuleMatching` (12 tests): Hit testing per category
- `TestJSScannerWithEnhancedRules` (7 tests): Scanner integration

Verification:
- All v2.3.0 rules compile (regex safety)
- Safe file no longer triggers false positives (`JSON.parse(userInput)`)
- Scanner correctly detects `window.eval`, prototype pollution, `constructor["prototype"]`

Coverage: **>96%**
