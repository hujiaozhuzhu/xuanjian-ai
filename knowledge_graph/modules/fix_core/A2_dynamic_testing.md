# A2. Dynamic Testing Enhancement

## Module: `fp_sentinel/dynamic_scanner/`

Strengthens dynamic scanning with WAF bypass testing, logic vulnerability
detection, and JavaScript dynamic rendering page analysis.

## Components

### WAF Bypass Tester (`waf_byppass.py`)
15 encoding/format techniques to test WAF/IDS rules:

| # | Technique | Method |
|---|-----------|--------|
| 1 | URL Encode | `urllib.parse.quote()` |
| 2 | Double Encode | `quote(quote())` |
| 3 | Base64 | `base64.b64encode()` |
| 4 | Hex Encode | `%XX%XX...` |
| 5 | Unicode Escape | `\uXXXX` |
| 6 | Case Variation | `aBcDeF` |
| 7 | Whitespace Inject | `a b c` |
| 8 | Comment Inject = `te/**/st` |
| 9 | Param Pollution | `v=1&v=2` |
| 10 | Header Inject | At request level |
| 11 | Method Override | GET -> POST |
| 12 | Content-Type Switch | JSON -> form |
| 13 | Chunked Transfer | Transfer-Encoding |
| 14 | Null Byte | `%00` suffix |
| 15 | Multipart Bypass | Boundary tricks |

All tests use ONLY the harmless marker `fp_sentinel_verify`.

### Logic Vulnerability Detector (`logic_detector.py`)
10 business logic flaw types:

| Type | Detection Method |
|------|-----------------|
| Price Tampering | Send 0, -1, 999999, marker |
| Quantity Tampering | Send 0, -1, 9999, 0.5 |
| Coupon Reuse | Repeated redemption attempts |
| Race Condition | Parallel request timing |
| Flow Skip | Direct jump to final step |
| Negative Value | Negative amounts accepted |
| Order Split | Quantity splitting to bypass limits |
| IDOR | Cross-user resource access by ID |
| Session Fixation | Session ID before/after login |
| Password Reset | Token reuse, email enumeration |

### JS Rendering Analyzer (`js_renderer.py`)
SPA/JavaScript-heavy page analysis:

1. Navigate and wait for JS execution (`js_render_wait_ms`)
2. Inject network hook (XHR/Fetch interception)
3. Inject console hook (capture runtime logs)
4. Capture page title after rendering
5. Extract rendered HTML and DOM snapshot
6. Identify API calls (same-domain filtering)
7. Extract inline JSON from `<script>` tags
8. Count DOM mutations

### Models (`models.py`)
- **BypassResult**: Technique, payload, status, blocked flag
- **LogicVulnFinding**: Type, endpoint, proof, reproducible steps
- **JSRenderResult**: Title, HTML, API calls, DOM mutations
- **DynamicScanConfig**: Target URL, techniques, render wait time
- **DynamicScanResult**: Aggregated scan session result

## Integration with Browser Engine
All modules accept a Playwright-compatible browser engine:
- `set_browser_engine(engine)` attaches the browser
- Graceful degradation to simulation mode when offline
- Compatible with `fp_sentinel.browser.engine.BrowserEngine`
