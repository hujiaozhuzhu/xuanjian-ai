# Sub-feature C: Scanner Manager Update v2.3.0

> Version: v2.3.0 | Files modified: 4 | Files added: 2
> Core: `fp_sentinel/scanners/manager.py` + `fp_sentinel/scanners/go_scanner.py`

## 1. Changes Summary

| File | Change Type | Description |
|------|------------|-------------|
| `models.py` | Modify | Added `GO_SCANNER = "go_scanner"` to `ScanTool` enum |
| `scanners/manager.py` | Modify | Go auto-detection, GoScanner registration, Go selection |
| `scanners/semgrep_scanner.py` | Modify | Go Semgrep ruleset routing |
| `scanners/go_scanner.py` | **New** | Go dedicated scanner with 29 rule patterns |
| `scanners/__init__.py` | Modify | Optional GoScanner export |
| `rules/__init__.py` | Modify | Optional Go rules import |

## 2. Language Detection Enhancements

### Detection Priority (v2.3.0):

```
Single file scan -> Check extension directly:
  .go -> go | .py -> python | .js -> javascript | .ts -> typescript

Project scan -> Build file sniffing:
  go.mod         -> go
  package.json   -> javascript
  tsconfig.json  -> typescript
  requirements.txt / setup.py / pyproject.toml -> python
  pom.xml / build.gradle -> java

Fallback -> Extension count statistics:
  .go count > 0 && >= other -> go
  .js/.ts/.jsx/.tsx count > 0 -> javascript/typescript
```

### New Constants:
```python
GO_EXTENSIONS = {".go}"
```

## 3. Scanner Selection Matrix (Updated)

```python
def _select_scanners(self, language: str) -> List[ScanTool]:
    if language == "go":
        tools = [ScanTool.SEMGREP]
        if ScanTool.GO_SCANNER in self.scanners:
            tools.append(ScanTool.GO_SCANNER)
        return tools
```

Result: `go` -> Semgrep + GoScanner (custom rule engine)

## 4. GoScanner Architecture

### Design Principles:
- **Isomorphic to PythonScanner/JSScanner**: Same prefix-separated implementation
- **Lazy rule import**: Direct `from ..rules.go.rules import (...)` to avoid server init chain
- **Per-rule fault tolerance**: Bad regex skips only itself
- **Context window guard**: 5-line window for category-based guard suppression

### Components:
```
GoScanner
├── _collect_go_files()       # Skips vendor, node_modules, testdata
├── _scan_with_rules()        # 29 rule patterns + FP suppression
│   ├── _get_compiled()       # Process regex cache
│   ├── _suppressed_by_guard() # Context window guard (5 lines)
│   └── _is_false_positive_file() # File-level FP filter (test/example)
├── _scan_secrets()           # Entropy-based secret detection
│   └── _is_obvious_fake_password() # Filter test/demo passwords
└── _calculate_entropy()      # Shannon entropy
```

### Sensitive Patterns (Go-specific):
```python
GO_SENSITIVE_PATTERNS = {
    "aws_access_key":     (r"AKIA[0-9A-Z]{16}", CRITICAL),
    "private_key":        (r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", CRITICAL),
    "google_api_key":     (r"AIza[0-9A-Za-z_-]{35}", HIGH),
    "slack_token":        (r"xox[baprs]-[0-9a-zA-Z-]{10,}", HIGH),
    "github_token":       (r"gh[pousr]_[A-Za-z0-9_]{36,}", HIGH),
    "jwt_token":          (r"eyJ[A-Za-z0-9-_]+...", MEDIUM),
    "password_in_url":    (r"://[^:]+:[^@]+@", HIGH),
}
```

## 5. Semgrep Ruleset Routing

```python
GO_SECURITY_RULESETS = [
    "p/golang",
    "p/owasp-top-ten",
    "p/security-audit",
    "p/secrets",
    "p/r2c-security-audit",
    "p/command-injection",
    "p/insecure-transport",
    "p/sql-injection",
]
```

## 6. Configuration Examples

```yaml
# Enable Go scanner (default: enabled)
scanners:
  go_scanner:
    enabled: true
    check_hardcoded_secrets: true
    window_guard: true

# Disable Go scanner (fall back to Semgrep-only)
scanners:
  go_scanner:
    enabled: false
```

## 7. Test Coverage

File: `tests/unit/test_scanner_manager_go_v230.py` (22 tests)

Coverage:
- `TestGoLanguageDetection` (3 tests): go.mod, .go single, extension count
- `TestGoScannerSelection` (6 tests): scanner selection matrix
- `TestScannerManagerGoConfig` (4 tests): configuration shapes
- `TestGoEndToEndScan` (6 tests): end-to-end scanning
- `TestGoModDetectionPriority` (2 tests): detection priority order

Regression verification: All 145 existing tests in modified areas still pass.

## 8. No Impact Guarantee

The following remain **completely unaffected**:
- Java scanning (FindSecBugs + Semgrep)
- Python scanning (Bandit + Semgrep + PythonScanner)
- JS/TS scanning (Semgrep + JSScanner) - only rules added, no behavior changes
- All existing ScanTool enum values unchanged
- All existing language detection paths unchanged
- Filter pipelines (L1/L2/L3) unchanged
