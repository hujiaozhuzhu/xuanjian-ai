# Sub-feature A: Go Language Rule Library v2.3.0

> Version: v2.3.0 | Total Rules: 29 | Categories: 8 | File: `fp_sentinel/rules/go/`

## 1. Rule Categories

### 1.1 Command Injection (5 rules)

| Rule ID | Severity | Confidence | Match Scenario |
|---------|----------|------------|----------------|
| `go.injection.exec-cmd` | CRITICAL | 0.75 | `exec.Command(variable/arg)` |
| `go.injection.exec-shell` | CRITICAL | 0.85 | `exec.Command("sh"/"bash"/"cmd"...)` |
| `go.injection.exec-output` | MEDIUM | 0.6 | `.CombinedOutput()` / `.Output()` |
| `go.injection.syscall-exec` | HIGH | 0.75 | `syscall.Exec/ForkExec(...)` |
| `go.injection-os-start-process` | HIGH | 0.70 | `os.StartProcess(...)` |

### 1.2 SQL Injection (5 rules)

| Rule ID | Severity | Confidence | Match Scenario |
|---------|----------|------------|----------------|
| `go.injection.sql-query-fmt` | CRITICAL | 0.85 | `fmt.Sprintf("SELECT...")` |
| `go.injection.sql-query-concat` | CRITICAL | 0.80 | `"SELECT..." + req.Param` |
| `go.injection.sql-string-concat` | CRITICAL | 0.80 | String concat with SQL keywords |
| `go.injection.sql-template-string` | HIGH | 0.70 | template + SQL |
| `go.injection-sql-raw-query` | HIGH | 0.75 | `db.Query(fmt.Sprintf(...))` |

### 1.3 Path Traversal (4 rules)

| Rule ID | Severity | Confidence | Match Scenario |
|---------|----------|------------|----------------|
| `go.path.open-user-input` | HIGH | 0.70 | `os.Open(variable)` / `ioutil.ReadFile(...)` |
| `go.path.join-user-input` | HIGH | 0.65 | `filepath.Join(variable)` |
| `go.path.ioutil-readdir` | MEDIUM | 0.55 | `ioutil.ReadDir(variable)` |
| `go.path.symlink-follow` | MEDIUM | 0.60 | `os.Symlink(input)` |

### 1.4 Hardcoded Secrets (5 rules)

| Rule ID | Severity | Confidence | CWE |
|---------|----------|------------|-----|
| `go.secrets.hardcoded-password` | CRITICAL | 0.75 | CWE-798 |
| `go.secrets.hardcoded-api-key` | CRITICAL | 0.75 | CWE-798 |
| `go.secrets.hardcoded-token` | CRITICAL | 0.75 | CWE-798 |
| `go.secrets.hardcoded-private-key` | CRITICAL | 0.90 | CWE-798 |
| `go.secrets.aws-access-key` | CRITICAL | 0.90 | CWE-798 |

False positive suppression: `os.Getenv` / `viper.Get` / `config.` / `flag.String` patterns

### 1.5 SSRF (3 rules)

| Rule ID | Severity | Confidence | Match Scenario |
|---------|----------|------------|----------------|
| `go.ssrf.http-get-user-input` | HIGH | 0.75 | `http.Get(variable)` |
| `go.ssrf.http-new-request` | HIGH | 0.70 | `http.NewRequest("GET", variable)` |
| `go.ssrf.http-no-timeout` | MEDIUM | 0.60 | `http.Client{...}` (no Timeout field) |

### 1.6 Weak Cryptography (3 rules)

| Rule ID | Severity | Confidence | Match Scenario |
|---------|----------|------------|----------------|
| `go.crypto.weak-hash` | MEDIUM | 0.70 | `md5.Sum`sha1.New` patterns |
| `go.crypto.des-3des` | HIGH | 0.80 | `des.NewCipher`/`NewTripleDESCipher` |
| `go.crypto.static-iv` | MEDIUM | 0.65 | IV as constant byte array |

### 1.7 Template Injection (2 rules)

| Rule ID | Severity | Confidence | Match Scenario |
|---------|----------|------------|----------------|
| `go.template.html-untrusted` | HIGH | 0.70 | `template.Execute(w, userInput)` |
| `go.template.text-template-user` | MEDIUM | 0.55 | text/template + user variable |

### 1.8 Insecure Transport (2 rules)

| Rule ID | Severity | Confidence | Match Scenario |
|---------|----------|------------|----------------|
| `go.transport.insecure-skip-verify` | HIGH | 0.85 | `InsecureSkipVerify: true` |
| `go.transport.http-no-tls` | MEDIUM | 0.50 | `net.Listen("http://...")` |

## 2. Security Guard Groups (GO_SECURITY_GUARD_PATTERNS)

```python
GO_SECURITY_GUARD_PATTERNS = {
    "command_injection": [r"exec\.CommandContext", r"whitelist", r"allowlist", ...],
    "sql_injection":       [r"\$1", r"\?", r":\w+", r"Prepare", ...],
    "path_traversal":     [r"filepath\.Clean", r"filepath\.Abs", r"\.HasPrefix", ...],
    "ssrf":              [r"whitelist", r"allowlist", r"isAllowed", ...],
    "secrets":           [r"os\.Getenv", r"os\.LookupEnv", r"viper\.Get", ...],
    "crypto":            [r"crypto/sha256", r"crypto/sha512", r"cipher\.NewGCM", ...],
}
```

**Suppression mechanism**: If any guard pattern from the category's guard group
appears within 5 lines of the hit line, the finding is suppressed.

## 3. False Positive Rules (GO_FALSE_POSITIVE_RULES)

| Rule ID | Match Pattern | Confidence |
|---------|--------------|------------|
| `go.fp.test-file` | `*_test.go` | 0.85 |
| `go.fp.example-file` | `*example*|*demo*|*sample*` | 0.60 |
| `go.fp.testmain` | `func TestMain(` | 0.70 |
| `go.fp.fake-password` | obvious fake passwords | 0.90 |

## 4. Architecture Specifications

- **Rule class**: `GoRule` (isomorphic to `PythonRule`/`CustomRule`)
- **Rule ID prefix**: `go.`
- **Import**: via `fp_sentinel.rules.go` or direct `fp_sentinel.rules.go.rules`
- **Regex compile cache**: Process-level `_compiled` dict; compile failure cached as None

## 5. Test Coverage

File: `tests/unit/test_go_rules_v230.py`
Coverage classes:
- `TestGoRulesCompile` (5 tests): Regex compilation guard
- `TestGoRuleCategories` (6 tests): Category completeness
- `TestGoRuleMatching` (12 tests): Hit testing
- `TestGoFalsePositiveSuppression` (3 tests): FP suppression
- `TestGoScannerIntegration` (18 tests): Scanner end-to-end
- `TestGoWindowGuard` (3 tests): Window guard

Coverage: **>98%**
