# A4. Harmless Auto-Verification Engine

## Module: `fp_sentinel/attack/harmless_verifier/`

Automatically verifies vulnerability harm using only harmless markers.
Produces complete reproducible verification steps with remediation guidance.

## Core Principle

All verification uses ONLY the marker string `fp_sentinel_verify`.
No real attack payloads. No code modification. No network requests.

## Components

### HarmlessVerifier (`verifier.py`)

Multi-strategy verification engine:

1. **Sink Detection** (pattern matching in source code):
   - 10 vulnerability categories with 40+ regex patterns
   - SQL injection, Command injection, XSS, Path traversal, SSRF
   - Deserialization (pickle/yaml/Java native/Fastjson/Jackson)
   - SSTI, XXE, Weak crypto, Hardcoded secrets

2. **Input Tracing** (finding user input in same file):
   - Flask: request.args/form/data/json
   - Django: request.GET/POST
   - Node.js: req.query/body/params
   - Generic: process.env, window.location, input()

3. **Confidence Classification**:
   - HIGH: Both sink AND input traced
   - MEDIUM: Sink found, input not traced
   - LOW: Sink not found
   - UNCERTAIN: Source unreadable or error

### Step Generator (`step_generator.py`)

Generates reproducible verification steps:

```
Step 1: Locate vulnerable code (file, line, sink pattern)
Step 2: Trace input to sink (identify user-controllable data flow)
Step 3: Craft harmless marker input (show marker is safe)
Step 4: Confirm fix (re-run marker after remediation)
Step 5: Recommended fix (specific to vulnerability type)
```

Remediation hints cover all 10+ vulnerability categories.

## Verification Flow

```
Finding[id, rule_id, file_path, line]
    |
    v
Read source code (read-only)
    |
    v
Detect sink pattern (regex matching)
    |
    v
Trace user input (input pattern matching)
    |
    v
Generate verification steps + marker PoC
    |
    v
Output HarmlessVerifyResult[confidence, evidence, steps, remediation]
```

## Batch Processing

```python
verifier = HarmlessVerifier(project_root=".")
report = verifier.verify_findings(findings)
# report.summary() -> {total, verified, simulated, manual, errors}
```

## Sink Pattern Database

| Category | # Patterns | Example |
|----------|-----------|---------|
| SQL Injection | 5 | `execute(... + ...)` |
| Command Injection | 5 | `os.system(...)`, `eval(...)` |
| XSS | 4 | `innerHTML =`, `document.write(...)` |
| Path Traversal | 3 | `open(... + ...)` |
| SSRF | 2 | `requests.get(... + ...)` |
| Deserialization | 6 | `pickle.loads(...)`, `ObjectInputStream` |
| SSTI | 2 | `Template(...).render(...)` |
| XXE | 2 | `lxml`, `etree` |
| Weak Crypto | 3 | `md5(...)`, `DES`, `RC4` |
| Hardcoded Secrets | 2 | `password = "..."` |

## Output Format

```json
{
  "finding_id": "f1",
  "rule_id": "sql-injection",
  "file_path": "app.py",
  "line": 42,
  "confidence": "high",
  "is_harmless": true,
  "evidence": "Sink pattern '...' found near input '...'",
  "reproducible_steps": [
    "1. Open file: app.py at line 42",
    "2. Identify dangerous function call (sink)",
    "3. Trace user input to the sink",
    "4. Send harmless marker as input",
    "5. Confirm vulnerability exists",
    "6. Apply parameterized queries fix"
  ],
  "remediation_hint": "Use parameterized queries..."
}
```
