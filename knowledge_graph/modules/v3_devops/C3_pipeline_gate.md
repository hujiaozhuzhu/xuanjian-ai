# C3 - Pipeline Gate Engine

## evaluate_gate(request) -> PipelineGateResult

Pure local computation, no network calls.

### Algorithm
1. Iterate findings, classify each by severity rank
2. Check against config thresholds:
   - block_on_critical: CRITICAL blocks
   - block_on_high: HIGH blocks
   - warn_on_medium: MEDIUM warns
   - warn_on_low: LOW warns (if enabled)
3. Check max_findings_threshold
4. Priority: BLOCK > WARN > PASS

### severity_rank()
`"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1`

### Output
- format_gate_output(result, "text"|"json") -> str
- gate_exit_code(result) -> int (0 or 1 for CI scripts)
