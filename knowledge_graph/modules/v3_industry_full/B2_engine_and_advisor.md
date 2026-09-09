# B2 - Benchmark Engine & Repair Advisor

## Benchmark Engine
Compares enterprise security metrics against industry benchmarks.

### Gap Analysis Dimensions
1. **Vulnerability Density** - Enterprise findings per scan vs industry average
2. **Repair Speed** - Avg repair days vs industry SLA
3. **Compliance** - Compliance score vs 80% industry target
4. **Coverage** - How many industry risk categories are covered

### Gap Classification
Gap ratios are classified into 5 severity levels based on configurable thresholds. The `_classify_gap` function supports both "lower is better" (repair days) and "higher is better" (compliance score) modes.

## Repair Advisor
Generates prioritized repair suggestions matched to:
- Vulnerability category
- Severity level
- CWE identifier (for compliance enrichment)
- Industry context (for industry-specific templates)

### Built-in Templates
12 remediation templates covering: SQL injection, XSS, access control, crypto failures, insecure design, vulnerable components, data leakage, auth failures, misconfiguration, business logic, DoS.

### Industry-Specific Templates
Special handling for critical scenarios: ICS/SCADA RCE, energy SCADA hack, securities flash crash.
