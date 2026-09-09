# A1 - Benchmark Data Model

## Data Structures

### Industry Enum
11 supported industries mapped to string values for serialization.

### BenchmarkDataset
Complete per-industry dataset containing:
- `vuln_distribution: List[VulnTypeStats]` - Category-level statistics
- `repair_cycle: RepairCycle` - Avg repair days by severity
- `top_vulnerabilities: List[TopVulnerability]` - TOP 10 with compliance refs
- `compliance_requirements: List[ComplianceRequirement]` - Regulatory mappings
- `industry_scenarios: List[IndustryScenario]` - Industry-specific attack scenarios
- `metadata: BenchmarkMetadata` - Source, confidence, sample period

### Gap Analysis Models
- `GapSeverity` enum: critical/high/medium/on_par/ahead
- `GapItem`: Single metric comparison (industry vs enterprise)
- `CategoryGap`: Group of items per dimension
- `GapAnalysisReport`: Full report with score, roadmap, highlights

## Built-in Datasets
Each industry has ~10 distribution entries, 5-7 compliance requirements, and 2 realistic scenarios. All data references public sources (CNVD, NVD, GB/T standards).
