# D4 - 行业修复建议生成逻辑

> **对应文件**: `fp_sentinel/industry_benchmark/repair_advisor.py`
> **版本**: v3.0.0
> **核心类**: `RepairAdvisor`
> **修复模板总数**: 12 个通用 + 3 个行业特定

---

## 1. 修复建议架构

### 1.1 设计目标

基于发现的漏洞类型、严重度、CWE 和所属行业，生成针对性的修复建议。支持通用修复模板和行业特定场景模板。

### 1.2 修复建议数据模型

```python
class RepairSuggestion(BaseModel):
    suggestion_id: str              # 建议唯一ID (格式: sug-{uuid8})
    title: str                      # 建议标题
    description: str                # 建议描述
    target_categories: List[str]    # 目标漏洞类别
    target_severities: List[str]    # 目标严重度级别
    effort: str                     # 工作量: low/medium/high
    priority: int                   # 优先级 1-10 (1最高)
    compliance_refs: List[str]      # 合规引用
    industry_specific: bool         # 是否行业特定
    code_example: str               # 代码示例
    reference_links: List[str]      # 参考链接
```

### 1.3 引擎结构

```
┌────────────────────────────────────────────────────────┐
│                     RepairAdvisor                       │
├────────────────────────────────────────────────────────┤
│ - _benchmark: Optional[BenchmarkDataset]                 │
├────────────────────────────────────────────────────────┤
│ + set_benchmark(benchmark)                              │
│ + suggest_for_finding(category, severity, cwe, industry)│
│ + suggest_for_industry(industry)                        │
│ + suggest_for_scenarios(industry)                       │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│              内置模板数据                                │
├────────────────────────────────────────────────────────┤
│ _REMEDIATION_TEMPLATES: Dict[str, RepairSuggestion]     │
│   通用模板: SQL_INJECTION, XSS, BROKEN_ACCESS_CONTROL,  │
│            CRYPTO_FAILURE, INSECURE_DESIGN,              │
│            VULNERABLE_COMPONENTS, DATA_LEAKAGE,         │
│            AUTH_FAILURE, MISCONFIGURATION,               │
│            BUSINESS_LOGIC, DOS                          │
├────────────────────────────────────────────────────────┤
│ _INDUSTRY_TEMPLATES: Dict[str, List[RepairSuggestion]]  │
│   行业模板: ICS_RCE, NRG_SCADA_HACK, SEC_FLASH_CRASH   │
└────────────────────────────────────────────────────────┘
```

---

## 2. 12 个通用修复模板

### 2.1 模板清单

| # | 模板Key | 标题 | 目标类别 | 严重度 | 工作量 | 优先级 |
|---|---------|------|---------|--------|--------|:---:|
| 1 | `SQL_INJECTION` | 参数化查询 | INJECTION | CRITICAL, HIGH | medium | 1 |
| 2 | `XSS` | 上下文感知输出编码 | XSS | HIGH, MEDIUM | medium | 2 |
| 3 | `BROKEN_ACCESS_CONTROL` | 资源级访问控制 | BROKEN_ACCESS_CONTROL | CRITICAL, HIGH | high | 1 |
| 4 | `CRYPTO_FAILURE` | 强加密算法(AES-256, SHA-256+) | CRYPTO_FAILURE | HIGH, CRITICAL | medium | 2 |
| 5 | `INSECURE_DESIGN` | 安全纵深设计 | INSECURE_DESIGN | MEDIUM, HIGH | high | 3 |
| 6 | `VULNERABLE_COMPONENTS` | 升级组件+SCA扫描 | VULNERABLE_COMPONENTS | HIGH, CRITICAL | medium | 1 |
| 7 | `DATA_LEAKAGE` | 静态和传输加密 | DATA_LEAKAGE | CRITICAL, HIGH | high | 1 |
| 8 | `AUTH_FAILURE` | MFA+安全会话管理 | AUTH_FAILURE | HIGH, CRITICAL | high | 1 |
| 9 | `MISCONFIGURATION` | 加固安全配置 | MISCONFIGURATION | MEDIUM, HIGH | low | 2 |
| 10 | `BUSINESS_LOGIC` | 业务逻辑验证+完整性 | BUSINESS_LOGIC | CRITICAL | high | 1 |
| 11 | `DOS` | 限流+DDoS防护 | DOS, AVAILABILITY | HIGH, CRITICAL | medium | 1 |
| 12 | *(DOS覆盖AVAILABILITY)* | - | - | - | - | - |

### 2.2 模板匹配逻辑

```python
def _match_template(template, category, severity):
    # 类别匹配: 模板的 target_categories 为空 或 包含该 category
    category_match = (
        not template.target_categories or category in template.target_categories
    )
    # 严重度匹配: 模板的 target_severities 为空 或 包含该 severity
    severity_match = (
        not template.target_severities or severity in template.target_severities
    )
    return category_match and severity_match
```

---

## 3. 3 个行业特定模板

| 模板Key | 场景 | 标题 | 目标严重度 | 工作量 | 优先级 |
|---------|------|------|-----------|--------|:---:|
| `ICS_RCE` | 工业控制 RCE | OT/IT 网络工业防火墙隔离 | CRITICAL | high | 1 |
| `NRG_SCADA_HACK` | 能源 SCADA 入侵 | 电力 SCADA 专用 IDS | CRITICAL | high | 1 |
| `SEC_FLASH_CRASH` | 证券闪电崩盘 | 熔断机制+延迟均等化 | CRITICAL | high | 1 |

这些模板通过 `suggest_for_industry()` 方法根据行业场景自动关联。

---

## 4. 修复建议生成流程

### 4.1 单发现建议 (suggest_for_finding)

```
suggest_for_finding(category, severity, cwe, industry)
       │
       ├─ 遍历 _REMEDIATION_TEMPLATES
       │    ↓
       │  匹配 target_categories 包含 category
       │  匹配 target_severities 包含 severity
       │    ↓
       │  复制模板 + 生成唯一 suggestion_id
       │    ↓
       │  合规丰富: 若 cwe 和 _benchmark 都提供
       │    └─ _build_compliance_map() → CWE 映射到合规引用
       │    ↓
       │  设置 sug.compliance_refs
       │
       └─ 返回按 priority 排序的建议列表
```

### 4.2 行业级建议 (suggest_for_industry)

```
suggest_for_industry(industry)
       │
       ├─ 取行业基准 (self._benchmark 或 build_benchmark_dataset)
       │
       ├─ 基于 top_vulnerabilities 前5条生成发现级建议
       │    └─ 循环调用 suggest_for_finding
       │    └─ 去重 (seen_ids)
       │
       ├─ 遍历行业场景 (bench.industry_scenarios)
       │    └─ 匹配 _INDUSTRY_TEMPLATES 中相同 scenario_id
       │    └─ 复制模板 + 合规引用自动提取
       │    └─ 去重
       │
       └─ 返回按 priority 排序的全部建议
```

### 4.3 场景级建议 (suggest_for_scenarios)

```
suggest_for_scenarios(industry)
       │
       ├─ 取行业基准
       ├─ 遍历每个行业场景
       │    └─ _INDUSTRY_TEMPLATES[scenario.scenario_id]
       │    └─ 复制模板 + 唯一ID
       │
       └─ Dict[scenario_id, List[RepairSuggestion]]
```

### 4.4 多发现建议 (suggest_repairs_for_findings)

这是便捷函数，接收多个发现的列表，统一生成去重排序的建议。

```python
def suggest_repairs_for_findings(
    findings: List[Tuple[str, str, Optional str]],
    industry: Industry,
    benchmark: Optional[BenchmarkDataset] = None,
) -> List[RepairSuggestion]:
    # findings 格式: [(category, severity, cwe?), ...]
```

---

## 5. 合规引用自动丰富

### 5.1 合规映射构建

```python
def _build_compliance_map(requirements: List[ComplianceRequirement]) -> Dict[str, List[str]]:
    """构建 CWE -> 合规引用编号 的映射"""
    cwe_to_compliance: Dict[str, List[str]] = {}
    for req in requirements:
        for cwe in req.related_cwes:
            cwe_to_compliance.setdefault(cwe, []).append(req.ref_id)
    return cwe_to_compliance
```

### 5.2 丰富机制

- 当 `cwe` 参数非空 且 `_benchmark` 已设置时触发
- 从基准数据的 `compliance_requirements` 构建 CWE→合规映射
- 将匹配的合规引用自动附加到建议的 `compliance_refs`

**示例**: 对于 `CWE-89` (SQL注入) + `Industry.INTERNET`:
```python
compliance_map = {
    "CWE-284": ["GB/T 22239-2019 三级-8.1.3"],
    "CWE-89": ["GB/T 22239-2019 三级-8.1.3"],
    "CWE-200": ["个人信息保护法-第51条", "数据安全法-第27条"],
    "CWE-327": ["个人信息保护法-第51条"],
}
# 对 CWE-89 的修复建议自动附加: ["GB/T 22239-2019 三级-8.1.3"]
```

---

## 6. 优先级体系

### 6.1 优先级分布

| 优先级 | 含义 | 适用模板 |
|--------|------|---------|
| 1 | 最高优先 | SQL注入、越权、组件漏洞、数据泄露、认证失效、业务逻辑、DoS |
| 2 | 高优先 | XSS、加密失效、配置错误 |
| 3 | 中优先 | 不安全设计 |

### 6.2 工作量评估

| 工作量 | 含义 | 示例模板 |
|--------|------|---------|
| `low` | < 1天 | 配置加固 |
| `medium` | 1-3天 | SQL注入修复、XSS修复、组件升级、DoS防护 |
| `high` | > 3天 | 访问控制重构、加密体系改造、数据加密、认证改造、业务逻辑验证 |

---

## 7. 代码示例

### 7.1 单发现建议

```python
from fp_sentinel.industry_benchmark import RepairAdvisor
from fp_sentinel.industry_benchmark.models import Industry

advisor = RepairAdvisor()
suggestions = advisor.suggest_for_finding(
    category="INJECTION",
    severity="CRITICAL",
    cwe="CWE-89",
    industry=Industry.INTERNET
)
# 返回: [RepairSuggestion(priority=1, title="Use parameterized queries...")]
```

### 7.2 行业级批量建议

```python
from fp_sentinel.industry_benchmark import RepairAdvisor
from fp_sentinel.industry_benchmark.models import Industry

advisor = RepairAdvisor()
suggestions = advisor.suggest_for_industry(Industry.SECURITIES)
# 返回按 priority 排序的全部建议 (含行业特定模板匹配)
```

### 7.3 多发现统一建议

```python
from fp_sentinel.industry_benchmark import suggest_repairs_for_findings
from fp_sentinel.industry_benchmark.models import Industry

findings = [
    ("INJECTION", "CRITICAL", "CWE-89"),
    ("XSS", "HIGH", "CWE-79"),
    ("BROKEN_ACCESS_CONTROL", "HIGH", "CWE-284"),
]
suggestions = suggest_repairs_for_findings(findings, Industry.INTERNET)
```

### 7.4 带基准上下文

```python
from fp_sentinel.industry_benchmark import RepairAdvisor
from fp_sentinel.industry_benchmark.builtin_data import build_benchmark_dataset

benchmark = build_benchmark_dataset(Industry.FINANCE)
advisor = RepairAdvisor(benchmark=benchmark)
# 修复建议将自动包含合规引用
suggestions = advisor.suggest_for_finding("BUSINESS_LOGIC", "CRITICAL", "CWE-840", Industry.FINANCE)
# 结果中 compliance_refs 将包含 JR/T 0071-2020 等
```

---

## 8. 行业特定场景模板匹配表

| 行业场景ID | 模板Key | 适用行业 |
|-----------|---------|---------|
| `INTERNET_API_ABUSE` | - | internet |
| `INTERNET_SUPPLY_CHAIN` | - | internet |
| `FINANCE_TRANS_TAMPER` | - | finance |
| `FINANCE_BATCH_RISK` | - | finance |
| `GOV_PII_MASS` | - | government |
| `GOV_SUPPLY_CHAIN` | - | government |
| `ICS_RCE` | ICS_RCE | industrial_ctrl |
| `ICS_FIRMWARE` | - | industrial_ctrl |
| `HC_MED_DEVICE` | - | healthcare |
| `HC_EMR_LEAK` | - | healthcare |
| `EDU_GRADE_CHANGE` | - | education |
| `EDU_THESIS_LEAK` | - | education |
| `TEL_BILLING_FRAUD` | - | telecom |
| `TEL_INTERCEPTION` | - | telecom |
| `NRG_SCADA_HACK` | NRG_SCADA_HACK | energy |
| `NRG_METER_HACK` | - | energy |
| `TRA_SIG_HACK` | - | transportation |
| `TRA_GPS_SPOOF` | - | transportation |
| `INS_CLAIM_FRAUD` | - | insurance |
| `INS_ACTUARY_TAMPER` | - | insurance |
| `SEC_FLASH_CRASH` | SEC_FLASH_CRASH | securities |
| `SEC_ORDER_SPOOF` | - | securities |

**注意**: 场景ID与模板Key的精确匹配实现于 `suggest_for_industry()` 方法中:
```python
for tmpl_key, templates in _INDUSTRY_TEMPLATES.items():
    if tmpl_key == scenario.scenario_id:
        # 使用该模板
```

---

## 9. 边界与降级处理

| 场景 | 处理方式 |
|------|---------|
| 无匹配的 category/severity | 返回空列表 |
| 无 CWE + 无 benchmark | 返回模板建议，compliance_refs 为空 |
| 有 CWE 但无 benchmark | 返回模板建议，无法丰富合规引用 |
| 重复发现去重 | 基于 suggestion_id 去重 |
| 全行业建议 | 遍历 top_vulnerabilities[:5] + industry_scenarios |
| 空发现列表 | `suggest_for_finding` 仍可能返回匹配 (空类别匹配所有) |

### 9.1 特殊说明

- `suggest_for_finding("", "INFO", None, Industry.INTERNET)` 由于模板可能使用空 `target_categories` (表示匹配所有)，某些低严重度模板可能返回结果。这是设计允许的。
- 建议ID总是通过 `f"sug-{uuid.uuid4().hex[:8]}"` 生成唯一标识，确保多次调用不产生冲突。

---

## 10. 参考链接清单

修复建议内置了 OWASP 等权威参考链接：

| 漏洞类别 | 参考链接 |
|---------|---------|
| SQL注入 | https://owasp.org/www-community/controls/SQL_Prevention_Cheat_Sheet |
| XSS | https://owasp.org/www-community/attacks/xss/ |
| 越权 | https://owasp.org/Top10/A01_2021-Broken_Access_Control/ |
| 加密失效 | https://owasp.org/www-project-cheat-sheets/ |
| 不安全设计 | https://owasp.org/www-project-application-security-verification-standard/ |
| 组件漏洞 | https://owasp.org/www-project-dependency-check/ |
| 数据泄露 | https://owasp.org/www-project-top-ten/ |
| 配置错误 | https://owasp.org/www-project-web-security-testing-guide/ |
