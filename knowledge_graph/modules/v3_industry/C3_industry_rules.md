# C3 - 行业专属规则引擎设计

> **对应文件**: `fp_sentinel/industry_benchmark/industry_rules.py`
> **版本**: v3.0.0
> **核心类**: `IndustryRuleEngine`
> **规则总数**: 25+ 条 (覆盖全部 11 个行业)

---

## 1. 规则引擎架构

### 1.1 设计目标

为每个行业提供定制化的扫描规则，针对行业特有的技术栈和风险模式进行精准检测。

### 1.2 规则引擎类图

```
┌────────────────────────────────────────────────────────┐
│                   IndustryRuleEngine                    │
├────────────────────────────────────────────────────────┤
│ - _rule_sets: Dict[Industry, IndustryRuleSet]           │
├────────────────────────────────────────────────────────┤
│ + _load_builtin_rules()          # 加载内置规则         │
│ + get_rule_set(industry)         # 获取行业规则集       │
│ + add_rule(industry, rule)       # 添加自定义规则       │
│ + get_rules_for_tech(industry, tech)  # 按技术栈过滤    │
│ + enable_rule(industry, rule_id, enabled)  # 启用/禁用  │
│ + get_all_industries_with_rules()     # 列出有规则的行业│
│ + count_rules(industry?)         # 统计规则数量         │
└────────────────────────────────────────────────────────┘
```

### 1.3 规则数据模型

```python
class IndustryRule(BaseModel):
    rule_id: str                    # 规则唯一ID (如 "INET-API-AUTH-001")
    industry: Industry              # 适用行业
    name: str                       # 规则名称
    category: str                   # 漏洞类别
    cwe: Optional[str]              # CWE 标识
    severity: str                   # 严重度
    pattern: str                    # 检测模式 (描述性)
    description: str                # 规则详细说明
    tech_targets: List[str]         # 目标技术栈列表
    enabled: bool                   # 是否启用 (默认 True)
    compliance_refs: List[str]      # 合规引用标准

class IndustryRuleSet(BaseModel):
    industry: Industry              # 行业
    rules: List[IndustryRule]       # 规则列表
    version: str = "3.0.0"         # 规则集版本
    
    @property
    def enabled_rules(self) -> List[IndustryRule]:
        return [r for r in self.rules if r.enabled]
```

---

## 2. 内置规则清单

### 2.1 互联网 (internet) - 4 条规则

| 规则ID | 类别 | CWE | 严重度 | 检测目标 | 技术栈 |
|--------|------|-----|--------|---------|--------|
| `COMMON-DEFENSE-001` | INSECURE_DESIGN | CWE-209 | MEDIUM | 纵深防御 | * |
| `INET-API-AUTH-001` | BROKEN_ACCESS_CONTROL | CWE-284 | HIGH | 水平越权 | REST, GraphQL, gRPC |
| `INET-SSRF-001` | SSRF | CWE-918 | HIGH | 用户URL注入 | Python, Java, Go, Node.js |
| `INET-XSS-DOM-001` | XSS | CWE-79 | MEDIUM | DOM型XSS | JavaScript, TypeScript, React, Vue.js |
| `INET-CRYPTO-001` | CRYPTO_FAILURE | CWE-327 | HIGH | 弱加密算法 | * |

**合规引用**: GB/T 22239-2019 三级-8.1.3 / 8.1.4

### 2.2 银行 (finance) - 4 条规则

| 规则ID | 类别 | CWE | 严重度 | 检测目标 | 技术栈 |
|--------|------|-----|--------|---------|--------|
| `FIN-LOGIC-001` | BUSINESS_LOGIC | CWE-840 | CRITICAL | 交易金额篡改 | Java, .NET, Spring |
| `FIN-MFA-001` | AUTH_FAILURE | CWE-287 | HIGH | MFA缺失 | Java, Spring, .NET |
| `FIN-CRYPTO-SM-001` | CRYPTO_FAILURE | CWE-327 | CRITICAL | 国密算法合规 | Java, C++ |
| `FIN-IDOR-001` | BROKEN_ACCESS_CONTROL | CWE-639 | HIGH | IDOR | Java, Spring, .NET |

**合规引用**: JR/T 0071-2020 三级-8.1.3 / 8.1.4

### 2.3 政务 (government) - 3 条规则

| 规则ID | 类别 | CWE | 严重度 | 检测目标 | 技术栈 |
|--------|------|-----|--------|---------|--------|
| `GOV-SQL-001` | INJECTION | CWE-89 | CRITICAL | 政务门户SQL注入 | Java, .NET, PHP |
| `GOV-PII-001` | DATA_LEAKAGE | CWE-200 | CRITICAL | 公民PII保护 | * |
| `GOV-SUPPLY-001` | VULNERABLE_COMPONENTS | CWE-1035 | HIGH | 三方组件审计 | Java, JavaScript, Python |

**合规引用**: GB/T 22239-2019, 个人信息保护法-第51条, 数据安全法-第27条

### 2.4 工业控制 (industrial_ctrl) - 3 条规则

| 规则ID | 类别 | CWE | 严重度 | 检测目标 | 技术栈 |
|--------|------|-----|--------|---------|--------|
| `ICS-PROTO-001` | INSECURE_PROTOCOL | CWE-299 | CRITICAL | 明文工控协议 | C/C++, Modbus, OPC UA |
| `ICS-AUTH-001` | AUTH_BYPASS | CWE-287 | CRITICAL | 默认密码/硬编码 | PLC, HMI, RTU |
| `ICS-BUF-001` | BUFFER_OVERFLOW | CWE-122 | CRITICAL | 固件缓冲区溢出 | C, C++ |

**合规引用**: GB/T 39204-2022, 工信部协〔2016〕432号

### 2.5 医疗 (healthcare) - 3 条规则

| 规则ID | 类别 | CWE | 严重度 | 检测目标 | 技术栈 |
|--------|------|-----|--------|---------|--------|
| `HC-PHI-001` | DATA_LEAKAGE | CWE-200 | CRITICAL | 患者健康信息泄露 | * |
| `HC-MFA-001` | AUTH_FAILURE | CWE-287 | HIGH | 医疗系统MFA | Java, .NET |
| `HC-AVAIL-001` | AVAILABILITY | CWE-400 | HIGH | 医疗系统高可用 | * |

**合规引用**: 健康医疗数据安全指南 GB/T 39725-2020, 个人信息保护法

### 2.6 教育 (education) - 2 条规则

| 规则ID | 类别 | CWE | 严重度 | 检测目标 | 技术栈 |
|--------|------|-----|--------|---------|--------|
| `EDU-SQL-001` | INJECTION | CWE-89 | CRITICAL | 学生信息SQL注入 | PHP, Java, Python |
| `EDU-CHILD-001` | DATA_LEAKAGE | CWE-200 | HIGH | 儿童隐私(<14岁) | * |

**合规引用**: GB/T 22239-2019, 儿童个人信息网络保护规定

### 2.7 运营商 (telecom) - 2 条规则

| 规则ID | 类别 | CWE | 严重度 | 检测目标 | 技术栈 |
|--------|------|-----|--------|---------|--------|
| `TEL-PROTO-001` | PROTOCOL_VULN | CWE-299 | CRITICAL | SIP/Diameter 未加密 | C/C++, SIP, Diameter |
| `TEL-BILL-001` | BUSINESS_LOGIC | CWE-840 | CRITICAL | 计费系统完整性 | Java, C++ |

**合规引用**: GB/T 22239-2019, 通信网络安全防护管理办法

### 2.8 能源 (energy) - 2 条规则

| 规则ID | 类别 | CWE | 严重度 | 检测目标 | 技术栈 |
|--------|------|-----|--------|---------|--------|
| `NRG-SCADA-001` | INSECURE_PROTOCOL | CWE-299 | CRITICAL | SCADA IEC 61850/Modbus | C/C++, IEC 61850, Modbus |
| `NRG-AUTH-001` | AUTH_BYPASS | CWE-287 | CRITICAL | 默认密码 | PLC, HMI, RTU, SCADA |

**合规引用**: 电力监控系统安全防护规定 (发改委令第14号)

### 2.9 交通 (transportation) - 2 条规则

| 规则ID | 类别 | CWE | 严重度 | 检测目标 | 技术栈 |
|--------|------|-----|--------|---------|--------|
| `TRA-SIG-001` | SIG_SYS_VULN | CWE-284 | CRITICAL | 信号系统越权 | C/C++, CBTC, ATC |
| `TRA-GPS-001` | GPS_SPOOFING | CWE-290 | CRITICAL | GPS/北斗欺骗 | C/C++, Python |

**合规引用**: GB/T 22239-2019

### 2.10 保险 (insurance) - 2 条规则

| 规则ID | 类别 | CWE | 严重度 | 检测目标 | 技术栈 |
|--------|------|-----|--------|---------|--------|
| `INS-LOGIC-001` | BUSINESS_LOGIC | CWE-840 | CRITICAL | 理赔逻辑绕过 | Java, .NET |
| `INS-PII-001` | DATA_LEAKAGE | CWE-200 | CRITICAL | 保险客户数据 | * |

**合规引用**: JR/T 0071-2020, 个人金融信息保护技术规范 JR/T 0171-2020

### 2.11 证券 (securities) - 3 条规则

| 规则ID | 类别 | CWE | 严重度 | 检测目标 | 技术栈 |
|--------|------|-----|--------|---------|--------|
| `SEC-LOGIC-001` | BUSINESS_LOGIC | CWE-840 | CRITICAL | 交易指令篡改 | Java, C++, Rust, FPGA |
| `SEC-LATENCY-001` | LATENCY_EXPLOIT | - | CRITICAL | HFT延迟.floor | C++, FPGA |
| `SEC-MARKET-001` | MARKET_MANIPULATION | - | CRITICAL | 行情操纵检测 | Java, C++ |

**合规引用**: JR/T 0071-2020, 证券法-第77条, JR/T 0060-2012

---

## 3. 统一防御规则 (COMMON-DEFENSE-001)

```python
IndustryRule(
    rule_id="COMMON-DEFENSE-001",
    industry=Industry.INTERNET,  # 初始化后复制到所有行业
    name="Defense in Depth Verification",
    category="INSECURE_DESIGN",
    cwe="CWE-209",
    severity="MEDIUM",
    pattern="Check for missing layered security controls",
    description="Verify defense-in-depth is implemented across all layers",
    tech_targets=["*"],  # 通配所有技术栈
    compliance_refs=[],
)
```

该规则使用 `model_copy(update={"industry": X})` 复制到所有 11 个行业。

---

## 4. 规则引擎 API 详解

### 4.1 获取规则集

```python
engine = IndustryRuleEngine()
rs = engine.get_rule_set(Industry.FINANCE)
# 如果行业无已有规则，返回含 COMMON-DEFENSE-001 的默认集
```

```python
# 便捷函数
rs = get_industry_rule_set(Industry.SECURITIES)
```

### 4.2 按技术栈过滤

```python
# 获取适用于 Java 的规则 (通配符 '*' 也匹配)
rules = engine.get_rules_for_tech(Industry.INTERNET, "Java")

# 获取适用于任意技术栈的规则 (通配符 '*')
rules = engine.get_rules_for_tech(Industry.FINANCE, "COBOL")  # 可能返回空 (COBOL 不在 targets)
rules = engine.get_rules_for_tech(Industry.FINANCE, "Rust")   # 返回带有 '*' 的规则
```

**匹配逻辑**:
```python
if "*" in r.tech_targets or tech in r.tech_targets:
    include(rule)
```

### 4.3 规则管理

```python
# 添加自定义规则
new_rule = IndustryRule(rule_id="CUSTOM-001", industry=Industry.INTERNET, ...)
engine.add_rule(Industry.INTERNET, new_rule)

# 启用/禁用规则
success = engine.enable_rule(Industry.INTERNET, "INET-API-AUTH-001", enabled=False)
# 返回 True(找到并操作) / False(未找到)

# 查看所有有规则的行业
industries = engine.get_all_industries_with_rules()  # 返回 11 个

# 统计
total = engine.count_rules()                  # 全部规则数
finance_count = engine.count_rules(Industry.FINANCE)  # 金融规则数

# 便捷函数
rules = list_industry_rules(Industry.INTERNET, enabled_only=True)
```

### 4.4 全局便捷函数

```python
from fp_sentinel.industry_benchmark import (
    get_industry_rule_set,
    list_industry_rules,
)

# 获取单个行业规则集
rs = get_industry_rule_set(Industry.HEALTHCARE)

# 列出行业规则
rules = list_industry_rules(Industry.ENERGY, enabled_only=True)
```

---

## 5. 检测模式 (Pattern) 说明

每条规则的 `pattern` 字段为描述性的检测模式说明，非可执行代码：

| 目标 | Pattern 示例 |
|------|-------------|
| SQL 注入 | `statement.execute with user input` |
| SSRF | `url.open \| requests.get \| urllib with user input` |
| 越权 | `id_or_resource_id in request params without ownership check` |
| 加密 | `MD5 \| SHA1 \| DES \| RC4` |
| 工控协议 | `Modbus \| OPC \| DNP3 \| IEC 61850 without TLS/VPN` |
| PII | `idcard \| mobile \| address without encryption/masking` |
| 交易逻辑 | `amount \| price \| fee in request without server-side re-validation` |

**注意**: Pattern 用于描述和标识，实际扫描由扫描器模块执行，规则引擎负责分类管理和查询。

---

## 6. 合规映射汇总

| 行业 | 主要合规标准 | 引用次数 |
|------|-------------|:---:|
| internet | GB/T 22239-2019 | 4 |
| finance | JR/T 0071-2020 | 4 |
| government | GB/T 22239-2019, 个人信息保护法, 数据安全法 | 3 |
| industrial_ctrl | GB/T 39204-2022, GB/T 22239-2019 工控扩展 | 3 |
| healthcare | GB/T 39725-2020, 个人信息保护法 | 3 |
| education | GB/T 22239-2019, 儿童保护规定 | 2 |
| telecom | GB/T 22239-2019, 通信管理办法 | 2 |
| energy | 发改委令第14号, GB/T 22239-2019 | 2 |
| transportation | GB/T 22239-2019 | 2 |
| insurance | JR/T 0071-2020, JR/T 0171-2020 | 2 |
| securities | JR/T 0071-2020, 证券法 | 3 |

---

## 7. 规则引擎内部状态

```
IndustryRuleEngine._rule_sets: Dict[Industry, IndustryRuleSet]

初始加载后:
{
  Industry.INTERNET:  IndustryRuleSet(rules=[5条]),
  Industry.FINANCE:   IndustryRuleSet(rules=[4条]),
  Industry.GOVERNMENT: IndustryRuleSet(rules=[3条]),
  Industry.INDUSTRIAL_CTRL: IndustryRuleSet(rules=[3条]),
  Industry.HEALTHCARE: IndustryRuleSet(rules=[3条]),
  Industry.EDUCATION:  IndustryRuleSet(rules=[2条]),
  Industry.TELECOM:    IndustryRuleSet(rules=[2条]),
  Industry.ENERGY:     IndustryRuleSet(rules=[2条]),
  Industry.TRANSPORTATION: IndustryRuleSet(rules=[2条]),
  Industry.INSURANCE:  IndustryRuleSet(rules=[2条]),
  Industry.SECURITIES: IndustryRuleSet(rules=[3条]),
}
总计: 31 条规则 (含 COMMON-DEFENSE-001 的 11 份复制)
```
