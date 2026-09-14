# 玄鉴 v4.0 移动安全模块 Round 2 开发报告

> 针对 Round 1 专家反馈的 6 条 P0 级短板（RD-001 ~ RD-006）的修复与验证报告。
> 验证靶场: `test_apps/2023移动安全培训：资料/3、第三阶段app漏洞/8.Android APP组件安全之Broadcast Receiver常见风险/InsecureBankv2.apk`

---

## 总览

| 编号 | 问题 | 状态 | 核心验证结果 |
|------|------|------|--------------|
| RD-001 | androguard 日志灾难（stderr 55MB / stdout 混入日志破坏 JSON） | ✅ 已修复 | hook recommend stderr = **0 字节**（修复前 55MB）；insight scan / shell detect stdout 均为可解析纯 JSON |
| RD-002 | 字符串提取结构性失效（孤立字面量永不命中） | ✅ 已修复 | InsecureBankv2 敏感字符串提取 **16+ 条**（要求 ≥5）；`--pattern` 正则过滤生效 |
| RD-003 | insight 误报成灾（框架类/命名空间/孤立词） | ✅ 已修复 | InsecureBankv2 31 条 findings **零框架类误报**；良性语料（专家误报样例）零命中 |
| RD-004 | 流水线断裂（recommend JSON → poc generate 报 `undefined variable: 'method_name'`） | ✅ 已修复 | E2E 链路跑通：recommend → generate 成功产出可校验 Frida 脚本 |
| RD-005 | insight 覆盖率低（已知 13 漏洞仅命中 ~2） | ✅ 已修复 | InsecureBankv2 命中 **31 条**（要求 ≥8），含 SQL 注入/硬编码凭证/SQLi/日志泄露/短信外发等 |
| RD-006 | 反编译降级误导（outline 伪装成 0.6 分源码） | ✅ 已修复 | 质量分 **0.3** + 显式警告 "不可用于代码审计" + `outline-only (jadx unavailable)` 标注 |

**测试**: 653 个用例全部通过，6 个移动模块合并覆盖率 **95.85%**（≥95% 达标），Round 1 既有测试全部保留并通过（仅按计划更新了规则总数 63→65 与 outline 质量分 0.6→0.3 两处断言）。

---

## RD-001 日志灾难

### 问题
androguard 4.x 经 loguru 向 stderr 透传海量 DEBUG 日志：`hook recommend` 单次 stderr 达 55MB；`shell detect` stdout 混入 128KB DEBUG 日志导致下游 `json.load` 解析失败。

### 修复
- 新增统一日志出口 `fp_sentinel/mobile_common/logging_config.py`（`configure_logging` / `suppress_androguard_noise` / 环境开关 `FP_SENTINEL_MOBILE_VERBOSE`）：
  - **loguru**: 移除默认 DEBUG sink；`logger.disable("androguard")` 直接禁用 androguard 命名空间；重挂仅 WARNING+ 的受控 stderr sink；
  - **stdlib logging**: `androguard`/`pyaxmlparser` 等噪音 logger 强制 ERROR；root handler 重建到 **stderr**（铁律：stdout 只承载业务结果）；
  - 幂等可重复调用；`verbose`/`log_file`/`force` 参数；env 开关便于 CI 排障。
- 全部 5 个模块 CLI 入口（shell/hook/decompile/poc/insight）统一接入 `configure_logging()`。

### 验证
```bash
python -m fp_sentinel.mobile_hook.cli hook recommend <InsecureBankv2.apk> --output rec.json 2>err.log
wc -c err.log          # => 0 字节（修复前 55MB）

python -m fp_sentinel.mobile_insight.cli scan <InsecureBankv2.apk> | python -c "import json,sys; json.load(sys.stdin)"
# => 解析成功（修复前 stdout 混入日志导致失败）
```
单元测试: `fp_sentinel/mobile_common/tests/test_logging_config.py`（幂等性、噪音 logger 压制、loguru disable 行为、env 开关、子进程端到端 stdout 纯 JSON）。

---

## RD-002 字符串提取结构性失效

### 问题
TOKEN/API_KEY/AES_KEY 正则要求 `key=value` 形态，而 DEX 字符串池中的密钥/令牌都是**孤立字面量**（无赋值上下文），导致结构性漏报。

### 修复（`fp_sentinel/mobile_decompile/output/string_extractor.py`）
- **两级证据模型**：
  - `confirmed`（确认级）：保留原 key=value 结构化正则（并补齐 password 赋值形态）；
  - `candidate`（候选级）：新增孤立字面量启发式评分 `_literal_hit()`，覆盖：
    - 已知密钥前缀（sk-/sk_live_/pk_/ghp_/github_pat_/AIza/AKIA/xoxb-/glpat_/dop_v1_ 等）；
    - JWT 三段式；PEM 密钥块；
    - 32-hex → AES-128 密钥候选（0.7）；40-hex → SHA1/密钥（0.6）；16-hex 高熵 → 短密钥/IV（0.5）；
    - 敏感词根（password/secret/credential/token/api_key/aes_key/bearer）；
    - Base64/base64url：严格解码成功 → 可读为 Token、二进制且含 `+/=` 特征为密钥候选。
- **误报护栏**（防止候选级泛化成新噪音）：
  - DEX 类型描述符 `Lcom/...;` / 数组描述符 `[L...;` / 内部类路径 `Landroid/support/...` 一律排除；
  - SCREAMING_SNAKE 框架常量（`ACCESSIBILITY_EVENT_CLASS_NAME`，含 `_` 无法通过严格 base64 解码）排除；
  - 纯字母 CamelCase 类名（`AccessibilityDelegateBridge`、`AccessibilityNodeInfoApi21Impl`）排除（驼峰开头 + 无 `+/=` 特征 + 解码校验三重护栏）；
  - 散文片段（`password is:`、`, token=`）与 URL 路径（`/changepassword`）排除（要求核心段含数字/符号且无空格）。
- **`--pattern` 修复**：由原来的"字符串池子串过滤"改为对**提取结果值**的正则过滤（`re.IGNORECASE`，非法正则回退字面量），赋值类证据保留 `key=value` 全文便于按键名过滤。

### 验证
```bash
python -m fp_sentinel.mobile_decompile.cli strings <InsecureBankv2.apk> --sensitive --limit 20
# => 16+ 条高置信密钥/令牌候选（如 44/64 字节 base64 密钥blob），要求 >=5
python -m fp_sentinel.mobile_decompile.cli strings <InsecureBankv2.apk> --sensitive --pattern "password|token" --limit 8
# => 正则过滤生效
```
单元测试: `fp_sentinel/mobile_decompile/tests/test_string_extractor_rd002.py`（confirmed/candidate 两级、6 类字面量形态、误报控制、真实 APK ≥5 条、--pattern 过滤）。

---

## RD-003 insight 误报成灾

### 问题
`android.view.ActionProvider` 被判为导出 Provider、XML 命名空间被判为 HTTP 明文、孤立词 `signatures`/`CRC32` 被判为签名校验/反分析。

### 修复（三层防御）
1. **上下文层白名单**（`mobile_insight/core/context.py`）：
   - `FRAMEWORK_PREFIXES` 框架命名空间白名单（android/androidx/java/javax/kotlin/dalvik/com.google./org.apache./org.json./com.facebook./com.squareup. 等）——`is_framework_class()` **先检查应用包名前缀**（InsecureBankv2 包名 `com.android.insecurebankv2` 中的 `com.android.*` 业务类不会被误杀）；
   - `_RESOURCE_MARKER_RE` 资源标记（`xmlns:`/`tools:`/`@+id`/`@android:`/`http://schemas.android.com`、w3.org 命名空间）不参与信号匹配；
   - 信号池过滤：classes 池仅保留业务类，strings 求证前剔除资源标记。
2. **规则层二次确认**：
   - `Rule` 新增 `confirm_patterns` 字段：patterns 命中之外还要求全部 confirm 正则同时命中（类名+字符串双证据）；
   - 重写高风险规则为 `check` 双证据：AA-003（Frida 特征+端口/proc）、AA-006（getPackageInfo + `signatures[]`/GET_SIGNATURES，删除裸词 `signatures`）、AA-007（CRC32 + getPackageCodePath/classes.dex）、CP-005/CP-011/CP-012、ST-005（Log 调用 + 敏感字段）等。
3. **导出组件唯一真相源**：`_exported_check()` 优先使用 ManifestParser 结构化 `exported_by_kind`（精确 exported=true 组件）；无结构化数据时仅在有 manifest 标记 + 业务类证据时给出"候选"级标签，不再凭孤立类名报告。

### 验证
- 专家误报样例（ActionProvider / xmlns URL / `signatures` / CRC32）加入良性语料 `BENIGN_STRINGS`，`TestAllRulesFire.test_no_false_positive_on_benign_context` 与 `TestRound2Filtering.test_benign_corpus_zero_hits` 均断言 **零命中**；
- InsecureBankv2 实测 31 条 findings 中无任何框架类/资源标记误报（AA-003/006/007 在无对应实现时正确不报）。
- 单元测试: `test_rules.py` 新增 `TestRound2Filtering` / `TestRound2DoubleEvidence`。

---

## RD-004 流水线断裂

### 问题
`hook recommend` 输出 JSON（`{"hook_points": [...]}` 嵌套）直接喂给 `poc generate --hook-point` 时，生成器只按扁平 dict 取字段，报 `undefined variable: 'method_name'`。

### 修复
- `POCGenerator._build_context()` 重构（`mobile_poc/core/generator.py`）：
  - `_unwrap_hook_point()`: 兼容 HookRecommendation 包装（自动取 `hook_points[rank]`，继承外层 `package_name`）、点位列表、单点位 dict 三种形态；
  - 字段别名归一化表 `_FIELD_ALIASES`（fqcn/method/package/bundle/signature/param_sig/technique_name）；
  - **schema 校验** `HookPointSchemaError`：点位只给了 class_name 或 method_name 之一时报错，错误信息列出缺失字段 + 现有 keys + 可操作指引（纯 JSON 输出，退出码 2）；
  - 文件非法 JSON 同样收敛为 schema 错误。
- CLI（`mobile_poc/cli.py`）：
  - 新增 `--rank N` 选择推荐输出的第 N 个点位；
  - `--output` 同时支持目录与 `.js`/`.py` 文件路径两种形态；
  - generate payload **始终包含 `script`** 字段（供流水线直接消费）；
  - typer bridge 同步 `--rank`。

### 验证
```bash
python -m fp_sentinel.mobile_hook.cli hook recommend <InsecureBankv2.apk> --top 3 --output rec.json
python -m fp_sentinel.mobile_poc.cli generate --goal basic-hook --hook-point rec.json --output scripts/
# => success: true，产出 java_basic_hook.js（Hook onReceive/aesEncryptedString）
# 修复前: undefined variable: 'method_name'
```
单元测试: `mobile_poc/tests/test_rd004_pipeline.py`（包装解包、别名、schema 报错、--rank、越界回退、--output 文件形态、E2E 链路，共 14 例）。

---

## RD-005 insight 覆盖率低

### 问题
已知 13 个漏洞仅命中 ~2 个；缺硬编码密码/AES 密钥、SQL 注入、日志泄露、短信外发等高价值规则。

### 修复（规则库 63 → 65 条）
- **新增 ST-009** SQL 注入风险：`rawQuery|execSQL|compileStatement` 与 SQL 关键字（SELECT/INSERT/UPDATE/DELETE）双证据（CWE-89）；
- **新增 PV-009** 短信外发敏感数据：`sendTextMessage|SmsManager` 调用 + SEND_SMS 权限/声明双证据（CWE-200/359）；
- **重写 ST-007** 硬编码凭证：`find_password_literals()`（`rules/context_filters.py`）——key=value 确认级 + 孤立字面量候选级（DEX 字符串池场景），排除包名/URL/驼峰 getter/纯键名；
- **强化 ST-005** 日志泄露：Log 调用点 + 敏感字段（password/token/session/cookie 等）双证据；
- **强化 CR-007** 硬编码加密密钥：SecretKeySpec 存在 + `has_crypto_key_material()`（key/secret 赋值形态，或 AES 变换串上下文下的 16/24/32 字节 base64、32-hex 素材）双证据；
- **上下文升级**：`AnalysisContext.from_apk` 走 DexParser+ManifestParser 深度路径（真实字符串池、业务类、method_refs 调用面含 `pkg.Class.method` 全名），未装 androguard 时回退轻量路径；
- PV-004 文案区分 RECEIVE_SMS（接收）与 READ_SMS（读取）语义。

### 验证
```bash
python -m fp_sentinel.mobile_insight.cli scan <InsecureBankv2.apk> --output insights.json
# => 31 条 insights（要求 >= 8）:
#   CRITICAL: CR-007 硬编码加密密钥, ST-007 硬编码凭证
#   HIGH: ST-009 SQL注入, ST-003 SQLite明文, ST-001/ST-004, CP-004/008/012,
#         PV-009 短信外发, NW-001 HTTP明文, CR-006 口令慢哈希 ...
```
单元测试: `test_rules.py` 新增 `TestRound2NewRules`（ST-009/PV-009/CR-007 的正反用例、`find_password_literals`）；`_regex_sample.py` 语料扩展使 65 条规则全量触发测试通过。

---

## RD-006 反编译降级误导

### 问题
无 jadx 时产出方法签名大纲（outline），却报告成功且质量分 0.6，误导下游把它当可审计源码。

### 修复
- `mobile_decompile/core/android_java.py`：
  - `find_jadx()` 扩展常见安装路径扫描（Windows: `C:\jadx\bin`、Program Files；Linux: /usr/local/bin、/opt/jadx、/snap；macOS/Linux: ~/jadx、~/opt/jadx）；
  - 新增 `try_install_jadx()`：best-effort 自动安装（scoop/choco/winget/brew/apt/snap），失败静默降级（pragma: no cover）；
  - 降级路径质量分 **0.6 → 0.3**；
  - 降级时显式追加警告："jadx 未安装，当前为方法签名大纲（outline），不可用于代码审计；仅供结构/字符串/交叉引用分析"。
- `DecompileResult.summary()` 新增 `quality_label`（`full-source` / `outline-only (jadx unavailable)` / `unknown`）与 `degrade_warning` 布尔；
- `formatter.py`：text 输出状态行在降级时显示"**完成（大纲模式）**"，并固定输出"反编译质量: outline-only (jadx unavailable)"与审计不可用警告；markdown 同步标注。

### 验证
```bash
python -m fp_sentinel.mobile_decompile.cli run <InsecureBankv2.apk>
# 反编译结果: 完成（大纲模式）
#   引擎: androguard
#   质量评分: 0.3
#   反编译质量: outline-only (jadx unavailable)
#   [WARN] jadx 未安装，当前为方法签名大纲，不可用于代码审计
```
单元测试: `mobile_decompile/tests/test_rd006_degrade.py`（常见路径发现、安装失败静默、quality_label/degrade_warning、text/json 格式标注、真实 APK CLI 级标注）。

---

## 测试与覆盖率

```
653 passed in ~4 min（全部通过, 无回归）
```

| 模块 | 结果 |
|------|------|
| mobile_shell | 全部通过 |
| mobile_decompile | 全部通过（含 RD-002/RD-006 新增） |
| mobile_hook | 全部通过 |
| mobile_poc | 全部通过（含 RD-004 新增 14 例） |
| mobile_insight | 全部通过（65 条规则全量触发 + RD-003 回归） |
| mobile_common | 全部通过（RD-001, 含子进程 stdout 纯 JSON 端到端） |
| **合并覆盖率** | **95.85%**（`--cov=fp_sentinel.mobile_*`, branch 模式, 达标 ≥95%） |

命令:
```bash
python -m pytest fp_sentinel/mobile_common fp_sentinel/mobile_shell fp_sentinel/mobile_decompile \
  fp_sentinel/mobile_hook fp_sentinel/mobile_poc fp_sentinel/mobile_insight -q \
  --cov=fp_sentinel.mobile_shell --cov=fp_sentinel.mobile_decompile --cov=fp_sentinel.mobile_hook \
  --cov=fp_sentinel.mobile_poc --cov=fp_sentinel.mobile_insight --cov=fp_sentinel.mobile_common \
  --cov-report=term
```

### 有意更新的既有断言（非破坏性）
- `test_rules.py`: 规则总数 63 → 65（新增 ST-009/PV-009），EXPECTED_COUNTS storage 8→9、privacy 8→9；
- `test_android_java.py`: outline 降级质量分 0.6 → 0.3（RD-006 的核心语义变更）；
- `test_generator.py`: 保留"缺字段 → 渲染失败退出码 1"的泛型 goal 用例，schema 报错语义由新增用例覆盖。

---

## 剩余风险与后续建议

1. **候选级字符串的残留噪音（低）**：孤立字面量启发式在候选级仍可能命中少量边缘形态（如 HTTP Header 名 `X-Afma-OAuth-Token-Status`、日志格式串）。所有候选级条目均带 `[candidate]` 标签与 0.5~0.7 置信度，供人工复核；后续可引入词典/频率统计进一步压噪。
2. **jadx 自动安装的 best-effort 语义**：`try_install_jadx` 依赖系统包管理器（scoop/choco/winget/brew/apt/snap），沙箱/离线环境必然失败并静默降级——符合预期，但不会保证 jadx 可用；报告中的降级标注已确保不被误用为审计源码。
3. **导出组件"候选"级输出**：ManifestParser 结构化数据缺失时，导出组件规则输出 `(exported=未确认, 候选)` 标签，仍需下游确认。
4. **规则触发面与恶意样本**：65 条规则在 InsecureBankv2（明文漏洞靶场）验证充分；加固/OLLVM 混淆样本上的字符串与方法引用覆盖率未测，建议 Round 3 引入加壳样本验证降级路径与漏报率。
5. **hook→poc 链路只验证到脚本生成**：真实设备执行（`poc run --real`）依赖授权与真机，本次保持 mock 语义未变。

---

## 关键交付文件

- `fp_sentinel/mobile_common/logging_config.py`（RD-001）
- `fp_sentinel/mobile_decompile/output/string_extractor.py`（RD-002）
- `fp_sentinel/mobile_insight/core/context.py`、`core/engine.py`、`rules/component_rules.py`、`rules/anti_analysis_rules.py`、`rules/storage_rules.py`、`rules/privacy_rules.py`、`rules/crypto_rules.py`、`rules/context_filters.py`（RD-003/RD-005）
- `fp_sentinel/mobile_poc/core/generator.py`、`mobile_poc/cli.py`（RD-004）
- `fp_sentinel/mobile_decompile/core/android_java.py`、`models/decompile_result.py`、`output/formatter.py`、`mobile_decompile/cli.py`（RD-006）
- 新增测试: `mobile_common/tests/test_logging_config.py`、`mobile_decompile/tests/test_string_extractor_rd002.py`、`mobile_decompile/tests/test_rd006_degrade.py`、`mobile_poc/tests/test_rd004_pipeline.py`、`mobile_insight/tests/test_rules.py`（Round 2 回归类）
