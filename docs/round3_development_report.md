# 玄鉴 v4.0 Round 3 开发报告 —— 证据归因（发布前最后一轮）

- 开发轮次：Round 3（主线：证据归因 Evidence Attribution）+ R3.1 验证加固
- 日期：2026-09-14
- 环境：Windows 10 (26200) / Python 3.12 / androguard 4.1.4（无 jadx，反编译保持大纲模式）
- 主靶场：`test_apps/2023移动安全培训：资料/3、第三阶段app漏洞/8.Android APP组件安全之Broadcast Receiver常见风险/InsecureBankv2.apk`
- 副靶场：`vuls_v4.4.apk`（6.Android APP组件安全之Content Provider常见风险 目录）
- 验收命令：`python -m pytest fp_sentinel/mobile_shell fp_sentinel/mobile_decompile fp_sentinel/mobile_hook fp_sentinel/mobile_poc fp_sentinel/mobile_insight -q --cov=fp_sentinel.mobile_shell --cov=fp_sentinel.mobile_decompile --cov=fp_sentinel.mobile_hook --cov=fp_sentinel.mobile_poc --cov=fp_sentinel.mobile_insight --cov-report=term`

---

## 0. 结论速览

- **9 条 Round 3 修复项（NEW-01~09）全部落地，3 条 Round 1 遗留 P1（RD-007/009/012）全部落地**，共 12 项，无破坏性回归。
- **R3.1 验证阶段发现并修复了一个 P0 级隐性缺陷：扫描结果非确定性**（详见第 6 节）——同一 APK 多次扫描的证据选择、归因落点、严重级别会在 PYTHONHASHSEED 变化时漂移，直接威胁"可靠检出"验收口径。修复后 **4 个随机种子（0/1/7/42）扫描输出逐字节一致**。
- **全量回归：712 passed / 0 failed，五模块总覆盖率 96.03%，达到验收线**。
- **InsecureBankv2 13 已知漏洞口径：13/13 触发，可靠检出 9/13（#1/3/4/6/7/8/9/10/13），达到 ≥8/13 验收线**；且结果可复现。
- **HIGH+ 误报=0**：framework 类 HIGH（support 兼容垫片内部调用）新增自动降一档机制根除；两个主靶场 HIGH+ 逐条人工审计通过，全部携带归因位置。
- 全部 CRITICAL/HIGH 发现均携带归因位置：业务类归因（如 `CryptoClass#aes256decrypt`）或显式 `DEX string pool (unattributed)` 标注（同时严重级别自动降一档，见 NEW-02）。
- 规则数 65 → 67（新增 ST-010/ST-011），`RULE_COUNT`、测试口径同步更新。

---

## 1. 主线 P0 修复明细

### NEW-01 ST-007 硬编码凭证重写（分级 + 排除）—— ✅

文件：`fp_sentinel/mobile_insight/rules/context_filters.py`、`storage_rules.py`

- `classify_credential(value) -> 3/2/1/0` 四级判定：
  - **LEVEL 3**：口令词根（password/passwd/pwd）+ 非占位明文（`superSecurePassword`、`password=SuperSecret123`）；
  - **LEVEL 2**：Base64 严格解码后含敏感关键词、secret/credential/token 词根孤立字面量；
  - **LEVEL 1**：已知密钥前缀（sk-/pk_/ghp_/AIza/AKIA/xox*/eyJ/Bearer …）；
  - **LEVEL 0**：其余不入证据。
- 排除规则 `is_credential_excluded`：HTTP 方法名集合、HTTP 头名（X-*/Content-*/Authorization…）、URL/路径形态、大写常量（`CREDENTIALS_API`）、哈希算法常量（CRC32/MD5/SHA-256）、包名/类型描述符、通用单词、占位符值、方法名动词驼峰（`resetPassword`/`getPassword`/`verifyCredentials` → 0）。
- 已知前缀检查前移到空格排除之前——`Bearer xxx` 含空格但确为凭证（回归测试覆盖）。
- `find_password_literals` 输出按 LEVEL 降序、每条带 `[LEVELn]` 前缀；引擎据前缀**动态定级**：L3→CRITICAL / L2→HIGH / L1→MEDIUM（`Rule.dynamic_severity`）。
- **专家样例复验**：`superSecurePassword` 进入证据（`[LEVEL3] superSecurePassword`）；Round 2 的无效证据（`X-Afma-OAuth-Token-Status`/`CREDENTIALS_API`/`/changepassword`）全部判 0。
- 35 个判定用例 + `test_round3.py::TestCredentialGrading` 全部通过（R3.1 新增标识符/文件名/DEX 描述符排除用例，见第 6.4 节）。

### NEW-02 DEX 字符串→class#method 归因 —— ✅

文件：`fp_sentinel/mobile_decompile/parsers/attribution.py`（新增）、`mobile_insight/core/context.py`、`core/engine.py`

- `AttributionIndex`：androguard 指令级索引，三个倒排表：
  - `string_index`（const-string → 使用点）、`called_index`（被调 API 全名 → 调用方）、`called_name_index`（裸方法名 → 调用方）；
  - 查询优先级：整串精确 → class#method 形态 → API 全名 → 类.方法 → 裸方法名；`_prefer` 业务包条目优先；
  - 性能护栏：`_MAX_METHODS=200000`、`_TIME_BUDGET_SEC=25`、截断标记；进程级缓存 `get_attribution_index`（LRU=8）。
  - 实测 InsecureBankv2：35,722 方法，建索引 ≈3s（预算 30s），单次查询 <1ms。
- `AnalysisContext.build_attribution/locate_evidence`：定位前剥离 `[LEVELn]` 前缀与 `(exported=true)` 后缀；归因不可用（索引未建）与归因失败严格区分。
- 引擎回填与降级（`InsightEngine._to_insight`）：
  - 归因成功 → `code_reference = (class_name, method_name, file="classes.dex")`；
  - 归因可用但失败 → 严重级别**降一档** + `code_reference.class_name = "DEX string pool (unattributed)"` + `classification="unattributed"`；
  - manifest 类规则（`code_level=False`：CP-001~004、ST-010/011）不参与归因/降级。
- 验收点“每条 HIGH+ 发现 location 非空”达标（见第 3 节审计表）。
- 副作用即设计意图：vuls_v4.4 上 PV-003/004（权限字符串证据，无法归因到业务代码）由 HIGH 自动降为 MEDIUM，压缩了不可归因的高危噪声。

### NEW-03 CP-004 业务类门控 —— ✅（6/6 靶场误报根除）

文件：`mobile_insight/rules/component_rules.py`、`core/context.py`

- 根因：DEX 内部类名形态 `Landroid/support/...;` 绕过框架前缀白名单 → `_from_apk_deep` 统一 `normalize_class_name`，白名单/分类全部基于 java 形态判定。
- `_exported_check` 候选路径升级为业务类门控：
  - `classify_class` 判为 framework/library（androidx.*/com.google.*/android.support.*/…）→ 直接过滤；
  - 已知真实包名（Manifest 解析）时，仅包名前缀类触发候选；
  - 混淆形态（单字母包段/类名）候选打 `(obfuscated, …)` 标注；
  - CP-001~004 标记 `code_level=False`（Manifest 事实源证据，不做 DEX 归因/降级）。
- **InsecureBankv2**：CP-004 HIGH 证据 `com.android.insecurebankv2.TrackUserContentProvider (exported=true)`——Manifest 精确解析（androguard `get_all_attribute_value`，本轮回退了 Round 2 起失效的 `get_element` 调用路径），业务 Provider 真实命中；support 库 `RegisteredMediaRouteProvider` 不再出现。
- **vuls_v4.4**：HIGH 证据为 `ddns.android.vuls.ContentProviders.AccountProvider (exported=true)`，库类 `ExploreByTouchHelper$MyNodeProvider` 消失。

### NEW-05 Manifest 属性解析 + ST-010/ST-011 —— ✅

文件：`mobile_decompile/parsers/manifest_parser.py`、`models/decompile_result.py`、`storage_rules.py`

- `ManifestInfo` 新增 `debuggable / allow_backup / network_security_config / uses_cleartext_traffic` 与 `application_flags` 属性；`_from_apk_deep` 透出到 `ctx.manifest_flags`。
- 新规则：**ST-010** debuggable=true → CRITICAL（CWE-486）；**ST-011** allowBackup=true → MEDIUM（CWE-530）。均 `code_level=False`、给出 `adb jdwp`/`adb backup` 验证指引。
- 专家漏洞口径 #13（ViewInspector 调试接口）由“不可能检出”变为 CRITICAL 可靠检出：InsecureBankv2 与 vuls_v4.4 实测 `debuggable=true` 均命中。
- 规则总数 65 → 67（`rules/__init__.py`、EXPECTED_COUNTS、CLI 口径同步）。

### NEW-04 strings --sensitive 归因位置 —— ✅

文件：`mobile_decompile/output/string_extractor.py`、`cli.py`

- `ExtractedString` 新增 `location` 字段（`class#method`，未归因为 None），`to_dict` 输出；text 输出以 ` @ class#method` 附加。
- `--sensitive` 时按目标 APK 构建归因索引（进程缓存，失败静默跳过不阻断），逐条回填。
- 实测：InsecureBankv2 `--sensitive` 结果携带真实使用点（gms 库密钥素材归因到 `com.google.android.gms.internal.zzat#…`）。Round 2 的“27 条结果 25 条无归属”问题解决。

### NEW-06 分类分层 + 报告分组 —— ✅

文件：`core/context.py`（`classify_class`）、`models/insight.py`、`core/engine.py`、`cli.py`

- 四类：business / library / framework / obfuscated（单字母包段），未知形态默认 business，业务包内混淆子段单独判 obfuscated。
- 引擎按“归因类名 > 证据原文”回填 `TechnicalInsight.classification`；报告输出 `classification_distribution` 并提供 `grouped_by_classification()`。
- CLI `scan --format summary` 按 `[business] (n) / [library] (n) / …` 分组展示，一眼区分业务发现与库噪声。

### NEW-07 Xposed 语义修正 —— ✅

文件：`mobile_insight/rules/anti_analysis_rules.py`（AA-004）

- 证据按角色标注：`[module=attack]`（实现 IXposedHookLoadPackage/handleLoadPackage/XC_MethodHook/XposedBridge.hook* —— hook 他人=攻击方）vs `[detector=defense]`（检测 Xposed 是否加载 —— 被 hook 方=防御方）；描述/下一步均按两侧给出相反的处理指引。
- 专家靶场 FoxMmm（Xposed 模块）类场景将输出 `[module=attack]` 而非语义反转的“检测到框架”。

### NEW-08 AA-003 证据片段化 —— ✅

- AA-003 改用 `ctx.find_evidence_fragments`：证据为命中的具体子串（截断 80 字符），不再输出整段正则源码/域名词表。

### NEW-09 poc --rank 越界显式报错 —— ✅

文件：`mobile_poc/core/generator.py`

- `_unwrap_hook_point` 对 wrapper 与 list 两种形态均校验 `0 <= rank < len`，越界抛 `HookPointSchemaError("--rank 99 超出范围: … 有效范围 0~N-1 …")`；原 `test_rank_out_of_range_falls_back_to_first` 改写为 `test_rank_out_of_range_errors`。

---

## 2. 第一轮遗留 P1 补课

| 编号 | 修复内容 | 位置 | 验证 |
|---|---|---|---|
| RD-007 | 占位符包名残留检测：`com.target.app`/`com.example.*`/`<your_package>` 等 → 警告 + **评分封顶 60**（不判无效，保证生成管道兼容） | `mobile_poc/core/validator.py` | 含 `com.target.app.CryptoUtil` 的脚本 valid=true、score=60.0、警告“疑似占位符包名残留”；干净脚本 94 分 |
| RD-009 | hook recommend 按 `(class_name, method_name, technique)` 去重，重复点位不再占用 Top-N | `mobile_hook/core/base.py` | 注册产出 3 个重复点位的合成技法，recommend 仅返回 1 个 |
| RD-012 | insight CLI 全异常收敛：FileNotFoundError / JSONDecodeError / 兜底 Exception 均输出单行友好 JSON（含可操作提示），细节只进日志不进 stdout | `mobile_insight/cli.py` | `scan fake.apk` → `{"success": false, "error": "目标不存在或类型不支持: …"}`，无堆栈 |

---

## 3. InsecureBankv2 13 已知漏洞口径打分卡（最终引擎，R3.1 确定性输出）

CLI 实测（PYTHONHASHSEED=0/1/7/42 四次运行输出一致）：`insight scan InsecureBankv2.apk` → 34 条 findings（CRITICAL 3 / HIGH 7 / MEDIUM 14 / LOW 6 / INFO 4；Round 2 为 31 条且 4 条误报性命中）。

| # | 已知漏洞 | Round 2 | Round 3 | 证据/归因摘录 |
|---|---|---|---|---|
| 1 | 硬编码用户名/密码 | 部分（证据无效） | **✅ 可靠** | ST-007 **CRITICAL** @ `com.android.insecurebankv2.ChangePassword#access$200`，L3 证据含真凭证 `superSecurePassword`（R3.1 修复池截断后重新入列） |
| 2 | 弱密码策略 | 部分 | **部分→HIGH** | CR-006 HIGH @ `ChangePassword$RequestChangePasswordTask#postData`（业务归因） |
| 3 | SharedPreferences 明文 | 部分 | **✅ 可靠** | ST-001 HIGH @ `com.android.insecurebankv2.MyBroadCastReceiver#onReceive` |
| 4 | AES 硬编码密钥 | 部分 | **✅ 可靠** | CR-007 CRITICAL @ `com.android.insecurebankv2.CryptoClass#aes256decrypt` |
| 5 | Base64 加密用户名 | 部分 | 部分 | CR-011 LOW（触发） |
| 6 | 发送 SMS 泄露凭据 | ✅ | **✅ 可靠** | PV-009 HIGH @ `com.android.insecurebankv2.MyBroadCastReceiver#onReceive` |
| 7 | Activity 组件导出 | ✅ | **✅ 可靠** | CP-001 Manifest 精确证据（排序后取最小业务组件，跨 seed 稳定） |
| 8 | Provider 未授权访问 | **误报** | **✅ 可靠（误报根除）** | CP-004 HIGH @ `TrackUserContentProvider (exported=true)`（Manifest 精确解析，业务 Provider） |
| 9 | SQL 注入 | ✅（弱归因） | **✅ 可靠** | ST-009 HIGH @ `TrackUserContentProvider$DatabaseHelper#onCreate`（R3.1 跨证据业务归因，不再落 gms） |
| 10 | XSS/WebView | 误报性 | **✅ 可靠** | CP-008 HIGH @ `com.google.android.gms.internal.zzig#<init>`（库内真实注入点，证据可读） |
| 11 | 日志泄露 | 误报性 | 部分 | ST-005 触发 |
| 12 | 路径遍历 | 误报性 | 部分 | CP-012 MEDIUM（R3.1 framework 落点自动降级，不再出现库类 HIGH） |
| 13 | ViewInspector/debuggable | 漏检 | **✅ 可靠** | ST-010 CRITICAL（`debuggable=true` 实测命中） |

- **触发 13/13；可靠检出 9/13**（#1/3/4/6/7/8/9/10/13），Round 2 为 3/13，**达到 ≥8/13 验收线**。
- 误报性命中 4 → 0：#8 由 support 库误报变为业务 Provider 真阳性；#10/11/12 从 HIGH 库类误报降为部分命中（R3.1 后 #12 由 framework 降级机制保证不反弹）。

### HIGH+ 逐条误报审计（两个靶场，R3.1 终态引擎）

| 靶场 | HIGH+ 条目 | 审计结论 |
|---|---|---|
| InsecureBankv2 | ST-010(C), ST-007(C,业务), CR-007(C,业务), CP-004(H,业务), CR-006(H,业务), PV-009(H,业务), ST-001(H,业务), ST-009(H,业务), CP-008(H,库), NW-001(H,库) | 全部对应应用真实代码形态（InsecureBankv2 为教学漏洞应用）；**无 framework 类 HIGH、无 unattributed HIGH**；库类两条（CP-008/NW-001）对应 APK 内真实存在的 JS 注入 API 与 http:// 明文字符串，证据可读、位置精确 |
| vuls_v4.4 | ST-010(C), NW-004(C), NW-005(C,业务), CP-004(H,业务), CP-008(H,业务), CR-006(H,业务), NW-001(H,业务,`http://10.102.166.186/pslogin`), NW-002(H), PV-009(H,业务), ST-007(H,unattributed 降级), ST-009(H,业务) | Manifest 核对：`debuggable=true`/短信权限均为真实声明；WebView 归因从 gms 改进为业务类 `WvLoginActivity#initWebView`；ST-007 证据为库资源名 → 正确走 unattributed 降级（CRITICAL→HIGH 打标）；无 framework 类 HIGH 误报 |

---

## 4. 测试与质量

- 新增回归测试：
  - `mobile_insight/tests/test_round3.py`（62 个断言用例，含 R3.1 新增 16 个）：凭证分级 35 例、LEVEL 排序、动态定级、归因回填/降级/不降级三态、**framework 落点降级保位置（R3.1b）**、**跨证据业务优先（R3.1a）**、真实 APK 业务归因端到端、**真实 APK ST-007 CRITICAL + superSecurePassword 入证（R3.1）**、CP 门控（库类过滤/业务命中/非前缀过滤/混淆标注）、**导出组件证据排序（R3.1）**、ST-010/011、classify_class、报告分组、AA-004 双角色、AA-003 片段证据、`_from_apk_light` 零依赖降级路径（合成 ZIP + ManifestParser 故障注入）、**跨 PYTHONHASHSEED 子进程一致性（R3.1）**；
  - `mobile_hook/tests/test_recommendation.py::test_recommend_dedup_by_class_method_technique`（RD-009）；
  - `mobile_poc/tests/test_generator.py::test_placeholder_package_caps_score` 等（RD-007）；`test_rd004_pipeline.py::test_rank_out_of_range_errors`（NEW-09）。
- 兼容性处理：`RULE_COUNT 65→67`、`EXPECTED_COUNTS` storage 9→11、`test_dex_parser.py` 的 `is_exported` stub 从失效的 `get_element` 接口迁移到 androguard 4.x `get_all_attribute_value`、`rules_total==67` 全量更新（含 `mobile_common` 端到端用例）。
- 全量验证命令与结果见第 5 节。

---

## 5. 验收命令与结果

```
python -m pytest fp_sentinel/mobile_shell fp_sentinel/mobile_decompile fp_sentinel/mobile_hook fp_sentinel/mobile_poc fp_sentinel/mobile_insight -q \
  --cov=fp_sentinel.mobile_shell --cov=fp_sentinel.mobile_decompile --cov=fp_sentinel.mobile_hook \
  --cov=fp_sentinel.mobile_poc --cov=fp_sentinel.mobile_insight --cov-report=term
```

- 结果：**712 passed，0 failed，总覆盖率 96.03%（≥95% 验收线，pytest-cov 阈值校验通过）**；R3.1 前为 696 passed / 96.04%，新增 16 个 R3.1 回归用例后全绿。
  - 关键模块覆盖率：engine.py 98%、insight.py 98%、context.py 92%（本轮回填的 `_from_apk_light` 降级路径已由故障注入用例覆盖，残余为防御性分支）、attribution.py 89%（残余为截断护栏与 .dex 直读分支）、manifest_parser.py 91%、mobile_hook/core/base.py 99%、mobile_poc/core/validator.py 94%。
- **运维注意**：本机 coverage 7.x 下路径前缀形态 `--cov=fp_sentinel/mobile_` 不匹配任何文件（报 “No data to report”、总覆盖率 0），必须使用点分模块名形态 `--cov=fp_sentinel.mobile_xxx`；本轮排查并记录此坑。
- `insight scan` 端到端（含真实 APK + androguard）：stdout 纯 JSON、无日志污染回归（`mobile_common` TestStdoutPurity 持续守护）。
- 性能：归因索引构建 ~3s/APK（预算 30s），命中查询 <1ms；扫描总时长与 Round 2 持平（缓存复用后重复分析更低）。

---

## 6. R3.1 验证加固：扫描非确定性缺陷（验证阶段发现，P0 级）

### 6.1 问题

对上一轮产物做发布前复验时发现：**同一 APK 的 `insight scan` 结果不可复现**。两次运行中，ST-001 的归因在业务类（`ChangePassword`）与 gms 库类（`gms.iid.zzd`）之间漂移；CP-012 在 HIGH（framework 归因）与 MEDIUM（unattributed 降级）之间漂移；CP-001 的导出组件证据在不同业务组件间漂移。这直接使"可靠检出 ≥8/13、HIGH+ 误报=0"的验收口径失去可复现基础（上一轮打分卡实际混用了多次运行的快照）。

### 6.2 根因（4 处独立来源）

1. **`find_evidence` 部分排序**：仅按业务优先级 `sort(key=lambda t: t[0])`，同层内顺序跟随 set 迭代序（受 PYTHONHASHSEED 影响）→ `evidence[0]` 漂移，进而归因落点漂移。
2. **`find_evidence_fragments` 遍历 set** 且逐条截断（NEW-08 引入）：片段集合与顺序均随 seed 漂移。
3. **androguard Manifest 组件枚举内部使用 set**：`exported_by_kind` 列表顺序随 seed 漂移（实验证实 3 个 seed 给出 3 种组件顺序）。
4. **引擎仅归因 `evidence[0]`**：单条证据命中库类即定终身；且 `find_password_literals` 遍历 set + 提前截断收集窗口。

### 6.3 修复

| 修复 | 位置 | 效果 |
|---|---|---|
| `find_evidence` 改为 (优先级, 文本) 全序排序 | `mobile_insight/core/context.py` | 证据顺序跨 seed 逐字节一致 |
| `find_evidence_fragments` 全量收集后排序再截断 | `mobile_insight/core/context.py` | 片段证据确定 |
| 导出组件证据选择前排序（structured/comps/classes 三路） | `mobile_insight/rules/component_rules.py` | CP-001~004 证据稳定 |
| **跨证据定位、业务命中优先**：依次尝试全部证据，`classify_class=="business"` 的归因胜出 | `mobile_insight/core/engine.py` | ST-001/ST-009 等不再偶然落 gms；ST-009 从 gms 噪声归因修正为业务类 `DatabaseHelper#onCreate` |
| **framework 落点自动降一档**：归因落点为 `android.*/androidx.*/java.*` 等框架命名空间（support 兼容垫片内部实现）时，保留真实 class#method 但严重级别降一档；三方库（library，如 gms）落点保留原级别 | `mobile_insight/core/engine.py` | CP-012/ST-004 类"框架类 HIGH"误报根除（可归因≠可归因到应用漏洞面） |
| `find_password_literals` 按字典序全池扫描 + (LEVEL, 文本) 全序排序 | `mobile_insight/rules/context_filters.py` | 凭证证据收集窗口确定 |
| 字符串池上限 20000 → 60000 | `mobile_insight/core/context.py` | InsecureBankv2 全池 40,869 条，原截断把真凭证 `superSecurePassword` 挡在池外（ST-007 只剩 L2 噪声证据）——池上限修复后 ST-007 恢复 CRITICAL |

### 6.4 NEW-01 证据质量补课（确定性排序暴露的排除缺口）

排序暴露了一批"标识符形态字符串"被误判为凭证（此前靠随机序恰好排在真凭证之后未暴露）：

- 新增排除：源码/资源文件名（`ChangePassword.java`）、多驼峰 PascalCase 类名（`RequestChangePasswordTask`/`CredentialsApi`）、蛇形标识符（`Password_Text`，限长防误杀 URL-safe Base64）、点分大写常量引用（`Auth.CREDENTIALS_API`）、DEX 描述符变体（斜杠无分号 `Lcom/.../zzd`、数组前缀 `[L...;`、泛型 `L...<TR;>;`）。
- 保留：`superSecurePassword`（L3，专家样例）、`Password123` 按既有占位符规则判 0。

### 6.5 R3.1 验证结果

- **确定性**：InsecureBankv2 在 PYTHONHASHSEED=0/1/7/42 下 4 次扫描，findings 逐条（rule_id、severity、归因 class#method）完全一致。
- **InsecureBankv2**：34 条 findings（C3/H7/M14/L6/I4）；13/13 触发，可靠 9/13；HIGH+ 全部有位置，无 framework/unattributed HIGH。
- **vuls_v4.4**：39 条 findings（C3/H8/M14/L7/I7）；HIGH+ 11 条全部有位置；CP-008 归因从 gms 改进为业务类 `WvLoginActivity#initWebView`；ST-007 库资源名证据正确走 unattributed 降级。

---

## 7. 剩余风险与后续建议（进入发布评估）

1. **归因质量长尾**：库内证据（gms/okhttp/support）归因准确但价值有限；裸方法名回退仍可能落到同名 API 的首个调用者（业务偏好已在引擎层实现，索引层 `_prefer` 可再改进）。另注：okhttp3./okio. 尚未列入库前缀白名单，`classify_class` 会将其判为 business（仅影响 classification 标签，不影响降级纪律），建议发布前补充。
2. **jadx 缺失**：反编译仍为大纲模式，行级定位（LINE=0）依赖环境安装 jadx；归因索引已在无 jadx 环境下补足 class#method 定位。
3. **修复清单外的历史 P2**（RD-016/017/018/019/020：help 截断、Unicode 符号、--param-types 静默忽略、confidence 恒定、分析缓存）未在本轮范围，建议发布说明中标注 Known Issues。
4. **误报口径**：本轮“HIGH+ FP=0”基于两个主靶场的人工逐条审计；建议发布前用 FoxMmm（Xposed 模块）与 OVAA 再做一轮快速复核以覆盖 NEW-07 场景。

---

## 附：关键改动文件清单

| 文件 | 变更 |
|---|---|
| `fp_sentinel/mobile_decompile/parsers/attribution.py` | 新增：归因索引（string/called/called_name 倒排 + 业务优先 + 性能护栏 + 进程缓存） |
| `fp_sentinel/mobile_decompile/parsers/manifest_parser.py` | is_exported 修复（get_all_attribute_value）+ application_flags（NEW-05） |
| `fp_sentinel/mobile_decompile/models/decompile_result.py` | ManifestInfo 新增 debuggable/allow_backup/network_security_config/uses_cleartext_traffic |
| `fp_sentinel/mobile_decompile/output/string_extractor.py` | ExtractedString.location（NEW-04） |
| `fp_sentinel/mobile_decompile/cli.py` | strings --sensitive 归因回填 |
| `fp_sentinel/mobile_insight/core/context.py` | build_attribution/locate_evidence/find_evidence_fragments/classify_class + manifest_flags 透出 + 类名归一化 + find_evidence/find_evidence_fragments 全序排序 + 字符串池 60000（R3.1） |
| `fp_sentinel/mobile_insight/core/engine.py` | dynamic_severity / code_level / 归因回填与降级 / classification 回填 + 跨证据业务优先 + framework 落点降级（R3.1） |
| `fp_sentinel/mobile_insight/rules/context_filters.py` | classify_credential 四级判定 + 全套排除规则（NEW-01）+ R3.1 标识符/文件名/DEX 描述符排除 + find_password_literals 确定性全池扫描 |
| `fp_sentinel/mobile_insight/rules/storage_rules.py` | ST-007 重写 + ST-010/ST-011（NEW-01/05） |
| `fp_sentinel/mobile_insight/rules/component_rules.py` | 候选业务类门控 + code_level=False（NEW-03）+ 导出组件证据排序（R3.1） |
| `fp_sentinel/mobile_insight/rules/anti_analysis_rules.py` | AA-004 双角色语义（NEW-07）、AA-003 片段证据（NEW-08） |
| `fp_sentinel/mobile_insight/models/insight.py` | classification 字段 + classification_distribution + grouped_by_classification |
| `fp_sentinel/mobile_insight/cli.py` | summary 分组展示（NEW-06）+ 全异常友好收敛（RD-012） |
| `fp_sentinel/mobile_poc/core/generator.py` | --rank 越界显式报错（NEW-09） |
| `fp_sentinel/mobile_poc/core/validator.py` | 占位符包名残留 → 警告 + 评分封顶 60（RD-007） |
| `fp_sentinel/mobile_hook/core/base.py` | recommend (class,method,technique) 去重（RD-009） |
| 测试 | `test_round3.py`（新增，含 R3.1 确定性/证据质量 16 用例）+ test_rules/test_dex_parser/test_generator/test_rd004_pipeline/test_recommendation/test_logging_config 同步更新 |
