# 玄鉴 v4.0 第三轮（最终轮）终验报告 —— 发布决策

- 测试人角色：App安全测试专家（移动安全渗透测试视角，发布决策者）
- 测试日期：2026-09（Round 3 终验）
- 测试环境：Windows 10 (26200) / Python 3.12.13 / androguard 4.x（未安装 jadx，反编译为大纲模式）
- 被测对象：`python -m fp_sentinel mobile {shell|decompile|hook|poc|insight}`
- 靶场（6 个）：InsecureBankv2.apk（主）、vuls_v4.4.apk、app_vul_test.apk（OVAA）、TestVuls.apk、com.st3v3nss.insecurebankingfingerprint指纹识别绕过复现demo.apk、FoxMmm-0.5.4.apk
- 测试方式：全部 CLI 真实执行，输出留档于 `round3_final_verify/`（ib2_seed{0,1,7,42}.json、vuls.json、vuls_seed7.json、ovaa.json、testvuls.json、fingerprint.json、foxmmm.json、manifest_ib2.json、strings_sensitive.json、strings_pattern.json、search_super.json、hook_rec.json、poc_rank99.json、poc_ssl.json、poc_ssl_final.js、decompile_run.txt、shell_out.txt、help_*.txt）
- 独立性声明：本报告所有结论均来自本轮独立执行的 CLI 实测，不以开发报告自述为判定依据；与开发报告不一致之处逐条标出。

---

## 0. 结论速览

- **总体评分：7.2 / 10**（Round 1：5 / 10 → Round 2：6.5 / 10 → Round 3：7.2 / 10）
- **最终判断：有条件发布。** 主线目标（证据归因）达成度高：InsecureBankv2 可靠检出 8/13（开发报告口径 9/13，本轮独立复核按更严口径计 8/13），达到 ≥8/13 验收线；CP-004 系统性误报 6/6 → 0/6 根除；扫描结果跨 PYTHONHASHSEED 确定性验证通过；712 用例全绿。
- **但"HIGH+ 误报 = 0"验收口径在扩展靶场（OVAA / 指纹demo）上未达成**：发现 3 类残留 HIGH+ 噪声——① `androidx.*` 未纳入 framework 落点降级名单（开发报告 R3.1b 声称的降级机制存在覆盖缺口）；② `okhttp3.*/okio.*` 未列入库前缀白名单（开发报告自述的发布前待办未做），导致 okhttp 内部代码以 CRITICAL/HIGH 入报告；③ 凭证分级器对资源名/字段名形态（`TextInputLayout_passwordToggleContentDescription`、`encodedPassword`）产生 3 处 HIGH+ 假凭证。
- **阻断级文档缺失**：README 仍为 v3.1，v4.0 五大移动能力的用户文档为零（HELP/API reference/CHANGELOG 均无 mobile 内容），以当前状态对外发布不成立。
- 一句话结论：**引擎核心（归因、确定性、误报根除、覆盖率）已达到可发布水位；剩余问题是 3 处可在一两天内完成的前缀/排除清单修补 + 文档补齐。修完即可发布；不修则只能以"研究/教学预览版"口径发布。**

---

## 1. 三轮问题闭环率（P0/P1/P2 逐条）

### 1.1 Round 2 新短板 NEW-01 ~ NEW-12（12 条）

| 编号 | 级别 | 问题 | 判定 | 终验证据 |
|---|---|---|---|---|
| NEW-01 | P0 | ST-007 CRITICAL 证据无效 | **✅ 已闭环**（主靶场达标，残留长尾见下方备注） | `insight scan InsecureBankv2`：ST-007 **CRITICAL**，evidence 含 `[LEVEL3] superSecurePassword`，归因 `com.android.insecurebankv2.ChangePassword#access$200`；Round 2 的无效证据（`X-Afma-OAuth-Token-Status`/`CREDENTIALS_API`/`/changepassword`）已全部消失。**残留**：分级器在 vuls/TestVuls 上把 support 库资源名 `TextInputLayout_passwordToggleContentDescription` 判为 `[LEVEL3]`（HIGH），在 OVAA 上把 okhttp 字段名 `encodedPassword` 判为 `[LEVEL3]`（CRITICAL）——假凭证 HIGH+ 共 3 处，属修复引入面的长尾 |
| NEW-02 | P0 | 代码级规则无 class#method 归因 | **✅ 已闭环（含保留）** | 6 靶场共 39 条 HIGH+，全部带归因字段；IB2 上 10 条 HIGH+ 归因全部为业务类或可读库位置。**保留**：3 个靶场各有 1 条 ST-007 以 `DEX string pool (unattributed)` 占位（已按设计降 CRITICAL→HIGH）；"全部 HIGH+ 有真实 location"的严格口径下，这 3 条是占位而非定位 |
| NEW-03 | P0 | CP-004 库类 HIGH 误报 | **✅ 已闭环** | 6 靶场 CP-004 仅在 3 个真实存在业务 Provider 的靶场触发，证据全部为 Manifest 精确业务类：`TrackUserContentProvider` / `ddns.android.vuls.ContentProviders.AccountProvider` / `oversecured.ovaa.providers.TheftOverwriteProvider`（均 exported=true）；support/gms/chromium 库类证据 0 出现。TestVuls/指纹demo/FoxMmm 无 CP-004 |
| NEW-04 | P1 | strings --sensitive 无归属字段 | **⚠️ 部分闭环** | 归属字段已实现：`--sensitive --format json` 27 条中 **26/27 带 location**（text 模式 `@ class#method` 后缀同步生效）。**未达部分**：真实敏感串仍为零——27 条中 25×AES_KEY + 2×TOKEN 全部为 gms 库候选；`--pattern "superSecurePassword\|EncryptedUsername\|mySharedPreferences"` 仍返回 **0 条**（superSecurePassword 已被证实存在于 DEX，`decompile search` 可命中）。Round 2 验收期望"已证实敏感串出现在结果中"未达成 |
| NEW-05 | P1 | manifest 缺 debuggable/allowBackup | **✅ 已闭环** | `decompile manifest --format json` 顶层含 `application_flags: {debuggable: true, allow_backup: true, network_security_config: '', uses_cleartext_traffic: null}`；ST-010（CRITICAL）/ST-011（MEDIUM）在全部含此属性的靶场实测触发，漏洞口径 #13 由"不可能检出"变为可靠检出 |
| NEW-06 | P1 | 库/业务分层 | **✅ 已闭环** | findings 带 `classification`（business/library/framework/obfuscated/unattributed），报告输出 `classification_distribution`（IB2：business 14 / library 9 / framework 6 / unattributed 5）；框架落点自动降级在 IB2 上生效（ST-004/CP-012/ST-005 均为 MEDIUM/LOW）。**缺口**：`androidx.*` 未进 framework 降级名单（见环节3），okhttp 判 business（开发报告自述待办未做） |
| NEW-07 | P1 | Xposed 语义反转 | **✅ 已闭环** | FoxMmm 实测 AA-004 INFO，evidence = `['[detector=defense] EdXposed', '[detector=defense] LSPosed', '[detector=defense] de.robv.android.xposed']`，描述按攻/防双角色输出。注：解包核对 FoxMmm 无 `assets/xposed_init`（实为 Magisk 模块管理器），输出 `[detector=defense]` 与事实相符；开发报告"FoxMmm 将输出 [module=attack]"的预期对不上该靶场，但语义方向已正确 |
| NEW-08 | P1 | AA-003 证据为正则原文 | **✅ 已闭环** | 5 个触发靶场 AA-003 evidence 均为具体命中片段 `['frida']`，无正则源码/词表拼接 |
| NEW-09 | P2 | poc --rank 越界静默回退 | **✅ 已闭环** | `--rank 99 --no-save` → `success=false`，error=`"--rank 99 超出范围: hook_points 只有 10 个点位 (有效范围 0~9)..."`，不再静默回退 |
| NEW-10 | P2 | poc output_path 恒 null | **❌ 未闭环** | `poc generate --goal ssl-bypass --output ...` 文件真实落盘（4839 字节）但 JSON 中 `output_path: None`。本轮未在修复清单（可接受），发布说明应列 Known Issues |
| NEW-11 | P2 | decompile run 5000 截断无 skipped 清单 | **❌ 未闭环** | 实测仍只有 `[WARN] 源码文件数超过上限 5000，已截断`，产物目录（outline/）无 skipped_classes 文件，6529 类中 1529 类去向不可知。本轮未在修复清单 |
| NEW-12 | P2 | hook recommend Top-N 有效率 | **⚠️ 部分闭环** | 实现了按 `(class, method, technique)` 去重，但**同一物理点位仍占多个 Top-N 槽位**：实测 Top10 中 `CryptoClass#aesEncryptedString`（base64/string）、`LoginActivity#fillData`（base64/toast）、`DoTransfer$RequestDoGets2#doInBackground`（base64/json）各 2 次，10 行实际仅 7 个物理点位，无 `unique_points` 计数。专家验收口径（按 class#method 合并技法）未达成 |

### 1.2 Round 1 遗留（终验要求三条）+ 相关遗留

| 编号 | 问题 | 判定 | 终验证据 |
|---|---|---|---|
| RD-007 | poc validate 占位符检查失效 | **✅ 已闭环** | 含 `com.target.app`（2 处）脚本 → `no_placeholder_pkg=false`、warning"疑似占位符包名残留(2处)"、**score=60.0**（干净脚本同分受其他注释项影响，评分封顶机制生效） |
| RD-009 | hook recommend 不去重 | **⚠️ 部分闭环** | 同 NEW-12：技法级去重已实现，物理点位重复仍在 |
| RD-012 | 坏 APK 抛 Python 堆栈 | **✅ 已闭环** | 路径不存在 → 单行 `{"success": false, "error": "目标不存在或类型不支持: ... 支持规则可见"，}`，无堆栈；本轮 9 次扫描 stderr 全部 0 字节 |
| RD-013 | search STRING 无归属（关联项） | **❌ 未闭环** | `decompile search superSecurePassword` → `match_type=STRING`，`class_name="" method_name="" line_number=0`。归因索引已在 insight/strings 落地，search 命令未接入 |
| RD-016/017/018/019/020 | help 截断等 P2 组 | **❌ 未闭环（已声明）** | 见环节4 |

### 1.3 闭环率统计

| 级别 | 总数 | 已闭环 | 部分闭环 | 未闭环 |
|---|---|---|---|---|
| P0（NEW-01/02/03） | 3 | **3** | 0 | 0 |
| P1（NEW-04~08） | 5 | 4 | 1（NEW-04） | 0 |
| P2（NEW-09~12） | 4 | 1 | 1（NEW-12） | 2 |
| 终验指定遗留（RD-007/009/012） | 3 | 2 | 1（RD-009） | 0 |
| **合计（15 条）** | 15 | **10（66.7%）** | 3（20%） | 2（13.3%） |

P0 全清、P1 近乎全清，未闭环项全部是无承诺的 P2——闭环质量合格。

---

## 2. 最终 InsecureBankv2 13 已知漏洞覆盖率（终验独立复核）

判定依据：`insight scan ib2_seed0.json`（34 条 findings：C3/H7/M14/L6/I4，PYTHONHASHSEED=0/1/7/42 四次运行逐条一致）+ `decompile manifest` + `decompile search` 交叉核对。

| # | 已知漏洞 | Round 2 | 终验判定 | 证据（实测摘录） |
|---|---|---|---|---|
| 1 | 硬编码用户名/密码 | 部分 | **✅ 可靠检出** | ST-007 **CRITICAL** @ `ChangePassword#access$200`，evidence 含 `[LEVEL3] superSecurePassword`（真实凭证，DEX 可交叉证实） |
| 2 | 弱密码策略 | 部分 | **部分** | CR-006 HIGH @ `ChangePassword$RequestChangePasswordTask#postData`（业务归因，真实调用点）；但"复杂度/长度校验缺失"仍无规则，且首条 evidence 为 `/changepassword`（URL 路径，弱证据） |
| 3 | SharedPreferences 明文存储 | 部分 | **✅ 可靠检出** | ST-001 HIGH @ `MyBroadCastReceiver#onReceive`（业务类，跨 seed 稳定） |
| 4 | AES 硬编码密钥 | 部分 | **✅ 可靠检出** | CR-007 **CRITICAL** @ `CryptoClass#aes256decrypt`（业务归因、可人工核验；密钥素材本身仍未入证，为保留项） |
| 5 | Base64 加密用户名 | 部分 | **部分** | CR-011 LOW 触发，归因 `com.google.android.gms.internal.zzbm$zza#toString`（库类）；业务侧 `usernameBase64ByteString` 仍未点名 |
| 6 | 发送 SMS 泄露凭据 | ✅ | **✅ 可靠检出** | PV-009 HIGH @ `MyBroadCastReceiver#onReceive`（业务类） |
| 7 | Activity 组件导出 | ✅ | **✅ 可靠检出** | CP-001 MEDIUM @ `ChangePassword (exported=true)`（Manifest 事实源） |
| 8 | ContentProvider 未授权访问 | 误报 | **✅ 可靠检出（误报根除）** | CP-004 HIGH @ `TrackUserContentProvider (exported=true)`（业务 Provider，Manifest 精确解析）；Round 2 的 support 库误报消失 |
| 9 | SQL 注入 | ✅（弱归因） | **✅ 可靠检出** | ST-009 HIGH @ `TrackUserContentProvider$DatabaseHelper#onCreate`（业务类，R3.1 跨证据业务优先生效） |
| 10 | XSS / WebView | 误报性 | **部分** | CP-008 HIGH @ `com.google.android.gms.internal.zzig#<init>`（库内真实 addJavascriptInterface 调用点，证据可读、位置可核验）；**业务 WebView 未被点名**。开发报告计为"可靠"，本报告按"命中点非业务代码"从严计为部分 |
| 11 | 日志泄露敏感信息 | 误报性 | **误报性命中（LOW）** | ST-005 LOW @ `android.support.v7...SpinnerCompat$DialogPopup#dismiss`（framework 类）；App 自身 Log 泄露凭据仍未检出 |
| 12 | 路径遍历 | 误报性 | **误报性命中（MEDIUM）** | CP-012 MEDIUM @ `android.support.v7...ActivityChooserModel#readHistoricalDataImpl`（framework 类，R3.1 降级后不再以 HIGH 出现，但命中点仍非业务漏洞面） |
| 13 | ViewInspector 调试接口 | 漏检 | **✅ 可靠检出** | ST-010 **CRITICAL**（`android:debuggable="true"`，Manifest 属性实测解析正确；`adb jdwp` 指引随附） |

### 覆盖率小结

| 口径 | Round 1 | Round 2 | Round 3 终验 | 目标 |
|---|---|---|---|---|
| 规则触发数 | ~5/13 | 12/13 | **13/13** | — |
| 可靠检出（本报告口径） | 2/13 | 3/13 | **8/13**（#1/3/4/6/7/8/9/13） | ≥8 |
| 可靠检出（开发报告口径） | — | — | 9/13（另计 #10） | ≥8 |
| 有效检出（含部分） | 5/13 | 8/13 | **10/13** | — |
| 误报性命中 | 2/13 | 4/13 | **2/13**（#11、#12，均已降至 LOW/MEDIUM，不再污染 HIGH+ 层） | 0 |
| 验收线 ≥8/13 | 未达 | 未达 | **达成（8 或 9 ≥ 8）** | ≥8 |

---

## 3. 全靶场回归测试结果（6/6 靶场完整分析）

### 3.1 运行质量

| 靶场 | findings | 严重级分布 | stderr | 崩溃 | 耗时 |
|---|---|---|---|---|---|
| InsecureBankv2 | 34 | C3/H7/M14/L6/I4 | 0 字节 | 无 | ~40s |
| vuls_v4.4 | 39 | C3/H8/M14/L7/I7 | 0 字节 | 无 | ~40s |
| app_vul_test (OVAA) | 35 | C5/H6/M17/L3/I4 | 0 字节 | 无 | ~40s |
| TestVuls | 21 | C1/H2/M7/L8/I3 | 0 字节 | 无 | ~30s |
| 指纹绕过demo | 24 | C1/H3/M15/L3/I2 | 0 字节 | 无 | ~30s |
| FoxMmm | 29 | C2/H8/M13/L3/I3 | 0 字节 | 无 | ~40s |

6/6 全部完整解析、stdout 纯 JSON 可直接 `json.load`。与 Round 2 相比无回归。

### 3.2 确定性验证（同 APK 两次结果必须一致）

- InsecureBankv2：PYTHONHASHSEED=**0 / 1 / 7 / 42** 四次扫描，34 条 findings 的 `(rule_id, severity, 归因class, 归因method)` 完全一致。**通过**。
- vuls_v4.4：两次运行（默认 seed 与 seed=7）39 条完全一致。**通过**。
- 结论：Round 2 发现的"同 APK 两次结果不一致"缺陷已被 R3.1 有效修复，并有回归测试守护。

### 3.3 HIGH+ 归因与误报审计（逐条，终验独立）

| 靶场 | HIGH+ 条数 | 无归因字段 | 库/框架落点 HIGH+（误报项） |
|---|---|---|---|
| InsecureBankv2 | 10 | 0 | NW-001 HIGH @ gms `AnalyticsReceiver#onReceive`、CP-008 HIGH @ gms `zzig#<init>`（开发报告判定为"APK 内真实存在的可核验调用点"，本报告认可证据可核验，但业务漏洞面未命中） |
| vuls_v4.4 | 11 | 0（1 条 ST-007 为 unattributed 占位） | **NW-004 CRITICAL @ `okhttp3.internal.platform.AndroidPlatform`**、**NW-002 HIGH @ `okhttp3.internal...api24IsCleartextTrafficPermitted`**（okhttp 库内部代码被误判 business）；ST-007 HIGH 假凭证 `TextInputLayout_passwordToggleContentDescription` |
| OVAA | 11 | 0 | **NW-004 CRITICAL / NW-005 CRITICAL @ okhttp3.internal.\*\*、NW-002 HIGH @ okhttp3**、**CP-012 HIGH @ `androidx.core.graphics.TypefaceCompatUtil#mmap`**（androidx 未走 framework 降级）、ST-007 CRITICAL 假凭证 `encodedPassword`（okhttp 字段名） |
| TestVuls | 3 | 0（1 条 unattributed 占位） | ST-007 HIGH 假凭证 `TextInputLayout_passwordToggleContentDescription` |
| 指纹绕过demo | 4 | 0（1 条 unattributed 占位） | **ST-004 HIGH @ `androidx.core.content.ContextCompat`**、**CP-012 HIGH @ androidx `TypefaceCompatUtil#mmap`** |
| FoxMmm | 10 | 0 | 混淆业务类落点（zu0#c/vh0#g/i11#a 等）判 business 而非 obfuscated，属分类精度问题，非误报 |

**判定：**
1. CP-004 类库误报（Round 2 每场必现）：**0/6，根除** ✅
2. "所有 HIGH+ 有 location"：形式上达成（39 条 HIGH+ 全部带归因字段），但 3 条为 `DEX string pool (unattributed)` 占位。**有保留通过**
3. "HIGH+ 误报 = 0"：**未达成**。两类机制性残留：
   - **androidx 降级缺口**：IB2 上同规则 CP-012/ST-004 落 `android.support.*` 已自动降为 MEDIUM/LOW，但 OVAA/指纹demo 上落 `androidx.*` 仍为 HIGH——R3.1b 的 framework 命名空间清单缺少 `androidx.*`（一行修复）。
   - **okhttp 前缀白名单未补**：开发报告第 7.1 节自述"okhttp3./okio. 尚未列入库前缀白名单，建议发布前补充"，实测未补，直接导致 OVAA 2 条 CRITICAL + 2 条 HIGH、vuls 1 条 CRITICAL + 1 条 HIGH 为库内部代码命中。
   - 附加：凭证分级器对 `TextInputLayout_passwordToggleContentDescription`（资源名）、`encodedPassword`（字段名）产生 3 处 HIGH+ 假凭证（R3.1 新增的蛇形标识符排除规则未覆盖长资源名）。

---

## 4. 易用性终验清单

| 检查项 | 结果 | 证据 |
|---|---|---|
| CLI 参数一致性 | ⚠️ 部分 | `decompile` 组统一 `--format text/json`；`insight scan` 无 `--format`，用 `--summary` 布尔开关；`poc generate` 用 `--no-save`。三组子命令的输出控制风格不一致（可接受的 P2，但应统一） |
| 帮助文本完整性 | ❌ 未闭环（RD-016 原样） | `hook recommend --help` goal 列表仍截断为 `encrypt-trace/request-plaintext/signature-bypass/…`；`insight scan --help` 无命令描述、`--category`/`--min-severity` 允许值不明 |
| 错误提示友好度 | ✅ 通过 | 路径不存在 → 单行友好 JSON + 支持类型提示；`poc validate` 对占位符/缺注记给出可操作警告；无裸堆栈 |
| 输出格式规范 | ✅ 通过 | 9 次全量扫描 + shell/decompile/poc 全部 stdout 纯净可解析、stderr 0 字节（RD-001 修复持续有效）；JSON 顶层 schema 稳定（insight_count/severity_distribution/classification_distribution/duration_sec） |
| 文档完整性 | ❌ **不通过（阻断级）** | README.md 仍标注"玄鉴 XuanJian AI v3.1"，grep `mobile/insight/hook/砸壳/脱壳` 零命中；`docs/api-reference.md`、`docs/architecture.md`、`CHANGELOG.md` 均无 v4.0 移动能力内容。**产品五大核心能力对外零文档** |
| 可用性细节 | ⚠️ | `shell detect` confidence 恒 0.85（RD-019 原样）；无分析缓存，重复解析同一 APK 各自 17~46s（RD-020 原样）；decompile run 大纲模式降级标注到位（RD-006 持续有效） |

---

## 5. 产品成熟度评分（1-10，5 维度）

| 维度 | 评分 | 依据 |
|---|---|---|
| 功能完整度（对标规划 5 大能力 + 审计） | **7.5** | 砸壳检测（仅检测，confidence 恒定）、反编译（无 jadx 时大纲模式 + 诚实降级标注 + 搜索/字符串）、Hook 定位（7 技法 + 评分）、insight 审计（67 规则 + 归因 + 确定性）、POC 生成（全链路 + schema 校验 + 越界防护）全部端到端可用；缺行级定位（依赖 jadx）、缺动态执行闭环 |
| 代码质量 | **8.5** | 712 用例全绿（本轮独立复跑确认，197s）；五模块覆盖率 96.03%（pytest-cov 阈值校验）；R3.1 确定性回归、凭证分级 35 例、CP 门控等测试矩阵完整 |
| 工程化程度 | **7.5** | CLI 完整、stdout 纯净、异常收敛、性能护栏（索引时间预算/字符串池）、进程级缓存；扣分：help 截断、无跨命令分析缓存、`--format` 风格不统一 |
| 分析正确性 / 检出能力 | **6.5** | 13/13 触发、可靠 8/13 达标、CP-004 误报根除、确定性达标；扣分：androidx/okhttp 白名单缺口造成 6 条库类 HIGH+、假凭证 3 处 HIGH+、search 无归属、#2/#5 证据质量弱、#11/#12 仍为低级别误报性命中 |
| 可用性（真实渗透场景价值） | **6.0** | 报告结论可定位可核验（这是 Round 3 最大进步，渗透人员可按 class#method 复测）；扣分：零用户文档（无法交付给非开发使用方）、strings 价值仍低、RD-019/020 影响效率与可信观感 |
| **综合** | **7.2 / 10** | 较 Round 2 的 6.5 提升 +0.7；距离"可直接对外发布"（≥8）差文档 + 2 处清单修补 + 凭证长尾 |

---

## 6. 最终判断：**有条件发布**

### 6.1 判断依据

**达成（支持发布）：**
1. Round 2 设定的 4 条发布门槛中 3 条达成：可靠检出 **8/13 ≥ 8** ✅；所有 CRITICAL/HIGH 带归因位置 ✅（3 条 unattributed 占位已按设计降级）；`poc validate` 不再对占位符给满分 ✅。
2. 系统性 CP-004 误报 6/6 → 0/6 根除；HIGH+ 库误报在两个主靶场的开发报告审计口径下成立。
3. 扫描结果确定性验证通过（4 seeds 逐字节级一致），"可靠检出"有了可复现基础。
4. 712 用例全绿、无破坏性回归、stderr 零污染全线保持。

**未达成（发布条件）：**
1. **HIGH+ 误报 = 0 在扩展靶场不成立**（OVAA/指纹demo/vuls 共 6 条机制性库类 HIGH+ + 3 条假凭证 HIGH+），且其中 2 条为 CRITICAL。
2. **用户文档为零**（README 仍 v3.1），任何对外交付形态都不成立。

### 6.2 发布条件（全部为小改动，合计约 2~3 天）

| # | 条件 | 工作量 | 验收标准 |
|---|---|---|---|
| C1 | `classify_class`/framework 降级名单补 `androidx.*`（并复核 `okhttp3.`、`okio.`、`kotlin.`、`com.google.`, `org.chromium.` 全量入库前缀） | 0.5 天 | OVAA CP-012/NW-004/NW-005/NW-002、指纹demo ST-004/CP-012、vuls NW-004/NW-002 全部降级或过滤；6 靶场 HIGH+ 库/框架落点 = 0 |
| C2 | 凭证分级器补排除：下划线资源名（`*_passwordToggleContentDescription` 形态）、驼峰字段名（`encodedPassword` 形态，非孤立字面量） | 0.5 天 | vuls/TestVuls ST-007 假凭证、OVAA ST-007 CRITICAL 假凭证消失；superSecurePassword 基准用例不回退 |
| C3 | 文档补齐：README v4.0 移动能力章节（安装、5 大能力 Quick Start、输出 schema、Known Issues）、`docs/api-reference.md` 补 mobile 命令、CHANGELOG v4.0 条目 | 1 天 | 非开发使用方可仅凭文档完成一次完整分析 |
| C4 | 发布说明列 Known Issues | 0.5 天 | 至少包含：RD-013/016/017/018/019/020、NEW-10/11/12、jadx 缺失限制、大纲模式边界 |

**满足 C1~C4 后：可发布（v4.0）。** 不满足则以"研究/教学预览版"口径发布，且不得宣称"HIGH+ 误报为 0"。

---

## 7. 发布前最后检查清单

- [ ] C1 库/框架前缀清单修补 + 6 靶场 HIGH+ 误回归（期望：`grep -E '"(okhttp|androidx)' ` 在 HIGH+ 归因中零命中）
- [ ] C2 凭证排除修补 + superSecurePassword/EncryptedUsername/mySharedPreferences 三字符串端到端回归不回退
- [ ] C3 文档三项（README / api-reference / CHANGELOG）
- [ ] C4 Known Issues 清单
- [ ] 指纹demo 与 OVAA 的 HIGH+ 逐条人工复核补录进测试报告（本报告已提供基线数据）
- [ ] 打 tag 后用 4 个 PYTHONHASHSEED 再跑一次主靶场留档（产物命名建议 `release_verify/`）

---

## 8. 下一版本（v4.1）建议（按影响力排序）

1. **search 命令接入归因索引（RD-013 收尾）**：`AttributionIndex` 已有 string_index，`decompile search` 的 STRING 命中回填 class#method 是纯接线工作（~1 天）。完成后 strings/search/insight 三条入口全部可定位。
2. **strings --sensitive 打通真实凭证**（NEW-04 收尾）：把 `find_password_literals` 的 L3 结果直接并入 `--sensitive` 输出（带 LEVEL 与 location），并将 `--pattern` 改为对全池子串匹配。这是"信息收集第一站"价值的最后一步。
3. **hook recommend 按 class#method 合并技法 + unique_points 计数**（RD-009/NEW-12 收尾，0.5 天）。
4. **分析缓存（RD-020）**：`--cache-dir` + androguard Session，对 hook/strings/insight 串行工作流收益最大（每次 17~46s → 秒级）。
5. **shell detect confidence 特征化（RD-019）**：输出命中特征列表与分级 confidence，消除"恒 0.85"的可信度损伤。
6. **help/参数规范化（RD-016）**：goal/category/min-severity 枚举全集展示；统一 `--format` 风格。
7. **jadx 可选集成与行级定位**：行号是渗透报告的最后一块拼图；至少在安装 jadx 的环境下输出 file:line。
8. **POC 生成规范清理（RD-017/018）**：去 Unicode 符号与 `--no-pause`；`--param-types` 过滤 overloads。
9. **回归语料制度化**：把 6 靶场 HIGH+ 清单（本报告第 3.3 节）固化为 CI 断言（每靶场 HIGH+ 归因必须落业务包或显式白名单库），防止前缀清单类缺陷再次逃逸。

---

## 附：本轮主要留档（`C:\Users\lenovo\xuanjian-ai\round3_final_verify\`）

| 文件 | 内容 |
|---|---|
| `ib2_seed{0,1,7,42}.json` | InsecureBankv2 四种子扫描（确定性证据，34 条 findings） |
| `vuls.json` / `vuls_seed7.json` | vuls_v4.4 双运行一致性 + okhttp 误报证据 |
| `ovaa.json` / `testvuls.json` / `fingerprint.json` / `foxmmm.json` | 扩展靶场回归（androidx 缺口、假凭证、AA-004 双角色证据） |
| `manifest_ib2.json` | application_flags（debuggable/allowBackup）证据 |
| `strings_sensitive.json` / `strings_pattern.json` / `search_super.json` | NEW-04 部分闭环与 RD-013 未闭环证据 |
| `hook_rec.json` / `hook_out.txt` / `hook_err.txt` | RD-009/NEW-12 重复点位证据（stderr 0 字节） |
| `poc_rank99.json` / `poc_ssl.json` / `poc_ssl_final.js` | NEW-09 越界报错 / NEW-10 output_path=null 证据 |
| `decompile_run.txt` / `out_final/` | 大纲模式降级标注与 5000 截断无 skipped 清单证据 |
| `shell_out.txt` / `shell_err.txt` | confidence 恒 0.85（RD-019）与 stderr 纯净证据 |
| `help_*.txt` | RD-016 help 截断证据 |

*报告完 —— Round 3 终验。核心判断：引擎已到发布水位，文档与前缀清单是发布前的最后一公里。*
