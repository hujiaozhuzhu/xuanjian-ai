# App安全测试专家复测报告 —— 玄鉴 v4.0 Round 2 修复验收

- 测试人角色：App安全测试专家（移动安全渗透测试视角）
- 测试日期：2026-09（Round 2 复测）
- 测试环境：Windows 10 (26200) / Python 3.12.13 / androguard 4.x（未安装 jadx）
- 被测对象：`python -m fp_sentinel mobile {shell|decompile|hook|poc|insight}`
- 靶场：InsecureBankv2.apk（主靶场）、vuls_v4.4.apk、app_vul_test.apk、TestVuls.apk、指纹识别绕过demo.apk、FoxMmm-0.5.4.apk
- 测试方式：全部 CLI 真实执行，输出留档于 `round2_retest/`（shell_out.txt / insight_ib2.json / hook_ib2_r2.json / poc_gen_out.json / strings_sensitive.json / manifest_ib2.json / out_ib2_r2/ 等）

---

## 0. 结论速览

- **总体评分：6.5 / 10**（Round 1 为 5/10）
- 6 条 P0：**3 条已修复（RD-001/004/006），3 条部分修复（RD-002/003/005）**，0 条未修复，无破坏性回归
- 13 漏洞口径：触发 12/13，但**可靠检出仅 3/13**（Round 1 为 2/13），4 条为误报性命中，未达 ≥10 目标
- 一句话结论：**"管道可用性"问题基本解决（日志/流水线/降级标注），但"证据可归因性"没有跟上——新增的 HIGH/CRITICAL 规则普遍只给通用 API 名作为证据，最核心的 CRITICAL 硬编码凭证证据是无效字符串；字符串提取仍有约半壁江山（真实凭据类字符串）未打通。**

---

## 1. P0 修复验证表（6 条逐条验证）

### RD-001 日志灾难 —— ✅ 已修复

| 验证点 | Round 1 | Round 2 实测 | 判定 |
|---|---|---|---|
| `shell detect` stderr | 128KB DEBUG 日志混入 stdout | **stderr = 0 字节**，stdout 仅 1 行 `protection=无壳 confidence=0.85 packed=False`（48 字节） | 通过 |
| `insight scan` stdout 可解析 | json.load 失败 | `json.load` 成功，31 条 insights，stderr = 0 字节 | 通过 |
| `hook recommend` stderr | 55,450,486 字节 | **0 字节** | 通过 |

### RD-002 字符串提取失效 —— ⚠️ 部分修复

- **达标部分**：`--sensitive` 在 InsecureBankv2 输出 **27 条**（要求 ≥5），candidate/confirmed 两级证据模型生效；`--pattern "password|token|key"` 对提取值做正则过滤功能正常（命中 2 条 TOKEN）。
- **未达标部分**：
  1. 已知存在于 DEX 的核心敏感串**依然提取不到**：`decompile search superSecurePassword` 确认该串在 DEX 中（STRING 类型命中），但 `strings --pattern "superSecurePassword|EncryptedUsername|mySharedPreferences|password"` 返回 `(no matches)`——Round 1 的核心抱怨只解决了一半；
  2. 27 条 `--sensitive` 结果中 25 条是**无任何归属**（无 class/method/上下文字段，JSON 字段仅 value/category/confidence/source/evidence_level）的长 base64 库噪声，被标为 AES_KEY(0.50)，而真实密钥类素材一条未中。敏感字符串提取的"信息收集第一站"价值仍然接近于 0。

### RD-003 insight 误报 —— ⚠️ 部分修复

- **已消除的误报**（Round 1 逐条留档样例全部复验）：`android.view.ActionProvider`（CP-004）、XML 命名空间（NW-001）、裸词 `signatures`（AA-006）、`CRC32`（AA-007）在 InsecureBankv2 的 31 条结果中均未再出现。
- **仍然存在的误报**：
  1. **CP-004 "Content Provider 导出"（HIGH）证据仍为框架/支持库类**：InsecureBankv2 上为 `Landroid/support/v7/media/RegisteredMediaRouteProvider$ReceiveHandler; (exported=未确认, 候选)`；vuls_v4.4 上为 `ExploreByTouchHelper$MyNodeProvider`；app_vul_test 上为 `ShareActionProvider$ShareActivityChooserModelPolicy`；FoxMmm 上为 `org.chromium.support_lib_boundary.*`。**6 个靶场全部命中此误报**，且"exported=未确认, 候选"的候选级结论却以 HIGH 级输出；
  2. **AA-003（Frida 检测）证据是一整段原始正则文本**（vuls_v4.4 为 TLD 域名正则，FoxMmm 为拼音词表拼接串），与 Round 1 相同的"证据不可读"问题；
  3. 业务包保护生效（`com.android.insecurebankv2.*` 未被框架过滤误杀），但库类过滤只在部分规则生效，`com.google.android.gms.*` 证据仍在 31 条中占约 14 条。

### RD-004 流水线断裂 —— ✅ 已修复

- `hook recommend -o hook.json` → `poc generate --goal basic-hook --hook-point hook.json`：**success=true，脚本 1984 字节**，`Java.perform` 骨架正确（Round 1 为 `undefined variable: 'method_name'`）。
- 新增能力实测：`--rank 2` 正确选择第 2 点位并按 `--output round2_retest/poc_rank2.js` 落盘；schema 校验存在（开发报告所述）。
- 小瑕疵：`--rank 99`（越界）**静默回退 Top1，success=true 且无任何 warning**（见 NEW-09）。

### RD-005 insight 覆盖率 —— ⚠️ 部分修复

- 触发面显著改善：InsecureBankv2 31 条 findings（Round 1 为 25 条且核心规则全哑）；新增 ST-009（SQL注入）、PV-009（短信外发）确认触发；CR-007/ST-007/ST-005/ST-001 均已触发。
- 但按 13 已知漏洞口径（见第 2 节）：**可靠检出仅 3/13**，且 CRITICAL 级 ST-007 的证据是无效字符串（`X-Afma-OAuth-Token-Status`、`CREDENTIALS_API`、`/changepassword`），CR-007 证据只有框架类名（`javax.crypto.spec.SecretKeySpec.<init>`）——"触发了"不等于"可信地检出了"。开发报告以"31 条 findings ≥ 8"作为达标依据，与 13 漏洞验收口径不是一回事。

### RD-006 反编译降级误导 —— ✅ 已修复

实测输出（`decompile run InsecureBankv2.apk -o out_ib2_r2`）：
```
反编译结果: 完成（大纲模式）
  引擎: androguard
  质量评分: 0.3
  反编译质量: outline-only (jadx unavailable)
  [WARN] jadx 未安装，当前为方法签名大纲，不可用于代码审计
```
措辞、质量分、标注、警告四项全部到位。

---

## 2. InsecureBankv2 13 已知漏洞覆盖率对比

判定依据：APK 模式 31 条 findings（主）+ 反编译目录模式 14 条（辅）+ `decompile manifest` 交叉核对（exported = LoginActivity / MyBroadCastReceiver / gms EnableWalletOptimizationReceiver；TrackUserContentProvider exported=false）。

| # | 已知漏洞 | Round 1 | Round 2 | 证据摘录与说明 |
|---|---|---|---|---|
| 1 | 硬编码用户名/密码 | 漏检 | **部分** | ST-007 (CRITICAL) 触发，但证据为 `['X-Afma-OAuth-Token-Status','CREDENTIALS_API','/changepassword',...]`——HTTP 头名/常量名/URL 路径，**无一为真实凭证**；`superSecurePassword` 已证实存在却未被引用 |
| 2 | 弱密码策略 | 漏检 | **部分** | CR-006 触发且证据为业务类 `ChangePassword$RequestChangePasswordTask`（真实）；但"密码复杂度/长度校验缺失"仍无规则，属相邻命中 |
| 3 | SharedPreferences 明文存储 | 部分 | **部分（持平）** | ST-001 触发，证据仍为通用 API（`SharedPreferences.getLong`、`PreferenceManager`），未指出具体敏感键值对 |
| 4 | AES 硬编码密钥 | 漏检 | **部分** | CR-007 (CRITICAL) 触发，但证据仅 `javax.crypto.spec.SecretKeySpec.<init>` 框架类名，无密钥素材、无业务类归属 |
| 5 | Base64 加密用户名 | 已检出 | **部分（回退）** | CR-011 (LOW) 触发，但证据为库 API `android.util.Base64OutputStream`；Round 1 目录模式曾给出真实证据 `usernameBase64ByteString`，本轮目录模式该证据消失 |
| 6 | 发送 SMS 泄露凭据 | 漏检 | **✅ 检出** | PV-009 (HIGH) 触发：`SmsManager.sendTextMessage` + SEND_SMS 权限双证据；未关联到"外发的是凭据" |
| 7 | Activity 组件导出 | 误报为主 | **✅ 检出** | CP-001 证据 `com.android.insecurebankv2.LoginActivity (exported=true)`——Manifest 唯一事实源，完全正确 |
| 8 | ContentProvider 未授权访问 | 误报 | **误报（持平）** | CP-004 证据仍为 support 库类；真实业务 Provider `TrackUserContentProvider(exported=false)` 仍未被讨论 |
| 9 | SQL 注入 | 漏检 | **✅ 检出（弱归因）** | ST-009 (HIGH) 新规则生效，证据 `execSQL`/`rawQuery` 通用 API，无 `ChangePassword#updatePassWord` 类/方法定位 |
| 10 | XSS / WebView 漏洞 | 已检出(部分) | **误报性命中** | CP-008 触发，但证据是 `com.google.android.gms.internal.zzig`（库类）；业务 WebView `ViewStatement` 未被点名 |
| 11 | 日志泄露敏感信息 | 漏检 | **误报性命中** | ST-005 触发，证据 `com.google.android.gms.playlog.internal.zzf.zznM`（库代码）；App 自身 Log 打印凭据未检出 |
| 12 | 路径遍历 | 部分 | **误报性命中** | CP-012 触发，证据 `com.google.android.gms.drive.internal.OpenFileIntentSenderRequest`（库类） |
| 13 | ViewInspector 调试接口 | 漏检 | **漏检** | 无 debuggable/调试组件类命中；且 manifest 结构化 JSON **根本不输出 `android:debuggable` 属性**（见 NEW-05），当前架构下此漏洞不可能被检出 |

### 覆盖率小结

| 口径 | Round 1 | Round 2 | 目标 |
|---|---|---|---|
| 规则触发数 | ~5/13 | **12/13**（仅 #13 漏） | — |
| 可靠检出 | 2/13 | **3/13**（#6、#7、#9） | — |
| 有效检出（含部分） | 5/13 | **8/13**（#1~#5 部分为低质量部分） | — |
| 误报性命中 | 2/13 | **4/13**（#8、#10、#11、#12） | 0 |
| 验收目标 ≥10/13 | 未达 | **未达** | ≥10 |

**判定：方向正确（2→3 可靠、漏检 8→1），但"触发即报"的证据质量把 12 次触发稀释成 3 次可靠。当前最大瓶颈已从"规则缺失"转移为"证据归因缺失"。**

---

## 3. 其他靶场快速测试（通用性）

| 靶场 | insight 结果 | 亮点/问题 |
|---|---|---|
| vuls_v4.4.apk | 34 条，CRITICAL×3 | **RD-010 修复的正面证据**：CP-001/002/003 证据为 Manifest 精确结果（`ddns.android.vuls.MainActivity / SMSService / TokenReceiver (exported=true)`）；AA-003 证据为正则文本（NEW-08）；CR-006/PV-002/CP-010/CP-011 带库证据 |
| app_vul_test.apk (OVAA) | 33 条，CRITICAL×4 | 可正常全量分析；CP-004/ST-001/ST-003/ST-005 等 8 条带 gms/support 库证据 |
| TestVuls.apk | 19 条 | 正常；`shell detect` 输出仍为恒定 `confidence=0.85`（RD-019 未修） |
| 指纹识别绕过demo.apk | 23 条，CRITICAL×1（ST-007） | 正常；CR-012/CR-013 加密类规则在此靶场触发，与"指纹绕过"主题相关；ST-007 的 CRITICAL 同样存在证据弱归因问题 |
| FoxMmm-0.5.4.apk（Xposed 模块） | 29 条，CRITICAL×3 | **RD-015 未修**：AA-004 仍以 INFO 报"Xposed 框架检测"（证据 `de.robv.android.xposed.installer`），语义仍与事实相反，且无"这是 Xposed 模块"的分类判断 |

**通用性结论：6 个 APK 全部可完整解析、无崩溃、无日志污染；但 CP-004 库类 HIGH 误报在 6/6 靶场复现，属于系统性问题。**

---

## 4. P1/P2 短板抽查复测（Round 1 的 14 条中抽查 12 条）

| 编号 | 问题 | 复测结果 | 证据 |
|---|---|---|---|
| RD-007 | poc validate 占位符检查失效 | **未修** | 含 5 处 `com.target.app` 的脚本仍 `valid: true, no_placeholders: true, score: 100.0` |
| RD-008 | poc generate --output/--no-save 语义 | **已修** ✅ | `--output round2_retest/poc_ssl_direct.js` 文件真实落盘；`--no-save` 时 payload 含完整 script（4259 字节） |
| RD-009 | hook recommend 不去重/截断 | **未修** | Top10 中 3 组重复（`CryptoClass#aesEncryptedString`×2、`LoginActivity#fillData`×2、`DoTransfer$RequestDoGets2#doInBackground`×2），Top10 实际仅 7 个物理点位；表格仍在 30 字符截断（`DoTransfer$RequestD...`） |
| RD-010 | insight 与 manifest 割裂 | **已修** ✅ | 见第 3 节 vuls_v4.4 证据 |
| RD-011 | 无库/业务分层 | **未修** | InsecureBankv2 APK 模式 31 条中约 14 条证据指向 gms/support 库；目录模式 14 条中 8 条为库类 |
| RD-012 | 坏 APK 抛 Python 堆栈 | **未修** | `insight scan fake.apk` 仍输出 rich 面板包裹的完整 Traceback（BadZipFile），仅 `FileNotFoundError` 场景收敛为 JSON |
| RD-013 | LINE=0、STRING 无归属 | **未修** | `decompile search superSecurePassword` LINE=0、CLASS/METHOD 空；insight 的 `code_reference` 仍全空 |
| RD-014 | SEND_SMS 无规则 | **已修** ✅ | PV-009 新增且在 InsecureBankv2 正确触发 |
| RD-015 | Xposed 模块语义反转 | **未修** | 见第 3 节 FoxMmm |
| RD-016 | help 截断/枚举值缺失 | **未修** | `hook recommend --help` goal 列表仍截断为 `encrypt-trace/request-plaintext/signature-bypass/…`；`insight scan --help` 无命令描述、`--category` 允许值不明 |
| RD-017 | POC 脚本 Unicode 符号/废弃参数 | **未修** | 新生成 ssl_bypass 脚本仍含 `[✓]`（第 19/99 行）与 `--no-pause`（第 18 行，frida ≥16 已废弃） |
| RD-018 | --param-types 被静默忽略 | **未修** | 传入 `--param-types "java.lang.String"` 后 warnings=[]，脚本仍 hook 全部 overloads（5 处 overload 处理，无参数过滤） |
| RD-019 | confidence 恒 0.85 | **未修** | InsecureBankv2 与 TestVuls 均输出 `confidence=0.85`，无特征列表 |
| RD-020 | 无分析缓存，重复解析 | **未修** | strings/search/hook/decompile 对同一 APK 仍各自全量 AnalyzeAPK（17~24s/次） |

小结：抽查 14 条中 **3 条已修（RD-008/010/014）**，其余 11 条未动。Round 2 资源明显全部投入 P0，P1/P2 层未同步还债——可接受，但 Round 3 必须补课。

---

## 5. 新发现短板清单（12 条：P0×3，P1×5，P2×4）

### NEW-01（P0）CRITICAL 级 ST-007 证据无效，旗舰规则"报了等于没报"
- **复现 CLI**：`python -m fp_sentinel mobile insight scan <InsecureBankv2.apk>`
- **期望**：硬编码凭证 CRITICAL 应引用真实凭证字符串（`superSecurePassword` 已证实存在于 DEX 字符串池，`decompile search` 可命中）。
- **实际**：evidence = `['X-Afma-OAuth-Token-Status', 'CREDENTIALS_API', '/changepassword', 'INAPP_CONTI...']`——分别是一个广告 SDK 的 HTTP 头名、一个常量名、一个 URL 路径。`find_password_literals()` 的"敏感词根"匹配把**包含 token/password 字样的任意字符串**当凭证，却没有要求其形如凭证（短字面量/赋值右侧），同时把真凭证排除在外（疑似被"排除 URL 路径/驼峰"护栏反向误伤或截断逻辑吞掉）。
- **影响**：审计报告第一条 CRITICAL 即不可信；渗透测试人员一次核验失败后会对全部结果失去信任。
- **修复建议**：① 对 `find_password_literals` 增加白名单否定式（`X-*-Token-*` 头名模式、`^[A-Z_]+$` 常量名、以 `/` 开头的路径）；② 增加"已证实在 DEX 的字符串必须能被提取"的回归断言（superSecurePassword/EncryptedUsername/mySharedPreferences 三条作为 InsecureBankv2 基准用例）；③ 候选级凭证命中强制要求"值部分"非驼峰、长度 6~64、含数字或符号。

### NEW-02（P0）全部代码级规则无代码归因：HIGH/CRITICAL finding 无法定位、无法核验
- **复现 CLI**：`insight scan <InsecureBankv2.apk>` 后查看 ST-009/CR-007/PV-009/ST-005 的 `code_reference` 与 evidence。
- **期望**：每条 finding 至少给出 `业务类#方法`（如 `ChangePassword#updatePassWord`、`CryptoClass`），指向真实调用点。
- **实际**：ST-009 证据 = `['execSQL','android.database.sqlite.SQLiteDatabase.rawQuery']`（API 名）；CR-007 = 框架类名；PV-009 = `android.telephony.SmsManager.*`；ST-005 = gms playlog 类。`code_reference.file/class/line` 全空。RD-013 未修的后果被 Round 2 新规则放大：**新增的 4 条高价值规则全部是"无归属命中"**。
- **影响**：对比 MobSF 每条 finding 带文件/行号，本工具的 HIGH 结果在实战中等于"这个 App 某处可能有问题"，无法支撑复测与验证。
- **修复建议**：① `AnalysisContext.from_apk` 深度路径已能拿到 `method_refs`（`pkg.Class.method` 全名），把命中字符串/方法引用**回填到所属业务类**作为 `affected_component`，一个下午可实现；② 无法归因的代码级命中降级为 INFO + 标注"待核实线索"；③ `code_reference` 至少填 class 与 method（行号可诚实为 null）。

### NEW-03（P0）CP-004 在 6/6 靶场系统性误报：库类被判"Content Provider 导出(HIGH)"
- **复现 CLI**：`insight scan <任意一个靶场 APK>`（6 个靶场全部复现）。
- **期望**：组件导出类结论只来自 Manifest（TrackUserContentProvider exported=false 是唯一业务 Provider，不应报 HIGH）。
- **实际**：证据形如 `Landroid/support/v7/media/RegisteredMediaRouteProvider$ReceiveHandler; (exported=未确认, 候选)`、`Landroidx/appcompat/widget/ShareActionProvider$...`、`Lorg/chromium/support_lib_boundary/...`——类名含 "Provider" 即触发，且**"候选/未确认"级结论以 HIGH 级入报告**。RD-003 的 `_exported_check` 只修了"无 manifest 数据时不报"，未修"有部分类名证据时的候选路径"。
- **影响**：每份报告必含一条 HIGH 误报，直接违反 Round 2 自己设定的"零框架类误报"目标。
- **修复建议**：① 候选级导出命中最高只能报 LOW/INFO，且 evidence 必须带"如何确认"指引；② 类名包含 Provider/Service/Receiver 的字符串需同时满足"在业务包内 ∧ Manifest 存在对应 `<provider>` 声明"才可升级；③ 把 6 个靶场的 CP-004 加入良性回归语料（期望零 HIGH）。

### NEW-04（P1）strings --sensitive 输出 25/27 为无归属库噪声，真实敏感串仍为零
- **复现 CLI**：`decompile strings <InsecureBankv2.apk> --sensitive`（27 条）与 `--pattern "superSecurePassword|password"`（0 条）。
- **期望**：敏感结果带 class/method 归属；DEX 中已证实的 `superSecurePassword` 等出现在结果中。
- **实际**：JSON 字段仅 `value/category/confidence/source/evidence_level`，无任何归属字段；25 条 AES_KEY(0.50) 候选是长 base64 库字符串（protobuf/gms 池），无一为真实密钥；`password` 词根在全部提取值上零命中，说明候选级启发式未覆盖"驼峰词中含 password"的字面量（`superSecurePassword` 是驼峰复合词）。
- **修复建议**：① 候选级词根匹配改为对 `(?i)(password|pwd|secret|token|key)` 的**子串**匹配而非词边界匹配；② 候选命中附 `xref_classes`（StringAnalysis 已能给出引用方法）；③ 用 superSecurePassword 作为 --pattern/--sensitive 的端到端回归用例。

### NEW-05（P1）manifest 结构化 JSON 缺失 android:debuggable / allowBackup 属性
- **复现 CLI**：`decompile manifest <InsecureBankv2.apk> --format json` → 顶层键仅 `package_name/version/min_sdk/target_sdk/app_name/permissions/components/exported_components`。
- **期望**：输出 `application_flags`（debuggable、allowBackup、networkSecurityConfig、cleartextTrafficPermitted）。
- **实际**：debuggable 信息完全不存在，导致 13 漏洞 #13（ViewInspector 调试接口）在当前架构下**不可能被任何规则检出**；allowBackup 备份风险同样无数据源。
- **修复建议**：AXML 解析处补 `application` 节点属性透出；新增 AA-010（debuggable=true）、ST-010（allowBackup=true）两条规则；此改动同时能把 #13 从"不可能"变为"可检出"。

### NEW-06（P1）库/业务分层在 APK 模式同样缺失（RD-011 只对目录模式做过局部处理）
- **复现 CLI**：`insight scan <InsecureBankv2.apk>`，统计 evidence 含 `com.google.android.gms|android.support|androidx` 的条目。
- **实际**：31 条中约 14 条为库证据（PV-001/002/005、CP-010/011/012、ST-005、CR-015 等），且 PV-001 的 IMEI 证据仍是 Round 1 同一个 `CastDevice.getDeviceId`。
- **修复建议**：按 Manifest package 前缀将 findings 分为 `app` / `library` 两组，默认只展示 app 组，`--include-libs` 展开库组；实现成本低（前缀判断已存在）。

### NEW-07（P1）Xposed 模块识别缺失（RD-015 未修，且属于培训资料库高频形态）
- **复现 CLI**：`insight scan <FoxMmm-0.5.4.apk>` → AA-004 INFO "Xposed 框架检测"。
- **修复建议**：入口检测 `assets/xposed_init` 与 `IXposedHookLoadPackage` 实现，命中则输出独立分类"Xposed 模块"，抑制 AA/NW 类规则或改写表述为"该模块作用于 X"。

### NEW-08（P1）AA-003 证据为原始正则文本，可读性与可信度双输
- **复现 CLI**：`insight scan <app_vul_test.apk>` → AA-003 evidence 为整段 TLD 正则（数百字符）。
- **期望**：证据为命中的具体字符串值或类名。
- **修复建议**：evidence 生成时禁止输出正则源码；对 pattern 命中输出**被命中的原始字符串**（截断至 80 字符），正则源码放入 `rule.explain`。

### NEW-09（P2）`poc generate --rank` 越界静默回退 Top1
- **复现 CLI**：`poc generate --goal basic-hook --hook-point rec.json --rank 99` → success=true、warnings=[]（实际使用 Top1）。
- **修复建议**：越界时 warning 指明"rank 99 超出 1~10，已回退 rank 1"，或退出码 2。

### NEW-10（P2）`poc generate` payload 中 `output_path` 恒为 null
- **复现 CLI**：`poc generate --goal ssl-bypass --output x.js` → 文件已落盘，但 JSON 中 `output_path: None`。流水线消费方无法从返回值得知产物位置。
- **修复建议**：落盘成功后回填绝对路径。

### NEW-11（P2）decompile run 5000 文件截断仍无 skipped 清单
- **复现 CLI**：`decompile run <InsecureBankv2.apk> -o out_ib2_r2` → 仅一句 `[WARN] 已截断`，无被跳过类列表文件。6529 类中 1529 类去向不可知。
- **修复建议**：输出 `skipped_classes.txt` 并在 summary 中给出 skipped 计数与业务类 skipped 计数。

### NEW-12（P2）hook recommend 技法统计口径与去重缺失叠加，Top-N 有效率仅 70%
- **复现 CLI**：`hook recommend <InsecureBankv2.apk> --top 10` → 10 行中 3 行重复（见 RD-009）。
- **修复建议**：按 `class#method` 去重后取 Top-N，技法合并展示为 `base64,string`；同时输出 `unique_points` 计数。

---

## 6. 更新后的总体评分：6.5 / 10（Round 1：5 / 10）

| 模块 | Round 1 | Round 2 | 变化说明 |
|---|---|---|---|
| shell detect | 7 | 7 | 日志修复，但 confidence 恒定问题原样 |
| decompile manifest | 8 | 8 | 保持；但缺 debuggable/allowBackup 成为覆盖率瓶颈 |
| decompile strings | 2 | 4 | --sensitive 从 0→27 条、--pattern 生效；但真实敏感串仍为零、无归属 |
| decompile search/run | 3 | 5 | run 降级标注到位；search LINE=0 原样 |
| insight scan | 4 | 5.5 | 触发 12/13、CP 类接 manifest；但 CRITICAL 证据无效 + 库类误报拉低可信度 |
| hook recommend | 7 | 7 | 日志修复；去重/截断原样 |
| poc | 6 | 7 | 链路打通 + --output 修复；validate/param-types 原样 |
| 日志/管道可用性 | 1 | 9 | RD-001 修复质量高（55MB→0 字节） |

评分理由：Round 2 兑现了全部承诺的"工程可用性"（日志、流水线、标注、manifest 集成、2 条新规则），没有破坏性回归，测试覆盖率高——这部分值得肯定。但渗透测试的核心诉求"每条结论可复现、可定位"在 Round 2 结束后依然不成立：CRITICAL 证据无效、HIGH 无代码归因、每场必现的 CP-004 误报。从 6.5 到 8 的路径非常清晰：**归因 + 证据质量**，不需要新功能。

---

## 7. Round 3 优先修复建议（按影响力排序）

1. **【P0】代码级规则归因回填（NEW-02）**：`from_apk` 深度路径已有 `method_refs` 全名，把 ST-009/CR-007/PV-009/ST-005/CR-006 的命中映射到 `业务类#方法` 并写入 `code_reference`；无归因命中降级 INFO。预期效果：可靠检出 3/13 → 6/13（#4、#11、#12 从误报性命中转为真实定位），且所有 HIGH 可被人工核验。工作量约 1~2 天。
2. **【P0】ST-007 证据质量 + 敏感串回归基准（NEW-01/NEW-04）**：修 `find_password_literals` 护栏反向误伤；建立"InsecureBankv2 三字符串必须被 strings --sensitive 与 ST-007 同时命中"的端到端回归。预期效果：#1 从部分转检出，--sensitive 价值从 0 变实。工作量 1 天。
3. **【P0】CP-004 候选级降级（NEW-03）**：候选级导出结论最高 LOW；6 靶场加入零 HIGH 误报回归。工作量半天。
4. **【P1】manifest 透出 debuggable/allowBackup + 新增 AA-010/ST-010（NEW-05）**：直接补齐 #13，13 漏洞口径 +1。工作量半天。
5. **【P1】库/业务分组输出（NEW-06）**：app 组默认、library 组折叠。预期误报观感减半。工作量半天。
6. **【P1】Xposed 模块分类（NEW-07）**：培训资料库高频形态，一小时工作量，显著提升"懂行"观感。
7. **【P1】补 P1 欠账**：RD-007（validate 占位符，半天）、RD-009（hook 去重，半天）、RD-012（错误出口统一，半天）、RD-013（search STRING 归属，1 天）。
8. **【P2】体验项**：RD-016 help 枚举全集、RD-017 脚本符号/--no-pause、RD-019 confidence 特征化、NEW-09/10/11、RD-020 分析缓存（缓存收益最大，建议 `--cache-dir` + androguard Session）。

---

## 8. 最终验收判断

- **是否可进入第三轮：可以。** 6 条 P0 中 3 条完全修复、3 条部分修复，修复方向全部正确，无破坏性回归（653 用例通过 + 本轮实测验证一致）；Round 3 有明确、低成本的提升路径（上述 1~3 项合计约 3 天即可把可靠检出推到 6+/13 并消除系统性 HIGH 误报）。
- **是否可发布：不可以。** 发布门槛建议：
  1. 13 已知漏洞可靠检出 ≥ 8/13（当前 3/13）；
  2. HIGH 及以上误报 = 0（当前每场必现 CP-004）；
  3. 所有 CRITICAL/HIGH finding 带类#方法归因（当前为 0%）；
  4. `poc validate` 不再对含占位符脚本给 100 分。
  四项中前三项达成前，产品对外口径应维持"研究/教学预览版"。

---

## 附：本轮主要留档（`C:\Users\lenovo\xuanjian-ai\round2_retest\`）

| 文件 | 内容 |
|---|---|
| `shell_out.txt` / `shell_err.txt` | RD-001：stdout 1 行纯净结果 / stderr 0 字节 |
| `insight_ib2.json` | InsecureBankv2 APK 模式 31 条 findings 全量 JSON |
| `insight_dir2.json` / `insight_dir_old.json` | 目录模式 14 条（新产物）与旧产物对照 |
| `hook_ib2_r2.json` / `hook_out.txt` / `hook_err.txt` | hook recommend：10 点位 JSON / 表格 / stderr 0 字节 |
| `poc_gen_out.json` / `poc_rank2.js` / `poc_ssl_direct.js` / `rd008b.json` | RD-004/RD-008 全链路证据 |
| `strings_sensitive.json` / `strings_pattern.txt` / `strings_known.txt` | RD-002 三组验证 |
| `manifest_ib2.json` | Manifest 结构化输出（缺 debuggable 的证据） |
| `out_ib2_r2/` / `decompile_run.txt` | RD-006 大纲模式产物与标注 |
| `mini/` / `mini_out.json` / `mini_signals.json` | 目录模式 vs JSON 模式对照实验 |
| `rd018.json` / `rd008*.json` | RD-018/RD-008 复测证据 |

*报告完 — Round 2 复测。Round 3 重点：证据归因（一条主线贯穿 NEW-01/02/03/04），而非继续堆规则数量。*
