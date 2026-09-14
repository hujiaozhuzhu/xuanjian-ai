# 玄鉴 v4.0 发布就绪报告（Release Ready Report）

- 日期：2026-09-14
- 范围：Round 3 终验（`docs/round3_expert_final_report.md`）发布条件 C1~C4 收尾验证
- 结论：**发布就绪（READY）** —— 4 项收尾工作全部完成，748+ 用例无回归，6 靶场 HIGH+ 库/框架落点误报 = 0

---

## 1. C1~C4 完成状态

| 项 | 内容 | 状态 |
|---|---|---|
| C1 | framework/library 前缀清单补齐 + 库落点降级 | ✅ 完成 |
| C2 | 凭证分级器排除规则（UI 资源/抽象名词/占位符/技术标识）+ 测试 | ✅ 完成 |
| C3 | README_v4 / api-reference-v4 / CHANGELOG_v4 / KNOWN_ISSUES 四份文档 | ✅ 完成 |
| C4 | 全量测试 + 覆盖率 ≥95% + 靶场复测 + 本报告 | ✅ 完成 |

### C1 具体改动（`fp_sentinel/mobile_insight/core/context.py`、`core/engine.py`）

1. `androidx.` 纳入 `_FRAMEWORK_ONLY_PREFIXES`，与 `android.support.*` 同级 —— `classify_class("androidx.*")` 返回 `framework`，归因落点走框架降级（终验 R3.1b 覆盖缺口闭合）。
2. 库前缀白名单（`FRAMEWORK_PREFIXES`，classify_class → `library`）新增：`okhttp3.`、`okio.`、`retrofit2.`、`gson.`、`com.google.gson.`、`org.jetbrains.`、`com.bumptech.`、`org.chromium.`、`com.tencent.bugly.`、`com.umeng.`、`rx.`。`kotlin./kotlinx./io.reactivex./com.facebook./com.squareup.` 原有保留（kotlin 系归 framework 分层，同样降级）。
3. **降级语义收紧（engine.py）**：framework 落点维持"降一档"；library 落点新增"至少降一档"；framework/library 落点最终封顶 MEDIUM（CRITICAL 经降级仍为 HIGH 时继续降一档）。依据终验验收标准"HIGH+ 库/框架落点 = 0"。既有测试 `test_framework_attribution_downgrades_but_keeps_location` 预期随之由 HIGH 更新为 MEDIUM（策略变更，注释已同步）。

### C2 具体改动（`fp_sentinel/mobile_insight/rules/context_filters.py`）

1. **UI 资源描述符后缀**：`*_contentDescription`/`*_hint`/`*_label`/`*_title`/`*_text`/`*_desc`（`_UI_RESOURCE_SUFFIX_RE`，要求下划线/连字符边界，防误杀散文）。
2. **抽象名词/技术标识（复合标识符判定 `_compound_tech_identifier`）**：全串为驼峰/蛇形标识符、含口令词根（password/passwd/pwd）、其余段全部命中技术词表 → 判定为字段名/资源名。覆盖 `encodedPassword`/`hashedPassword`/`encryptedPassword`/`passwordHash`/`passwordSalt`/`passwordToggle`/`passwordStrength`/`passwordAuth`/`passwordPolicy`/`passwordField`/`passwordType`/`passwordColonOffset`/`TextInputLayout_passwordToggle*` 系列/`confirm_device_credential_password` 等。修饰词（super/secure/very 等）不在词表，真实口令 `superSecurePassword` 基准不回退（回归测试守护）。
3. **开发占位符**：`_PLACEHOLDER_VALUE_RE` 扩充 `%s`（及 `%d/%f` 等格式化符）、`{...}`、`{{}}`；`<password>`/`${...}` 原有保留。另增 KV 形态右侧短占位守卫（`password=%s` → 0）。
4. **测试**：新增 `fp_sentinel/mobile_insight/tests/test_v4_release.py`（34 用例），覆盖 C1 前缀分类、库落点 HIGH+ 封顶、四类排除、占位符、基准不回退、混合上下文真凭证存活；`test_round3.py` 中 androidx 分类断言同步更新。

### C3 文档交付物

| 文件 | 内容 |
|---|---|
| `README_v4.md` | 项目简介（六大能力）、快速开始、每能力 2-3 个 CLI 示例、CLI 速查表、与 v3.x 关系说明 |
| `docs/api-reference-v4.md` | 全部子命令参数说明、insight 输出 JSON schema、归因/降级语义、退出码规范 |
| `CHANGELOG_v4.md` | 新增模块清单、相对 v3.1.0 全部变更、验收基线、已知问题指引 |
| `docs/KNOWN_ISSUES.md` | KI-01~KI-09 + 未闭环 P2 清单（RD-013/016~020、NEW-04/10/11/12） |

---

## 2. 测试结果（C4.1/C4.2）

```
python -m pytest fp_sentinel/mobile_shell fp_sentinel/mobile_decompile \
  fp_sentinel/mobile_hook fp_sentinel/mobile_poc fp_sentinel/mobile_insight \
  --cov=fp_sentinel/mobile_shell --cov=fp_sentinel/mobile_decompile \
  --cov=fp_sentinel/mobile_hook --cov=fp_sentinel/mobile_poc \
  --cov=fp_sentinel/mobile_insight --cov-report=term -q

753 passed in 317.45s
Required test coverage of 95.0% reached. Total coverage: 96.05%   (7814 stmts, 201 miss)
```

- **无回归**：753 通过 / 0 失败（终验时 748 通过；净增为 v4.0 收尾新用例）。
- **覆盖率 ≥95% 达标**：五模块合计 96.05%。说明：任务书中的 `--cov=fp_sentinel/mobile_` 写法在 coverage 7.16 下解析为模块名并告警 no-data，改用五个模块路径的等价写法获得真实覆盖率。
- 移动端五模块测试含 InsecureBankv2/OVAA 真实 APK 端到端用例与 `PYTHONHASHSEED` 确定性回归用例。

## 3. 最终验证数据（C4.3/C4.4）

### 3.1 六靶场 HIGH+ 复核（最终代码全量重扫，原始 JSON 见 `release_verify/`）

| 靶场 | findings | HIGH+ | 库/框架落点 HIGH+ | HIGH+ 全部归因 |
|---|---|---|---|---|
| InsecureBankv2（主靶场） | 34 | 8 | **0** | ✅ 全部 business |
| OVAA（app_vul_test） | 35 | 6 | **0** | ✅ 全部 business |
| TestVuls | 21 | 2 | **0** | ✅ 全部 business |
| vuls_v4.4 | 39 | 8 | **0** | ✅ 全部 business |
| 指纹识别绕过demo | 24 | 1 | **0** | ✅（ST-010 Manifest） |
| FoxMmm | 29 | 10 | **0** | ✅ 全部 business（应用内混淆类） |
| **合计** | 182 | 35 | **0** | — |

- **任务书要求（三靶场 HIGH+ 误报 = 0）达成**；终验报告要求的"6 靶场 HIGH+ 库/框架落点 = 0"同样达成。
- 全部 stderr 0 字节；无 Python 堆栈泄漏。

### 3.2 修复前后对照（HIGH+ 误报清零明细）

| 终验误报项 | 终验级别 | 修复后 |
|---|---|---|
| OVAA NW-004/NW-005 CRITICAL @ okhttp3.internal | CRITICAL | library 落点 → **MEDIUM**（保留真实落点） |
| OVAA NW-002 HIGH @ okhttp3 / vuls NW-004 CRITICAL、NW-002 HIGH @ okhttp3 | CRITICAL/HIGH | → **MEDIUM** |
| OVAA CP-012 HIGH、指纹demo ST-004/CP-012 HIGH @ androidx | HIGH | androidx→framework → **MEDIUM** |
| vuls/TestVuls/OVAA ST-007 HIGH/CRITICAL（TextInputLayout_passwordToggleContentDescription、encodedPassword 等假凭证） | HIGH/CRITICAL | **排除/不触发**（C2） |
| IB2 NW-001/CP-008 HIGH @ com.google.android.gms | HIGH | library 落点 → **MEDIUM**（可核验性保留） |
| 指纹demo ST-007 HIGH（TextInputLayout_passwordToggle* 资源名） | HIGH | **排除/不触发**（C2） |

### 3.3 不回退验证（关键基准保留）

- IB2 `superSecurePassword` → `[LEVEL3]` → ST-007 **CRITICAL**，归因 `com.android.insecurebankv2.ChangePassword#access$200`（真实漏洞面，终验 #1 可靠检出）✅
- IB2 13 已知漏洞规则触发覆盖不变（HIGH+ 8 条全部业务归因，与终验"可靠检出 8/13"一致）✅
- 确定性：IB2 以默认/`PYTHONHASHSEED=7`/`PYTHONHASHSEED=42` 三种子扫描，34 条 findings 逐条一致 ✅
- IB2/OVAA/TestVuls/vuls ST-010（debuggable）等 Manifest 规则行为不变 ✅

### 3.4 复核备注

- FoxMmm 的 HIGH+（`zu0#c` 等应用内混淆类、`com.fox2code.mmm.*`）均为该应用自身（混淆后的网络/应用代码），classification=business，属可核验调用点而非库/框架误报；混淆类的 business/obfuscated 边界已在 KNOWN_ISSUES（启发式边界）中说明。
- IB2 ST-007 证据中 `broadcastChangepasswordSMS`/`newpassword` 等仍为 L3 候选（业务包字段名形态），属启发式规则的已知边界（KI-02），不构成库/框架落点误报。

## 4. 发布判断

**READY。**

- 终验报告发布条件：主靶场可靠检出 ≥8/13 ✅（8/13）、CP-004 误报 0 ✅、HIGH+ 库/框架落点 = 0 ✅、关键测试 100% 通过 ✅、扫描确定性 ✅、全量测试 753/753 ✅、覆盖率 96.05% ≥95% ✅、C1~C4 全部闭环 ✅。
- 残留风险均已显式登记于 `docs/KNOWN_ISSUES.md`（jadx 缺失定位限制、RealFridaClient 未实测、启发式规则边界、RD/NEW 编号 P2 项），均为能力边界或非阻断缺陷，不影响发布。

### 改动清单（本次收尾）

| 文件 | 变更 |
|---|---|
| `fp_sentinel/mobile_insight/core/context.py` | C1 前缀清单 |
| `fp_sentinel/mobile_insight/core/engine.py` | C1 库落点降级 + HIGH+ 封顶 |
| `fp_sentinel/mobile_insight/rules/context_filters.py` | C2 四类排除规则 |
| `fp_sentinel/mobile_insight/tests/test_round3.py` | androidx 断言 / 框架 CRITICAL 封顶预期更新 |
| `fp_sentinel/mobile_insight/tests/test_v4_release.py` | 新增 34 用例 |
| `README_v4.md` / `docs/api-reference-v4.md` / `CHANGELOG_v4.md` / `docs/KNOWN_ISSUES.md` | C3 文档 |
| `release_verify/*.json|*.err` | 六靶场发布验证原始数据 |
