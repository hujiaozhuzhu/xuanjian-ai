# 玄鉴 v4.0 已知问题清单（KNOWN ISSUES）

> 状态基准：v4.0 发布前（Round 3 终验 + 收尾修复 C1~C4 之后）。
> 修复情况与验证数据见 `docs/release_ready_report.md` 与 `docs/round3_expert_final_report.md`。

## 1. 能力边界类

### KI-01 jadx 缺失时的行级定位限制
- **现象**：未安装 jadx 时，`decompile run` 自动降级为 androguard **大纲模式**（类/方法签名级，非源码）；`insight scan` 的归因提供 `class#method`，但无 `file:line`。
- **影响**：渗透报告无法直接给出代码行号，需按类名人工定位。
- **缓解**：安装 jadx 后 `decompile run --engine auto` 即可获得源码与行级定位；归因的 `class#method` 在大纲模式下仍可复测。
- **计划**：v4.1 考虑 jadx 深度集成与 `file:line` 回填。

### KI-02 正则规则本质为启发式
- **现象**：67 条规则以 DEX 字符串池/类名/方法引用/Manifest 为信号源，属静态启发式匹配。个别 L3 凭证候选可能实为业务字段名（如 IB2 的 `broadcastChangepasswordSMS`/`supportsPasswordLogin` 形态），且"复杂度校验缺失"类语义漏洞（如 IB2 #2 弱密码策略）无规则覆盖。
- **影响**：证据需人工确认；部分已知漏洞只能"部分检出"。
- **缓解**：凭证分级器已排除资源名/抽象名词/占位符/技术标识四类假凭证（C2）；每条证据附 `class#method` 归因可快速人工复核。
- **定位**：这是工具定位（技术提示 + 动态验证入口），不承诺替代人工审计。

### KI-03 `strings --sensitive` / `decompile search` 的归属边界
- **现象**：`strings --sensitive` 的候选目前主要为库内字符串（gms 等），真实凭证检出路径在 `insight scan`（ST-007 分级证据）；`decompile search` 的 STRING 命中暂无 `class#method` 归因（RD-013 未闭环）。
- **计划**：v4.1 将归因索引接入 search，并把 ST-007 分级结果并入 `--sensitive` 输出。

### KI-04 RealFridaClient 未实测
- **现象**：`mobile_poc` 的 `poc run` / 实机执行链路（RealFridaClient）未在真机环境完成实测验证；`hook verify` 与 `poc validate` 为 mock 化（脚本合法性 + 静态一致性）。
- **影响**：POC 生成/校验链路可靠，**实机执行结果需测试人员自行在授权设备上验证**。
- **计划**：v4.1 补充真机验收。

### KI-05 shell detect confidence 恒定
- **现象**：`shell detect` 的 `confidence` 固定 0.85（RD-019），未按命中特征分级。
- **计划**：v4.1 输出命中特征列表 + 分级置信度。

### KI-06 无跨命令分析缓存
- **现象**：每次解析同一 APK 独立耗时约 17~46s，`hook`/`strings`/`insight` 串行工作流重复解析（RD-020）。
- **缓解**：进程内归因索引缓存已消除同进程内重复构建。
- **计划**：v4.1 提供 `--cache-dir` 会话级缓存。

## 2. 已在本轮（v4.0 收尾）修复的条目

### KI-07 okhttp3/okio 库归因（✅ 已于本轮修复）
- **历史**：Round 3 终验发现 `okhttp3.*`/`okio.*` 未列入库前缀白名单，okhttp 内部代码以 CRITICAL/HIGH 入报告（OVAA 2C+1H、vuls 1C+1H）。
- **修复**：C1 补齐库前缀白名单 + 库/框架落点降级封顶 MEDIUM；三靶场复测 HIGH+ 误报 = 0（见 release_ready_report）。

### KI-08 androidx 框架降级缺口（✅ 已于本轮修复）
- **历史**：`androidx.*` 未纳入 framework 落点降级名单，OVAA/指纹demo 上 androidx 落点保持 HIGH。
- **修复**：C1 将 `androidx.` 与 `android.support.*` 同级处理（classify_class → framework，落点降级）。

### KI-09 凭证假阳性长尾（✅ 已于本轮修复）
- **历史**：`TextInputLayout_passwordToggleContentDescription`（资源名）、`encodedPassword`（okhttp 字段名）、`passwordColonOffset` 产生 3 处 HIGH+ 假凭证。
- **修复**：C2 排除 UI 资源描述符后缀、复合技术标识符（驼峰/蛇形切分 + 技术词表）、开发占位符；`superSecurePassword` 基准不回退（有回归测试）。

## 3. 未闭环 P2 清单（继承自终验报告，均有明确编号）

| 编号 | 问题 | 状态 |
|---|---|---|
| RD-013 | `decompile search` STRING 命中无 class#method 归因 | 未闭环（v4.1 接线归因索引） |
| RD-016 | help 文本枚举截断（`hook recommend --help` goal 列表、`insight scan --help` 取值说明） | 未闭环 |
| RD-017 | POC 脚本含 Unicode 符号，需清理 | 未闭环 |
| RD-018 | POC 生成 `--no-pause` / `--param-types` 重载过滤不完整 | 未闭环 |
| RD-019 | `shell detect` confidence 恒 0.85（同 KI-05） | 未闭环 |
| RD-020 | 无跨命令分析缓存（同 KI-06） | 未闭环 |
| NEW-10 | `poc generate --output` 落盘成功但 JSON `output_path` 恒 null | 未闭环 |
| NEW-11 | `decompile run` 大纲模式 5000 文件截断无 skipped 清单 | 未闭环 |
| NEW-12 | `hook recommend` 同一物理点位可占多个 Top-N 槽位，无 `unique_points` 计数 | 部分闭环（技法级去重已实现） |
| NEW-04 | `strings --sensitive` 真实凭证仍为零、`--pattern` 子串匹配未打通 | 部分闭环（同 KI-03） |

## 4. 使用注意

- 所有能力均为**授权测试场景**设计；`poc run` 要求 `--package` 授权确认。
- `insight scan` 结果对 `PYTHONHASHSEED` 确定性（跨进程可复现），但规则升级会改变结果基线——升级版本后建议重新留档。
