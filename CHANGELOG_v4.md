# 玄鉴 v4.0.0 变更日志

发布日期：2026-09（v4.0 移动安全能力版）
相对基线：v3.1.0（服务端代码审计/误报排查 MCP）

---

## 1. 新增模块

| 模块 | 能力 | 说明 |
|---|---|---|
| `fp_sentinel/mobile_shell` | ① 砸壳 | 加固检测（360/腾讯/梆梆/爱加密/娜迦/百度/阿里）、Android 动态/静态脱壳、iOS 脱壳（越狱）、批量处理；集成 BlackDex / frida-dexdump |
| `fp_sentinel/mobile_decompile` | ② 反编译 | APK/DEX 解析、jadx/androguard 双引擎（缺失 jadx 时大纲模式诚实降级）、关键字搜索（TEXT/STRING/CALL/XREF）、字符串提取、Manifest 解析（含 application flags）、类层次结构 |
| `fp_sentinel/mobile_hook` | ③ Hook 定位 | 7 种技法（keyword/collection/toast/log/json/string/base64）、关键性评分推荐、组合扫描、mock 验证、Frida 脚本导出 |
| `fp_sentinel/mobile_insight` | ④ 技术提示 | 67 条规则（存储/网络/加密/组件/反分析/隐私）、凭证证据分级（LEVEL1~3 动态定级）、代码级归因（class#method）、库/业务/框架分层与落点降级、PYTHONHASHSEED 确定性输出 |
| `fp_sentinel/mobile_poc` | ⑤ Frida POC | goal 驱动生成（ssl-bypass/root-bypass/签名绕过等）、模板引擎（Java/JS/Native/iOS）、schema 校验、占位符/红线检查、批量生成、越界防护、受控执行 |
| `fp_sentinel/mobile_common` | 公共底座 | 日志等公共配置 |

CLI 统一入口：`python -m fp_sentinel mobile {shell|decompile|hook|insight|poc} ...`（五组子命令聚合在 `mobile` 组下）。

## 2. 相对 v3.1.0 的全部变更

### 新增（New）

- 新增移动端六大能力与对应 CLI 命令组（见上表），v3.x 服务端命令（`scan`/`mcp`/`devops`/`privacy`/`kg`/`fp`/`auto-pr`/...）全部保留、无破坏性变更。
- 新增移动端规则体系：67 条规则，全部对齐 CWE 与 OWASP MASVS，附带 Hook/验证技法建议与修复提示。
- 新增证据归因体系：DEX string/invoke → `class#method` 归因索引（进程内缓存）、跨证据业务类优先定位、来源五分类（business/library/framework/obfuscated/unattributed）与分类分布统计。
- 新增凭证证据分级器：`[LEVEL3]/[LEVEL2]/[LEVEL1]` 前缀动态定级 ST-007；HTTP 头名/URL/大写常量/类型描述符/文件名/PascalCase/蛇形标识符等排除规则；**v4.0 收尾补充**：UI 资源描述符（`*_contentDescription/*_hint/*_label/*_title/*_text/*_desc`）、抽象名词字段（`encodedPassword`/`passwordHash` 等）、技术标识（`passwordPolicy`/`passwordColonOffset` 等）、开发占位符（`<password>`/`%s`/`${...}`/`{...}`/`{{}}`）。
- 新增 framework/library 归因落点降级：`android.*`/`androidx.*` 等框架命名空间与 `okhttp3.*`/`okio.*`/`retrofit2.*`/`gson.*`/`org.jetbrains.*`/`com.bumptech.*`/`org.chromium.*`/`com.tencent.bugly.*`/`com.umeng.*`/`rx.*` 等三方库命名空间内部落点不构成应用自身漏洞面，严重级别降档且封顶 MEDIUM。
- 新增 Manifest 深度解析：`debuggable`/`allowBackup`/`network_security_config` 透出（ST-010 CRITICAL / ST-011 MEDIUM 规则随之新增）。
- 新增组件规则门控：导出组件类规则仅信任 Manifest 精确解析的结构化组件（`exported_by_kind`），库类证据不再触发（CP-004 误报根除）。
- 新增确定性保障：扫描结果对 `PYTHONHASHSEED` 逐条一致（证据全序排序、集合遍历字典序化），含回归测试守护。
- 新增 Xposed 语义双角色（AA-004 `[module=attack]`/`[detector=defense]`）与 AA-003 证据片段化（不再输出正则源码）。
- 新增 POC 生成防护：`--rank` 越界显式报错（不静默回退）、占位符包名扣分、红线操作检查。

### 修复（Fixed，相对 v3.1 已知问题）

- 错误收敛：坏 APK/不存在路径输出单行友好 JSON，无 Python 堆栈；全线 stderr 0 字节。
- 证据治理：框架/库类名白名单过滤、XML/资源标记过滤、业务证据优先排序。

### 变更（Changed）

- 测试体系：新增五模块 700+ 用例（含真实靶场 APK 端到端用例），覆盖率 ≥95%（pytest-cov 阈值校验）。
- 文档：新增 `README_v4.md`、`docs/api-reference-v4.md`、`docs/KNOWN_ISSUES.md` 与本变更日志（v3.1 文档保留）。

### 验收基线（v4.0 发布验证）

- InsecureBankv2 主靶场 13 已知漏洞：规则触发 13/13，可靠检出 8/13（终验口径，≥8 达标）；
- 三靶场（InsecureBankv2/OVAA/TestVuls）HIGH+ 误报 = 0（库/框架落点与假凭证全部降级/排除）；
- CP-004 库类误报 6/6 靶场根除；扫描确定性 4 种子一致。

## 3. 已知问题

见 `docs/KNOWN_ISSUES.md`（jadx 缺失时的定位限制、strings --sensitive 价值边界、RealFridaClient 未实测、启发式规则边界、未闭环 P2 清单等）。
