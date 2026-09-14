# 玄鉴 v4.0 移动端 CLI API 参考

- 入口：`python -m fp_sentinel mobile <组> <子命令> [参数]`
- 适用模块：`mobile_shell` / `mobile_decompile` / `mobile_hook` / `mobile_poc` / `mobile_insight`
- 通用约定：
  - 结构化结果均为**纯 stdout JSON**（可直接 `json.load`），诊断/警告走 stderr（正常情况 stderr 为 0 字节）；
  - `--format text/json/markdown` 控制人类可读/结构化输出（各命令可用值见下表）；
  - 目标文件不存在或类型不支持时输出单行 `{"success": false, "error": "..."}` 并以非零码退出，不抛 Python 堆栈。

---

## 1. mobile shell —— 砸壳（能力①）

### 1.1 `shell detect <target>`

| 项 | 说明 |
|---|---|
| 作用 | 自动识别加固类型：360 / 腾讯 / 梆梆 / 爱加密 / 娜迦 / 百度 / 阿里 / 无壳 |
| 参数 | `target`（必填）：APK/IPA 路径；`--json`：JSON 输出 |
| 输出 | 加固厂商判定、命中的特征文件/类名列表；`confidence` 当前为固定启发值（见 KNOWN_ISSUES） |

```bash
python -m fp_sentinel mobile shell detect app.apk --json
```

### 1.2 `shell dump-android`

| 项 | 说明 |
|---|---|
| 作用 | Android 脱壳：优先 frida-dexdump 动态 dump，无设备/失败时降级 androguard 静态检测 |
| 参数 | `--apk`（必填）APK 路径；`--output` 输出目录（默认 `./reports/mobile_shell/`）；`--mode auto/static`；`--device` USB 设备 ID |

### 1.3 `shell dump-ios`

| 项 | 说明 |
|---|---|
| 作用 | iOS 脱壳：frida-ios-dump（需越狱设备），降级检测模式 |
| 参数 | `--app` IPA 路径；`--package` 目标包名；`--output`；`--device` 设备 UDID |

### 1.4 `shell batch <directory>`

| 项 | 说明 |
|---|---|
| 作用 | 批量检测 + 脱壳目录内所有安装包 |
| 参数 | `directory`（必填）；`--output`；`--platform all/android/ios`；`--mode auto/static` |

---

## 2. mobile decompile —— 反编译（能力②）

### 2.1 `decompile run <target>`

| 项 | 说明 |
|---|---|
| 作用 | 完整反编译。jadx 可用时输出源码（行级定位可用）；缺失时自动降级 androguard 大纲模式并在结果中标注 |
| 参数 | `target`（必填）APK/DEX；`--engine auto/jadx/androguard`；`-o/--output` 源码输出目录；`--format text/json/markdown`；`--call-graph` 同时构建调用图 |
| 注意 | 大纲模式下源码文件数上限 5000，超出部分截断且暂无 skipped 清单（见 KNOWN_ISSUES） |

### 2.2 `decompile search <target> <keyword>`

| 项 | 说明 |
|---|---|
| 作用 | 关键字搜索，四种匹配类型 |
| 参数 | `-t/--type text/string/call/xref`（默认全部）；`--scope` 类名前缀过滤；`--limit`（默认 50）；`--format text/json/markdown` |
| 输出 | JSON 含 `match_type` 与命中项；STRING 类命中当前无 class#method 归因（RD-013，见 KNOWN_ISSUES） |

### 2.3 `decompile strings <target>`

| 项 | 说明 |
|---|---|
| 作用 | 字符串提取：URL/Token/密钥/API endpoint/包名/手机号/邮箱 |
| 参数 | `--pattern` 过滤关键字；`--sensitive` 仅输出凭证/密钥类高敏结果；`--limit`（默认 100）；`--format text/json` |
| 注意 | `--sensitive` 的候选主要来自库内字符串，真实凭证检出依赖 insight ST-007 分级（见 KNOWN_ISSUES） |

### 2.4 `decompile manifest <target>`

| 项 | 说明 |
|---|---|
| 作用 | Manifest 解析：包名/版本/权限/组件/导出组件/Intent Filter |
| 参数 | `--format text/json` |
| JSON 顶层 | `package_name`、`version_*`、`permissions`、`components[]`（含 `type`/`name`/`exported`）、`application_flags: {debuggable, allow_backup, network_security_config, uses_cleartext_traffic}` |

### 2.5 `decompile hierarchy <target>`

| 项 | 说明 |
|---|---|
| 作用 | 类层次结构（继承树） |
| 参数 | `--root` 从指定类开始展示子树；`--format text/json/markdown` |

---

## 3. mobile hook —— Hook 定位（能力③）

### 3.1 `hook recommend <apk>`

| 项 | 说明 |
|---|---|
| 作用 | 七技法自动推荐 Hook 点位，关键性评分排序 |
| 参数 | `-g/--goal`（默认 `encrypt-trace`，可选 `encrypt-trace/request-plaintext/signature-bypass/...`）；`-n/--top`（默认 10）；`-o/--output` 结果 JSON 文件 |
| 注意 | 同一技法去重，但同一物理点位可能以不同技法占据多个槽位（RD-009/NEW-12，见 KNOWN_ISSUES） |

### 3.2 `hook technique <name>`

| 项 | 说明 |
|---|---|
| 作用 | 执行单一技法（独立可运行，含脚本模板导出） |
| 参数 | `name`（必填）：`keyword/collection/toast/log/json/string/base64`；`--apk`（必填）；`-g` 分析目标；`-o` 结果 JSON；`--script` 同时导出 Frida 脚本路径 |

### 3.3 `hook scan <apk>`

| 项 | 说明 |
|---|---|
| 作用 | 组合技法扫描（多技法并行、统一评分） |
| 参数 | `-t/--techniques` 逗号分隔技法列表或 `all`；`-g`（默认 `request-plaintext`）；`-n`（默认 20）；`-o` |

### 3.4 `hook verify <hook_point_file>`

| 项 | 说明 |
|---|---|
| 作用 | 验证 Hook 点位（mock 化：脚本合法性 + 静态一致性，不连接设备） |
| 参数 | `hook_point_file`（必填，recommend/technique 的输出）；`-d` 设备序列号（mock） |

---

## 4. mobile poc —— Frida POC 生成（能力⑤）

### 4.1 `poc generate`

| 项 | 说明 |
|---|---|
| 作用 | 依据 goal + hook 点位/类方法生成 Frida POC |
| 参数 | `--goal`（必填，如 `ssl-bypass`/`root-bypass`；全集见 `poc goals`）；`--hook-point` hook 点位 JSON；`--class-name`/`--method-name`/`--package`(或 `--apk`)；`--param-types` 重载过滤；`--output` 脚本落盘路径；`--rank` 候选点位序号（默认 0，**越界报错不回退**）；`--no-save` 不落盘仅 stdout |
| 注意 | `--output` 落盘成功时 JSON 中 `output_path` 恒为 null（NEW-10，见 KNOWN_ISSUES） |

### 4.2 `poc batch`

| 项 | 说明 |
|---|---|
| 作用 | 批量生成 |
| 参数 | `--hook-points`（必填）、`--goal`（必填）、`--output`（必填） |

### 4.3 `poc validate <script>`

| 项 | 说明 |
|---|---|
| 作用 | POC 合法性校验：schema、占位符包名（如 `com.target.app` 残留）、红线操作检查；占位符残留会扣分并输出 warning |
| 参数 | `script`（必填）；`--language` |

### 4.4 `poc run <script>`

| 项 | 说明 |
|---|---|
| 作用 | 受控执行（需目标包名授权） |
| 参数 | `script`（必填）；`--package`（必填）；`--authorized-packages` 授权包列表 |

### 4.5 `poc templates` / `poc goals`

列出内置脚本模板 / 支持的生成目标全集。

---

## 5. mobile insight —— 技术提示/App 审计（能力④⑥）

### 5.1 `insight scan <target>`

| 项 | 说明 |
|---|---|
| 作用 | 67 条内置规则全量审计（存储 11 / 网络 10 / 加密 15 / 组件 12 / 反分析 10 / 隐私 9） |
| 目标 | APK / 信号 JSON（`{"package_name":..., "strings":[...]}`）/ 反编译目录 |
| 参数 | `--category crypto/network/storage/component/anti-analysis/privacy`；`--min-severity INFO/LOW/MEDIUM/HIGH/CRITICAL`；`--output` 结果落盘；`--summary` 摘要输出；`--max-insights <n>` 限流 |

### 5.2 `insight rules`

列出全部规则（id/title/category/severity/cwe/masvs）。

### 5.3 输出 schema（`--output` / stdout JSON）

```jsonc
{
  "target": "app.apk",
  "insight_count": 34,               // findings 总数
  "rules_total": 67,                 // 注册规则数
  "rules_matched": 21,               // 命中规则数
  "duration_sec": 40.1234,
  "severity_distribution": {         // CRITICAL/HIGH/MEDIUM/LOW/INFO 计数
    "CRITICAL": 3, "HIGH": 5, "MEDIUM": 11, "LOW": 10, "INFO": 5
  },
  "classification_distribution": {   // 归因来源分布
    "business": 14, "library": 9, "framework": 6, "obfuscated": 0, "unattributed": 5
  },
  "insights": [
    {
      "id": "INS-ST-007",
      "rule_id": "ST-007",
      "title": "硬编码凭证(口令/API Key)",
      "category": "STORAGE",
      "severity": "CRITICAL",          // INFO/LOW/MEDIUM/HIGH/CRITICAL
      "confidence": 0.85,
      "description": "...",            // 风险解释
      "affected_component": "...",     // 首条证据
      "code_reference": {              // 归因位置（渗透复测入口）
        "file": "classes.dex",
        "class_name": "com.android.insecurebankv2.ChangePassword",
        "method_name": "access$200",
        "line": 0
      },
      "technical_context": "...",      // 动态验证思路（Hook/JDB 等）
      "suggested_technique": "string-dump(凭证构造点)",
      "estimated_difficulty": "中",     // 低/中/高
      "next_steps": ["...", "..."],
      "cwe_ids": ["CWE-798"],
      "masvs_refs": ["MASVS-STORAGE-1"],
      "references": ["https://mas.owasp.org/MASVS/..."],
      "auto_fixable": false,
      "fix_hint": null,
      "evidence": ["[LEVEL3] superSecurePassword", "..."],   // 最多 10 条
      "classification": "business"     // business/library/framework/obfuscated/unattributed
    }
  ]
}
```

**归因与降级语义（v4.0）**

- 代码级规则（`code_level=true`）自动经归因索引回填 `class#method`；跨证据定位业务类优先；
- 归因可用但失败 → 降一级并标注 `DEX string pool (unattributed)`；
- 归因落点为 **framework**（`android.*`/`androidx.*`/`java.*`/`kotlin.*`/`dalvik.*`）或 **library**（`okhttp3.`/`okio.`/`retrofit2.`/`gson.`/`org.chromium.`/`com.tencent.bugly.`/`com.google.*` 等，全量清单见 `fp_sentinel/mobile_insight/core/context.py` 的 `FRAMEWORK_PREFIXES`）→ 严重级别降档，**最终不高于 MEDIUM**（HIGH+ 库/框架落点 = 0）；
- Manifest 规则（ST-010/ST-011，`code_level=false`）不参与归因降级；
- ST-007 凭证证据分级：`[LEVEL3]`→CRITICAL、`[LEVEL2]`→HIGH、`[LEVEL1]`→MEDIUM；资源名/字段名/占位符形态（`*_contentDescription`、`encodedPassword`、`passwordPolicy`、`<password>`、`%s`、`${...}` 等）在分级器中排除。

### 5.4 退出码规范

| 退出码 | 含义 |
|---|---|
| 0 | 成功（含"扫描完成且零命中"） |
| 1 | 运行期错误（目标解析失败、内部异常被收敛为友好 JSON 的场景视实现返回 1 或 2） |
| 2 | 用法/参数错误或目标不存在、目标 JSON 损坏（`insight scan` 路径类失败） |

> 约定：所有错误场景 stdout 输出单行可解析 JSON（`{"success": false, "error": ...}` 或等价结构），stderr 保持 0 字节。
