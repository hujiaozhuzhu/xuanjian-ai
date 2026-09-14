# 玄鉴 XuanJian AI v4.0 —— README（移动安全分析版）

> **v4.0 是玄鉴的移动安全能力版本**：在 v3.x 服务端代码审计（误报排查 MCP）基础上，新增面向 Android/iOS 应用渗透测试的六大能力，全部通过统一 CLI `python -m fp_sentinel mobile ...` 驱动。

---

## 1. 项目简介

玄鉴（XuanJian AI）v4.0 是一款面向移动安全渗透测试人员的静态分析工具链，核心是**证据归因**：每一条 HIGH/CRITICAL 发现都回填 `class#method` 级归因位置与来源分类（business / library / framework / obfuscated / unattributed），可直接按类名复测，而非"报告一大堆没法落地"的启发式噪声。

### 六大能力

| # | 能力 | 命令组 | 说明 |
|---|------|--------|------|
| ① | 砸壳（加固检测/脱壳） | `mobile shell` | 识别 360/腾讯/梆梆/爱加密/娜迦/百度/阿里 等加固；Android 优先 frida-dexdump 动态脱壳、降级静态检测；iOS 走 frida-ios-dump（需越狱） |
| ② | 反编译 | `mobile decompile` | APK/DEX → 源码/大纲（jadx 可用时行级定位，缺失时大纲模式并诚实降级标注）；关键字搜索（TEXT/STRING/CALL/XREF）；字符串提取；Manifest 解析；类层次结构 |
| ③ | Hook 定位 | `mobile hook` | 7 种技法（keyword/collection/toast/log/json/string/base64）自动推荐 Hook 点位，关键性评分排序，支持单技法/组合扫描/mock 验证 |
| ④ | 技术提示（App 审计） | `mobile insight` | 67 条内置规则（存储/网络/加密/组件/反分析/隐私，CWE+MASVS 对齐），证据分级（凭证 LEVEL1~3 动态定级）、归因、确定性输出、库/框架落点自动降级 |
| ⑤ | Frida POC 生成 | `mobile poc` | 依据 Hook 点位自动生成 Frida POC（ssl-bypass/root-bypass/签名绕过等 goal），schema 校验、占位符检查、越界防护、批量生成与合法性验证 |
| ⑥ | App 审计报告 | `mobile insight scan` | 一键输出带严重级分布、分类分布、逐条归因证据的 JSON/摘要报告 |

### 与 v3.x 的关系

- v3.x 的服务端能力（`xuanjian scan` / `mcp` / `devops` / `privacy` / `kg` 等）**全部保留**，v4.0 是纯增量：新增 `mobile` 命令组与 `fp_sentinel/mobile_*` 六个模块。
- v3.1 的规则引擎、误报治理框架（二次确认、白名单、FP 标记）在 v4.0 移动规则上延续复用。
- 版本号约定：v3.x 线继续维护服务端审计；v4.0 线主打移动渗透测试。详见 `CHANGELOG_v4.md`。

---

## 2. 快速开始

### 2.1 环境准备

```bash
# Python 3.10+（v4.0 开发/测试环境: 3.12）
pip install -r requirements.txt

# 核心依赖（必装）
pip install androguard        # APK/DEX 解析底座

# 可选增强
#  - jadx: 安装后 decompile run 获得行级源码定位；缺失时自动大纲模式
#  - frida / frida-tools: shell dump-android 动态脱壳与 POC 实机执行
#  - frida-dexdump: 脱壳动态模式
```

验证安装：

```bash
python -m fp_sentinel --version          # 玄鉴 (xuanjian-ai) fp_sentinel v4.0.0
python -m fp_sentinel mobile --help
```

### 2.2 首个命令

对任意 APK 做一次完整审计（能力④⑥）：

```bash
python -m fp_sentinel mobile insight scan app.apk
```

输出为纯 stdout JSON（`--output` 可另存），含 `insight_count`、`severity_distribution`、`classification_distribution` 与逐条归因证据。

### 2.3 典型渗透工作流

```bash
# 1) 加固检测
python -m fp_sentinel mobile shell detect app.apk --json
# 2) 反编译/大纲
python -m fp_sentinel mobile decompile run app.apk -o out/
# 3) 敏感字符串与搜索
python -m fp_sentinel mobile decompile strings app.apk --sensitive
# 4) Hook 点位推荐
python -m fp_sentinel mobile hook recommend app.apk -g encrypt-trace -o hooks.json
# 5) 生成 POC
python -m fp_sentinel mobile poc generate --goal ssl-bypass --hook-points hooks.json
# 6) 审计报告
python -m fp_sentinel mobile insight scan app.apk --output report.json
```

---

## 3. 六大能力使用示例

### ① 砸壳（mobile shell）

```bash
# 加固类型识别（JSON 输出）
python -m fp_sentinel mobile shell detect app.apk --json

# Android 脱壳（动态优先, 无设备时自动降级静态检测）
python -m fp_sentinel mobile shell dump-android --apk app.apk --output ./dump/

# 批量检测目录内所有安装包
python -m fp_sentinel mobile shell batch ./apks/ --platform android --mode static
```

### ② 反编译（mobile decompile）

```bash
# 完整反编译（jadx 优先; 缺失时 androguard 大纲模式）
python -m fp_sentinel mobile decompile run app.apk --engine auto -o out_src/ --format json

# 关键字搜索（STRING 匹配 DEX 字符串池）
python -m fp_sentinel mobile decompile search app.apk superSecurePassword -t string --format json

# Manifest 解析（含 debuggable/allowBackup 等 application flags）
python -m fp_sentinel mobile decompile manifest app.apk --format json
```

### ③ Hook 定位（mobile hook）

```bash
# 七技法综合推荐 Top10
python -m fp_sentinel mobile hook recommend app.apk -g encrypt-trace -n 10 -o hooks.json

# 单技法执行并导出 Frida 脚本
python -m fp_sentinel mobile hook technique string --apk app.apk --script dump_strings.js

# 组合扫描 + mock 验证
python -m fp_sentinel mobile hook scan app.apk -t base64,json,log -n 20 -o combo.json
python -m fp_sentinel mobile hook verify hooks.json
```

### ④ 技术提示 / App 审计（mobile insight）

```bash
# 全量审计（默认 67 条规则）
python -m fp_sentinel mobile insight scan app.apk

# 只看加密类、HIGH 及以上
python -m fp_sentinel mobile insight scan app.apk --category crypto --min-severity HIGH

# 摘要输出 + 规则清单
python -m fp_sentinel mobile insight scan app.apk --summary
python -m fp_sentinel mobile insight rules
```

### ⑤ Frida POC（mobile poc）

```bash
# 从 hook 点位生成 SSL 绕过 POC
python -m fp_sentinel mobile poc generate --goal ssl-bypass --hook-points hooks.json --output poc_ssl.js

# 指定类#方法直接生成（rank 选择候选点位; 越界会明确报错）
python -m fp_sentinel mobile poc generate --goal request-plaintext --package com.example.app \
    --class-name com.example.app.Crypto --method-name encrypt --rank 0 --no-save

# 合法性校验（占位符/红线检查, 不连接设备）
python -m fp_sentinel mobile poc validate poc_ssl.js --language js

# goal / 模板清单
python -m fp_sentinel mobile poc goals
python -m fp_sentinel mobile poc templates
```

### ⑥ App 审计报告（能力④⑥组合）

```bash
# JSON 报告落盘（渗透报告素材: 归因 + 证据 + 修复建议 + MASVS 引用）
python -m fp_sentinel mobile insight scan app.apk --output report.json
```

---

## 4. CLI 命令速查表

| 命令 | 作用 | 关键参数 |
|---|---|---|
| `mobile shell detect <target>` | 加固类型识别 | `--json` |
| `mobile shell dump-android` | Android 脱壳 | `--apk` `--output` `--mode auto/static` `--device` |
| `mobile shell dump-ios` | iOS 脱壳 | `--app` `--package` `--output` `--device` |
| `mobile shell batch <dir>` | 批量检测+脱壳 | `--output` `--platform` `--mode` |
| `mobile decompile run <target>` | 完整反编译 | `--engine auto/jadx/androguard` `-o` `--format text/json/markdown` `--call-graph` |
| `mobile decompile search <target> <kw>` | 关键字搜索 | `-t text/string/call/xref` `--scope` `--limit` `--format` |
| `mobile decompile strings <target>` | 字符串提取 | `--pattern` `--sensitive` `--limit` `--format text/json` |
| `mobile decompile manifest <target>` | Manifest 解析 | `--format text/json` |
| `mobile decompile hierarchy <target>` | 类层次结构 | `--root` `--format` |
| `mobile hook recommend <apk>` | Hook 点位推荐 | `-g <goal>` `-n <top>` `-o` |
| `mobile hook technique <name>` | 单技法执行 | `--apk` `-g` `-o` `--script` |
| `mobile hook scan <apk>` | 组合技法扫描 | `-t <技法列表/all>` `-g` `-n` `-o` |
| `mobile hook verify <file>` | 点位 mock 验证 | `-d <设备号>` |
| `mobile poc generate` | 生成 Frida POC | `--goal` `--hook-point/--class-name/--method-name/--package` `--rank` `--output` `--no-save` |
| `mobile poc batch` | 批量生成 | `--hook-points` `--goal` `--output` |
| `mobile poc validate <script>` | POC 合法性校验 | `--language` |
| `mobile poc run <script>` | 受控执行 | `--package` `--authorized-packages` |
| `mobile poc templates` / `goals` | 模板/目标清单 | — |
| `mobile insight scan <target>` | 67 规则审计 | `--category` `--min-severity` `--output` `--summary` `--max-insights` |
| `mobile insight rules` | 规则清单 | — |

完整参数说明与输出 schema 见 `docs/api-reference-v4.md`。

---

## 5. 输出与验收基线（v4.0 发布数据）

- InsecureBankv2（主靶场）：34 findings，HIGH+ 8 条全部归因业务类，库/框架落点 HIGH+ = 0；
- OVAA（app_vul_test）：35 findings，HIGH+ 6 条全部业务归因；
- TestVuls：21 findings，HIGH+ 2 条（Manifest + 业务类）；
- 扫描结果对 `PYTHONHASHSEED` 确定性（4 种子逐条一致，有回归测试守护）；
- 测试 700+ 用例、五模块覆盖率 ≥95%。

已知问题与能力边界见 `docs/KNOWN_ISSUES.md`；三轮专家验收过程见 `docs/round1_expert_feedback.md` / `round2_expert_feedback.md` / `round3_expert_final_report.md`。

## 6. License

见 `LICENSE`。
