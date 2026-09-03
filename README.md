
```
  ██╗  ██╗██╗   ██╗ █████╗ ███╗   ██╗     ██╗██╗ █████╗ ███╗  ██╗
  ╚██╗██╔╝██║   ██║██╔══██╗████╗  ██║     ██║██║██╔══██╗████╗ ██║
   ╚███╔╝ ██║   ██║███████║██╔██╗ ██║     ██║██║███████║██╔██╗██║
   ██╔██╗ ██║   ██║██╔══██║██║╚██╗██║██   ██║██║██╔══██║██║╚████║
  ██╔╝ ██╗╚██████╔╝██║  ██║██║ ╚████║╚█████╔╝██║██║  ██║██║ ╚███║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝
```

# 玄鉴 XuanJian AI v2.2.1

> **鉴伪存真，洞察代码风险** — 面向安全研究团队的开源代码审计与红蓝对抗平台

> v2.2.1 是基于真实 Windows 用户反馈的稳定性补丁：CLI 在 GBK/CP936 终端安全降级，Semgrep 未安装时明确提示，支持无需 PATH 配置的模块入口。所有攻防验证默认只做本地特征模拟，身份画像默认匿名化。

## Windows 用户注意

Windows 安装后，不依赖 `Scripts` 目录是否已加入 PATH：

```powershell
python -m fp_sentinel --version
python -m fp_sentinel scan C:\path\to\project --lang javascript
```

如需直接使用 `fp-sentinel` 命令，请将当前 Python 环境的 `Scripts` 目录加入 PATH。GBK/CP936 终端会自动使用 `[SCAN]`、`[OK]`、`[WARN]` 等 ASCII 状态标记，不会改动系统代码页。

安装建议：基础安装适用于内置规则；高级 Semgrep 规则使用 `pip install -e ".[scanners]"`；完整安装使用 `pip install -e ".[all]"`。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![MCP](https://img.shields.io/badge/MCP-1.0-green.svg)](https://modelcontextprotocol.io)

---

## ✨ v2.2.0 新特性

| 特性 | 说明 |
|------|------|
| 🎯 **攻击可验证** | 20 类本地 PoC 模板、可利用性评分、攻击链编排；目标限制为 localhost/127.0.0.1 |
| 📄 **双报告体系** | 合规报告包含 Diff/CVE/ROI/趋势；攻防报告包含验证状态、攻击路径与修复优先级 |
| 👤 **开发者画像** | 只读 git blame、SHA256 匿名别名、六维画像、团队健康度与本地 SQLite 存储 |
| 🔒 **零危险边界** | 不修改源代码、不删除用户文件、不攻击外部目标、不向外部 API 写数据 |

## ✨ v2.0 新特性

| 特性 | 说明 |
|------|------|
| 🔴 **红蓝对抗** | 红队攻击用例生成 vs 蓝队自适应防御，自动收敛迭代 |
| 🛡️ **四级降噪** | L1语法→L2语义→L3统计→L4智能(LLM)，误报率 < 8% |
| 🌐 **多语言支持** | Java + JavaScript/TypeScript + Python，各20+条规则 |
| 🤖 **JSRPC 浏览器引擎** | Playwright 集成，函数 Hook，密钥自动捕获 |
| ⛓️ **攻击链发现** | 基于图论的漏洞关联分析，10种预置攻击链模板 |
| 📊 **动态风险评分** | CVSS + EPSS + 资产价值 + 可达性多维评分 |
| 🧪 **AIGC 安全治理** | Prompt Injection、幻觉依赖、LLM输出直接执行检测 |
| ⚡ **性能基准** | 自动化性能测试，10万行 < 3分钟 |

---

## 📈 效果展示

```
┌─────────────────────────────────────────────────────────────┐
│  扫描器原始发现:     247 条                                   │
│  ─────────────────────────────────                           │
│  L1 语法降噪:        -89 条  (白名单注释+安全函数+测试文件)   │
│  L2 语义降噪:        -52 条  (框架安全+MVC分层+安全装饰器)    │
│  L3 统计降噪:        -31 条  (误报指纹+聚类去重)              │
│  L4 智能降噪:        -12 条  (LLM边界判断)                   │
│  ─────────────────────────────────                           │
│  最终待复核:          63 条                                   │
│  误报减少率:         74.5%                                    │
│  检出率:             96.8%                                    │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 快速开始

### 安装

```bash
git clone https://github.com/hujiaozhuzhu/xuanjian-ai.git
cd xuanjian-ai

python3 -m venv .venv
source .venv/bin/activate

# 基础安装
pip install -e .

# 完整安装（含浏览器引擎、扫描器、ML、Web）
pip install -e ".[all]"

# 安装 Playwright 浏览器（JSRPC 功能需要）
playwright install chromium
```

### CLI 使用

```bash
# 扫描项目（自动检测语言）
fp-sentinel scan /path/to/project --format table

# 指定语言扫描
fp-sentinel scan /path/to/project --lang javascript
fp-sentinel scan /path/to/project --lang python
fp-sentinel scan /path/to/project --lang java

# 列出发现
fp-sentinel list --severity HIGH

# 标记误报
fp-sentinel mark <finding-id> --reason "使用PreparedStatement" --scope rule

# 查看统计
fp-sentinel stats

# 生成合规报告或攻防报告（报告仅写入 --output 目录）
fp-sentinel scan /path/to/project --report compliance --output ./reports
fp-sentinel scan /path/to/project --report attack --output ./reports
fp-sentinel scan /path/to/project --report all --output ./reports

# 开发者画像（默认只显示匿名别名）
fp-sentinel profile me /path/to/project
fp-sentinel profile team /path/to/project
fp-sentinel profile forget /path/to/project --alias <alias>

# 清理超过 30 天的本地攻防 PoC 记录
fp-sentinel attack purge --days 30

# 浏览器自动化（JSRPC）
fp-sentinel browser start --url "https://target.com/login"
fp-sentinel browser hook --target "encrypt" --type trace
fp-sentinel browser call --func "encryptPassword" --args '["test"]'
fp-sentinel browser keys
```

### MCP Server

```bash
# stdio 模式（推荐用于 AI 客户端集成）
fp-sentinel mcp --transport stdio

# SSE 模式
fp-sentinel mcp --transport sse --port 8000
```

---

## 🔧 MCP 工具列表 (16个)

### 代码审计工具

| # | 工具名 | 说明 |
|---|--------|------|
| 1 | `scan_project` | 扫描项目，自动检测语言并调度扫描器 |
| 2 | `triage_findings` | 对扫描结果进行分诊，应用过滤器识别误报 |
| 3 | `explain_finding` | 解释单条发现，提供详细分析和处理建议 |
| 4 | `mark_false_positive` | 将发现标记为误报，写入历史基线 |
| 5 | `list_findings` | 列出扫描发现，支持按 verdict、severity 过滤 |
| 6 | `export_report` | 导出扫描报告（JSON/Markdown） |
| 7 | `get_statistics` | 获取项目统计信息 |
| 8 | `list_projects` | 列出已扫描的项目 |

### JSRPC 浏览器工具

| # | 工具名 | 说明 |
|---|--------|------|
| 9 | `jspy_start` | 启动浏览器实例 |
| 10 | `jspy_navigate` | 导航到目标 URL |
| 11 | `jspy_hook` | 注入函数 Hook（trace/before/after/replace） |
| 12 | `jspy_call` | 远程调用页面函数 |
| 13 | `jspy_evaluate` | 执行 JavaScript 表达式 |
| 14 | `jspy_trace` | 追踪函数调用链，捕获输入输出 |
| 15 | `jspy_extract_keys` | 自动提取加密密钥 |
| 16 | `jspy_stop` | 关闭浏览器实例 |

---

## 🏗️ 架构图

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        玄鉴 v2.0 架构                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    MCP Server (16 工具)                          │   │
│  │  ┌──────────┬──────────┬──────────┬──────────┐                 │   │
│  │  │scan_     │triage_   │jspy_     │jspy_     │ ...             │   │
│  │  │project   │findings  │start     │hook      │                 │   │
│  │  └────┬─────┴────┬─────┴────┬─────┴────┬─────┘                 │   │
│  └───────┼──────────┼──────────┼──────────┼────────────────────────┘   │
│          │          │          │          │                             │
│  ┌───────▼──────────▼──────────▼──────────▼────────────────────────┐   │
│  │                      核心服务层                                   │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌─────────────────────┐   │   │
│  │  │ 扫描器管理    │  │ 降噪流水线   │  │  JSRPC 引擎         │   │   │
│  │  │ ScannerMgr   │  │ L1→L2→L3→L4 │  │  BrowserEngine      │   │   │
│  │  └──────┬───────┘  └──────┬───────┘  └──────────┬──────────┘   │   │
│  └─────────┼─────────────────┼──────────────────────┼──────────────┘   │
│            │                 │                      │                   │
│  ┌─────────▼─────────────────▼──────────────────────▼──────────────┐   │
│  │                       扫描器层                                    │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │   │
│  │  │ Semgrep  │ │  Bandit  │ │FindSec   │ │ JS Scanner       │  │   │
│  │  │ Scanner  │ │ Scanner  │ │ Bugs     │ │ (50+规则)        │  │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘  │   │
│  └────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                       过滤器层                                   │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │   │
│  │  │ L1 语法  │→│ L2 语义  │→│ L3 统计  │→│ L4 智能(LLM) │  │   │
│  │  │ 降噪     │  │ 降噪     │  │ 降噪     │  │ 降噪         │  │   │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────────┘  │   │
│  └────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                    红蓝对抗引擎                                  │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐  │   │
│  │  │ 红队生成器    │  │ 对抗循环     │  │ 攻击链发现         │  │   │
│  │  │ 10种变异策略  │  │ 自动收敛     │  │ 10种预置链         │  │   │
│  │  └──────────────┘  └──────────────┘  └────────────────────┘  │   │
│  └────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │  SQLite (WAL) │ 规则库 │ 基线指纹库 │ 对抗历史 │ 配置管理     │   │
│  └────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🔐 v2.2.0 安全与隐私边界

- PoC 生成器只接受 `localhost`、`127.0.0.1` 和 `::1`，外部目标会被拒绝。
- 默认验证模式为源码特征模拟，不发起网络请求；Docker 验证必须显式开启且失败时降级为 `simulated`。
- git 归因仅允许 `log`、`blame`、`show`，不执行 commit、push、tag、config 等写操作。
- 开发者 email 不落盘，画像使用确定性 SHA256 别名；原始姓名仅在内存态或本地加密字段中处理。
- `--reveal` 必须同时满足环境变量和安全负责人确认参数；画像仅用于培训与能力提升，不用于绩效考核。
- 报告路径经过白名单校验，PoC 记录支持按保留期清理；不会修改被扫描源代码。

## 🛡️ 四级降噪引擎

| 层级 | 名称 | 功能 | 性能 |
|------|------|------|------|
| L1 | 语法降噪 | 白名单注释、安全函数、常量表达式、测试文件 | < 5ms/file |
| L2 | 语义降噪 | 框架安全特性、MVC分层、安全装饰器 | < 50ms/file |
| L3 | 统计降噪 | 误报指纹、置信度评分、聚类去重 | < 100ms/100条 |
| L4 | 智能降噪 | LLM边界判断（仅边界案例触发） | < 10次调用/扫描 |

```python
from fp_sentinel.filters import NoisePipeline

pipeline = NoisePipeline(
    enable_l1=True,
    enable_l2=True,
    enable_l3=True,
    enable_l4=True,  # 需要 LLM 客户端
    llm_client=your_llm,
)

filtered_findings = await pipeline.process(findings)
print(f"降噪统计: {pipeline.get_stats()}")
```

---

## 🔴 红蓝对抗

### 红队攻击用例生成

```python
from fp_sentinel.redteam import RedTeamGenerator

generator = RedTeamGenerator(llm_client=your_llm)
result = await generator.generate_bypasses(
    rule_id="js.injection.eval",
    description="eval() 执行任意代码",
    pattern=r"\beval\s*\(",
    count=20,
)

# 10种变异策略
# L1: API替换 (eval→Function/setTimeout)
# L2: 编码绕过 (Unicode/Hex/Base64)
# L3: 控制流混淆 (try-catch/IIFE)
# L4: 原型链利用 (constructor chain)
```

### 对抗循环

```python
from fp_sentinel.redteam import AdversarialLoop

loop = AdversarialLoop()
result = await loop.run(
    rule_id="js.injection.eval",
    count_per_round=20,
)

# 收敛条件: 检出率≥96%, 误报率≤8%, L3绕过率≤3%
# 连续3轮稳定, 方差<1.5%, 最大15轮
```

---

## ⛓️ 攻击链发现

```python
from fp_sentinel.analysis import AttackChainDiscovery

discovery = AttackChainDiscovery()
chains = discovery.discover_chains(findings)

for chain in chains[:5]:
    print(f"{chain.name} (评分: {chain.overall_score:.2f})")
    for step in chain.steps:
        print(f"  Step {step.step_number}: {step.action}")
```

### 10种预置攻击链

| ID | 名称 | 步骤 |
|----|------|------|
| CHAIN-001 | JWT弱密钥→管理员伪造→数据导出 | 3 |
| CHAIN-002 | SQL注入→认证绕过→数据泄露 | 3 |
| CHAIN-003 | XSS→会话劫持→账户接管 | 3 |
| CHAIN-004 | 反序列化→RCE→横向移动 | 3 |
| CHAIN-005 | SSRF→元数据读取→密钥泄露 | 3 |
| CHAIN-006 | 文件上传→WebShell→权限提升 | 3 |
| CHAIN-007 | 路径遍历→配置泄露→内网渗透 | 3 |
| CHAIN-008 | 逻辑缺陷→批量操作→数据篡改 | 3 |
| CHAIN-009 | 第三方库→供应链攻击→后门 | 3 |
| CHAIN-010 | AI幻觉→依赖投毒→构建劫持 | 3 |

---

## 🌐 多语言规则覆盖

### JavaScript/TypeScript (50+ 条规则)

| 类别 | 规则数 | 覆盖 |
|------|--------|------|
| XSS | 8 | innerHTML, outerHTML, document.write, jQuery.html, dangerouslySetInnerHTML, v-html |
| 注入 | 4 | eval, Function, setTimeout(string), 动态脚本加载 |
| 原型污染 | 3 | Object.assign, 深合并, 动态属性访问 |
| 加密 | 5 | Math.random, MD5, SHA1, DES, ECB模式 |
| 敏感信息 | 4 | 硬编码密码/API Key/Token/私钥 |
| AIGC | 15 | Prompt Injection, LLM输出执行, 幻觉依赖, API Key泄露 |

### Python (20 条规则)

| 类别 | 规则数 | 覆盖 |
|------|--------|------|
| SQL注入 | 2 | 字符串拼接, .format() |
| 命令注入 | 3 | os.system, subprocess, eval/exec |
| 反序列化 | 3 | pickle, yaml.load, marshal |
| 加密 | 3 | MD5/SHA1, 硬编码密钥, DES/RC4 |
| 认证 | 3 | DEBUG模式, CSRF, JWT弱密钥 |
| 其他 | 6 | SSRF, 路径穿越, XXE, 敏感信息 |

### Java (70+ 条规则)

详见 [Java 误报规则文档](docs/java-rules.md)。

---

## 🤖 JSRPC 浏览器引擎

```python
from fp_sentinel.browser import BrowserEngine
from fp_sentinel.models import BrowserConfig, RPCConfig

engine = BrowserEngine(
    BrowserConfig(headless=True, stealth_mode=True),
    RPCConfig(port=18800),
)

session = await engine.start()
await engine.navigate(session.session_id, "https://target.com/login")

# 注入函数 Hook
await engine.inject_hook(session.session_id, "encrypt", "trace")

# 自动捕获加密密钥
await engine.inject_crypto_hooks(session.session_id)

# 远程调用
result = await engine.call_function(
    session.session_id, "encryptPassword", ["test123"]
)
```

### 内置 Hook 脚本

| 脚本 | 功能 |
|------|------|
| `rpc_bridge.js` | RPC 通信桥接（WebSocket） |
| `crypto_hooks.js` | Web Crypto API / CryptoJS / JSEncrypt 自动 Hook |
| `cookie_hooks.js` | Cookie 读写监控 |
| `xhr_hooks.js` | XHR/Fetch 请求监控 |
| `anti_detect.js` | 反检测（隐藏 webdriver/修改指纹） |

---

## 📊 动态风险评分

```python
from fp_sentinel.analysis import ChainRiskScorer, AssetContext

scorer = ChainRiskScorer()
context = AssetContext(
    data_sensitivity=0.8,
    user_count=100000,
    network_exposure="public",
    has_waf=True,
)

risk = scorer.score(chain, context)
print(f"风险评分: {risk.overall_score:.2f}")
print(f"严重级别: {risk.severity}")
print(f"CVSS: {risk.cvss}, EPSS: {risk.epss}")
```

---

## ⚡ 性能基准

```bash
# 运行性能测试
python -c "
from fp_sentinel.benchmark import BenchmarkRunner
runner = BenchmarkRunner()
report = runner.run('/path/to/project')
print(runner.generate_report(report))
"
```

| 指标 | 基线 |
|------|------|
| 扫描速度 | > 500 行/秒 |
| 10万行耗时 | < 3 分钟 |
| 内存占用 | < 2 GB |

---

## 🗺️ 路线图

### v1.0 ✅
- [x] MCP Server（8 个工具）
- [x] 三层过滤架构
- [x] CLI 命令行工具
- [x] Web 仪表板
- [x] Java 误报规则库

### v2.0 ✅
- [x] JS/TS 审计支持（50+ 规则）
- [x] Python 审计支持（20 规则）
- [x] JSRPC 浏览器引擎
- [x] 四级降噪引擎
- [x] 红蓝对抗循环
- [x] 攻击链发现（10种模板）
- [x] 动态风险评分
- [x] AIGC 安全规则
- [x] 性能基准测试

### v2.1 🚧
- [ ] Go 语言规则集
- [ ] Rust 语言规则集
- [ ] IDE 插件（VS Code）
- [ ] 团队协作与多用户

---

## 🤝 贡献

欢迎贡献！请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 📄 License

[MIT License](LICENSE) — 自由使用，自由修改，自由分发。

---

<p align="center">
  <sub>由玄鉴团队用 ❤️ 构建 | 鉴伪存真，让代码审计更高效</sub>
</p>
