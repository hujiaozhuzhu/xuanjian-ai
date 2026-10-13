# fp_sentinel v5.x 开发交接提示词

> 把这篇完整提示词交给新 Agent。Agent 必须严格按本文约束执行。
> 称谓约定：「你」= 接到此提示词的 Agent；「用户」= 发起审计的人类。

---

## 一、项目身份

- 项目名：fp_sentinel（玄鉴 AI）
- 版本：v5.0（skill 规则系统已落地）
- 目标：面向安全团队的 AI 驱动代码审计与红蓝对抗平台
- 当前分支：`feature/v4.0-mobile-security`
- GitHub：https://github.com/hujiaozhuzhu/xuanjian-ai
- 工作目录：`C:\Users\lenovo\xuanjian-ai`（Windows 10 / Python 3.12）
- 必须在此目录下执行所有命令

---

## 二、文件位置索引

```
xuanjian-ai/
├── fp_sentinel/                    # 主包（335+ .py）
│   ├── cli/__init__.py             # CLI 主入口，已接入 rule_registry 闸门
│   ├── rules/                      # rules/ 注册器（加载 skills/ 下规则）
│   │   └── rule_registry.py        # 新增：check_scope / require_write_opt_in / fail_closed / load_routes
│   ├── attack/
│   │   ├── dom_verify/             # DOM marker 注入验证器（nuclei 风格）
│   │   └── harmless_verifier/      # 静态 source grep + DOM 双轨验证
│   ├── api_knowledge/              # API 图谱 GraphRAG（新增 v4.3）
│   │   ├── store.py               # SQLite + FTS5 + digraph
│   │   ├── schema_infer.py        # 请求/响应 → OpenAPI schema
│   │   ├── associator.py          # 5 维关联引擎 + BOLA 检测
│   │   ├── exporter.py            # OpenAPI 3.0.3 + HAR 1.2 + JSON
│   │   └── visualize.py           # D3 v7 力导向图
│   ├── web_api/                    # API 发现 + 越权扫描
│   ├── mobile_shell/               # iOS/Android 砸壳降级链
│   ├── mobile_decompile/           # jadx → androguard → baksmali → DexBaksmali
│   ├── mobile_insight/             # 80 条规则 6 类 MASVS
│   ├── mobile_hook/               # Frida Hook 模板 + PCAP/HAR 导出
│   ├── mobile_reporting/          # Excel(11) / Word(6) / HTML
│   └── ...
├── tests/                         # 根测试（test_rule_registry / test_routes）
├── CHANGELOG_v5.md                # v5.0 发布说明
├── docs/
│   ├── v5.0-skill-package-design.md
│   └── v5-agent-handoff-prompt.md  # 本文件
└── (skill 包位置)
    ~/.meituan-catpaw/4275287949/skills/fp_sentinel/
    ├── SKILL.md                    # Agent 入口规则
    ├── rules/                      # 11 份红线文件 + routing-table.yaml
    ├── modules/                    # 5 份模块说明 + glossary + README
    └── tests/
        ├── self_check.py           # 机器合规检查脚本
        └── self-check-style.md     # 祈使句校验流程
```

---

## 三、核心禁令（规则冲突时 rules/ 优先级最高）

1. 禁止在未持有 `--i-have-authorization` 标志时发起任何网络连接。
2. 禁止修改目标文件、数据库、配置。写操作须显式 opt-in。
3. 禁止执行递归删除命令（rm -rf / rmdir /s /q / del /s /q / Remove-Item -Recurse）。
4. 禁止做社工、钓鱼、物理接触、内部人员串通。
5. 禁止在未持有书面授权时连接内网目标。
6. 禁止输出可直接投递的武器化利用链。
7. 禁止绕过 `~/.meituan-catpaw/4275287949/skills/fp_sentinel/rules/` 中的任意红线。
8. 禁止跳过规则文件合入开发流程。
9. 禁止在报告中遗漏 CVSS 评分与复现步骤。
10. 禁止改写操作日志。
11. 禁止模块自仲裁（冲突时以 rules/ 为准）。
12. 禁止「应该」「可以」「推荐」「通常情况下」出现在规则文档（祈使句约束）。

---

## 四、核心义务

1. 必须先读 `rules/routing-table.yaml` 决定管线走向。
2. 必须模块冲突时 rules/ 优先。
3. 必须模块未声明的能力视为禁止（默认拒绝）。
4. 必须在报告中明确标注未覆盖场景与本次限制。
5. 必须每条审计结论附证据（文件:行号:hash）。
6. 必须操作日志原文留存。
7. 必须异常时 fail-closed（立即停止并上报）。
8. 必须新术语先在 `modules/00-glossary.md` 登记，后使用。
9. 必须每条规则可被 `grep -E "(禁止|必须|只认|不得)"` 自动解析。
10. 必须所有新增模块暴露 `available()` / `self_check()` / `module_version()`。
11. 必须在每次 commit 前运行 `python skills/fp_sentinel/tests/self_check.py`。
12. 必须所有模块的 `__init__.py` 显式导出新增接口。

---

## 五、路由决策表（新增 target 须先补一条）

```
Web  + 有源码   → web-pretreat → web-scan → cvss → web-evidence → report
Web  + 无源码   → api-discover → classify → api-knowledge link → attack-surface → report
移动 + APK      → detect → dump-android → decompile → insight → audit --cvss
移动 + IPA      → detect → dump-ios → insight → audit --cvss
未命中          → stop + escalate（禁止自主拼接）
```

---

## 六、模块接口契约

5 个核心模块已落地（v5.0）：

| 模块 | available() 实现 | module_version() |
|---|---|---|
| `attack/dom_verify/executor.py` | 恒返 True（有 Python fallback） | 5.0.0 |
| `api_knowledge/store.py` | 检查 sqlite3 导入 | 5.0.0 |
| `api_knowledge/associator.py` | 检查 ApiKnowledgeStore 可 import | 5.0.0 |
| `web_api/api_discovery.py` | 检查 ApiDiscovery 可实例化 | 5.0.0 |
| `harmless_verifier/verifier.py` | 恒返 True | 5.0.0-dom |

后续新增模块必须按同样模式追加三函数 + 更新 `__init__.py`。

---

## 七、测试

```bash
# 全仓（当前基准 1400+ tests，0 failed 不得下跌）
python -m pytest fp_sentinel/ -q

# 新增模块契约测试
python -m pytest tests/test_rule_registry.py tests/test_routes.py fp_sentinel/tests/test_module_contracts.py -q

# 全仓库祈使句合规（必须全通过才允许合入）
python ~/.meituan-catpaw/4275287949/skills/fp_sentinel/tests/self_check.py
```

---

## 八、新增能力四步登记（漏一步禁止合入）

1. **glossary**：在 `skills/fp_sentinel/modules/00-glossary.md` 登记术语（术语 | 含义 | 首次出现文件）
2. **routing-table.yaml**：在 `skills/fp_sentinel/rules/01-routing-table.yaml` 追加路由
3. **rules/ 红线**：在对应 rules/ md 中补充约束
4. **module 实现**：实现模块 + 三接口 + `__init__.py` 导出
5. **test**：至少 1 个 test 文件 + 全仓回归通过

---

## 九、开发规范

- 单函数 ≤ 25 行，单文件 ≤ 200 行。
- 必须含祈使句 docstring（实现 xxx / 暴露 xxx / 验证 xxx）。
- 必须 `from pathlib import Path`。
- 必须显式 `from typing import Optional / NoReturn / Any`。
- 禁止裸捕获 `Exception`（必须显式类型）。
- 禁止 `import *`。
- 命令必须可执行（不得给伪代码）。
- 代码块中不得出现「应该」「可以」「推荐」等模糊词。

---

## 十、已知限制（下一版本待补）

- 双网卡 USB NIC（135.192.15.106）环境已脱离，须回联后能做内网审计。
- 内网目标 135.192.199.40:8072（TAR-M）在可回联后恢复审计。
- v5.0 未覆盖 CORS / 点击劫持 / CRLF / DNS 重绑定 / 0day 武器化 / gRPC。
- CVSS 评分与报告格式已齐全，但报告模板未在多模块统一。

---

## 十一、交接检查清单（开工前必跑）

```bash
# 1. 导入验证
python -c "from fp_sentinel.rules.rule_registry import get_registry; print('rules OK')"

# 2. 模块契约
python -c "
from fp_sentinel.attack.dom_verify import available as dv
from fp_sentinel.api_knowledge.store import available as ks
print(f'dom_verify.available={dv()}, store.available={ks()}')
"

# 3. 测试基线
python -m pytest fp_sentinel/ -q --tb=no | tail -3

# 4. 祈使句自检
python ~/.meituan-catpaw/4275287949/skills/fp_sentinel/tests/self_check.py
```

四项全通过才允许开始开发。
