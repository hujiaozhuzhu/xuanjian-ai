# A2. GitHub 真实修复案例匹配模块

## 模块路径
`fp_sentinel/reporting/github_fix_matcher.py`

## 功能概述

基于目标系统技术框架自动匹配 GitHub 上的真实修复案例，生成可直接使用的代码级修复方案。

核心特点：零网络依赖（S6 红线），纯本地案例库匹配。

## 技术栈检测

### 支持框架

| 框架 | 语言 | 检测规则前缀 |
|------|------|-------------|
| spring-boot | java | `java-`, `semgrep-java`, `findsecbugs` |
| django | python | `python-`, `bandit`, `semgrep-python` |
| express | javascript | `js-`, `node-`, `semgrep-js` |
| laravel | php | `php-`, `semgrep-php` |
| gin | go | `go-`, `semgrep-go`, `gosec` |

### 检测算法

1. **语言推断**: 从 `file_path` 后缀 + `rule_id` 前缀计分
2. **框架匹配**: 从 `rule_id` 前缀频率 + 指示文件命中计分
3. **依赖提取**: 识别 `pom.xml`, `package.json`, `go.mod` 等

## 修复案例库

### 内置案例 (14+ 真实案例)

每个案例包含：
- `fix_id`: 唯一标识
- `vuln_category`: 漏洞类别
- `tech_framework`: 目标框架
- `title`: 修复标题
- `severity`: 严重度
- `description`: 问题描述
- `before_code`: 问题代码
- `after_code`: 修复代码
- `reference_cve`: 关联 CVE
- `reference_commit_url`: GitHub 链接

### 案例覆盖

- SQL_INJECTION: Spring/Django/Laravel/Go (参数化查詢)
- XSS: Django/Express (输出转义)
- DESERIALIZATION: Spring Boot/Laravel/PHP (禁用反序列化)
- SSRF: Spring Boot/Go (URL 白名单校验)
- PATH_TRAVERSAL: Django/Go (路径规范化)
- COMMAND_INJECTION: Express (execFile 替代 exec)
- CRYPTO_FAILURE: Django (环境变量加载密钥)
- XXE: Java (禁用外部实体)
- PROTOTYPE_POLLUTION: Node.js (Object.create(null))
- DEBUG_MODE: Django (生产配置)

## 匹配引擎

### 倒排索引

`_FIX_CASE_LIBRARY` -> `_build_index()` -> 多维映射 {category/framework/severity: [case_indices]}

### 置信度计算

confidence = 0.4 * 类别匹配 + 0.3 * 框架匹配 + 0.2 * 严重度匹配 + 0.1 * 规则ID精确匹配

过滤阈值: confidence >= 0.3

## 公开 API

核心类: `GitHubFixMatcher`
- `match_fixes(findings, fingerprint, max_results)` -> List[CodeFix]
- `get_library_stats()` -> Dict[str, int]

便捷函数:
- `detect_tech_fingerprint(findings, project_path)` -> TechFingerprint
- `generate_fix_suggestions(findings, fingerprint, max_per_finding)` -> List[CodeFix]
- `fix_to_markdown(fix)` -> str

## 安全红线

- S6: 零网络依赖，纯本地案例库
- S2: 不修改用户源文件，仅输出建议
- 案例库基于已知公开 CVE 修复 commit

## 测试覆盖

- 测试文件: tests/exp_fix/test_github_fix_matcher.py
- 测试数量: ~55
- 覆盖率: 96%
- 覆盖要点: 案例完整性验证/指纹检测/匹配引擎/PR模板生成/类别提取全分支
