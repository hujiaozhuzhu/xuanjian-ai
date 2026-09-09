# 玄鉴 v2.2.0 开发者画像（Agent-Profile）知识库索引

> 版本：v2.2.0 | 生成时间：2026-09-07 | Agent：Agent-Profile

## 子功能清单

| 子功能 | 归档文档 | 代码位置 | 状态 |
|--------|---------|---------|------|
| P1 画像数据模型 | [P1-profile-models.md](./P1-profile-models.md) | `fp_sentinel/profile/models.py` | 完成 |
| P2 作者归因采集 | [P2-profile-attribution.md](./P2-profile-attribution.md) | `fp_sentinel/profile/attribution.py` | 完成 |
| P3 画像算法(六维度+健康度) | [P3-profile-analyzer.md](./P3-profile-analyzer.md) | `fp_sentinel/profile/analyzer.py` | 完成 |
| P4 报告生成 | [P4-profile-report.md](./P4-profile-report.md) | `fp_sentinel/reporting/profile_report.py` | 完成 |
| P5 隐私控制 | [P5-profile-privacy.md](./P5-profile-privacy.md) | 融入上述模块 | 完成 |
| P6 CLI集成 | [P6-profile-cli.md](./P6-profile-cli.md) | `fp_sentinel/cli/profile_commands.py` | 完成 |

## 测试覆盖

- 单测文件：`tests/unit/test_profile_{models,attribution,analyzer,report,cli,privacy}.py`
- 总用例数：45
- 结果：全部通过（2026-09-07）
- 关联失败：0（全量测试有4个预存在于无关模块的旧失败）

## 安全红线落地

- S1 (禁止外网)：代码中零网络调用
- S2 (禁止修改代码)：git 命令只读（白名单 log/blame/show），subprocess 硬校验
- S3 (禁止删除文件)：forget 仅删画像库数据，不动源文件
- S6 (隐私)：SHA256 别名化 + 可选本地弱加密 + reveal 双条件 + 无绩效导出接口
- S7 (输出白名单)：报告写入 --output 目录，拒绝路径穿透
