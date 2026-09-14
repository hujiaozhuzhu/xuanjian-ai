"""fp_sentinel.mobile_poc —— 玄鉴 v4.0 能力⑤: Frida POC 自动生成。

安全红线对齐(规划文档第五章):
- M6: 生成的 POC 脚本只能 Hook 用户授权的 app 包名;
- M7: POC 仅用于抓包/参数打印/返回值修改, 禁止提权/注入/持久化;
- M2: Hook 数据仅本地留存, 模板禁止任何网络外发代码。
"""

__version__ = "4.0.0"

__all__ = ["POCGenerator", "POCValidator", "TemplateEngine", "POCResult"]
