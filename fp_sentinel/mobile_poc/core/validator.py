"""POC 校验器: JS/Python 语法检查 + 占位符检查 + API 使用合规检查。

三道校验关卡(规划文档 2.5.2 第5步):
1. 语法检查  —— JS: 括号/引号配对 + 结构完整性; Python: py_compile 编译;
2. 占位符检查 —— 渲染残留的 {{ }} / {% %} / __UPPERCASE__ 占位符必须为空;
3. API 合规   —— 禁止网络外发 API(红线 M2)、禁止提权/持久化 API(红线 M7);
                 必须包含风险提示注释(安全注记, 规划文档 2.5.2 第4步)。
"""

from __future__ import annotations

import py_compile
import re
import tempfile
from pathlib import Path
from typing import List, Optional

from ..models.poc_result import ValidationReport

__all__ = ["POCValidator"]

# ---- 红线 M2: 禁止 Hook 数据网络外发 ----
_FORBIDDEN_JS_NET = [
    (r"\bfetch\s*\(", "JS fetch() 网络外发 API(红线 M2)"),
    (r"\bXMLHttpRequest\b", "XMLHttpRequest 网络外发 API(红线 M2)"),
    (r"\bnew\s+WebSocket\b", "WebSocket 网络外发 API(红线 M2)"),
    (r"\bjava\.net\.URL\s*\(", "JS 内构造 URL 网络外发(红线 M2)"),
    (r"new\s+okhttp3\.(?:Request|OkHttpClient|Builder)", "JS 内构造 okhttp 请求外发数据(红线 M2)"),
    (r"\bHttpURLConnection\b", "HttpURLConnection 网络外发 API(红线 M2)"),
]
# ---- 红线 M7: 禁止提权/注入/持久化 ----
_FORBIDDEN_JS_EXPLOIT = [
    (r"\bexec\s*\(\s*['\"]su\b", "su 提权执行(红线 M7)"),
    (r"\bRuntime\.getRuntime\(\)\.exec\b", "JS 内 Runtime.exec 提权(红线 M7)"),
    (r"\bpersistent\b.*=\s*true", "持久化标记(红线 M7)"),
]

_PLACEHOLDER_RE = re.compile(r"\{\{.*?\}\}|\{%.*?%\}")
_PLACEHOLDER_CONST_RE = re.compile(r"__[A-Z][A-Z0-9_]{2,}__")
# RD-007: 占位符包名/占位符值残留（如 com.target.app / com.example.app）。
# 这类残留不构成语法错误，但意味着 POC 未针对真实目标渲染 —— 只降分不报错。
_PLACEHOLDER_PKG_RE = re.compile(
    r"(?i)\bcom\.(?:target|example|yourapp|yourcompany|test|demo|dummy)"
    r"(?:\.[a-z0-9_]+)+\b"
    r"|<your[_-]?package[_-]?name?>"
    r"|\bcom\.package\.name\b"
    r"|\byour[_-]?package[_-]?name\b"
)

_BRACKET_PAIRS = {")": "(", "]": "[", "}": "{"}


class POCValidator:
    """POC 脚本校验器。"""

    def validate(self, script: str, language: str = "js") -> ValidationReport:
        if language in ("js", "javascript"):
            return self.validate_js(script)
        if language in ("py", "python"):
            return self.validate_py(script)
        report = ValidationReport(valid=False)
        report.errors.append(f"unsupported language: {language!r}")
        return report

    # ------------------------------------------------------------------- js
    def validate_js(self, script: str) -> ValidationReport:
        errors: List[str] = []
        warnings: List[str] = []
        checks: dict = {}

        checks["syntax_brackets"] = self._check_brackets(script, errors)
        checks["syntax_quotes"] = self._check_quotes(script, errors, warnings)
        checks["no_placeholders"] = self._check_placeholders(script, errors)
        checks["no_placeholder_pkg"] = self._check_placeholder_package(script, warnings)
        checks["api_compliance"] = self._check_api_compliance_js(script, errors)
        checks["risk_annotation"] = self._check_risk_annotation(script, warnings, errors)
        if "Java.perform" not in script and "Java.use" in script:
            errors.append("使用了 Java.use 但缺少 Java.perform 包裹(线程安全)")
        if not script.strip():
            errors.append("脚本内容为空")

        valid = not errors
        score = self._score(checks, len(errors), len(warnings))
        return ValidationReport(valid=valid, errors=errors, warnings=warnings,
                                checks=checks, score=score)

    # ------------------------------------------------------------------- py
    def validate_py(self, script: str) -> ValidationReport:
        errors: List[str] = []
        warnings: List[str] = []
        checks: dict = {}

        checks["syntax_compile"] = self._check_py_compile(script, errors)
        checks["no_placeholders"] = self._check_placeholders(script, errors)
        checks["no_placeholder_pkg"] = self._check_placeholder_package(script, warnings)
        checks["api_compliance"] = self._check_api_compliance_py(script, errors)
        checks["risk_annotation"] = self._check_risk_annotation(script, warnings, errors)
        if "requests.post" in script or "urllib.request.urlopen" in script:
            errors.append("检测到网络外发调用(红线 M2): 数据仅允许写本地 SQLite")

        valid = not errors
        score = self._score(checks, len(errors), len(warnings))
        return ValidationReport(valid=valid, errors=errors, warnings=warnings,
                                checks=checks, score=score)

    # -------------------------------------------------------------- helpers
    @staticmethod
    def _strip_js_comments(script: str) -> str:
        """去除 /* */ 与 // 注释, 保留字符串原样(近似实现, 供括号/引号检查)。"""
        no_block = re.sub(r"/\*.*?\*/", lambda m: " " * len(m.group(0)), script, flags=re.DOTALL)
        return re.sub(r"//[^\n]*", lambda m: " " * len(m.group(0)), no_block)

    @staticmethod
    def _check_brackets(script: str, errors: List[str]) -> bool:
        source = POCValidator._strip_js_comments(script)
        stack: List[str] = []
        in_str: Optional[str] = None
        escape = False
        for idx, ch in enumerate(source):
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == in_str:
                    in_str = None
                continue
            if ch in ("'", '"', "`"):
                in_str = ch
            elif ch in "([{":
                stack.append(ch)
            elif ch in ")]}":
                if not stack or stack[-1] != _BRACKET_PAIRS[ch]:
                    line = source.count("\n", 0, idx) + 1
                    errors.append(f"括号不匹配: 第 {line} 行附近出现多余 {ch!r}")
                    return False
                stack.pop()
        if in_str:
            errors.append("存在未闭合的字符串字面量")
            return False
        if stack:
            errors.append(f"存在未闭合的括号: {stack}")
            return False
        return True

    @staticmethod
    def _check_quotes(script: str, errors: List[str], warnings: List[str]) -> bool:
        """逐行检查未闭合的普通引号(模板字符串反引号允许跨行)。"""
        source = POCValidator._strip_js_comments(script)
        for line_no, line in enumerate(source.splitlines(), 1):
            no_template = re.sub(r"`[^`]*`", '""', line)
            for quote in ("'", '"'):
                count = 0
                escape = False
                for ch in no_template:
                    if escape:
                        escape = False
                    elif ch == "\\":
                        escape = True
                    elif ch == quote:
                        count += 1
                if count % 2 != 0:
                    # 反引号跨行包含单双引号属于合法场景, 仅警告
                    warnings.append(f"第 {line_no} 行引号数量为奇数, 请人工复核")
        return True

    @staticmethod
    def _check_placeholders(script: str, errors: List[str]) -> bool:
        leftovers = _PLACEHOLDER_RE.findall(script)
        if leftovers:
            errors.append(f"渲染残留占位符({len(leftovers)}处): {leftovers[:3]}")
        consts = _PLACEHOLDER_CONST_RE.findall(script)
        if consts:
            errors.append(f"存在未填充的常量占位符: {sorted(set(consts))}")
        return not leftovers and not consts

    @staticmethod
    def _check_placeholder_package(script: str, warnings: List[str]) -> bool:
        """RD-007: 占位符包名残留检测（仅警告 + 评分封顶，不判无效）。"""
        hits = sorted(set(_PLACEHOLDER_PKG_RE.findall(script)))
        if hits:
            warnings.append(
                f"疑似占位符包名残留({len(hits)}处): {hits[:3]} —— "
                "请替换为真实目标包名后重新渲染")
        return not hits

    @staticmethod
    def _check_api_compliance_js(script: str, errors: List[str]) -> bool:
        ok = True
        for pattern, msg in _FORBIDDEN_JS_NET:
            if re.search(pattern, script):
                errors.append(f"API 违规: {msg} (匹配 {pattern!r})")
                ok = False
        for pattern, msg in _FORBIDDEN_JS_EXPLOIT:
            if re.search(pattern, script):
                errors.append(f"API 违规: {msg} (匹配 {pattern!r})")
                ok = False
        return ok

    @staticmethod
    def _check_api_compliance_py(script: str, errors: List[str]) -> bool:
        ok = True
        if re.search(r"\bsocket\.socket\b", script) and "frida" not in script:
            errors.append("API 违规: 原生 socket 外发(红线 M2)")
            ok = False
        if re.search(r"os\.system\s*\(\s*['\"]su\b", script):
            errors.append("API 违规: su 提权(红线 M7)")
            ok = False
        return ok

    @staticmethod
    def _check_risk_annotation(script: str, warnings: List[str], errors: List[str]) -> bool:
        head = script[:3000]
        has_risk = ("风险提示" in head) or ("RISK" in head) or ("Risk" in head)
        if not has_risk:
            errors.append("缺少【风险提示】安全注记注释(规划文档 2.5.2 第4步)")
        if "功能说明" not in head:
            warnings.append("缺少【功能说明】注释, 建议补充")
        if "使用方法" not in head and "使用说明" not in head:
            warnings.append("缺少【使用方法】注释, 建议补充")
        return has_risk

    @staticmethod
    def _check_py_compile(script: str, errors: List[str]) -> bool:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".py", delete=False, encoding="utf-8"
        ) as fp:
            fp.write(script)
            tmp = Path(fp.name)
        try:
            py_compile.compile(str(tmp), doraise=True)
            return True
        except py_compile.PyCompileError as exc:
            errors.append(f"Python 语法错误: {exc}")
            return False
        finally:
            tmp.unlink(missing_ok=True)

    @staticmethod
    def _score(checks: dict, n_errors: int, n_warnings: int) -> float:
        if not checks:
            return 0.0
        passed = sum(1 for v in checks.values() if v)
        base = passed / len(checks) * 100
        score = round(max(0.0, base - n_errors * 15 - n_warnings * 3), 1)
        # RD-007: 占位符包名残留 → 评分封顶 60（提示必须重新渲染真实目标）
        if checks.get("no_placeholder_pkg") is False:
            score = min(score, 60.0)
        return score
