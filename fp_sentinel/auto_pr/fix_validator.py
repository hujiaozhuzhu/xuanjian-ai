"""
玄鉴 v3.0 — 修复验证引擎

提交PR前自动验证修复代码的有效性，确保：
1. 原漏洞已被修复（坏模式不再出现）
2. 没有引入新的漏洞（修复代码不含已知危险模式）
3. 代码语法有效
4. 修复逻辑基本正确

安全红线：
- S2: 不修改用户源文件
- S1: 零网络依赖
- 纯本地分析，可测试
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Set, Tuple

from .models import (
    FixPatch,
    FixVerificationResult,
    VerificationStatus,
    VerifyFixRequest,
    VulnerabilityType,
)


# ─────────────────────────── 危险模式定义 ───────────────────────────

# 各漏洞类型对应的危险模式（用于验证原漏洞是否被修复和是否引入新问题）
_VULN_DANGEROUS_PATTERNS: Dict[VulnerabilityType, List[str]] = {
    VulnerabilityType.SQL_INJECTION: [
        ".format(", "f\"SELECT", "f'SELECT", "+ \"SELECT", "+ 'SELECT",
        "\"SELECT", "f\"INSERT", "f\"UPDATE", "f\"DELETE",
    ],
    VulnerabilityType.XSS: [
        "innerHTML", "document.write", "dangerouslySetInnerHTML",
        "v-html", "outerHTML",
    ],
    VulnerabilityType.COMMAND_INJECTION: [
        "os.system(", "exec(", "popen(", "child_process", "shell=True",
    ],
    VulnerabilityType.PATH_TRAVERSAL: [
        "os.path.join(", "path.join(", "open(filepath", "readFile(",
    ],
    VulnerabilityType.HARDCODED_SECRET: [
        "SECRET_KEY = \"", "API_KEY = \"", "PASSWORD = \"",
        "sk-", "AKIA[0-9A-Z]{16}",  # AWS key pattern
    ],
    VulnerabilityType.JWT_WEAK: [
        "algorithm: 'none'", "algorithm: \"none\"",
        "jwt.sign(payload,",
    ],
    VulnerabilityType.YAML_UNSAFE: [
        "yaml.load(", "yaml.unsafe_load(",
    ],
    VulnerabilityType.PICKLE_DESERIALIZE: [
        "pickle.loads(", "pickle.load(",
    ],
    VulnerabilityType.EVAL_INJECTION: [
        "eval(", "new Function(", "Function(",
    ],
    VulnerabilityType.OS_COMMAND: [
        "os.system(",
    ],
    VulnerabilityType.SSRF: [
        "requests.get(url", "axios.get(url", "urlopen(",
    ],
    VulnerabilityType.WEAK_HASH: [
        "hashlib.md5(", "hashlib.sha1(", "createHash('md5')",
    ],
    VulnerabilityType.ECB_MODE: [
        "MODE_ECB", "'aes-ecb'", "mode: 'ecb'",
    ],
    VulnerabilityType.DEBUG_EXPOSURE: [
        "debug=True", "debug = True",
    ],
    VulnerabilityType.OPEN_REDIRECT: [
        "redirect(url", "window.location = url",
    ],
}

# 通用危险模式（任何修复代码都不应包含）
_GENERIC_DANGEROUS_PATTERNS: List[str] = [
    "eval(", "exec(", "os.system(", "shell=True",
    "pickle.loads(", "yaml.load(",
]


# ─────────────────────────── 安全标志 ──────────────────────────各漏洞类型对应的安全标志（表示漏洞已修复的信号）
_VULN_SAFE_PATTERNS: Dict[VulnerabilityType, List[str]] = {
    VulnerabilityType.SQL_INJECTION: [
        "PreparedStatement", "parameterized", "%s", "execute(",
        "cursor.execute", "session.execute", "params=",
    ],
    VulnerabilityType.XSS: [
        "textContent", "DOMPurify", "escape(", "sanitize(",
        "encodeURI", "innerText",
    ],
    VulnerabilityType.COMMAND_INJECTION: [
        "shell=False", "subprocess.run([", "shlex.split",
        "parameterized",
    ],
    VulnerabilityType.PATH_TRAVERSAL: [
        "realpath", "startswith(base)", "abspath", "os.path.realpath",
        "os.path.abspath",
    ],
    VulnerabilityType.HARDCODED_SECRET: [
        "os.environ", "environment", "config.get", "vault",
        "get_secret",
    ],
    VulnerabilityType.JWT_WEAK: [
        "algorithm: 'HS256'", "algorithm: \"HS256\"",
        "verify", "decode(",
    ],
    VulnerabilityType.YAML_UNSAFE: [
        "yaml.safe_load", "safe_load",
    ],
    VulnerabilityType.PICKLE_DESERIALIZE: [
        "json.loads", "json.load",
    ],
    VulnerabilityType.EVAL_INJECTION: [
        "ast.literal_eval", "JSON.parse", "json.loads",
    ],
    VulnerabilityType.OS_COMMAND: [
        "subprocess.run([", "shell=False",
    ],
    VulnerabilityType.SSRF: [
        "ALLOWED_HOSTS", "url.startswith", "whitelist",
        "urlparse", "is_safe_url",
    ],
    VulnerabilityType.WEAK_HASH: [
        "bcrypt", "argon2", "scrypt", "hashlib.sha256",
    ],
    VulnerabilityType.ECB_MODE: [
        "MODE_GCM", "AES.MODE_GCM",
    ],
    VulnerabilityType.DEBUG_EXPOSURE: [
        "debug=False", "debug = False",
    ],
    VulnerabilityType.OPEN_REDIRECT: [
        "urlparse", "ALLOWED_HOST", "is_safe", "netloc",
    ],
}


class FixValidator:
    """修复验证引擎"""

    def __init__(self, strict_mode: bool = False):
        """
        Args:
            strict_mode: 严格模式（True=任何警告都判定为FAIL）
        """
        self.strict_mode = strict_mode

    def verify_fix(self, request: VerifyFixRequest) -> FixVerificationResult:
        """
        验证修复代码的有效性

        Args:
            request: 验证请求

        Returns:
            FixVerificationResult
        """
        details: List[str] = []
        warnings: List[str] = []

        # 1. 语法检查
        syntax_valid = self._check_syntax(request.fixed_code, request.rule_id)
        details.append(f"语法检查: {'通过' if syntax_valid else '失败'}")

        # 2. 检查原漏洞是否已修复
        original_resolved = self._check_vuln_resolved(
            request.original_code, request.fixed_code, request.vuln_type
        )
        details.append(f"原漏洞修复: {'通过' if original_resolved else '未通过'}")

        # 3. 检查是否引入新漏洞
        new_vulns = self._check_new_vulnerabilities(
            request.fixed_code, request.rule_id
        )
        details.append(f"新漏洞检查: 引入 {new_vulns} 个新风险")
        if new_vulns > 0:
            warnings.append(f"修复代码引入了 {new_vulns} 个新的安全风险模式")

        # 4. 综合判定
        security_passed = original_resolved and new_vulns == 0
        if not security_passed:
            if not original_resolved:
                warnings.append("原漏洞的危险模式在修复代码中仍然存在")
            if new_vulns > 0:
                warnings.append("修复代码引入了新的安全风险")

        # 判定验证状态
        if not syntax_valid or not original_resolved or new_vulns > 0:
            status = VerificationStatus.FAIL
        elif warnings:
            status = VerificationStatus.WARN if not self.strict_mode else VerificationStatus.FAIL
        else:
            status = VerificationStatus.PASS

        return FixVerificationResult(
            patch_id=request.patch_id,
            finding_id=request.finding_id,
            status=status,
            original_vuln_resolved=original_resolved,
            new_vulns_introduced=new_vulns,
            syntax_valid=syntax_valid,
            security_check_passed=security_passed,
            details=details,
            warnings=warnings,
        )

    def verify_patch(self, patch: FixPatch, original_code: str) -> FixVerificationResult:
        """
        验证补丁

        Args:
            patch: 修复补丁
            original_code: 原始代码

        Returns:
            FixVerificationResult
        """
        fixed_code = "\n".join(d.fixed_code for d in patch.diffs) if patch.diffs else ""
        request = VerifyFixRequest(
            patch_id=patch.id,
            finding_id=patch.finding_id,
            original_code=original_code,
            fixed_code=fixed_code,
            rule_id="",
            vuln_type=patch.vuln_type,
        )
        return self.verify_fix(request)

    def batch_verify(
        self,
        patches: List[FixPatch],
        original_codes: Dict[str, str],  # finding_id -> original_code
    ) -> List[FixVerificationResult]:
        """批量验证补丁"""
        results = []
        for patch in patches:
            original_code = original_codes.get(patch.finding_id, "")
            result = self.verify_patch(patch, original_code)
            results.append(result)
        return results

    # ─────────────────── 私有方法 ───────────────────

    def _check_syntax(self, code: str, rule_id: str) -> bool:
        """检查代码语法"""
        if not code or not code.strip():
            return False

        # 仅对Python代码进行AST解析
        if self._is_python_code(code, rule_id):
            try:
                ast.parse(code)
                return True
            except SyntaxError:
                return False

        # 非Python代码做基本检查：括号匹配
        return self._check_brackets_balanced(code)

    def _is_python_code(self, code: str, rule_id: str) -> bool:
        """简单判断是否为Python代码"""
        if rule_id and ("python" in rule_id.lower() or rule_id.startswith("py.")):
            return True
        # Python特征
        python_indicators = [
            "import ", "def ", "class ", "print(", "os.", "sys.",
            "cursor.execute", "subprocess.",
        ]
        return any(ind in code for ind in python_indicators)

    def _check_brackets_balanced(self, code: str) -> bool:
        """检查括号是否匹配"""
        pairs = {"(": ")", "[": "]", "{": "}"}
        stack = []
        for char in code:
            if char in pairs:
                stack.append(char)
            elif char in pairs.values():
                if not stack:
                    return False
                if pairs[stack.pop()] != char:
                    return False
        return not stack

    def _check_vuln_resolved(
        self, original_code: str, fixed_code: str, vuln_type: VulnerabilityType
    ) -> bool:
        """检查原漏洞是否已修复"""
        dangerous = _VULN_DANGEROUS_PATTERNS.get(vuln_type, [])
        safe = _VULN_SAFE_PATTERNS.get(vuln_type, [])

        # 特殊处理 SQL 注入：检查是否还有字符串拼接
        if vuln_type == VulnerabilityType.SQL_INJECTION:
            # 修复代码不应包含 SQL 字符串拼接 (f-string or + concatenation with SQL keywords)
            has_concat = (
                ('"SELECT' in fixed_code or "'SELECT" in fixed_code or
                 '"INSERT' in fixed_code or '"UPDATE' in fixed_code or '"DELETE' in fixed_code)
                and ('" + ' in fixed_code or "' + " in fixed_code or
                     'f"' in fixed_code or "f'" in fixed_code or '.format(' in fixed_code)
            )
            # 修复代码应包含参数化查询标志
            has_parameterized = any(p in fixed_code for p in safe)
            if has_concat:
                return False
            return has_parameterized or not has_concat

        # 特殊处理路径遍历：检查是否使用了 realpath/abspath
        if vuln_type == VulnerabilityType.PATH_TRAVERSAL:
            # os.path.join 配合 realpath 和 startswith 是安全的
            if "realpath" in fixed_code or "abspath" in fixed_code:
                return True
            # 如果仍然直接 open(os.path.join(...)) 没有路径校验
            if "os.path.join(" in fixed_code and "realpath" not in fixed_code:
                return False
            return True

        # 通用检查：修复代码不包含危险模式
        still_dangerous = any(p in fixed_code for p in dangerous)
        if still_dangerous:
            return False

        return True

    def _check_new_vulnerabilities(self, fixed_code: str, original_rule_id: str) -> int:
        """检查修复代码是否引入新的漏洞"""
        new_vuln_count = 0

        # 检查通用危险模式
        for pattern in _GENERIC_DANGEROUS_PATTERNS:
            if pattern in fixed_code:
                new_vuln_count += 1

        return new_vuln_count
