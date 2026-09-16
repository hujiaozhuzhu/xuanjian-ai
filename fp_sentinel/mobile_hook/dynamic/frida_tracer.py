# -*- coding: utf-8 -*-
"""FridaTracer —— frida-trace 封装 + Native 层 Hook 模板引擎。

职责：
- 依据 HookPoint 列表生成 Frida 注入脚本（复用技法层脚本模板）；
- 封装设备附加 / 脚本注入 / 消息回调的生命周期；
- **降级策略**：frida 库不可用或无设备时，``is_available()`` 返回 False，
  ``attach()`` 抛出 :class:`FridaUnavailableError`，上层
  （HookLocator / CLI）捕获后自动回退为纯静态分析结果；
- Native 层 Hook：提供常见 native / SSL / OkHttp / SharedPreferences /
  SQLite 等预置模板，支持按目标参数化生成完整 Frida JS 脚本。

本模块自身绝不直接连接设备，除非调用方显式传入已就绪的 device serial
并调用 ``run()``；``dry_run`` 模式（默认）只生成与校验脚本。

所有模板保证 Frida 16.x 兼容性（使用 Interceptor.attach / Java.use，
避免已废弃的 NativeFunction 旧写法）。
"""

from __future__ import annotations

import logging
import time
from typing import Callable, Dict, List, Optional

from ..models import HookPoint
from ..techniques.base import build_technique

logger = logging.getLogger(__name__)


class FridaUnavailableError(RuntimeError):
    """frida 运行时不可用（未安装 / 无 USB 设备 / server 未启动）。"""


# ─────────────────────────────────────────────────────────────
# Native Hook 模板（Frida 16.x 兼容）
# ─────────────────────────────────────────────────────────────

NATIVE_HOOK_TEMPLATES: Dict[str, str] = {
    "ssl_pinning_bypass": """\
// ─── SSL Pinning Bypass (javax.net.ssl.X509TrustManager + OkHttp3) ───
Java.perform(function () {
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var X509TrustManager = Java.registerClass({
        name: "com.fsentinel.X509TrustManager",
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) {},
            checkServerTrusted: function (chain, authType) {},
            getAcceptedIssuers: function () { return []; }
        }
    });
    var TrustManagers = [X509TrustManager.$new()];
    var init = SSLContext.getInstance("TLS").init(
        null, TrustManagers, Java.use("java.security.SecureRandom").$new()
    );
    console.log("[*] SSLContext TrustManager replaced");

    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function () {
            console.log("[*] OkHttp3 CertificatePinner.check bypassed");
        };
    } catch (e) { console.log("[!] OkHttp3 not found: " + e); }
});""",

    "jni_function_trace": """\
// ─── JNI Function Trace: {so_name} / {func_name} ───
// 支持的占位符: {so_name}, {func_name}, {arg_count}, {ret_type}
Java.perform(function () {{
    var mod = Process.findModuleByName("{so_name}");
    if (!mod) {{
        console.log("[!] Module {so_name} not loaded yet");
        return;
    }}
    var addr = Module.findExportByName("{so_name}", "{func_name}");
    if (!addr) {{
        console.log("[!] Export {func_name} not found in {so_name}");
        return;
    }}
    console.log("[*] Hooking {so_name}!{func_name} at " + addr);
    Interceptor.attach(addr, {{
        onEnter: function (args) {{
            console.log("[+] Enter {so_name}!{func_name}{arg_dump}");
        }},
        onLeave: function (retval) {{
            console.log("[-] Leave  {so_name}!{func_name} ret=" + retval);
        }}
    }});
}});""",

    "crypto_native": """\
// ─── Native Crypto Hook (OpenSSL EVP / BCrypt) ───
Java.perform(function () {{
    // OpenSSL EVP_EncryptInit_ex / EVP_EncryptUpdate / EVP_EncryptFinal_ex
    var opensslFns = [
        {{ name: "EVP_EncryptInit_ex", dumpArgs: false }},
        {{ name: "EVP_CipherInit_ex", dumpArgs: false }},
        {{ name: "EVP_EncryptUpdate", dumpArgs: false }},
        {{ name: "EVP_EncryptFinal_ex", dumpArgs: false }},
        {{ name: "EVP_DecryptInit_ex", dumpArgs: false }},
        {{ name: "EVP_DecryptUpdate", dumpArgs: false }},
        {{ name: "EVP_DecryptFinal_ex", dumpArgs: false }}
    ];
    opensslFns.forEach(function (fn) {{
        try {{
            var addr = Module.findExportByName("libssl.so", fn.name)
                || Module.findExportByName("libcrypto.so", fn.name)
                || Module.findExportByName("libssl.so.3", fn.name)
                || Module.findExportByName("libcrypto.so.3", fn.name);
            if (addr) {{
                Interceptor.attach(addr, {{
                    onEnter: function (args) {{
                        console.log("[crypto] " + fn.name + " called from " + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\\n"));
                    }}
                }});
                console.log("[*] Hooked " + fn.name + " @ " + addr);
            }}
        }} catch (e) {{ console.log("[!] " + fn.name + ": " + e); }}
    }});
    // Android BCrypt / native crypto
    var bcAddr = Module.findExportByName("libbc.so", "BCryptEncrypt")
        || Module.findExportByName(null, "BCryptEncrypt");
    if (bcAddr) {{
        Interceptor.attach(bcAddr, {{
            onEnter: function (args) {{ console.log("[crypto] BCryptEncrypt called"); }},
            onLeave: function (retval) {{ console.log("[-] BCryptEncrypt ret=" + retval); }}
        }});
    }}
}});""",

    "okhttp3_interceptor": """\
// ─── OkHttp3 Internal Layer Hook 完整请求/响应 ───
Java.perform(function () {{
    try {{
        var Buffer = Java.use("okio.Buffer");
        // Hook ResponseBody.source 获取完整响应体
        var ResponseBody = Java.use("okhttp3.ResponseBody");
        ResponseBody.string.implementation = function () {{
            var result = this.string();
            try {{
                var req = this.$field_response ? this.$field_response.request() : null;
                if (req) {{
                    console.log("\\n[*] === OkHttp3 Response ===");
                    console.log("URL:    " + req.url());
                    console.log("Method: " + req.method());
                    console.log("Body:  " + result.substring(0, Math.min(result.length, 4096)));
                }}
            }} catch (e) {{ console.log("[!] ResponseBody.string hook err: " + e); }}
            return result;
        }};
        // Hook Request.Builder 记录完整请求
        var RequestBuilder = Java.use("okhttp3.Request$Builder");
        RequestBuilder.build.implementation = function () {{
            var request = this.build();
            console.log("\\n[*] === OkHttp3 Build Request ===");
            console.log("URL:    " + request.url());
            console.log("Method: " + request.method());
            return request;
        }};
        console.log("[*] OkHttp3 internal hook installed on {target_class}");
    }} catch (e) {{ console.log("[!] OkHttp3 hook failed: " + e); }}
}});""",

    "shared_preferences_dump": """\
// ─── Android SharedPreferences Hook (getString/putString) ───
Java.perform(function () {{
    try {{
        var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");
        SharedPreferencesImpl.getString.overload("java.lang.String", "java.lang.Object").implementation = function (key, defVal) {{
            var result = this.getString(key, defVal);
            console.log("[SP] getString(\\"" + key + "\\") => \\"" + result + "\\"");
            return result;
        }};
        SharedPreferencesImpl.EditorImpl.putString.implementation = function (key, value) {{
            console.log("[SP] putString(\\"" + key + "\\", \\"" + value + "\\")");
            return this.putString(key, value);
        }};
        console.log("[*] SharedPreferences hook installed");
    }} catch (e) {{ console.log("[!] SharedPreferences hook failed: " + e); }}
}});""",

    "sqlite_query_hook": """\
// ─── SQLite execSQL / rawQuery Hook ───
Java.perform(function () {{
    try {{
        var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
        SQLiteDatabase.execSQL.overload("java.lang.String").implementation = function (sql) {{
            console.log("[SQL] execSQL(\\"" + sql + "\\")");
            return this.execSQL(sql);
        }};
        SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;").implementation = function (sql, args) {{
            console.log("[SQL] rawQuery(\\"" + sql + "\\")");
            return this.rawQuery(sql, args);
        }};
        try {{
            SQLiteDatabase.rawQueryWithFactory.overload(
                "android.database.sqlite.SQLiteDatabase$CursorFactory",
                "java.lang.String",
                "[Ljava.lang.String;",
                "java.lang.String",
                "android.database.sqlite.SQLiteDatabase$CursorFactory"
            ).implementation = function (factory, sql, selectionArgs, editTable, cancellationSignal) {{
                console.log("[SQL] rawQueryWithFactory(\\"" + sql + "\\")");
                return this.rawQueryWithFactory(factory, sql, selectionArgs, editTable, cancellationSignal);
            }};
        }} catch (e) {{ /* API level dependent */ }}
        console.log("[*] SQLite query hook installed");
    }} catch (e) {{ console.log("[!] SQLite hook failed: " + e); }}
}});""",
}


class FridaScriptGenerator:
    """Frida JS 脚本生成器：管理 native hook 模板与多模板合并。

    用法::

        gen = FridaScriptGenerator()
        script = gen.generate_native_hook("ssl_pinning_bypass")
        combined = gen.generate_combined_trace(["ssl_pinning_bypass", "sqlite_query_hook"])
    """

    def __init__(self) -> None:
        self._templates: Dict[str, str] = dict(NATIVE_HOOK_TEMPLATES)

    @property
    def available_templates(self) -> List[str]:
        """返回所有可用的模板名称列表。"""
        return sorted(self._templates.keys())

    # ─────────────────────── 单模板生成 ───────────────────────

    def generate_native_hook(self, target: str, **ctx: object) -> str:
        """根据目标标识（模板名）生成完整的 Frida JS 脚本。

        使用安全替换：遍历 ``ctx`` 中的键值对，在模板中做字面
        ``{key}`` -> ``value`` 替换，避免 Python ``.format()`` 与
        JS 字面大括号冲突。

        :param target: 模板名称（``NATIVE_HOOK_TEMPLATES`` 的 key）
        :param ctx:   模板参数化上下文（key=模板占位符, value=替换值）
        :return: 完整的 Frida JS 脚本字符串
        :raises KeyError: 目标模板不存在时抛出
        """
        tpl = self._templates.get(target)
        if tpl is None:
            raise KeyError(
                f"未知 native hook 模板: {target!r}，可用: {list(self._templates)}"
            )
        header = (
            f"// ═══════ 玄鉴 v4.0 Frida Native Hook ═══════\n"
            f"// 模板: {target}\n"
            f"// 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        body = tpl
        for k, v in ctx.items():
            body = body.replace("{" + str(k) + "}", str(v))
        return header + "\n" + body

    # ─────────────────────── 多模板合并 ───────────────────────

    def generate_combined_trace(self, targets: List[str]) -> str:
        """将多个 native hook 模板合并为一个共用 rpc.exports 的完整脚本。

        :param targets: 有序模板名称列表；重复项自动去重
        :return: 合并后的 Frida JS 脚本字符串（包裹在单个 Java.perform 内）
        """
        seen: set = set()
        ordered: List[str] = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                ordered.append(t)

        parts = [
            "// ═══════ 玄鉴 v4.0 Frida Combined Native Trace ═══════",
            f"// 模板列表: {ordered}",
            f"// 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "Java.perform(function () {",
        ]
        exported_methods: List[str] = []
        for t in ordered:
            tpl = self._templates.get(t)
            if tpl is None:
                parts.append(f"  // !! 未知模板 {t}，跳过")
                continue
            # 提取每个模板中的 Java.use / Interceptor.attach 调用并嵌入
            lines = tpl.splitlines()
            # 找到 Block 内的具体 hook 行
            in_block = False
            block_body: List[str] = []
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("Java.perform(function ("):
                    in_block = True
                    continue
                if in_block and stripped == "});":
                    in_block = False
                    continue
                if in_block:
                    block_body.append(line)
            parts.append(f"  // ─── 模板: {t} ───")
            parts.extend("  " + bl if bl.strip() else bl for bl in block_body)
            parts.append("")

        # rpc.exports：提供统一消息回传接口
        if exported_methods:
            parts.append("  // ─── rpc.exports ───")
            for i, method in enumerate(exported_methods):
                parts.append(f'  rpc.exports.{method}: function () {{')

        parts.append("});")

        # rpc.exports 放在 Java.perform 外
        rpc_lines = ["", "rpc.exports = {"]
        rpc_lines.append('    ping: function () { return "pong"; }')
        if exported_methods:
            for m in exported_methods:
                rpc_lines.append(f"    {m}: function () {{ /* auto */ }},")
        rpc_lines.append("};")

        return "\n".join(parts) + "\n" + "\n".join(rpc_lines)


class FridaTracer:
    """frida-trace 封装：脚本生成 + 附加执行（可降级）。

    扩展：集成 :class:`FridaScriptGenerator`，支持 native hook 脚本生成。
    """

    def __init__(
        self,
        device_serial: Optional[str] = None,
        package: Optional[str] = None,
        dry_run: bool = True,
    ):
        self.device_serial = device_serial
        self.package = package
        self.dry_run = dry_run
        self._frida = None  # 惰性导入
        self._native_gen = FridaScriptGenerator()

    # ─────────────────────── 属性访问 ───────────────────────

    @property
    def native_gen(self) -> FridaScriptGenerator:
        """native hook 脚本生成器实例。"""
        return self._native_gen

    # ────────────────────────── 可用性 ──────────────────────────

    def is_available(self) -> bool:
        """frida Python 绑定是否可导入（不探测设备，探测放 attach）。"""
        try:
            self._import_frida()
            return True
        except FridaUnavailableError:
            return False

    def _import_frida(self):
        if self._frida is not None:
            return self._frida
        try:
            import frida  # noqa: PLC0415

            self._frida = frida
            return frida
        except ImportError as exc:
            raise FridaUnavailableError(
                "frida 未安装，动态追踪不可用，已降级为静态分析。"
                "安装: pip install frida frida-tools"
            ) from exc

    # ────────────────────────── 脚本生成 ──────────────────────────

    def generate_script(self, hook_points: List[HookPoint]) -> str:
        """按技法分组生成合并脚本（每个技法一段模板 + 预置系统 Hook）。"""
        if not hook_points:
            return "// 无 Hook 点位"
        by_technique: Dict[str, List[HookPoint]] = {}
        for hp in hook_points:
            by_technique.setdefault(hp.technique, []).append(hp)
        parts = [
            "// ═══════ 玄鉴 v4.0 mobile_hook 自动生成脚本 ═══════",
            f"// 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"// 点位总数: {len(hook_points)}，技法数: {len(by_technique)}",
        ]
        for technique_name, points in by_technique.items():
            try:
                technique = build_technique(technique_name)
                parts.append(f"\n// ───── 技法 {technique_name}（{len(points)} 点位） ─────")
                parts.append(technique.generate_frida_script(points))
            except KeyError:
                logger.warning("未知技法 %s，跳过其脚本生成", technique_name)
                parts.append(f"// !! 未知技法 {technique_name}，未生成脚本")
        return "\n".join(parts)

    def generate_native_hook(self, target: str, **ctx: object) -> str:
        """按 native hook 模板名生成完整 Frida JS 脚本（委托给 FridaScriptGenerator）。

        :param target: 模板名称（``NATIVE_HOOK_TEMPLATES`` 的 key）
        :param ctx:   模板参数化上下文（so_name / func_name 等）
        :return: 完整的 Frida JS 脚本字符串
        """
        return self._native_gen.generate_native_hook(target, **ctx)

    def generate_combined_trace(self, targets: List[str]) -> str:
        """合并多个 native hook 模板为一个脚本（共用 rpc.exports）。

        :param targets: 模板名称列表（有序，去重）
        :return: 合并后的 Frida JS 脚本字符串
        """
        return self._native_gen.generate_combined_trace(targets)

    # ────────────────────────── 附加执行 ──────────────────────────

    def attach(
        self,
        hook_points: List[HookPoint],
        on_message: Optional[Callable[[Dict, Dict], None]] = None,
    ):
        """附加到目标进程并注入脚本。

        - ``dry_run=True``（默认）：只生成并返回脚本，不连接任何设备；
        - ``dry_run=False``：真实附加（需要 frida 环境 + USB 设备）。
        """
        script_src = self.generate_script(hook_points)
        if self.dry_run:
            logger.info("dry_run 模式：仅生成脚本（%d 字符），未连接设备", len(script_src))
            return {"mode": "dry_run", "script": script_src}

        frida = self._import_frida()  # frida 不可用则抛 FridaUnavailableError
        if not self.package:
            raise FridaUnavailableError("真实附加需要指定目标包名 --package")
        try:
            device = (
                frida.get_device(self.device_serial)
                if self.device_serial
                else frida.get_usb_device(timeout=5)
            )
            session = device.attach(self.package)
            script = session.create_script(script_src)
            if on_message is not None:
                script.on("message", on_message)
            script.load()
            return {"mode": "live", "session": session, "script": script}
        except Exception as exc:
            raise FridaUnavailableError(f"Frida 附加失败: {exc}") from exc

    # ────────────────────────── 降级静态 ──────────────────────────

    @staticmethod
    def static_fallback(hook_points: List[HookPoint]) -> Dict:
        """Frida 不可用时的降级输出：静态点位 + 脚本仍可生成备用。"""
        tracer = FridaTracer(dry_run=True)
        return {
            "mode": "static_fallback",
            "reason": "frida 不可用或未连接设备，返回静态分析结果",
            "hook_points": [hp.to_dict() for hp in hook_points],
            "script_ready": bool(hook_points),
            "script": tracer.generate_script(hook_points) if hook_points else "",
        }
