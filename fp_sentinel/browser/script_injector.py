"""
脚本注入器

管理 JavaScript 脚本的注入，支持:
- 页面加载前注入 (addInitScript)
- 页面加载后注入 (evaluate)
- 函数 Hook 注入
- 自定义脚本模板
"""

import logging
from typing import Optional, Dict, Any, List
from pathlib import Path

logger = logging.getLogger(__name__)

# 内置脚本目录
SCRIPTS_DIR = Path(__file__).parent / "scripts"


class ScriptInjector:
    """脚本注入器"""

    def __init__(self):
        self._templates: Dict[str, str] = {}
        self._load_builtin_scripts()

    def _load_builtin_scripts(self):
        """加载内置脚本"""
        if not SCRIPTS_DIR.exists():
            return

        for script_file in SCRIPTS_DIR.glob("*.js"):
            try:
                content = script_file.read_text(encoding="utf-8")
                self._templates[script_file.stem] = content
            except Exception as e:
                logger.error(f"Failed to load script {script_file}: {e}")

    async def inject_before_load(self, page, script: str):
        """页面加载前注入 (addInitScript)"""
        await page.add_init_script(script)
        logger.debug(f"Injected init script ({len(script)} chars)")

    async def inject_after_load(self, page, script: str) -> Any:
        """页面加载后注入 (evaluate)"""
        result = await page.evaluate(script)
        logger.debug(f"Evaluated script ({len(script)} chars)")
        return result

    async def inject_hook(self, page, target: str, hook_type: str = "trace") -> Dict[str, Any]:
        """注入函数 Hook"""
        hook_script = self._generate_hook_script(target, hook_type)
        result = await page.evaluate(hook_script)
        logger.info(f"Injected {hook_type} hook on: {target}")
        return {"target": target, "hook_type": hook_type, "result": result}

    async def inject_rpc_bridge(self, page, rpc_port: int = 18800):
        """注入 RPC 桥接脚本"""
        template = self._templates.get("rpc_bridge", "")
        if not template:
            logger.warning("RPC bridge script not found")
            return

        script = template.replace("__PORT__", str(rpc_port))
        await page.evaluate(script)
        logger.info(f"Injected RPC bridge (port: {rpc_port})")

    async def inject_crypto_hooks(self, page):
        """注入加解密 Hook 脚本"""
        template = self._templates.get("crypto_hooks", "")
        if not template:
            logger.warning("Crypto hooks script not found")
            return

        await page.evaluate(template)
        logger.info("Injected crypto hooks")

    async def inject_xhr_hooks(self, page):
        """注入 XHR/Fetch Hook 脚本"""
        template = self._templates.get("xhr_hooks", "")
        if not template:
            logger.warning("XHR hooks script not found")
            return

        await page.evaluate(template)
        logger.info("Injected XHR/Fetch hooks")

    async def inject_cookie_hooks(self, page):
        """注入 Cookie Hook 脚本"""
        template = self._templates.get("cookie_hooks", "")
        if not template:
            logger.warning("Cookie hooks script not found")
            return

        await page.evaluate(template)
        logger.info("Injected cookie hooks")

    def _generate_hook_script(self, target: str, hook_type: str) -> str:
        """生成 Hook 脚本"""
        if hook_type == "trace":
            return self._generate_trace_hook(target)
        elif hook_type == "before":
            return self._generate_before_hook(target)
        elif hook_type == "after":
            return self._generate_after_hook(target)
        elif hook_type == "replace":
            return self._generate_replace_hook(target)
        else:
            raise ValueError(f"Unknown hook type: {hook_type}")

    def _generate_trace_hook(self, target: str) -> str:
        """生成函数追踪 Hook"""
        return f"""
        (function() {{
            try {{
                var parts = '{target}'.split('.');
                var obj = window;
                for (var i = 0; i < parts.length - 1; i++) {{
                    obj = obj[parts[i]];
                    if (!obj) return {{ success: false, error: 'Object path not found: ' + parts.slice(0, i+1).join('.') }};
                }}
                var funcName = parts[parts.length - 1];
                var original = obj[funcName];
                if (typeof original !== 'function') {{
                    return {{ success: false, error: 'Target is not a function: ' + typeof original }};
                }}

                var callLog = [];
                obj[funcName] = function() {{
                    var args = Array.from(arguments);
                    var start = performance.now();
                    var result = original.apply(this, arguments);
                    var end = performance.now();

                    var entry = {{
                        args: args.map(function(a) {{
                            try {{ return typeof a === 'object' ? JSON.stringify(a) : String(a); }}
                            catch(e) {{ return '[Unserializable]'; }}
                        }}),
                        result: typeof result === 'object' ? JSON.stringify(result) : String(result),
                        duration: Math.round((end - start) * 100) / 100,
                        timestamp: Date.now(),
                        stack: new Error().stack.split('\\n').slice(1, 4).join('\\n')
                    }};
                    callLog.push(entry);

                    // 通过自定义事件上报
                    window.dispatchEvent(new CustomEvent('xuanjian_hook', {{
                        detail: {{ type: 'trace', target: '{target}', entry: entry }}
                    }}));

                    return result;
                }};
                obj[funcName].__original = original;
                obj[funcName].__hooked = true;
                obj[funcName].__callLog = callLog;

                return {{ success: true, message: 'Hook installed on {target}' }};
            }} catch(e) {{
                return {{ success: false, error: e.message }};
            }}
        }})();
        """

    def _generate_before_hook(self, target: str) -> str:
        """生成前置 Hook"""
        return f"""
        (function() {{
            try {{
                var parts = '{target}'.split('.');
                var obj = window;
                for (var i = 0; i < parts.length - 1; i++) {{
                    obj = obj[parts[i]];
                    if (!obj) return {{ success: false, error: 'Path not found' }};
                }}
                var funcName = parts[parts.length - 1];
                var original = obj[funcName];

                obj[funcName] = function() {{
                    var args = Array.from(arguments);
                    window.dispatchEvent(new CustomEvent('xuanjian_hook', {{
                        detail: {{ type: 'before', target: '{target}', args: args }}
                    }}));
                    return original.apply(this, arguments);
                }};
                obj[funcName].__original = original;

                return {{ success: true }};
            }} catch(e) {{
                return {{ success: false, error: e.message }};
            }}
        }})();
        """

    def _generate_after_hook(self, target: str) -> str:
        """生成后置 Hook"""
        return f"""
        (function() {{
            try {{
                var parts = '{target}'.split('.');
                var obj = window;
                for (var i = 0; i < parts.length - 1; i++) {{
                    obj = obj[parts[i]];
                    if (!obj) return {{ success: false, error: 'Path not found' }};
                }}
                var funcName = parts[parts.length - 1];
                var original = obj[funcName];

                obj[funcName] = function() {{
                    var result = original.apply(this, arguments);
                    window.dispatchEvent(new CustomEvent('xuanjian_hook', {{
                        detail: {{ type: 'after', target: '{target}', result: result }}
                    }}));
                    return result;
                }};
                obj[funcName].__original = original;

                return {{ success: true }};
            }} catch(e) {{
                return {{ success: false, error: e.message }};
            }}
        }})();
        """

    def _generate_replace_hook(self, target: str) -> str:
        """生成替换 Hook（需要用户提供替换函数）"""
        return f"""
        (function() {{
            try {{
                var parts = '{target}'.split('.');
                var obj = window;
                for (var i = 0; i < parts.length - 1; i++) {{
                    obj = obj[parts[i]];
                    if (!obj) return {{ success: false, error: 'Path not found' }};
                }}
                var funcName = parts[parts.length - 1];
                var original = obj[funcName];

                // 保存原函数引用，用户可通过 __setReplacement 设置替换函数
                obj[funcName].__original = original;
                obj[funcName].__setReplacement = function(fn) {{
                    obj[funcName] = fn;
                    obj[funcName].__original = original;
                }};

                return {{ success: true, message: 'Use __setReplacement(fn) to replace' }};
            }} catch(e) {{
                return {{ success: false, error: e.message }};
            }}
        }})();
        """

    def get_template(self, name: str) -> Optional[str]:
        """获取脚本模板"""
        return self._templates.get(name)

    def register_template(self, name: str, script: str):
        """注册自定义脚本模板"""
        self._templates[name] = script
        logger.info(f"Registered script template: {name}")

    def list_templates(self) -> List[str]:
        """列出所有模板"""
        return list(self._templates.keys())
