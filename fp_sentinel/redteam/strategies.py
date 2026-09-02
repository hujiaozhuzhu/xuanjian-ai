"""
变异策略库

定义各种绕过静态分析规则的变异策略
每种策略包含：应用方法、难度等级、描述
"""

import re
import random
import string
from typing import Dict, Any, Optional
from .generator import MutationStrategy, DifficultyLevel


class StrategyMeta:
    """策略元信息"""
    def __init__(
        self,
        name: MutationStrategy,
        difficulty: DifficultyLevel,
        description: str,
        expected_detected: bool = True,
        is_exploitable: bool = True,
    ):
        self.name = name
        self.difficulty = difficulty
        self.description = description
        self.expected_detected = expected_detected
        self.is_exploitable = is_exploitable

    def apply(self, pattern: str, rule_id: str) -> str:
        """应用策略生成绕过代码"""
        raise NotImplementedError


# ─────────────────────── API 等价替换策略 ───────────────────────

class APISubstitutionStrategy(StrategyMeta):
    """API 等价替换"""

    # JS 危险API → 等价替代映射
    JS_EQUIVALENTS = {
        "eval": [
            'new Function("return " + {arg})()',
            'setTimeout({arg}, 0)',
            'setInterval({arg}, 0)',
            'window["e" + "val"]({arg})',
            'window["eval"]({arg})',
            'this["eval"]({arg})',
            'globalThis["eval"]({arg})',
            'Reflect.apply(eval, globalThis, [{arg}])',
            'import("data:text/javascript," + {arg})',
        ],
        "innerHTML": [
            'outerHTML',
            'insertAdjacentHTML("beforeend", {arg})',
            'document.write({arg})',
            'document.writeln({arg})',
        ],
        "document.write": [
            'document.writeln({arg})',
            'document.body.innerHTML = {arg}',
            'document.documentElement.innerHTML = {arg}',
        ],
        "Function": [
            'eval({arg})',
            'setTimeout({arg}, 0)',
            'Reflect.construct(Function, [{arg}])',
        ],
    }

    def __init__(self):
        super().__init__(
            name=MutationStrategy.API_SUBSTITUTION,
            difficulty=DifficultyLevel.L1_DIRECT,
            description="使用语义等价的API替换原始危险API",
            expected_detected=True,
            is_exploitable=True,
        )

    def apply(self, pattern: str, rule_id: str) -> str:
        for api, equivalents in self.JS_EQUIVALENTS.items():
            if api in pattern:
                replacement = random.choice(equivalents)
                # 提取参数
                arg_match = re.search(r'\(([^)]+)\)', pattern)
                arg = arg_match.group(1) if arg_match else "userInput"
                return replacement.format(arg=arg)
        return pattern


# ─────────────────────── 编码绕过策略 ───────────────────────

class EncodingBypassStrategy(StrategyMeta):
    """编码绕过"""

    def __init__(self):
        super().__init__(
            name=MutationStrategy.ENCODING_BYPASS,
            difficulty=DifficultyLevel.L2_MUTATION,
            description="通过字符串编码绕过关键字检测",
            expected_detected=False,
            is_exploitable=True,
        )

    def apply(self, pattern: str, rule_id: str) -> str:
        # 提取关键字符串
        string_match = re.search(r'["\']([^"\']+)["\']', pattern)
        if not string_match:
            return pattern

        original = string_match.group(1)
        method = random.choice([
            self._unicode_escape,
            self._hex_escape,
            self._base64_encode,
            self._char_code,
            self._string_concat,
            self._template_literal,
            self._reverse_string,
            self._char_at_concat,
        ])
        encoded = method(original)
        return pattern.replace(f'"{original}"', encoded).replace(f"'{original}'", encoded)

    def _unicode_escape(self, s: str) -> str:
        escaped = ''.join(f'\\u{ord(c):04x}' for c in s)
        return f'"{escaped}"'

    def _hex_escape(self, s: str) -> str:
        escaped = ''.join(f'\\x{ord(c):02x}' for c in s)
        return f'"{escaped}"'

    def _base64_encode(self, s: str) -> str:
        import base64
        encoded = base64.b64encode(s.encode()).decode()
        return f'atob("{encoded}")'

    def _char_code(self, s: str) -> str:
        codes = [str(ord(c)) for c in s]
        return f'String.fromCharCode({",".join(codes)})'

    def _string_concat(self, s: str) -> str:
        mid = len(s) // 2
        return f'"{s[:mid]}" + "{s[mid:]}"'

    def _template_literal(self, s: str) -> str:
        mid = len(s) // 2
        return f'`{s[:mid]}${"{"}"{s[mid:]}${"}"}`'

    def _reverse_string(self, s: str) -> str:
        return f'"{s[::-1]}".split("").reverse().join("")'

    def _char_at_concat(self, s: str) -> str:
        parts = [f'String.fromCharCode({ord(c)})' for c in s[:3]]
        if len(s) > 3:
            parts.append(f'"{s[3:]}"')
        return ' + '.join(parts)


# ─────────────────────── 控制流混淆策略 ───────────────────────

class ControlFlowStrategy(StrategyMeta):
    """控制流混淆"""

    def __init__(self):
        super().__init__(
            name=MutationStrategy.CONTROL_FLOW,
            difficulty=DifficultyLevel.L3_OBFUSCATION,
            description="通过控制流变换绕过静态分析",
            expected_detected=False,
            is_exploitable=True,
        )

    def apply(self, pattern: str, rule_id: str) -> str:
        method = random.choice([
            self._ternary_wrapper,
            self._if_else_wrapper,
            self._switch_wrapper,
            self._try_catch_wrapper,
            self._callback_wrapper,
            self._promise_chain,
            self._iife_wrapper,
        ])
        return method(pattern)

    def _ternary_wrapper(self, code: str) -> str:
        return f'true ? {code} : null'

    def _if_else_wrapper(self, code: str) -> str:
        return f'if (true) {{ {code} }}'

    def _switch_wrapper(self, code: str) -> str:
        return f'switch(0) {{ default: {code}; break; }}'

    def _try_catch_wrapper(self, code: str) -> str:
        return f'try {{ {code} }} catch(e) {{}}'

    def _callback_wrapper(self, code: str) -> str:
        return f'[() => {{ {code} }}][0]()'

    def _promise_chain(self, code: str) -> str:
        return f'Promise.resolve().then(() => {{ {code} }})'

    def _iife_wrapper(self, code: str) -> str:
        return f'(function() {{ {code} }})()'


# ─────────────────────── 字符串拆分策略 ───────────────────────

class StringSplittingStrategy(StrategyMeta):
    """字符串拆分"""

    def __init__(self):
        super().__init__(
            name=MutationStrategy.STRING_SPLITTING,
            difficulty=DifficultyLevel.L2_MUTATION,
            description="将关键字符串拆分为多部分拼接",
            expected_detected=False,
            is_exploitable=True,
        )

    def apply(self, pattern: str, rule_id: str) -> str:
        # 提取函数名或关键字
        func_match = re.search(r'(\w+)\s*\(', pattern)
        if not func_match:
            return pattern

        func_name = func_match.group(1)
        if len(func_name) <= 2:
            return pattern

        # 随机拆分点
        split_point = random.randint(1, len(func_name) - 1)
        part1 = func_name[:split_point]
        part2 = func_name[split_point:]

        method = random.choice([
            lambda p1, p2: f'window["{p1}" + "{p2}"]',
            lambda p1, p2: f'`{p1}${{"{p2}"}}`',
            lambda p1, p2: f'["{p1}", "{p2}"].join("")',
            lambda p1, p2: f'"{p1}".concat("{p2}")',
        ])
        return pattern.replace(func_name, method(part1, part2))


# ─────────────────────── 框架特性利用策略 ───────────────────────

class FrameworkAbuseStrategy(StrategyMeta):
    """框架特性利用"""

    def __init__(self):
        super().__init__(
            name=MutationStrategy.FRAMEWORK_ABUSE,
            difficulty=DifficultyLevel.L3_OBFUSCATION,
            description="利用前端框架的特性绕过检测",
            expected_detected=False,
            is_exploitable=True,
        )

    def apply(self, pattern: str, rule_id: str) -> str:
        method = random.choice([
            self._vue_dynamic_component,
            self._react_ref,
            self._angular_innerhtml,
            self._jquery_attr,
            self._dom_parser,
        ])
        return method(pattern)

    def _vue_dynamic_component(self, code: str) -> str:
        return f'<component :is="{{template: `{code}`}}" />'

    def _react_ref(self, code: str) -> str:
        return f'ref.current.innerHTML = {code}'

    def _angular_innerhtml(self, code: str) -> str:
        return f'[innerHTML]="{code}"'

    def _jquery_attr(self, code: str) -> str:
        return f'$("div").attr("onclick", {code})'

    def _dom_parser(self, code: str) -> str:
        return f'new DOMParser().parseFromString({code}, "text/html").body.innerHTML'


# ─────────────────────── 异步包装策略 ───────────────────────

class AsyncWrappingStrategy(StrategyMeta):
    """异步包装"""

    def __init__(self):
        super().__init__(
            name=MutationStrategy.ASYNC_WRAPPING,
            difficulty=DifficultyLevel.L2_MUTATION,
            description="通过异步执行绕过同步分析",
            expected_detected=False,
            is_exploitable=True,
        )

    def apply(self, pattern: str, rule_id: str) -> str:
        method = random.choice([
            self._setTimeout,
            self._setInterval,
            self._requestAnimationFrame,
            self._queueMicrotask,
            self._promise_then,
            self._async_await,
        ])
        return method(pattern)

    def _setTimeout(self, code: str) -> str:
        return f'setTimeout(() => {{ {code} }}, 0)'

    def _setInterval(self, code: str) -> str:
        return f'setInterval(() => {{ {code} }}, 1000)'

    def _requestAnimationFrame(self, code: str) -> str:
        return f'requestAnimationFrame(() => {{ {code} }})'

    def _queueMicrotask(self, code: str) -> str:
        return f'queueMicrotask(() => {{ {code} }})'

    def _promise_then(self, code: str) -> str:
        return f'Promise.resolve().then(() => {{ {code} }})'

    def _async_await(self, code: str) -> str:
        return f'(async () => {{ {code} }})()'


# ─────────────────────── 原型链利用策略 ───────────────────────

class PrototypeChainStrategy(StrategyMeta):
    """原型链利用"""

    def __init__(self):
        super().__init__(
            name=MutationStrategy.PROTOTYPE_CHAIN,
            difficulty=DifficultyLevel.L4_COMPOSITION,
            description="通过原型链操作绕过检测",
            expected_detected=False,
            is_exploitable=True,
        )

    def apply(self, pattern: str, rule_id: str) -> str:
        method = random.choice([
            self._constructor_chain,
            self._proto_access,
            self._reflect_get,
        ])
        return method(pattern)

    def _constructor_chain(self, code: str) -> str:
        return f'[][\"constructor\"][\"constructor\"]({code})()'

    def _proto_access(self, code: str) -> str:
        return f'window.__proto__.__proto__.eval({code})'

    def _reflect_get(self, code: str) -> str:
        return f'Reflect.get(globalThis, \"eval\")({code})'


# ─────────────────────── 编码器链策略 ───────────────────────

class EncoderChainStrategy(StrategyMeta):
    """编码器链（多层编码）"""

    def __init__(self):
        super().__init__(
            name=MutationStrategy.ENCODER_CHAIN,
            difficulty=DifficultyLevel.L3_OBFUSCATION,
            description="多层编码嵌套绕过检测",
            expected_detected=False,
            is_exploitable=True,
        )

    def apply(self, pattern: str, rule_id: str) -> str:
        import base64
        string_match = re.search(r'["\']([^"\']+)["\']', pattern)
        if not string_match:
            return pattern

        original = string_match.group(1)
        # Base64 → Unicode → Base64
        layer1 = base64.b64encode(original.encode()).decode()
        layer2 = ''.join(f'\\u{ord(c):04x}' for c in layer1)
        return f'atob("{layer2}")'


# ─────────────────────── 类型混淆策略 ───────────────────────

class TypeConfusionStrategy(StrategyMeta):
    """类型混淆"""

    def __init__(self):
        super().__init__(
            name=MutationStrategy.TYPE_CONFUSION,
            difficulty=DifficultyLevel.L2_MUTATION,
            description="利用类型转换绕过检测",
            expected_detected=False,
            is_exploitable=True,
        )

    def apply(self, pattern: str, rule_id: str) -> str:
        method = random.choice([
            self._number_to_string,
            self._boolean_coercion,
            self._array_to_string,
        ])
        return method(pattern)

    def _number_to_string(self, code: str) -> str:
        return f'({code}).toString()'

    def _boolean_coercion(self, code: str) -> str:
        return f'!!{code} ? {code} : null'

    def _array_to_string(self, code: str) -> str:
        return f'[{code}].pop()'


# ─────────────────────── 时序攻击策略 ───────────────────────

class TimingAttackStrategy(StrategyMeta):
    """时序攻击"""

    def __init__(self):
        super().__init__(
            name=MutationStrategy.TIMING_ATTACK,
            difficulty=DifficultyLevel.L4_COMPOSITION,
            description="利用时序差异绕过检测",
            expected_detected=False,
            is_exploitable=True,
        )

    def apply(self, pattern: str, rule_id: str) -> str:
        return f'setTimeout(() => {{ {pattern} }}, Math.random() * 100)'


# ─────────────────────── 策略注册表 ───────────────────────

MUTATION_STRATEGIES: Dict[MutationStrategy, StrategyMeta] = {
    MutationStrategy.API_SUBSTITUTION: APISubstitutionStrategy(),
    MutationStrategy.ENCODING_BYPASS: EncodingBypassStrategy(),
    MutationStrategy.CONTROL_FLOW: ControlFlowStrategy(),
    MutationStrategy.STRING_SPLITTING: StringSplittingStrategy(),
    MutationStrategy.FRAMEWORK_ABUSE: FrameworkAbuseStrategy(),
    MutationStrategy.ASYNC_WRAPPING: AsyncWrappingStrategy(),
    MutationStrategy.PROTOTYPE_CHAIN: PrototypeChainStrategy(),
    MutationStrategy.ENCODER_CHAIN: EncoderChainStrategy(),
    MutationStrategy.TYPE_CONFUSION: TypeConfusionStrategy(),
    MutationStrategy.TIMING_ATTACK: TimingAttackStrategy(),
}
