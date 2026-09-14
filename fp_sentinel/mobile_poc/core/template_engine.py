"""模板渲染引擎(Jinja2 风格, 零第三方依赖)。

支持语法子集:
- 变量: ``{{ var }}`` ``{{ obj.attr }}`` ``{{ items | join(", ") }}``
- 分支: ``{% if expr %} / {% elif expr %} / {% else %} / {% endif %}``
- 循环: ``{% for x in seq %} / {% endfor %}``  (循环体内提供 ``loop.index0/1/last``)
- 注释: ``{% comment %} ... {% endcomment %}`` (渲染时整块剔除)
- 过滤器: default / length / upper / lower / trim / join / replace

安全设计: 表达式仅允许字面量、名称、属性、下标、布尔/比较/算术运算,
禁止函数调用与导入, 防止模板注入面。
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

__all__ = [
    "TemplateEngine",
    "TemplateError",
    "TemplateNotFoundError",
    "TemplateSyntaxError",
    "UndefinedVariableError",
    "ExpressionError",
]


class TemplateError(Exception):
    """模板引擎基础异常。"""


class TemplateNotFoundError(TemplateError):
    """模板文件不存在。"""


class TemplateSyntaxError(TemplateError):
    """模板语法错误。"""


class UndefinedVariableError(TemplateError):
    """严格模式下变量未定义。"""


class ExpressionError(TemplateError):
    """表达式非法(类型受限或求值失败)。"""


_TOKEN_RE = re.compile(r"(\{\{.*?\}\}|\{%.*?%\})", re.DOTALL)

_ALLOWED_BINOPS = (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod)
_ALLOWED_CMPOPS = (
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
    ast.In,
    ast.NotIn,
    ast.Is,
    ast.IsNot,
)

_FILTER_LENGTH = "length"


def _split_pipes(expr: str) -> List[str]:
    """按引号状态分割管道符 ``|``, 避免 filter 参数内的 ``|`` 被误切。"""
    parts: List[str] = []
    buf: List[str] = []
    quote: Optional[str] = None
    for ch in expr:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
            buf.append(ch)
        elif ch == "|":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return parts


class _Node:
    __slots__ = ()


class _Text(_Node):
    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text


class _Var(_Node):
    __slots__ = ("expr", "filters")

    def __init__(self, expr: str, filters: List[tuple]) -> None:
        self.expr = expr
        self.filters = filters


class _If(_Node):
    __slots__ = ("branches",)

    def __init__(self, branches: List[tuple]) -> None:
        self.branches = branches  # List[(expr_or_None, body)]


class _For(_Node):
    __slots__ = ("var", "iter_expr", "body")

    def __init__(self, var: str, iter_expr: str, body: List[_Node]) -> None:
        self.var = var
        self.iter_expr = iter_expr
        self.body = body


class _Strip(_Node):
    """输出剥离标记: 吞掉前后纯空白文本, 用于 {% ... %} 行级标签。"""

    __slots__ = ()


def _strip_blank(nodes: List[_Node]) -> None:
    """移除语句节点之间的纯空白文本(实现行级标签不留空行)。"""
    cleaned: List[_Node] = []
    for node in nodes:
        if isinstance(node, _Text) and node.text.strip() == "":
            continue
        cleaned.append(node)
    nodes[:] = cleaned


class TemplateEngine:
    """Jinja2 风格轻量模板引擎。

    Parameters
    ----------
    template_dirs:
        模板搜索目录列表, 按顺序查找(支持 ``java/basic_hook.js.tmpl`` 相对名)。
    strict:
        True 时未定义变量抛出 :class:`UndefinedVariableError`;
        False 时渲染为空字符串(Jinja2 default 行为)。
    """

    def __init__(
        self,
        template_dirs: Optional[Sequence[Union[str, Path]]] = None,
        strict: bool = True,
    ) -> None:
        self.template_dirs = [Path(d) for d in (template_dirs or [])]
        self.strict = strict
        self._cache: Dict[str, List[_Node]] = {}

    # ------------------------------------------------------------------ load
    def resolve(self, name: str) -> Path:
        """按目录顺序解析模板相对路径。"""
        rel = Path(name.replace("\\", "/"))
        for base in self.template_dirs:
            candidate = base / rel
            if candidate.is_file():
                return candidate
        searched = ", ".join(str(base / rel) for base in self.template_dirs)
        raise TemplateNotFoundError(f"template not found: {name} (searched: {searched})")

    def get_source(self, name: str) -> str:
        return self.resolve(name).read_text(encoding="utf-8")

    def list_templates(self, suffix: str = ".tmpl") -> List[str]:
        """枚举全部模板相对名(相对第一个存在的目录)。"""
        found: List[str] = []
        for base in self.template_dirs:
            for path in sorted(base.rglob(f"*{suffix}")):
                found.append(path.relative_to(base).as_posix())
        return sorted(set(found))

    # ---------------------------------------------------------------- render
    def render(self, name: str, context: Optional[Mapping[str, Any]] = None) -> str:
        """渲染指定模板, 返回最终文本。"""
        key = name
        if key not in self._cache:
            self._cache[key] = self.parse(self.get_source(name), source_name=name)
        nodes = self._cache[key]
        out: List[str] = []
        self._render_nodes(nodes, dict(context or {}), out)
        return "".join(out)

    def render_string(self, source: str, context: Optional[Mapping[str, Any]] = None) -> str:
        """直接渲染模板字符串(用于内嵌脚本片段)。"""
        nodes = self.parse(source, source_name="<string>")
        out: List[str] = []
        self._render_nodes(nodes, dict(context or {}), out)
        return "".join(out)

    # ----------------------------------------------------------------- parse
    def parse(self, source: str, source_name: str = "<template>") -> List[_Node]:
        for opener, closer in (("{{", "}}"), ("{%", "%}")):
            if source.count(opener) != source.count(closer):
                raise TemplateSyntaxError(
                    f"{source_name}: unbalanced {opener}...{closer} delimiters"
                )
        tokens = _TOKEN_RE.split(source)
        body, pos = self._parse_block(tokens, 0, set(), source_name)
        if pos < len(tokens):
            raise TemplateSyntaxError(
                f"{source_name}: unexpected tag {tokens[pos]!r} outside any block"
            )
        return body

    def _parse_block(
        self,
        tokens: List[str],
        start: int,
        terminators: set,
        source_name: str,
    ) -> tuple:
        nodes: List[_Node] = []
        i = start
        while i < len(tokens):
            tok = tokens[i]
            if i % 2 == 0:  # 纯文本 token
                if tok:
                    nodes.append(_Text(tok))
                i += 1
                continue
            if tok.startswith("{{"):
                expr = tok[2:-2].strip()
                if not expr:
                    raise TemplateSyntaxError(f"{source_name}: empty variable expression")
                nodes.append(_Var(expr, []))
                i += 1
                continue
            inner = tok[2:-2].strip()
            keyword = inner.split(None, 1)[0] if inner else ""
            if keyword in terminators or keyword.startswith("end"):
                return nodes, i
            if keyword == "if":
                node, i = self._parse_if(tokens, i, source_name)
                nodes.append(node)
            elif keyword == "for":
                node, i = self._parse_for(tokens, i, source_name)
                nodes.append(node)
            elif keyword == "comment":
                i = self._skip_comment(tokens, i, source_name)
                nodes.append(_Strip())
            elif keyword in ("else", "elif", "endif", "endfor", "endcomment"):
                raise TemplateSyntaxError(f"{source_name}: unexpected tag {tok!r}")
            else:
                raise TemplateSyntaxError(f"{source_name}: unknown tag {tok!r}")
        return nodes, i

    def _expect(self, tokens: List[str], i: int, keyword: str, source_name: str) -> str:
        tok = tokens[i]
        inner = tok[2:-2].strip()
        first = inner.split(None, 1)[0] if inner else ""
        if first != keyword:
            raise TemplateSyntaxError(
                f"{source_name}: expected {{% {keyword} %}}, got {tok!r}"
            )
        return inner

    def _parse_if(self, tokens: List[str], i: int, source_name: str) -> tuple:
        tok = tokens[i]
        expr = tok[2:-2].strip()[2:].strip()  # strip "if"
        branches: List[tuple] = []
        i += 1
        body, i = self._parse_block(tokens, i, {"elif", "else", "endif"}, source_name)
        branches.append((expr, body))
        while True:
            if i >= len(tokens):
                raise TemplateSyntaxError(
                    f"{source_name}: unterminated {{% if %}} block"
                )
            inner = tokens[i][2:-2].strip()
            kw = inner.split(None, 1)[0] if inner else ""
            if kw == "elif":
                cond = inner[len("elif"):].strip()
                body, i = self._parse_block(tokens, i + 1, {"elif", "else", "endif"}, source_name)
                branches.append((cond, body))
            elif kw == "else":
                body, i = self._parse_block(tokens, i + 1, {"endif"}, source_name)
                branches.append((None, body))
                self._expect(tokens, i, "endif", source_name)
                i += 1
                break
            else:  # endif
                i += 1
                break
        node = _If(branches)
        for _, body in branches:
            _strip_blank(body)
        return node, i

    def _parse_for(self, tokens: List[str], i: int, source_name: str) -> tuple:
        tok = tokens[i]
        clause = tok[2:-2].strip()[len("for"):].strip()
        m = re.fullmatch(r"(\w+)\s+in\s+(.+)", clause)
        if not m:
            raise TemplateSyntaxError(f"{source_name}: bad for clause {tok!r}")
        var, iter_expr = m.group(1), m.group(2)
        body, i = self._parse_block(tokens, i + 1, {"endfor"}, source_name)
        self._expect(tokens, i, "endfor", source_name)
        _strip_blank(body)
        return _For(var, iter_expr, body), i + 1

    def _skip_comment(self, tokens: List[str], i: int, source_name: str) -> int:
        i += 1  # 跳过 {% comment %} 自身
        while i < len(tokens):
            if tokens[i].startswith("{%"):
                return i + 1
            i += 1
        raise TemplateSyntaxError(f"{source_name}: unterminated comment block")

    # ---------------------------------------------------------------- render
    def _render_nodes(self, nodes: List[_Node], ctx: Dict[str, Any], out: List[str]) -> None:
        for node in nodes:
            if isinstance(node, _Text):
                out.append(node.text)
            elif isinstance(node, _Var):
                out.append(self._render_var(node, ctx))
            elif isinstance(node, _If):
                self._render_if(node, ctx, out)
            elif isinstance(node, _For):
                self._render_for(node, ctx, out)
            elif isinstance(node, _Strip):
                continue
            else:  # pragma: no cover - 防御式分支
                raise TemplateError(f"unknown node type: {type(node).__name__}")

    def _render_var(self, node: _Var, ctx: Dict[str, Any]) -> str:
        try:
            value = self.eval_expr(node.expr, ctx)
        except UndefinedVariableError:
            if self.strict:
                raise
            value = ""
        for fname, args in node.filters:
            value = self._apply_filter(value, fname, args, ctx)
        if value is None:
            return ""
        if isinstance(value, float):
            return repr(value)
        return str(value)

    def _render_if(self, node: _If, ctx: Dict[str, Any], out: List[str]) -> None:
        for expr, body in node.branches:
            if expr is None:
                self._render_nodes(body, ctx, out)
                return
            try:
                cond = bool(self.eval_expr(expr, ctx))
            except UndefinedVariableError:
                cond = False  # Jinja2 语义: 未定义变量在 if 条件中视为 false
            if cond:
                self._render_nodes(body, ctx, out)
                return

    def _render_for(self, node: _For, ctx: Dict[str, Any], out: List[str]) -> None:
        try:
            seq = self.eval_expr(node.iter_expr, ctx)
        except UndefinedVariableError:
            seq = None  # 未定义迭代目标视为空序列
        if seq is None:
            return
        items = list(seq)
        n = len(items)
        for idx, item in enumerate(items):
            ctx[node.var] = item
            ctx["loop"] = {"index0": idx, "index1": idx + 1, "last": idx == n - 1, "length": n}
            self._render_nodes(node.body, ctx, out)
        ctx.pop("loop", None)

    # ------------------------------------------------------------ expression
    def eval_expr(self, expr: str, ctx: Dict[str, Any]) -> Any:
        """安全求值: 管道过滤器拆分 + AST 白名单求值。"""
        parts = _split_pipes(expr)
        has_default = any(p.strip().startswith("default") for p in parts[1:])
        saved_strict = self.strict
        if has_default:
            # Jinja2 语义: {{ x | default("v") }} 不因 x 未定义而报错
            self.strict = False
        try:
            value = self._eval_ast(parts[0], ctx)
            if len(parts) > 1:
                for filt in parts[1:]:
                    m = re.fullmatch(r"(\w+)(?:\((.*)\))?", filt.strip())
                    if not m:
                        raise ExpressionError(f"bad filter: {filt!r}")
                    args = self._parse_filter_args(m.group(2), ctx)
                    value = self._apply_filter(value, m.group(1), args, ctx)
            return value
        finally:
            self.strict = saved_strict

    def _eval_ast(self, expr: str, ctx: Dict[str, Any]) -> Any:
        try:
            tree = ast.parse(expr.strip(), mode="eval")
        except SyntaxError as exc:
            raise ExpressionError(f"invalid expression {expr!r}: {exc}") from exc
        return self._eval_node(tree.body, ctx, expr)

    def _eval_node(self, node: ast.AST, ctx: Dict[str, Any], expr: str) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in ctx:
                return ctx[node.id]
            if self.strict:
                raise UndefinedVariableError(f"undefined variable: {node.id!r} in {expr!r}")
            return ""
        if isinstance(node, ast.Attribute):
            base = self._eval_node(node.value, ctx, expr)
            if base == "" or base is None:
                if self.strict:
                    raise UndefinedVariableError(
                        f"cannot access {node.attr!r} on empty value in {expr!r}"
                    )
                return ""
            try:
                return getattr(base, node.attr)
            except AttributeError:
                if isinstance(base, dict) and node.attr in base:
                    return base[node.attr]
                raise ExpressionError(
                    f"no attribute {node.attr!r} in {expr!r}"
                ) from None
        if isinstance(node, ast.Subscript):
            base = self._eval_node(node.value, ctx, expr)
            key = self._eval_node(node.slice, ctx, expr)
            try:
                return base[key]
            except (KeyError, IndexError, TypeError) as exc:
                raise ExpressionError(f"bad subscript in {expr!r}: {exc}") from exc
        if isinstance(node, (ast.List, ast.Tuple)):
            items = [self._eval_node(e, ctx, expr) for e in node.elts]
            return items if isinstance(node, ast.List) else tuple(items)
        if isinstance(node, ast.Dict):
            return {
                self._eval_node(k, ctx, expr): self._eval_node(v, ctx, expr)
                for k, v in zip(node.keys, node.values)
            }
        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                result: Any = True
                for v in node.values:
                    result = self._eval_node(v, ctx, expr)
                    if not result:
                        return result
                return result
            for v in node.values:
                result = self._eval_node(v, ctx, expr)
                if result:
                    return result
            return result
        if isinstance(node, ast.UnaryOp):
            v = self._eval_node(node.operand, ctx, expr)
            if isinstance(node.op, ast.Not):
                return not v
            if isinstance(node.op, ast.USub):
                try:
                    return -v
                except TypeError:
                    raise ExpressionError(
                        f"unary '-' requires numeric operand in {expr!r}"
                    ) from None
            if isinstance(node.op, ast.UAdd):
                try:
                    return +v
                except TypeError:
                    raise ExpressionError(
                        f"unary '+' requires numeric operand in {expr!r}"
                    ) from None
            raise ExpressionError(f"bad unary op in {expr!r}")
        if isinstance(node, ast.BinOp) and isinstance(node.op, _ALLOWED_BINOPS):
            left = self._eval_node(node.left, ctx, expr)
            right = self._eval_node(node.right, ctx, expr)
            try:
                if isinstance(node.op, ast.Add):
                    return left + right
                if isinstance(node.op, ast.Sub):
                    return left - right
                if isinstance(node.op, ast.Mult):
                    return left * right
                if isinstance(node.op, ast.Div):
                    return left / right
                return left % right
            except TypeError as exc:
                raise ExpressionError(f"bad operands for arithmetic in {expr!r}: {exc}") from None
        if isinstance(node, ast.Compare):
            left = self._eval_node(node.left, ctx, expr)
            for op, comp in zip(node.ops, node.comparators):
                right = self._eval_node(comp, ctx, expr)
                if not self._compare(op, left, right):
                    return False
                left = right
            return True
        if isinstance(node, ast.Call):
            raise ExpressionError(
                f"function calls are not allowed in expressions: {expr!r}"
            )
        raise ExpressionError(f"unsupported expression node: {type(node).__name__} in {expr!r}")

    @staticmethod
    def _compare(op: ast.AST, left: Any, right: Any) -> bool:
        if isinstance(op, ast.Eq):
            return left == right
        if isinstance(op, ast.NotEq):
            return left != right
        if isinstance(op, ast.Lt):
            return left < right
        if isinstance(op, ast.LtE):
            return left <= right
        if isinstance(op, ast.Gt):
            return left > right
        if isinstance(op, ast.GtE):
            return left >= right
        if isinstance(op, ast.In):
            return left in right
        if isinstance(op, ast.NotIn):
            return left not in right
        if isinstance(op, ast.Is):
            return left is right
        if isinstance(op, ast.IsNot):
            return left is not right
        raise ExpressionError(f"unsupported comparison: {type(op).__name__}")  # pragma: no cover

    # --------------------------------------------------------------- filters
    def _parse_filter_args(self, arg_src: Optional[str], ctx: Dict[str, Any]) -> List[Any]:
        if not arg_src or not arg_src.strip():
            return []
        try:
            tree = ast.parse(f"[{arg_src}]", mode="eval")
        except SyntaxError as exc:
            raise ExpressionError(f"bad filter args {arg_src!r}: {exc}") from exc
        if not isinstance(tree.body, ast.List):  # pragma: no cover
            raise ExpressionError(f"bad filter args {arg_src!r}")
        return [self._eval_node(e, ctx, arg_src) for e in tree.body.elts]

    def _apply_filter(
        self, value: Any, fname: str, args: Sequence[Any], ctx: Dict[str, Any]
    ) -> Any:
        if fname == "default":
            return value if value not in ("", None) else (args[0] if args else "")
        if fname == _FILTER_LENGTH:
            try:
                return len(value)
            except TypeError as exc:
                raise ExpressionError("length filter applied to non-sized value") from exc
        if fname == "upper":
            return str(value).upper()
        if fname == "lower":
            return str(value).lower()
        if fname == "trim":
            return str(value).strip()
        if fname == "join":
            sep = args[0] if args else ", "
            return sep.join(str(v) for v in value)
        if fname == "replace":
            if len(args) != 2:
                raise ExpressionError("replace filter requires 2 args")
            return str(value).replace(args[0], args[1])
        raise ExpressionError(f"unknown filter: {fname!r}")
