"""POC 生成器主类 —— goal 驱动(意图 → 模板映射 → 参数填充 → 校验)。

支持的目标(goal)(规划文档 2.5.4 CLI):
    basic-hook / overload-hook / constructor-hook / static-hook /
    param-modify / return-modify / callstack-trace / string-dump /
    bytearray-print / hashmap-trace / json-trace /
    native-hook / inline-hook / oc-hook / oc-replace / oc-fuzzy /
    plaintext-capture / sign-bypass / ssl-bypass / root-bypass
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Union

from .template_engine import TemplateEngine, TemplateError
from .validator import POCValidator
from ..models.poc_result import POCResult

__all__ = [
    "POCGenerator", "UnknownGoalError", "HookPointSchemaError",
    "DEFAULT_TEMPLATE_DIR", "DEFAULT_GOALS",
]

# 默认模板目录: 包内 templates/
DEFAULT_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


class UnknownGoalError(ValueError):
    """未知生成意图。"""


class HookPointSchemaError(ValueError):
    """Hook 点位数据不符合 schema（RD-004: 流水线 schema 统一）。"""


# goal → (模板, 语言, 平台)
DEFAULT_GOALS: Dict[str, List[Dict[str, str]]] = {
    "basic-hook": [{"template": "java/basic_hook.js.tmpl", "language": "js", "platform": "android"}],
    "overload-hook": [{"template": "java/overload_hook.js.tmpl", "language": "js", "platform": "android"}],
    "constructor-hook": [{"template": "java/constructor_hook.js.tmpl", "language": "js", "platform": "android"}],
    "static-hook": [{"template": "java/static_hook.js.tmpl", "language": "js", "platform": "android"}],
    "param-modify": [{"template": "java/param_modify.js.tmpl", "language": "js", "platform": "android"}],
    "return-modify": [{"template": "java/return_modify.js.tmpl", "language": "js", "platform": "android"}],
    "callstack-trace": [{"template": "java/callstack_print.js.tmpl", "language": "js", "platform": "android"}],
    "string-dump": [{"template": "java/string_dump.js.tmpl", "language": "js", "platform": "android"}],
    "bytearray-print": [{"template": "java/bytearray_print.js.tmpl", "language": "js", "platform": "android"}],
    "hashmap-trace": [{"template": "java/hashmap_hook.js.tmpl", "language": "js", "platform": "android"}],
    "json-trace": [{"template": "java/json_hook.js.tmpl", "language": "js", "platform": "android"}],
    "native-hook": [{"template": "native/so_hook.js.tmpl", "language": "js", "platform": "android"}],
    "inline-hook": [{"template": "native/inline_hook.js.tmpl", "language": "js", "platform": "android"}],
    "oc-hook": [{"template": "ios/oc_basic.js.tmpl", "language": "js", "platform": "ios"}],
    "oc-replace": [{"template": "ios/oc_replace.js.tmpl", "language": "js", "platform": "ios"}],
    "oc-fuzzy": [{"template": "ios/oc_fuzzy.js.tmpl", "language": "js", "platform": "ios"}],
    "plaintext-capture": [{"template": "combo/plaintext_capture.py.tmpl", "language": "py", "platform": "android"}],
    "sign-bypass": [{"template": "combo/sign_bypass.py.tmpl", "language": "py", "platform": "android"}],
    "ssl-bypass": [{"template": "combo/ssl_bypass.js.tmpl", "language": "js", "platform": "android"}],
    "root-bypass": [{"template": "combo/root_bypass.js.tmpl", "language": "js", "platform": "android"}],
}


class POCGenerator:
    """Frida POC 生成器。

    用法::

        gen = POCGenerator()
        result = gen.generate_for_goal("ssl-bypass", package_name="com.target.app")
        result.save("./scripts/")
    """

    def __init__(
        self,
        template_dirs: Optional[List[Union[str, Path]]] = None,
        goals: Optional[Dict[str, List[Dict[str, str]]]] = None,
        strict_template: bool = True,
    ) -> None:
        if template_dirs is None:
            template_dirs = [DEFAULT_TEMPLATE_DIR]
        self.engine = TemplateEngine(template_dirs, strict=strict_template)
        self.validator = POCValidator()
        self.goals = goals if goals is not None else DEFAULT_GOALS

    # ------------------------------------------------------------ introspect
    def list_templates(self) -> List[str]:
        return self.engine.list_templates()

    def list_goals(self) -> List[str]:
        return sorted(self.goals)

    # ---------------------------------------------------------------- render
    def generate(
        self,
        template: str,
        context: Optional[Mapping[str, Any]] = None,
        goal: str = "adhoc",
        language: str = "js",
        platform: str = "android",
        validate: bool = True,
    ) -> POCResult:
        """按指定模板 + 上下文渲染 POC。"""
        ctx = dict(context or {})
        ctx.setdefault("package_name", "com.target.app")
        ctx.setdefault("bundle_id", "com.target.iosapp")
        ctx.setdefault("log_tag", "[fp-sentinel]")
        try:
            script = self.engine.render(template, ctx)
            success = True
            warnings: List[str] = []
        except TemplateError as exc:
            script = ""
            success = False
            warnings = [f"template render failed: {exc}"]

        report = None
        if validate and success:
            report = self.validator.validate(script, language)
            success = report.valid

        return POCResult(
            success=success,
            template=template,
            goal=goal,
            language=language,
            script=script,
            platform=platform,
            package_name=ctx.get("package_name") or ctx.get("bundle_id"),
            validation=report,
            warnings=warnings,
        )

    # ------------------------------------------------------------------ goal
    def generate_for_goal(
        self,
        goal: str,
        hook_point: Optional[Union[Mapping[str, Any], str]] = None,
        output_dir: Optional[str] = None,
        rank: int = 0,
        **extra: Any,
    ) -> POCResult:
        """按意图(goal)生成 POC。

        Parameters
        ----------
        goal:
            生成意图, 见 :data:`DEFAULT_GOALS`。
        hook_point:
            Hook 点位, 可为 dict / dict 列表 / HookRecommendation 包装 dict
            (``{"hook_points": [...]}``)或指向上述任一形态的 JSON 文件路径。
        output_dir:
            若给出, 脚本同时落盘到该目录。
        rank:
            hook_point 为列表/推荐包装时, 取第 rank 个点位(0 起始, 越界显式报错)。
        **extra:
            直接透传给模板的补充变量(优先级低于 hook_point)。
        """
        if goal not in self.goals:
            raise UnknownGoalError(
                f"unknown goal {goal!r}; available: {', '.join(self.list_goals())}"
            )

        ctx = self._build_context(hook_point, rank=rank)
        ctx.update(extra)

        results: List[POCResult] = []
        for spec in self.goals[goal]:
            result = self.generate(
                template=spec["template"],
                context=ctx,
                goal=goal,
                language=spec["language"],
                platform=spec["platform"],
            )
            if output_dir and result.success:
                result.save(output_dir)
            results.append(result)
        return results[0]

    def batch_generate(
        self,
        hook_points: Union[str, Path, List[Union[Mapping[str, Any], str]]],
        goal: str,
        output_dir: Optional[str] = None,
    ) -> List[POCResult]:
        """针对多个 Hook 点位批量生成 POC。

        hook_points 可为 JSON 文件路径(list)或点位列表; 每个元素为 dict 或
        JSON 文件路径。
        """
        points: List[Union[Mapping[str, Any], str]]
        if isinstance(hook_points, (str, Path)):
            raw = Path(hook_points).read_text(encoding="utf-8")
            data = json.loads(raw)
            if not isinstance(data, list):
                raise ValueError("hook-points JSON must be a list")
            points = data
        else:
            points = list(hook_points)

        results: List[POCResult] = []
        for point in points:
            try:
                results.append(
                    self.generate_for_goal(goal, hook_point=point, output_dir=output_dir)
                )
            except (TemplateError, ValueError) as exc:
                results.append(
                    POCResult(
                        success=False,
                        template="",
                        goal=goal,
                        language="js",
                        warnings=[f"batch item failed: {exc}"],
                    )
                )
        return results

    # --------------------------------------------------------------- context
    _FIELD_ALIASES = {
        "fqcn": "class_name",
        "method": "method_name",
        "package": "package_name",
        "bundle": "bundle_id",
        "signature": "param_signature",
        "param_sig": "param_signature",
        "technique_name": "technique",
    }

    @classmethod
    def _unwrap_hook_point(
        cls, data: Any, rank: int = 0
    ) -> Mapping[str, Any]:
        """解开 HookRecommendation 包装/列表, 取第 rank 个点位(RD-004)。"""
        if isinstance(data, Mapping) and "hook_points" in data:
            points = data.get("hook_points") or []
            wrapper_package = data.get("package_name", "")
            if not isinstance(points, list):
                raise HookPointSchemaError(
                    "field 'hook_points' must be a list of hook point dicts"
                )
            if not points:
                raise HookPointSchemaError(
                    "hook_points is empty — 没有任何可用的 Hook 点位"
                )
            # NEW-09: --rank 越界必须显式报错，不允许静默回退首个点位
            if not 0 <= rank < len(points):
                raise HookPointSchemaError(
                    f"--rank {rank} 超出范围: hook_points 只有 {len(points)} 个点位 "
                    f"(有效范围 0~{len(points) - 1})。请检查 hook recommend 输出或调整 --rank"
                )
            point = points[rank]
            if isinstance(point, Mapping) and wrapper_package and not point.get("package_name"):
                point = {**point, "package_name": wrapper_package}
            return point  # type: ignore[return-value]
        if isinstance(data, list):
            if not data:
                raise HookPointSchemaError("hook point list is empty")
            if not 0 <= rank < len(data):
                raise HookPointSchemaError(
                    f"--rank {rank} 超出范围: hook point 列表只有 {len(data)} 个点位 "
                    f"(有效范围 0~{len(data) - 1})"
                )
            return data[rank]  # type: ignore[return-value]
        return data

    @classmethod
    def _build_context(
        cls,
        hook_point: Optional[Union[Mapping[str, Any], str]],
        rank: int = 0,
    ) -> Dict[str, Any]:
        """从 Hook 点位提取模板参数(规划文档 2.5.2 第2步)。

        RD-004: 兼容 hook recommend 的完整输出（含 hook_points 包装），
        归一化字段别名，并对缺失关键字段给出明确报错。
        """
        if hook_point is None:
            return {}
        if isinstance(hook_point, (str, Path)):
            raw = Path(hook_point).read_text(encoding="utf-8")
            try:
                data: Any = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise HookPointSchemaError(
                    f"hook point file is not valid JSON: {exc}"
                ) from exc
        else:
            data = hook_point

        point = cls._unwrap_hook_point(data, rank=rank)
        if not isinstance(point, Mapping):
            raise HookPointSchemaError(
                "hook point must be a JSON object, got: "
                f"{type(point).__name__}"
            )

        ctx: Dict[str, Any] = dict(point)
        # 归一化常见字段别名
        for alias, canonical in cls._FIELD_ALIASES.items():
            if alias in ctx and canonical not in ctx:
                ctx[canonical] = ctx[alias]
        param_types = ctx.get("param_types") or ctx.get("params") or []
        ctx["param_types"] = [str(p) for p in param_types]
        ctx.setdefault("platform", "android")

        # RD-004: schema 校验 —— 点位数据只给了部分关键字段时给出明确、
        # 可操作的报错; 完全不含定位字段(如 ssl-bypass 这类全局 goal)则放行。
        has_class = bool(ctx.get("class_name"))
        has_method = bool(ctx.get("method_name"))
        if has_class != has_method:
            missing = "method_name" if has_class else "class_name"
            raise HookPointSchemaError(
                "hook point missing required field(s): "
                + missing
                + f"; available keys: {sorted(ctx.keys())}. "
                "请提供 --hook-point 指向单个 hook 点位 JSON "
                "(含 class_name/method_name), 或使用 hook recommend 的完整输出"
                "配合 --rank 选择点位"
            )
        return ctx
