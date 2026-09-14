"""HTML 单文件自包含安全审计报告生成器。

面向 玄鉴AI（fp_sentinel）移动端安全评估，将
:class:`MobileSecurityReport` 渲染为离线可打开的单文件 HTML：

- 所有 CSS / JS 内联，截图转 base64 data URI 嵌入，零外部依赖；
- 所有动态文本经 ``html.escape`` 转义，防存储型 XSS；
- 输出路径强制走 S7 白名单（继承 :class:`BaseReportGenerator`）；
- 生成后自检（DOCTYPE / 锚点 / base64 数量），失败抛
  :class:`ReportGenerationError`。

数据模型双来源兼容：优先共享模型
``fp_sentinel.mobile_reporting.models.report_models``，导入失败时回退
``formats._fallback_models``；字段读取统一走 :func:`get_attr` 鸭子类型，
并对两种模型已知的字段命名差异（如 ``vulnerabilities``/``findings``、
``cwe``/``cwe_id``、``fix_suggestions``/``remediation``）做别名兼容。
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from .base_generator import BaseReportGenerator
from ._fallback_models import get_attr
from . import html_templates as tpl

try:  # 正式模型由 models 子包提供；未就绪时使用回退定义
    from ..models.report_models import MobileSecurityReport
except ImportError:  # pragma: no cover - 依赖并行开发的模型包
    from ._fallback_models import MobileSecurityReport

__all__ = ["HtmlGenerator", "ReportGenerationError"]

logger = logging.getLogger(__name__)

#: 超过该字节数的截图在缩略图上标注"超大图片"
_OVERSIZE_LIMIT_BYTES = 5 * 1024 * 1024

_MAGIC_PNG = b"\x89PNG\r\n\x1a\n"
_MAGIC_JPEG = b"\xff\xd8\xff"

#: 合法 severity 集合之外的取值一律降级为 INFO
_VALID_SEVERITIES = set(tpl.SEVERITY_ORDER)

#: 目标应用字段别名（回退模型名 -> 兼容别名元组）
_TARGET_KEY_ALIASES: Dict[str, Tuple[str, ...]] = {
    "app_name": ("app_name", "name"),
    "package_name": ("package_name", "package"),
    "version_name": ("version_name", "version"),
    "version_code": ("version_code",),
    "min_sdk": ("min_sdk",),
    "target_sdk": ("target_sdk",),
    "file_size": ("file_size",),
    "sha256": ("sha256",),
}


class ReportGenerationError(RuntimeError):
    """HTML 报告生成后自检失败（DOCTYPE / 锚点 / 内嵌图片数量异常）。"""


def _as_str(value: Any) -> str:
    """任意值转字符串，``None`` 归一为空串。"""
    return "" if value is None else str(value)


def _as_str_list(value: Any) -> List[str]:
    """字段归一为非空字符串列表：兼容 str / 单对象 / 列表三种来源。"""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple)):
        return [_as_str(x) for x in value if _as_str(x).strip()]
    text = _as_str(value)
    return [text] if text.strip() else []


def _first_attr(obj: Any, names: Tuple[str, ...], default: Any = None) -> Any:
    """按别名顺序读取对象属性，返回第一个真值，全部缺失返回默认值。"""
    for name in names:
        value = get_attr(obj, name, None)
        if value:
            return value
    return default


class HtmlGenerator(BaseReportGenerator):
    """单文件自包含 HTML 报告生成器。

    Args:
        allowed_roots: S7 输出路径白名单根目录集合。
        allowed_suffixes: 允许的输出后缀；默认仅 ``.html``。
        screenshot_base_dir: 截图相对路径的解析基准目录（可选）。
        evidence_roots: 截图证据路径白名单根目录集合（安全红线）。
            截图解析出的真实路径必须位于任一根目录之内才允许读取并
            base64 嵌入，防止磁盘任意文件读取外带；默认仅允许当前
            工作目录（``Path.cwd()``）。
    """

    DEFAULT_ALLOWED_SUFFIXES = frozenset({".html"})

    def __init__(
        self,
        allowed_roots: Optional[List[Union[str, Path]]] = None,
        allowed_suffixes: Optional[List[str]] = None,
        screenshot_base_dir: Optional[Union[str, Path]] = None,
        evidence_roots: Optional[Sequence[Union[str, Path]]] = None,
    ) -> None:
        super().__init__(
            allowed_roots=allowed_roots, allowed_suffixes=allowed_suffixes
        )
        self._screenshot_base_dir: Optional[Path] = None
        if screenshot_base_dir is not None:
            self._screenshot_base_dir = (
                Path(screenshot_base_dir)
                .expanduser()
                .resolve(strict=False)
            )
        roots = (
            [Path(r) for r in evidence_roots]
            if evidence_roots is not None
            else [Path.cwd()]
        )
        if not roots:
            roots = [Path.cwd()]
        self._evidence_roots: List[Path] = [
            r.expanduser().resolve(strict=False) for r in roots
        ]
        # 本轮生成中成功嵌入 / 被白名单拦截的截图计数
        self._embedded_count = 0
        self._blocked_count = 0

    def get_format_name(self) -> str:
        """返回格式名称。"""
        return "HTML (.html)"

    # ────────────────────────── 对外主流程 ──────────────────────────

    def generate(
        self, report: MobileSecurityReport, output_path: Path
    ) -> Path:
        """生成单文件 HTML 报告。

        Args:
            report: 移动安全评估报告数据（共享模型或回退模型均可）。
            output_path: 输出路径（必须通过 S7 白名单校验）。

        Returns:
            实际生成的 HTML 文件路径。

        Raises:
            PathNotAllowedError: 输出路径不在白名单内或后缀不被允许。
            ReportGenerationError: 生成后自检失败。
        """
        resolved = self.validate_output_path(output_path)
        # 每轮生成前重置截图嵌入/拦截计数器
        self._embedded_count = 0
        self._blocked_count = 0
        findings = self._collect_findings(report, resolved.parent)
        html_str = self._render_report(report, findings)
        self._self_check(html_str, findings)
        resolved.write_text(html_str, encoding="utf-8")
        logger.info(
            "HTML 报告已生成: %s (%d findings, 嵌入截图 %d 张，"
            "拦截白名单外截图 %d 张)",
            resolved,
            len(findings),
            self._embedded_count,
            self._blocked_count,
        )
        return resolved

    # ────────────────────────── 渲染编排 ──────────────────────────

    def _render_report(
        self,
        report: MobileSecurityReport,
        findings: List[Dict[str, Any]],
    ) -> str:
        """收集元数据并组装完整 HTML 文档。"""
        meta = self._collect_meta(report)
        counts: Dict[str, int] = {sev: 0 for sev in tpl.SEVERITY_ORDER}
        for f in findings:
            counts[str(f["severity"])] += 1
        total = len(findings)
        toc_items = [
            {
                "anchor": f["anchor"],
                "label": f"{f['vuln_id']} {f['title']}".strip(),
                "sev": f["severity"],
            }
            for f in findings
        ]
        ctx = {
            "title": meta["title"],
            "nav": tpl.render_nav(meta["title"], counts, total),
            "sidebar": tpl.render_sidebar(toc_items),
            "header": tpl.render_header(meta),
            "overview": tpl.render_overview(total, counts),
            "target": tpl.render_target(meta["target"]),
            "summary": tpl.render_summary(meta["overall_assessment"]),
            "findings": "".join(
                tpl.render_finding_card(f) for f in findings
            ),
            "stats": tpl.render_stats(counts, total),
            "appendix": tpl.render_appendix(meta),
            "lightbox": tpl.render_lightbox(),
        }
        return tpl.render_page(ctx)

    # ────────────────────────── 数据归集 ──────────────────────────

    def _collect_meta(self, report: MobileSecurityReport) -> Dict[str, Any]:
        """归集报告级元数据（标题 / 目标应用 / 环境信息等）。"""
        metadata = get_attr(report, "metadata", None)

        def meta_or(field: str, meta_field: str, default: str = "") -> str:
            """先取报告顶层字段，缺失时回退到 metadata 子对象字段。"""
            top = _as_str(_first_attr(report, (field,), ""))
            if top:
                return top
            if metadata is not None:
                alt = _as_str(_first_attr(metadata, (meta_field,), ""))
                if alt:
                    return alt
            return default

        env = get_attr(report, "environment", None)
        scan_date = meta_or("scan_date", "date")
        if not scan_date and env is not None and not isinstance(env, dict):
            scan_date = _as_str(get_attr(env, "scan_time", ""))
        return {
            "title": meta_or("title", "title", "移动安全评估报告")
            or "移动安全评估报告",
            "subtitle": _as_str(_first_attr(report, ("subtitle",), "")),
            "company": meta_or("company", "author"),
            "classification": meta_or(
                "classification", "classification"
            ),
            "report_version": meta_or("report_version", "version"),
            "scan_date": scan_date,
            "standard": _as_str(_first_attr(report, ("standard",), "")),
            "overall_assessment": _as_str(
                _first_attr(report, ("overall_assessment",), "")
            ),
            "project_background": _as_str(
                _first_attr(report, ("project_background",), "")
            ),
            "test_scope": _as_str_list(
                _first_attr(report, ("test_scope",), [])
            ),
            "test_methods": _as_str_list(
                _first_attr(report, ("test_methods",), [])
            ),
            "cli_commands": _as_str_list(
                _first_attr(report, ("cli_commands",), [])
            ),
            "target": self._collect_target(report),
            "env": self._collect_environment(report),
        }

    def _collect_target(self, report: MobileSecurityReport) -> Dict[str, str]:
        """归集目标应用信息；兼容 target 对象与顶层字段两种来源。"""
        raw_target = _first_attr(report, ("target",), None)
        if raw_target is None:
            env = get_attr(report, "environment", None)
            if env is not None and not isinstance(env, dict):
                raw_target = get_attr(env, "target_app", None)
        target: Dict[str, str] = {}
        if raw_target is None:
            pass
        elif isinstance(raw_target, dict):
            target = {
                _as_str(k): _as_str(v)
                for k, v in raw_target.items()
                if _as_str(v).strip()
            }
        else:
            for key, aliases in _TARGET_KEY_ALIASES.items():
                val = _as_str(_first_attr(raw_target, aliases, "")).strip()
                if val:
                    target[key] = val
        if not target:
            pkg = _as_str(
                _first_attr(report, ("package_name",), "")
            ).strip()
            sha = _as_str(_first_attr(report, ("sha256",), "")).strip()
            if pkg:
                target["package_name"] = pkg
            if sha:
                target["sha256"] = sha
        return target

    @staticmethod
    def _collect_environment(
        report: MobileSecurityReport,
    ) -> List[List[str]]:
        """归集环境信息；兼容 Dict 与 EnvironmentInfo 对象两种来源。"""
        raw_env = get_attr(report, "environment", None)
        rows: List[List[str]] = []
        if raw_env is None:
            return rows
        if isinstance(raw_env, dict):
            return [
                [_as_str(k), _as_str(v)]
                for k, v in raw_env.items()
                if _as_str(k).strip()
            ]
        for label, aliases in (
            ("操作系统", ("os_name", "os")),
            ("系统版本", ("os_version",)),
            ("Python", ("python_version",)),
            ("测试设备", ("device",)),
        ):
            val = _as_str(_first_attr(raw_env, aliases, "")).strip()
            if val:
                rows.append([label, val])
        tools = _as_str_list(get_attr(raw_env, "tools", None))
        if tools:
            rows.append(["工具链", ", ".join(tools)])
        tool_versions = get_attr(raw_env, "tool_versions", None)
        if isinstance(tool_versions, dict) and tool_versions:
            rows.append(
                [
                    "工具版本",
                    ", ".join(
                        f"{_as_str(k)} {_as_str(v)}".strip()
                        for k, v in tool_versions.items()
                    ),
                ]
            )
        deps = _as_str_list(get_attr(raw_env, "dependencies", None))
        if deps:
            rows.append(["依赖", ", ".join(deps)])
        return rows

    def _collect_findings(
        self, report: MobileSecurityReport, output_dir: Path
    ) -> List[Dict[str, Any]]:
        """归集全部 finding 并渲染为模板上下文字典列表。"""
        vulns = _first_attr(report, ("vulnerabilities", "findings"), [])
        findings: List[Dict[str, Any]] = []
        for idx, vuln in enumerate(vulns or [], start=1):
            findings.append(self._normalize_finding(vuln, idx, output_dir))
        return findings

    def _normalize_finding(
        self, vuln: Any, idx: int, output_dir: Path
    ) -> Dict[str, Any]:
        """将单条漏洞对象（鸭子类型）归一为模板上下文字典。"""
        vuln_id = (
            _as_str(_first_attr(vuln, ("vuln_id", "finding_id", "id"), ""))
            or f"FIND-{idx:03d}"
        )
        anchor = "finding-" + re.sub(r"[^0-9A-Za-z_-]", "_", vuln_id)
        severity = _as_str(
            get_attr(vuln, "severity", "INFO") or "INFO"
        ).upper()
        if severity not in _VALID_SEVERITIES:
            logger.warning("未知 severity %r，按 INFO 处理: %s",
                           severity, vuln_id)
            severity = "INFO"
        title = _as_str(_first_attr(vuln, ("title",), ""))
        description = _as_str(_first_attr(vuln, ("description",), ""))
        search_blob = " ".join(
            " ".join(
                [
                    vuln_id,
                    title,
                    description,
                    _as_str(_first_attr(vuln, ("cwe", "cwe_id"), "")),
                    _as_str(
                        _first_attr(vuln, ("masvs", "owasp_masvs"), "")
                    ),
                    _as_str(_first_attr(vuln, ("category",), "")),
                ]
            ).split()
        ).lower()
        return {
            "anchor": anchor,
            "vuln_id": vuln_id,
            "title": title,
            "severity": severity,
            "category": _as_str(_first_attr(vuln, ("category",), "")),
            "cwe": _as_str(_first_attr(vuln, ("cwe", "cwe_id"), "")),
            "masvs": _as_str(
                _first_attr(vuln, ("masvs", "owasp_masvs"), "")
            ),
            "confidence": self._normalize_confidence(vuln),
            "description": description,
            "impact": _as_str(_first_attr(vuln, ("impact",), "")),
            "components": _as_str_list(
                _first_attr(vuln, ("components",), [])
            ),
            "evidence": self._normalize_evidence(
                _first_attr(vuln, ("evidence",), [])
            ),
            "steps": self._normalize_steps(
                _first_attr(
                    vuln, ("reproduction_steps", "repro_steps"), []
                )
            ),
            "screenshots": self._normalize_screenshots(
                _first_attr(vuln, ("screenshots",), []), output_dir
            ),
            "poc": self._normalize_poc(vuln),
            "exp": self._normalize_exp(vuln),
            "fixes": _as_str_list(
                _first_attr(
                    vuln,
                    ("fix_suggestions", "fix_recommendation",
                     "remediation"),
                    [],
                )
            ),
            "references": _as_str_list(
                _first_attr(vuln, ("references",), [])
            ),
            "search_blob": search_blob,
        }

    @staticmethod
    def _normalize_confidence(vuln: Any) -> str:
        """置信度归一：共享模型为 0~1 浮点，回退模型为等级字符串。"""
        raw = get_attr(vuln, "confidence", None)
        if raw is None:
            return "Firm"
        if isinstance(raw, (int, float)):
            if raw >= 0.8:
                return "高"
            if raw >= 0.5:
                return "中"
            return "低"
        return _as_str(raw) or "Firm"

    @staticmethod
    def _normalize_poc(vuln: Any) -> str:
        """POC 归一：兼容纯文本与 PocInfo / PocReport 对象。"""
        raw = _first_attr(vuln, ("poc",), None)
        if raw is None:
            return ""
        if isinstance(raw, str):
            return raw
        return _as_str(
            _first_attr(raw, ("script_content", "code", "description"), "")
        )

    @staticmethod
    def _normalize_exp(vuln: Any) -> str:
        """EXP 归一：兼容纯文本与 ExpInfo 对象（利用链步骤列表）。"""
        raw = _first_attr(vuln, ("exp", "exploit"), None)
        if raw is None:
            return ""
        if isinstance(raw, str):
            return raw
        parts = _as_str_list(get_attr(raw, "steps", None))
        return _as_str(
            _first_attr(raw, ("code", "script_content"), "")
        ) or "\n".join(parts)

    @staticmethod
    def _normalize_evidence(raw: Any) -> List[Dict[str, str]]:
        """证据归一：兼容 str / Evidence 对象 / 列表。"""
        items: List[Dict[str, str]] = []
        if isinstance(raw, str):
            if raw.strip():
                items.append(
                    {"location": "", "content": raw, "description": ""}
                )
            return items
        for evi in raw or []:
            if isinstance(evi, str):
                items.append(
                    {"location": "", "content": evi, "description": ""}
                )
            else:
                items.append(
                    {
                        "location": _as_str(
                            _first_attr(evi, ("location",), "")
                        ),
                        "content": _as_str(
                            _first_attr(evi, ("content",), "")
                        ),
                        "description": _as_str(
                            _first_attr(evi, ("description",), "")
                        ),
                    }
                )
        return items

    @staticmethod
    def _normalize_steps(raw: Any) -> List[Dict[str, str]]:
        """复现步骤归一：兼容 str / ReproStep 对象 / 列表。"""
        items: List[Dict[str, str]] = []
        for step in raw or []:
            if isinstance(step, str):
                items.append(
                    {"action": step, "command": "",
                     "expected": "", "actual": ""}
                )
            else:
                items.append(
                    {
                        "action": _as_str(
                            _first_attr(step, ("action",), "")
                        ),
                        "command": _as_str(
                            _first_attr(step, ("command",), "")
                        ),
                        "expected": _as_str(
                            _first_attr(
                                step, ("expected", "expected_result"), ""
                            )
                        ),
                        "actual": _as_str(
                            _first_attr(
                                step, ("actual", "actual_result"), ""
                            )
                        ),
                    }
                )
        return items

    # ────────────────────────── 截图嵌入 ──────────────────────────

    def _normalize_screenshots(
        self, raw: Any, output_dir: Path
    ) -> List[Dict[str, Any]]:
        """截图归一并尝试嵌入 base64 data URI。"""
        shots: List[Dict[str, Any]] = []
        for item in raw or []:
            shots.append(self._embed_screenshot(item, output_dir))
        return shots

    def _embed_screenshot(
        self, shot: Any, output_dir: Path
    ) -> Dict[str, Any]:
        """读取单个截图文件并转换为 base64 data URI。

        文件缺失、校验未通过或格式不支持时返回占位信息（state=missing），
        不中断整体生成。
        """
        if isinstance(shot, (str, Path)):
            path_str, caption, status, message = _as_str(shot), "", \
                "verified", ""
        else:
            path_str = _as_str(
                _first_attr(shot, ("path", "file_path"), "")
            )
            caption = _as_str(
                _first_attr(shot, ("caption", "description"), "")
            )
            status, message = self._screenshot_status(shot)
        result: Dict[str, Any] = {
            "state": "missing",
            "data_uri": "",
            "caption": caption,
            "sha16": "",
            "reason": "",
            "oversize": False,
            "size_mb": 0.0,
        }
        if not path_str.strip():
            result["reason"] = "未提供截图路径"
            return result
        if status in {"problem", "invalid", "failed"}:
            result["reason"] = "截图校验未通过" + (
                f": {message}" if message else ""
            )
            return result
        path = self._resolve_screenshot_path(path_str, output_dir)
        if path is None:
            result["reason"] = f"文件不存在: {path_str}"
            return result
        if not self._is_evidence_path_allowed(path):
            # 安全红线：截图不在证据白名单内，拒绝读取，仅渲染占位框
            self._blocked_count += 1
            logger.warning(
                "截图路径不在证据白名单内，拒绝嵌入: %s", path
            )
            result["reason"] = "路径不在证据白名单"
            return result
        try:
            data = path.read_bytes()
        except OSError as exc:
            result["reason"] = f"读取失败: {exc}"
            return result
        mime = self._sniff_mime(data)
        if mime is None:
            result["reason"] = "不支持的图片格式（仅支持 PNG/JPEG）"
            return result
        sha = _as_str(
            get_attr(shot, "sha256", "")
            if not isinstance(shot, (str, Path)) else ""
        ).strip() or hashlib.sha256(data).hexdigest()
        result.update(
            {
                "state": "ok",
                "data_uri": "data:%s;base64,%s"
                % (mime, base64.b64encode(data).decode("ascii")),
                "sha16": sha[:16],
            }
        )
        self._embedded_count += 1
        if len(data) > _OVERSIZE_LIMIT_BYTES:
            result["oversize"] = True
            result["size_mb"] = round(len(data) / (1024 * 1024), 1)
            logger.warning("截图超过 5MB，已在报告中标注: %s", path)
        return result

    @staticmethod
    def _screenshot_status(shot: Any) -> Tuple[str, str]:
        """截图校验状态归一。

        兼容回退模型的 ``verification_status`` 字符串与共享模型的
        ``verified`` 布尔值；校验失败时附带 ``verify_message``。
        """
        vs = get_attr(shot, "verification_status", None)
        if vs is not None:
            return _as_str(vs).lower(), ""
        verified = get_attr(shot, "verified", None)
        if verified is False:
            return "problem", _as_str(
                get_attr(shot, "verify_message", "")
            )
        return "verified", ""

    def _resolve_screenshot_path(
        self, path_str: str, output_dir: Path
    ) -> Optional[Path]:
        """解析截图路径：绝对路径直取；相对路径按候选基准目录探测。"""
        raw = Path(path_str)
        if raw.is_absolute():
            return raw if raw.is_file() else None
        candidates: List[Path] = []
        if self._screenshot_base_dir is not None:
            candidates.append(self._screenshot_base_dir / raw)
        candidates.append(output_dir / raw)
        candidates.append(Path.cwd() / raw)
        for cand in candidates:
            if cand.is_file():
                return cand
        return None

    def _is_evidence_path_allowed(self, path: Path) -> bool:
        """校验截图真实路径是否位于任一证据白名单根目录之内。"""
        try:
            resolved = path.resolve(strict=False)
        except (OSError, ValueError):
            return False
        return any(
            self._is_within(resolved, root)
            for root in self._evidence_roots
        )

    @staticmethod
    def _is_within(child: Path, parent: Path) -> bool:
        """判断 ``child`` 是否位于 ``parent`` 之下（含相等）。

        兼容 Windows 文件系统大小写不敏感语义：``relative_to`` 失败时
        回退为小写化后的字符串前缀比较。
        """
        try:
            child.relative_to(parent)
            return True
        except ValueError:
            pass
        parent_l = str(parent).lower()
        if not parent_l.endswith(os.sep):
            parent_l += os.sep
        return str(child).lower().startswith(parent_l)

    @staticmethod
    def _sniff_mime(data: bytes) -> Optional[str]:
        """按魔数识别 PNG / JPEG，其他格式返回 ``None``。"""
        if data.startswith(_MAGIC_PNG):
            return "image/png"
        if data.startswith(_MAGIC_JPEG):
            return "image/jpeg"
        return None

    # ────────────────────────── 生成后自检 ─────────────────────────

    def _self_check(
        self,
        html_str: str,
        findings: List[Dict[str, Any]],
    ) -> None:
        """自检：DOCTYPE、finding 锚点、内嵌 base64 图片数量。

        内嵌数量以 :attr:`_embedded_count`（嵌入成功时自增的实例计数器）
        为准，不再从 HTML 文本统计期望值，避免用户证据文本中恰好含有
        ``data:image/`` 字样导致的误判；实际出现次数不少于期望次数即
        视为通过（多出的次数可能来自用户文本，属正常现象）。

        Raises:
            ReportGenerationError: 任一断言不满足。
        """
        problems: List[str] = []
        if not html_str.lstrip().lower().startswith("<!doctype html>"):
            problems.append("缺少 DOCTYPE 声明")
        for f in findings:
            anchor = str(f.get("anchor", ""))
            if anchor and f'id="{anchor}"' not in html_str:
                problems.append(f"缺少 finding 锚点: {anchor}")
        expected = self._embedded_count * 2
        actual = html_str.count("data:image/")
        # 每张截图 data URI 出现两次（缩略图 src 与灯箱 data-full）
        if actual < expected:
            problems.append(
                f"内嵌 base64 图片数量不符: 期望至少 {expected}, "
                f"实际 {actual}"
            )
        if problems:
            raise ReportGenerationError(
                "HTML 报告自检失败: " + "; ".join(problems)
            )
