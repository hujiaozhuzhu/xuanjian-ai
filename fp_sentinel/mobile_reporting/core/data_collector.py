"""扫描产物数据收集器。

DataCollector 负责读取 fp_sentinel.mobile_insight（静态洞察）与
fp_sentinel.mobile_hook（动态 Hook）的扫描输出 JSON，
构建 :class:`MobileSecurityReport`：

- 字段缺失时宽容处理（``.get`` 兜底 + warning 记录，绝不抛异常中断）；
- 自动统计 by_severity / by_category；
- 自动为每个 finding 生成基础复现步骤（扫描命令回放）。
"""

from __future__ import annotations

import json
import logging
import platform
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..models.report_models import (
    VALID_SEVERITIES,
    EnvironmentInfo,
    Evidence,
    FindingReport,
    MobileSecurityReport,
    PocInfo,
    ReportMetadata,
    ReportStatistics,
    ReproStep,
    TargetAppInfo,
)
from .poc_exp_integrator import PocExpIntegrator

__all__ = ["DataCollector", "CATEGORY_LABELS"]

logger = logging.getLogger(__name__)

#: mobile_insight 分类枚举值到中文报告分类的映射
CATEGORY_LABELS: Dict[str, str] = {
    "CRYPTO": "密码学",
    "NETWORK": "网络通信",
    "STORAGE": "数据存储",
    "COMPONENT": "平台交互",
    "ANTI": "反分析",
    "ANTI_ANALYSIS": "反分析",
    "PRIVACY": "隐私合规",
    "CONFIG": "应用配置",
}

JsonSource = Union[str, Path, Dict[str, Any], List[Any], None]


class DataCollector:
    """从扫描产物 JSON 收集数据构建移动安全报告。

    Usage:
        collector = DataCollector()
        report = collector.from_scan_outputs(
            insight_json="out/insight.json",
            hook_json=hook_dict,
            target_info={"name": "demo", "sha256": "..."},
        )
        print(collector.warnings)
    """

    def __init__(self, tool_version: str = "") -> None:
        """初始化收集器。

        Args:
            tool_version: 写入每个 finding 的工具版本号；为空时自动探测。
        """
        self.warnings: List[str] = []
        self._tool_version = tool_version or self._detect_tool_version()

    # ─────────────────────────── 主入口 ──────────────────────────

    def from_scan_outputs(
        self,
        insight_json: JsonSource = None,
        hook_json: JsonSource = None,
        poc_json: JsonSource = None,
        target_info: Optional[Dict[str, Any]] = None,
    ) -> MobileSecurityReport:
        """从扫描产物构建完整报告。

        Args:
            insight_json: mobile_insight 输出（dict / JSON 字符串 / 文件路径）。
            hook_json: mobile_hook 输出（dict / JSON 字符串 / 文件路径）。
            poc_json: mobile_poc 输出（dict / JSON 字符串 / 文件路径）。
            target_info: 目标应用信息（name/package/version/sha256/scan_command）。

        Returns:
            MobileSecurityReport: 聚合后的报告（statistics 已自动汇总）。
        """
        self.warnings = []
        target = target_info or {}
        findings: List[FindingReport] = []
        duration = 0.0

        insight_data = self._load_json(insight_json, "insight")
        findings.extend(self._collect_from_insight(insight_data))
        duration += self._to_float(insight_data.get("duration_sec"), 0.0)

        hook_data = self._load_json(hook_json, "hook")
        findings.extend(self._collect_from_hook(hook_data))
        duration += self._hook_duration(hook_data)

        poc_data = self._load_json(poc_json, "poc")
        findings = self._attach_pocs(findings, poc_data)

        report = MobileSecurityReport(
            metadata=self._build_metadata(target),
            environment=self._build_environment(insight_data, hook_data, target),
            statistics=self._build_statistics(findings, duration),
            findings=findings,
        )
        if self.warnings:
            logger.warning("数据收集共产出 %d 条 warning", len(self.warnings))
        return report

    # ─────────────────────── insight 产物收集 ────────────────────

    def _collect_from_insight(self, data: Dict[str, Any]) -> List[FindingReport]:
        """把 mobile_insight 输出的 insights 列表转换为 findings。"""
        findings: List[FindingReport] = []
        insights = data.get("insights")
        if insights is None:
            self._warn("insight 产物缺少 insights 字段，跳过静态发现收集")
            return findings
        if not isinstance(insights, list):
            self._warn("insight 产物的 insights 字段不是列表，跳过")
            return findings
        target = str(data.get("target", "") or "")
        for idx, item in enumerate(insights, start=1):
            if not isinstance(item, dict):
                self._warn(f"insights[{idx}] 不是对象，已跳过")
                continue
            finding_id = str(item.get("id") or f"VUL-{idx:03d}")
            severity = str(item.get("severity", "") or "").upper()
            if not severity:
                self._warn(f"{finding_id} 缺少 severity，默认按 MEDIUM 处理")
                severity = "MEDIUM"
            if severity not in VALID_SEVERITIES:
                self._warn(f"{finding_id} 非法 severity {severity!r}，按 MEDIUM 处理")
                severity = "MEDIUM"
            category_raw = str(item.get("category", "") or "")
            category = CATEGORY_LABELS.get(category_raw, category_raw or "其他")
            code_ref = item.get("code_reference") or {}
            if not isinstance(code_ref, dict):
                code_ref = {}
            file_ref = str(code_ref.get("file", "") or "<未知文件>")
            line_ref = self._to_int(code_ref.get("line"), 0)
            location = f"{file_ref}:{line_ref}"
            evidence_raw = item.get("evidence")
            if isinstance(evidence_raw, str):
                evidence_items = [evidence_raw] if evidence_raw.strip() else []
            elif isinstance(evidence_raw, list):
                evidence_items = [
                    str(x)
                    for x in evidence_raw
                    if isinstance(x, (str, int, float)) and str(x).strip()
                ]
            else:
                if evidence_raw not in (None, []):
                    self._warn(f"{finding_id} 的 evidence 类型不受支持，已忽略")
                evidence_items = []
            evidence = Evidence(
                id=f"EV-{finding_id}-01",
                location=location,
                content=evidence_items[0] if evidence_items else "",
                description=str(
                    item.get("technical_context") or item.get("description") or ""
                ),
                source="静态",
            )
            cwe_ids = [str(x) for x in (item.get("cwe_ids") or []) if x]
            masvs_refs = [str(x) for x in (item.get("masvs_refs") or []) if x]
            references = [str(x) for x in (item.get("references") or []) if x]
            finding = FindingReport(
                id=finding_id,
                title=str(item.get("title") or f"未命名发现 {finding_id}"),
                severity=severity,
                cwe_id=cwe_ids[0] if cwe_ids else "",
                owasp_masvs=masvs_refs[0] if masvs_refs else "",
                category=category,
                description=str(item.get("description") or ""),
                evidence=[evidence],
                repro_steps=[
                    ReproStep(
                        step_no=1,
                        action=f"回放扫描命令以复现 {finding_id}",
                        command=self._scan_command_for(target),
                        expected_result="扫描规则再次命中并产出相同发现",
                        actual_result="",
                    )
                ],
                remediation=str(item.get("fix_hint") or ""),
                references=references,
                tool_version=self._tool_version,
                confidence=self._to_float(item.get("confidence"), 0.5),
            )
            findings.append(finding)
        return findings

    # ───────────────────────── hook 产物收集 ─────────────────────

    def _collect_from_hook(self, data: Dict[str, Any]) -> List[FindingReport]:
        """把 mobile_hook 输出的技法结果转换为 findings（动态证据）。"""
        findings: List[FindingReport] = []
        techniques = data.get("techniques")
        if techniques is None and isinstance(data.get("results"), list):
            techniques = data["results"]
        if techniques is None:
            self._warn("hook 产物缺少 techniques 字段，跳过动态发现收集")
            return findings
        for t_idx, tech in enumerate(techniques, start=1):
            if not isinstance(tech, dict):
                self._warn(f"hook techniques[{t_idx}] 不是对象，已跳过")
                continue
            technique_name = str(tech.get("technique", "") or f"technique-{t_idx}")
            hook_points = tech.get("hook_points") or []
            if not isinstance(hook_points, list):
                self._warn(f"技法 {technique_name} 的 hook_points 不是列表，已跳过")
                continue
            for h_idx, point in enumerate(hook_points, start=1):
                if not isinstance(point, dict):
                    self._warn(
                        f"技法 {technique_name} 的 hook_points[{h_idx}] 不是对象，已跳过"
                    )
                    continue
                class_name = str(point.get("class_name", "") or "<未知类>")
                method_name = str(point.get("method_name", "") or "<未知方法>")
                fid = f"HOOK-{t_idx:02d}{h_idx:02d}"
                strings = [
                    str(x) for x in (point.get("strings_matched") or []) if x
                ]
                confidence = self._to_float(point.get("confidence"), 0.5)
                finding = FindingReport(
                    id=fid,
                    title=f"动态 Hook 命中: {class_name}#{method_name}",
                    severity="MEDIUM",
                    category="动态行为",
                    description=str(
                        point.get("reason")
                        or f"技法 {technique_name} 在 {class_name}#{method_name} 命中"
                    ),
                    evidence=[
                        Evidence(
                            id=f"EV-{fid}-01",
                            location=f"{class_name}#{method_name}",
                            content=str(strings[0]) if strings else "",
                            description=str(point.get("reason") or ""),
                            source="动态",
                        )
                    ],
                    repro_steps=[
                        ReproStep(
                            step_no=1,
                            action=f"回放 Hook 扫描以复现 {fid}",
                            command=self._hook_command_for(class_name, technique_name),
                            expected_result=f"技法 {technique_name} 再次命中同一方法",
                            actual_result="",
                        )
                    ],
                    remediation="人工确认该动态行为的业务合法性并评估泄露风险",
                    tool_version=self._tool_version,
                    confidence=max(0.0, min(1.0, confidence)),
                )
                findings.append(finding)
        return findings

    def _hook_duration(self, data: Dict[str, Any]) -> float:
        """汇总 hook 产物中各技法的执行耗时（秒）。"""
        total = 0.0
        for tech in data.get("techniques") or []:
            if isinstance(tech, dict):
                total += self._to_float(tech.get("duration_ms"), 0.0) / 1000.0
        return total

    # ───────────────────────── poc 产物收集 ──────────────────────

    def _attach_pocs(
        self, findings: List[FindingReport], poc_data: Dict[str, Any]
    ) -> List[FindingReport]:
        """把 mobile_poc 输出的 POC 结果挂接到匹配的 finding。"""
        results = poc_data.get("results")
        if results is None and isinstance(poc_data, dict) and "success" in poc_data:
            results = [poc_data]
        if not results:
            if poc_data:
                self._warn("poc 产物中未找到可用的 results 列表")
            return findings
        by_id = {f.id: f for f in findings}
        integrator = PocExpIntegrator()
        for idx, item in enumerate(results, start=1):
            if not isinstance(item, dict):
                self._warn(f"poc results[{idx}] 不是对象，已跳过")
                continue
            meta = item.get("metadata")
            if not isinstance(meta, dict):
                if meta is not None:
                    self._warn(
                        f"poc results[{idx}] 的 metadata 不是对象，已按空处理"
                    )
                meta = {}
            target_finding = str(
                meta.get("vuln_id") or meta.get("finding_id") or ""
            )
            finding = by_id.get(target_finding)
            if finding is None:
                self._warn(
                    f"poc results[{idx}] 未找到对应 finding（{target_finding or '未标注'}），"
                    "已跳过挂接"
                )
                continue
            content = str(item.get("script") or "")
            safety_level, reasons = integrator.safety_check(content)
            display = integrator._truncate_for_display(content, safety_level)
            poc = PocInfo(
                id=f"POC-{finding.id}",
                name=str(item.get("goal") or item.get("template") or finding.id),
                type="frida" if str(item.get("language", "js")) == "js" else "java",
                script_path=str(item.get("script_path") or ""),
                script_content=display,
                safety_level=safety_level,
                description=str(
                    item.get("goal") or ""
                ) + (f"；危险特征: {'; '.join(reasons)}" if reasons else ""),
            )
            finding.poc = poc
        return findings

    # ─────────────────────────── 组装 ────────────────────────────

    def _build_metadata(self, target: Dict[str, Any]) -> ReportMetadata:
        """构建报告元信息。"""
        return ReportMetadata(
            title=str(
                target.get("report_title")
                or f"{target.get('name') or '目标应用'} 移动安全评估报告"
            ),
            author="玄鉴AI (fp_sentinel)",
            classification="内部资料",
            version="V1.0",
            date=datetime.now().strftime("%Y-%m-%d"),
        )

    def _build_environment(
        self,
        insight_data: Dict[str, Any],
        hook_data: Dict[str, Any],
        target: Dict[str, Any],
    ) -> EnvironmentInfo:
        """构建环境信息（含目标应用信息与扫描命令）。"""
        package = str(
            target.get("package")
            or hook_data.get("package_name")
            or hook_data.get("package")
            or ""
        )
        target_app = TargetAppInfo(
            name=str(target.get("name") or insight_data.get("target") or ""),
            package=package,
            version=str(target.get("version") or ""),
            sha256=str(target.get("sha256") or ""),
            file_size=self._to_int(target.get("file_size"), 0),
        )
        return EnvironmentInfo(
            os=f"{platform.system()} {platform.release()}",
            python_version=sys.version.split()[0],
            tool_versions={"fp_sentinel": self._tool_version},
            target_app=target_app,
            scan_time=datetime.now().isoformat(timespec="seconds"),
            scan_command=str(target.get("scan_command") or ""),
        )

    def _build_statistics(
        self, findings: List[FindingReport], duration: float
    ) -> ReportStatistics:
        """自动统计 by_severity / by_category 与总耗时。"""
        by_severity: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        for finding in findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            cat = finding.category or "其他"
            by_category[cat] = by_category.get(cat, 0) + 1
        return ReportStatistics(
            total_count=len(findings),
            by_severity=by_severity,
            by_category=by_category,
            scan_duration_seconds=round(duration, 4),
        )

    # ─────────────────────────── 工具 ────────────────────────────

    def _load_json(self, source: JsonSource, label: str) -> Dict[str, Any]:
        """把 dict / JSON 字符串 / 文件路径统一加载为 dict。

        任何失败均降级为空 dict 并记录 warning。
        """
        if source is None:
            return {}
        if isinstance(source, dict):
            return source
        if isinstance(source, list):
            return {"insights": source} if label == "insight" else {"results": source}
        if isinstance(source, (str, Path)):
            text = str(source)
            candidate = Path(text)
            if candidate.is_file():
                try:
                    loaded = json.loads(candidate.read_text(encoding="utf-8"))
                except (OSError, ValueError) as exc:
                    self._warn(f"{label} 文件解析失败: {candidate} ({exc})")
                    return {}
                return self._as_dict(loaded, label)
            try:
                loaded = json.loads(text)
            except ValueError as exc:
                self._warn(f"{label} 输入既非文件也非合法 JSON: {text[:80]} ({exc})")
                return {}
            return self._as_dict(loaded, label)
        self._warn(f"{label} 输入类型不受支持: {type(source).__name__}")
        return {}

    def _as_dict(self, loaded: Any, label: str) -> Dict[str, Any]:
        """把加载结果规整为 dict，列表输入包装为标准结构。"""
        if isinstance(loaded, dict):
            return loaded
        if isinstance(loaded, list):
            return {"insights": loaded} if label == "insight" else {"results": loaded}
        self._warn(f"{label} 产物顶层结构不是对象/列表，已忽略")
        return {}

    def _warn(self, message: str) -> None:
        """记录一条 warning（logger + 列表）。"""
        self.warnings.append(message)
        logger.warning("%s", message)

    @staticmethod
    def _scan_command_for(target: str) -> str:
        """为目标生成静态扫描回放命令。"""
        if target:
            return f"fp_sentinel insight scan {target} --sensitive"
        return "fp_sentinel insight scan <target> --sensitive"

    @staticmethod
    def _hook_command_for(class_name: str, technique: str) -> str:
        """为动态命中生成 Hook 回放命令。"""
        pkg = class_name.rsplit(".", 1)[0] if "." in class_name else "<package>"
        return (
            f"fp_sentinel mobile-hook scan <target.apk> --keyword {technique} "
            f"--class {pkg}"
        )

    @staticmethod
    def _to_float(value: Any, default: float) -> float:
        """宽容 float 转换。"""
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _to_int(value: Any, default: int) -> int:
        """宽容 int 转换。"""
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _detect_tool_version() -> str:
        """探测 fp_sentinel 版本号，失败时返回未知标记。"""
        try:
            import fp_sentinel

            return str(getattr(fp_sentinel, "__version__", "unknown"))
        except Exception:  # noqa: BLE001 - 版本探测失败不应影响主流程
            return "unknown"
