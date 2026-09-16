"""Web 证据报告构造器。

聚合来自 Burp / Nuclei / ZAP / CSV / 手工录入等多种来源的漏洞证据，
构建
:class:`~fp_sentinel.mobile_reporting.models.report_models.MobileSecurityReport`，
并调用 :func:`~fp_sentinel.mobile_reporting.generate_report`
输出 Excel / Word / HTML。
"""

from __future__ import annotations

import csv
import json
import logging
import platform
import sys
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, List, Optional, Sequence

from .adapters import (
    burp_alert_to_finding,
    manual_finding,
    nuclei_result_to_finding,
    zap_alert_to_finding,
)

if TYPE_CHECKING:  # 注解-only，避免包解析错位
    from fp_sentinel.mobile_reporting.models import (  # pragma: no cover
        FindingReport,
        MobileSecurityReport,
    )

__all__ = ["WebEvidenceReportBuilder"]

logger = logging.getLogger(__name__)


def _safe_read_json(path: Path) -> Optional[list]:
    """安全读取 JSON 文件（期望顶层为列表）。

    失败时记录 error 并返回 None，不抛异常。
    """
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        logger.error("文件不存在: %s", path)
        return None
    except PermissionError:
        logger.error("文件不可读（权限不足）: %s", path)
        return None
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.error("文件解析失败: %s (%s)", path, exc)
        return None
    if not isinstance(data, list):
        logger.error("期望 JSON 顶层为列表，实际为: %s (%s)", type(data).__name__, path)
        return None
    return data


def _safe_read_json_object(path: Path) -> Optional[dict]:
    """安全读取 JSON 文件（期望顶层为 dict，如 Burp 导出）。"""
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        logger.error("文件不存在: %s", path)
        return None
    except PermissionError:
        logger.error("文件不可读（权限不足）: %s", path)
        return None
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.error("文件解析失败: %s (%s)", path, exc)
        return None
    if not isinstance(data, dict):
        logger.error("期望 JSON 顶层为对象，实际为: %s (%s)", type(data).__name__, path)
        return None
    return data


class WebEvidenceReportBuilder:
    """Web 漏洞证据收集与报告构造器。

    链式调用 ``add_*`` 方法添加证据，最终通过 :meth:`build` 生成
    :class:`MobileSecurityReport`，再通过 :meth:`generate` 输出文件。
    """

    def __init__(self) -> None:
        self._findings: List[FindingReport] = []
        self._sources: dict[str, int] = {}

    # ────────────────────────── 添加接口 ──────────────────────────

    def add_finding(
        self, finding: FindingReport,
    ) -> "WebEvidenceReportBuilder":
        """添加一条已构造好的 :class:`FindingReport`。"""
        if finding is not None:
            self._findings.append(finding)
        return self

    def add_findings(
        self, findings: Iterable[FindingReport]
    ) -> "WebEvidenceReportBuilder":
        """批量添加 :class:`FindingReport` 列表。"""
        for finding in findings:
            if finding is not None:
                self._findings.append(finding)
        return self

    def add_from_burp_json(
        self, path: str | Path,
    ) -> "WebEvidenceReportBuilder":
        """从 Burp Suite JSON 导出文件中读取 issues 列表。

        Burp 导出格式有两种常见形态：

        - 顶层为 list：每条为 issue dict
        - 顶层为 dict 且含 ``issues`` 键：值为 issue list

        同时也接受单层 issue dict（转为单元素列表处理）。
        """
        file_path = Path(path)
        raw = _safe_read_json(file_path)
        if raw is not None:
            return self._ingest_burp_issues(raw, str(file_path))

        raw_obj = _safe_read_json_object(file_path)
        if raw_obj is not None:
            issues = raw_obj.get("issues") or []
            if isinstance(issues, list):
                return self._ingest_burp_issues(issues, str(file_path))
            # 单层 dict 视为单条 issue
            finding = burp_alert_to_finding(raw_obj)
            if finding:
                self._findings.append(finding)
                self._sources["burp"] = self._sources.get("burp", 0) + 1
        return self

    def _ingest_burp_issues(
        self, issues: list, source_label: str
    ) -> "WebEvidenceReportBuilder":
        count = 0
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            finding = burp_alert_to_finding(issue)
            if finding:
                self._findings.append(finding)
                count += 1
        if count:
            self._sources["burp"] = self._sources.get("burp", 0) + count
        logger.info(
            "Burp JSON 解析完成: %s → %d 条 finding", source_label, count,
        )
        return self

    def add_from_nuclei_json(
        self, path: str | Path,
    ) -> "WebEvidenceReportBuilder":
        """从 Nuclei JSON 结果文件读取（每行一个 JSON 对象）。"""
        file_path = Path(path)
        count = 0
        try:
            with file_path.open("r", encoding="utf-8") as fh:
                for line_no, line in enumerate(fh, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        result = json.loads(line)
                    except json.JSONDecodeError as exc:
                        logger.warning(
                            "Nuclei JSON 行 %d 解析失败，跳过: %s",
                            line_no,
                            exc,
                        )
                        continue
                    if not isinstance(result, dict):
                        finding = nuclei_result_to_finding(result)
                    else:
                        finding = nuclei_result_to_finding(result)
                    if finding:
                        self._findings.append(finding)
                        count += 1
        except FileNotFoundError:
            logger.error("文件不存在: %s", file_path)
            return self
        except PermissionError:
            logger.error("文件不可读（权限不足）: %s", file_path)
            return self
        except UnicodeDecodeError as exc:
            logger.error("文件编码错误: %s (%s)", file_path, exc)
            return self
        if count:
            self._sources["nuclei"] = self._sources.get("nuclei", 0) + count
        logger.info(
            "Nuclei JSON 解析完成: %s → %d 条 finding", file_path, count,
        )
        return self

    def add_from_zap_json(
        self, path: str | Path,
    ) -> "WebEvidenceReportBuilder":
        """从 OWASP ZAP JSON 报告文件读取。

        ZAP JSON 报告顶层为 dict，含 ``site`` 键，其值列表中
        每个 site 对象含 ``alerts`` 键。
        """
        file_path = Path(path)
        raw = _safe_read_json_object(file_path)
        if raw is None:
            # 尝试按行读取（某些导出将每条 alert 放在独立行）
            raw_list = _safe_read_json(file_path)
            if raw_list is not None:
                count = 0
                for item in raw_list:
                    if isinstance(item, dict):
                        finding = zap_alert_to_finding(item)
                        if finding:
                            self._findings.append(finding)
                            count += 1
                if count:
                    self._sources["zap"] = self._sources.get("zap", 0) + count
                logger.info(
                    "Zap JSON (line format) 解析完成: %s → %d 条 finding",
                    file_path,
                    count,
                )
            return self

        alerts: list = []
        sites = raw.get("site") or []
        if isinstance(sites, dict):
            sites = [sites]
        for site in sites:
            if isinstance(site, dict):
                site_alerts = site.get("alerts") or []
                if isinstance(site_alerts, list):
                    alerts.extend(site_alerts)
                elif isinstance(site_alerts, dict):
                    alerts.append(site_alerts)

        count = 0
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            finding = zap_alert_to_finding(alert)
            if finding:
                self._findings.append(finding)
                count += 1
        if count:
            self._sources["zap"] = self._sources.get("zap", 0) + count
        logger.info("ZAP JSON 报告解析完成: %s → %d 条 finding", file_path, count)
        return self

    def add_from_csv(self, csv_path: str | Path) -> "WebEvidenceReportBuilder":
        """从 CSV 文件读取手工漏洞记录。

        CSV 列：id, title, severity, cwe_id, description, evidence, remediation
        """
        file_path = Path(csv_path)
        count = 0
        try:
            with file_path.open("r", encoding="utf-8", newline="") as fh:
                reader = csv.DictReader(fh)
                for row_no, row in enumerate(reader, start=2):
                    finding = manual_finding(
                        id=str(row.get("id", "") or f"CSV-{row_no}"),
                        title=str(row.get("title", "") or ""),
                        severity=str(row.get("severity", "") or ""),
                        cwe_id=str(row.get("cwe_id", "") or ""),
                        description=str(row.get("description", "") or ""),
                        evidence=str(row.get("evidence", "") or ""),
                        remediation=str(row.get("remediation", "") or ""),
                    )
                    if finding:
                        self._findings.append(finding)
                        count += 1
        except FileNotFoundError:
            logger.error("CSV 文件不存在: %s", file_path)
            return self
        except PermissionError:
            logger.error("CSV 文件不可读（权限不足）: %s", file_path)
            return self
        except UnicodeDecodeError as exc:
            logger.error("CSV 文件编码错误: %s (%s)", file_path, exc)
            return self
        if count:
            self._sources["csv"] = self._sources.get("csv", 0) + count
        logger.info("CSV 解析完成: %s → %d 条 finding", file_path, count)
        return self

    # ────────────────────────── 工厂方法 ──────────────────────────

    @classmethod
    def from_paths(
        cls,
        *,
        burp: str | Path | None = None,
        nuclei: str | Path | None = None,
        zap: str | Path | None = None,
        csv: str | Path | None = None,
        manual: Sequence[FindingReport] | None = None,
    ) -> "WebEvidenceReportBuilder":
        """从多种来源一次性构造 builder。

        Args:
            burp: Burp Suite JSON 路径
            nuclei: Nuclei JSON 路径
            zap: ZAP JSON 路径
            csv: CSV 文件路径
            manual: 手工 FindingReport 列表

        Returns:
            已填充 findings 的 :class:`WebEvidenceReportBuilder` 实例
        """
        builder = cls()
        if burp:
            builder.add_from_burp_json(burp)
        if nuclei:
            builder.add_from_nuclei_json(nuclei)
        if zap:
            builder.add_from_zap_json(zap)
        if csv:
            builder.add_from_csv(csv)
        if manual:
            builder.add_findings(manual)
        return builder

    # ────────────────────────── 构建 / 生成 ──────────────────────────

    def build(
        self,
        target_app_name: str = "",
        scan_command: str = "",
    ) -> MobileSecurityReport:
        """自动构造 :class:`MobileSecurityReport`。

        Args:
            target_app_name: 目标应用/站点名称
            scan_command: 触发扫描的命令（用于审计追溯）

        Returns:
            聚合完成的 MobileSecurityReport 实例
        """
        from fp_sentinel.mobile_reporting.models import (  # 惰性导入，防全仓收集时包解析错位
            EnvironmentInfo,
            MobileSecurityReport,
            ReportMetadata,
            ReportStatistics,
        )

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 聚合统计
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        for finding in self._findings:
            sev = finding.severity.strip().upper() or "INFO"
            by_severity[sev] = by_severity.get(sev, 0) + 1
            cat = finding.category.strip() or "未分类"
            by_category[cat] = by_category.get(cat, 0) + 1

        statistics = ReportStatistics(
            total_count=len(self._findings),
            by_severity=by_severity,
            by_category=by_category,
            coverage_metrics={"sources": dict(self._sources)},
        )

        environment = EnvironmentInfo(
            os=platform.platform(),
            python_version=sys.version.split()[0],
            tool_versions={"fp_sentinel": "web-evidence-adapter"},
            scan_command=scan_command,
            scan_time=now_str,
        )

        metadata = ReportMetadata(
            title=f"Web 安全评估报告 - {target_app_name or '未指定目标'}",
            author="玄鉴AI (fp_sentinel)",
            date=now_str,
        )

        return MobileSecurityReport(
            metadata=metadata,
            environment=environment,
            statistics=statistics,
            findings=list(self._findings),
            generated_at=now_str,
        )

    def generate(
        self,
        output_dir: str | Path,
        formats: Sequence[str] = ("excel", "word", "html"),
        target_app_name: str = "",
        scan_command: str = "",
    ) -> dict[str, str]:
        """调用报告模块生成文件。

        先 :meth:`build` 再调 :func:`generate_report`。

        Args:
            output_dir: 输出目录
            formats: 输出格式列表（excel / word / html）
            target_app_name: 目标应用名称
            scan_command: 触发扫描的命令

        Returns:
            ``{格式: 输出路径}`` 字典
        """
        from fp_sentinel.mobile_reporting import generate_report  # 惰性导入，防循环依赖
        report = self.build(
            target_app_name=target_app_name,
            scan_command=scan_command,
        )
        return generate_report(report, str(output_dir), formats=list(formats))
