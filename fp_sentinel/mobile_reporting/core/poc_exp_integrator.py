"""POC / EXP 集成器。

PocExpIntegrator 将 mobile_poc 模块生成的 Frida 脚本 POC 与 EXP 信息
集成进报告 findings：

- attach_poc: 读取 POC 脚本内容与元数据并填入 :class:`PocInfo`；
- attach_exp: 填入 :class:`ExpInfo`（前提条件 / 步骤 / 影响 / 缓解措施）；
- safety_check: 脚本包含危险操作时标记 ``DANGER`` 并截断展示（安全红线）；
- update_coverage: 集成后自动统计 POC/EXP 覆盖写入 statistics.coverage_metrics。
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models.report_models import ExpInfo, FindingReport, MobileSecurityReport, PocInfo

__all__ = ["PocExpIntegrator", "DANGEROUS_PATTERNS"]

logger = logging.getLogger(__name__)

#: 危险操作特征（出现即标记 DANGER，安全红线）
DANGEROUS_PATTERNS: Tuple[Tuple[str, str], ...] = (
    ("os.system", "调用 os.system 执行系统命令"),
    ("subprocess.", "调用 subprocess 执行外部进程"),
    ("rm -rf", "递归强制删除文件"),
    ("del /", "Windows del 批量删除命令"),
    ("rd /s", "Windows rd 递归删除目录"),
    ("Remove-Item", "PowerShell Remove-Item 删除命令"),
    ("format ", "磁盘格式化命令"),
    ("mkfs", "文件系统格式化命令"),
    ("dd if=", "磁盘级块写入"),
    ("shutdown", "关机/重启命令"),
    ("reg delete", "Windows 注册表删除"),
)

#: 警示级特征（出现标记 WARNING，不截断但需人工确认）
WARNING_PATTERNS: Tuple[Tuple[str, str], ...] = (
    ("Java.perform", "执行 Java 层主动调用"),
    ("Interceptor.attach", "运行时函数拦截"),
    ("eval(", "动态求值代码"),
)

#: 危险脚本展示时的最大保留字符数（安全红线：截断展示）
DANGER_TRUNCATE_LIMIT = 800
#: 安全脚本展示时的最大保留字符数
SAFE_TRUNCATE_LIMIT = 5000

#: POC 脚本识别的扩展名
SCRIPT_EXTENSIONS = (".js", ".py")

#: 安全级别常量
SAFETY_SAFE = "SAFE"
SAFETY_WARNING = "WARNING"
SAFETY_DANGER = "DANGER"


class PocExpIntegrator:
    """POC / EXP 集成器。"""

    def __init__(self) -> None:
        """初始化集成器（内部记录已消费的 POC 脚本，避免重复挂接）。"""
        self._consumed: set = set()

    # ─────────────────────────── 安全红线 ────────────────────────

    @staticmethod
    def safety_check(script_content: str) -> Tuple[str, List[str]]:
        """检查脚本内容的安全级别。

        匹配规则：命中任一危险特征即 DANGER；否则命中警示特征为 WARNING；
        都未命中为 SAFE。

        Args:
            script_content: POC/EXP 脚本全文。

        Returns:
            Tuple[str, List[str]]: (安全级别, 命中原因列表)。
        """
        reasons: List[str] = []
        level = SAFETY_SAFE
        content = script_content or ""
        content_lower = content.lower()
        for pattern, reason in DANGEROUS_PATTERNS:
            if pattern.lower() in content_lower:
                reasons.append(f"{reason}（特征: {pattern.strip()}）")
                level = SAFETY_DANGER
        if level == SAFETY_DANGER:
            return level, reasons
        for pattern, reason in WARNING_PATTERNS:
            if pattern.lower() in content_lower:
                reasons.append(f"{reason}（特征: {pattern.strip()}）")
                level = SAFETY_WARNING
        return level, reasons

    @staticmethod
    def _truncate_for_display(content: str, safety_level: str) -> str:
        """按安全级别截断脚本内容用于报告展示。"""
        limit = (
            DANGER_TRUNCATE_LIMIT
            if safety_level == SAFETY_DANGER
            else SAFE_TRUNCATE_LIMIT
        )
        if len(content) <= limit:
            return content
        marker = (
            "\n# [安全红线] 脚本包含危险操作，报告内已截断展示，"
            "完整内容请查看 script_path 指向的文件。"
            if safety_level == SAFETY_DANGER
            else "\n# [内容过长已截断] 完整内容请查看 script_path 指向的文件。"
        )
        return content[:limit] + marker

    # ─────────────────────────── POC 集成 ────────────────────────

    def attach_poc(
        self,
        finding: FindingReport,
        poc_dir: str,
    ) -> Optional[PocInfo]:
        """读取 POC 目录中的脚本与元数据，填入 finding.poc。

        选择策略：文件名包含 finding.id（不区分大小写）的脚本优先；
        否则取目录内第一个未被消费的脚本（同一脚本不重复挂接到多个 finding）。
        元数据从同名 ``<stem>.json``
        或目录级 ``poc_metadata.json`` 读取，缺失时宽容降级。

        Args:
            finding: 目标漏洞发现（原地更新 poc 字段）。
            poc_dir: POC 产物目录。

        Returns:
            Optional[PocInfo]: 成功时返回构建的 PocInfo；目录无效或
            无可用脚本时返回 None（记录 warning，不抛异常）。
        """
        dir_path = Path(poc_dir)
        if not dir_path.is_dir():
            logger.warning("POC 目录不存在: %s", poc_dir)
            return None
        scripts = [
            s
            for s in self._discover_scripts(dir_path)
            if os.path.normcase(str(s)) not in self._consumed
        ]
        if not scripts:
            logger.warning("POC 目录中未发现可用脚本: %s", poc_dir)
            return None
        script = self._match_script(scripts, finding.id)
        try:
            content = script.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("POC 脚本读取失败: %s (%s)", script, exc)
            return None
        metadata = self._load_metadata(script, dir_path)

        safety_level, reasons = self.safety_check(content)
        display = self._truncate_for_display(content, safety_level)
        poc_type = str(metadata.get("type") or ("frida" if script.suffix == ".js" else "java"))
        if poc_type not in ("frida", "java", "native"):
            logger.warning("POC 元数据类型非法 %r，回退为 frida", poc_type)
            poc_type = "frida"
        description = str(
            metadata.get("description")
            or metadata.get("goal")
            or f"自动集成自 {dir_path}"
        )
        if reasons:
            description += f"；安全检查: {'; '.join(reasons)}"
        poc = PocInfo(
            id=f"POC-{finding.id}",
            name=str(metadata.get("name") or script.stem),
            type=poc_type,
            script_path=str(script),
            script_content=display,
            safety_level=safety_level,
            description=description,
        )
        if safety_level == SAFETY_DANGER:
            logger.warning(
                "POC %s 命中安全红线，已标记 DANGER 并截断展示", poc.id
            )
        finding.poc = poc
        self._consumed.add(os.path.normcase(str(script)))
        logger.info("POC 已集成: %s -> %s", script.name, finding.id)
        return poc

    def attach_poc_to_findings(
        self,
        report: MobileSecurityReport,
        poc_dir: str,
    ) -> Dict[str, PocInfo]:
        """批量为报告中尚无 POC 的 finding 集成 POC（脚本不重复消费）。

        Args:
            report: 移动安全报告。
            poc_dir: POC 产物目录。

        Returns:
            Dict[str, PocInfo]: finding id -> PocInfo 的成功映射。
        """
        attached: Dict[str, PocInfo] = {}
        for finding in report.findings:
            if finding.poc is not None:
                continue
            poc = self.attach_poc(finding, poc_dir)
            if poc is not None:
                attached[finding.id] = poc
        return attached

    # ─────────────────────────── EXP 集成 ────────────────────────

    def attach_exp(self, finding: FindingReport, exp_data: Dict[str, Any]) -> ExpInfo:
        """把 EXP 信息填入 finding.exp。

        Args:
            finding: 目标漏洞发现（原地更新 exp 字段）。
            exp_data: EXP 数据（preconditions/steps/impact/mitigation 等）。

        Returns:
            ExpInfo: 构建并挂接后的 ExpInfo。
        """
        data = exp_data or {}
        pre = [str(x) for x in (data.get("preconditions") or []) if str(x).strip()]
        steps = [str(x) for x in (data.get("steps") or []) if str(x).strip()]
        exp = ExpInfo(
            id=str(data.get("id") or f"EXP-{finding.id}"),
            name=str(data.get("name") or f"{finding.id} 受控利用"),
            preconditions=pre,
            steps=steps,
            impact=str(data.get("impact") or ""),
            mitigation=str(data.get("mitigation") or ""),
        )
        finding.exp = exp
        logger.info("EXP 已集成: %s -> %s", exp.id, finding.id)
        return exp

    # ─────────────────────────── 覆盖统计 ────────────────────────

    def update_coverage(self, report: MobileSecurityReport) -> Dict[str, Any]:
        """统计 POC/EXP 覆盖情况并写入 statistics.coverage_metrics。

        Args:
            report: 移动安全报告（statistics 为 None 时自动创建）。

        Returns:
            Dict[str, Any]: 写入后的 coverage_metrics 字典。
        """
        if report.statistics is None:
            from ..models.report_models import ReportStatistics

            report.statistics = ReportStatistics()
        total = len(report.findings)
        with_poc = sum(1 for f in report.findings if f.poc is not None)
        with_exp = sum(1 for f in report.findings if f.exp is not None)
        danger_poc = sum(
            1
            for f in report.findings
            if f.poc is not None and f.poc.safety_level == SAFETY_DANGER
        )
        metrics: Dict[str, Any] = {
            "poc_findings": with_poc,
            "exp_findings": with_exp,
            "poc_coverage": round(with_poc / total, 4) if total else 0.0,
            "exp_coverage": round(with_exp / total, 4) if total else 0.0,
            "danger_poc_count": danger_poc,
        }
        report.statistics.coverage_metrics.update(metrics)
        logger.info(
            "POC/EXP 覆盖统计完成: %d/%d POC, %d/%d EXP",
            with_poc,
            total,
            with_exp,
            total,
        )
        return dict(report.statistics.coverage_metrics)

    # ─────────────────────────── 内部工具 ────────────────────────

    @staticmethod
    def _discover_scripts(dir_path: Path) -> List[Path]:
        """递归发现目录下的 POC 脚本（按路径排序保证确定性）。"""
        scripts: List[Path] = []
        for ext in SCRIPT_EXTENSIONS:
            scripts.extend(dir_path.rglob(f"*{ext}"))
        return sorted(set(scripts), key=lambda p: str(p))

    def _match_script(self, scripts: List[Path], finding_id: str) -> Path:
        """优先返回文件名包含 finding.id 的脚本，否则返回第一个。"""
        key = (finding_id or "").lower()
        for script in scripts:
            if key and key in script.stem.lower():
                return script
        return scripts[0]

    @staticmethod
    def _load_metadata(script: Path, dir_path: Path) -> Dict[str, Any]:
        """加载 POC 元数据（同名 json 优先，其次目录级 poc_metadata.json）。"""
        for candidate in (script.with_suffix(".json"), dir_path / "poc_metadata.json"):
            if candidate.is_file():
                try:
                    loaded = json.loads(candidate.read_text(encoding="utf-8"))
                except (OSError, ValueError) as exc:
                    logger.warning("POC 元数据解析失败 %s: %s", candidate, exc)
                    continue
                if isinstance(loaded, dict):
                    return loaded
        return {}
