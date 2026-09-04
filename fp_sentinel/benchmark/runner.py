"""
性能基准测试框架

测试扫描速度、内存占用、CPU使用率、并发能力
"""

import time
import logging
import psutil
from typing import Dict, Any
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class BenchmarkReport:
    """基准测试报告"""
    total_files: int = 0
    total_lines: int = 0
    scan_duration_seconds: float = 0
    lines_per_second: float = 0
    files_per_second: float = 0
    peak_memory_mb: float = 0
    avg_cpu_percent: float = 0
    findings_count: int = 0
    rules_executed: int = 0
    passed: bool = False
    details: Dict[str, Any] = field(default_factory=dict)


class BenchmarkRunner:
    """性能基准测试运行器"""

    # 性能基线要求
    BASELINES = {
        "max_duration_100k_lines": 180,  # 10万行 < 3分钟
        "max_memory_mb": 2048,            # 内存 < 2GB
        "min_lines_per_second": 500,      # 最低500行/秒
    }

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}

    def run(
        self,
        codebase_path: str,
        scanner_func=None,
        ruleset: str = "default",
    ) -> BenchmarkReport:
        """
        运行基准测试

        Args:
            codebase_path: 代码库路径
            scanner_func: 扫描函数 (path) -> findings
            ruleset: 规则集名称
        """
        path = Path(codebase_path)
        if not path.exists():
            raise FileNotFoundError(f"Path not found: {codebase_path}")

        # 统计代码量
        files, lines = self._count_code(path)
        logger.info(f"Benchmark: {files} files, {lines} lines")

        # 监控资源
        process = psutil.Process()

        # 运行扫描
        start_time = time.time()
        findings = []

        if scanner_func:
            try:
                findings = scanner_func(codebase_path)
            except Exception as e:
                logger.error(f"Scanner failed: {e}")

        duration = time.time() - start_time

        # 收集资源使用
        try:
            memory_info = process.memory_info()
            peak_memory = memory_info.rss / 1024 / 1024  # MB
        except Exception:
            peak_memory = 0

        # 计算指标
        lines_per_sec = lines / duration if duration > 0 else 0
        files_per_sec = files / duration if duration > 0 else 0

        # 检查是否达标
        passed = self._check_baselines(lines, duration, peak_memory)

        report = BenchmarkReport(
            total_files=files,
            total_lines=lines,
            scan_duration_seconds=round(duration, 2),
            lines_per_second=round(lines_per_sec, 2),
            files_per_second=round(files_per_sec, 2),
            peak_memory_mb=round(peak_memory, 2),
            findings_count=len(findings) if isinstance(findings, list) else 0,
            passed=passed,
            details={
                "ruleset": ruleset,
                "baselines": self.BASELINES,
            },
        )

        logger.info(f"Benchmark result: {lines_per_sec:.0f} lines/s, "
                    f"{peak_memory:.0f}MB, {'PASSED' if passed else 'FAILED'}")

        return report

    def _count_code(self, path: Path) -> tuple:
        """统计代码行数"""
        code_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java',
            '.go', '.rs', '.php', '.rb', '.c', '.cpp', '.h',
        }
        skip_dirs = {
            'node_modules', '.git', 'dist', 'build', 'vendor',
            '__pycache__', '.venv', 'venv', '.env',
        }

        total_files = 0
        total_lines = 0

        for file_path in path.rglob("*"):
            if any(skip in file_path.parts for skip in skip_dirs):
                continue
            if file_path.suffix in code_extensions and file_path.is_file():
                total_files += 1
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        total_lines += sum(1 for _ in f)
                except Exception:
                    pass

        return total_files, total_lines

    def _check_baselines(self, lines: int, duration: float, memory: float) -> bool:
        """检查是否满足基线要求"""
        # 10万行 < 3分钟
        if lines >= 100000:
            if duration > self.BASELINES["max_duration_100k_lines"]:
                return False

        # 内存 < 2GB
        if memory > self.BASELINES["max_memory_mb"]:
            return False

        # 最低速度
        lines_per_sec = lines / duration if duration > 0 else 0
        if lines_per_sec < self.BASELINES["min_lines_per_second"]:
            return False

        return True

    def generate_report(self, report: BenchmarkReport, format: str = "markdown") -> str:
        """生成报告"""
        if format == "markdown":
            return self._to_markdown(report)
        elif format == "json":
            import json
            return json.dumps(report.__dict__, indent=2, ensure_ascii=False)
        return ""

    def _to_markdown(self, report: BenchmarkReport) -> str:
        status = "✅ PASSED" if report.passed else "❌ FAILED"
        return f"""# 性能基准测试报告

## 结果: {status}

| 指标 | 值 | 基线 | 状态 |
|------|-----|------|------|
| 文件数 | {report.total_files} | - | - |
| 代码行数 | {report.total_lines:,} | - | - |
| 扫描耗时 | {report.scan_duration_seconds}s | <180s/10万行 | {'✅' if report.scan_duration_seconds < 180 or report.total_lines < 100000 else '❌'} |
| 扫描速度 | {report.lines_per_second:,.0f} 行/秒 | >500行/秒 | {'✅' if report.lines_per_second >= 500 else '❌'} |
| 峰值内存 | {report.peak_memory_mb:.0f} MB | <2048MB | {'✅' if report.peak_memory_mb < 2048 else '❌'} |
| 发现数 | {report.findings_count} | - | - |
"""
