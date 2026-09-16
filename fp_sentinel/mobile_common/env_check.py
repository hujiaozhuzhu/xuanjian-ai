"""环境依赖检查器 —— 玄鉴AI 常用扫描器 / LibreOffice / Node.js 可用性审计。

提供三类检测能力：

- :class:`ScannerChecker`: 常见安全扫描器（semgrep, bandit, nuclei, ...）是否可用、
  版本多少、缺了怎么装；
- :class:`LibreOfficeChecker`: soffice 是否在 PATH，用于 DOCX 渲染；
- :class:`NodeJSExtendedChecker`: Node.js 是否可用，用于高压缩 JS 美化/解析。

最终由 :func:`run_env_audit` 一键汇总为 Markdown 审计报告（可直接贴给运维同事）。

参考安装指引常数 :data:`SCANNER_INSTALL_CMD`（fp-sentinel[scanners] extras 方式）。
"""

from __future__ import annotations

import logging
import platform
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

__all__ = [
    "SCANNER_INSTALL_CMD",
    "ScannerChecker",
    "LibreOfficeChecker",
    "NodeJSExtendedChecker",
    "run_env_audit",
]

#: fp-sentinel[scanners] 统一安装命令（用户缺扫描器时推荐的首选安装方式）。
SCANNER_INSTALL_CMD: str = "pip install fp-sentinel[scanners]"

#: 常用扫描器列表及其安装指引；每个 value 给出"为什么本工具用到它" 的简短原因。
SCANNER_CATALOG: Dict[str, Dict[str, str]] = {
    "semgrep": {
        "version_args": ["--version"],
        "pip_package": "semgrep",
        "install_hints": {
            "windows": "pip install semgrep  或  winget install Semgrep.Semgrep",
            "generic": "pip install semgrep",
        },
        "reason": "SAST 静态分析，覆盖 30+ 语言漏洞模式（SQLi/XSS/SSRF/反序列化等）。",
    },
    "bandit": {
        "version_args": ["--version"],
        "pip_package": "bandit",
        "install_hints": {
            "windows": "pip install bandit",
            "generic": "pip install bandit",
        },
        "reason": "Python 代码安全扫描，识别命令注入/硬编码密钥/不安全的 pickle 等。",
    },
    "nuclei": {
        "version_args": ["-version"],
        "go_package": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "install_hints": {
            "windows": (
                "winget install ProjectDiscovery.Nuclei  "
                "或 go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            ),
            "generic": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        },
        "reason": "模板化 Web 漏洞扫描器，识别 CVE/配置错误/暴露面板。",
    },
    "dirsearch": {
        "version_args": ["--version"],
        "pip_package": "dirsearch",
        "install_hints": {
            "windows": "pip install dirsearch",
            "generic": "pip install dirsearch",
        },
        "reason": "Web 路径暴力枚举，用于发现隐藏接口/后台/备份文件。",
    },
    "sqlmap": {
        "version_args": ["--version"],
        "pip_package": "sqlmap",
        "install_hints": {
            "windows": "pip install sqlmap",
            "generic": "pip install sqlmap",
        },
        "reason": "SQL 注入检测与利用工具，验证疑似注入点的可利用性。",
    },
    "httpx": {
        "version_args": ["-version"],
        "go_package": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "install_hints": {
            "windows": (
                "winget install ProjectDiscovery.HTTPX  "
                "或 go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
            ),
            "generic": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        },
        "reason": "HTTP 探针：快速识别 Web 服务、状态码、标题、技术栈。",
    },
    "subfinder": {
        "version_args": ["-version"],
        "go_package": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "install_hints": {
            "windows": (
                "winget install ProjectDiscovery.Subfinder  "
                "或 go install -v "
                "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            ),
            "generic": (
                "go install -v "
                "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            ),
        },
        "reason": "子域名枚举，扩大资产覆盖面。",
    },
    "gf": {
        "version_args": [],
        "go_package": "github.com/tomnomnom/gf@latest",
        "install_hints": {
            "windows": "go install -v github.com/tomnomnom/gf@latest",
            "generic": "go install -v github.com/tomnomnom/gf@latest",
        },
        "reason": "grep 模式复用工具，从 URL/响应中提取敏感信息（token、密钥等）。",
    },
}

# 当前平台关键词
_CURRENT_PLATFORM: str = "windows" if platform.system() == "Windows" else "generic"


@dataclass
class ScannerResult:
    """单个扫描器的检测结果。"""

    name: str
    available: bool
    version: str
    install_hint: str
    reason: str

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


def _run_version_cmd(cmd: List[str], version_args: List[str]) -> Optional[str]:
    """安全地调用 ``cmd version_args`` 获取版本字符串。

    任何异常（找不到命令、超时、非零退出码）都会静默返回 None，
    不会抛出任何错误给上层调用者。
    """
    try:
        result = subprocess.run(
            cmd + version_args,
            capture_output=True,
            text=True,
            timeout=10,
            encoding="utf-8",
            errors="replace",
        )
        output = (result.stdout + result.stderr).strip()
        if result.returncode != 0 and not output:
            return None
        return output.splitlines()[0] if output else None
    except FileNotFoundError:
        logger.debug("命令未找到: %s", cmd)
        return None
    except subprocess.TimeoutExpired:
        logger.debug("命令超时: %s", cmd)
        return None
    except Exception as exc:  # noqa: BLE001 —— 防御性，不因异常阻断整个审计
        logger.debug("调用 %s 出错: %s", cmd, exc)
        return None


def _extract_version(output: Optional[str]) -> str:
    """从版本输出中提取形如 ``x.y.z`` 或 ``vx.y.z`` 的版本号。"""
    if not output:
        return ""
    match = re.search(r"v?(\d+\.\d+(?:\.\d+)?)", output)
    return match.group(1) if match else output[:60]


class ScannerChecker:
    """常见安全扫描器可用性检查器。

    检测语义："命令存在于 PATH 且能稳定返回版本号"。
    不含网络调用，不含破解/破解绕过逻辑，纯本地可用性探测。
    """

    def __init__(self, catalog: Optional[Dict[str, Dict[str, str]]] = None) -> None:
        """初始化检查器。

        Parameters
        ----------
        catalog:
            自定义扫描器字典；缺省时使用内置 :data:`SCANNER_CATALOG`。
        """
        self._catalog = catalog or SCANNER_CATALOG

    @property
    def scanner_names(self) -> List[str]:
        """返回所有管理的扫描器名称（有序）。"""
        return list(self._catalog.keys())

    def check(self, name: str) -> ScannerResult:
        """检测单个扫描器的可用性。

        Parameters
        ----------
        name:
            扫描器名称（如 ``"semgrep"``, ``"bandit"``）。

        Returns
        -------
        ScannerResult
            包含 name / available / version / install_hint / reason。
        """
        entry = self._catalog.get(name)
        if entry is None:
            return ScannerResult(
                name=name,
                available=False,
                version="",
                install_hint=f"未知扫描器；如需安装请参考官方文档。推荐 pip 方式: {SCANNER_INSTALL_CMD}",
                reason="未录入 catalog。",
            )

        cmd_path = shutil.which(name)
        if cmd_path is None:
            hints = entry.get("install_hints", {})
            hint = hints.get(_CURRENT_PLATFORM, hints.get("generic", SCANNER_INSTALL_CMD))
            return ScannerResult(
                name=name,
                available=False,
                version="",
                install_hint=f"未找到命令；请安装: {hint}    （或: {SCANNER_INSTALL_CMD}）",
                reason=entry.get("reason", ""),
            )

        version_raw = _run_version_cmd([name], entry.get("version_args", []))
        version = _extract_version(version_raw) if version_raw else ""
        return ScannerResult(
            name=name,
            available=True,
            version=version or "未知",
            install_hint="已就绪",
            reason=entry.get("reason", ""),
        )

    def check_all(self) -> List[ScannerResult]:
        """检测所有扫描器的可用性。

        Returns
        -------
        list[ScannerResult]
            按 SCANNER_CATALOG 定义顺序排列的结果列表。
        """
        return [self.check(name) for name in self._catalog]

    def print_table(self, results: List[ScannerResult]) -> str:
        """生成友好的表格字符串（纯文本，适合贴入报告 / 终端）。

        Parameters
        ----------
        results:
            :meth:`check_all` 的输出。

        Returns
        -------
        str
            人类可读的表格字符串（含分隔线、状态标记与安装建议）。
        """
        if not results:
            return "(无扫描器记录)"

        name_width = max(len(r.name) for r in results)
        name_width = max(name_width, 10)  # 表头 "扫描器" 的宽度

        lines: List[str] = []
        lines.append(f"{'扫描器':<{name_width}}  {'状态':<6}  {'版本':<16}  安装指引")
        lines.append("-" * (name_width + 60))

        for r in results:
            flag = "可用" if r.available else "缺失"
            line = f"{r.name:<{name_width}}  {flag:<6}  {r.version:<16}  {r.install_hint}"
            lines.append(line)

        return "\n".join(lines)


class LibreOfficeChecker:
    """LibreOffice (soffice) 可用性检查器。

    用途: 某些扫描结果 / 报告生成路径会用 LibreOffice 把 ODT/DOCX
    渲染为 PDF 进行人工复核。soffice 不在 PATH 时相关业务会自动降级，
    但会提示用户安装。

    检测命令: ``soffice --version``。
    """

    NAME: str = "soffice"
    REASON: str = "用于 DOCX/ODT 文档渲染（报告生成、证据留档），缺失时相关业务降级为 HTML。"

    def is_available(self) -> bool:
        """检查 soffice 是否在 PATH 且能返回版本号。"""
        return shutil.which(self.NAME) is not None

    def get_version(self) -> str:
        """获取 LibreOffice 版本字符串。"""
        output = _run_version_cmd([self.NAME], ["--version"])
        return _extract_version(output) if output else ""

    def get_install_hint(self) -> str:
        """返回当前平台的安装指引（含原因）。"""
        if _CURRENT_PLATFORM == "windows":
            return (
                "Windows 安装: winget install TheDocumentFoundation.LibreOffice"
                "   或   choco install libreoffice-fresh"
                "   原因: " + self.REASON
            )
        return (
            "官网: https://www.libreoffice.org/download/download/"
            "   原因: " + self.REASON
        )

    def check(self) -> Dict[str, str]:
        """返回综合检测结果字典。"""
        available = self.is_available()
        return {
            "name": "LibreOffice (soffice)",
            "available": str(available),
            "version": self.get_version() if available else "",
            "install_hint": "已就绪" if available else self.get_install_hint(),
            "reason": self.REASON,
        }


class NodeJSExtendedChecker:
    """Node.js 可用性检查器。

    用途: 高压缩 JS 的安全审计场景。某些混淆/打包后的 JS 单文件极大，
    用 Node 原生 ``vm`` 模块加载比 Python 解析器更贴近期望执行结果。
    缺失时审计流程会自动降级到正则/静态方式。

    检测命令: ``node --version``。
    """

    NAME: str = "node"
    REASON: str = "用于高压缩 / 混淆 JS 的美化与执行环境探测（webpack / obfuscator-io 等）。"

    def is_available(self) -> bool:
        """检查 node 是否在 PATH。"""
        return shutil.which(self.NAME) is not None

    def get_version(self) -> str:
        """获取 Node.js 版本字符串。"""
        output = _run_version_cmd([self.NAME], ["--version"])
        return _extract_version(output) if output else ""

    def get_install_hint(self) -> str:
        """返回安装指引（含原因）。"""
        if _CURRENT_PLATFORM == "windows":
            return (
                "Windows 安装: winget install OpenJS.NodeJS.LTS"
                "   或   choco install nodejs-lts"
                "   原因: " + self.REASON
            )
        return (
            "官网: https://nodejs.org/en/download/"
            "   原因: " + self.REASON
        )

    def check(self) -> Dict[str, str]:
        """返回综合检测结果字典。"""
        available = self.is_available()
        return {
            "name": "Node.js",
            "available": str(available),
            "version": self.get_version() if available else "",
            "install_hint": "已就绪" if available else self.get_install_hint(),
            "reason": self.REASON,
        }


def _markdown_scanner_table(results: List[ScannerResult]) -> str:
    """把 ScannerResult 列表转为 Markdown 表格。"""
    lines: List[str] = []
    lines.append("| 扫描器 | 状态 | 版本 | 安装指引 | 审计用途 |")
    lines.append("|--------|------|------|----------|----------|")
    for r in results:
        flag = "可用" if r.available else "缺失"
        reason = r.reason.replace("|", "/")
        hint = r.install_hint.replace("|", "/")
        lines.append(f"| {r.name} | {flag} | {r.version or '-'} | {hint} | {reason} |")
    return "\n".join(lines)


def _markdown_checker_section(title: str, check_result: Dict[str, str]) -> str:
    """把单个检查器的 Markdown 段落拼出来。"""
    flag = "可用" if check_result["available"] == "True" else "缺失"
    lines = [
        f"### {title}",
        "",
        f"- **状态**: {flag}",
        f"- **版本**: {check_result.get('version', '') or '-'}",
        f"- **安装指引**: {check_result['install_hint']}",
        f"- **用途**: {check_result['reason']}",
        "",
    ]
    return "\n".join(lines)


def run_env_audit(output_path: Optional[str] = None) -> str:
    """一键跑所有检查，生成 Markdown 格式的依赖审计报告。

    Parameters
    ----------
    output_path:
        若给定，Markdown 报告会写入该路径；否则只返回字符串。

    Returns
    -------
    str
        完整 Markdown 审计报告文本。
    """
    checker = ScannerChecker()
    scanner_results = checker.check_all()

    lo_checker = LibreOfficeChecker()
    lo_result = lo_checker.check()

    node_checker = NodeJSExtendedChecker()
    node_result = node_checker.check()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    available_count = sum(1 for r in scanner_results if r.available)
    total_count = len(scanner_results)

    sections: List[str] = []
    sections.append("# 玄鉴AI (fp_sentinel) 依赖环境审计报告\n")
    sections.append(f"> 生成时间: {timestamp}\n")
    sections.append(f"- **扫描器可用**: {available_count}/{total_count}\n")
    sections.append(f"- **LibreOffice**: {'可用' if lo_result['available'] == 'True' else '缺失'}\n")
    sections.append(f"- **Node.js**: {'可用' if node_result['available'] == 'True' else '缺失'}\n")
    sections.append("")

    sections.append("## 1. 常用扫描器可用性\n")
    sections.append(_markdown_scanner_table(scanner_results))
    sections.append("")

    sections.append("## 2. 文档渲染 (LibreOffice)\n")
    sections.append(_markdown_checker_section("LibreOffice", lo_result))

    sections.append("## 3. JS 解析 (Node.js)\n")
    sections.append(_markdown_checker_section("Node.js", node_result))

    sections.append("## 4. 一键安装命令\n")
    sections.append("推荐通过安装 extras 补全 scanner 能力：\n")
    sections.append(f"```\n{SCANNER_INSTALL_CMD}\n```\n")

    severity_hint = []
    if available_count < total_count:
        missing = [r.name for r in scanner_results if not r.available]
        severity_hint.append(f"缺少: {', '.join(missing)}")
    if lo_result["available"] != "True":
        severity_hint.append("缺少 LibreOffice: DOCX 渲染将降级为 HTML")
    if node_result["available"] != "True":
        severity_hint.append("缺少 Node.js: 高压缩 JS 将无法使用 vm 探测")

    if severity_hint:
        sections.append("## 5. 风险提示\n")
        for hint in severity_hint:
            sections.append(f"- {hint}")
        sections.append("")

    full_report = "\n".join(sections)

    if output_path is not None:
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(full_report)
            logger.info("依赖审计报告已写入: %s", output_path)
        except OSError as exc:
            logger.warning("写入报告失败 %s: %s", output_path, exc)

    return full_report
