"""扫描器一键安装与项目扫描器推荐。

提供三类能力：

- :data:`SCANNERS` —— 受管扫描器字典（pip 包名、binary 名、用途、最低版本、官方链接）；
- :class:`ScannerInstaller` —— 单个扫描器的可用性检测、逐包安装、一键脚本生成；
- :class:`ProjectScannerAdvisor` —— 按目录语言构成自动推荐扫描器组合。

操作确认原则：真实 pip 安装前必须满足双层同意之一——
``I_HAVE_ENV_AUTH=1`` 环境变量，或用户交互输入 y/yes。
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Union

from fp_sentinel.mobile_reporting.formats.base_generator import PathNotAllowedError

logger = logging.getLogger(__name__)

__all__ = [
    "SCANNERS",
    "SCANNER_INSTALL_CMD",
    "ScannerInstaller",
    "ProjectScannerAdvisor",
    "interactive_agreement",
    "env_token_agreed",
]

#: 受管扫描器定义。
#:
#: 每项 key 为扫描器名，value 包含:
#: - ``pip_package``: pip 安装包名
#: - ``binary``: 安装后在 PATH 中期望的可执行文件名
#: - ``purpose``: 一句话用途说明
#: - ``min_version``: 最低版本；空字符串表示不检测
#: - ``homepage``: 官方链接
SCANNERS: Dict[str, Dict[str, str]] = {
    "semgrep": {
        "pip_package": "semgrep",
        "binary": "semgrep",
        "purpose": "SAST 静态分析，覆盖 30+ 语言漏洞模式",
        "min_version": "1.0",
        "homepage": "https://semgrep.dev/",
    },
    "bandit": {
        "pip_package": "bandit",
        "binary": "bandit",
        "purpose": "Python 安全扫描（命令注入/硬编码密钥等）",
        "min_version": "1.7",
        "homepage": "https://github.com/PyCQA/bandit",
    },
    "findsecbugs": {
        "pip_package": "findsecbugs",
        "binary": "findsecbugs",
        "purpose": "Java 字节码漏洞模式扫描",
        "min_version": "",
        "homepage": "https://findsecbugs.github.io/",
    },
    "njsscan": {
        "pip_package": "njsscan",
        "binary": "njsscan",
        "purpose": "Node.js 应用 SAST 扫描",
        "min_version": "",
        "homepage": "https://github.com/ajinabraham/njsscan",
    },
    "eslint": {
        "pip_package": "eslint",
        "binary": "eslint",
        "purpose": "JavaScript/TypeScript 代码质量与安全扫描",
        "min_version": "",
        "homepage": "https://eslint.org/",
    },
    "shellcheck": {
        "pip_package": "shellcheck",
        "binary": "shellcheck",
        "purpose": "Shell 脚本静态分析",
        "min_version": "",
        "homepage": "https://www.shellcheck.net/",
    },
    "dirsearch": {
        "pip_package": "dirsearch",
        "binary": "dirsearch",
        "purpose": "Web 路径暴力枚举（隐藏接口/后台/备份）",
        "min_version": "",
        "homepage": "https://github.com/maurosoria/dirsearch",
    },
    "httpx": {
        "pip_package": "httpx",
        "binary": "httpx",
        "purpose": "HTTP 探针（快速识别 Web 服务/状态/技术栈）",
        "min_version": "",
        "homepage": "https://github.com/projectdiscovery/httpx",
    },
}

#: 统一安装命令（extras 方式）。
SCANNER_INSTALL_CMD: str = "pip install fp-sentinel[scanners]"

#: pip 安装失败时的通用建议
_INSTALL_SUGGESTIONS: str = (
    "安装失败时可尝试：\n"
    "  1. 镜像源：pip install -i https://pypi.tuna.tsinghua.edu.cn/simple <package>\n"
    "  2. 网络代理：set HTTPS_PROXY=http://proxy:port  (Windows)\n"
    "  3. 虚拟环境：python -m venv .venv  &&  .venv\\Scripts\\activate\n"
    "  4. 管理员权限：以管理员身份运行终端\n"
    f"  5. 一键安装 extras：{SCANNER_INSTALL_CMD}"
)


def _resolve_within_whitelist(path: Path, allowed_roots: Iterable[Path]) -> Path:
    """解析路径并校验白名单。

    Raises:
        PathNotAllowedError: 路径逃逸出白名单。
    """
    raw = path
    if not raw.is_absolute():
        raw = Path.cwd() / raw
    resolved = raw.expanduser().resolve(strict=False)
    roots = {r.expanduser().resolve(strict=False) for r in allowed_roots}
    for root in roots:
        try:
            resolved.relative_to(root)
            return resolved
        except ValueError:
            continue
    raise PathNotAllowedError(
        f"S7 红线: 输出路径 {resolved} 不在白名单根目录 "
        f"{sorted(str(r) for r in roots)} 之内。"
    )


def interactive_agreement() -> bool:
    """询问用户是否继续安装。

    Returns:
        y/yes（大小写不敏感）返回 True；其他均 False。
    """
    try:
        answer = input("是否继续安装？(y/N) ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("y", "yes")


def env_token_agreed() -> bool:
    """检查环境变量 I_HAVE_ENV_AUTH 是否为 '1'。

    Returns:
        运维已书面授权时返回 True。
    """
    return os.environ.get("I_HAVE_ENV_AUTH") == "1"


class ScannerInstaller:
    """扫描器安装器 / 可用性检测器。"""

    def __init__(
        self,
        allowed_roots: Optional[Iterable[Union[str, Path]]] = None,
    ) -> None:
        roots = list(allowed_roots) if allowed_roots is not None else [Path.cwd()]
        if not roots:
            roots = [Path.cwd()]
        self._allowed_roots: List[Path] = [
            Path(r).expanduser().resolve(strict=False) for r in roots
        ]

    def check(self, name: str) -> dict:
        """检测单个扫描器的可用性。

        Args:
            name: 扫描器名称（如 ``"semgrep"``）。

        Returns:
            dict: ``{name, installed, version, error}``。
        """
        meta = SCANNERS.get(name)
        if meta is None:
            return {
                "name": name,
                "installed": False,
                "version": None,
                "error": f"未知扫描器: {name}；受管扫描器: {list(SCANNERS.keys())}",
            }

        binary = meta["binary"]
        cmd_path = shutil.which(binary)
        if cmd_path is None:
            return {
                "name": name,
                "installed": False,
                "version": None,
                "error": f"命令 {binary} 不在 PATH；请安装: pip install {meta['pip_package']}",
            }

        try:
            proc = subprocess.run(
                [binary, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                encoding="utf-8",
                errors="replace",
            )
            output = (proc.stdout + proc.stderr).strip()
            version = _extract_version(output)
            return {
                "name": name,
                "installed": True,
                "version": version,
                "error": None,
            }
        except (subprocess.TimeoutExpired, OSError) as exc:
            return {
                "name": name,
                "installed": False,
                "version": None,
                "error": f"调用 {binary} --version 失败: {exc}",
            }

    def install(
        self,
        names: List[str],
        index_url: Optional[str] = None,
        upgrade: bool = False,
        dry_run: bool = False,
    ) -> dict:
        """逐包 pip install。

        Args:
            names: 要安装的扫描器名称列表。
            index_url: pip 镜像源 URL。
            upgrade: 是否加 ``--upgrade``。
            dry_run: True 时只返回 ``{"dry_run": True, "commands": [...]}`` 不执行。

        Returns:
            dict: 含 ``dry_run``、``commands``、``results``（逐包结果）。
        """
        commands: List[str] = []
        for name in names:
            meta = SCANNERS.get(name, {})
            pkg = meta.get("pip_package", name)
            cmd_parts = [sys.executable, "-m", "pip", "install", pkg]
            if index_url:
                cmd_parts += ["-i", index_url]
            if upgrade:
                cmd_parts.append("--upgrade")
            commands.append(" ".join(cmd_parts))

        if dry_run:
            logger.info("dry-run 模式，不执行安装命令: %s", commands)
            return {
                "dry_run": True,
                "commands": commands,
                "results": [],
            }

        results: List[dict] = []
        per_timeout = max(30, 120 * max(1, len(names)) // max(1, len(names)))
        for name in names:
            meta = SCANNERS.get(name, {})
            pkg = meta.get("pip_package", name)
            cmd = [sys.executable, "-m", "pip", "install", pkg]
            if index_url:
                cmd += ["-i", index_url]
            if upgrade:
                cmd.append("--upgrade")

            logger.info("正在安装 %s ...", name)
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=per_timeout,
                    encoding="utf-8",
                    errors="replace",
                )
                ok = proc.returncode == 0
                results.append(
                    {
                        "name": name,
                        "ok": ok,
                        "returncode": proc.returncode,
                        "stdout_tail": proc.stdout.strip()[-500:],
                        "stderr_tail": proc.stderr.strip()[-500:],
                    }
                )
                if not ok:
                    logger.warning(
                        "%s 安装失败 (rc=%d): %s",
                        name,
                        proc.returncode,
                        proc.stderr.strip()[-200:],
                    )
            except (subprocess.TimeoutExpired, OSError) as exc:
                results.append(
                    {
                        "name": name,
                        "ok": False,
                        "returncode": -1,
                        "stdout_tail": "",
                        "stderr_tail": str(exc)[-500:],
                    }
                )

        failed = [r["name"] for r in results if not r["ok"]]
        return {
            "dry_run": False,
            "commands": commands,
            "results": results,
            "suggestions": _INSTALL_SUGGESTIONS if failed else "",
        }

    def verify(self, names: List[str]) -> dict:
        """安装后再 check，返回可用性汇总。

        Returns:
            dict: 每项含 ``name, installed, usable, version``。
        """
        results: List[dict] = []
        for name in names:
            info = self.check(name)
            results.append(
                {
                    "name": name,
                    "installed": info["installed"],
                    "usable": info["installed"] and info["error"] is None,
                    "version": info.get("version"),
                }
            )
        return {"results": results}

    def generate_one_click_script(
        self,
        names: List[str],
        shell: str = "ps1",
        output_path: Optional[Union[str, Path]] = None,
    ) -> str:
        """生成可分发的一键脚本。

        Args:
            names: 要包含的扫描器名称列表。
            shell: ``ps1`` 或 ``sh``。
            output_path: 若给定则写入文件（白名单校验）。

        Returns:
            脚本文本字符串。
        """
        if shell not in ("ps1", "sh"):
            raise ValueError(f"不支持的脚本类型: {shell}（仅 ps1 或 sh）")

        lines: List[str] = []
        if shell == "ps1":
            lines.append("# 玄鉴 fp-sentinel 扫描器一键安装脚本 (PowerShell)")
            lines.append("Write-Host '以下扫描器将被安装：' -ForegroundColor Cyan")
            for name in names:
                meta = SCANNERS.get(name, {})
                pkg = meta.get("pip_package", name)
                purpose = meta.get("purpose", "")
                lines.append(f"Write-Host '  - {name}: {purpose}'")
            lines.append("")
            lines.append(
                "$confirm = Read-Host '是否继续安装？(y/N)'"
            )
            lines.append("if ($confirm -notin @('y','yes','Y','YES')) {")
            lines.append(
                "    Write-Host '已取消。' -ForegroundColor Yellow; exit 0"
            )
            lines.append("}")
            lines.append("")
            for name in names:
                meta = SCANNERS.get(name, {})
                pkg = meta.get("pip_package", name)
                binary = meta.get("binary", name)
                lines.append(f"Write-Host 'Installing {name}...'")
                lines.append(
                    f"python -m pip install {pkg}"
                )
                lines.append(f"& {binary} --version")
                lines.append("")
        else:
            lines.append("#!/usr/bin/env bash")
            lines.append("# 玄鉴 fp-sentinel 扫描器一键安装脚本 (Bash)")
            lines.append("echo '以下扫描器将被安装：'")
            for name in names:
                meta = SCANNERS.get(name, {})
                pkg = meta.get("pip_package", name)
                purpose = meta.get("purpose", "")
                lines.append(f"echo '  - {name}: {purpose}'")
            lines.append("")
            lines.append(
                "read -r -p '是否继续安装？(y/N) ' confirm"
            )
            lines.append(
                "if [[ ! $confirm =~ ^[Yy]([Ee][Ss])?$ ]]; then"
            )
            lines.append(
                "    echo '已取消。'; exit 0"
            )
            lines.append("fi")
            lines.append("")
            for name in names:
                meta = SCANNERS.get(name, {})
                pkg = meta.get("pip_package", name)
                binary = meta.get("binary", name)
                lines.append(f"echo 'Installing {name}...'")
                lines.append(f"python -m pip install {pkg}")
                lines.append(f"{binary} --version")
                lines.append("")

        script = "\n".join(lines) + "\n"

        if output_path is not None:
            out = _resolve_within_whitelist(
                Path(output_path), self._allowed_roots
            )
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(script, encoding="utf-8")
            logger.info("一键脚本已写入: %s", out)

        return script


class ProjectScannerAdvisor:
    """基于项目目录语言的扫描器推荐器。"""

    #: 扩展名 → 语言映射
    _EXT_TO_LANG: Dict[str, str] = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".jsx": "javascript",
        ".java": "java",
        ".go": "go",
        ".c": "c",
        ".h": "c",
        ".sh": "shell",
        ".bash": "shell",
        ".html": "web",
        ".htm": "web",
        ".php": "php",
    }

    #: 语言 → 推荐扫描器组合
    _LANG_RECOMMENDATIONS: Dict[str, List[str]] = {
        "python": ["bandit", "semgrep"],
        "javascript": ["eslint", "njsscan", "semgrep"],
        "typescript": ["eslint", "njsscan", "semgrep"],
        "java": ["findsecbugs", "semgrep"],
        "web": ["dirsearch", "httpx", "semgrep"],
        "php": ["dirsearch", "httpx", "semgrep"],
        "go": ["semgrep"],
        "c": ["semgrep", "shellcheck"],
        "shell": ["shellcheck", "semgrep"],
    }

    #: 应忽略的目录名
    _IGNORE_DIRS = frozenset({"node_modules", ".git", "__pycache__", ".venv", "venv"})

    def detect_languages(self, scan_dir: Union[str, Path]) -> dict:
        """统计目录中各语言扩展名的占比。

        Args:
            scan_dir: 待检测的项目目录。

        Returns:
            dict: ``{语言: 文件数}``，按数量降序排列。
        """
        scan_path = Path(scan_dir)
        if not scan_path.exists():
            raise FileNotFoundError(f"目录不存在: {scan_path}")

        counts: Dict[str, int] = {}
        for root, dirnames, filenames in os.walk(scan_path):
            # 过滤忽略目录
            dirnames[:] = [
                d for d in dirnames if d not in self._IGNORE_DIRS
            ]
            for fname in filenames:
                ext = Path(fname).suffix.lower()
                lang = self._EXT_TO_LANG.get(ext)
                if lang:
                    counts[lang] = counts.get(lang, 0) + 1

        # 按数量降序
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    def recommend(
        self,
        scan_dir: Union[str, Path],
        extra: Optional[List[str]] = None,
    ) -> List[dict]:
        """按目录语言构成推荐扫描器组合。

        Args:
            scan_dir: 项目目录。
            extra: 额外强制包含的扫描器名称列表。

        Returns:
            推荐列表，每项含 ``name, reason``。
        """
        lang_counts = self.detect_languages(scan_dir)
        if not lang_counts:
            # 回退通用推荐
            recommended = ["semgrep"]
        else:
            recommended_set: set = set()
            for lang in lang_counts:
                scanners = self._LANG_RECOMMENDATIONS.get(lang, ["semgrep"])
                recommended_set.update(scanners)
            recommended = list(recommended_set)

        if extra:
            for name in extra:
                if name not in recommended:
                    recommended.append(name)

        result: List[dict] = []
        for name in recommended:
            meta = SCANNERS.get(name, {})
            result.append(
                {
                    "name": name,
                    "reason": meta.get("purpose", "通用扫描器"),
                }
            )
        return result

    def format_report(
        self,
        scan_dir: Union[str, Path],
        recommendations: Optional[List[dict]] = None,
    ) -> str:
        """生成 Markdown 友好的推荐报告。

        Args:
            scan_dir: 项目目录。
            recommendations: 推荐列表；若 None 则内部调用 :meth:`recommend`。

        Returns:
            Markdown 格式报告字符串。
        """
        if recommendations is None:
            recommendations = self.recommend(scan_dir)

        lang_counts = self.detect_languages(scan_dir)
        lines: List[str] = []

        lines.append("# 扫描器推荐报告\n")
        lines.append(f"- **项目目录**: `{scan_dir}`")
        lines.append(f"- **检测到的语言**: {lang_counts or '（回退为通用）'}")
        lines.append("")
        lines.append("## 推荐扫描器\n")
        lines.append("| 扫描器 | 用途 | 安装命令 |")
        lines.append("|--------|------|----------|")
        for rec in recommendations:
            name = rec["name"]
            meta = SCANNERS.get(name, {})
            pkg = meta.get("pip_package", name)
            purpose = meta.get("purpose", "通用")
            lines.append(f"| {name} | {purpose} | `pip install {pkg}` |")
        lines.append("")
        lines.append("## 一键安装\n")
        cmds = " ".join(
            f"pip install {SCANNERS.get(r['name'], {}).get('pip_package', r['name'])}"
            for r in recommendations
        )
        lines.append(f"```\n{cmds}\n```")
        lines.append(f"\n或使用: `{SCANNER_INSTALL_CMD}`")
        return "\n".join(lines)


# ─────────────────────────── 内部辅助 ───────────────────────────


def _extract_version(output: str) -> Optional[str]:
    """从版本输出中提取 ``x.y.z`` 版本号。"""
    if not output:
        return None
    match = re.search(r"v?(\d+\.\d+(?:\.\d+)?)", output)
    return match.group(1) if match else output.strip()[:60]
