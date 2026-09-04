"""
A4. 靶场验证器 —— 三状态诚实标注

- verified_local : 仅 Docker 隔离靶场 + --verify 显式开启时才可能出现
- simulated      : 默认路径。对靶场/用户项目源码做 payload 特征匹配（零网络）
- manual_required: 源码不可读或特征不足以判定时，转人工确认

S1：网络探测（如存在）仅允许发往 127.0.0.1。
S4：无 Docker 自动降级为 simulated，绝不把 simulated 标成 verified_local。
"""

import logging
import shutil
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class VerifyStatus(str, Enum):
    """验证状态（诚实三态）"""
    VERIFIED_LOCAL = "verified_local"    # 仅 Docker 靶场可达
    SIMULATED = "simulated"              # 特征匹配模拟验证（默认）
    MANUAL_REQUIRED = "manual_required"  # 需人工确认


@dataclass
class VerifyResult:
    """单条验证结果"""
    status: VerifyStatus
    method: str                 # docker / signature-match / fallback
    evidence: str = ""          # 判定依据说明
    detail: str = ""            # 补充信息（写入报告）


# ─────────────────────── sink / 输入特征（特征匹配用） ───────────────────────

_SINK_SIGNATURES = {
    "sqli": ["SELECT", "query(", "execute(", "db.query"],
    "cmd-injection": ["os.system(", "subprocess", "exec(", "child_process", "spawn("],
    "eval": ["eval("],
    "path-traversal": ["open(", "readFile(", "fs.", "os.path.join("],
    "ssrf": ["axios.get(", "requests.get(", "urllib", "fetch("],
    "deser-pickle": ["pickle.loads("],
    "deser-yaml": ["yaml.load("],
    "jwt": ["jwt.sign", "jwt.decode", "jsonwebtoken"],
    "xss": ["innerHTML", "document.write", "res.send(", "$(".encode().decode()],
    "ssti": ["Template(", "render_template_string("],
    "xxe": ["lxml", "minidom", "etree"],
    "weak-hash": ["md5", "sha1"],
    "secret": ["SECRET", "API_KEY", "PASSWORD", "TOKEN"],
}

# rule_id / 漏洞类型 → 特征键映射
_RULE_TO_KEY = [
    (("sql", "injection.sql"), "sqli"),
    (("command", "cmd", "os.system", "injection.command"), "cmd-injection"),
    (("eval",), "eval"),
    (("path", "traversal"), "path-traversal"),
    (("ssrf",), "ssrf"),
    (("pickle",), "deser-pickle"),
    (("yaml",), "deser-yaml"),
    (("jwt",), "jwt"),
    (("xss",), "xss"),
    (("ssti", "template"), "ssti"),
    (("xxe",), "xxe"),
    (("hash", "md5", "sha1"), "weak-hash"),
    (("secret", "hardcoded"), "secret"),
]


def _rule_key(rule_id: str) -> Optional[str]:
    rid = (rule_id or "").lower()
    for patterns, key in _RULE_TO_KEY:
        if any(p in rid for p in patterns):
            return key
    return None


# 用户输入特征（同 exploitability 的判定思想）
_INPUT_SIGNATURES = [
    "request.args", "request.form", "request.get_data", "request.json",
    "req.query", "req.body", "req.params", "flask.request",
    "process.env", "window.location", "URLSearchParams", "input(",
]


def docker_available() -> bool:
    """检测 Docker 是否可用（S4 降级依据）"""
    return shutil.which("docker") is not None


def _read_source(file_path: str, project_root: Optional[str] = None) -> Optional[str]:
    """只读方式读取源文件（不修改，S2）"""
    candidates = [Path(file_path)]
    if project_root:
        rel = file_path.lstrip("/\\")
        candidates.append(Path(project_root) / rel)
    for p in candidates:
        try:
            if p.is_file():
                return p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return None


def _signature_match(rule_id: str, source: str) -> tuple:
    """
    对源码做 payload 特征匹配：
    - sink 特征存在
    - 且该 sink 所在链路上能看到用户输入特征（同文件内）

    Returns:
        (matched: bool, evidence: str)
    """
    key = _rule_key(rule_id)
    if key is None:
        return False, f"规则 {rule_id} 无内置特征库"

    sink_sigs = _SINK_SIGNATURES.get(key, [])
    sink_hit = next((s for s in sink_sigs if s in source), None)
    if not sink_hit:
        return False, f"未在源码中找到 {key} sink 特征"

    input_hit = next((s for s in _INPUT_SIGNATURES if s in source), None)
    if input_hit:
        return True, f"sink 特征 {sink_hit!r} + 输入特征 {input_hit!r} 同时命中"
    return True, f"sink 特征 {sink_hit!r} 命中，但同文件未见用户输入特征（置信度较低）"


def verify(
    finding: Any,
    project_root: Optional[str] = None,
    allow_docker: bool = False,
) -> VerifyResult:
    """
    对单条 finding 做验证（默认 simulated 特征匹配路径）。

    Args:
        finding: Finding 模型
        project_root: 项目根目录（用于读取源码做特征匹配）
        allow_docker: 是否允许 Docker 靶场验证（需 --verify 显式开启，S4）

    Returns:
        VerifyResult（诚实标注验证方式）
    """
    rule_id = getattr(finding, "rule_id", "") or ""
    file_path = getattr(finding, "file_path", "") or ""

    # ── Docker 路径（可选）：仅当显式允许且 Docker 可用 ──
    if allow_docker and docker_available():
        result = _verify_with_docker(finding)
        if result is not None:
            return result
        # docker 路径失败 → 降级 simulated（绝不伪造成 verified_local）

    # ── 默认：特征匹配模拟验证（零网络） ──
    source = _read_source(file_path, project_root)
    if source is None:
        return VerifyResult(
            status=VerifyStatus.MANUAL_REQUIRED,
            method="fallback",
            evidence=f"源码不可读: {file_path}",
            detail="无法读取源文件做特征匹配，请人工确认。",
        )

    matched, evidence = _signature_match(rule_id, source)
    if matched:
        return VerifyResult(
            status=VerifyStatus.SIMULATED,
            method="signature-match",
            evidence=evidence,
            detail="模拟验证（特征匹配）：PoC payload 特征可映射到该 sink，未发起任何网络请求。",
        )
    return VerifyResult(
        status=VerifyStatus.MANUAL_REQUIRED,
        method="signature-match",
        evidence=evidence,
        detail="特征匹配未命中，建议人工复核该漏洞是否可达。",
    )


def _verify_with_docker(finding: Any) -> Optional[VerifyResult]:
    """
    Docker 靶场验证（可选路径，S4 模式 C）。

    约束：
    - 仅当调用方显式 allow_docker=True 且 docker 二进制存在时才会进入
    - 容器端口只绑定 127.0.0.1
    - 本实现不自动拉取镜像；环境无镜像时返回 None → 降级 simulated
    """
    try:
        import subprocess  # 仅调用 docker 只读/生命周期命令（T9 白名单审查）

        # 检查 docker daemon 是否真正可用（而非仅二进制存在）
        proc = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, timeout=10,
        )
        if proc.returncode != 0:
            return None
        return None  # 未配置具体靶场镜像时降级 simulated（诚实标注）
    except (OSError, subprocess.SubprocessError):
        return None


def verify_many(
    findings: list,
    project_root: Optional[str] = None,
    allow_docker: bool = False,
) -> "list":
    """批量验证，返回与 findings 等长的 VerifyResult 列表"""
    return [verify(f, project_root=project_root, allow_docker=allow_docker) for f in findings]
