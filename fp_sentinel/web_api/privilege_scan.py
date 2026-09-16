"""越权 / 访问控制探测模块（只读基线）。

重要说明：这是只读探测，只做对比、不提交任何修改。
业务范围由输入决定；操作者在运行前必须自行持有合法测试授权。
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .endpoints_models import ApiEndpoint, FindingReport, Evidence

logger = logging.getLogger(__name__)

__all__ = ["PrivilegeScanner", "PrivilegeFinding"]

# 尝试导入 requests，标注为可选依赖
try:
    import requests as _requests  # type: ignore[import-unavailable]

    _HAS_REQUESTS = True
except ImportError:  # pragma: no cover - 环境无 requests 时仍可加载模块
    _HAS_REQUESTS = False
    _requests = None  # type: ignore[assignment]


@dataclass
class PrivilegeFinding:
    """单次越权探测结果。"""

    method: str
    url: str
    finding_type: str  # "horizontal" / "vertical"
    verdict: str  # "exposed" / "controlled" / "inconclusive"
    status_a: Optional[int] = None
    status_b: Optional[int] = None
    body_hash_a: str = ""
    body_hash_b: str = ""
    length_a: int = 0
    length_b: int = 0
    cwe_id: str = ""
    confidence: float = 0.5
    notes: List[str] = field(default_factory=list)

    def to_finding_report(self) -> FindingReport:
        """转换为标准 :class:`FindingReport`。

        水平越权使用 CWE-639，垂直越权使用 CWE-285。

        Returns:
            FindingReport: 标准化漏洞发现记录。
        """
        if self.finding_type == "horizontal":
            title = f"疑似水平越权: {self.method} {self.url}"
            description = (
                f"账号 B 使用账号 A 的请求上下文访问 ``{self.method} {self.url}``，"
                f"响应状态 {self.status_b}（账号 A 原为 {self.status_a}），"
                f"响应长度差 {abs(self.length_b - self.length_a)} 字节，"
                f"疑似未校验资源归属（CWE-639）。"
            )
        else:
            title = f"疑似垂直越权: {self.method} {self.url}"
            description = (
                f"低权限账号请求高权限路径 ``{self.method} {self.url}``，"
                f"响应状态 {self.status_b}，疑似存在垂直越权风险（CWE-285）。"
            )
        return FindingReport(
            id=f"PRIV-{hash(self.url + self.finding_type) & 0xFFFFFF:06X}",
            title=title,
            severity="HIGH" if self.verdict == "exposed" else "MEDIUM",
            cwe_id=self.cwe_id,
            owasp_masvs="" if self.finding_type == "horizontal" else "MASVS-AUTH-2",
            category="access-control",
            description=description,
            evidence=[
                Evidence(
                    id="priv-evidence",
                    location=self.url,
                    content=(
                        f"status_a={self.status_a}\n"
                        f"status_b={self.status_b}\n"
                        f"body_hash_a={self.body_hash_a}\n"
                        f"body_hash_b={self.body_hash_b}\n"
                        f"length_a={self.length_a}\n"
                        f"length_b={self.length_b}"
                    ),
                    description=f"越权探测对比基线（{self.finding_type}）",
                    source="动态",
                )
            ],
            remediation="在后端校验资源归属（水平）或引入角色/权限门控（垂直）。",
            references=[
                "https://cwe.mitre.org/data/definitions/639.html",
                "https://cwe.mitre.org/data/definitions/285.html",
            ],
            tool_version="fp_sentinel-web-api",
            confidence=self.confidence,
        )


def _body_hash(content: bytes) -> str:
    """对响应体计算 SHA-256 摘要。

    Args:
        content: 响应体字节。

    Returns:
        str: 十六进制摘要。
    """
    return hashlib.sha256(content).hexdigest()


def _length_diff_exceeds(a: int, b: int, threshold_ratio: float = 0.1, min_diff: int = 50) -> bool:
    """判断两个响应长度差异是否超过阈值。

    使用相对变化率 ``|a-b| / max(a,b)`` 与绝对差值双重门控，
    避免小响应时误报。

    Args:
        a: 第一响应长度。
        b: 第二响应长度。
        threshold_ratio: 相对差异比例阈值。
        min_diff: 绝对差异字节阈值。

    Returns:
        bool: 是否超过阈值。
    """
    if a == 0 and b == 0:
        return False
    if a == 0 or b == 0:
        return True
    abs_diff = abs(a - b)
    ratio = abs_diff / max(a, b)
    return abs_diff > min_diff and ratio > threshold_ratio


class PrivilegeScanner:
    """越权 / 访问控制只读探测。

    输入 ``base_url`` + 至少两个测试账号（由调用方提供凭证），
    ``never_attempt_bruteforce=True``（硬编码禁止爆破）。
    仅发送 GET/HEAD（不产生写操作），支持 ``rate_limit`` 参数（默认 2 req/s）。

    Args:
        base_url: 目标基础 URL。
        test_cookies: 测试用 cookie 字典，格式 ``{name: cookie_string}``。
        admin_cookie: 管理员 cookie（可选）。
        low_cookie: 低权限 cookie（可选）。
        rate_limit: 每秒最大请求数（默认 2）。
        audit_log_path: 审计日志输出路径（默认当前工作目录下的 ``.audit.log``）。
        http_client: 可选 HTTP 客户端（不传则使用 requests；测试时 mock 注入）。
    """

    # 硬编码禁止爆破
    NEVER_ATTEMPT_BRUTEFORCE: bool = True

    def __init__(
        self,
        base_url: str,
        test_cookies: Dict[str, str],
        admin_cookie: Optional[str] = None,
        low_cookie: Optional[str] = None,
        rate_limit: float = 2.0,
        audit_log_path: Optional[str | Path] = None,
        http_client: Any = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        if len(test_cookies) < 2 and not (admin_cookie and low_cookie):
            raise ValueError("必须提供至少两个测试账号凭证或 admin_cookie + low_cookie")
        self.test_cookies = test_cookies
        self.admin_cookie = admin_cookie
        self.low_cookie = low_cookie
        self.rate_limit = max(0.1, rate_limit)
        self._http = http_client or (_requests if _HAS_REQUESTS else None)
        self._audit_path = Path(audit_log_path or ".audit.log")
        self._findings: List[PrivilegeFinding] = []
        self._request_count: int = 0
        logger.info(
            "PrivilegeScanner 初始化: base_url=%s, 账号数=%d, rate=%.1f req/s, 审计日志=%s",
            self.base_url,
            len(test_cookies) + int(bool(admin_cookie)),
            self.rate_limit,
            self._audit_path,
        )

    # ────────────────────────── 审计日志 ──────────────────────────

    def _audit(self, method: str, path: str, status: Optional[int], verdict: str) -> None:
        """向审计日志追加一行。

        记录方法、路径、状态码差异、判定结果；不保存响应体全文。

        Args:
            method: HTTP 方法。
            path: 请求路径。
            status: 响应状态码。
            verdict: 判定结论。
        """
        line = (
            f"[web-api-priv] method={method} path={path} "
            f"status={status} verdict={verdict} count={self._request_count}\n"
        )
        try:
            with self._audit_path.open("a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError as exc:
            logger.warning("审计日志写入失败: %s", exc)

    # ────────────────────────── 限速发送 ──────────────────────────

    def _request(
        self,
        method: str,
        url: str,
        cookie: Optional[str] = None,
        timeout: float = 10.0,
    ) -> Tuple[Optional[int], bytes, Dict[str, str]]:
        """发送受限 HTTP 请求。

        仅发送 GET/HEAD；遵守 rate_limit；外部未注入 http_client 时
        使用 requests。

        Args:
            method: HTTP 方法（仅 GET/HEAD）。
            url: 完整请求 URL。
            cookie: Cookie 头部值。
            timeout: 超时秒数。

        Returns:
            tuple: (status_code, body_bytes, headers)；失败时返回 (None, b"", {})。
        """
        m = method.upper()
        if m not in {"GET", "HEAD"}:
            logger.error("越权探测器仅允许 GET/HEAD，已拒绝: %s", m)
            raise ValueError(f"越权探测器不允许的 HTTP 方法: {m}")
        if self._request_count > 0:
            interval = 1.0 / self.rate_limit
            time.sleep(interval)
        self._request_count += 1
        headers: Dict[str, str] = {"User-Agent": "fp_sentinel-web-api/1.0"}
        if cookie:
            headers["Cookie"] = cookie  # noqa: S105 - 测试账号 cookie
        if self._http is None:
            logger.warning("无可用 HTTP 客户端，返回空响应")
            return (None, b"", {})
        try:
            resp = self._http.request(
                method=m,
                url=url,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
            )
            return (resp.status_code, getattr(resp, "content", b""), dict(resp.headers))
        except Exception as exc:  # noqa: BLE001 - 全部捕获以不中断批处理
            logger.warning("HTTP 请求失败: %s %s -> %s", m, url, exc)
            return (None, b"", {})

    # ────────────────────────── 水平越权 ──────────────────────────

    def test_horizontal(
        self,
        base_endpoints: List[ApiEndpoint],
        cookie_a: str,
        cookie_b: str,
    ) -> List[PrivilegeFinding]:
        """水平越权探测。

        把账号 B 的 cookie 替换到账号 A 的请求（反之亦然），
        对比两次响应 body_hash/状态码/长度；差异超过阈值标记为
        可能的水平越权；完全相同或都被 401 则标记为受控。

        Args:
            base_endpoints: 基线端点列表。
            cookie_a: 账号 A 的 cookie。
            cookie_b: 账号 B 的 cookie。

        Returns:
            List[PrivilegeFinding]: 探测结果列表。
        """
        findings: List[PrivilegeFinding] = []
        for ep in base_endpoints:
            url = ep.url if ep.url.startswith("http") else f"{self.base_url}{ep.path}"
            if not url:
                continue
            status_a, body_a, _ = self._request(ep.method, url, cookie_a)
            status_b, body_b, _ = self._request(ep.method, url, cookie_b)
            hash_a, hash_b = _body_hash(body_a), _body_hash(body_b)
            len_a, len_b = len(body_a), len(body_b)
            verdict = self._judge_horizontal(status_a, status_b, hash_a, hash_b, len_a, len_b)
            self._audit(ep.method, ep.path or url, status_b, verdict)
            finding = PrivilegeFinding(
                method=ep.method,
                url=url,
                finding_type="horizontal",
                verdict=verdict,
                status_a=status_a,
                status_b=status_b,
                body_hash_a=hash_a,
                body_hash_b=hash_b,
                length_a=len_a,
                length_b=len_b,
                cwe_id="CWE-639",
                confidence=0.75 if verdict == "exposed" else 0.3,
                notes=[
                    f"A status={status_a}, B status={status_b}",
                    f"length diff: {abs(len_b - len_a)}",
                ],
            )
            findings.append(finding)
            logger.debug("水平越权 %s -> %s", url, verdict)
        self._findings.extend(findings)
        return findings

    # ────────────────────────── 垂直越权 ──────────────────────────

    def test_vertical(
        self,
        admin_cookie: str,
        low_cookie: str,
        admin_only_paths: List[ApiEndpoint],
    ) -> List[PrivilegeFinding]:
        """垂直越权探测。

        低权限账号请求高权限路径，对比状态与响应；
        200 且返回数据说明垂直越权风险。

        Args:
            admin_cookie: 管理员 cookie。
            low_cookie: 低权限账号 cookie。
            admin_only_paths: 已知为高权限的路径列表。

        Returns:
            List[PrivilegeFinding]: 探测结果列表。
        """
        findings: List[PrivilegeFinding] = []
        for ep in admin_only_paths:
            url = ep.url if ep.url.startswith("http") else f"{self.base_url}{ep.path}"
            if not url:
                continue
            status_admin, body_admin, _ = self._request(ep.method, url, admin_cookie)
            status_low, body_low, _ = self._request(ep.method, url, low_cookie)
            hash_admin = _body_hash(body_admin)
            hash_low = _body_hash(body_low)
            len_admin = len(body_admin)
            len_low = len(body_low)
            verdict = self._judge_vertical(status_admin, status_low, len_low)
            self._audit(ep.method, ep.path or url, status_low, verdict)
            finding = PrivilegeFinding(
                method=ep.method,
                url=url,
                finding_type="vertical",
                verdict=verdict,
                status_a=status_admin,
                status_b=status_low,
                body_hash_a=hash_admin,
                body_hash_b=hash_low,
                length_a=len_admin,
                length_b=len_low,
                cwe_id="CWE-285",
                confidence=0.7 if verdict == "exposed" else 0.25,
                notes=[
                    f"admin status={status_admin}, low status={status_low}",
                    f"low response length={len_low}",
                ],
            )
            findings.append(finding)
            logger.debug("垂直越权 %s -> %s", url, verdict)
        self._findings.extend(findings)
        return findings

    # ────────────────────────── 判定逻辑 ──────────────────────────

    @staticmethod
    def _judge_horizontal(
        status_a: Optional[int],
        status_b: Optional[int],
        hash_a: str,
        hash_b: str,
        len_a: int,
        len_b: int,
    ) -> str:
        """水平越权判定逻辑。

        - 均被 401/403/404 -> ``"controlled"``
        - body_hash 不同且长度差异超阈值 -> ``"exposed"``
        - 完全相同 -> ``"controlled"``
        - 其他 -> ``"inconclusive"``

        Args:
            status_a: 账号 A 状态码。
            status_b: 账号 B 状态码。
            hash_a: 账号 A 响应体 hash。
            hash_b: 账号 B 响应体 hash。
            len_a: A 响应长度。
            len_b: B 响应长度。

        Returns:
            str: 判定结论。
        """
        if status_a in {401, 403, 404} and status_b in {401, 403, 404}:
            return "controlled"
        if status_a is None or status_b is None:
            return "inconclusive"
        if hash_a and hash_b and hash_a != hash_b and _length_diff_exceeds(len_a, len_b):
            if status_b == 200:
                return "exposed"
            return "inconclusive"
        if hash_a and hash_b and hash_a == hash_b and status_a == status_b:
            return "controlled"
        return "inconclusive"

    @staticmethod
    def _judge_vertical(
        status_admin: Optional[int],
        status_low: Optional[int],
        len_low: int,
    ) -> str:
        """垂直越权判定逻辑。

        - 低权限收到 200 且响应体有长度 -> ``"exposed"``
        - 低权限收到 401/403 -> ``"controlled"``
        - 其他 -> ``"inconclusive"``

        Args:
            status_admin: 管理员状态码。
            status_low: 低权限状态码。
            len_low: 低权限响应体长度。

        Returns:
            str: 判定结论。
        """
        if status_low is None:
            return "inconclusive"
        if status_low == 200 and len_low > 0:
            return "exposed"
        if status_low in {401, 403}:
            return "controlled"
        return "inconclusive"

    @property
    def findings(self) -> List[PrivilegeFinding]:
        """获取所有已记录的探测结果（只读视图）。"""
        return list(self._findings)
