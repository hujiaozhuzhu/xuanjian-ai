"""API 端点发现模块。

从 HAR / Burp Suite / Nuclei / JS / 文本等多种来源提取 API 端点，
输出统一 :class:`ApiEndpoint` 列表。所有方法均为纯函数 / 纯类方法，
不产生外发网络请求。
"""

from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from .endpoints_models import ApiEndpoint

logger = logging.getLogger(__name__)

__all__ = ["ApiDiscovery"]


class ApiDiscovery:
    """多源 API 端点发现器。

    支持来源：

    - HAR (HTTP Archive)
    - Burp Suite 导出 (XML/JSON items)
    - Nuclei 扫描结果 JSON
    - JS 文件正则提取
    - 通用文本正则提取
    """

    # JS 中提取 API 路径的正则模式集合
    _JS_PATTERNS: List[Tuple[str, str]] = [
        # axios / fetch / url: / baseURL 等
        (r"""(?:axios|fetch)\s*\(\s*['"`]([^'"`]+)['"`]""", "axios/fetch"),
        (r"""url\s*:\s*['"`]([^'"`]+)['"`]""", "url-field"),
        (r"""baseURL\s*[:=]\s*['"`]([^'"`]+)['"`]""", "baseURL"),
        (r"""endpoint\s*[:=]\s*['"`]([^'"`]+)['"`]""", "endpoint-field"),
        (r"""api[_-]?url\s*[:=]\s*['"`]([^'"`]+)['"`]""", "api-url"),
        # 字符串拼接形式的 API 路径
        (
            r"""['"`]((?:/api|/v\d+)[/a-zA-Z0-9_{}.-]*)['"`]""",
            "api-path",
        ),
        (
            r"""(?:"|')(/[a-zA-Z][a-zA-Z0-9_-]*(?:/[a-zA-Z0-9_{}.-]+)+)(?:"|')""",
            "relative-path",
        ),
    ]

    # 通用绝对 URL 正则
    _ABSOLUTE_URL_RE = re.compile(r"""https?://[^\s'"<>]+""", re.IGNORECASE)

    # 相对路径正则（以 / 开头，至少两级）
    _RELATIVE_PATH_RE = re.compile(
        r"""(?<![a-zA-Z0-9_/])(/[a-zA-Z][a-zA-Z0-9_-]*(?:/[a-zA-Z0-9_{}.-]+)+)""",
    )

    def __init__(self) -> None:
        """初始化发现器。"""
        self._seen_urls: Set[str] = set()

    # ────────────────────────── 统一去重合并 ──────────────────────────

    def _dedup_add(self, endpoints: List[ApiEndpoint]) -> List[ApiEndpoint]:
        """按 ``method + url`` 去重后追加到收集器。

        Args:
            endpoints: 新提取的端点列表。

        Returns:
            List[ApiEndpoint]: 去重后的新增列表。
        """
        fresh: List[ApiEndpoint] = []
        for ep in endpoints:
            key = f"{ep.method.upper()}|{ep.url}"
            if key and key not in self._seen_urls:
                self._seen_urls.add(key)
                fresh.append(ep)
        if endpoints and not fresh:
            logger.debug("本批 %d 个端点全部为重复，已忽略。", len(endpoints))
        return fresh

    # ────────────────────────── HAR 解析 ──────────────────────────

    @classmethod
    def from_har(cls, har_path: str | Path) -> List[ApiEndpoint]:
        """从 HAR 文件提取所有请求 URL、method、MIME、status、响应大小。

        使用 ``method|url`` 去重合并；重复的请求只保留首次出现者。

        Args:
            har_path: HAR 文件路径。

        Returns:
            List[ApiEndpoint]: 提取并去重后的端点列表。

        Raises:
            FileNotFoundError: 文件不存在。
            json.JSONDecodeError: JSON 格式错误。
            KeyError: 缺少必要的 ``log.entries`` 键。
        """
        har_path = Path(har_path)
        if not har_path.is_file():
            raise FileNotFoundError(f"HAR 文件不存在: {har_path}")
        with har_path.open("r", encoding="utf-8", errors="replace") as fh:
            data: Dict[str, Any] = json.load(fh)
        entries = data.get("log", {}).get("entries", [])
        if not isinstance(entries, list):
            raise KeyError("HAR 文件缺少 log.entries 列表")
        discovery = cls()
        batch: List[ApiEndpoint] = []
        for entry in entries:
            req = entry.get("request", {})
            res = entry.get("response", {})
            method = str(req.get("method", "GET")).upper()
            url = str(req.get("url", ""))
            status = res.get("status")
            mime = ""
            resp_size = 0
            content = res.get("content", {})
            if isinstance(content, dict):
                mime = str(content.get("mimeType", "") or "")
                try:
                    resp_size = int(content.get("size", 0) or 0)
                except (TypeError, ValueError):
                    resp_size = 0
            if not url:
                continue
            parsed = urlparse(url)
            batch.append(
                ApiEndpoint(
                    method=method,
                    url=url,
                    path=parsed.path,
                    host=parsed.hostname or "",
                    port=parsed.port or (443 if parsed.scheme == "https" else 80),
                    protocol=parsed.scheme or "https",
                    status_code=int(status) if status is not None else None,
                    content_type=mime,
                    response_size=resp_size,
                    source="har",
                )
            )
        endpoints = discovery._dedup_add(batch)
        logger.info("HAR 解析完成: %s 共 %d 个唯一端点", har_path.name, len(endpoints))
        return endpoints

    # ────────────────────────── Burp 解析 ──────────────────────────

    @classmethod
    def from_burp(cls, file_or_path: str | Path) -> List[ApiEndpoint]:
        """从 Burp Suite 导出文件提取 items。

        兼容两种常见格式：

        - XML ``<items><item>...</item></items>``
        - JSON ``{"items": [...]}``

        每个 item 中提取 url/host/port/protocol/method/status/responselength/path。

        Args:
            file_or_path: Burp 导出文件路径（XML 或 JSON）。

        Returns:
            List[ApiEndpoint]: 提取并去重后的端点列表。

        Raises:
            FileNotFoundError: 文件不存在。
            ValueError: 文件格式无法解析。
        """
        file_or_path = Path(file_or_path)
        if not file_or_path.is_file():
            raise FileNotFoundError(f"Burp 导出文件不存在: {file_or_path}")
        raw = file_or_path.read_text(encoding="utf-8", errors="replace").strip()
        if raw.startswith("<"):
            return cls._parse_burp_xml(raw, file_or_path.name)
        if raw.startswith("{") or raw.startswith("["):
            return cls._parse_burp_json(raw, file_or_path.name)
        raise ValueError(f"Burp 文件格式无法识别（非 XML/JSON）: {file_or_path}")

    @classmethod
    def _parse_burp_xml(cls, raw: str, filename: str) -> List[ApiEndpoint]:
        """解析 Burp XML 格式内容。

        Args:
            raw: XML 文本。
            filename: 原始文件名（仅用于日志）。

        Returns:
            List[ApiEndpoint]: 提取到的端点列表。
        """
        discovery = cls()
        batch: List[ApiEndpoint] = []
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            logger.error("Burp XML 解析失败: %s", exc)
            return []
        items = root.findall(".//item") or root.findall(".//items/item")
        if not items:
            items = root.findall(".//items/item")
        for item in items:
            url_elem = item.find("url")
            host_elem = item.find("host")
            port_elem = item.find("port")
            protocol_elem = item.find("protocol")
            method_elem = item.find("method")
            status_elem = item.find("status")
            resp_len_elem = item.find("responselength")
            path_elem = item.find("path")

            url = cls._elem_text(url_elem)
            if not url:
                continue
            try:
                port = int(cls._elem_text(port_elem, "443"))
            except ValueError:
                port = 443
            try:
                status = int(cls._elem_text(status_elem, ""))
            except ValueError:
                status = None
            try:
                resp_len = int(cls._elem_text(resp_len_elem, "0"))
            except ValueError:
                resp_len = 0
            parsed = urlparse(url)
            batch.append(
                ApiEndpoint(
                    method=cls._elem_text(method_elem, "GET").upper() or "GET",
                    url=url,
                    path=cls._elem_text(path_elem) or parsed.path,
                    host=cls._elem_text(host_elem) or parsed.hostname or "",
                    port=port,
                    protocol=cls._elem_text(protocol_elem) or parsed.scheme or "https",
                    status_code=status,
                    response_size=resp_len,
                    source="burp",
                )
            )
        result = discovery._dedup_add(batch)
        logger.info("Burp XML 解析完成: %s 共 %d 个唯一端点", filename, len(result))
        return result

    @classmethod
    def _parse_burp_json(cls, raw: str, filename: str) -> List[ApiEndpoint]:
        """解析 Burp JSON 格式内容。

        Args:
            raw: JSON 文本。
            filename: 原始文件名（仅用于日志）。

        Returns:
            List[ApiEndpoint]: 提取到的端点列表。
        """
        discovery = cls()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.error("Burp JSON 解析失败: %s", exc)
            return []
        items = data if isinstance(data, list) else data.get("items", [])
        batch: List[ApiEndpoint] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url", ""))
            if not url:
                continue
            try:
                port = int(item.get("port", 443) or 443)
            except (TypeError, ValueError):
                port = 443
            try:
                status = int(item.get("status", 0) or 0) or None
            except (TypeError, ValueError):
                status = None
            try:
                resp_len = int(item.get("responselength", 0) or 0)
            except (TypeError, ValueError):
                resp_len = 0
            parsed = urlparse(url)
            batch.append(
                ApiEndpoint(
                    method=str(item.get("method", "GET")).upper() or "GET",
                    url=url,
                    path=str(item.get("path", "") or parsed.path),
                    host=str(item.get("host", "") or parsed.hostname or ""),
                    port=port,
                    protocol=str(item.get("protocol", "") or parsed.scheme or "https"),
                    status_code=status,
                    response_size=resp_len,
                    source="burp",
                )
            )
        result = discovery._dedup_add(batch)
        logger.info("Burp JSON 解析完成: %s 共 %d 个唯一端点", filename, len(result))
        return result

    @staticmethod
    def _elem_text(elem: Optional[Any], default: str = "") -> str:
        """安全读取 XML 元素的 text 内容。

        Args:
            elem: XML 元素（可能为 None）。
            default: 默认值。

        Returns:
            str: 元素文本或默认值。
        """
        if elem is None:
            return default
        return str(elem.text or default)

    # ────────────────────────── Nuclei 解析 ───────────────────────

    @classmethod
    def from_nuclei_json(cls, path: str | Path) -> List[ApiEndpoint]:
        """从 Nuclei 结果 JSON 提取 matched-at / template-id / type / severity。

        Args:
            path: Nuclei 结果 JSON 文件路径。每条记录形如::

                {
                  "template-id": "...",
                  "matched-at": "https://...",
                  "type": "http",
                  "severity": "high",
                  ...
                }

        Returns:
            List[ApiEndpoint]: 提取并去重后的端点列表。

        Raises:
            FileNotFoundError: 文件不存在。
        """
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(f"Nuclei 结果文件不存在: {path}")
        discovery = cls()
        batch: List[ApiEndpoint] = []
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                matched = str(record.get("matched-at", "") or "")
                if not matched:
                    continue
                template = str(record.get("template-id", "") or "")
                severity = str(record.get("severity", "") or "").lower()
                rtype = str(record.get("type", "") or "").lower()
                parsed = urlparse(matched)
                batch.append(
                    ApiEndpoint(
                        method="GET",
                        url=matched,
                        path=parsed.path,
                        host=parsed.hostname or "",
                        port=parsed.port or (443 if parsed.scheme == "https" else 80),
                        protocol=parsed.scheme or "https",
                        source="nuclei",
                        matched_template=template,
                        severity_hint=severity,
                        content_type=rtype,
                    )
                )
        result = discovery._dedup_add(batch)
        logger.info("Nuclei JSON 解析完成: %s 共 %d 个唯一端点", path.name, len(result))
        return result

    # ────────────────────────── JS 提取 ────────────────────────────

    @classmethod
    def from_js(cls, paths: List[str | Path]) -> List[ApiEndpoint]:
        """从 JS 文件中通过正则提取 API 端点模式。

        提取模式包括 ``/api/``、``"/"``、``'/'``、``url:``、
        ``axios.``、``fetch(``、``baseURL`` 等。候选路径及所在文件位置一并记录。

        Args:
            paths: JS 文件路径列表。

        Returns:
            List[ApiEndpoint]: 去重后的候选端点列表（URL 相对路径拼接占位 host）。
        """
        discovery: cls = cls()
        batch: List[ApiEndpoint] = []
        for js_path in paths:
            js_path = Path(js_path)
            if not js_path.is_file():
                logger.warning("JS 文件不存在，已跳过: %s", js_path)
                continue
            try:
                text = js_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                logger.warning("JS 文件读取失败，已跳过: %s (%s)", js_path, exc)
                continue
            for pattern, label in cls._JS_PATTERNS:
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    candidate = match.group(1).strip()
                    if not candidate or len(candidate) < 2:
                        continue
                    parsed = urlparse(candidate)
                    batch.append(
                        ApiEndpoint(
                            method="GET",
                            url=candidate,
                            path=parsed.path or candidate,
                            host=parsed.hostname or "",
                            port=parsed.port or 443,
                            protocol=parsed.scheme or (
                                "https" if parsed.scheme != "http" else "http"
                            ),
                            source=f"js:{label}",
                        )
                    )
        result = discovery._dedup_add(batch)
        logger.info("JS 端点提取完成: %d 个文件，共 %d 个唯一候选", len(paths), len(result))
        return result

    # ────────────────────────── 文本提取 ──────────────────────────

    @classmethod
    def from_text(cls, text: str) -> List[ApiEndpoint]:
        """从通用文本中正则提取所有 ``https?://...`` 与以 ``/`` 开头的相对路径。

        Args:
            text: 任意文本内容。

        Returns:
            List[ApiEndpoint]: 去重后的端点候选列表。
        """
        discovery = cls()
        batch: List[ApiEndpoint] = []
        for match in cls._ABSOLUTE_URL_RE.finditer(text):
            url = match.group(0).rstrip("'\")")
            parsed = urlparse(url)
            batch.append(
                ApiEndpoint(
                    method="GET",
                    url=url,
                    path=parsed.path,
                    host=parsed.hostname or "",
                    port=parsed.port or (443 if parsed.scheme == "https" else 80),
                    protocol=parsed.scheme or "https",
                    source="text",
                )
            )
        for match in cls._RELATIVE_PATH_RE.finditer(text):
            candidate = match.group(1).rstrip("'\")")
            if candidate in {"/", "/api"} or len(candidate) < 4:
                continue
            parsed = urlparse(candidate)
            batch.append(
                ApiEndpoint(
                    method="GET",
                    url=candidate,
                    path=parsed.path or candidate,
                    host="",
                    port=443,
                    protocol="https",
                    source="text",
                )
            )
        result = discovery._dedup_add(batch)
        logger.info("文本端点提取完成: 共 %d 个唯一端点", len(result))
        return result
