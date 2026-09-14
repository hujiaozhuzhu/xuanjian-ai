"""AndroidManifest.xml 解析器（基于 androguard）。

提取：包名 / 版本 / 权限 / 四大组件 / 导出组件 / Intent Filter。
安全约束：只读解析，不修改原始 APK。
"""

from __future__ import annotations

import os
import zipfile
from typing import Dict, List, Optional

from ..models.decompile_result import ComponentInfo, ManifestInfo

try:  # androguard 为 P0 依赖
    from androguard.core.apk import APK  # type: ignore

    HAS_ANDROGUARD = True
except Exception:  # pragma: no cover
    APK = None  # type: ignore[assignment]
    HAS_ANDROGUARD = False

_IMPORT_HINT = (
    "androguard 未安装。请执行: pip install androguard "
    "(玄鉴 v4.0 反编译引擎的 P0 依赖)"
)

_COMPONENT_GETTERS = {
    "activity": "get_activities",
    "service": "get_services",
    "receiver": "get_receivers",
    "provider": "get_providers",
}


class ManifestParser:
    """AndroidManifest 解析器。

    仅支持 APK（zip 容器，内含二进制 AndroidManifest.xml）。
    """

    def __init__(self, apk_path: str) -> None:
        if not HAS_ANDROGUARD:
            raise ImportError(_IMPORT_HINT)
        self.apk_path = str(apk_path)
        if not os.path.exists(self.apk_path):
            raise FileNotFoundError(f"APK 不存在: {self.apk_path}")
        if not zipfile.is_zipfile(self.apk_path):
            raise ValueError(f"不是有效的 APK(zip) 文件: {self.apk_path}")
        self._apk: Optional[APK] = None

    @property
    def apk(self) -> APK:
        if self._apk is None:
            self._apk = APK(self.apk_path)
        return self._apk

    # ------------------------------------------------------------ attributes
    @staticmethod
    def _parse_bool(value: object) -> Optional[bool]:
        """AXML 布尔属性归一: 'true'/'1' → True, 'false'/'0' → False。"""
        if value is None:
            return None
        text = str(value).strip().lower()
        if text in ("true", "1"):
            return True
        if text in ("false", "0"):
            return False
        return None

    def get_application_attribute(self, attribute: str):
        """读取 application 节点属性（未声明返回 None; NEW-05）。"""
        try:
            return self.apk.get_attribute_value("application", attribute,
                                                format_value=False)
        except Exception:
            return None

    def application_flags(self) -> Dict[str, object]:
        """提取 android:debuggable / allowBackup / networkSecurityConfig 等。"""
        netsec = self.get_application_attribute("networkSecurityConfig")
        return {
            "debuggable": self._parse_bool(
                self.get_application_attribute("debuggable")) or False,
            "allow_backup": self._parse_bool(
                self.get_application_attribute("allowBackup")),
            "network_security_config": str(netsec) if netsec else "",
            "uses_cleartext_traffic": self._parse_bool(
                self.get_application_attribute("usesCleartextTraffic")),
        }

    def parse(self) -> ManifestInfo:
        """解析 Manifest 并返回结构化信息。"""
        a = self.apk
        info = ManifestInfo(
            package_name=a.get_package() or "",
            version_name=str(a.get_androidversion_name() or ""),
            version_code=str(a.get_androidversion_code() or ""),
            min_sdk=str(a.get_min_sdk_version() or ""),
            target_sdk=str(a.get_target_sdk_version() or ""),
            app_name=a.get_app_name() or "",
            permissions=sorted(a.get_permissions()),
        )
        # NEW-05: application 节点安全属性
        flags = self.application_flags()
        info.debuggable = bool(flags["debuggable"])
        info.allow_backup = flags["allow_backup"]
        info.network_security_config = str(flags["network_security_config"] or "")
        info.uses_cleartext_traffic = flags["uses_cleartext_traffic"]
        for comp_type, getter in _COMPONENT_GETTERS.items():
            for name in getattr(a, getter)():
                info.components.append(
                    self._component_info(a, comp_type, name)
                )
        return info

    def _component_info(self, a: APK, comp_type: str, name: str) -> ComponentInfo:
        filters = self.get_intent_filters(comp_type, name)
        exported = self.is_exported(a, comp_type, name, bool(filters))
        return ComponentInfo(
            type=comp_type,
            name=name,
            exported=exported,
            intent_filters=filters,
        )

    def get_intent_filters(self, comp_type: str, name: str) -> Dict[str, List[str]]:
        """提取组件的 Intent Filter（action/category 归一为 list）。"""
        try:
            raw = self.apk.get_intent_filters(comp_type, name)
        except Exception:
            raw = {}
        filters: Dict[str, List[str]] = {}
        if isinstance(raw, dict):
            for key, value in raw.items():
                if isinstance(value, (list, tuple, set)):
                    filters[str(key)] = sorted(str(v) for v in value)
                else:
                    filters[str(key)] = [str(value)]
        return filters

    @staticmethod
    def is_exported(
        a: APK, comp_type: str, name: str, has_filters: bool
    ) -> bool:
        """判定组件是否导出。

        显式 android:exported 优先（androguard 4.x 用 get_all_attribute_value
        按 name 过滤定位到具体组件节点）；未声明时，含 intent-filter 的组件
        在旧 targetSdk(<17) 下默认导出（保守按可导出处理）。
        """
        val = None
        try:
            for item in a.get_all_attribute_value(
                    comp_type, "exported", format_value=False, **{"name": name}):
                val = item
                break
        except Exception:
            val = None
        if val is not None:
            text = str(val).strip().lower()
            if text in ("true", "1"):
                return True
            if text in ("false", "0"):
                return False
        return has_filters

    def exported_components(self) -> List[ComponentInfo]:
        return [c for c in self.parse().components if c.exported]
