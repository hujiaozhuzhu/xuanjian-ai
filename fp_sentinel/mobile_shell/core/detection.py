"""
加固类型自动识别 —— 特征码 / 入口类 / 特征字符串三路匹配

对齐《v4.0.0-mobile-reverse-engineering-plan.md》2.1 能力①：
支持 360 / 腾讯乐固 / 梆梆 / 爱加密 / 娜迦 / 百度 / 阿里聚安全 / 无壳 的识别。

识别策略（三路证据融合）：
1. 文件特征码：APK 内是否存在加固 so / dat 特征文件
2. 入口类：AndroidManifest application android:name 是否为加固 Stub 类
3. 特征字符串：dex / assets / so 中是否含加固 SDK 特征字符串

置信度 = min(1.0, 命中特征数 / 该加固所需最低特征数)，
命中特征越多样置信度越高；单一命中（如仅一个 so）置信度 = 0.5。

androguard 可用时用其解析 Manifest 入口类（要求 9：未安装则优雅降级）。
"""

from __future__ import annotations

import logging
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from fp_sentinel.mobile_shell.models.protection_info import (
    KNOWN_PROTECTIONS,
    PROTECTION_360,
    PROTECTION_ALI,
    PROTECTION_BAIDU,
    PROTECTION_BANGCLE,
    PROTECTION_IJIAMI,
    PROTECTION_NAGA,
    PROTECTION_NONE,
    PROTECTION_TENCENT,
    PROTECTION_UNKNOWN,
    ProtectionInfo,
)

logger = logging.getLogger(__name__)

# ─────────────────────── 加固特征库 ───────────────────────

#: 文件特征码：{加固名: (文件名精确集合, 文件名前缀集合, so 名子串集合)}
FILE_SIGNATURES: Dict[str, Dict[str, Tuple[str, ...]]] = {
    PROTECTION_360: {
        "exact": (),
        "prefix": (),
        "substr": (
            "libjiagu.so", "libjiagu_art.so", "libjiagu_64.so",
            "libjiagu_x86.so", "libjiagu_a64.so", "libjiagu_pro.so",
        ),
    },
    PROTECTION_TENCENT: {
        "exact": (),
        "prefix": ("libshella-", "libshellx-", "libtup.", "libtosprotection", "libmix"),
        "substr": ("libshell.so", "libexec.so", "libtup.so",),
    },
    PROTECTION_BANGCLE: {
        "exact": (),
        "prefix": ("libsecexe", "libsecmain", "libDexHelper", "libSecShell"),
        "substr": ("libdexhelper",),
    },
    PROTECTION_IJIAMI: {
        "exact": ("ijiami.dat", "ijiami.ajm", "assets/ijiami.dat"),
        "prefix": ("libexecmain", "libexec", "ijm_lib/"),
        "substr": (),
    },
    PROTECTION_NAGA: {
        "exact": (),
        "prefix": (),
        "substr": ("libchaosvmp.so", "libddog.so", "libfdog.so", "libnagain.so"),
    },
    PROTECTION_BAIDU: {
        "exact": (),
        "prefix": ("libbaiduprotect",),
        "substr": (),
    },
    PROTECTION_ALI: {
        "exact": (),
        "prefix": ("libmobisec", "libsgmain", "libsgsecuritybody", "libpreverify"),
        "substr": (),
    },
}

#: 入口 Application 类特征：{加固名: (类名, ...)}
PACKER_CLASSES: Dict[str, Tuple[str, ...]] = {
    PROTECTION_360: ("com.stub.StubApp", "com.qihoo.util.StubApplication"),
    PROTECTION_TENCENT: ("com.tencent.StubShell", "com.tencent.tmgp.StubApp"),
    PROTECTION_BANGCLE: ("com.secneo.apkwrapper.ApplicationWrapper", "com.secneo.SApplication"),
    PROTECTION_IJIAMI: ("com.shell.SuperApplication", "com.ijoy.jiaMiFen"),
    PROTECTION_NAGA: ("com.nagain.protectedapp", "com.nblauncher.NBLauncher"),
    PROTECTION_BAIDU: ("com.baidu.protect.Application", "com.baidu.protect.StubApplication"),
    PROTECTION_ALI: ("com.alibaba.wireless.security.x.EdgeApplication", "com.taobao.android.task.SecurityGuardApplication"),
}

#: 特征字符串：{加固名: (字节串, ...)}
STRING_SIGNATURES: Dict[str, Tuple[bytes, ...]] = {
    PROTECTION_360: (
        b"Lcom/stub/StubApp;",
        b"com/qihoo/util",
        b"jiagu",
    ),
    PROTECTION_TENCENT: (
        b"Lcom/tencent/StubShell;",
        b"tencentshell",
        b"legu",
    ),
    PROTECTION_BANGCLE: (
        b"Lcom/secneo/apkwrapper;",
        b"secneo",
        b"bangcle",
    ),
    PROTECTION_IJIAMI: (
        b"Lcom/shell/SuperApplication;",
        b"ijiami",
    ),
    PROTECTION_NAGA: (
        b"nagain",
        b"chaosvmp",
    ),
    PROTECTION_BAIDU: (
        b"libbaiduprotect",
        b"com/baidu/protect",
    ),
    PROTECTION_ALI: (
        b"mobisec",
        b"com/alibaba/wireless/security",
        b"libsgmain",
    ),
}

#: 每类加固的最低命中特征数（用于置信度归一）
MIN_HITS: Dict[str, int] = {name: 3 for name in KNOWN_PROTECTIONS}

#: 扫描字符串特征时单个条目最多读取的字节数（控制内存）
_MAX_SCAN_BYTES = 2 * 1024 * 1024
#: 需要扫描字符串特征的条目后缀
_SCANNABLE_SUFFIXES = (".dex", ".so", ".dat", ".bin", ".jar", ".properties")


class ProtectionDetector:
    """加固类型自动识别器。

    支持三种证据来源：
    - ZIP 条目文件名特征码匹配
    - Manifest 入口 Application 类匹配（androguard 可用时自动解析）
    - dex/so/assets 内容特征字符串匹配

    用法::

        detector = ProtectionDetector()
        info = detector.detect("app.apk")
        print(info.summary())   # protection=360加固 confidence=0.67 packed=True
    """

    name = "protection-detector"

    def __init__(self, use_androguard: bool = True) -> None:
        """初始化检测器。

        Args:
            use_androguard: 是否尝试使用 androguard 解析 Manifest 入口类
        """
        self._androguard_ok = False
        if use_androguard:
            try:
                from androguard.core.apk import APK  # noqa: F401

                self._androguard_ok = True
            except Exception:  # pragma: no cover - 依赖环境相关
                logger.info("androguard 不可用，入口类检测降级为字符串匹配")
        self.use_androguard = use_androguard

    @property
    def androguard_available(self) -> bool:
        """androguard 是否可用。"""
        return self._androguard_ok

    # ── 主入口 ──

    def detect(self, target_path: str) -> ProtectionInfo:
        """识别 APK 的加固类型。

        Args:
            target_path: 本地 APK 路径

        Returns:
            ProtectionInfo: 识别结果；无任何特征命中时返回"无壳"

        Raises:
            FileNotFoundError: 文件不存在
            ValueError: 非 ZIP/APK 结构
        """
        path = Path(target_path)
        if not path.is_file():
            raise FileNotFoundError(f"目标文件不存在: {target_path}")

        candidates: Dict[str, ProtectionInfo] = {}
        try:
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
                # 证据 1：文件特征码
                for prot, hits in self._match_file_signatures(names).items():
                    info = candidates.setdefault(prot, self._new_info(prot))
                    info.merge_hit(hits, [], [], None)
                # 证据 3：特征字符串
                for prot, hits in self._scan_string_signatures(zf, names).items():
                    info = candidates.setdefault(prot, self._new_info(prot))
                    info.merge_hit([], hits, [], None)
        except zipfile.BadZipFile as exc:
            raise ValueError(f"目标不是有效的 APK(ZIP) 结构: {target_path}") from exc

        # 证据 2：入口类
        packer_class = self._extract_application_class(str(path))
        if packer_class:
            matched_prot = self._match_packer_class(packer_class)
            if matched_prot:
                info = candidates.setdefault(matched_prot, self._new_info(matched_prot))
                info.merge_hit([], [], [], packer_class)
            else:
                for info in candidates.values():
                    info.details.setdefault("application", packer_class)

        if not candidates:
            result = ProtectionInfo(
                protection=PROTECTION_NONE,
                confidence=0.85,
                packer_class=packer_class,
                is_packed=False,
                details={"file": path.name, "entry_class": packer_class},
            )
            logger.info("未命中加固特征 → %s", result.summary())
            return result

        # 取命中特征最多的候选
        best_prot = max(candidates, key=lambda k: candidates[k].hit_count)
        best = candidates[best_prot]
        best.confidence = self._compute_confidence(best)
        best.is_packed = True
        best.details["file"] = path.name
        best.details["all_candidates"] = sorted(candidates)
        logger.info("加固识别完成 → %s", best.summary())
        return best

    # ── 证据匹配实现 ──

    def _new_info(self, protection: str) -> ProtectionInfo:
        """为候选加固构建空的 ProtectionInfo。"""
        return ProtectionInfo(protection=protection)

    def _match_file_signatures(
        self, names: List[str]
    ) -> Dict[str, List[str]]:
        """证据 1：按 APK 条目名匹配文件特征码。

        Returns:
            {加固名: 命中的条目名列表}
        """
        lowered = {n.lower(): n for n in names}
        hits: Dict[str, List[str]] = {}
        for prot, sigs in FILE_SIGNATURES.items():
            matched: List[str] = []
            for exact in sigs["exact"]:
                if exact.lower() in lowered:
                    matched.append(lowered[exact.lower()])
            for name in lowered:
                base = name.rsplit("/", 1)[-1]
                if any(base.startswith(p) for p in sigs["prefix"]):
                    matched.append(name)
                elif any(s in base for s in sigs["substr"]):
                    matched.append(name)
            if matched:
                hits[prot] = sorted(set(matched))
        return hits

    def _scan_string_signatures(
        self, zf: zipfile.ZipFile, names: List[str]
    ) -> Dict[str, List[str]]:
        """证据 3：读取 dex/so 等条目内容，搜索特征字符串。

        Returns:
            {加固名: 命中的特征字符串(可读形式)}
        """
        hits: Dict[str, List[str]] = {}
        compiled = {
            prot: [s for s in sigs]
            for prot, sigs in STRING_SIGNATURES.items()
        }
        for name in names:
            if not name.lower().endswith(_SCANNABLE_SUFFIXES):
                continue
            try:
                with zf.open(name) as fh:
                    blob = fh.read(_MAX_SCAN_BYTES)
            except (zipfile.BadZipFile, OSError):
                continue
            for prot, sigs in compiled.items():
                for sig in sigs:
                    if sig in blob:
                        # 可读形式（bytes → latin1 文本）
                        hits.setdefault(prot, []).append(
                            f"{name}:{sig.decode('latin1', 'replace')}"
                        )
        return hits

    def _match_packer_class(self, app_class: str) -> Optional[str]:
        """证据 2：入口类名 → 加固名。"""
        for prot, classes in PACKER_CLASSES.items():
            if any(app_class.startswith(c) or app_class == c for c in classes):
                return prot
        return None

    # ── androguard 集成（可降级） ──

    def _extract_application_class(self, target_path: str) -> Optional[str]:
        """解析 AndroidManifest 的 application android:name。

        androguard 可用时精确解析；否则从 AndroidManifest.xml 二进制中
        提取 UTF-16 字符串池做启发式匹配。
        """
        if self._androguard_ok and self.use_androguard:
            try:
                from androguard.core.apk import APK

                apk = APK(target_path)
                return apk.get_attribute_value("application", "name")
            except Exception as exc:  # pragma: no cover - 依赖具体 APK
                logger.debug("androguard 解析失败，降级: %s", exc)
        return self._extract_application_class_raw(target_path)

    @staticmethod
    def _extract_application_class_raw(target_path: str) -> Optional[str]:
        """降级实现：在二进制 Manifest 的字符串池中查找已知加固入口类。"""
        try:
            with zipfile.ZipFile(target_path) as zf:
                blob = zf.read("AndroidManifest.xml")
        except (KeyError, zipfile.BadZipFile, OSError):
            return None
        text = blob.decode("utf-16-le", errors="ignore")
        for classes in PACKER_CLASSES.values():
            for cls in classes:
                if cls in text:
                    return cls
        return None

    @staticmethod
    def _compute_confidence(info: ProtectionInfo) -> float:
        """置信度 = min(1.0, 0.5 + 0.25 * (命中数 - 1) / (最低特征数 - 1))。

        单一命中 → 0.5；命中越多越高；≥最低特征数 → 1.0。
        """
        min_hits = MIN_HITS.get(info.protection, 3)
        hits = max(info.hit_count, 1)
        if min_hits <= 1:
            return 1.0
        return round(min(1.0, 0.5 + 0.25 * (hits - 1) / (min_hits - 1)), 2)


def detect_protection(target_path: str) -> ProtectionInfo:
    """模块级便捷入口：识别加固类型。"""
    return ProtectionDetector().detect(target_path)
