"""
test_detection —— 加固类型自动识别单元测试

靶场：
- 真实 APK：InsecureBankv2.apk / vuls_v4.4.apk（无加固基线）
- 合成 APK：七类加固特征受控样本
"""

from __future__ import annotations

import pytest

from fp_sentinel.mobile_shell.core.detection import (
    ProtectionDetector,
    detect_protection,
)
from fp_sentinel.mobile_shell.models.protection_info import (
    PROTECTION_360,
    PROTECTION_ALI,
    PROTECTION_BAIDU,
    PROTECTION_BANGCLE,
    PROTECTION_IJIAMI,
    PROTECTION_NAGA,
    PROTECTION_NONE,
    PROTECTION_TENCENT,
    ProtectionInfo,
)

from .conftest import build_apk


# ─────────────────────── 真实 APK 靶场 ───────────────────────


class TestRealApkDetection:
    """真实实验 APK 检测（无加固基线）。"""

    def test_insecure_bankv2_unpacked(self, insecure_bank_apk):
        """InsecureBankv2.apk 为明文 APK → 无壳。"""
        info = ProtectionDetector().detect(str(insecure_bank_apk))
        assert info.protection == PROTECTION_NONE
        assert info.is_packed is False
        assert info.confidence > 0
        assert "无壳" in info.summary()

    def test_vuls_apk_unpacked(self, vuls_apk):
        """vuls_v4.4.apk 为明文 APK → 无壳。"""
        info = detect_protection(str(vuls_apk))
        assert info.protection == PROTECTION_NONE
        assert not info.native_libs

    def test_real_apk_android_dumper_detect(self, insecure_bank_apk):
        """经 AndroidDumper.detect_protection 的间接入口。"""
        from fp_sentinel.mobile_shell.core.android_dumper import AndroidDumper

        info = AndroidDumper().detect_protection(str(insecure_bank_apk))
        assert info.protection == PROTECTION_NONE


# ─────────────────────── 合成 APK：七类加固 ───────────────────────


class _PackerSamples:
    """各类加固的合成样本（文件特征 + dex 特征字符串）。"""

    @staticmethod
    def pack_360(tmp_path):
        return build_apk(tmp_path / "p360.apk", {
            "AndroidManifest.xml": b"\x03\x00stub",
            "classes.dex": b"Lcom/stub/StubApp;" + b"\x00" * 64,
            "lib/armeabi-v7a/libjiagu.so": b"MZ-jiagu",
        })

    @staticmethod
    def pack_tencent(tmp_path):
        return build_apk(tmp_path / "legu.apk", {
            "classes.dex": b"Lcom/tencent/StubShell;" + b"\x00" * 64,
            "lib/armeabi-v7a/libshella-2.10.3.6.so": b"legu",
            "lib/armeabi-v7a/libtup.so": b"tup",
        })

    @staticmethod
    def pack_bangcle(tmp_path):
        return build_apk(tmp_path / "bangcle.apk", {
            "classes.dex": b"Lcom/secneo/apkwrapper;" + b"\x00" * 64,
            "lib/armeabi-v7a/libsecexe.so": b"secneo",
            "lib/armeabi-v7a/libDexHelper.so": b"dexhelper",
        })

    @staticmethod
    def pack_ijiami(tmp_path):
        return build_apk(tmp_path / "ijiami.apk", {
            "classes.dex": b"Lcom/shell/SuperApplication; ijiami" + b"\x00" * 32,
            "ijiami.dat": b"\x01\x02",
            "lib/armeabi-v7a/libexecmain.so": b"ijm",
        })

    @staticmethod
    def pack_naga(tmp_path):
        return build_apk(tmp_path / "naga.apk", {
            "classes.dex": b"nagain" + b"\x00" * 64,
            "lib/armeabi-v7a/libchaosvmp.so": b"chaosvmp",
        })

    @staticmethod
    def pack_baidu(tmp_path):
        return build_apk(tmp_path / "baidu.apk", {
            "classes.dex": b"com/baidu/protect" + b"\x00" * 64,
            "lib/armeabi-v7a/libbaiduprotect.so": b"bdprotect",
        })

    @staticmethod
    def pack_ali(tmp_path):
        return build_apk(tmp_path / "ali.apk", {
            "classes.dex": b"com/alibaba/wireless/security" + b"\x00" * 32,
            "lib/armeabi-v7a/libmobisec.so": b"mobisec",
        })


class TestPackerDetection:
    """七类加固特征识别。"""

    @pytest.mark.parametrize(
        "builder,expected",
        [
            (_PackerSamples.pack_360, PROTECTION_360),
            (_PackerSamples.pack_tencent, PROTECTION_TENCENT),
            (_PackerSamples.pack_bangcle, PROTECTION_BANGCLE),
            (_PackerSamples.pack_ijiami, PROTECTION_IJIAMI),
            (_PackerSamples.pack_naga, PROTECTION_NAGA),
            (_PackerSamples.pack_baidu, PROTECTION_BAIDU),
            (_PackerSamples.pack_ali, PROTECTION_ALI),
        ],
        ids=["360", "tencent", "bangcle", "ijiami", "naga", "baidu", "ali"],
    )
    def test_detect_packer(self, tmp_path, builder, expected):
        apk = builder(tmp_path)
        info = ProtectionDetector(use_androguard=False).detect(str(apk))
        assert info.protection == expected
        assert info.is_packed is True
        assert info.hit_count >= 2
        assert info.confidence >= 0.5

    def test_confidence_scales_with_hits(self, tmp_path):
        """命中特征越多置信度越高。"""
        single = build_apk(tmp_path / "single.apk", {
            "lib/armeabi-v7a/libjiagu.so": b"x",
        })
        multi = build_apk(tmp_path / "multi.apk", {
            "lib/armeabi-v7a/libjiagu.so": b"x",
            "lib/arm64-v8a/libjiagu_64.so": b"x",
            "classes.dex": b"Lcom/stub/StubApp;",
        })
        det = ProtectionDetector(use_androguard=False)
        c1 = det.detect(str(single)).confidence
        c2 = det.detect(str(multi)).confidence
        assert c2 > c1
        assert c1 == 0.5
        assert c2 <= 1.0


class TestDetectionEdgeCases:
    """边界与降级路径。"""

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            ProtectionDetector().detect("Z:/no/such/app.apk")

    def test_bad_zip(self, tmp_path):
        fake = tmp_path / "fake.apk"
        fake.write_text("not a zip", encoding="utf-8")
        with pytest.raises(ValueError, match="ZIP"):
            ProtectionDetector(use_androguard=False).detect(str(fake))

    def test_packer_class_matching(self):
        det = ProtectionDetector(use_androguard=False)
        assert det._match_packer_class("com.stub.StubApp") == PROTECTION_360
        assert det._match_packer_class("com.tencent.StubShell") == PROTECTION_TENCENT
        assert det._match_packer_class("com.unknown.App") is None

    def test_raw_manifest_fallback(self, tmp_path):
        """androguard 不可用时从二进制 Manifest 字符串池启发式提取入口类。"""
        apk = build_apk(tmp_path / "raw.apk", {
            "AndroidManifest.xml": (
                "com.secneo.apkwrapper.ApplicationWrapper".encode("utf-16-le")
            ),
            "classes.dex": b"\x00" * 16,
        })
        det = ProtectionDetector(use_androguard=False)
        cls = det._extract_application_class(str(apk))
        assert cls == "com.secneo.apkwrapper.ApplicationWrapper"

    def test_raw_manifest_missing_entry(self, tmp_path):
        """无 AndroidManifest 条目时返回 None。"""
        apk = build_apk(tmp_path / "nomani.apk", {"classes.dex": b"\x00"})
        assert ProtectionDetector._extract_application_class_raw(str(apk)) is None

    def test_raw_manifest_no_packer_class(self, tmp_path):
        """Manifest 无已知加固类时返回 None。"""
        apk = build_apk(tmp_path / "plain.apk", {
            "AndroidManifest.xml": "com.example.App".encode("utf-16-le"),
        })
        assert ProtectionDetector._extract_application_class_raw(str(apk)) is None

    def test_androguard_fallback_flag(self, tmp_path):
        """use_androguard=False 时强制走 raw 路径。"""
        det = ProtectionDetector(use_androguard=False)
        assert det.androguard_available is False
        apk = build_apk(tmp_path / "x.apk", {
            "AndroidManifest.xml": "com.stub.StubApp".encode("utf-16-le"),
            "classes.dex": b"\x00" * 8,
        })
        info = det.detect(str(apk))
        assert info.protection == PROTECTION_360
        assert info.packer_class == "com.stub.StubApp"

    def test_androguard_exception_falls_back(self, tmp_path, monkeypatch):
        """androguard 解析抛异常时降级 raw 解析并仍能识别入口类。"""
        import androguard.core.apk as apk_mod

        det = ProtectionDetector()
        assert det.androguard_available is True

        def boom(_path):
            raise RuntimeError("parse error")

        monkeypatch.setattr(apk_mod, "APK", boom)
        apk = build_apk(tmp_path / "y.apk", {
            "AndroidManifest.xml": "com.stub.StubApp".encode("utf-16-le"),
            "classes.dex": b"\x00" * 8,
        })
        info = det.detect(str(apk))
        assert info.protection == PROTECTION_360
        assert info.packer_class == "com.stub.StubApp"

    def test_merge_hit_and_details(self):
        info = ProtectionInfo(protection=PROTECTION_360)
        info.merge_hit(["libjiagu.so"], ["stub"], ["libjiagu.so"], "com.stub.StubApp")
        assert info.hit_count == 4
        assert info.packer_class == "com.stub.StubApp"
        # packer_class 已存在时不覆盖
        info.merge_hit([], [], [], "other.Class")
        assert info.packer_class == "com.stub.StubApp"

    def test_min_hits_guard(self):
        """MIN_HITS 边界（<=1 时置信度 1.0）。"""
        from fp_sentinel.mobile_shell.core.detection import MIN_HITS

        info = ProtectionInfo(protection=PROTECTION_360)
        info.merge_hit([], [], [], None)
        original = MIN_HITS[PROTECTION_360]
        MIN_HITS[PROTECTION_360] = 1
        try:
            assert ProtectionDetector._compute_confidence(info) == 1.0
        finally:
            MIN_HITS[PROTECTION_360] = original

    def test_unknown_protection_candidate(self):
        info = ProtectionInfo()
        assert info.protection == "unknown"
        assert info.hit_count == 0
