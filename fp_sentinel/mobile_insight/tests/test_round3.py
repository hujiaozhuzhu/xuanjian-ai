"""Round 3 回归测试 —— 证据归因主线（NEW-01/02/03/05/06/07/08）。

验收要点（对应 docs/round3 任务书）:
- NEW-01: 凭证分级 L3/L2/L1/L0 + 排除规则; superSecurePassword 必须命中;
- NEW-02: 归因成功回填 class#method; 归因失败降一级并标注 unattributed;
- NEW-03: CP 系列候选门控 —— 库类不触发, 业务包前缀类触发;
- NEW-05: ST-010 debuggable / ST-011 allowBackup;
- NEW-06: classification 回填与报告分组;
- NEW-07: AA-004 module(攻击方)/detector(防御方)语义;
- NEW-08: AA-003 证据为具体片段而非正则原文。
"""

from __future__ import annotations

import pytest

from fp_sentinel.mobile_insight.core.context import AnalysisContext, classify_class
from fp_sentinel.mobile_insight.core.engine import InsightEngine
from fp_sentinel.mobile_insight.models.insight import InsightCategory, Severity
from fp_sentinel.mobile_insight.rules import get_all_rules
from fp_sentinel.mobile_insight.rules.anti_analysis_rules import RULES as AA
from fp_sentinel.mobile_insight.rules.component_rules import RULES as CP
from fp_sentinel.mobile_insight.rules.context_filters import (
    classify_credential,
    find_password_literals,
    is_credential_excluded,
)
from fp_sentinel.mobile_insight.rules.storage_rules import RULES as ST


# ============================================================ NEW-01
class TestCredentialGrading:
    @pytest.mark.parametrize("value,expected", [
        # LEVEL 3: 口令变量名 + 非占位明文
        ("superSecurePassword", 3),
        ("password=SuperSecret123", 3),
        ("my_db_passwd=Abc123!@#", 3),
        # LEVEL 2: Base64 解码含敏感词 / secret 词根
        ("dXNlcjpwYXNzd29yZDEyMw==", 2),
        ("mySuperSecretApiKey123", 2),
        # LEVEL 1: 已知密钥前缀
        ("ghp_abcdefghijklmnopqrstuvwxyz012345", 1),
        ("sk-live-abcdefghijklmnop", 1),
        ("Bearer abc.def.ghi", 1),
        # LEVEL 0: 排除项 —— 永不触发
        ("X-Afma-OAuth-Token-Status", 0),   # HTTP 头名
        ("Content-Type", 0),
        ("GET", 0),
        ("CREDENTIALS_API", 0),             # 大写常量
        ("/changepassword", 0),             # URL 路径
        ("http://evil.com/x", 0),
        ("com.example.app.MainActivity", 0),
        ("MD5", 0), ("CRC32", 0),
        ("resetPassword", 0), ("getPassword", 0),  # 方法名风格
        ("password", 0), ("user", 0),       # 通用单词
        # R3.1 NEW-01 补课: 标识符/文件名/描述符形态（确定性排序后暴露）
        ("ChangePassword.java", 0),          # 源码文件名
        ("strings.xml", 0),
        ("RequestChangePasswordTask", 0),    # PascalCase 类名
        ("CredentialsApi", 0),               # PascalCase 类名
        ("Password_Text", 0),                # 蛇形资源/变量名
        ("Auth.CREDENTIALS_API", 0),         # 点分大写常量引用
        ("Lcom/google/android/gms/auth/api/credentials/Credential;", 0),   # DEX 描述符
        ("Lcom/google/android/gms/auth/api/credentials/internal/zzd", 0),  # 无分号斜杠形态
        ("[Lcom/google/android/gms/auth/api/credentials/Credential;", 0),  # 数组前缀
        ("Lcom/google/android/gms/common/api/BatchResultToken<TR;>;", 0),  # 泛型
        ("Password123", 0),                  # 占位符（弱口令样本值）
    ])
    def test_grading(self, value, expected):
        assert classify_credential(value) == expected, value

    def test_exclusion_flags(self):
        assert is_credential_excluded("Content-Type")
        assert is_credential_excluded("GET")
        assert not is_credential_excluded("superSecurePassword")

    def test_find_password_literals_orders_by_level(self):
        ctx = AnalysisContext(package_name="com.demo")
        ctx.add_strings([
            "ghp_abcdefghijklmnopqrstuvwxyz012345",   # L1
            "password=SuperSecret123",                # L3
            "superSecurePassword",                    # L3
        ])
        out = find_password_literals(ctx)
        assert out and out[0].startswith("[LEVEL3]")
        assert any("[LEVEL1]" in e for e in out)
        # 无 L2 时 L3 先于 L1
        assert "[LEVEL1]" in out[-1]

    def test_st007_dynamic_severity(self):
        rule = next(r for r in ST if r.id == "ST-007")
        assert rule.dynamic_severity(["[LEVEL3] password=x"]) is Severity.CRITICAL
        assert rule.dynamic_severity(["[LEVEL2] dXNlcjpwYXNz"]) is Severity.HIGH
        assert rule.dynamic_severity(["[LEVEL1] ghp_x"]) is Severity.MEDIUM

    def test_insecurebank_password_literal_detected(self):
        """专家样例: superSecurePassword 必须进证据。"""
        ctx = AnalysisContext(package_name="com.android.insecurebankv2")
        ctx.add_strings(["superSecurePassword"])
        rule = next(r for r in ST if r.id == "ST-007")
        evidence = rule.match(ctx)
        assert evidence and "[LEVEL3]" in evidence[0]
        assert "superSecurePassword" in evidence[0]


# ============================================================ NEW-02
class _StubIndex:
    """归因索引桩: 只返回预设值, 用于引擎回填逻辑测试。"""

    method_count = 1

    def __init__(self, mapping=None):
        self._mapping = mapping or {}

    def locate_kv(self, evidence, package_name=""):
        return self._mapping.get(evidence)


class TestAttributionBackfill:
    def _ctx(self, mapping=None, available=True):
        ctx = AnalysisContext(package_name="com.android.insecurebankv2")
        ctx.add_strings(["superSecurePassword"])
        ctx.attribution_index = _StubIndex(mapping)
        ctx.attribution_available = available
        return ctx

    def test_attributed_hit_backfills_location(self):
        ctx = self._ctx({"superSecurePassword": ("com.android.insecurebankv2.CryptoClass",
                                                "aes19encryptedString")})
        report = InsightEngine().run(ctx, target="demo")
        st007 = next(i for i in report.insights if i.rule_id == "ST-007")
        assert st007.code_reference.class_name == "com.android.insecurebankv2.CryptoClass"
        assert st007.code_reference.method_name == "aes19encryptedString"
        assert st007.severity is Severity.CRITICAL  # L3 证据, 未降级

    def test_unattributed_downgrades_severity(self):
        """归因可用但失败 → 降一级 + unattributed 标注。"""
        ctx = self._ctx({})  # 索引为空, 查不到
        report = InsightEngine().run(ctx, target="demo")
        st007 = next(i for i in report.insights if i.rule_id == "ST-007")
        assert st007.code_reference.class_name == "DEX string pool (unattributed)"
        # L3 证据动态定级 CRITICAL, 归因失败降为 HIGH
        assert st007.severity is Severity.HIGH
        assert st007.classification == "unattributed"

    def test_manifest_rules_never_downgrade(self):
        """ST-010/ST-011 是 manifest 规则(code_level=False), 无归因也不降级。"""
        ctx = AnalysisContext(package_name="com.demo")
        ctx.set_manifest_flags({"debuggable": True, "allow_backup": True})
        ctx.attribution_index = _StubIndex()
        ctx.attribution_available = True
        report = InsightEngine().run(ctx, target="demo")
        by_id = {i.rule_id: i for i in report.insights}
        assert by_id["ST-010"].severity is Severity.CRITICAL
        assert by_id["ST-011"].severity is Severity.MEDIUM

    def test_no_index_no_downgrade(self):
        """索引未构建(attribution_available=False)时保持原级别, 不降级。"""
        ctx = self._ctx(available=False)
        report = InsightEngine().run(ctx, target="demo")
        st007 = next(i for i in report.insights if i.rule_id == "ST-007")
        assert st007.severity is Severity.CRITICAL

    def test_real_apk_attribution_business_preferred(self):
        """真实 APK: 归因索引能定位业务类（NEW-02 端到端）。"""
        apk = _SAMPLE_APK()
        if apk is None:
            pytest.skip("InsecureBankv2.apk 不在测试靶场")
        ctx = AnalysisContext.from_apk(apk)
        assert ctx.attribution_available
        report = InsightEngine().run(ctx, target=apk)
        attributed = [
            i for i in report.insights
            if i.code_reference.class_name.startswith("com.android.insecurebankv2")
        ]
        assert attributed, "没有任何发现归因到业务包"


def _SAMPLE_APK():
    from pathlib import Path
    apk = (Path(__file__).resolve().parents[3] / "test_apps"
           / "2023移动安全培训：资料" / "3、第三阶段app漏洞"
           / "8.Android APP组件安全之Broadcast Receiver常见风险" / "InsecureBankv2.apk")
    return str(apk) if apk.exists() else None


# ============================================================ NEW-03
class TestComponentGating:
    def _ctx(self, package_name="com.app"):
        ctx = AnalysisContext(package_name=package_name)
        ctx.set_manifest_flags({"has_provider": True, "has_receiver": True})
        return ctx

    def test_support_library_filtered(self):
        """专家误报样例: support 库 Provider/Receiver 类不触发。"""
        ctx = self._ctx()
        ctx.add_classes([
            "android.support.v4.content.FileProvider",
            "androidx.core.app.NotificationManagerCompat",
            "com.google.android.gms.internal.zzat",
        ])
        cp004 = next(r for r in CP if r.id == "CP-004")
        assert cp004.match(ctx) == []
        cp003 = next(r for r in CP if r.id == "CP-003")
        assert cp003.match(ctx) == []

    def test_business_prefix_triggers(self):
        ctx = self._ctx(package_name="com.android.insecurebankv2")
        ctx.add_classes([
            "com.android.insecurebankv2.TrackUserContentProvider",
            "com.android.insecurebankv2.MyBroadCastReceiver",
        ])
        cp004 = next(r for r in CP if r.id == "CP-004")
        evidence = cp004.match(ctx)
        assert evidence and "TrackUserContentProvider" in evidence[0]
        cp003 = next(r for r in CP if r.id == "CP-003")
        assert "MyBroadCastReceiver" in cp003.match(ctx)[0]

    def test_non_prefix_class_filtered_when_package_known(self):
        """已知真实包名时, 非包名前缀的业务词类名不再作为候选。"""
        ctx = self._ctx(package_name="com.app")
        ctx.add_classes(["other.pkg.SomeProvider"])
        cp004 = next(r for r in CP if r.id == "CP-004")
        assert cp004.match(ctx) == []

    def test_obfuscated_class_annotated(self):
        # 无真实包名时, 单字母包段混淆形态仍可作为候选但打标
        ctx = self._ctx(package_name="")
        ctx.add_classes(["a.b.c.Provider"])
        cp004 = next(r for r in CP if r.id == "CP-004")
        evidence = cp004.match(ctx)
        assert evidence and "obfuscated" in evidence[0]


# ============================================================ NEW-05
class TestManifestRules:
    def test_st010_debuggable(self):
        ctx = AnalysisContext(package_name="com.demo")
        ctx.set_manifest_flags({"debuggable": True})
        rule = next(r for r in ST if r.id == "ST-010")
        assert rule.match(ctx)
        assert rule.cwe_ids == ["CWE-486"]
        assert rule.severity is Severity.CRITICAL

    def test_st010_not_flagged_when_false(self):
        ctx = AnalysisContext(package_name="com.demo")
        ctx.set_manifest_flags({"debuggable": False})
        rule = next(r for r in ST if r.id == "ST-010")
        assert rule.match(ctx) == []

    def test_st011_allow_backup(self):
        ctx = AnalysisContext(package_name="com.demo")
        ctx.set_manifest_flags({"allow_backup": True})
        rule = next(r for r in ST if r.id == "ST-011")
        assert rule.match(ctx)
        assert rule.cwe_ids == ["CWE-530"]
        assert rule.severity is Severity.MEDIUM

    def test_from_apk_populates_flags(self):
        """真实 APK: InsecureBankv2 实际是 debuggable=true。"""
        from pathlib import Path
        apk = (Path(__file__).resolve().parents[3] / "test_apps"
               / "2023移动安全培训：资料" / "3、第三阶段app漏洞"
               / "8.Android APP组件安全之Broadcast Receiver常见风险" / "InsecureBankv2.apk")
        if not apk.exists():
            pytest.skip("InsecureBankv2.apk 不在测试靶场")
        ctx = AnalysisContext.from_apk(str(apk))
        assert ctx.manifest_flags.get("debuggable") is True


# ============================================================ NEW-06
class TestClassification:
    def test_classify_class(self):
        assert classify_class("com.android.insecurebankv2.DoLogin",
                              "com.android.insecurebankv2") == "business"
        # v4.0 C1: androidx 与 android.support 同级, 归入 framework
        assert classify_class("androidx.core.app.ActivityCompat") == "framework"
        assert classify_class("android.view.View") == "framework"
        assert classify_class("okhttp3.OkHttpClient") == "library"
        assert classify_class("okio.Buffer") == "library"
        assert classify_class("com.tencent.bugly.BugStrategy") == "library"
        assert classify_class("com.app.a.b") == "obfuscated"
        assert classify_class("com.app.MyCls", "com.app") == "business"
        assert classify_class("com.app.a", "com.app") == "obfuscated"  # 单字母类名

    def test_engine_backfills_classification(self):
        ctx = AnalysisContext(package_name="com.demo")
        ctx.add_strings(["http://api.example.com/login"])
        report = InsightEngine().run(ctx, target="demo")
        assert report.insights
        assert all(hasattr(i, "classification") for i in report.insights)

    def test_report_groups_and_distribution(self):
        ctx = AnalysisContext(package_name="com.demo")
        ctx.add_strings(["http://api.example.com/login"])
        report = InsightEngine().run(ctx, target="demo")
        payload = report.to_dict()
        assert "classification_distribution" in payload
        groups = report.grouped_by_classification()
        assert sum(len(v) for v in groups.values()) == len(report.insights)


# ============================================================ NEW-07/08
class TestAntiAnalysisEvidence:
    def test_aa004_module_vs_detector(self):
        rule = next(r for r in AA if r.id == "AA-004")
        # 模块实现侧: hook 他人 = 攻击方
        ctx_mod = AnalysisContext(package_name="com.demo")
        ctx_mod.add_strings([
            "de.robv.android.xposed.IXposedHookLoadPackage",
            "handleLoadPackage",
        ])
        evidence = rule.match(ctx_mod)
        assert any(e.startswith("[module=attack]") for e in evidence)
        # 检测侧: 被 hook 方 = 防御方
        ctx_det = AnalysisContext(package_name="com.demo")
        ctx_det.add_strings(["de.robv.android.xposed.XposedBridge"])
        evidence = rule.match(ctx_det)
        assert evidence
        assert any(e.startswith("[detector=defense]") for e in evidence)

    def test_aa003_evidence_is_fragment(self):
        rule = next(r for r in AA if r.id == "AA-003")
        ctx = AnalysisContext(package_name="com.demo")
        ctx.add_strings([
            "checking frida-server on port 27042 via /proc/net/tcp",
            "linjector",
        ])
        evidence = rule.match(ctx)
        assert evidence
        # 证据是命中的片段, 不是整段原文/正则（池序不定，断言与顺序无关）
        assert all(len(e) < 100 for e in evidence)
        assert all(
            any(frag in e.lower() for frag in ("frida", "gum-js-loop", "linjector", "2704"))
            for e in evidence
        )
        assert any("frida" in e.lower() for e in evidence)


# ============================================================ 轻量降级路径
class TestLightPathFallback:
    """from_apk 深度路径失败时降级为二进制粗提取（零依赖兜底）。"""

    @staticmethod
    def _make_light_apk(tmp_path):
        import zipfile

        p = tmp_path / "light.apk"
        dex = (
            b"\x00Lcom/demo/bank/Main;\x00"
            b"doLogin\x00"
            b"MY_CONST\x00"        # 大写常量 → 不算方法名
            b"httpabc\x00"          # http 前缀 → 不算方法名
            b"http://evil.example\x00"
        )
        manifest = "\x00".join(
            ["android.permission.CAMERA", "activity"]
        ).encode("utf-16-le")
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("classes.dex", dex)
            zf.writestr("AndroidManifest.xml", manifest)
        return str(p)

    def test_light_fallback_extracts_signals(self, tmp_path, monkeypatch):
        from fp_sentinel.mobile_insight.core import context as ctx_mod

        class _Boom:
            def __init__(self, *a, **k):
                raise RuntimeError("androguard unavailable")

        # ManifestParser 在 _from_apk_deep 内局部导入 → patch 源模块
        monkeypatch.setattr(
            "fp_sentinel.mobile_decompile.parsers.manifest_parser.ManifestParser",
            _Boom,
        )
        ctx = ctx_mod.AnalysisContext.from_apk(self._make_light_apk(tmp_path))
        # 文件名兜底包名
        assert ctx.package_name == "light"
        # dex ASCII 提取: 类名/方法名筛选
        assert "com.demo.bank.Main" in ctx.classes
        assert "doLogin" in ctx.methods
        assert "MY_CONST" not in ctx.methods
        assert "httpabc" not in ctx.methods
        # manifest UTF-16 信号
        assert "android.permission.CAMERA" in ctx.permissions
        assert ctx.manifest_flags.get("has_activity") is True


# ============================================================ 规则库完整性
class TestRuleCatalogRound3:
    def test_total_67(self):
        assert len(get_all_rules()) == 67

    def test_storage_has_11(self):
        from fp_sentinel.mobile_insight.rules.storage_rules import RULES
        assert len(RULES) == 11
        assert {r.id for r in RULES[-2:]} == {"ST-010", "ST-011"}


# ============================================================ R3.1 确定性
class TestDeterminismRound31:
    """R3.1: 扫描结果对 PYTHONHASHSEED 不可变（证据顺序/归因/降级全确定）。"""

    def test_find_password_literals_stable_across_hash_seeds(self):
        """find_password_literals / find_evidence / fragments 跨 seed 一致。"""
        import os
        import subprocess
        import sys

        strings = (
            [f"batch_{i:03d}_token_payload_{i * 7}" for i in range(120)]
            + [f"lib_note_{i:03d} no keyword here" for i in range(120)]
            + ["superSecurePassword", "password=SuperSecret123",
               "ghp_abcdefghijklmnopqrstuvwxyz012345",
               "RequestChangePasswordTask", "ChangePassword.java",
               "Lcom/google/android/gms/auth/api/credentials/Credential;"]
        )
        snippet = (
            "from fp_sentinel.mobile_insight.core.context import AnalysisContext\n"
            "from fp_sentinel.mobile_insight.rules.context_filters"
            " import find_password_literals\n"
            f"strings = {strings!r}\n"
            "ctx = AnalysisContext(package_name='com.demo')\n"
            "ctx.add_strings(strings)\n"
            "print(find_password_literals(ctx))\n"
            "print(ctx.find_evidence(r'token|secret|password', limit=8))\n"
            "print(ctx.find_evidence_fragments(r'token|secret|password',"
            " limit=8))\n"
        )
        outputs = []
        for seed in ("0", "1"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            proc = subprocess.run(
                [sys.executable, "-c", snippet], capture_output=True,
                text=True, env=env, timeout=120,
            )
            assert proc.returncode == 0, proc.stderr
            outputs.append(proc.stdout)
        assert outputs[0] == outputs[1], (
            "证据输出随 PYTHONHASHSEED 漂移 —— 存在 set 迭代序依赖"
        )

    def test_exported_evidence_is_sorted(self):
        """Manifest 导出组件顺序随机（androguard set）→ 证据必须排序。"""
        ctx = AnalysisContext(package_name="com.app")
        ctx.add_exported_component("activity", "com.app.ZebraActivity")
        ctx.add_exported_component("activity", "com.app.AlphaActivity")
        ctx.add_exported_component("activity", "com.app.MangoActivity")
        cp001 = next(r for r in CP if r.id == "CP-001")
        evidence = cp001.match(ctx)
        assert evidence == sorted(evidence)
        assert evidence[0].startswith("com.app.AlphaActivity")

    def test_framework_attribution_downgrades_but_keeps_location(self):
        """R3.1b: 归因落点为框架类 → 降级, 但保留真实 class#method。
        v4.0 C1: 落点级别封顶在 HIGH 以下（HIGH+ 库/框架落点 = 0）。"""
        ctx = AnalysisContext(package_name="com.android.insecurebankv2")
        ctx.add_strings(["superSecurePassword"])
        ctx.attribution_index = _StubIndex({
            "superSecurePassword": ("android.support.v4.widget.DrawableUtils",
                                    "applyTint"),
        })
        ctx.attribution_available = True
        report = InsightEngine().run(ctx, target="demo")
        st007 = next(i for i in report.insights if i.rule_id == "ST-007")
        # v4.0 C1: 框架落点不得以 HIGH+ 呈现 —— CRITICAL 降两档至 MEDIUM
        assert st007.severity is Severity.MEDIUM
        assert st007.code_reference.class_name == \
            "android.support.v4.widget.DrawableUtils"  # 位置保留
        assert st007.classification == "framework"

    def test_cross_evidence_prefers_business_attribution(self):
        """R3.1a: 跨证据定位 —— 库类命中在前也必须让位业务类命中。"""
        ctx = AnalysisContext(package_name="com.android.insecurebankv2")
        ctx.add_strings(["superSecurePassword", "password=SuperSecret123"])
        # 字典序 "password=..." 在前; 其命中 gms 库, "superSecurePassword"
        # 命中业务类 —— 业务优先必须胜出。
        ctx.attribution_index = _StubIndex({
            "password=SuperSecret123":
                ("com.google.android.gms.internal.zzig", "zzd"),
            "superSecurePassword":
                ("com.android.insecurebankv2.CryptoClass", "aes19encrypted"),
        })
        ctx.attribution_available = True
        report = InsightEngine().run(ctx, target="demo")
        st007 = next(i for i in report.insights if i.rule_id == "ST-007")
        assert st007.code_reference.class_name == \
            "com.android.insecurebankv2.CryptoClass"
        assert st007.severity is Severity.CRITICAL   # 业务命中 → 不降级

    def test_real_apk_st007_business_critical(self):
        """端到端: 真实 APK 上 ST-007 必须拿到真凭证 L3 证据 + 业务归因。"""
        apk = _SAMPLE_APK()
        if apk is None:
            pytest.skip("InsecureBankv2.apk 不在测试靶场")
        ctx = AnalysisContext.from_apk(apk)
        assert ctx.attribution_available
        report = InsightEngine().run(ctx, target=apk)
        st007 = next(i for i in report.insights if i.rule_id == "ST-007")
        assert st007.severity is Severity.CRITICAL
        assert st007.code_reference.class_name.startswith(
            "com.android.insecurebankv2")
        assert any("superSecurePassword" in e for e in st007.evidence)
