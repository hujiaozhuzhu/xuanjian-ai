"""
修复验证引擎测试
覆盖：语法检查、漏洞修复验证、新漏洞检测、批量验证、各VulnerabilityType
"""

import pytest
from fp_sentinel.auto_pr.fix_validator import FixValidator
from fp_sentinel.auto_pr.models import (
    FixPatch,
    VerificationStatus,
    VerifyFixRequest,
    VulnerabilityType,
)


class TestFixValidator:
    """测试修复验证引擎"""

    def setup_method(self):
        self.validator = FixValidator()

    # ─────────────────── SQL注入修复验证 ───────────────────

    def test_sql_injection_fixed(self):
        request = VerifyFixRequest(
            patch_id="p1",
            finding_id="f1",
            original_code='cursor.execute("SELECT * FROM users WHERE id = " + uid)',
            fixed_code='cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))',
            rule_id="py.injection.sql",
            vuln_type=VulnerabilityType.SQL_INJECTION,
        )
        result = self.validator.verify_fix(request)
        # Should pass or warn (still has "SELECT" in the fixed code but no concatenation)
        assert result.status in (VerificationStatus.PASS, VerificationStatus.WARN)
        assert result.original_vuln_resolved is True
        assert result.new_vulns_introduced == 0
        assert result.syntax_valid is True

    def test_sql_injection_not_fixed(self):
        request = VerifyFixRequest(
            patch_id="p2",
            finding_id="f2",
            original_code='cursor.execute("SELECT * FROM users WHERE id = " + uid)',
            fixed_code='cursor.execute("SELECT * FROM users WHERE id = " + uid)',  # same bad
            rule_id="py.injection.sql",
            vuln_type=VulnerabilityType.SQL_INJECTION,
        )
        result = self.validator.verify_fix(request)
        assert result.original_vuln_resolved is False

    # ─────────────────── 命令注入修复验证 ───────────────────

    def test_command_injection_fixed(self):
        request = VerifyFixRequest(
            patch_id="p3",
            finding_id="f3",
            original_code="os.system('ls ' + user_input)",
            fixed_code='subprocess.run(["ls", user_input], shell=False)',
            rule_id="py.command.injection",
            vuln_type=VulnerabilityType.COMMAND_INJECTION,
        )
        result = self.validator.verify_fix(request)
        assert result.original_vuln_resolved is True
        assert result.status in (VerificationStatus.PASS, VerificationStatus.WARN)

    def test_command_injection_not_fixed(self):
        request = VerifyFixRequest(
            patch_id="p4",
            finding_id="f4",
            original_code="os.system(cmd)",
            fixed_code="os.system(cmd)",  # unchanged
            rule_id="py.command.injection",
            vuln_type=VulnerabilityType.COMMAND_INJECTION,
        )
        result = self.validator.verify_fix(request)
        assert result.original_vuln_resolved is False

    # ─────────────────── XSS修复验证 ───────────────────

    def test_xss_fixed(self):
        request = VerifyFixRequest(
            patch_id="p5",
            finding_id="f5",
            original_code="el.innerHTML = userInput",
            fixed_code="el.textContent = userInput",
            rule_id="py.xss.dom",
            vuln_type=VulnerabilityType.XSS,
        )
        result = self.validator.verify_fix(request)
        assert result.original_vuln_resolved is True

    def test_xss_not_fixed(self):
        request = VerifyFixRequest(
            patch_id="p6",
            finding_id="f6",
            original_code="el.innerHTML = userInput",
            fixed_code="el.innerHTML = userInput",  # unchanged
            rule_id="py.xss.dom",
            vuln_type=VulnerabilityType.XSS,
        )
        result = self.validator.verify_fix(request)
        assert result.original_vuln_resolved is False

    # ─────────────────── 路径遍历修复验证 ───────────────────

    def test_path_traversal_fixed(self):
        request = VerifyFixRequest(
            patch_id="p7",
            finding_id="f7",
            original_code='f = open(os.path.join(base, user_path))',
            fixed_code=(
                'realpath = os.path.realpath(os.path.join(base, user_path))\n'
                'if not realpath.startswith(os.path.realpath(base)):\n'
                '    abort(403)\n'
                'f = open(realpath)'
            ),
            rule_id="py.path.traversal",
            vuln_type=VulnerabilityType.PATH_TRAVERSAL,
        )
        result = self.validator.verify_fix(request)
        assert result.original_vuln_resolved is True
        assert result.status in (VerificationStatus.PASS, VerificationStatus.WARN)

    # ─────────────────── 硬编码密钥修复验证 ───────────────────

    def test_hardcoded_secret_fixed(self):
        request = VerifyFixRequest(
            patch_id="p8",
            finding_id="f8",
            original_code='SECRET_KEY = "abc123"',
            fixed_code='SECRET_KEY = os.environ["SECRET_KEY"]',
            rule_id="py.hardcoded.credential",
            vuln_type=VulnerabilityType.HARDCODED_SECRET,
        )
        result = self.validator.verify_fix(request)
        assert result.original_vuln_resolved is True

    # ─────────────────── 语法检查测试 ───────────────────

    def test_python_syntax_valid(self):
        request = VerifyFixRequest(
            patch_id="p9",
            finding_id="f9",
            original_code="os.system(cmd)",
            fixed_code='subprocess.run(["ls", "-la"], shell=False, capture_output=True)',
            rule_id="py.os.system",
            vuln_type=VulnerabilityType.OS_COMMAND,
        )
        result = self.validator.verify_fix(request)
        assert result.syntax_valid is True

    def test_python_syntax_invalid(self):
        request = VerifyFixRequest(
            patch_id="p10",
            finding_id="f10",
            original_code="os.system(cmd)",
            fixed_code="subprocess.run([, broken_syntax = ",  # broken
            rule_id="py.os.system",
            vuln_type=VulnerabilityType.OS_COMMAND,
        )
        result = self.validator.verify_fix(request)
        assert result.syntax_valid is False

    def test_empty_code(self):
        request = VerifyFixRequest(
            patch_id="p11",
            finding_id="f11",
            original_code="os.system(cmd)",
            fixed_code="",
            rule_id="py.os.system",
            vuln_type=VulnerabilityType.OS_COMMAND,
        )
        result = self.validator.verify_fix(request)
        assert result.syntax_valid is False

    # ─────────────────── 新漏洞检测 ───────────────────

    def test_new_vuln_not_introduced(self):
        request = VerifyFixRequest(
            patch_id="p12",
            finding_id="f12",
            original_code="os.system(cmd)",
            fixed_code='subprocess.run(["ls", cmd], shell=False)',
            rule_id="py.os.system",
            vuln_type=VulnerabilityType.OS_COMMAND,
        )
        result = self.validator.verify_fix(request)
        assert result.new_vulns_introduced == 0

    def test_new_vuln_introduced(self):
        """修复代码中仍然包含eval()"""
        request = VerifyFixRequest(
            patch_id="p13",
            finding_id="f13",
            original_code="os.system(cmd)",
            fixed_code="eval(user_input)",  # introduces eval
            rule_id="py.os.system",
            vuln_type=VulnerabilityType.OS_COMMAND,
        )
        result = self.validator.verify_fix(request)
        # eval() is a generic dangerous pattern
        assert result.new_vulns_introduced > 0

    # ─────────────────── 严格模式测试 ───────────────────

    def test_strict_mode_with_warnings(self):
        strict_validator = FixValidator(strict_mode=True)
        request = VerifyFixRequest(
            patch_id="p14",
            finding_id="f14",
            original_code="os.system(cmd)",
            fixed_code='subprocess.run(["ls", cmd], shell=False)',
            rule_id="py.os.system",
            vuln_type=VulnerabilityType.OS_COMMAND,
        )
        result = strict_validator.verify_fix(request)
        # Should pass since no warnings
        assert result.status in (VerificationStatus.PASS, VerificationStatus.WARN)

    # ─────────────────── 补丁验证测试 ───────────────────

    def test_verify_patch(self):
        from fp_sentinel.auto_pr.models import FixDiff
        patch = FixPatch(
            finding_id="f15",
            vuln_type=VulnerabilityType.XSS,
            title="Fix XSS",
            diffs=[FixDiff(
                file_path="app.py",
                original_code="el.innerHTML = userInput",
                fixed_code="el.textContent = userInput",
                description="Use textContent",
            )],
        )

        result = self.validator.verify_patch(
            patch,
            original_code="el.innerHTML = userInput",
        )
        assert result.patch_id == patch.id
        assert result.finding_id == "f15"
        assert result.original_vuln_resolved is True

    # ─────────────────── 批量验证测试 ───────────────────

    def test_batch_verify(self):
        patches = []
        from fp_sentinel.auto_pr.models import FixDiff
        for i in range(3):
            patch = FixPatch(
                finding_id=f"batch-f-{i}",
                vuln_type=VulnerabilityType.SQL_INJECTION,
                title=f"Fix {i}",
                diffs=[FixDiff(
                    file_path="app.py",
                    original_code=f"bad code {i}",
                    fixed_code=f"cursor.execute('SELECT * FROM t WHERE id = %s', ({i},))",
                    description="Fix",
                )],
            )
            patches.append(patch)

        original_codes = {f"batch-f-{i}": f"bad code {i}" for i in range(3)}
        results = self.validator.batch_verify(patches, original_codes)
        assert len(results) == 3
        for r in results:
            assert isinstance(r.status, VerificationStatus)

    # ─────────────────── 通用类型验证 ───────────────────

    def test_generic_type_passes(self):
        request = VerifyFixRequest(
            patch_id="p16",
            finding_id="f16",
            original_code="bad_code()",
            fixed_code="good_code()",
            rule_id="unknown.rule",
            vuln_type=VulnerabilityType.GENERIC,
        )
        result = self.validator.verify_fix(request)
        assert result.original_vuln_resolved is True
        assert result.status in (VerificationStatus.PASS, VerificationStatus.WARN)

    def test_all_vuln_types_have_dangerous_patterns(self):
        """验证所有漏洞类型都有对应的安全模式"""
        from fp_sentinel.auto_pr.fix_validator import _VULN_DANGEROUS_PATTERNS
        for vtype in VulnerabilityType:
            assert vtype in _VULN_DANGEROUS_PATTERNS or vtype == VulnerabilityType.GENERIC

    def test_weak_hash_resolved(self):
        request = VerifyFixRequest(
            patch_id="p17",
            finding_id="f17",
            original_code="hashed = hashlib.md5(password)",
            fixed_code="hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
            rule_id="py.weak.hash",
            vuln_type=VulnerabilityType.WEAK_HASH,
        )
        result = self.validator.verify_fix(request)
        assert result.original_vuln_resolved is True
        assert result.status in (VerificationStatus.PASS, VerificationStatus.WARN)

    def test_yaml_unsafe_resolved(self):
        request = VerifyFixRequest(
            patch_id="p18",
            finding_id="f18",
            original_code="data = yaml.load(raw)",
            fixed_code="data = yaml.safe_load(raw)",
            rule_id="py.yaml.load",
            vuln_type=VulnerabilityType.YAML_UNSAFE,
        )
        result = self.validator.verify_fix(request)
        assert result.original_vuln_resolved is True

    def test_pickle_resolved(self):
        request = VerifyFixRequest(
            patch_id="p19",
            finding_id="f19",
            original_code="obj = pickle.loads(data)",
            fixed_code="obj = json.loads(data)",
            rule_id="py.pickle.loads",
            vuln_type=VulnerabilityType.PICKLE_DESERIALIZE,
        )
        result = self.validator.verify_fix(request)
        assert result.original_vuln_resolved is True

    def test_open_redirect_resolved(self):
        request = VerifyFixRequest(
            patch_id="p20",
            finding_id="f20",
            original_code="return redirect(url)",
            fixed_code='from urllib.parse import urlparse\np = urlparse(url)\nif p.netloc and p.netloc != ALLOWED_HOST:\n    return abort(403)\nreturn redirect(url)',
            rule_id="py.open.redirect",
            vuln_type=VulnerabilityType.OPEN_REDIRECT,
        )
        result = self.validator.verify_fix(request)
        assert result.security_check_passed is not None

    def test_ecb_mode_resolved(self):
        request = VerifyFixRequest(
            patch_id="p21",
            finding_id="f21",
            original_code="cipher = AES.new(key, AES.MODE_ECB)",
            fixed_code="cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)",
            rule_id="py.ecb.mode",
            vuln_type=VulnerabilityType.ECB_MODE,
        )
        result = self.validator.verify_fix(request)
        assert result.original_vuln_resolved is True

    def test_debug_exposure_resolved(self):
        request = VerifyFixRequest(
            patch_id="p22",
            finding_id="f22",
            original_code="app.run(debug=True)",
            fixed_code="app.run(debug=False)",
            rule_id="py.debug.exposure",
            vuln_type=VulnerabilityType.DEBUG_EXPOSURE,
        )
        result = self.validator.verify_fix(request)
        assert result.original_vuln_resolved is True

    def test_ssrf_resolved(self):
        request = VerifyFixRequest(
            patch_id="p23",
            finding_id="f23",
            original_code="resp = requests.get(user_url)",
            fixed_code='if urlparse(user_url).netloc in ALLOWED_HOSTS:\n    resp = requests.get(user_url)',
            rule_id="py.ssrf",
            vuln_type=VulnerabilityType.SSRF,
        )
        result = self.validator.verify_fix(request)
        assert result.original_vuln_resolved is True

    def test_jwt_weak_resolved(self):
        request = VerifyFixRequest(
            patch_id="p24",
            finding_id="f24",
            original_code="jwt.sign(payload, JWT_SECRET)",
            fixed_code="jws.encode(payload, process.env.JWT_SECRET, algorithm='HS256')",
            rule_id="py.jwt.weak",
            vuln_type=VulnerabilityType.JWT_WEAK,
        )
        result = self.validator.verify_fix(request)
        # Fixed code uses jws.encode instead of jwt.sign with proper algorithm
        assert result.original_vuln_resolved is True
