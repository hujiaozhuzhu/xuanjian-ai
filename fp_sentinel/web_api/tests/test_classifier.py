"""分类命中测试。"""

from __future__ import annotations

from fp_sentinel.web_api.classifier import classify
from fp_sentinel.web_api.endpoints_models import ApiEndpoint


class TestClassify:
    """classify 函数测试。"""

    def test_auth_keyword(self) -> None:
        """验证 auth 类别命中。"""
        ep = ApiEndpoint(method="POST", url="https://x.com/api/login", path="/api/login")
        result = classify(ep)
        assert result["category"] == "auth"
        assert result["sensitivity"] == "high"
        assert any("login" in r for r in result["reasons"])

    def test_finance_keyword(self) -> None:
        """验证 finance 类别命中。"""
        ep = ApiEndpoint(method="POST", url="https://x.com/api/payment", path="/api/payment")
        result = classify(ep)
        assert result["category"] == "finance"
        assert result["sensitivity"] == "high"

    def test_user_profile(self) -> None:
        """验证 user 类别命中。"""
        ep = ApiEndpoint(
            method="GET",
            url="https://x.com/api/users/profile",
            path="/api/users/profile",
        )
        result = classify(ep)
        assert result["category"] == "user"
        assert result["sensitivity"] in {"medium", "high"}

    def test_admin_keyword(self) -> None:
        """验证 admin 类别命中。"""
        ep = ApiEndpoint(method="GET", url="https://x.com/admin/users", path="/admin/users")
        result = classify(ep)
        assert result["category"] == "admin"
        assert result["sensitivity"] == "high"

    def test_generic_endpoint(self) -> None:
        """验证无敏感标记的端点返回 low。"""
        ep = ApiEndpoint(method="GET", url="https://x.com/static/logo.png", path="/static/logo.png")
        result = classify(ep)
        assert result["sensitivity"] == "low"
        assert result["category"] == "generic"

    def test_high_risk_pattern_password(self) -> None:
        """验证密码模式命中高危。"""
        ep = ApiEndpoint(
            method="POST",
            url="https://x.com/api/reset",
            path="/api/reset?token=abc&old_password=X",
        )
        result = classify(ep)
        assert result["sensitivity"] == "high"

    def test_idcard_pattern(self) -> None:
        """验证身份证号模式命中高危。"""
        ep = ApiEndpoint(
            method="GET",
            url="https://x.com/api/kyc",
            path="/api/kyc?id_number=110101199001011234",
        )
        result = classify(ep)
        assert result["sensitivity"] == "high"

    def test_empty_path(self) -> None:
        """验证空路径返回 low + unknown。"""
        ep = ApiEndpoint(method="GET", url="", path="")
        result = classify(ep)
        assert result["sensitivity"] == "low"
