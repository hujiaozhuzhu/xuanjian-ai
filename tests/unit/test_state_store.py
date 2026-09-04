"""
状态持久化单元测试
"""

import pytest
import tempfile
import os
from fp_sentinel.redteam.state_store import AdversarialStateStore


class TestAdversarialStateStore:
    """状态持久化测试"""

    def setup_method(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "test.db")
        self.store = AdversarialStateStore(self.db_path)

    def teardown_method(self):
        import gc
        gc.collect()  # 强制垃圾回收，释放SQLite连接
        try:
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
            os.rmdir(self.tmp_dir)
        except PermissionError:
            pass  # Windows 上 SQLite 文件可能被锁定

    def test_save_and_load_round(self):
        """保存并加载轮次"""
        self.store.save_round(
            rule_id="js.injection.eval",
            round_num=1,
            detection_rate=0.95,
            total_cases=10,
            detected_cases=9,
        )

        latest = self.store.load_latest("js.injection.eval")
        assert latest is not None
        assert latest["detection_rate"] == 0.95

    def test_load_nonexistent(self):
        """加载不存在的规则"""
        result = self.store.load_latest("nonexistent.rule")
        assert result is None

    def test_get_history(self):
        """获取历史记录"""
        for i in range(5):
            self.store.save_round(
                rule_id="js.injection.eval",
                round_num=i + 1,
                detection_rate=0.90 + i * 0.02,
            )

        history = self.store.get_history("js.injection.eval")
        assert len(history) == 5

    def test_get_best_result(self):
        """获取最佳结果"""
        self.store.save_round(
            rule_id="js.injection.eval",
            round_num=1,
            detection_rate=0.85,
        )
        self.store.save_round(
            rule_id="js.injection.eval",
            round_num=2,
            detection_rate=0.96,
        )

        best = self.store.get_best_result("js.injection.eval")
        assert best["detection_rate"] == 0.96

    def test_get_statistics(self):
        """获取统计信息"""
        self.store.save_round(
            rule_id="js.injection.eval",
            round_num=1,
            detection_rate=0.95,
            converged=True,
        )

        stats = self.store.get_statistics()
        assert stats["total_rules_tested"] >= 1
        assert stats["converged_rules"] >= 1

    def test_save_with_bypass_cases(self):
        """保存绕过用例"""
        self.store.save_round(
            rule_id="js.injection.eval",
            round_num=1,
            detection_rate=0.90,
            bypass_cases=[
                {
                    "difficulty": "L1",
                    "strategy": "api_substitution",
                    "bypass_code": "new Function(x)()",
                    "detected": True,
                },
                {
                    "difficulty": "L2",
                    "strategy": "encoding_bypass",
                    "bypass_code": "atob('ZXZhbA==')",
                    "detected": False,
                },
            ],
        )

        latest = self.store.load_latest("js.injection.eval")
        assert latest is not None

    def test_clear_rule(self):
        """清除规则数据"""
        self.store.save_round(
            rule_id="js.injection.eval",
            round_num=1,
            detection_rate=0.95,
        )

        self.store.clear("js.injection.eval")
        result = self.store.load_latest("js.injection.eval")
        assert result is None

    def test_convergence_history(self):
        """获取收敛历史"""
        for i in range(5):
            self.store.save_round(
                rule_id="js.injection.eval",
                round_num=i + 1,
                detection_rate=0.90 + i * 0.02,
            )

        history = self.store.get_convergence_history("js.injection.eval", window=3)
        assert len(history) == 3
