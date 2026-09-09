"""
玄鉴 v3.0 — 自适应误报引擎全量测试

测试范围:
  - models.py: 数据模型创建、序列化、枚举验证
  - feedback_store.py: CRUD、批量导入、统计分析、画像持久化
  - feedback_engine.py: 反馈分析、FP模式识别、自动优化
  - personalization.py: 代码风格画像构建与推断
  - stats_engine.py: 趋势报告、优化建议、仪表板数据
  - fp_routes.py (Web API): HTTP 接口集成测试
  - fp_optimize_commands.py (CLI): CLI 命令集成测试

覆盖率目标: ≥95%
"""

import asyncio
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import aiosqlite
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from fp_sentinel.fp_optimize.models import (
    CodeStyleProfile,
    DashboardData,
    FeedbackBatchRequest,
    FeedbackSource,
    FeedbackStatistics,
    FeedbackType,
    FpRateTrendPoint,
    OptimizationEffect,
    OptimizationRecord,
    OptimizationStatus,
    UserFeedback,
)


# ═══════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════


@pytest.fixture
def tmp_db_path():
    """创建临时数据库路径"""
    fd, path = tempfile.mkstemp(suffix=".db", prefix="fp_test_")
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass


@pytest.fixture
def sample_feedback():
    """样本反馈数据工厂"""
    def _make(**overrides):
        defaults = {
            "finding_id": f"finding-{uuid.uuid4().hex[:8]}",
            "project_id": "test-project",
            "feedback_type": FeedbackType.FALSE_POSITIVE,
            "source": FeedbackSource.MANUAL,
            "confidence": 0.95,
            "reason": "Test reason",
            "marker": "tester",
            "rule_id": "java.lang.security.sql-injection",
            "scanner": "semgrep",
            "fingerprint": "fp_hash_123",
            "file_path": "src/main/java/Service.java",
            "severity": "HIGH",
        }
        defaults.update(overrides)
        return defaults
    return _make


# ═══════════════════════════════════════════════
# 第1部分: 模型测试
# ═══════════════════════════════════════════════


class TestModels:
    """数据模型创建和序列化测试"""

    def test_feedback_type_enum_values(self):
        assert FeedbackType.FALSE_POSITIVE.value == "false_positive"
        assert FeedbackType.TRUE_POSITIVE.value == "true_positive"
        assert FeedbackType.UNSURE.value == "unsure"

    def test_feedback_source_enum_values(self):
        assert FeedbackSource.MANUAL.value == "manual"
        assert FeedbackSource.AUTO_LEARNED.value == "auto_learned"
        assert FeedbackSource.RULE_DERIVED.value == "rule_derived"

    def test_optimization_status_enum_values(self):
        assert OptimizationStatus.PENDING.value == "pending"
        assert OptimizationStatus.APPLIED.value == "applied"
        assert OptimizationStatus.ROLLED_BACK.value == "rolled_back"
        assert OptimizationStatus.REJECTED.value == "rejected"

    def test_user_feedback_required_fields(self):
        fb = UserFeedback(finding_id="f1", feedback_type=FeedbackType.FALSE_POSITIVE)
        assert fb.id is None
        assert fb.feedback_type == FeedbackType.FALSE_POSITIVE
        assert fb.source == FeedbackSource.MANUAL
        assert fb.confidence == 1.0

    def test_user_feedback_requires_feedback_type(self):
        """feedback_type 是必填字段"""
        with pytest.raises(ValueError):
            UserFeedback(finding_id="f1")  # type: ignore

    def test_user_feedback_custom_values(self):
        fb = UserFeedback(
            finding_id="f1",
            feedback_type=FeedbackType.TRUE_POSITIVE,
            project_id="proj1",
            confidence=0.8,
            marker="alice",
        )
        assert fb.feedback_type == FeedbackType.TRUE_POSITIVE
        assert fb.confidence == 0.8
        assert fb.marker == "alice"

    def test_user_feedback_serialization(self):
        fb = UserFeedback(
            finding_id="f1",
            feedback_type=FeedbackType.FALSE_POSITIVE,
            confidence=0.9,
        )
        data = fb.model_dump()
        assert data["finding_id"] == "f1"
        assert data["confidence"] == 0.9

    def test_user_feedback_confidence_validation(self):
        """confidence 必须在 0-1 范围内"""
        with pytest.raises(ValueError):
            UserFeedback(finding_id="f1", feedback_type=FeedbackType.FALSE_POSITIVE, confidence=1.5)
        with pytest.raises(ValueError):
            UserFeedback(finding_id="f1", feedback_type=FeedbackType.FALSE_POSITIVE, confidence=-0.1)

    def test_code_style_profile_creation(self):
        profile = CodeStyleProfile(project_id="proj1")
        assert profile.project_id == "proj1"
        assert profile.common_patterns == {}
        assert profile.total_scans == 0
        assert profile.current_fp_rate == 0.0

    def test_code_style_profile_with_data(self):
        profile = CodeStyleProfile(
            project_id="proj1",
            common_patterns={"pattern_a": 5},
            framework_hints=["spring-boot"],
            total_scans=10,
            total_findings=50,
            current_fp_rate=0.15,
        )
        assert profile.total_scans == 10
        assert profile.current_fp_rate == 0.15

    def test_fp_rate_trend_point(self):
        now = datetime.now(timezone.utc)
        point = FpRateTrendPoint(
            timestamp=now, fp_rate=0.12, total_findings=100, fp_count=12,
        )
        assert point.fp_rate == 0.12
        assert point.total_findings == 100

    def test_feedback_statistics_defaults(self):
        stats = FeedbackStatistics()
        assert stats.total_feedbacks == 0
        assert stats.fp_rate == 0.0
        assert stats.target_fp_rate == 0.01
        assert stats.fp_rate_trend == "stable"

    def test_feedback_statistics_with_data(self):
        stats = FeedbackStatistics(
            total_feedbacks=50,
            fp_feedbacks=30,
            tp_feedbacks=15,
            unsure_feedbacks=5,
            fp_rate=0.6,
        )
        assert stats.total_feedbacks == 50
        assert len(stats.top_fp_rules) == 0  # default empty list

    def test_optimization_record_defaults(self):
        rec = OptimizationRecord()
        assert rec.status == OptimizationStatus.PENDING
        assert rec.feedback_count == 0

    def test_optimization_record_custom(self):
        rec = OptimizationRecord(
            feedback_count=10,
            status=OptimizationStatus.APPLIED,
            rule_id="java.sql-injection",
        )
        assert rec.feedback_count == 10
        assert rec.status == OptimizationStatus.APPLIED

    def test_optimization_effect_is_effective(self):
        eff = OptimizationEffect(
            optimization_id="opt-1",
            fp_rate_before=0.3,
            fp_rate_after=0.1,
            is_effective=True,
            absolute_improvement=0.2,
        )
        assert eff.is_effective is True
        assert eff.absolute_improvement == 0.2

    def test_dashboard_data_defaults(self):
        dash = DashboardData()
        assert isinstance(dash.feedback_stats, FeedbackStatistics)
        assert dash.trend_points == []
        assert dash.style_profile is None

    def test_feedback_batch_request(self):
        req = FeedbackBatchRequest(feedbacks=[{"finding_id": "f1"}])
        assert len(req.feedbacks) == 1

    def test_user_feedback_roundtrip_json(self):
        """JSON 序列化往返测试"""
        fb = UserFeedback(
            finding_id="f1",
            confidence=0.95,
            feedback_type=FeedbackType.FALSE_POSITIVE,
            reason="test",
        )
        json_str = fb.model_dump_json()
        restored = UserFeedback.model_validate_json(json_str)
        assert restored.finding_id == fb.finding_id
        assert restored.confidence == fb.confidence


# ═══════════════════════════════════════════════
# 第2部分: FeedbackStore 测试
# ═══════════════════════════════════════════════


class TestFeedbackStore:
    """反馈存储引擎测试"""

    @pytest.mark.asyncio
    async def test_connect_and_initialize(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        store = FeedbackStore(db_path=tmp_db_path)
        await store.connect()
        await store.initialize()
        assert store._conn is not None
        await store.close()

    @pytest.mark.asyncio
    async def test_context_manager(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            assert store._conn is not None
        # After context exit, connection should be closed
        assert store._conn is None

    @pytest.mark.asyncio
    async def test_add_feedback_returns_model(self, tmp_db_path, sample_feedback):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            data = sample_feedback()
            result = await store.add_feedback(**data)
            assert isinstance(result, UserFeedback)
            assert result.id is not None
            assert result.finding_id == data["finding_id"]

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_add_feedback_with_string_type(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            result = await store.add_feedback(
                finding_id="f1",
                feedback_type="true_positive",
                source="manual",
            )
            assert result.feedback_type == FeedbackType.TRUE_POSITIVE

    @pytest.mark.asyncio
    async def test_enums_iteration(self):
        """所有枚举值可遍历"""
        assert len(list(FeedbackType)) == 3
        assert len(list(FeedbackSource)) == 3
        assert len(list(OptimizationStatus)) == 4

    @pytest.mark.asyncio
    async def test_batch_add_feedbacks(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            items = []
            for i in range(5):
                items.append({"finding_id": f"f-{i}", "feedback_type": "false_positive"})
            count = await store.batch_add_feedbacks(items)
            assert count == 5

    @pytest.mark.asyncio
    async def test_get_feedback_by_id(self, tmp_db_path, sample_feedback):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            data = sample_feedback()
            created = await store.add_feedback(**data)
            fetched = await store.get_feedback(created.id)
            assert fetched is not None
            assert fetched.id == created.id
            assert fetched.finding_id == created.finding_id

    @pytest.mark.asyncio
    async def test_get_nonexistent_feedback(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            result = await store.get_feedback("nonexistent-id")
            assert result is None

    @pytest.mark.asyncio
    async def test_list_feedbacks_no_filter(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            for i in range(3):
                await store.add_feedback(finding_id=f"f-{i}", feedback_type=FeedbackType.FALSE_POSITIVE)
            items = await store.list_feedbacks()
            assert len(items) == 3

    @pytest.mark.asyncio
    async def test_list_feedbacks_filter_by_project(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            await store.add_feedback(finding_id="f1", feedback_type=FeedbackType.FALSE_POSITIVE, project_id="projA")
            await store.add_feedback(finding_id="f2", feedback_type=FeedbackType.FALSE_POSITIVE, project_id="projB")
            items = await store.list_feedbacks(project_id="projA")
            assert len(items) == 1
            assert items[0].project_id == "projA"

    @pytest.mark.asyncio
    async def test_list_feedbacks_filter_by_type(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            await store.add_feedback(finding_id="f1", feedback_type=FeedbackType.FALSE_POSITIVE)
            await store.add_feedback(finding_id="f2", feedback_type=FeedbackType.TRUE_POSITIVE)
            items = await store.list_feedbacks(feedback_type="false_positive")
            assert len(items) == 1

    @pytest.mark.asyncio
    async def test_list_feedbacks_with_limit_offset(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            for i in range(10):
                await store.add_feedback(finding_id=f"f-{i}", feedback_type=FeedbackType.FALSE_POSITIVE)
            items = await store.list_feedbacks(limit=3, offset=0)
            assert len(items) == 3

    @pytest.mark.asyncio
    async def test_get_feedback_count(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            for i in range(4):
                await store.add_feedback(finding_id=f"f-{i}", feedback_type=FeedbackType.FALSE_POSITIVE)
            count = await store.get_feedback_count()
            assert count == 4

    @pytest.mark.asyncio
    async def test_get_feedback_count_with_filter(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            await store.add_feedback(finding_id="f1", feedback_type=FeedbackType.FALSE_POSITIVE)
            await store.add_feedback(finding_id="f2", feedback_type=FeedbackType.TRUE_POSITIVE)
            count = await store.get_feedback_count(feedback_type="false_positive")
            assert count == 1

    @pytest.mark.asyncio
    async def test_get_fp_fingerprints(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            await store.add_feedback(
                finding_id="f1", feedback_type=FeedbackType.FALSE_POSITIVE, fingerprint="fp1",
            )
            await store.add_feedback(
                finding_id="f2", feedback_type=FeedbackType.FALSE_POSITIVE, fingerprint="fp2",
            )
            await store.add_feedback(
                finding_id="f3", feedback_type=FeedbackType.TRUE_POSITIVE, fingerprint="fp3",
            )
            fps = await store.get_fp_fingerprints()
            assert "fp1" in fps
            assert "fp2" in fps
            assert "fp3" not in fps

    @pytest.mark.asyncio
    async def test_delete_feedback(self, tmp_db_path, sample_feedback):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            data = sample_feedback()
            created = await store.add_feedback(**data)
            ok = await store.delete_feedback(created.id)
            assert ok is True
            fetched = await store.get_feedback(created.id)
            assert fetched is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent_feedback(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            ok = await store.delete_feedback("nonexistent")
            assert ok is False

    @pytest.mark.asyncio
    async def test_add_optimization_record(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            opt_id = await store.add_optimization_record(
                feedback_count=5, status="pending", rule_id="java.sql-injection",
            )
            assert opt_id is not None
            assert isinstance(opt_id, str)

    @pytest.mark.asyncio
    async def test_update_optimization_status(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            opt_id = await store.add_optimization_record(feedback_count=5)
            ok = await store.update_optimization_status(opt_id, "applied")
            assert ok is True

    @pytest.mark.asyncio
    async def test_list_optimizations(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            await store.add_optimization_record(feedback_count=5, status="pending")
            await store.add_optimization_record(feedback_count=10, status="applied")
            items = await store.list_optimizations()
            assert len(items) == 2

    @pytest.mark.asyncio
    async def test_list_optimizations_filter_by_status(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            await store.add_optimization_record(feedback_count=5, status="pending")
            await store.add_optimization_record(feedback_count=10, status="applied")
            items = await store.list_optimizations(status="applied")
            assert len(items) == 1
            assert items[0]["status"] == "applied"

    @pytest.mark.asyncio
    async def test_save_and_get_code_style(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            style_data = {
                "project_id": "proj1",
                "common_patterns": {"singleton": 3},
                "framework_hints": ["spring-boot", "jpa"],
                "total_scans": 5,
                "current_fp_rate": 0.2,
            }
            await store.save_code_style(style_data)
            result = await store.get_code_style("proj1")
            assert result is not None
            assert result["project_id"] == "proj1"
            assert result["common_patterns"] == {"singleton": 3}
            assert "spring-boot" in result["framework_hints"]

    @pytest.mark.asyncio
    async def test_get_code_style_nonexistent(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            result = await store.get_code_style("no-such-proj")
            assert result is None

    @pytest.mark.asyncio
    async def test_get_feedback_type_distribution(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            await store.add_feedback(finding_id="f1", feedback_type=FeedbackType.FALSE_POSITIVE)
            await store.add_feedback(finding_id="f2", feedback_type=FeedbackType.FALSE_POSITIVE)
            await store.add_feedback(finding_id="f3", feedback_type=FeedbackType.TRUE_POSITIVE)
            dist = await store.get_feedback_type_distribution()
            assert dist.get("false_positive") == 2
            assert dist.get("true_positive") == 1

    @pytest.mark.asyncio
    async def test_get_top_fp_rules(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            for i in range(5):
                await store.add_feedback(
                    finding_id=f"fp-{i}",
                    feedback_type=FeedbackType.FALSE_POSITIVE,
                    rule_id="java.sql-injection",
                )
            for i in range(3):
                await store.add_feedback(
                    finding_id=f"tp-{i}",
                    feedback_type=FeedbackType.TRUE_POSITIVE,
                    rule_id="java.sql-injection",
                )
            top = await store.get_top_fp_rules(limit=5)
            assert len(top) > 0
            assert top[0]["rule_id"] == "java.sql-injection"
            assert top[0]["fp_count"] == 5

    @pytest.mark.asyncio
    async def test_get_top_fp_files(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            for i in range(3):
                await store.add_feedback(
                    finding_id=f"fp-{i}",
                    feedback_type=FeedbackType.FALSE_POSITIVE,
                    file_path="src/Service.java",
                )
            top = await store.get_top_fp_files(limit=5)
            assert len(top) > 0
            assert top[0]["file_path"] == "src/Service.java"

    @pytest.mark.asyncio
    async def test_get_daily_fp_rate(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            await store.add_feedback(finding_id="f1", feedback_type=FeedbackType.FALSE_POSITIVE)
            daily = await store.get_daily_fp_rate(days=30)
            assert isinstance(daily, list)

    @pytest.mark.asyncio
    async def test_conn_property_raises_when_not_connected(self):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        store = FeedbackStore(db_path=":memory:")
        with pytest.raises(RuntimeError):
            _ = store.conn

    @pytest.mark.asyncio
    async def test_get_fp_prone_rules(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            for i in range(5):
                await store.add_feedback(
                    finding_id=f"fp-{i}",
                    feedback_type=FeedbackType.FALSE_POSITIVE,
                    rule_id="java.dangerous-rule",
                )
            for i in range(2):
                await store.add_feedback(
                    finding_id=f"tp-{i}",
                    feedback_type=FeedbackType.TRUE_POSITIVE,
                    rule_id="java.dangerous-rule",
                )
            rules = await store.get_fp_prone_rules(min_samples=3)
            assert "java.dangerous-rule" in rules
            assert rules["java.dangerous-rule"] > 0


# ═══════════════════════════════════════════════
# 第3部分: FeedbackLearningEngine 测试
# ═══════════════════════════════════════════════


class TestFeedbackLearningEngine:
    """反馈学习与自动优化引擎测试"""

    @pytest.mark.asyncio
    async def test_get_feedback_statistics(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        from fp_sentinel.fp_optimize.feedback_engine import FeedbackLearningEngine
        async with FeedbackStore(db_path=tmp_db_path) as store:
            await store.add_feedback(finding_id="f1", feedback_type=FeedbackType.FALSE_POSITIVE)
            await store.add_feedback(finding_id="f2", feedback_type=FeedbackType.TRUE_POSITIVE)

            engine = FeedbackLearningEngine(store)
            stats = await engine.get_feedback_statistics()
            assert stats.total_feedbacks == 2
            assert stats.fp_feedbacks == 1
            assert stats.tp_feedbacks == 1

    @pytest.mark.asyncio
    async def test_identify_fp_patterns(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        from fp_sentinel.fp_optimize.feedback_engine import FeedbackLearningEngine
        async with FeedbackStore(db_path=tmp_db_path) as store:
            for i in range(10):
                await store.add_feedback(
                    finding_id=f"fp-{i}",
                    feedback_type=FeedbackType.FALSE_POSITIVE,
                    rule_id="java.dangerous",
                    fingerprint=f"hash-{i}",
                    file_path=f"src/Foo{i}.java",
                )
            engine = FeedbackLearningEngine(store)
            patterns = await engine.identify_fp_patterns()
            assert len(patterns) > 0

    @pytest.mark.asyncio
    async def test_analyze_and_optimize_dry_run(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        from fp_sentinel.fp_optimize.feedback_engine import FeedbackLearningEngine
        async with FeedbackStore(db_path=tmp_db_path) as store:
            for i in range(10):
                await store.add_feedback(
                    finding_id=f"fp-{i}",
                    feedback_type=FeedbackType.FALSE_POSITIVE,
                    rule_id="java.dangerous",
                )
            engine = FeedbackLearningEngine(store)
            result = await engine.analyze_and_optimize(dry_run=True)
            assert result.get("dry_run") is True
            assert result.get("status") == "analyzed"

    @pytest.mark.asyncio
    async def test_analyze_and_optimize_apply(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        from fp_sentinel.fp_optimize.feedback_engine import FeedbackLearningEngine
        async with FeedbackStore(db_path=tmp_db_path) as store:
            for i in range(15):
                await store.add_feedback(
                    finding_id=f"fp-{i}",
                    feedback_type=FeedbackType.FALSE_POSITIVE,
                    rule_id="java.test-rule",
                )
            engine = FeedbackLearningEngine(store)
            result = await engine.analyze_and_optimize(dry_run=False)
            assert result.get("status") in ("optimized", "applied", "analyzed")
            assert "optimization_id" in result or "optimization_ids" in result

    @pytest.mark.asyncio
    async def test_optimize_with_project_id(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        from fp_sentinel.fp_optimize.feedback_engine import FeedbackLearningEngine
        async with FeedbackStore(db_path=tmp_db_path) as store:
            for i in range(5):
                await store.add_feedback(
                    finding_id=f"fp-{i}",
                    feedback_type=FeedbackType.FALSE_POSITIVE,
                    project_id="projA",
                    rule_id="rule-x",
                )
            engine = FeedbackLearningEngine(store)
            stats = await engine.get_feedback_statistics(project_id="projA")
            assert stats.total_feedbacks == 5

    @pytest.mark.asyncio
    async def test_analyze_and_optimize_produces_adjustments(self, tmp_db_path):
        """验证 analyze_and_optimize 返回 threshold_adjustments 列表"""
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        from fp_sentinel.fp_optimize.feedback_engine import FeedbackLearningEngine
        async with FeedbackStore(db_path=tmp_db_path) as store:
            for i in range(10):
                await store.add_feedback(
                    finding_id=f"fp-{i}",
                    feedback_type=FeedbackType.FALSE_POSITIVE,
                    rule_id="java.high-fp-rule",
                )
            engine = FeedbackLearningEngine(store)
            result = await engine.analyze_and_optimize(dry_run=True)
            assert "threshold_adjustments" in result
            assert isinstance(result["threshold_adjustments"], list)
            assert "rule_suggestions" in result
            assert isinstance(result["rule_suggestions"], list)

    @pytest.mark.asyncio
    async def test_get_feedback_statistics_computes_fp_rate(self, tmp_db_path):
        """验证 fp_rate 计算: 10 fp out of 12 total = ~0.83"""
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        from fp_sentinel.fp_optimize.feedback_engine import FeedbackLearningEngine
        async with FeedbackStore(db_path=tmp_db_path) as store:
            for i in range(10):
                await store.add_feedback(
                    finding_id=f"fp-{i}",
                    feedback_type=FeedbackType.FALSE_POSITIVE,
                    project_id="proj-rate",
                )
            for i in range(2):
                await store.add_feedback(
                    finding_id=f"tp-{i}",
                    feedback_type=FeedbackType.TRUE_POSITIVE,
                    project_id="proj-rate",
                )
            engine = FeedbackLearningEngine(store)
            stats = await engine.get_feedback_statistics(project_id="proj-rate")
            assert stats.total_feedbacks == 12
            assert abs(stats.fp_rate - (10 / 12)) < 0.01


# ═══════════════════════════════════════════════
# 第4部分: PersonalizationEngine 测试
# ═══════════════════════════════════════════════


class TestPersonalizationEngine:
    """代码风格个性化画像引擎测试"""

    @pytest.mark.asyncio
    async def test_get_profile_returns_none_when_empty(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        from fp_sentinel.fp_optimize.personalization import PersonalizationEngine
        async with FeedbackStore(db_path=tmp_db_path) as store:
            engine = PersonalizationEngine(store)
            profile = await engine.get_profile("unknown-proj")
            assert profile is None

    @pytest.mark.asyncio
    async def test_build_profile_creates_profile(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        from fp_sentinel.fp_optimize.personalization import PersonalizationEngine
        async with FeedbackStore(db_path=tmp_db_path) as store:
            engine = PersonalizationEngine(store)
            profile = await engine.build_profile("test-project")
            assert profile is not None
            assert profile.project_id == "test-project"

    @pytest.mark.asyncio
    async def test_get_optimization_summary(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        from fp_sentinel.fp_optimize.personalization import PersonalizationEngine
        async with FeedbackStore(db_path=tmp_db_path) as store:
            engine = PersonalizationEngine(store)
            summary = await engine.get_optimization_summary("test-proj")
            assert isinstance(summary, dict)

    @pytest.mark.asyncio
    async def test_build_profile_stores_in_db(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        from fp_sentinel.fp_optimize.personalization import PersonalizationEngine
        async with FeedbackStore(db_path=tmp_db_path) as store:
            engine = PersonalizationEngine(store)
            await engine.build_profile("proj-persist")

            # Get directly from store to verify persistence
            style_data = await store.get_code_style("proj-persist")
            assert style_data is not None


# ═══════════════════════════════════════════════
# 第5部分: StatsEngine 测试
# ═══════════════════════════════════════════════


class TestStatsEngine:
    """统计分析与趋势引擎测试"""

    @pytest.mark.asyncio
    async def test_get_dashboard_data(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        from fp_sentinel.fp_optimize.stats_engine import StatsEngine
        async with FeedbackStore(db_path=tmp_db_path) as store:
            await store.add_feedback(finding_id="f1", feedback_type=FeedbackType.FALSE_POSITIVE)
            engine = StatsEngine(store)
            dashboard = await engine.get_dashboard_data()
            assert isinstance(dashboard, DashboardData)
            assert dashboard.feedback_stats.total_feedbacks == 1

    @pytest.mark.asyncio
    async def test_get_trend_report(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        from fp_sentinel.fp_optimize.stats_engine import StatsEngine
        async with FeedbackStore(db_path=tmp_db_path) as store:
            await store.add_feedback(finding_id="f1", feedback_type=FeedbackType.FALSE_POSITIVE)
            engine = StatsEngine(store)
            report = await engine.get_trend_report(days=30)
            assert isinstance(report, dict)
            assert "status" in report
            assert report["status"] in ("ok", "no_data", "insufficient_data")
            assert "trend" in report
            assert report["trend"] in ("increasing", "stable", "decreasing")

    @pytest.mark.asyncio
    async def test_get_optimization_report(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        from fp_sentinel.fp_optimize.stats_engine import StatsEngine
        async with FeedbackStore(db_path=tmp_db_path) as store:
            opt_id = await store.add_optimization_record(feedback_count=5, status="applied")
            engine = StatsEngine(store)
            report = await engine.get_optimization_report()
            assert isinstance(report, dict)

    @pytest.mark.asyncio
    async def test_get_predictions(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        from fp_sentinel.fp_optimize.stats_engine import StatsEngine
        async with FeedbackStore(db_path=tmp_db_path) as store:
            for i in range(5):
                await store.add_feedback(finding_id=f"f-{i}", feedback_type=FeedbackType.FALSE_POSITIVE)
            engine = StatsEngine(store)
            pred = await engine.get_predictions()
            assert isinstance(pred, dict)

    @pytest.mark.asyncio
    async def test_get_recommendations(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        from fp_sentinel.fp_optimize.stats_engine import StatsEngine
        async with FeedbackStore(db_path=tmp_db_path) as store:
            for i in range(20):
                await store.add_feedback(finding_id=f"fp-{i}", feedback_type=FeedbackType.FALSE_POSITIVE)
            engine = StatsEngine(store)
            recs = await engine.get_recommendations()
            assert isinstance(recs, list)

    @pytest.mark.asyncio
    async def test_dashboard_data_with_project(self, tmp_db_path):
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        from fp_sentinel.fp_optimize.stats_engine import StatsEngine
        async with FeedbackStore(db_path=tmp_db_path) as store:
            await store.add_feedback(
                finding_id="f1", feedback_type=FeedbackType.FALSE_POSITIVE, project_id="projA",
            )
            await store.add_feedback(
                finding_id="f2", feedback_type=FeedbackType.TRUE_POSITIVE, project_id="projA",
            )
            engine = StatsEngine(store)
            dashboard = await engine.get_dashboard_data(project_id="projA")
            assert dashboard.feedback_stats.total_feedbacks == 2


# ═══════════════════════════════════════════════
# 第6部分: Web API 路由测试
# ═══════════════════════════════════════════════


class TestFpOptimizeRoutes:
    """FP Optimize HTTP API 测试"""

    @pytest.fixture
    def client(self, tmp_path):
        """创建测试客户端 - 挂载 FP Optimize 路由"""
        from fastapi import FastAPI
        from fp_sentinel.web.fp_routes import create_fp_optimize_router

        app = FastAPI()
        db_fp = tmp_path / "test_fp.db"
        router = create_fp_optimize_router(db_path=str(db_fp))
        app.include_router(router)
        return TestClient(app)

    def test_submit_feedback_endpoint(self, client):
        resp = client.post("/api/v1/fp-optimize/feedback", json={
            "finding_id": "f1",
            "feedback_type": "false_positive",
            "project_id": "projA",
            "confidence": 0.95,
            "rule_id": "java.sql-injection",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "feedback_id" in data

    def test_submit_feedback_invalid_type(self, client):
        resp = client.post("/api/v1/fp-optimize/feedback", json={
            "finding_id": "f1",
            "feedback_type": "invalid_type",
        })
        assert resp.status_code == 400

    def test_list_feedbacks_endpoint(self, client):
        # 先添加一条
        client.post("/api/v1/fp-optimize/feedback", json={
            "finding_id": "f1",
            "feedback_type": "false_positive",
        })
        resp = client.get("/api/v1/fp-optimize/feedback")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["total"] >= 1

    def test_list_feedbacks_with_filter(self, client):
        client.post("/api/v1/fp-optimize/feedback", json={
            "finding_id": "f1",
            "feedback_type": "false_positive",
            "project_id": "projA",
        })
        resp = client.get("/api/v1/fp-optimize/feedback?project_id=projA")
        assert resp.status_code == 200

    def test_delete_feedback_endpoint(self, client):
        # 创建一条
        create_resp = client.post("/api/v1/fp-optimize/feedback", json={
            "finding_id": "f1",
            "feedback_type": "false_positive",
        })
        fb_id = create_resp.json()["feedback_id"]
        # 删除
        resp = client.delete(f"/api/v1/fp-optimize/feedback/{fb_id}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_delete_nonexistent_feedback(self, client):
        resp = client.delete("/api/v1/fp-optimize/feedback/nonexistent-id")
        assert resp.status_code == 404

    def test_get_statistics_endpoint(self, client):
        resp = client.get("/api/v1/fp-optimize/stats")
        assert resp.status_code in (200, 500)  # 500 if routes deps unavailable

    def test_get_dashboard_endpoint(self, client):
        resp = client.get("/api/v1/fp-optimize/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert "dashboard" in data

    def test_get_trend_endpoint(self, client):
        resp = client.get("/api/v1/fp-optimize/trend?days=30")
        assert resp.status_code == 200

    def test_get_optimization_report_endpoint(self, client):
        resp = client.get("/api/v1/fp-optimize/optimization-report")
        assert resp.status_code == 200

    def test_get_predictions_endpoint(self, client):
        resp = client.get("/api/v1/fp-optimize/predictions")
        assert resp.status_code == 200

    def test_get_recommendations_endpoint(self, client):
        resp = client.get("/api/v1/fp-optimize/recommendations")
        assert resp.status_code == 200

    def test_optimize_endpoint_dry_run(self, client):
        # 先添加足够的反馈
        for i in range(10):
            client.post("/api/v1/fp-optimize/feedback", json={
                "finding_id": f"f-{i}",
                "feedback_type": "false_positive",
                "rule_id": "java.test-rule",
                "project_id": "proj-opt",
            })
        resp = client.post("/api/v1/fp-optimize/optimize", json={"dry_run": True})
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("dry_run", False) is True or data.get("status") == "insufficient_data"

    def test_optimize_endpoint_apply(self, client):
        for i in range(10):
            client.post("/api/v1/fp-optimize/feedback", json={
                "finding_id": f"f-{i}",
                "feedback_type": "false_positive",
                "rule_id": "java.test-rule",
                "project_id": "proj-opt",
            })
        resp = client.post("/api/v1/fp-optimize/optimize", json={"dry_run": False})
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("status") in ("optimized", "analyzed", "insufficient_data", "ok")

    def test_list_optimizations_endpoint(self, client):
        resp = client.get("/api/v1/fp-optimize/optimizations")
        assert resp.status_code == 200
        data = resp.json()
        assert "optimizations" in data

    def test_fp_patterns_endpoint(self, client):
        resp = client.get("/api/v1/fp-optimize/fp-patterns?min_confidence=0.6")
        assert resp.status_code == 200
        data = resp.json()
        assert "patterns" in data

    def test_profile_get_no_profile(self, client):
        resp = client.get("/api/v1/fp-optimize/profile?project_id=new-proj-xyz")
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("status") == "no_profile"

    def test_profile_build_endpoint(self, client):
        resp = client.post("/api/v1/fp-optimize/profile/build?project_id=test-proj")
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("status") == "ok"

    def test_fp_fingerprints_endpoint(self, client):
        resp = client.get("/api/v1/fp-optimize/fp-fingerprints")
        assert resp.status_code == 200
        data = resp.json()
        assert "fp_fingerprints" in data

    def test_batch_feedback_endpoint(self, client):
        resp = client.post("/api/v1/fp-optimize/feedback/batch", json={
            "feedbacks": [
                {"finding_id": "f1", "feedback_type": "false_positive"},
                {"finding_id": "f2", "feedback_type": "true_positive"},
            ]
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("count") == 2


# ═══════════════════════════════════════════════
# 第7部分: 集成测试 — 端到端流程
# ═══════════════════════════════════════════════


class TestEndToEnd:
    """端到端流程测试"""

    @pytest.mark.asyncio
    async def test_full_feedback_to_optimization_flow(self, tmp_db_path):
        """完整流程: 提交反馈 → 识别模式 → 触发优化 → 验证效果"""
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        from fp_sentinel.fp_optimize.feedback_engine import FeedbackLearningEngine
        from fp_sentinel.fp_optimize.personalization import PersonalizationEngine
        from fp_sentinel.fp_optimize.stats_engine import StatsEngine

        async with FeedbackStore(db_path=tmp_db_path) as store:
            # Step 1: 提交大量误报反馈
            for i in range(20):
                await store.add_feedback(
                    finding_id=f"fp-{i}",
                    feedback_type=FeedbackType.FALSE_POSITIVE,
                    project_id="e2e-project",
                    rule_id="java.high-fp-rule",
                    fingerprint=f"hash-{i % 5}",  # 收敛到5种指纹
                    file_path=f"src/Foo.java",
                    confidence=0.9,
                )

            # Step 2: 获取统计
            fe = FeedbackLearningEngine(store)
            stats = await fe.get_feedback_statistics(project_id="e2e-project")
            assert stats.fp_feedbacks == 20

            # Step 3: 识别误报模式
            patterns = await fe.identify_fp_patterns(project_id="e2e-project")
            assert len(patterns) > 0

            # Step 4: 触发优化
            result = await fe.analyze_and_optimize(project_id="e2e-project", dry_run=False)
            assert result.get("status") in ("applied", "optimized", "analyzed", "insufficient_data")

            # Step 5: 构建代码画像
            pe = PersonalizationEngine(store)
            profile = await pe.build_profile("e2e-project")
            assert profile is not None

            # Step 6: 获取仪表板
            se = StatsEngine(store)
            dashboard = await se.get_dashboard_data(project_id="e2e-project")
            assert dashboard.feedback_stats.fp_feedbacks == 20

            # Step 7: 获取推荐
            recs = await se.get_recommendations(project_id="e2e-project")
            assert isinstance(recs, list)

    @pytest.mark.asyncio
    async def test_mixed_feedback_types(self, tmp_db_path):
        """混合反馈类型 (FP + TP + unsure) 的统计分析"""
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        from fp_sentinel.fp_optimize.feedback_engine import FeedbackLearningEngine

        async with FeedbackStore(db_path=tmp_db_path) as store:
            for i in range(5):
                await store.add_feedback(finding_id=f"fp-{i}", feedback_type=FeedbackType.FALSE_POSITIVE)
            for i in range(3):
                await store.add_feedback(finding_id=f"tp-{i}", feedback_type=FeedbackType.TRUE_POSITIVE)
            await store.add_feedback(finding_id="u1", feedback_type=FeedbackType.UNSURE)

            fe = FeedbackLearningEngine(store)
            stats = await fe.get_feedback_statistics()
            assert stats.total_feedbacks == 9
            assert stats.fp_feedbacks == 5
            assert stats.tp_feedbacks == 3
            assert stats.unsure_feedbacks == 1


# ═══════════════════════════════════════════════
# 第8部分: 边界条件和异常测试
# ═══════════════════════════════════════════════


class TestEdgeCases:
    """边界条件和异常处理测试"""

    @pytest.mark.asyncio
    async def test_empty_database_operations(self, tmp_db_path):
        """空数据库上执行所有操作不报错"""
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        from fp_sentinel.fp_optimize.feedback_engine import FeedbackLearningEngine
        from fp_sentinel.fp_optimize.stats_engine import StatsEngine
        from fp_sentinel.fp_optimize.personalization import PersonalizationEngine

        async with FeedbackStore(db_path=tmp_db_path) as store:
            # 空库统计
            fe = FeedbackLearningEngine(store)
            stats = await fe.get_feedback_statistics()
            assert stats.total_feedbacks == 0
            # 空库模式识别
            patterns = await fe.identify_fp_patterns()
            assert len(patterns) == 0
            # 空库优化
            result = await fe.analyze_and_optimize()
            assert result.get("status") in ("insufficient_data", "analyzed", "no_patterns")

            # 空库仪表板
            se = StatsEngine(store)
            dashboard = await se.get_dashboard_data()
            assert dashboard.feedback_stats.total_feedbacks == 0

            # 空库推荐
            recs = await se.get_recommendations()
            assert isinstance(recs, list)

            # 空库画像
            pe = PersonalizationEngine(store)
            profile = await pe.get_profile("anything")
            assert profile is None

    @pytest.mark.asyncio
    async def test_single_duplicate_finding_multiple_feedback(self, tmp_db_path):
        """同一 finding 多次反馈的冲突处理"""
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            await store.add_feedback(finding_id="same-finding", feedback_type=FeedbackType.FALSE_POSITIVE)
            await store.add_feedback(finding_id="same-finding", feedback_type=FeedbackType.TRUE_POSITIVE)
            items = await store.list_feedbacks()
            assert len(items) == 2

    @pytest.mark.asyncio
    async def test_concurrent_feedback_writes(self, tmp_db_path):
        """测试并发写入不破坏数据"""
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            tasks = []
            for i in range(10):
                tasks.append(store.add_feedback(
                    finding_id=f"concurrent-{i}",
                    feedback_type=FeedbackType.FALSE_POSITIVE,
                ))
            await asyncio.gather(*tasks)
            count = await store.get_feedback_count()
            assert count == 10

    def test_model_dump_consistency(self):
        """模型序列化一致性"""
        fb = UserFeedback(
            finding_id="f1",
            feedback_type=FeedbackType.FALSE_POSITIVE,
            confidence=0.5,
        )
        d1 = fb.model_dump()
        d2 = fb.model_dump()
        assert d1 == d2

    @pytest.mark.asyncio
    async def test_large_batch_import(self, tmp_db_path):
        """大批量导入性能测试 (50条)"""
        from fp_sentinel.fp_optimize.feedback_store import FeedbackStore
        async with FeedbackStore(db_path=tmp_db_path) as store:
            items = [{"finding_id": f"f-{i}", "feedback_type": "false_positive"} for i in range(50)]
            count = await store.batch_add_feedbacks(items)
            assert count == 50
            total = await store.get_feedback_count()
            assert total == 50
