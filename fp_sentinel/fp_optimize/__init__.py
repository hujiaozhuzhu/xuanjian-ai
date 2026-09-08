"""
玄鉴 v3.0 — 自适应误报引擎 (Adaptive False Positive Optimization Engine)

提供用户反馈学习、规则自动优化、个性化模型、反馈统计四大核心能力。
长期使用后误报率可降到 1% 以下。

使用方式:
    from fp_sentinel.fp_optimize import (
        FeedbackStore, FeedbackLearningEngine,
        StatsEngine, PersonalizationEngine,
    )

    store = FeedbackStore()
    await store.initialize()

    engine = FeedbackLearningEngine(store)
    result = await engine.analyze_and_optimize(project_id="xxx")
"""

from .feedback_engine import (
    FeedbackLearningEngine,
    MIN_FEEDBACK_FOR_OPTIMIZATION,
    MAX_THRESHOLD_STEP,
    RULE_FP_PROBABILITY_THRESHOLD,
    TARGET_FP_RATE,
    CONFIDENCE_DECAY_FACTOR,
)
from .feedback_store import (
    FeedbackStore,
    FEEDBACK_SCHEMA_SQL,
)
from .models import (
    FeedbackBatchRequest,
    FeedbackSource,
    FeedbackStatistics,
    FeedbackType,
    FpRateTrendPoint,
    OptimizationEffect,
    OptimizationRecord,
    OptimizationStatus,
    UserFeedback,
    CodeStyleProfile,
    DashboardData,
)
from .personalization import (
    FRAMEWORK_PATTERNS,
    SECURITY_PATTERNS,
    PersonalizationEngine,
)
from .stats_engine import StatsEngine

__version__ = "3.0.0"

__all__ = [
    # Engines
    "FeedbackLearningEngine",
    "PersonalizationEngine",
    "StatsEngine",
    # Storage
    "FeedbackStore",
    "FEEDBACK_SCHEMA_SQL",
    # Models
    "FeedbackBatchRequest",
    "FeedbackSource",
    "FeedbackStatistics",
    "FeedbackType",
    "FpRateTrendPoint",
    "OptimizationEffect",
    "OptimizationRecord",
    "OptimizationStatus",
    "UserFeedback",
    "CodeStyleProfile",
    "DashboardData",
    # Constants
    "MIN_FEEDBACK_FOR_OPTIMIZATION",
    "MAX_THRESHOLD_STEP",
    "RULE_FP_PROBABILITY_THRESHOLD",
    "TARGET_FP_RATE",
    "CONFIDENCE_DECAY_FACTOR",
    # Pattern dictionaries
    "FRAMEWORK_PATTERNS",
    "SECURITY_PATTERNS",
]
